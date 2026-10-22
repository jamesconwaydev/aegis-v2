// SPDX-License-Identifier: MIT OR Apache-2.0
//! The enforcer: one thread that turns a throttle or quarantine verdict
//! into systemd scopes, kernel holds and an nftables rule, and records
//! every step on the incident. The event loop only queues jobs here, so
//! a slow systemd never holds up detection.

use std::collections::{BTreeSet, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use super::nft::Nft;
#[cfg(test)]
use super::systemd::Run;
use super::systemd::{Limits, Systemd};
use crate::config::Mode;
use crate::ebpf::Holds;
use crate::incident::{ActionRecord, IncidentId, IncidentStore};
use crate::proctable::{ProcKey, ProcTable};
use crate::scoring::Tier;
use crate::telemetry::{now_ns, rfc3339, Sinks, TelemetryRecord};

/// Jobs waiting for the enforcer; past this the loop drops and counts.
const QUEUE: usize = 256;
const QUARANTINE_SLICE: &str = "aegis-quarantine.slice";
const THROTTLE_SLICE: &str = "aegis-throttle.slice";

/// Where a release or kill answers: Ok with a message, or Err with why.
pub type Reply = tokio::sync::oneshot::Sender<Result<String, String>>;

#[derive(Debug)]
pub enum EnforceJob {
    Throttle {
        id: String,
        pids: Vec<ProcKey>,
    },
    Quarantine {
        id: String,
        pids: Vec<ProcKey>,
    },
    // Sent by `aegisctl incidents release|kill`, which comes next.
    #[allow(dead_code)]
    Release {
        id: String,
        reply: Option<Reply>,
    },
    #[allow(dead_code)]
    Kill {
        id: String,
        reply: Option<Reply>,
    },
}

pub struct EnforcerHandle {
    pub tx: SyncSender<EnforceJob>,
    /// Jobs the loop dropped because the queue was full.
    pub dropped: Arc<AtomicU64>,
    #[allow(dead_code)] // exported with the metrics
    pub actions_ok: Arc<AtomicU64>,
    #[allow(dead_code)]
    pub actions_failed: Arc<AtomicU64>,
}

pub fn spawn_enforcer(
    store: Arc<IncidentStore>,
    holds: Holds,
    sys: Systemd,
    nft: Nft,
    limits: Limits,
    sinks: Arc<Sinks>,
) -> EnforcerHandle {
    let (tx, rx) = sync_channel(QUEUE);
    let h = EnforcerHandle {
        tx,
        dropped: Arc::default(),
        actions_ok: Arc::default(),
        actions_failed: Arc::default(),
    };
    let mut e = Enforcer {
        store,
        holds,
        sys,
        nft,
        limits,
        sinks,
        ok: h.actions_ok.clone(),
        failed: h.actions_failed.clone(),
    };
    std::thread::Builder::new()
        .name("aegis-enforce".into())
        .spawn(move || {
            for job in rx {
                e.run(job);
            }
        })
        .expect("spawning the enforcer thread");
    h
}

/// Live members and every live descendant of one, by tgid. Each process
/// is kept only if it or something above it is a member, so an ancestor
/// of the tree (the admin's shell, sshd) is never reached; a process
/// between two members is under the upper one and is kept. pid 1,
/// kthreadd and aegisd are dropped whatever the table says.
// ponytail: walks every process's parent chain, O(table x depth); index
// children by parent if incidents get large.
pub fn target_set(table: &ProcTable, members: &[ProcKey], me: u32) -> Vec<ProcKey> {
    let m: HashSet<ProcKey> = members.iter().copied().collect();
    let mut out: Vec<ProcKey> = table
        .iter()
        .filter(|p| !matches!(p.key.tgid, 1 | 2) && p.key.tgid != me)
        .filter(|p| {
            m.contains(&p.key)
                || table
                    .parent_chain(&p.key)
                    .iter()
                    .any(|a| m.contains(&a.key))
        })
        .map(|p| p.key)
        .collect();
    out.sort_by_key(|k| (k.tgid, k.start_time_ns));
    out
}

fn q_unit(id: &str) -> String {
    format!("aegis-incident-{id}-q.scope")
}

fn t_unit(id: &str) -> String {
    format!("aegis-incident-{id}.scope")
}

fn act(kind: &str, unit: Option<&str>, pids: Vec<u32>, r: Result<Option<u64>>) -> ActionRecord {
    let (ok, nft_handle, error) = match r {
        Ok(h) => (true, h, None),
        Err(e) => (false, None, Some(format!("{e:#}"))),
    };
    ActionRecord {
        kind: kind.into(),
        ok,
        unit: unit.map(String::from),
        nft_handle,
        pids,
        error,
        ts: rfc3339(now_ns()),
    }
}

/// The last thing that changed the tree's state, ignoring bookkeeping
/// (holds, rules): a scope, attach or freeze means enforced; thaw,
/// lift_limits or kill means an admin already ended it.
fn state(acts: &[ActionRecord]) -> Option<&str> {
    acts.iter()
        .rev()
        .filter(|a| a.ok)
        .map(|a| a.kind.as_str())
        .find(|k| {
            matches!(
                *k,
                "scope" | "attach" | "freeze" | "thaw" | "lift_limits" | "kill"
            )
        })
}

/// nft rules added and not yet removed.
fn live_rules(acts: &[ActionRecord]) -> Vec<u64> {
    let removed: HashSet<u64> = acts
        .iter()
        .filter(|a| a.ok && a.kind == "nft_remove")
        .filter_map(|a| a.nft_handle)
        .collect();
    acts.iter()
        .filter(|a| a.ok && a.kind == "nft_drop")
        .filter_map(|a| a.nft_handle)
        .filter(|h| !removed.contains(h))
        .collect()
}

pub struct Enforcer {
    store: Arc<IncidentStore>,
    holds: Holds,
    sys: Systemd,
    nft: Nft,
    limits: Limits,
    sinks: Arc<Sinks>,
    ok: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

impl Enforcer {
    pub fn run(&mut self, job: EnforceJob) {
        match job {
            EnforceJob::Throttle { id, pids } => self.throttle(&id, &pids),
            EnforceJob::Quarantine { id, pids } => self.quarantine(&id, &pids),
            EnforceJob::Release { id, reply } => {
                let r = self.release(&id);
                if let Some(tx) = reply {
                    let _ = tx.send(r);
                }
            }
            EnforceJob::Kill { id, reply } => {
                let r = self.kill(&id);
                if let Some(tx) = reply {
                    let _ = tx.send(r);
                }
            }
        }
    }

    fn actions(&self, id: &str) -> Vec<ActionRecord> {
        self.store
            .get(&IncidentId(id.into()))
            .map(|i| i.actions)
            .unwrap_or_default()
    }

    fn throttle(&mut self, id: &str, pids: &[ProcKey]) {
        // Already moved (a restart re-sending, say): a throttle scope
        // must never pull a frozen tree out of its quarantine scope.
        if state(&self.actions(id)).is_some() {
            return;
        }
        let unit = t_unit(id);
        let r = self
            .sys
            .start_scope(&unit, THROTTLE_SLICE, pids, Some(self.limits));
        let a = act("scope", Some(&unit), tgids(pids), r.map(|_| None));
        let v = a.ok.then_some("throttled");
        self.finish(id, vec![a], v);
    }

    /// Hold, move, freeze, cut off. Each step is recorded; the verdict
    /// becomes `quarantined` only once the tree is moved and frozen. If
    /// that fails the holds stay: they still stop the tree acting.
    fn quarantine(&mut self, id: &str, pids: &[ProcKey]) {
        let prior = self.actions(id);
        // An admin released or killed it; that stands.
        if matches!(state(&prior), Some("thaw" | "kill")) || pids.is_empty() {
            return;
        }
        let unit = q_unit(id);
        let done = |kind: &str| {
            prior
                .iter()
                .any(|a| a.ok && a.kind == kind && a.unit.as_deref() == Some(unit.as_str()))
        };
        let (scoped, frozen, ruled) = (
            done("scope") || done("attach"),
            done("freeze"),
            done("nft_drop"),
        );
        let mut acts = Vec::new();

        let (mut held, mut errs) = (Vec::new(), Vec::new());
        for k in pids {
            match self.holds.hold(*k) {
                Ok(()) => held.push(k.tgid),
                Err(e) => errs.push(format!("{e:#}")),
            }
        }
        let r = if errs.is_empty() {
            Ok(None)
        } else {
            Err(anyhow::anyhow!(errs.join("; ")))
        };
        acts.push(act("hold", None, held, r));

        // A newcomer joins the scope the tree is already in.
        let moved = if scoped {
            let r = self.sys.attach(&unit, pids);
            acts.push(act("attach", Some(&unit), tgids(pids), r.map(|_| None)));
            acts.last().unwrap().ok
        } else {
            let r = self.sys.start_scope(&unit, QUARANTINE_SLICE, pids, None);
            acts.push(act("scope", Some(&unit), tgids(pids), r.map(|_| None)));
            acts.last().unwrap().ok
        };
        let mut now_frozen = frozen;
        if moved && !frozen {
            let r = self.sys.freeze(&unit);
            now_frozen = r.is_ok();
            acts.push(act("freeze", Some(&unit), vec![], r.map(|_| None)));
        }
        if moved && !ruled {
            let cg = Nft::scope_cgroup(QUARANTINE_SLICE, &unit);
            let r = self
                .nft
                .ensure_table()
                .and_then(|()| self.nft.drop_cgroup(&cg));
            acts.push(act("nft_drop", Some(&unit), vec![], r.map(Some)));
        }
        let v = (moved && now_frozen).then_some("quarantined");
        self.finish(id, acts, v);
    }

    fn release(&mut self, id: &str) -> Result<String, String> {
        let prior = self.actions(id);
        let unit = q_unit(id);
        self.refuse_ended(id, &prior)?;
        let quarantined = prior
            .iter()
            .any(|a| a.ok && (a.kind == "hold" || a.unit.as_deref() == Some(unit.as_str())));
        let mut acts = Vec::new();
        if quarantined {
            if prior.iter().any(|a| a.ok && a.kind == "freeze") {
                let r = self.sys.thaw(&unit);
                acts.push(act("thaw", Some(&unit), vec![], r.map(|_| None)));
            }
            let pids: BTreeSet<u32> = prior
                .iter()
                .filter(|a| a.kind == "hold")
                .flat_map(|a| a.pids.iter().copied())
                .collect();
            let errs: Vec<String> = pids
                .iter()
                .filter_map(|&p| self.holds.release(p).err().map(|e| format!("{e:#}")))
                .collect();
            let r = if errs.is_empty() {
                Ok(None)
            } else {
                Err(anyhow::anyhow!(errs.join("; ")))
            };
            acts.push(act("unhold", None, pids.into_iter().collect(), r));
            self.remove_rules(&prior, &unit, &mut acts);
            // ponytail: the tree stays in its -q scope, so its accounting
            // lives under aegis-quarantine.slice. Moving it back to its
            // original unit is AttachProcessesToUnit, if that's ever wanted.
        } else {
            let t = t_unit(id);
            let r = self.sys.lift_limits(&t);
            acts.push(act("lift_limits", Some(&t), vec![], r.map(|_| None)));
        }
        self.conclude(id, acts, "released")
    }

    fn kill(&mut self, id: &str) -> Result<String, String> {
        let prior = self.actions(id);
        let unit = q_unit(id);
        self.refuse_ended(id, &prior)?;
        if !prior
            .iter()
            .any(|a| a.ok && a.unit.as_deref() == Some(unit.as_str()))
        {
            return Err(format!("{id} was only throttled; release it instead"));
        }
        // A frozen cgroup still takes SIGKILL.
        let r = self.sys.kill(&unit);
        let mut acts = vec![act("kill", Some(&unit), vec![], r.map(|_| None))];
        self.remove_rules(&prior, &unit, &mut acts);
        self.conclude(id, acts, "killed")
    }

    /// Refuses an incident never enforced, or already released or killed.
    fn refuse_ended(&self, id: &str, prior: &[ActionRecord]) -> Result<(), String> {
        if !prior.iter().any(|a| a.ok) {
            return Err(format!("{id} was never enforced"));
        }
        match state(prior) {
            Some("thaw" | "lift_limits") => Err(format!("{id} was already released")),
            Some("kill") => Err(format!("{id} was already killed")),
            _ => Ok(()),
        }
    }

    fn remove_rules(&self, prior: &[ActionRecord], unit: &str, acts: &mut Vec<ActionRecord>) {
        for h in live_rules(prior) {
            let r = self.nft.remove(h);
            acts.push(act("nft_remove", Some(unit), vec![], r.map(|()| Some(h))));
        }
    }

    fn conclude(
        &mut self,
        id: &str,
        acts: Vec<ActionRecord>,
        what: &str,
    ) -> Result<String, String> {
        let errs: Vec<String> = acts.iter().filter_map(|a| a.error.clone()).collect();
        self.finish(id, acts, None);
        if errs.is_empty() {
            Ok(format!("{what} {id}"))
        } else {
            Err(format!("{id}: {}", errs.join("; ")))
        }
    }

    /// Records `acts` on the incident, counts them, and sends each
    /// failure to telemetry.
    fn finish(&mut self, id: &str, acts: Vec<ActionRecord>, verdict: Option<&'static str>) {
        let n_ok = acts.iter().filter(|a| a.ok).count() as u64;
        self.ok.fetch_add(n_ok, Ordering::Relaxed);
        self.failed
            .fetch_add(acts.len() as u64 - n_ok, Ordering::Relaxed);
        let iid = IncidentId(id.into());
        // The loop queues the incident's record before its first job, but
        // the writer thread may not have written it yet.
        for _ in 0..50 {
            if self.store.get(&iid).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let failures: Vec<String> = acts.iter().filter_map(|a| a.error.clone()).collect();
        if let Err(e) = self.store.add_actions(&iid, acts, verdict) {
            eprintln!("aegisd: recording enforcement on {id} failed: {e:#}");
        }
        let inc = self.store.get(&iid);
        for err in failures {
            eprintln!("aegisd: enforcement failed on {id}: {err}");
            let (tier, verdict) = match inc.as_ref().map(|i| i.verdict.as_str()) {
                Some("quarantined") => (Tier::Quarantine, "quarantined"),
                Some("would_quarantine") => (Tier::Quarantine, "would_quarantine"),
                Some("throttled") => (Tier::Throttle, "throttled"),
                _ => (Tier::Throttle, "would_throttle"),
            };
            self.sinks.emit(&TelemetryRecord {
                ts_unix_ns: now_ns(),
                incident: id.into(),
                tier,
                verdict,
                score: inc.as_ref().map_or(0.0, |i| i.score),
                mode: Mode::Enforce,
                tgid: inc.as_ref().map_or(0, |i| i.root.tgid),
                comm: inc
                    .as_ref()
                    .map(|i| i.root.comm.clone())
                    .unwrap_or_default(),
                exe: inc
                    .as_ref()
                    .and_then(|i| i.root.exe.clone())
                    .map(String::into_bytes),
                target: None,
                reasons: vec![format!("enforcement failed: {err}")],
            });
        }
    }
}

fn tgids(pids: &[ProcKey]) -> Vec<u32> {
    pids.iter().map(|k| k.tgid).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    use aegis_common::{Event, EventKind};
    use anyhow::bail;

    use crate::config::Mode;
    use crate::incident::IncidentId;
    use crate::proctable::ProcInfo;
    use crate::scoring::{Decision, Evidence, Signal, Tier};
    use crate::verify::Verification;

    thread_local! {
        static CALLS: RefCell<Vec<Vec<String>>> = const { RefCell::new(Vec::new()) };
    }

    /// Records `prog args…`; nft's echo carries rule handle 7.
    fn ok(prog: &str, a: &[String]) -> Result<String> {
        CALLS.with(|c| c.borrow_mut().push([&[prog.to_string()], a].concat()));
        Ok(if a.first().is_some_and(|s| s == "--echo") {
            "add rule inet aegis out ... drop # handle 7\n".into()
        } else {
            String::new()
        })
    }
    fn fail_freeze(prog: &str, a: &[String]) -> Result<String> {
        if a.first().is_some_and(|s| s == "freeze") {
            CALLS.with(|c| c.borrow_mut().push([&[prog.to_string()], a].concat()));
            bail!("systemctl freeze: exit Some(1): no such unit")
        }
        ok(prog, a)
    }
    fn alive(_: u32, _: u64) -> bool {
        true
    }
    fn take() -> Vec<Vec<String>> {
        CALLS.with(|c| c.take())
    }

    fn k(tgid: u32) -> ProcKey {
        ProcKey {
            tgid,
            start_time_ns: 100 + u64::from(tgid),
        }
    }

    fn proc(tgid: u32) -> ProcInfo {
        ProcInfo {
            key: k(tgid),
            parent: None,
            exe: Some(PathBuf::from("/tmp/x")),
            exe_id: None,
            comm: "x".into(),
            uid: 1000,
            has_tty: false,
            selinux_domain: None,
            verification: Verification::Unverified,
            cgroup_id: 0,
            env_taint: None,
            env_pending: false,
            ptraced: false,
        }
    }

    struct Fx {
        e: Enforcer,
        id: String,
        dir: PathBuf,
    }
    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
            let _ = std::fs::remove_file(self.dir.with_extension("jsonl"));
        }
    }

    /// An enforcer over a store holding one would_quarantine incident for
    /// tgid 10, telemetry going to `<dir>.jsonl`.
    fn fx(name: &str, run: Run) -> Fx {
        take();
        let dir = std::env::temp_dir().join(format!("aegis-enf-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = IncidentStore::open_at(&dir, Some("boot".into()), 0).unwrap();
        let d = Decision {
            key: k(10),
            score: 90.0,
            tier: Tier::Quarantine,
            evidence: vec![Evidence {
                signal: Signal::TmpExec,
                base: 90.0,
                modifier: 1.0,
                reason: "r".into(),
                ts_ns: 1,
            }],
        };
        let id = store.record(&d, &[proc(10)], Mode::Enforce).unwrap().0;
        let e = Enforcer {
            store: Arc::new(store),
            holds: Holds::default(),
            sys: Systemd::with(run, alive),
            nft: Nft::with(run),
            limits: Limits {
                cpu_quota_percent: 25,
                memory_high_bytes: 256 << 20,
            },
            sinks: Arc::new(Sinks::jsonl_at(&dir.with_extension("jsonl"))),
            ok: Arc::default(),
            failed: Arc::default(),
        };
        Fx { e, id, dir }
    }

    impl Fx {
        fn incident(&self) -> crate::incident::Incident {
            self.e.store.get(&IncidentId(self.id.clone())).unwrap()
        }
        fn kinds(&self) -> Vec<(String, bool)> {
            self.incident()
                .actions
                .iter()
                .map(|a| (a.kind.clone(), a.ok))
                .collect()
        }
    }

    /// Builds a table from (child, parent) forks, parents first.
    fn table(forks: &[(u32, u32)]) -> ProcTable {
        let mut t = ProcTable::new();
        for &(child, parent) in forks {
            // SAFETY: Event is plain old data; all-zero is valid.
            let mut e: Event = unsafe { std::mem::zeroed() };
            e.kind = EventKind::Fork as u32;
            e.tgid = parent;
            e.start_time_ns = 100 + u64::from(parent);
            e.child_tgid = child;
            e.child_start_time_ns = 100 + u64::from(child);
            t.apply(&e);
        }
        t
    }

    #[test]
    fn target_set_never_includes_ancestors() {
        // 1 -> 50 (bash) -> 80 (member) -> 81 (its child, unscored).
        let t = table(&[(50, 1), (80, 50), (81, 80)]);
        let got = target_set(&t, &[k(80)], 999);
        assert_eq!(got, [k(80), k(81)]);
    }

    #[test]
    fn target_set_keeps_a_member_above_another_and_what_lies_between() {
        // 80 and 86 are members; 85, between them, is under 80.
        let t = table(&[(50, 1), (80, 50), (85, 80), (86, 85)]);
        let got = target_set(&t, &[k(86), k(80)], 999);
        assert_eq!(got, [k(80), k(85), k(86)]);
    }

    #[test]
    fn target_set_excludes_aegisd() {
        let t = table(&[(50, 1), (80, 50), (81, 80)]);
        assert_eq!(target_set(&t, &[k(80)], 80), [k(81)]);
        // pid 1 and kthreadd, even named as members.
        assert_eq!(target_set(&t, &[k(1)], 999), [k(50), k(80), k(81)]);
        // A member no longer in the table is gone: nothing to act on.
        assert!(target_set(&t, &[k(70)], 999).is_empty());
    }

    #[test]
    fn quarantine_records_hold_scope_freeze_nft() {
        let mut f = fx("q", ok);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10), k(11)],
        });
        let unit = format!("aegis-incident-{}-q.scope", f.id);
        let c = take();
        let heads: Vec<Vec<&str>> = c
            .iter()
            .map(|a| a.iter().take(2).map(String::as_str).collect())
            .collect();
        assert_eq!(
            heads,
            [
                vec!["/usr/bin/busctl", "call"],
                vec!["/usr/bin/systemctl", "freeze"],
                vec!["/usr/sbin/nft", "add"],
                vec!["/usr/sbin/nft", "add"],
                vec!["/usr/sbin/nft", "--echo"],
            ]
        );
        assert!(c[0].contains(&unit) && c[0].contains(&"aegis-quarantine.slice".into()));
        assert_eq!(c[1][2], unit);
        let cg = format!("aegis.slice/aegis-quarantine.slice/{unit}");
        assert!(c[4].contains(&cg), "{:?}", c[4]);
        let inc = f.incident();
        assert_eq!(inc.verdict, "quarantined");
        assert_eq!(
            f.kinds(),
            [
                ("hold".into(), true),
                ("scope".into(), true),
                ("freeze".into(), true),
                ("nft_drop".into(), true)
            ]
        );
        assert_eq!(inc.actions[0].pids, [10, 11]);
        assert_eq!(inc.actions[3].nft_handle, Some(7));
        assert_eq!(f.e.holds.held(), 2);
        assert_eq!(f.e.ok.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn quarantine_failure_keeps_hold_and_would_verdict() {
        let mut f = fx("qfail", fail_freeze);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10), k(11)],
        });
        let inc = f.incident();
        assert_eq!(inc.verdict, "would_quarantine");
        assert_eq!(f.e.holds.held(), 2);
        let freeze = inc.actions.iter().find(|a| a.kind == "freeze").unwrap();
        assert!(!freeze.ok);
        assert!(freeze.error.as_deref().unwrap().contains("no such unit"));
        assert_eq!(f.e.failed.load(Ordering::Relaxed), 1);
        let log = std::fs::read_to_string(f.dir.with_extension("jsonl")).unwrap();
        assert!(
            log.contains("enforcement failed: systemctl freeze"),
            "{log}"
        );
    }

    #[test]
    fn newcomer_is_attached_to_the_frozen_scope() {
        let mut f = fx("attach", ok);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        take();
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(12)],
        });
        // Attached, not a second StartTransientUnit; no second freeze or
        // rule, since the cgroup already has both.
        let c = take();
        assert_eq!(c.len(), 1, "{c:?}");
        assert!(c[0].contains(&"AttachProcessesToUnit".into()));
        assert_eq!(f.e.holds.held(), 2);
        let kinds = f.kinds();
        assert_eq!(kinds[4..], [("hold".into(), true), ("attach".into(), true)]);
    }

    #[test]
    fn throttle_starts_a_limited_scope() {
        let mut f = fx("t", ok);
        f.e.run(EnforceJob::Throttle {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let c = take();
        assert_eq!(c.len(), 1);
        let unit = format!("aegis-incident-{}.scope", f.id);
        assert!(c[0].contains(&unit) && c[0].contains(&"aegis-throttle.slice".into()));
        assert!(c[0].contains(&"CPUQuotaPerSecUSec".into()));
        assert_eq!(f.kinds(), [("scope".into(), true)]);
        assert_eq!(f.e.holds.held(), 0);
    }

    fn reply() -> (
        Option<Reply>,
        tokio::sync::oneshot::Receiver<Result<String, String>>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (Some(tx), rx)
    }

    #[test]
    fn release_thaws_unholds_and_removes_the_rule() {
        let mut f = fx("rel", ok);
        let (r, mut rx) = reply();
        f.e.run(EnforceJob::Release {
            id: f.id.clone(),
            reply: r,
        });
        assert_eq!(
            rx.try_recv().unwrap(),
            Err(format!("{} was never enforced", f.id))
        );
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        take();
        let (r, mut rx) = reply();
        f.e.run(EnforceJob::Release {
            id: f.id.clone(),
            reply: r,
        });
        assert!(rx.try_recv().unwrap().is_ok());
        let c = take();
        assert_eq!(
            c[0][1..3],
            [
                "thaw".to_string(),
                format!("aegis-incident-{}-q.scope", f.id)
            ]
        );
        assert_eq!(c[1][1..3], ["delete".to_string(), "rule".into()]);
        assert_eq!(c[1].last().unwrap(), "7");
        assert_eq!(f.e.holds.held(), 0);
        let kinds = f.kinds();
        assert_eq!(
            kinds[4..],
            [
                ("thaw".into(), true),
                ("unhold".into(), true),
                ("nft_remove".into(), true)
            ]
        );
        // Released once: a second release changes nothing.
        let (r, mut rx) = reply();
        f.e.run(EnforceJob::Release {
            id: f.id.clone(),
            reply: r,
        });
        assert!(rx.try_recv().unwrap().is_err());
        assert!(take().is_empty());
    }

    #[test]
    fn kill_is_refused_on_a_throttle_only_incident() {
        let mut f = fx("kill-t", ok);
        f.e.run(EnforceJob::Throttle {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        take();
        let (r, mut rx) = reply();
        f.e.run(EnforceJob::Kill {
            id: f.id.clone(),
            reply: r,
        });
        assert_eq!(
            rx.try_recv().unwrap(),
            Err(format!("{} was only throttled; release it instead", f.id))
        );
        assert!(take().is_empty());
    }

    #[test]
    fn kill_sigkills_the_scope_and_removes_the_rule() {
        let mut f = fx("kill-q", ok);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        take();
        f.e.run(EnforceJob::Kill {
            id: f.id.clone(),
            reply: None,
        });
        let c = take();
        assert_eq!(c[0][1..3], ["kill".to_string(), "--signal=SIGKILL".into()]);
        assert_eq!(c[1][1..3], ["delete".to_string(), "rule".into()]);
        let kinds = f.kinds();
        assert_eq!(
            kinds[4..],
            [("kill".into(), true), ("nft_remove".into(), true)]
        );
    }
}
