// SPDX-License-Identifier: MIT OR Apache-2.0
//! The enforcer: one thread that turns a throttle or quarantine verdict
//! into systemd scopes, kernel holds and an nftables rule, and records
//! every step on the incident. The event loop only queues jobs here, so
//! a slow systemd never holds up detection.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use super::nft::Nft;
#[cfg(test)]
use super::systemd::Run;
use super::systemd::{Limits, Systemd};
use crate::config::Mode;
use crate::ebpf::Holds;
use crate::incident::{verdict_rank, ActionRecord, IncidentId, IncidentStore};
use crate::pipeline::{proc_start_matches, proc_stat};
use crate::proctable::{ProcKey, ProcTable};
use crate::scoring::Tier;
use crate::telemetry::{now_ns, rfc3339, Sinks, TelemetryRecord};

/// Jobs waiting for the enforcer; past this the loop drops and counts.
const QUEUE: usize = 256;
const QUARANTINE_SLICE: &str = "aegis-quarantine.slice";
const THROTTLE_SLICE: &str = "aegis-throttle.slice";
/// How long a throttle or quarantine waits for the writer thread to
/// create its incident. Nothing is done to a tree that has no record.
const INCIDENT_WAIT: Duration = Duration::from_secs(5);
/// Most processes the `/proc` children walk adds to one quarantine: a
/// tree that forks faster than it can be read is cut off, not chased.
const MAX_FOUND: usize = 1024;
/// Fork jobs may fill only this much of the queue. The rest is kept for
/// escalations, scored newcomers, releases and kills, so a tree forking
/// in a loop can never crowd those out.
const FORK_SLOTS: usize = QUEUE / 2;
/// How long a failed freeze waits before its one retry.
const FREEZE_RETRY: Duration = Duration::from_millis(200);

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
    /// A child forked by a process the incident's throttle or
    /// quarantine already covers; it joins at the same tier.
    Fork {
        id: String,
        tier: Tier,
        pid: ProcKey,
    },
    // Sent by `aegisctl incidents release|kill`.
    Release {
        id: String,
        reply: Option<Reply>,
    },
    Kill {
        id: String,
        reply: Option<Reply>,
    },
    /// Sent every 10 seconds: put back any quarantined tree's drop rule
    /// that a ruleset flush removed.
    Reassert,
}

pub struct EnforcerHandle {
    pub tx: SyncSender<EnforceJob>,
    /// Jobs dropped: the queue was full, or a reload to audit came
    /// while they waited.
    pub dropped: Arc<AtomicU64>,
    pub actions_ok: Arc<AtomicU64>,
    pub actions_failed: Arc<AtomicU64>,
    /// Fork jobs in the queue now; the enforcer counts them down.
    forks: Arc<AtomicUsize>,
    sinks: Arc<Sinks>,
    /// Fork jobs are being dropped and that has been logged.
    fork_drops_logged: AtomicBool,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EnforcerHandle {
    fn new(tx: SyncSender<EnforceJob>, sinks: Arc<Sinks>) -> Self {
        Self {
            tx,
            dropped: Arc::default(),
            actions_ok: Arc::default(),
            actions_failed: Arc::default(),
            forks: Arc::default(),
            sinks,
            fork_drops_logged: AtomicBool::new(false),
            thread: None,
        }
    }

    /// Closes the queue and waits up to `cap` for the enforcer to finish
    /// the job in hand and those still queued. False if it hadn't.
    pub fn shutdown(self, cap: Duration) -> bool {
        let Self { tx, thread, .. } = self;
        drop(tx);
        let Some(t) = thread else { return true };
        let until = std::time::Instant::now() + cap;
        while !t.is_finished() {
            if std::time::Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = t.join();
        true
    }

    /// Queues a job without waiting. Fork jobs take at most
    /// `FORK_SLOTS`. A dropped job is counted (`aegisctl status`) and
    /// logged; a dropped throttle or quarantine also goes to telemetry,
    /// so a webhook says the tree was left alone.
    pub fn queue(&self, job: EnforceJob) {
        self.queue_about(job, |_, _| (0.0, String::new()));
    }

    /// `queue`, with `about` giving a dropped job's incident score and
    /// root process name (from its id and first process) for telemetry.
    pub fn queue_about(
        &self,
        job: EnforceJob,
        about: impl FnOnce(&str, Option<ProcKey>) -> (f64, String),
    ) {
        let fork = matches!(job, EnforceJob::Fork { .. });
        if fork {
            if self.forks.load(Ordering::Relaxed) >= FORK_SLOTS {
                return self.drop_job(&job, about);
            }
            self.forks.fetch_add(1, Ordering::Relaxed);
        }
        match self.tx.try_send(job) {
            Ok(()) => {
                if fork {
                    self.fork_drops_logged.store(false, Ordering::Relaxed);
                }
            }
            Err(TrySendError::Full(job) | TrySendError::Disconnected(job)) => {
                if fork {
                    self.forks.fetch_sub(1, Ordering::Relaxed);
                }
                self.drop_job(&job, about);
            }
        }
    }

    fn drop_job(
        &self,
        job: &EnforceJob,
        about: impl FnOnce(&str, Option<ProcKey>) -> (f64, String),
    ) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        let (id, tier, pid) = match job {
            EnforceJob::Fork { id, .. } => {
                // A forking tree can drop thousands: log the first.
                if !self.fork_drops_logged.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "aegisd: {id}: enforcer busy, dropping jobs for forked children \
                         (counted in aegisctl status)"
                    );
                }
                return;
            }
            EnforceJob::Throttle { id, pids } => (id, Tier::Throttle, pids.first()),
            EnforceJob::Quarantine { id, pids } => (id, Tier::Quarantine, pids.first()),
            EnforceJob::Release { .. } | EnforceJob::Kill { .. } | EnforceJob::Reassert => return,
        };
        let reason = "enforcement failed: queue full, nothing was done".to_string();
        eprintln!("aegisd: {id}: {reason}");
        let (score, comm) = about(id, pid.copied());
        self.sinks.emit(&TelemetryRecord {
            ts_unix_ns: now_ns(),
            incident: id.clone(),
            tier,
            verdict: crate::incident::verdict(tier).unwrap_or("would_throttle"),
            score,
            mode: Mode::Enforce,
            tgid: pid.map_or(0, |k| k.tgid),
            comm,
            exe: None,
            target: None,
            reasons: vec![reason],
        });
    }
}

pub fn spawn_enforcer(
    store: Arc<IncidentStore>,
    holds: Holds,
    sys: Systemd,
    nft: Nft,
    limits: Limits,
    sinks: Arc<Sinks>,
    enforcing: Arc<AtomicBool>,
) -> EnforcerHandle {
    let (tx, rx) = sync_channel(QUEUE);
    let mut h = EnforcerHandle::new(tx, sinks.clone());
    let mut e = Enforcer {
        store,
        holds,
        sys,
        nft,
        limits,
        sinks,
        ok: h.actions_ok.clone(),
        failed: h.actions_failed.clone(),
        enforcing,
        dropped: h.dropped.clone(),
        wait: INCIDENT_WAIT,
        unsaved: HashMap::new(),
        children: proc_children,
        forks: h.forks.clone(),
    };
    let t = std::thread::Builder::new()
        .name("aegis-enforce".into())
        .spawn(move || {
            for job in rx {
                e.run(job);
            }
        })
        .expect("spawning the enforcer thread");
    h.thread = Some(t);
    h
}

/// Live members and every live descendant of one, by tgid. Each process
/// is kept only if it or something above it is a member, so an ancestor
/// of the tree (the admin's shell, sshd) is never reached; a process
/// between two members is under the upper one and is kept. pid 1,
/// kthreadd and aegisd are dropped whatever the table says.
// Walks every process's parent chain, O(table x depth); index
// children by parent if incidents get large. `parent_chain` stops at 64
// levels, so a descendant deeper than that below a member is left out:
// it fails towards acting on less.
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

/// Children of `k` from `/proc/<tgid>/task/*/children`; nothing once
/// `k` is no longer that process.
fn proc_children(k: ProcKey) -> Vec<ProcKey> {
    if !proc_start_matches(k.tgid, k.start_time_ns) {
        return Vec::new();
    }
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{}/task", k.tgid)) else {
        return Vec::new();
    };
    let listed = tasks
        .flatten()
        .filter_map(|t| std::fs::read_to_string(t.path().join("children")).ok())
        .flat_map(|s| {
            s.split_whitespace()
                .filter_map(|c| c.parse().ok())
                .collect::<Vec<u32>>()
        })
        .collect();
    still_children(k.tgid, listed, proc_stat)
}

/// The listed pids `stat` still shows as children of `parent`, keyed by
/// the start time from the same read. A child that exited after it was
/// listed, its pid taken by a stranger, is left out.
fn still_children(
    parent: u32,
    listed: Vec<u32>,
    stat: fn(u32) -> Option<(u32, u64)>,
) -> Vec<ProcKey> {
    listed
        .into_iter()
        .filter_map(|tgid| {
            let (ppid, start_time_ns) = stat(tgid)?;
            (ppid == parent).then_some(ProcKey {
                tgid,
                start_time_ns,
            })
        })
        .collect()
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
        start_times: Vec::new(),
        error,
        detail: None,
        ts: rfc3339(now_ns()),
    }
}

/// The last thing that changed the tree's state, ignoring bookkeeping
/// (holds, rules): a scope, attach or freeze means enforced; thaw,
/// lift_limits or kill means an admin already ended it, and expired
/// that it was from an earlier boot.
fn last_state(acts: &[ActionRecord]) -> Option<&ActionRecord> {
    acts.iter().rev().filter(|a| a.ok).find(|a| {
        matches!(
            a.kind.as_str(),
            "scope" | "attach" | "freeze" | "thaw" | "lift_limits" | "kill" | "expired"
        )
    })
}

fn state(acts: &[ActionRecord]) -> Option<&str> {
    last_state(acts).map(|a| a.kind.as_str())
}

/// What enforcement left in place, for `incidents list`: held (scoped,
/// frozen or only held), released, killed, or expired (an earlier
/// boot). None if nothing was ever enforced.
pub fn summary_state(acts: &[ActionRecord]) -> Option<&'static str> {
    if !acts.iter().any(|a| a.ok || holding(a)) {
        return None;
    }
    Some(match state(acts) {
        Some("thaw" | "lift_limits") => "released",
        Some("kill") => "killed",
        Some("expired") => "expired",
        _ => "held",
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
    /// The daemon's mode now, which a reload can change while jobs wait.
    enforcing: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    wait: Duration,
    /// Actions done but not yet on the incident (its write failed), and
    /// the verdict they earned. Release and kill read these too, and the
    /// next job for the incident writes them first.
    unsaved: HashMap<String, (Vec<ActionRecord>, Option<&'static str>)>,
    /// Lists a process's children; tests pass a fake.
    children: fn(ProcKey) -> Vec<ProcKey>,
    /// Shared with the handle: fork jobs still queued.
    forks: Arc<AtomicUsize>,
}

impl Enforcer {
    pub fn run(&mut self, job: EnforceJob) {
        match job {
            EnforceJob::Fork { id, tier, pid } => {
                let _ = self
                    .forks
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
                let pids = vec![pid];
                self.run(match tier {
                    Tier::Quarantine => EnforceJob::Quarantine { id, pids },
                    _ => EnforceJob::Throttle { id, pids },
                });
            }
            EnforceJob::Throttle { id, .. } | EnforceJob::Quarantine { id, .. }
                if !self.ready(&id) => {}
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
            EnforceJob::Reassert => self.reassert(),
        }
    }

    /// Whether a throttle or quarantine for `id` may act now: still in
    /// enforce mode, and the incident recorded. The mode is read again
    /// after the wait, since a reload to audit can land during it.
    fn ready(&self, id: &str) -> bool {
        let enforcing = || {
            let on = self.enforcing.load(Ordering::Relaxed);
            if !on {
                eprintln!("aegisd: audit mode now; enforcement for {id} dropped");
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            on
        };
        if !enforcing() {
            return false;
        }
        if !self.recorded(id) {
            self.report(id, "enforcement skipped: incident not recorded".into());
            return false;
        }
        enforcing()
    }

    /// Whether the incident exists, waiting for the writer thread if it
    /// has not got there yet: the loop queues the record first.
    fn recorded(&self, id: &str) -> bool {
        let iid = IncidentId(id.into());
        let until = std::time::Instant::now() + self.wait;
        loop {
            if self.store.get(&iid).is_some() {
                return true;
            }
            if std::time::Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn actions(&self, id: &str) -> Vec<ActionRecord> {
        let mut acts = self
            .store
            .get(&IncidentId(id.into()))
            .map(|i| i.actions)
            .unwrap_or_default();
        acts.extend(self.unsaved.get(id).into_iter().flat_map(|u| u.0.clone()));
        acts
    }

    fn throttle(&mut self, id: &str, pids: &[ProcKey]) {
        let unit = t_unit(id);
        // A newcomer to a throttled tree joins its scope. Anything else
        // stands: a throttle scope must never pull a frozen tree out of
        // its quarantine scope, nor undo a release.
        let prior = self.actions(id);
        let kind = match last_state(&prior) {
            // The tree's own move failed: a newcomer must not start the
            // scope with only itself in it.
            None if prior.iter().any(|a| a.kind == "scope") => return,
            None => "scope",
            Some(a)
                if matches!(a.kind.as_str(), "scope" | "attach")
                    && a.unit.as_deref() == Some(unit.as_str()) =>
            {
                "attach"
            }
            Some(_) => return,
        };
        let r = if kind == "scope" {
            self.sys
                .start_scope(&unit, THROTTLE_SLICE, pids, Some(self.limits))
        } else {
            match self.sys.attach(&unit, pids) {
                // All already in the scope (born there): nothing to
                // record, and no rewrite of incident.json per fork.
                Ok(false) => return,
                r => r.map(drop),
            }
        };
        let a = act(kind, Some(&unit), tgids(pids), r.map(|_| None));
        let v = a.ok.then_some("throttled");
        self.finish(id, vec![a], v);
    }

    /// `pids` and every descendant `/proc` lists below them, walked until
    /// nothing new turns up: children forked after the job was queued,
    /// or whose Fork event was lost. pid 1, kthreadd and aegisd are never
    /// added; nothing above `pids` is ever reached.
    fn with_children(&self, pids: &[ProcKey]) -> Vec<ProcKey> {
        let me = std::process::id();
        let mut seen: HashSet<u32> = pids.iter().map(|k| k.tgid).collect();
        let mut all = pids.to_vec();
        let mut i = 0;
        while i < all.len() && all.len() < pids.len() + MAX_FOUND {
            for c in (self.children)(all[i]) {
                if !matches!(c.tgid, 1 | 2) && c.tgid != me && seen.insert(c.tgid) {
                    all.push(c);
                }
            }
            i += 1;
        }
        all
    }

    /// Hold, move, freeze, cut off. Each step is recorded; the verdict
    /// becomes `quarantined` only once the tree is moved and frozen. If
    /// that fails the holds stay: they still stop the tree acting.
    fn quarantine(&mut self, id: &str, pids: &[ProcKey]) {
        let prior = self.actions(id);
        // An admin released or killed it; that stands.
        if matches!(state(&prior), Some("thaw" | "kill" | "expired")) || pids.is_empty() {
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
                Ok(()) => held.push(*k),
                Err(e) => errs.push(format!("{e:#}")),
            }
        }
        let r = if errs.is_empty() {
            Ok(None)
        } else {
            Err(anyhow::anyhow!(errs.join("; ")))
        };
        let mut a = act("hold", None, tgids(&held), r);
        a.start_times = held.iter().map(|k| k.start_time_ns).collect();
        acts.push(a);

        // The held can no longer fork, so this walk ends. What it finds
        // is moved and frozen with the tree but not held: /proc gives a
        // start time only to the clock tick, and the kernel matches holds
        // to the nanosecond. Each one's Fork event brings a job of its
        // own, with the exact key, that holds it.
        let all = self.with_children(pids);
        let pids = &all[..];

        // A newcomer joins the scope the tree is already in. If the
        // tree's own move failed it is only held, like the tree: a scope
        // holding the newcomer alone would freeze it and call the
        // incident quarantined.
        let tried = prior
            .iter()
            .any(|a| a.kind == "scope" && a.unit.as_deref() == Some(unit.as_str()));
        let moved = if scoped {
            self.attach(&unit, pids, &mut acts)
        } else if tried {
            false
        } else {
            let r = self.sys.start_scope(&unit, QUARANTINE_SLICE, pids, None);
            acts.push(act("scope", Some(&unit), tgids(pids), r.map(|_| None)));
            acts.last().unwrap().ok
        };
        let mut now_frozen = frozen;
        if moved && !frozen {
            let is_frozen = || matches!(self.sys.is_frozen(QUARANTINE_SLICE, &unit), Ok(true));
            let mut r = self.sys.freeze(&unit);
            if r.is_err() && !is_frozen() {
                // busctl returns once the start job is queued, not done:
                // on a loaded host the scope may not be active yet.
                std::thread::sleep(FREEZE_RETRY);
                r = self.sys.freeze(&unit);
            }
            // The command can fail after the freeze took effect; the
            // kernel has the last word. The error stays on the record.
            let mut a = act("freeze", Some(&unit), vec![], r.map(|_| None));
            if !a.ok {
                a.ok = is_frozen();
            }
            now_frozen = a.ok;
            acts.push(a);
        }
        if moved && now_frozen {
            // Once more: a child the walk found but couldn't hold may
            // have forked before the move, leaving its own child outside.
            // Joining the frozen scope stops it.
            let late = self.with_children(pids).split_off(pids.len());
            if !late.is_empty() {
                self.attach(&unit, &late, &mut acts);
            }
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

    /// Moves `pids` into the running quarantine scope and records it.
    /// Ok(false) moved nothing (all already in it, or exited), so it isn't
    /// recorded: an attach on the record names pids that were moved.
    /// True if the tree is in the scope.
    fn attach(&self, unit: &str, pids: &[ProcKey], acts: &mut Vec<ActionRecord>) -> bool {
        match self.sys.attach(unit, pids) {
            Ok(false) => true,
            r => {
                let a = act("attach", Some(unit), tgids(pids), r.map(|_| None));
                let ok = a.ok;
                acts.push(a);
                ok
            }
        }
    }

    fn release(&mut self, id: &str) -> Result<String, String> {
        let prior = self.actions(id);
        let unit = q_unit(id);
        self.refuse_ended(id, &prior)?;
        if let Some(r) = self.expire(id) {
            return r;
        }
        let quarantined = prior
            .iter()
            .any(|a| holding(a) || (a.ok && a.unit.as_deref() == Some(unit.as_str())));
        let mut acts = Vec::new();
        let mut done = format!("released {id}: limits lifted");
        if quarantined {
            // Unhold before the thaw: the tree is still frozen while the
            // holds come off, so it never wakes to find every write,
            // connect and fork refused.
            let keys: BTreeSet<(u32, u64)> = prior
                .iter()
                .filter(|a| a.kind == "hold")
                .flat_map(|a| a.pids.iter().copied().zip(a.start_times.iter().copied()))
                .collect();
            let errs: Vec<String> = keys
                .iter()
                .filter_map(|&(tgid, start_time_ns)| {
                    let k = ProcKey {
                        tgid,
                        start_time_ns,
                    };
                    self.holds.release(k).err().map(|e| format!("{e:#}"))
                })
                .collect();
            let r = if errs.is_empty() {
                Ok(None)
            } else {
                Err(anyhow::anyhow!(errs.join("; ")))
            };
            acts.push(act("unhold", None, keys.iter().map(|k| k.0).collect(), r));
            // Always thaw: a freeze recorded as failed may still have
            // taken effect, and thawing an unfrozen unit is harmless.
            if prior.iter().any(|a| a.ok && a.kind == "scope") {
                let r = self.sys.thaw(&unit);
                let mut a = act("thaw", Some(&unit), vec![], r.map(|_| None));
                if !a.ok {
                    a.ok = matches!(self.sys.is_frozen(QUARANTINE_SLICE, &unit), Ok(false));
                }
                acts.push(a);
            }
            let found = self.find_rules(&prior, &unit);
            let gone = self.remove_rules(found, &unit, &mut acts);
            done = format!("released {id}: thawed, network restored{gone}");
            // The tree stays in its -q scope, so its accounting
            // lives under aegis-quarantine.slice. Moving it back to its
            // original unit is AttachProcessesToUnit, if that's ever wanted.
        } else {
            let t = t_unit(id);
            let r = self.sys.lift_limits(&t);
            acts.push(act("lift_limits", Some(&t), vec![], r.map(|_| None)));
        }
        self.conclude(id, acts, done)
    }

    fn kill(&mut self, id: &str) -> Result<String, String> {
        let prior = self.actions(id);
        let unit = q_unit(id);
        self.refuse_ended(id, &prior)?;
        if let Some(r) = self.expire(id) {
            return r;
        }
        if !prior
            .iter()
            .any(|a| a.ok && a.unit.as_deref() == Some(unit.as_str()))
        {
            if prior.iter().any(holding) {
                return Err(format!("{id} was never moved into its scope; release it"));
            }
            return Err(format!("{id} was only throttled; release it instead"));
        }
        // Looked up first: once the scope empties its cgroup goes, and
        // nft shows the rule by a bare id, no longer by the path.
        let found = self.find_rules(&prior, &unit);
        // A frozen cgroup still takes SIGKILL.
        let r = self.sys.kill(&unit);
        let mut acts = vec![act("kill", Some(&unit), vec![], r.map(|_| None))];
        let gone = self.remove_rules(found, &unit, &mut acts);
        self.conclude(id, acts, format!("killed {id}{gone}"))
    }

    /// Refuses an incident never enforced, or already released or killed.
    fn refuse_ended(&self, id: &str, prior: &[ActionRecord]) -> Result<(), String> {
        if !prior.iter().any(|a| a.ok || holding(a)) {
            return Err(format!("{id} was never enforced"));
        }
        match state(prior) {
            Some("thaw" | "lift_limits") => Err(format!("{id} is already released")),
            Some("kill") => Err(format!("{id} is already killed")),
            Some("expired") => Err(format!("{id} is from an earlier boot and already ended")),
            _ => Ok(()),
        }
    }

    /// An incident from an earlier boot: its scope and rule went with
    /// that boot, and its tgids and nft handles may name something else
    /// now. Nothing on the host is touched; it is recorded as ended.
    fn expire(&mut self, id: &str) -> Option<Result<String, String>> {
        if !self.earlier_boot(id)? {
            return None;
        }
        let a = act("expired", None, vec![], Ok(None));
        Some(self.conclude(
            id,
            vec![a],
            format!("{id} is from an earlier boot; nothing of it is left on this host"),
        ))
    }

    /// Whether the incident is from an earlier boot; None if unknown.
    fn earlier_boot(&self, id: &str) -> Option<bool> {
        let now = self.store.boot_id().unwrap_or_default();
        Some(self.store.get(&IncidentId(id.into()))?.boot_id != now)
    }

    /// The incident's drop rules as the live chain shows them, by its
    /// cgroup path: after a ruleset flush a recorded handle may belong to
    /// another incident's rule. Once the scope is gone nft shows a bare
    /// cgroup id instead, and then a recorded handle counts only if its
    /// line is one of those. None if no rule was ever added.
    fn find_rules(&self, prior: &[ActionRecord], unit: &str) -> Option<Result<Vec<u64>>> {
        if !prior.iter().any(|a| a.ok && a.kind == "nft_drop") {
            return None;
        }
        let cg = Nft::scope_cgroup(QUARANTINE_SLICE, unit);
        Some(self.nft.list().map(|l| {
            let l = l.unwrap_or_default();
            let live = Nft::handles(&l, &cg);
            if !live.is_empty() {
                return live;
            }
            let bare = Nft::unresolved(&l);
            live_rules(prior)
                .into_iter()
                .filter(|h| bare.contains(h))
                .collect()
        }))
    }

    /// Deletes what `find_rules` found. Returns what the reply should add
    /// when there was no rule left to delete.
    fn remove_rules(
        &self,
        found: Option<Result<Vec<u64>>>,
        unit: &str,
        acts: &mut Vec<ActionRecord>,
    ) -> &'static str {
        let live = match found {
            None => return "",
            Some(Ok(live)) => live,
            Some(Err(e)) => {
                acts.push(act("nft_remove", Some(unit), vec![], Err(e)));
                return "";
            }
        };
        if live.is_empty() {
            let mut a = act("nft_remove", Some(unit), vec![], Ok(None));
            a.detail = Some("the rule was already gone".into());
            acts.push(a);
            return "; its drop rule was already gone";
        }
        for h in live {
            let r = self.nft.remove(h);
            acts.push(act("nft_remove", Some(unit), vec![], r.map(|()| Some(h))));
        }
        ""
    }

    /// Puts back the drop rule of each tree still quarantined in this
    /// boot whose rule a ruleset flush removed, recreating the table if
    /// it went too. A poll, so a tree can have its network for up to
    /// one interval. Nothing quarantined, no nft call. In audit mode it
    /// only restores a rule enforce mode added; a tree whose first rule
    /// failed gets one late only in enforce mode.
    fn reassert(&mut self) {
        let enforcing = self.enforcing.load(Ordering::Relaxed);
        let ids: Vec<String> = self
            .store
            .list()
            .into_iter()
            .filter(|s| s.verdict == "quarantined")
            .map(|s| s.id)
            .filter(|id| self.earlier_boot(id) == Some(false))
            .filter(|id| {
                let acts = self.actions(id);
                matches!(state(&acts), Some("scope" | "attach" | "freeze"))
                    && (enforcing || acts.iter().any(|a| a.ok && a.kind == "nft_drop"))
            })
            // A tree no longer frozen has exited, leaving no cgroup for
            // a rule to match, or was thawed outside aegisctl.
            .filter(|id| matches!(self.sys.is_frozen(QUARANTINE_SLICE, &q_unit(id)), Ok(true)))
            .collect();
        if ids.is_empty() {
            return;
        }
        let (listing, why) = match self.nft.list() {
            Ok(Some(l)) => (l, "re-added after the rule was removed"),
            Ok(None) => match self.nft.ensure_table() {
                Ok(()) => (String::new(), "re-added after the table was removed"),
                Err(e) => return eprintln!("aegisd: recreating the nft table: {e:#}"),
            },
            Err(e) => return eprintln!("aegisd: listing the nft table: {e:#}"),
        };
        for id in ids {
            let unit = q_unit(&id);
            let cg = Nft::scope_cgroup(QUARANTINE_SLICE, &unit);
            if !Nft::handles(&listing, &cg).is_empty() {
                continue;
            }
            let had = self
                .actions(&id)
                .iter()
                .any(|a| a.ok && a.kind == "nft_drop");
            let r = self.nft.drop_cgroup(&cg);
            let mut a = act("nft_drop", Some(&unit), vec![], r.map(Some));
            let why = if had {
                why
            } else {
                "added late: the first attempt failed"
            };
            a.detail = Some(why.into());
            if a.ok {
                eprintln!("aegisd: {id}: drop rule {why}");
            } else if self
                .actions(&id)
                .iter()
                .rev()
                .find(|a| a.kind == "nft_drop")
                .is_some_and(|a| !a.ok)
            {
                // Already on the record as failing: say it again only
                // in the journal, not every 10 seconds on the incident.
                eprintln!("aegisd: {id}: {}", a.error.unwrap_or_default());
                continue;
            }
            self.finish(&id, vec![a], None);
        }
    }

    fn conclude(
        &mut self,
        id: &str,
        acts: Vec<ActionRecord>,
        done: String,
    ) -> Result<String, String> {
        let errs: Vec<String> = acts
            .iter()
            .filter(|a| !a.ok)
            .filter_map(|a| a.error.clone())
            .collect();
        self.finish(id, acts, None);
        if errs.is_empty() {
            Ok(done)
        } else {
            Err(format!("{id}: {}", errs.join("; ")))
        }
    }

    /// Records `acts` on the incident, counts them, and sends each
    /// failure to telemetry. Actions an earlier write lost go first.
    fn finish(&mut self, id: &str, acts: Vec<ActionRecord>, verdict: Option<&'static str>) {
        let n_ok = acts.iter().filter(|a| a.ok).count() as u64;
        self.ok.fetch_add(n_ok, Ordering::Relaxed);
        self.failed
            .fetch_add(acts.len() as u64 - n_ok, Ordering::Relaxed);
        let failures: Vec<String> = acts
            .iter()
            .filter(|a| !a.ok)
            .filter_map(|a| a.error.clone())
            .collect();
        let (mut all, earlier) = self.unsaved.remove(id).unwrap_or_default();
        all.extend(acts);
        let verdict = verdict.or(earlier);
        let iid = IncidentId(id.into());
        let before = self.store.get(&iid).map_or(0, |i| verdict_rank(&i.verdict));
        let saved = self.store.add_actions(&iid, all.clone(), verdict);
        // Say so once, when the verdict rises: a newcomer joining a
        // tree already quarantined is not news.
        if let (Ok(()), Some(v)) = (&saved, verdict) {
            if verdict_rank(v) > before {
                self.report(id, done(v, &all));
            }
        }
        if let Err(e) = saved {
            self.failed.fetch_add(1, Ordering::Relaxed);
            // Nothing else knows what is now on the host: say what to undo.
            let mut undo: Vec<String> = all
                .iter()
                .filter(|a| a.ok)
                .filter_map(|a| a.unit.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            undo.extend(live_rules(&all).iter().map(|h| format!("nft handle {h}")));
            self.report(
                id,
                format!(
                    "enforcement failed: recording actions: {e:#}; on the host: {}",
                    undo.join(", ")
                ),
            );
            self.unsaved.insert(id.into(), (all, verdict));
        }
        for err in failures {
            self.report(id, format!("enforcement failed: {err}"));
        }
    }

    /// Logs `reason` and sends it to telemetry, against the incident as
    /// it stands now.
    fn report(&self, id: &str, reason: String) {
        eprintln!("aegisd: {id}: {reason}");
        let inc = self.store.get(&IncidentId(id.into()));
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
            reasons: vec![reason],
        });
    }
}

/// The reason on the record that announces a verdict the enforcer
/// earned.
fn done(verdict: &str, acts: &[ActionRecord]) -> String {
    if verdict == "throttled" {
        return "enforcement done: moved into a CPU and memory limited scope".into();
    }
    let mut words: Vec<&str> = acts
        .iter()
        .filter(|a| a.ok)
        .filter_map(|a| match a.kind.as_str() {
            // Only the job's own processes are held; walked children
            // are moved and frozen.
            "hold" => Some("members held"),
            "scope" | "attach" => Some("moved"),
            "freeze" => Some("frozen"),
            "nft_drop" => Some("egress dropped"),
            _ => None,
        })
        .collect();
    words.dedup();
    format!("enforcement done: {}", words.join(", "))
}

/// A hold that left pids held, even if part of it failed.
fn holding(a: &ActionRecord) -> bool {
    a.kind == "hold" && (a.ok || !a.pids.is_empty())
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
        /// The fake nft's `inet aegis out`: None while there is no table.
        static TABLE: RefCell<Option<FakeTable>> = const { RefCell::new(None) };
        /// Cgroups that no longer exist: nft lists their rules by id.
        static GONE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    /// Records `prog args…`. nft keeps its table in TABLE, where a new
    /// table's first rule gets handle 7.
    fn ok(prog: &str, a: &[String]) -> Result<String> {
        CALLS.with(|c| c.borrow_mut().push([&[prog.to_string()], a].concat()));
        if prog != "/usr/sbin/nft" {
            return Ok(String::new());
        }
        TABLE.with(|t| fake_nft(&mut t.borrow_mut(), a))
    }

    /// The next handle, and each rule's (handle, cgroup path).
    type FakeTable = (u64, Vec<(u64, String)>);

    fn fake_nft(t: &mut Option<FakeTable>, a: &[String]) -> Result<String> {
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        let gone = || anyhow::anyhow!("nft: exit Some(1): Error: No such file or directory");
        match a[..] {
            ["add", "table", ..] => {
                t.get_or_insert((7, Vec::new()));
            }
            ["--echo", ..] => {
                let (next, rules) = t.as_mut().ok_or_else(gone)?;
                rules.push((*next, a[a.len() - 3].into()));
                *next += 1;
                return Ok(format!("add rule ... drop # handle {}\n", *next - 1));
            }
            ["-a", "list", ..] => {
                let (_, rules) = t.as_ref().ok_or_else(gone)?;
                let gone = GONE.with(|g| g.borrow().clone());
                return Ok(rules
                    .iter()
                    .map(|(h, cg)| {
                        let shown = if gone.contains(cg) {
                            "18342".to_string()
                        } else {
                            format!("\"{cg}\"")
                        };
                        format!("socket cgroupv2 level 3 {shown} drop # handle {h}\n")
                    })
                    .collect());
            }
            ["delete", "rule", .., h] => {
                let (_, rules) = t.as_mut().ok_or_else(gone)?;
                let n = rules.len();
                rules.retain(|r| r.0.to_string() != h);
                if rules.len() == n {
                    bail!("nft: exit Some(1): Error: Could not process rule");
                }
            }
            _ => {}
        }
        Ok(String::new())
    }
    /// What the fake nft table holds now: (handle, cgroup path).
    fn rules() -> Option<Vec<(u64, String)>> {
        TABLE.with(|t| t.borrow().as_ref().map(|t| t.1.clone()))
    }
    fn set_rules(r: Option<Vec<(u64, String)>>) {
        TABLE.with(|t| {
            *t.borrow_mut() = r.map(|r| (r.iter().map(|x| x.0 + 1).max().unwrap_or(7), r))
        });
    }
    fn fail_freeze(prog: &str, a: &[String]) -> Result<String> {
        if a.first().is_some_and(|s| s == "freeze") {
            CALLS.with(|c| c.borrow_mut().push([&[prog.to_string()], a].concat()));
            bail!("systemctl freeze: exit Some(1): no such unit")
        }
        ok(prog, a)
    }
    fn fail_freeze_and_thaw(prog: &str, a: &[String]) -> Result<String> {
        if a.first().is_some_and(|s| s == "thaw") {
            CALLS.with(|c| c.borrow_mut().push([&[prog.to_string()], a].concat()));
            bail!("systemctl thaw: exit Some(1): timed out")
        }
        fail_freeze(prog, a)
    }
    fn fail_thaw_unloaded(prog: &str, a: &[String]) -> Result<String> {
        if a.first().is_some_and(|s| s == "thaw") {
            CALLS.with(|c| c.borrow_mut().push([&[prog.to_string()], a].concat()));
            bail!("systemctl thaw: exit Some(5): Unit x.scope not loaded.")
        }
        ok(prog, a)
    }
    fn no_cgroup(_: &str) -> Result<String> {
        Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
    }
    fn frozen(_: &str) -> Result<String> {
        Ok("populated 1\nfrozen 1\n".into())
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
        set_rules(None);
        GONE.with(|g| g.borrow_mut().clear());
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
            enforcing: Arc::new(AtomicBool::new(true)),
            dropped: Arc::default(),
            wait: Duration::ZERO,
            unsaved: HashMap::new(),
            children: |_| Vec::new(),
            forks: Arc::default(),
        };
        Fx { e, id, dir }
    }

    impl Fx {
        fn incident(&self) -> crate::incident::Incident {
            self.e.store.get(&IncidentId(self.id.clone())).unwrap()
        }
        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.with_extension("jsonl")).unwrap_or_default()
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

    fn slow(_: &str, _: &[String]) -> Result<String> {
        std::thread::sleep(Duration::from_millis(300));
        Ok(String::new())
    }

    fn spawn_slow(f: &Fx) -> EnforcerHandle {
        spawn_enforcer(
            f.e.store.clone(),
            Holds::default(),
            Systemd::with(slow, alive),
            Nft::with(slow),
            f.e.limits,
            f.e.sinks.clone(),
            Arc::new(AtomicBool::new(true)),
        )
    }

    #[test]
    fn shutdown_waits_for_the_job_in_hand() {
        let f = fx("stop", ok);
        let h = spawn_slow(&f);
        h.queue(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        assert!(h.shutdown(Duration::from_secs(10)));
        // Moved and frozen, and on the record before shutdown returned.
        assert_eq!(f.incident().verdict, "quarantined");
    }

    #[test]
    fn shutdown_gives_up_at_the_cap() {
        let f = fx("stop-cap", ok);
        let h = spawn_slow(&f);
        h.queue(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let t = std::time::Instant::now();
        assert!(!h.shutdown(Duration::from_millis(100)));
        assert!(t.elapsed() < Duration::from_millis(250));
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
    fn a_freeze_that_finds_the_scope_not_yet_started_is_tried_again() {
        // The first freeze fails (the start job is still running); the
        // second, after a pause, works.
        fn first_freeze_fails(prog: &str, a: &[String]) -> Result<String> {
            let tried = CALLS.with(|c| c.borrow().iter().any(|c| c[1] == "freeze"));
            if a.first().is_some_and(|s| s == "freeze") && !tried {
                CALLS.with(|c| c.borrow_mut().push([&[prog.to_string()], a].concat()));
                bail!("systemctl freeze: exit Some(1): unit not active")
            }
            ok(prog, a)
        }
        let mut f = fx("qretry", first_freeze_fails);
        f.e.sys = Systemd::with(first_freeze_fails, alive).with_events(no_cgroup);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let freezes = take().iter().filter(|c| c[1] == "freeze").count();
        assert_eq!(freezes, 2);
        let inc = f.incident();
        assert_eq!(inc.verdict, "quarantined");
        let freeze = inc.actions.iter().find(|a| a.kind == "freeze").unwrap();
        assert!(freeze.ok && freeze.error.is_none(), "{freeze:?}");
    }

    #[test]
    fn freeze_error_but_frozen_counts_as_frozen() {
        let mut f = fx("qfrozen", fail_freeze);
        f.e.sys = Systemd::with(fail_freeze, alive).with_events(frozen);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let inc = f.incident();
        assert_eq!(inc.verdict, "quarantined");
        let freeze = inc.actions.iter().find(|a| a.kind == "freeze").unwrap();
        assert!(freeze.ok);
        assert!(freeze.error.as_deref().unwrap().contains("no such unit"));
        assert_eq!(f.e.failed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn release_thaws_even_when_freeze_was_recorded_failed() {
        let mut f = fx("rel-nofreeze", fail_freeze);
        let id = f.id.clone();
        f.e.run(EnforceJob::Quarantine {
            id: id.clone(),
            pids: vec![k(10)],
        });
        assert_eq!(
            f.kinds()[..3],
            [
                ("hold".into(), true),
                ("scope".into(), true),
                ("freeze".into(), false)
            ]
        );
        take();
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release {
            id: id.clone(),
            reply,
        });
        assert_eq!(r, Ok(format!("released {id}: thawed, network restored")));
        assert_eq!(
            take()[0][1..3],
            ["thaw".to_string(), format!("aegis-incident-{id}-q.scope")]
        );
    }

    #[test]
    fn release_succeeds_when_the_scope_has_vanished() {
        let mut f = fx("rel-gone", fail_thaw_unloaded);
        f.e.sys = Systemd::with(fail_thaw_unloaded, alive).with_events(no_cgroup);
        let id = f.id.clone();
        f.e.run(EnforceJob::Quarantine {
            id: id.clone(),
            pids: vec![k(10)],
        });
        take();
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release {
            id: id.clone(),
            reply,
        });
        assert_eq!(r, Ok(format!("released {id}: thawed, network restored")));
        let c = take();
        assert_eq!(c[0][1], "thaw");
        assert_eq!(c[1][1..3], ["-a".to_string(), "list".into()]);
        assert_eq!(c[2][1..3], ["delete".to_string(), "rule".into()]);
    }

    #[test]
    fn release_reports_error_when_still_frozen() {
        let mut f = fx("rel-stuck", fail_freeze_and_thaw);
        f.e.sys = Systemd::with(fail_freeze_and_thaw, alive).with_events(frozen);
        let id = f.id.clone();
        f.e.run(EnforceJob::Quarantine {
            id: id.clone(),
            pids: vec![k(10)],
        });
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release {
            id: id.clone(),
            reply,
        });
        let e = r.unwrap_err();
        assert!(e.contains("systemctl thaw"), "{e}");
        assert!(!e.contains("thawed"), "{e}");
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
    fn a_newcomer_already_in_the_quarantine_scope_records_no_attach() {
        thread_local! { static UNIT: RefCell<String> = const { RefCell::new(String::new()) }; }
        fn cg(_: u32) -> Option<String> {
            UNIT.with(|u| {
                let u = u.borrow();
                (!u.is_empty()).then(|| format!("0::/aegis.slice/aegis-quarantine.slice/{u}\n"))
            })
        }
        let mut f = fx("q-born", ok);
        f.e.sys = Systemd::with(ok, alive).with_cgroup(cg);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        UNIT.with(|u| *u.borrow_mut() = q_unit(&f.id));
        take();
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(12)],
        });
        UNIT.with(|u| u.borrow_mut().clear());
        assert!(take().is_empty());
        // Held, but nothing moved: no attach claiming pid 12 was.
        let kinds = f.kinds();
        assert_eq!(kinds[4..], [("hold".into(), true)]);
        assert_eq!(f.incident().verdict, "quarantined");
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
        assert_eq!(c[1][1..3], ["-a".to_string(), "list".into()]);
        assert_eq!(c[2][1..3], ["delete".to_string(), "rule".into()]);
        assert_eq!(c[2].last().unwrap(), "7");
        assert_eq!(f.e.holds.held(), 0);
        let kinds = f.kinds();
        assert_eq!(
            kinds[4..],
            [
                ("unhold".into(), true),
                ("thaw".into(), true),
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

    fn run_reply(
        e: &mut Enforcer,
        job: impl FnOnce(Option<Reply>) -> EnforceJob,
    ) -> Result<String, String> {
        let (r, mut rx) = reply();
        e.run(job(r));
        rx.try_recv().unwrap()
    }

    #[test]
    fn the_incident_list_shows_what_enforcement_left_in_place() {
        let state = |f: &Fx| f.e.store.list()[0].state.clone();
        let mut f = fx("state-q", ok);
        assert_eq!(state(&f), None);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        assert_eq!(state(&f).as_deref(), Some("held"));
        let id = f.id.clone();
        run_reply(&mut f.e, |reply| EnforceJob::Release { id, reply }).unwrap();
        assert_eq!(state(&f).as_deref(), Some("released"));

        let mut f = fx("state-k", ok);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let id = f.id.clone();
        run_reply(&mut f.e, |reply| EnforceJob::Kill { id, reply }).unwrap();
        assert_eq!(state(&f).as_deref(), Some("killed"));

        // The move failed, but the tree is held.
        let mut f = fx("state-h", |p, a| {
            if a.get(4).is_some_and(|m| m == "StartTransientUnit") {
                bail!("busctl: refused")
            }
            ok(p, a)
        });
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        assert_eq!(f.incident().verdict, "would_quarantine");
        assert_eq!(state(&f).as_deref(), Some("held"));
    }

    #[test]
    fn release_refuses_incident_without_actions() {
        let mut f = fx("rel-none", ok);
        let id = f.id.clone();
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release {
            id: id.clone(),
            reply,
        });
        assert_eq!(r, Err(format!("{id} was never enforced")));
    }

    #[test]
    fn release_refuses_twice() {
        let mut f = fx("rel-twice", ok);
        let id = f.id.clone();
        f.e.run(EnforceJob::Quarantine {
            id: id.clone(),
            pids: vec![k(10)],
        });
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release {
            id: id.clone(),
            reply,
        });
        assert_eq!(r, Ok(format!("released {id}: thawed, network restored")));
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release {
            id: id.clone(),
            reply,
        });
        assert_eq!(r, Err(format!("{id} is already released")));
    }

    #[test]
    fn release_of_a_throttle_lifts_limits_and_kill_says_killed() {
        let mut f = fx("rel-thr", ok);
        let id = f.id.clone();
        f.e.run(EnforceJob::Throttle {
            id: id.clone(),
            pids: vec![k(10)],
        });
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release {
            id: id.clone(),
            reply,
        });
        assert_eq!(r, Ok(format!("released {id}: limits lifted")));
        let mut f = fx("kill-ok", ok);
        let id = f.id.clone();
        f.e.run(EnforceJob::Quarantine {
            id: id.clone(),
            pids: vec![k(10)],
        });
        let r = run_reply(&mut f.e, |reply| EnforceJob::Kill {
            id: id.clone(),
            reply,
        });
        assert_eq!(r, Ok(format!("killed {id}")));
    }

    #[test]
    fn kill_refuses_throttle_only() {
        let mut f = fx("kill-thr", ok);
        let id = f.id.clone();
        f.e.run(EnforceJob::Throttle {
            id: id.clone(),
            pids: vec![k(10)],
        });
        let r = run_reply(&mut f.e, |reply| EnforceJob::Kill {
            id: id.clone(),
            reply,
        });
        assert_eq!(
            r,
            Err(format!("{id} was only throttled; release it instead"))
        );
    }

    #[test]
    fn release_after_restart_uses_recorded_actions() {
        let mut f = fx("restart", ok);
        let id = f.id.clone();
        f.e.run(EnforceJob::Quarantine {
            id: id.clone(),
            pids: vec![k(10)],
        });
        take();
        // A new process: same store directory, nothing in memory.
        let store = IncidentStore::open_at(&f.dir, Some("boot".into()), 0).unwrap();
        let mut e2 = Enforcer {
            store: Arc::new(store),
            holds: Holds::default(),
            sys: Systemd::with(ok, alive),
            nft: Nft::with(ok),
            limits: Limits {
                cpu_quota_percent: 25,
                memory_high_bytes: 256 << 20,
            },
            sinks: Arc::new(Sinks::jsonl_at(&f.dir.with_extension("jsonl"))),
            ok: Arc::default(),
            failed: Arc::default(),
            enforcing: Arc::new(AtomicBool::new(false)),
            dropped: Arc::default(),
            wait: Duration::ZERO,
            unsaved: HashMap::new(),
            children: |_| Vec::new(),
            forks: Arc::default(),
        };
        let r = run_reply(&mut e2, |reply| EnforceJob::Release {
            id: id.clone(),
            reply,
        });
        assert!(r.is_ok(), "{r:?}");
        let c = take();
        assert_eq!(
            c[0][1..3],
            ["thaw".to_string(), format!("aegis-incident-{id}-q.scope")]
        );
        assert_eq!(c[1][1..3], ["-a".to_string(), "list".into()]);
        assert_eq!(c[2][1..3], ["delete".to_string(), "rule".into()]);
        assert_eq!(c[2].last().unwrap(), "7");
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
        assert_eq!(c[0][1..3], ["-a".to_string(), "list".into()]);
        assert_eq!(c[1][1..3], ["kill".to_string(), "--signal=SIGKILL".into()]);
        assert_eq!(c[2][1..3], ["delete".to_string(), "rule".into()]);
        let kinds = f.kinds();
        assert_eq!(
            kinds[4..],
            [("kill".into(), true), ("nft_remove".into(), true)]
        );
    }

    #[test]
    fn queued_jobs_do_nothing_once_back_in_audit() {
        let mut f = fx("audit", ok);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        take();
        // A reload to audit while more jobs wait in the queue.
        f.e.enforcing.store(false, Ordering::Relaxed);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(12)],
        });
        f.e.run(EnforceJob::Throttle {
            id: f.id.clone(),
            pids: vec![k(12)],
        });
        assert!(take().is_empty());
        assert_eq!(f.e.holds.held(), 1);
        assert_eq!(f.kinds().len(), 4);
        assert_eq!(f.e.dropped.load(Ordering::Relaxed), 2);
        // An admin's release still runs.
        f.e.run(EnforceJob::Release {
            id: f.id.clone(),
            reply: None,
        });
        assert_eq!(f.e.holds.held(), 0);
        assert!(!take().is_empty());
    }

    #[test]
    fn an_incident_never_recorded_is_not_acted_on() {
        let mut f = fx("missing", ok);
        f.e.run(EnforceJob::Quarantine {
            id: "AEG-20261021-000000-0000000000000000".into(),
            pids: vec![k(10)],
        });
        assert!(take().is_empty());
        assert_eq!(f.e.holds.held(), 0);
        assert!(
            f.log()
                .contains("enforcement skipped: incident not recorded"),
            "{}",
            f.log()
        );
    }

    #[test]
    fn actions_that_could_not_be_recorded_are_kept_and_retried() {
        let mut f = fx("unsaved", ok);
        // A file where the incident's directory belongs: every write fails.
        let inc_dir = f.dir.join(&f.id);
        std::fs::remove_dir_all(&inc_dir).unwrap();
        std::fs::write(&inc_dir, "").unwrap();
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        assert!(f.incident().actions.is_empty());
        let unit = format!("aegis-incident-{}-q.scope", f.id);
        let log = f.log();
        assert!(log.contains("recording actions"), "{log}");
        assert!(log.contains(&unit) && log.contains("nft handle 7"), "{log}");
        take();
        // The disk is back: release works from the kept actions, and
        // everything lands on the incident.
        std::fs::remove_file(&inc_dir).unwrap();
        std::fs::create_dir(&inc_dir).unwrap();
        let (r, mut rx) = reply();
        f.e.run(EnforceJob::Release {
            id: f.id.clone(),
            reply: r,
        });
        assert!(rx.try_recv().unwrap().is_ok());
        let kinds: Vec<String> = f.kinds().into_iter().map(|k| k.0).collect();
        assert_eq!(
            kinds,
            [
                "hold",
                "scope",
                "freeze",
                "nft_drop",
                "unhold",
                "thaw",
                "nft_remove"
            ]
        );
        assert!(f.e.unsaved.is_empty());
    }

    #[test]
    fn a_restart_requarantine_reholds_and_attaches_only() {
        let mut f = fx("restart", ok);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        take();
        // The hold map is lost with the old aegisd; the cgroup is not.
        f.e.holds = Holds::default();
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let c = take();
        assert_eq!(c.len(), 1);
        assert!(c[0].contains(&"AttachProcessesToUnit".into()));
        assert_eq!(f.e.holds.held(), 1);
    }

    #[test]
    fn kill_after_a_failed_move_says_so() {
        fn fail_scope(prog: &str, a: &[String]) -> Result<String> {
            if prog.ends_with("busctl") {
                bail!("busctl: exit Some(1)")
            }
            ok(prog, a)
        }
        let mut f = fx("kill-noscope", fail_scope);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let (r, mut rx) = reply();
        f.e.run(EnforceJob::Kill {
            id: f.id.clone(),
            reply: r,
        });
        assert_eq!(
            rx.try_recv().unwrap(),
            Err(format!(
                "{} was never moved into its scope; release it",
                f.id
            ))
        );
    }

    #[test]
    fn a_newcomer_after_a_failed_move_is_held_not_scoped_alone() {
        fn fail_scope(prog: &str, a: &[String]) -> Result<String> {
            CALLS.with(|c| c.borrow_mut().push([&[prog.to_string()], a].concat()));
            if prog.ends_with("busctl") {
                bail!("busctl: exit Some(1)")
            }
            ok(prog, a)
        }
        let mut f = fx("q-nomove", fail_scope);
        for k in [k(10), k(12)] {
            f.e.run(EnforceJob::Quarantine {
                id: f.id.clone(),
                pids: vec![k],
            });
        }
        f.e.run(EnforceJob::Throttle {
            id: f.id.clone(),
            pids: vec![k(13)],
        });
        // One StartTransientUnit, for the tree; nothing after it.
        assert_eq!(take().len(), 1);
        assert_eq!(f.e.holds.held(), 2);
        assert_eq!(f.incident().verdict, "would_quarantine");
        let mut f = fx("t-nomove", fail_scope);
        for k in [k(10), k(12)] {
            f.e.run(EnforceJob::Throttle {
                id: f.id.clone(),
                pids: vec![k],
            });
        }
        assert_eq!(take().len(), 1);
    }

    #[test]
    fn a_reload_to_audit_during_the_incident_wait_stops_the_job() {
        let mut f = fx("late", ok);
        f.e.wait = Duration::from_secs(3);
        // The incident lands late, and audit mode came while it waited.
        let id = "AEG-20261021-000000-00000000000000aa".to_string();
        let (store, enforcing, want) = (f.e.store.clone(), f.e.enforcing.clone(), id.clone());
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            enforcing.store(false, Ordering::Relaxed);
            let d = Decision {
                key: k(20),
                score: 90.0,
                tier: Tier::Quarantine,
                evidence: vec![],
            };
            store
                .record_as(&d, &[proc(20)], Mode::Enforce, Some(&want))
                .unwrap();
        });
        f.e.run(EnforceJob::Quarantine {
            id,
            pids: vec![k(20)],
        });
        t.join().unwrap();
        assert!(take().is_empty());
        assert_eq!(f.e.holds.held(), 0);
        assert_eq!(f.e.dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_lost_timeline_line_does_not_double_the_release() {
        let mut f = fx("tl", ok);
        // A directory where the timeline belongs: every append fails, but
        // incident.json is still written.
        let tl = f.dir.join(&f.id).join("timeline.jsonl");
        std::fs::remove_file(&tl).unwrap();
        std::fs::create_dir(&tl).unwrap();
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        assert!(f.e.unsaved.is_empty());
        assert!(!f.log().contains("recording actions"), "{}", f.log());
        assert_eq!(f.kinds().len(), 4);
        take();
        let (r, mut rx) = reply();
        f.e.run(EnforceJob::Release {
            id: f.id.clone(),
            reply: r,
        });
        assert!(rx.try_recv().unwrap().is_ok());
        let deletes = take().iter().filter(|a| a[1] == "delete").count();
        assert_eq!(deletes, 1);
    }
    #[test]
    fn children_forked_before_the_hold_are_moved_with_the_tree() {
        fn kids(p: ProcKey) -> Vec<ProcKey> {
            match p.tgid {
                10 => vec![k(20)],
                // pid 1 can never be a child, but is refused even so.
                20 => vec![k(21), k(1), k(10)],
                _ => vec![],
            }
        }
        let mut f = fx("kids", ok);
        f.e.children = kids;
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let inc = f.incident();
        assert_eq!(inc.verdict, "quarantined");
        // Only the job's own keys are held; what /proc found is moved.
        assert_eq!(inc.actions[0].pids, [10]);
        assert_eq!(inc.actions[0].start_times, [110]);
        assert_eq!(inc.actions[1].kind, "scope");
        assert_eq!(inc.actions[1].pids, [10, 20, 21]);
        let c = take();
        assert!(
            c[0].windows(5).any(|w| w == ["au", "3", "10", "20", "21"]),
            "{:?}",
            c[0]
        );
    }

    #[test]
    fn newcomer_to_a_throttled_tree_joins_its_scope() {
        let mut f = fx("t-new", ok);
        f.e.run(EnforceJob::Throttle {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        take();
        f.e.run(EnforceJob::Throttle {
            id: f.id.clone(),
            pids: vec![k(12)],
        });
        let c = take();
        assert_eq!(c.len(), 1, "{c:?}");
        assert!(c[0].contains(&"AttachProcessesToUnit".into()));
        assert!(c[0].contains(&format!("aegis-incident-{}.scope", f.id)));
        assert_eq!(f.kinds(), [("scope".into(), true), ("attach".into(), true)]);
        // Once quarantined, a throttle job never pulls anything back out.
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10), k(12)],
        });
        take();
        f.e.run(EnforceJob::Throttle {
            id: f.id.clone(),
            pids: vec![k(13)],
        });
        assert!(take().is_empty());
    }

    #[test]
    fn success_is_announced_once_with_the_verdict_earned() {
        let mut f = fx("announce", ok);
        // A throttle under a would_quarantine verdict raises nothing.
        f.e.run(EnforceJob::Throttle {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        // A newcomer to the quarantined tree is not news.
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(12)],
        });
        let done: Vec<serde_json::Value> = f
            .log()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|v: &serde_json::Value| v.to_string().contains("enforcement done"))
            .collect();
        assert_eq!(done.len(), 1, "{}", f.log());
        assert_eq!(done[0]["verdict"], "quarantined");
        assert_eq!(
            done[0]["reasons"][0],
            "enforcement done: members held, moved, frozen, egress dropped"
        );
    }

    #[test]
    fn release_or_kill_from_an_earlier_boot_touches_nothing() {
        for kill in [false, true] {
            let mut f = fx(&format!("oldboot-{kill}"), ok);
            let id = f.id.clone();
            f.e.run(EnforceJob::Quarantine {
                id: id.clone(),
                pids: vec![k(10)],
            });
            take();
            // After a reboot: a new store boot, an empty hold map, and
            // tgid 10 now someone else's, held for another incident.
            f.e.store = Arc::new(IncidentStore::open_at(&f.dir, Some("later".into()), 0).unwrap());
            f.e.holds = Holds::default();
            f.e.holds
                .hold(ProcKey {
                    tgid: 10,
                    start_time_ns: 999,
                })
                .unwrap();
            let job = |reply: Option<Reply>| {
                if kill {
                    EnforceJob::Kill {
                        id: id.clone(),
                        reply,
                    }
                } else {
                    EnforceJob::Release {
                        id: id.clone(),
                        reply,
                    }
                }
            };
            let r = run_reply(&mut f.e, job);
            assert_eq!(
                r,
                Ok(format!(
                    "{id} is from an earlier boot; nothing of it is left on this host"
                ))
            );
            assert!(take().is_empty());
            assert_eq!(f.e.holds.held(), 1);
            assert_eq!(f.kinds().last().unwrap(), &("expired".into(), true));
            let r = run_reply(&mut f.e, job);
            assert_eq!(
                r,
                Err(format!("{id} is from an earlier boot and already ended"))
            );
            assert!(take().is_empty());
        }
    }

    #[test]
    fn release_leaves_a_reused_tgid_held() {
        let mut f = fx("reused", ok);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        // 10 exited (the kernel dropped its hold) and the tgid now
        // belongs to a process held for another incident.
        f.e.holds = Holds::default();
        f.e.holds
            .hold(ProcKey {
                tgid: 10,
                start_time_ns: 999,
            })
            .unwrap();
        let id = f.id.clone();
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release { id, reply });
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(f.e.holds.held(), 1);
    }

    #[test]
    fn a_flood_of_fork_jobs_never_crowds_out_an_escalation() {
        let path =
            std::env::temp_dir().join(format!("aegis-enf-{}-flood.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let (tx, rx) = sync_channel(QUEUE);
        let h = EnforcerHandle::new(tx, Arc::new(Sinks::jsonl_at(&path)));
        for c in 0..1000 {
            h.queue(EnforceJob::Fork {
                id: "AEG-f".into(),
                tier: Tier::Throttle,
                pid: k(1000 + c),
            });
        }
        assert_eq!(h.dropped.load(Ordering::Relaxed), 1000 - FORK_SLOTS as u64);
        // The escalation still gets a slot.
        h.queue(EnforceJob::Quarantine {
            id: "AEG-f".into(),
            pids: vec![k(10)],
        });
        let jobs: Vec<EnforceJob> = rx.try_iter().collect();
        assert_eq!(jobs.len(), FORK_SLOTS + 1);
        assert!(matches!(jobs.last(), Some(EnforceJob::Quarantine { .. })));
        // No fork drop reached telemetry; a dropped escalation does.
        assert!(std::fs::read_to_string(&path)
            .unwrap_or_default()
            .is_empty());
        for _ in 0..QUEUE + 1 {
            h.queue(EnforceJob::Quarantine {
                id: "AEG-g".into(),
                pids: vec![k(11)],
            });
        }
        let log = std::fs::read_to_string(&path).unwrap();
        assert_eq!(log.lines().count(), 1, "{log}");
        assert!(log.contains("enforcement failed: queue full") && log.contains("AEG-g"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_dropped_escalation_carries_the_score_and_root_name() {
        let path =
            std::env::temp_dir().join(format!("aegis-enf-{}-full.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let (tx, _rx) = sync_channel(0);
        let h = EnforcerHandle::new(tx, Arc::new(Sinks::jsonl_at(&path)));
        h.queue_about(
            EnforceJob::Quarantine {
                id: "AEG-h".into(),
                pids: vec![k(11)],
            },
            |id, k| {
                assert_eq!((id, k.map(|k| k.tgid)), ("AEG-h", Some(11)));
                (72.5, "payload".into())
            },
        );
        let log = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(log.trim()).unwrap();
        assert_eq!(
            (v["score"].as_f64(), v["comm"].as_str()),
            (Some(72.5), Some("payload"))
        );
        assert_eq!(v["tgid"], 11);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_enforcer_counts_fork_jobs_down() {
        let mut f = fx("forkjob", ok);
        f.e.forks.store(1, Ordering::Relaxed);
        f.e.run(EnforceJob::Fork {
            id: f.id.clone(),
            tier: Tier::Quarantine,
            pid: k(10),
        });
        assert_eq!(f.e.forks.load(Ordering::Relaxed), 0);
        assert_eq!(f.incident().verdict, "quarantined");
    }

    #[test]
    fn a_walked_child_whose_pid_was_reused_is_left_out() {
        fn stat(tgid: u32) -> Option<(u32, u64)> {
            match tgid {
                20 => Some((10, 120)),
                // Listed under 10, but now someone else's.
                21 => Some((77, 121)),
                _ => None,
            }
        }
        assert_eq!(still_children(10, vec![20, 21, 22], stat), [k(20)]);
    }

    #[test]
    fn a_second_walk_after_the_freeze_catches_a_late_grandchild() {
        thread_local! { static WALKS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) }; }
        fn kids(p: ProcKey) -> Vec<ProcKey> {
            match p.tgid {
                10 => vec![k(20)],
                // 20 isn't held; by the second walk it has forked 22.
                20 => {
                    let n = WALKS.with(|w| {
                        w.set(w.get() + 1);
                        w.get()
                    });
                    if n > 1 {
                        vec![k(22)]
                    } else {
                        vec![]
                    }
                }
                _ => vec![],
            }
        }
        let mut f = fx("latewalk", ok);
        f.e.children = kids;
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let inc = f.incident();
        let kinds: Vec<&str> = inc.actions.iter().map(|a| a.kind.as_str()).collect();
        assert_eq!(kinds, ["hold", "scope", "freeze", "attach", "nft_drop"]);
        assert_eq!(inc.actions[1].pids, [10, 20]);
        assert_eq!(inc.actions[3].pids, [22]);
    }

    #[test]
    fn forks_born_in_the_throttle_scope_leave_the_record_alone() {
        thread_local! { static UNIT: RefCell<String> = const { RefCell::new(String::new()) }; }
        fn cg(_: u32) -> Option<String> {
            UNIT.with(|u| {
                let u = u.borrow();
                (!u.is_empty()).then(|| format!("0::/aegis.slice/aegis-throttle.slice/{u}\n"))
            })
        }
        let mut f = fx("t-born", ok);
        f.e.sys = Systemd::with(ok, alive).with_cgroup(cg);
        f.e.run(EnforceJob::Throttle {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        let file = f.dir.join(&f.id).join("incident.json");
        let before = std::fs::read(&file).unwrap();
        UNIT.with(|u| *u.borrow_mut() = format!("aegis-incident-{}.scope", f.id));
        take();
        for c in 0..100 {
            f.e.run(EnforceJob::Fork {
                id: f.id.clone(),
                tier: Tier::Throttle,
                pid: k(1000 + c),
            });
        }
        assert!(take().is_empty());
        assert_eq!(std::fs::read(&file).unwrap(), before);
        UNIT.with(|u| u.borrow_mut().clear());
    }

    /// A quarantined fixture whose scope the kernel reports frozen.
    fn quarantined(name: &str) -> (Fx, String) {
        let mut f = fx(name, ok);
        f.e.sys = Systemd::with(ok, alive).with_events(frozen);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        take();
        let cg = Nft::scope_cgroup(QUARANTINE_SLICE, &q_unit(&f.id));
        (f, cg)
    }

    fn last_act(f: &Fx) -> ActionRecord {
        f.incident().actions.last().unwrap().clone()
    }

    #[test]
    fn reassert_recreates_a_flushed_table_and_the_rule() {
        let (mut f, cg) = quarantined("re-table");
        set_rules(None);
        f.e.run(EnforceJob::Reassert);
        let heads: Vec<String> = take().iter().map(|c| c[1..3].join(" ")).collect();
        assert_eq!(
            heads,
            ["-a list", "add table", "add chain", "--echo --handle"]
        );
        assert_eq!(rules(), Some(vec![(7, cg)]));
        let a = last_act(&f);
        assert_eq!(
            (a.kind.as_str(), a.ok, a.nft_handle),
            ("nft_drop", true, Some(7))
        );
        assert_eq!(
            a.detail.as_deref(),
            Some("re-added after the table was removed")
        );
        // Back in place: the next check only looks.
        let n = f.incident().actions.len();
        f.e.run(EnforceJob::Reassert);
        assert_eq!(take().len(), 1);
        assert_eq!(f.incident().actions.len(), n);
    }

    #[test]
    fn reassert_readds_a_missing_rule() {
        let (mut f, cg) = quarantined("re-rule");
        set_rules(Some(vec![(9, "aegis.slice/other.scope".into())]));
        f.e.run(EnforceJob::Reassert);
        let heads: Vec<String> = take().iter().map(|c| c[1..3].join(" ")).collect();
        assert_eq!(heads, ["-a list", "--echo --handle"]);
        assert_eq!(
            rules(),
            Some(vec![(9, "aegis.slice/other.scope".into()), (10, cg)])
        );
        let a = last_act(&f);
        assert_eq!(
            a.detail.as_deref(),
            Some("re-added after the rule was removed")
        );
        assert_eq!(a.nft_handle, Some(10));
    }

    #[test]
    fn reassert_with_nothing_quarantined_never_runs_nft() {
        // Recorded, never enforced.
        let mut f = fx("re-none", ok);
        f.e.sys = Systemd::with(ok, alive).with_events(frozen);
        f.e.run(EnforceJob::Reassert);
        assert!(take().is_empty());
        // Released: thawed and ended, whatever the table holds.
        let (mut f, _) = quarantined("re-released");
        let id = f.id.clone();
        run_reply(&mut f.e, |reply| EnforceJob::Release { id, reply }).unwrap();
        set_rules(None);
        take();
        f.e.run(EnforceJob::Reassert);
        assert!(take().is_empty());
        // From an earlier boot: its scope and rule went with that boot.
        let (mut f, _) = quarantined("re-oldboot");
        f.e.store = Arc::new(IncidentStore::open_at(&f.dir, Some("later".into()), 0).unwrap());
        set_rules(None);
        f.e.run(EnforceJob::Reassert);
        assert!(take().is_empty());
        // Every process gone: no cgroup for a rule to match.
        let (mut f, _) = quarantined("re-exited");
        f.e.sys = Systemd::with(ok, alive).with_events(no_cgroup);
        set_rules(None);
        f.e.run(EnforceJob::Reassert);
        assert!(take().is_empty());
    }

    #[test]
    fn release_deletes_the_live_handle_not_a_reused_one() {
        let (mut f, cg) = quarantined("re-reused");
        assert_eq!(f.incident().actions.last().unwrap().nft_handle, Some(7));
        // A flush, then another rule takes handle 7 before the next check
        // puts this incident's back as 8.
        let other = "aegis.slice/aegis-quarantine.slice/other-q.scope".to_string();
        set_rules(Some(vec![(7, other.clone())]));
        f.e.run(EnforceJob::Reassert);
        assert_eq!(rules(), Some(vec![(7, other.clone()), (8, cg)]));
        take();
        let id = f.id.clone();
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release { id, reply });
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(rules(), Some(vec![(7, other)]));
        let a = last_act(&f);
        assert_eq!((a.kind.as_str(), a.nft_handle), ("nft_remove", Some(8)));
    }

    #[test]
    fn release_succeeds_when_the_rule_is_already_gone() {
        for kill in [false, true] {
            let (mut f, _) = quarantined(&format!("re-gone-{kill}"));
            set_rules(None);
            let id = f.id.clone();
            let r = run_reply(&mut f.e, |reply| {
                if kill {
                    EnforceJob::Kill { id, reply }
                } else {
                    EnforceJob::Release { id, reply }
                }
            })
            .unwrap();
            assert!(r.ends_with("; its drop rule was already gone"), "{r}");
            assert!(!take().iter().any(|c| c[1] == "delete"));
            let a = last_act(&f);
            assert_eq!(
                (a.kind.as_str(), a.ok, a.nft_handle),
                ("nft_remove", true, None)
            );
            assert_eq!(a.detail.as_deref(), Some("the rule was already gone"));
        }
    }

    /// `systemctl kill` empties the scope, and systemd removes its cgroup.
    fn kill_empties(prog: &str, a: &[String]) -> Result<String> {
        if a.first().is_some_and(|s| s == "kill") {
            let unit = a.last().unwrap();
            GONE.with(|g| {
                g.borrow_mut()
                    .push(Nft::scope_cgroup(QUARANTINE_SLICE, unit))
            });
        }
        ok(prog, a)
    }

    #[test]
    fn kill_finds_the_rule_before_its_cgroup_goes() {
        let (mut f, _) = quarantined("kill-gone");
        f.e.sys = Systemd::with(kill_empties, alive).with_events(frozen);
        let id = f.id.clone();
        let r = run_reply(&mut f.e, |reply| EnforceJob::Kill { id, reply });
        assert_eq!(r, Ok(format!("killed {}", f.id)));
        let heads: Vec<String> = take().iter().map(|c| c[1..3].join(" ")).collect();
        assert_eq!(heads, ["-a list", "kill --signal=SIGKILL", "delete rule"]);
        assert_eq!(rules(), Some(vec![]));
        let a = last_act(&f);
        assert_eq!(
            (a.kind.as_str(), a.ok, a.nft_handle),
            ("nft_remove", true, Some(7))
        );
    }

    #[test]
    fn release_of_a_vanished_scope_deletes_its_rule_by_the_recorded_handle() {
        let (mut f, cg) = quarantined("rel-bare");
        GONE.with(|g| g.borrow_mut().push(cg));
        let id = f.id.clone();
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release { id, reply }).unwrap();
        assert!(!r.contains("already gone"), "{r}");
        assert_eq!(rules(), Some(vec![]));
        assert_eq!(last_act(&f).nft_handle, Some(7));
    }

    #[test]
    fn a_recorded_handle_shown_with_a_path_is_never_deleted() {
        let (mut f, cg) = quarantined("rel-path");
        // The scope is gone and a flush gave handle 7 to a live scope.
        GONE.with(|g| g.borrow_mut().push(cg));
        let other = "aegis.slice/aegis-quarantine.slice/other-q.scope".to_string();
        set_rules(Some(vec![(7, other.clone())]));
        let id = f.id.clone();
        let r = run_reply(&mut f.e, |reply| EnforceJob::Release { id, reply }).unwrap();
        assert!(r.ends_with("; its drop rule was already gone"), "{r}");
        assert!(!take().iter().any(|c| c[1] == "delete"));
        assert_eq!(rules(), Some(vec![(7, other)]));
    }

    #[test]
    fn reassert_in_audit_mode_restores_only_a_rule_enforce_added() {
        let (mut f, cg) = quarantined("re-audit");
        f.e.enforcing.store(false, Ordering::Relaxed);
        set_rules(None);
        f.e.run(EnforceJob::Reassert);
        assert_eq!(rules(), Some(vec![(7, cg)]));
        assert_eq!(
            last_act(&f).detail.as_deref(),
            Some("re-added after the table was removed")
        );
    }

    #[test]
    fn a_first_rule_that_failed_is_added_late_only_in_enforce_mode() {
        fn no_drop(prog: &str, a: &[String]) -> Result<String> {
            if a.first().is_some_and(|s| s == "--echo") {
                bail!("nft: exit Some(1): Error: Could not process rule")
            }
            ok(prog, a)
        }
        let mut f = fx("re-late", ok);
        f.e.sys = Systemd::with(ok, alive).with_events(frozen);
        f.e.nft = Nft::with(no_drop);
        f.e.run(EnforceJob::Quarantine {
            id: f.id.clone(),
            pids: vec![k(10)],
        });
        assert_eq!(last_act(&f).kind, "nft_drop");
        assert!(!last_act(&f).ok);
        f.e.nft = Nft::with(ok);
        take();
        f.e.enforcing.store(false, Ordering::Relaxed);
        f.e.run(EnforceJob::Reassert);
        assert!(take().is_empty());
        f.e.enforcing.store(true, Ordering::Relaxed);
        f.e.run(EnforceJob::Reassert);
        let a = last_act(&f);
        assert_eq!((a.kind.as_str(), a.ok), ("nft_drop", true));
        assert_eq!(
            a.detail.as_deref(),
            Some("added late: the first attempt failed")
        );
    }
}
