// SPDX-License-Identifier: MIT OR Apache-2.0
//! One probe event at a time: process table, scoring, incidents and
//! telemetry.
//!
//! The loop owns this and drives it synchronously. Two things it must
//! not do inline leave through a side door:
//!
//! - **Verification** (rpm + SHA-256) runs on the caller's blocking
//!   pool. `handle` queues paths in `to_verify`; the verdict comes back
//!   through `verified`.
//! - **Incident writes** (fsync) go to a writer thread over a bounded
//!   channel. Telemetry stays here, so a slow disk never holds up a
//!   record.
//!
//! Scoring a process waits for its verification. A fresh exec is
//! Unverified for the moment it takes the verdict to return, and an
//! allowlisted binary (runc's memfd self-clone, systemd's unit memfds,
//! gdb attaching) would score in that gap. So a signal whose verdict is
//! still in flight is deferred and scored when the verdict lands, or
//! after a 2 s deadline as Unverified.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use aegis_common::{Event, EventKind, EXEC_MEMFD, PATH_TRUNCATED};

use crate::config::{Config, Mode};
use crate::incident::{verdict, IncidentStore};
use crate::proctable::{ProcInfo, ProcKey, ProcTable};
use crate::scoring::{signals_for, DaemonClassifier, Decision, ScanDetector, Scorer, Signal};
use crate::telemetry::{now_ns, Sinks, TelemetryRecord};
use crate::verify::Verification;

/// Resolves a process's exe to the path aegisd should open to verify it.
/// Takes the start time so a reused pid is caught.
pub type Resolve = fn(u32, u64, &Path) -> Option<PathBuf>;

/// A decision and the tree to record it against, sent to the writer.
pub type RecordJob = (Decision, Vec<ProcInfo>, Mode);

/// How long a signal waits for its verdict before it scores Unverified.
const DEFER_DEADLINE: Duration = Duration::from_secs(2);
/// Per process, pending deferred signals; past this they score at once.
const MAX_DEFERRED_PER_PROC: usize = 64;
/// Executables being verified at once; past this an exec stays Unverified.
const MAX_PENDING: usize = 1024;
/// Processes waiting on one path's verdict (forks pile up here).
const MAX_WAITERS: usize = 1024;

/// Where incidents are recorded. The daemon sends jobs to a writer
/// thread; tests record inline.
pub struct Incidents {
    pub store: Arc<IncidentStore>,
    pub tx: Option<SyncSender<RecordJob>>,
    /// `record` calls that failed, shared with the writer thread.
    pub errors: Arc<AtomicU64>,
}

impl Incidents {
    #[cfg(test)]
    pub fn inline(store: IncidentStore) -> Self {
        Self {
            store: Arc::new(store),
            tx: None,
            errors: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// A signal held back until the gate process's verification lands.
struct Deferred {
    gate: PathBuf,
    /// True when the verdict belongs to the parent (a TmpExec is judged
    /// by its parent), false when it belongs to the subject itself.
    gate_is_parent: bool,
    subject: ProcInfo,
    ancestors: Vec<ProcInfo>,
    signal: Signal,
    target: Option<PathBuf>,
    ts_ns: u64,
    deadline: Instant,
}

pub struct Pipeline {
    pub table: ProcTable,
    scorer: Scorer,
    scan: ScanDetector,
    daemons: Box<dyn DaemonClassifier>,
    incidents: Incidents,
    pub sinks: Sinks,
    mode: Mode,
    resolve: Resolve,
    /// Verifications in flight, by the path being verified: who is
    /// waiting, and the exe each had when it asked.
    pending: HashMap<PathBuf, Vec<(ProcKey, PathBuf)>>,
    deferred: Vec<Deferred>,
    /// Paths for the caller to verify. Each is queued once while in flight.
    pub to_verify: Vec<PathBuf>,
    pub events_total: u64,
    pub incident_dropped: u64,
    pub verify_skipped: u64,
    pub deferred_overflow: u64,
    debug: bool,
}

impl Pipeline {
    pub fn new(
        cfg: &Config,
        incidents: Incidents,
        sinks: Sinks,
        daemons: Box<dyn DaemonClassifier>,
        resolve: Resolve,
        debug: bool,
    ) -> Self {
        Self {
            table: ProcTable::new(),
            scorer: Scorer::new(cfg),
            scan: ScanDetector::new(cfg.scoring.scan.clone()),
            daemons,
            incidents,
            sinks,
            mode: cfg.general.mode,
            resolve,
            pending: HashMap::new(),
            deferred: Vec::new(),
            to_verify: Vec::new(),
            events_total: 0,
            incident_dropped: 0,
            verify_skipped: 0,
            deferred_overflow: 0,
            debug,
        }
    }

    pub fn store(&self) -> &Arc<IncidentStore> {
        &self.incidents.store
    }

    pub fn incident_errors(&self) -> u64 {
        self.incidents.errors.load(Ordering::Relaxed)
    }

    /// Takes a reloaded config. Scores and scan windows carry over.
    pub fn set_config(&mut self, cfg: &Config) {
        self.scorer.set_config(cfg);
        self.scan.set_config(cfg.scoring.scan.clone());
        self.mode = cfg.general.mode;
    }

    /// Pins may have changed on reload, so a `Pinned` verdict no longer
    /// means what it did. Re-verify every process that held one.
    pub fn reverify_pinned(&mut self) {
        for key in self.table.pinned_keys() {
            self.table.set_verification(&key, Verification::Unverified);
            self.request_verification(key);
        }
    }

    pub fn handle(&mut self, ev: &Event) {
        self.events_total += 1;
        let key = ProcKey {
            tgid: ev.tgid,
            start_time_ns: ev.start_time_ns,
        };
        let kind = EventKind::try_from(ev.kind).ok();
        if kind != Some(EventKind::Exit) && self.table.ensure(ev) && kind != Some(EventKind::Exec) {
            // Found late, with its exe read from /proc: verify that.
            self.request_verification(key);
        }
        let mut sigs = signals_for(ev, &self.table, &*self.daemons);
        if kind == Some(EventKind::Connect) {
            sigs.extend(self.scan.on_connect(ev));
        }
        // For an exec, the target is the new image; the subject stays the
        // pre-exec binary (allowlists judge what did the exec).
        let target = (kind == Some(EventKind::Exec)).then(|| exec_path(ev));
        for sig in sigs {
            self.consider(key, sig, target.clone(), ev.ts_ns);
        }
        match kind {
            Some(EventKind::Exit) => self.forget(&key),
            Some(EventKind::Fork) => {
                let child = ProcKey {
                    tgid: ev.child_tgid,
                    start_time_ns: ev.child_start_time_ns,
                };
                self.scorer.on_fork(&key, &child, ev.ts_ns);
                // A child forked while its parent's exe is being verified
                // shares the image, so it waits on the same verdict.
                for w in self.pending.values_mut() {
                    if w.len() >= MAX_WAITERS {
                        continue;
                    }
                    if let Some(exe) = w.iter().find(|(k, _)| *k == key).map(|(_, e)| e.clone()) {
                        w.push((child, exe));
                    }
                }
            }
            _ => {}
        }
        self.table.apply(ev);
        // A memfd has no path to open, and a truncated path is not the file.
        if kind == Some(EventKind::Exec) && ev.flags & (EXEC_MEMFD | PATH_TRUNCATED) == 0 {
            self.request_verification(key);
        }
    }

    /// Scores a signal now, or defers it if the verdict it needs is still
    /// in flight.
    fn consider(&mut self, key: ProcKey, sig: Signal, target: Option<PathBuf>, ts_ns: u64) {
        let Some(subject) = self.table.get(&key).cloned() else {
            return;
        };
        let ancestors: Vec<ProcInfo> = self.table.parent_chain(&key).into_iter().cloned().collect();

        // Which process's verdict gates this signal, and its verify path.
        let gate_is_parent = matches!(sig, Signal::TmpExec);
        let gated = if gate_is_parent {
            ancestors.first()
        } else {
            Some(&subject)
        };
        let gate = gated
            .and_then(|p| p.exe.as_ref().map(|e| (p.key, e)))
            .and_then(|(k, e)| (self.resolve)(k.tgid, k.start_time_ns, e));

        if let Some(path) = gate {
            if self.pending.contains_key(&path) {
                let held = self
                    .deferred
                    .iter()
                    .filter(|d| d.subject.key == key)
                    .count();
                if held >= MAX_DEFERRED_PER_PROC {
                    self.deferred_overflow += 1;
                } else {
                    self.deferred.push(Deferred {
                        gate: path,
                        gate_is_parent,
                        subject,
                        ancestors,
                        signal: sig,
                        target,
                        ts_ns,
                        deadline: Instant::now() + DEFER_DEADLINE,
                    });
                    return;
                }
            }
        }
        self.score(&subject, &ancestors, sig, target.as_deref(), ts_ns);
    }

    fn request_verification(&mut self, key: ProcKey) {
        let Some(exe) = self.table.get(&key).and_then(|p| p.exe.clone()) else {
            return;
        };
        if exe.as_os_str().is_empty() {
            return;
        }
        let Some(path) = (self.resolve)(key.tgid, key.start_time_ns, &exe) else {
            return;
        };
        if let Some(waiting) = self.pending.get_mut(&path) {
            if waiting.len() < MAX_WAITERS {
                waiting.push((key, exe));
            }
            return;
        }
        if self.pending.len() >= MAX_PENDING {
            // Backlog full: leave it Unverified, which scores nothing off.
            self.verify_skipped += 1;
            return;
        }
        self.pending.insert(path.clone(), vec![(key, exe)]);
        self.to_verify.push(path);
    }

    /// The verdict for a path queued in `to_verify`. Applied to every
    /// waiting process that still runs the exe it asked about, then any
    /// signal that was waiting on this path is scored.
    pub fn verified(&mut self, path: &Path, v: Verification) {
        for (k, exe) in self.pending.remove(path).unwrap_or_default() {
            if self.table.get(&k).and_then(|p| p.exe.as_ref()) == Some(&exe) {
                self.table.set_verification(&k, v.clone());
            }
        }
        let ready: Vec<Deferred> = {
            let mut keep = Vec::new();
            let mut ready = Vec::new();
            for d in self.deferred.drain(..) {
                if d.gate == path {
                    ready.push(d);
                } else {
                    keep.push(d);
                }
            }
            self.deferred = keep;
            ready
        };
        for mut d in ready {
            // The gate's verdict is known now; put it on the snapshot.
            let gated = if d.gate_is_parent {
                d.ancestors.first_mut()
            } else {
                Some(&mut d.subject)
            };
            if let Some(p) = gated {
                p.verification = v.clone();
            }
            self.score(
                &d.subject,
                &d.ancestors,
                d.signal,
                d.target.as_deref(),
                d.ts_ns,
            );
        }
    }

    /// Scores every signal whose deadline has passed as Unverified. The
    /// caller runs this on a timer.
    pub fn flush_expired(&mut self, cutoff: Instant) {
        let (expired, keep): (Vec<_>, Vec<_>) =
            self.deferred.drain(..).partition(|d| d.deadline <= cutoff);
        self.deferred = keep;
        for d in expired {
            self.score(
                &d.subject,
                &d.ancestors,
                d.signal,
                d.target.as_deref(),
                d.ts_ns,
            );
        }
    }

    /// Drops a process from the scorer, scan detector and every queue.
    fn forget(&mut self, key: &ProcKey) {
        self.scorer.on_exit(key);
        self.scan.on_exit(key);
        for w in self.pending.values_mut() {
            w.retain(|(k, _)| k != key);
        }
        self.pending.retain(|_, w| !w.is_empty());
        self.deferred.retain(|d| d.subject.key != *key);
    }

    /// Removes processes the kernel has reaped that we missed the exit
    /// for (a dropped Exit event, say). The caller runs this on a timer.
    pub fn sweep(&mut self) {
        for key in self.table.sweep() {
            self.forget(&key);
        }
    }

    fn score(
        &mut self,
        subject: &ProcInfo,
        ancestors: &[ProcInfo],
        sig: Signal,
        target: Option<&Path>,
        ts_ns: u64,
    ) {
        let refs: Vec<&ProcInfo> = ancestors.iter().collect();
        let d = self.scorer.observe(subject, &refs, sig, target, ts_ns);
        if self.debug {
            let last = d.evidence.last().map_or("", |e| e.reason.as_str());
            eprintln!(
                "aegisd: debug: tgid {} comm {} score {:.1} tier {:?}: {last}",
                subject.key.tgid, subject.comm, d.score, d.tier
            );
        }
        let Some(verdict) = verdict(d.tier) else {
            return;
        };
        // pid 1 and 2 (kthreadd) are never incident subjects, and they
        // never drag a child's incident into a kernel-rooted group.
        if matches!(subject.key.tgid, 1 | 2) {
            return;
        }
        let tree: Vec<ProcInfo> = std::iter::once(subject.clone())
            .chain(ancestors.iter().cloned())
            .filter(|p| !matches!(p.key.tgid, 1 | 2))
            .collect();
        self.record(&d, tree);
        // Best effort: on the first decision of a new incident the writer
        // may not have assigned the id yet, so this can be empty.
        let incident = self
            .incidents
            .store
            .incident_for(&subject.key)
            .unwrap_or_default();
        self.sinks.emit(&TelemetryRecord {
            ts_unix_ns: now_ns(),
            incident,
            tier: d.tier,
            verdict,
            score: d.score,
            mode: self.mode,
            tgid: subject.key.tgid,
            comm: subject.comm.clone(),
            exe: subject
                .exe
                .as_ref()
                .map(|e| e.as_os_str().as_encoded_bytes().to_vec()),
            reasons: d.evidence.iter().map(|e| e.reason.clone()).collect(),
        });
    }

    fn record(&mut self, d: &Decision, tree: Vec<ProcInfo>) {
        match &self.incidents.tx {
            Some(tx) => {
                if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
                    tx.try_send((d.clone(), tree, self.mode))
                {
                    self.incident_dropped += 1;
                }
            }
            None => {
                if let Err(e) = self.incidents.store.record(d, &tree, self.mode) {
                    self.incidents.errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "aegisd: recording incident for tgid {} failed: {e:#}",
                        d.key.tgid
                    );
                }
            }
        }
    }
}

/// The exec'd file from the event, by its exact path bytes.
fn exec_path(ev: &Event) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let n = (ev.path_len as usize).min(ev.path.len());
    PathBuf::from(std::ffi::OsStr::from_bytes(&ev.path[..n]))
}

/// Whether /proc says `tgid` is still the process that started at
/// `start_time_ns`. Guards every /proc read against pid reuse.
///
/// The probe's start time is `CLOCK_MONOTONIC`; `/proc/<pid>/stat`
/// field 22 is in clock ticks from boot, i.e. `CLOCK_BOOTTIME`. The two
/// agree except for time the host spent suspended, so on a box that
/// suspends this can read a live process as gone (then it stays
/// Unverified, which is safe). Servers don't suspend.
pub fn proc_start_matches(tgid: u32, start_time_ns: u64) -> bool {
    let Some(got) = proc_start_ns(tgid) else {
        return false;
    };
    // One clock tick of slack, since the stat value is quantised to ticks.
    let tick = 1_000_000_000 / clk_tck();
    got.abs_diff(start_time_ns) <= tick
}

fn clk_tck() -> u64 {
    // SAFETY: sysconf takes a constant and only reads a value.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 {
        v as u64
    } else {
        100
    }
}

/// Process start time from `/proc/<tgid>/stat` field 22, in ns.
fn proc_start_ns(tgid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{tgid}/stat")).ok()?;
    // comm (field 2) is parenthesised and may hold spaces or ')': the
    // fields after it start at the last ')'.
    let rest = &stat[stat.rfind(')')? + 1..];
    // After comm: state is field 3, so starttime (field 22) is the 20th.
    let ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    Some(ticks * 1_000_000_000 / clk_tck())
}

/// The path to verify `exe` by, for the process `tgid` that started at
/// `start_time_ns`.
///
/// An exe path is only meaningful in the mount namespace of the process
/// that ran it. A container (or a service with PrivateTmp and friends)
/// has its own, where `/usr/bin/x` may be a different file from ours.
/// For such a process we open the file through `/proc/<tgid>/root`,
/// which the kernel resolves in that process's namespace. The host
/// rpmdb doesn't own that path, so in practice a container process
/// stays `Unverified`, which is the safe answer: no allowlist offsets.
///
/// None when the process is gone or a different one now holds the pid,
/// since then its path means nothing to us; it stays `Unverified`.
pub fn resolve_exe(tgid: u32, start_time_ns: u64, exe: &Path) -> Option<PathBuf> {
    if !proc_start_matches(tgid, start_time_ns) {
        return None;
    }
    static OURS: OnceLock<Option<PathBuf>> = OnceLock::new();
    let ours = OURS
        .get_or_init(|| std::fs::read_link("/proc/self/ns/mnt").ok())
        .as_ref()?;
    let theirs = std::fs::read_link(format!("/proc/{tgid}/ns/mnt")).ok()?;
    if &theirs == ours {
        return Some(exe.to_path_buf());
    }
    Some(PathBuf::from(format!("/proc/{tgid}/root")).join(exe.strip_prefix("/").ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::EXEC_FROM_TMP;

    struct Pid1;
    impl DaemonClassifier for Pid1 {
        fn is_system_daemon(&self, tgid: u32) -> bool {
            tgid == 1
        }
    }

    fn same_ns(_: u32, _: u64, exe: &Path) -> Option<PathBuf> {
        Some(exe.to_path_buf())
    }

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn pipeline(name: &str) -> (Pipeline, Dir) {
        let d = std::env::temp_dir().join(format!("aegis-pipe-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let store =
            IncidentStore::open_at(&d, Some("boot".into()), now_ns() / 1_000_000_000).unwrap();
        let mut cfg = Config::default();
        cfg.allowlist.memfd_callers = vec!["/usr/bin/runc".into()];
        let p = Pipeline::new(
            &cfg,
            Incidents::inline(store),
            Sinks::none(),
            Box::new(Pid1),
            same_ns,
            false,
        );
        (p, Dir(d))
    }

    fn ev(kind: EventKind, tgid: u32) -> Event {
        // SAFETY: Event is plain old data; all-zero is valid.
        let mut e: Event = unsafe { std::mem::zeroed() };
        e.kind = kind as u32;
        e.tgid = tgid;
        e.start_time_ns = u64::from(tgid);
        e.ts_ns = 1_000_000_000;
        e
    }

    fn exec(tgid: u32, path: &str, flags: u32) -> Event {
        let mut e = ev(EventKind::Exec, tgid);
        e.path[..path.len()].copy_from_slice(path.as_bytes());
        e.path_len = path.len() as u32;
        e.flags = flags;
        e
    }

    fn fork(parent: u32, child: u32) -> Event {
        let mut e = ev(EventKind::Fork, parent);
        e.child_tgid = child;
        e.child_start_time_ns = u64::from(child);
        e
    }

    fn key(tgid: u32) -> ProcKey {
        ProcKey {
            tgid,
            start_time_ns: u64::from(tgid),
        }
    }

    fn paths(p: &[&str]) -> Vec<PathBuf> {
        p.iter().map(PathBuf::from).collect()
    }

    fn rpm(pkg: &str) -> Verification {
        Verification::RpmOwned {
            package: pkg.into(),
        }
    }

    /// bash forks pid 60, which execs /usr/bin/runc; runc creates a memfd
    /// and execs it, as on every container start. The memfd events arrive
    /// before runc's verdict does, so the signals are deferred.
    fn runc_self_clone(p: &mut Pipeline, runc_verdict: Option<Verification>) {
        p.handle(&exec(50, "/usr/bin/bash", 0));
        assert_eq!(std::mem::take(&mut p.to_verify), paths(&["/usr/bin/bash"]));
        p.verified(Path::new("/usr/bin/bash"), rpm("bash"));
        p.handle(&fork(50, 60));
        p.handle(&exec(60, "/usr/bin/runc", 0));
        assert_eq!(std::mem::take(&mut p.to_verify), paths(&["/usr/bin/runc"]));
        // runc's verdict is NOT back yet: the memfd signals must defer.
        p.handle(&ev(EventKind::MemfdCreate, 60));
        p.handle(&exec(
            60,
            "/memfd:runc_cloned (deleted)",
            EXEC_MEMFD | EXEC_FROM_TMP,
        ));
        assert!(p.to_verify.is_empty(), "a memfd is not verified");
        assert_eq!(p.deferred.len(), 2, "memfd_create and memfd exec deferred");
        if let Some(v) = runc_verdict {
            p.verified(Path::new("/usr/bin/runc"), v);
        } else {
            // Verdict never comes: the deadline fires them as Unverified.
            p.flush_expired(Instant::now() + Duration::from_secs(3));
        }
        assert!(p.deferred.is_empty());
    }

    #[test]
    fn verified_runc_memfd_self_clone_is_not_an_incident() {
        let (mut p, _d) = pipeline("runc");
        runc_self_clone(&mut p, Some(rpm("runc")));
        assert_eq!(p.store().open_count(), 0);
        // The exec did land: the table now shows the memfd image.
        let after = p.table.get(&key(60)).unwrap();
        assert_eq!(
            after.exe.as_deref(),
            Some(Path::new("/memfd:runc_cloned (deleted)"))
        );
    }

    #[test]
    fn unverified_memfd_self_clone_is_quarantined_after_the_deadline() {
        let (mut p, _d) = pipeline("fake-runc");
        runc_self_clone(&mut p, None);
        let l = p.store().list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].verdict, "would_quarantine");
        assert_eq!((l[0].max_score, l[0].root_tgid), (80.0, 60));
    }

    #[test]
    fn a_verdict_that_lands_in_time_forgives_the_memfd_clone() {
        // The same as the verified case, but proving the verdict path (not
        // the deadline) is what cleared it: nothing is ever expired.
        let (mut p, _d) = pipeline("intime");
        p.handle(&exec(60, "/usr/bin/runc", 0));
        p.to_verify.clear();
        p.handle(&ev(EventKind::MemfdCreate, 60));
        assert_eq!(p.deferred.len(), 1);
        p.verified(Path::new("/usr/bin/runc"), rpm("runc"));
        assert_eq!(p.store().open_count(), 0);
    }

    #[test]
    fn deferred_queue_overflow_scores_at_once_and_counts() {
        let (mut p, _d) = pipeline("overflow");
        p.handle(&exec(90, "/usr/bin/x", 0));
        p.to_verify.clear();
        for _ in 0..MAX_DEFERRED_PER_PROC + 5 {
            p.handle(&ev(EventKind::MemfdCreate, 90));
        }
        assert_eq!(p.deferred.len(), MAX_DEFERRED_PER_PROC);
        assert_eq!(p.deferred_overflow, 5);
    }

    #[test]
    fn verification_is_deduped_and_lands_when_done() {
        let (mut p, _d) = pipeline("dedupe");
        p.handle(&exec(70, "/usr/bin/x", 0));
        p.handle(&fork(70, 71));
        p.handle(&exec(72, "/usr/bin/x", 0));
        // Pid 73 moved on to another binary before the verdict came back.
        p.handle(&exec(73, "/usr/bin/x", 0));
        p.handle(&exec(73, "/usr/bin/y", 0));
        assert_eq!(p.to_verify, paths(&["/usr/bin/x", "/usr/bin/y"]));
        assert_eq!(
            p.table.get(&key(70)).unwrap().verification,
            Verification::Unverified
        );
        p.verified(Path::new("/usr/bin/x"), rpm("x"));
        for t in [70, 71, 72] {
            assert_eq!(p.table.get(&key(t)).unwrap().verification, rpm("x"), "{t}");
        }
        assert_eq!(
            p.table.get(&key(73)).unwrap().verification,
            Verification::Unverified
        );
        // Done means done: the next exec of x asks again (the Verifier caches).
        p.handle(&exec(74, "/usr/bin/x", 0));
        assert_eq!(
            p.to_verify.last().map(PathBuf::as_path),
            Some(Path::new("/usr/bin/x"))
        );
    }

    #[test]
    fn pending_cap_skips_and_counts() {
        let (mut p, _d) = pipeline("cap");
        for i in 0..MAX_PENDING + 3 {
            let path = format!("/usr/bin/x{i}");
            p.handle(&exec(1000 + i as u32, &path, 0));
        }
        assert_eq!(p.pending.len(), MAX_PENDING);
        assert_eq!(p.verify_skipped, 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn late_found_process_takes_its_exe_from_proc_and_is_verified() {
        let (mut p, _d) = pipeline("late");
        let me = std::process::id();
        let st = proc_start_ns(me).unwrap();
        let mut e = ev(EventKind::MemfdCreate, me);
        e.start_time_ns = st;
        p.handle(&e);
        let exe = std::env::current_exe().unwrap();
        let k = ProcKey {
            tgid: me,
            start_time_ns: st,
        };
        assert_eq!(p.table.get(&k).unwrap().exe.as_ref(), Some(&exe));
        assert_eq!(std::mem::take(&mut p.to_verify), std::slice::from_ref(&exe));
    }

    #[test]
    fn incident_write_failure_is_counted_not_fatal() {
        let (mut p, d) = pipeline("fail");
        std::fs::remove_dir_all(&d.0).unwrap();
        runc_self_clone(&mut p, None);
        assert!(p.incident_errors() >= 1);
        assert_eq!(p.store().open_count(), 0);
        // And the pipeline keeps going.
        p.handle(&ev(EventKind::Exit, 60));
        assert!(p.table.get(&key(60)).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_exe_in_our_namespace_is_the_path_itself() {
        let me = std::process::id();
        let st = proc_start_ns(me).unwrap();
        let p = Path::new("/usr/bin/true");
        assert_eq!(resolve_exe(me, st, p).as_deref(), Some(p));
        // A start time that doesn't match is pid reuse: refused.
        assert_eq!(resolve_exe(me, st + 1_000_000_000, p), None);
    }

    #[test]
    fn resolve_exe_of_a_dead_process_is_none() {
        // Pid numbers stop well short of u32::MAX.
        assert_eq!(resolve_exe(u32::MAX, 1, Path::new("/usr/bin/true")), None);
    }
}
