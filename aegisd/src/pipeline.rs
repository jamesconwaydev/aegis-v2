// SPDX-License-Identifier: MIT OR Apache-2.0
//! One probe event at a time: process table, scoring, incidents and
//! telemetry.
//!
//! The loop owns this and drives it synchronously. Two things it must
//! not do inline leave through a side door:
//!
//! - **Verification** (rpm + SHA-256) runs on the caller's blocking
//!   pool. `handle` queues jobs in `to_verify`; the verdict comes back
//!   through `verified`.
//! - **Incident writes** (fsync) go to a writer thread over a bounded
//!   channel. Telemetry stays here, so a slow disk never holds up a
//!   record.
//!
//! Only executables an allowlist entry or a pin names are verified: for
//! any other a verdict changes nothing, so it stays Unverified at no
//! cost.
//!
//! Scoring a process waits for its verification. A fresh exec is
//! Unverified for the moment it takes the verdict to return, and an
//! allowlisted binary (runc's memfd self-clone, systemd's unit memfds,
//! gdb attaching) would score in that gap. So a signal whose verdict is
//! still in flight is deferred and scored when the verdict lands, or
//! after `DEFER_DEADLINE` as Unverified.
//!
//! Inside an open incident, a decision is recorded and sent to
//! telemetry only when it says something new: the tier rose, a process
//! showed a signal kind it hadn't before, or a minute has passed since
//! the incident last spoke. The rest are counted in `incident_suppressed`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_common::{Event, EventKind, EXEC_MEMFD, PATH_TRUNCATED};

use crate::config::{Config, Mode};
use crate::incident::{new_incident_id, verdict, IncidentStore};
use crate::proctable::{ProcInfo, ProcKey, ProcTable};
use crate::scoring::{
    signals_for, DaemonClassifier, Decision, ScanDetector, Scorer, Signal, SignalKind, Tier, KINDS,
};
use crate::telemetry::{now_ns, Sinks, TelemetryRecord};
use crate::verify::{Verification, RPM_TIMEOUT};

/// What a verdict is about: the exe path, which names the file for rpm
/// and the pins, and the (dev, ino) the process actually ran. Two
/// processes showing the same path can run different files (one in a
/// chroot, say), so they never share a verdict. These are also the jobs
/// in `to_verify`.
pub type ExeKey = (PathBuf, (u64, u64));

/// A decision and the tree to record it against, sent to the writer.
/// The id is the one the loop assigned when it opened the incident.
pub type RecordJob = (Decision, Vec<ProcInfo>, Mode, String);

/// How long a signal waits for its verdict before it scores Unverified.
/// A verification is at worst two rpm calls at their timeout plus a
/// hash, so this leaves room for the hash on top.
const DEFER_DEADLINE: Duration = Duration::from_secs(6);
const _: () = assert!(DEFER_DEADLINE.as_secs() > 2 * RPM_TIMEOUT.as_secs());
/// Per process, pending deferred signals; past this they score at once.
const MAX_DEFERRED_PER_PROC: usize = 64;
/// Deferred signals across every process; past this they score at once.
const MAX_DEFERRED: usize = 8192;
/// Inside an incident, the longest it stays quiet while decisions keep
/// coming that add nothing new.
const HEARTBEAT_NS: u64 = 60 * 1_000_000_000;
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

/// What an open incident has already said, so a repeat isn't said again.
struct Spoken {
    tier: Tier,
    seen: HashSet<(ProcKey, SignalKind)>,
    last_ns: Option<u64>,
}

pub struct Pipeline {
    pub table: ProcTable,
    scorer: Scorer,
    scan: ScanDetector,
    daemons: Box<dyn DaemonClassifier>,
    incidents: Incidents,
    pub sinks: Sinks,
    mode: Mode,
    /// Verifications in flight, by what is being verified: who is
    /// waiting, and the exe each had when it asked.
    pending: HashMap<ExeKey, Vec<(ProcKey, PathBuf)>>,
    /// Signals waiting on a verdict, by the verdict they wait on.
    deferred: HashMap<ExeKey, Vec<Deferred>>,
    /// Signals in `deferred`, in all.
    deferred_len: usize,
    /// Signals in `deferred`, per subject process.
    held: HashMap<ProcKey, usize>,
    /// The executables worth verifying: `Allowlist::verify_paths`.
    verify_paths: BTreeSet<PathBuf>,
    /// Per incident id, what it has recorded so far.
    // ponytail: one entry per incident for the daemon's life, like the
    // store's own map; evict both together if that ever matters.
    spoken: HashMap<String, Spoken>,
    /// Incident membership on the loop, by a local group number: the
    /// same grouping rule the store applies, kept here so the incident
    /// score can be computed without waiting on the writer thread.
    groups: HashMap<ProcKey, String>,
    /// Exited processes whose deferred signals are still waiting. Their
    /// scorer and group state is kept until those are scored.
    exited: Vec<ProcKey>,
    writer_gone_logged: bool,
    /// Verifications for the caller to run. Each key is queued once while
    /// in flight.
    pub to_verify: Vec<ExeKey>,
    pub events_total: u64,
    pub incident_dropped: u64,
    pub verify_skipped: u64,
    pub deferred_overflow: u64,
    /// Incident decisions not recorded, as they added nothing new.
    pub incident_suppressed: u64,
    debug: bool,
}

impl Pipeline {
    pub fn new(
        cfg: &Config,
        incidents: Incidents,
        sinks: Sinks,
        daemons: Box<dyn DaemonClassifier>,
        debug: bool,
    ) -> Self {
        let groups = incidents.store.memberships().into_iter().collect();
        Self {
            table: ProcTable::new(),
            scorer: Scorer::new(cfg),
            scan: ScanDetector::new(cfg.scoring.scan.clone()),
            daemons,
            incidents,
            sinks,
            mode: cfg.general.mode,
            pending: HashMap::new(),
            deferred: HashMap::new(),
            deferred_len: 0,
            held: HashMap::new(),
            verify_paths: cfg.allowlist.verify_paths(),
            spoken: HashMap::new(),
            // Seeded once from what the store loaded, so an incident opened
            // before a restart keeps its members. After this the store is
            // never asked: its lock must stay off the event loop's path.
            groups,
            exited: Vec::new(),
            writer_gone_logged: false,
            to_verify: Vec::new(),
            events_total: 0,
            incident_dropped: 0,
            verify_skipped: 0,
            deferred_overflow: 0,
            incident_suppressed: 0,
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
        self.verify_paths = cfg.allowlist.verify_paths();
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
        let gate = gated.and_then(|p| Some((p.exe.clone()?, p.exe_id?)));

        if let Some(path) = gate {
            if self.pending.contains_key(&path) {
                let held = self.held.get(&key).copied().unwrap_or(0);
                if held >= MAX_DEFERRED_PER_PROC || self.deferred_len >= MAX_DEFERRED {
                    self.deferred_overflow += 1;
                } else {
                    *self.held.entry(key).or_default() += 1;
                    self.deferred_len += 1;
                    self.deferred.entry(path).or_default().push(Deferred {
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
        let Some((exe, id)) = self
            .table
            .get(&key)
            .and_then(|p| Some((p.exe.clone()?, p.exe_id?)))
        else {
            return;
        };
        // Not named by any allowlist or pin: no verdict would change its
        // score, so no rpm call and no hash.
        if exe.as_os_str().is_empty() || !self.verify_paths.contains(&exe) {
            return;
        }
        let path = (exe.clone(), id);
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

    /// The verdict for a job queued in `to_verify`. Applied to every
    /// waiting process that still runs the exe it asked about, then any
    /// signal that was waiting on this key is scored.
    pub fn verified(&mut self, path: &ExeKey, v: Verification) {
        for (k, _) in self.pending.remove(path).unwrap_or_default() {
            // Only if it still runs this very file: same path is not
            // enough, a chroot can show another inode under it.
            let runs = self
                .table
                .get(&k)
                .is_some_and(|p| p.exe.as_ref() == Some(&path.0) && p.exe_id == Some(path.1));
            if runs {
                self.table.set_verification(&k, v.clone());
            }
        }
        let ready = self.deferred.remove(path).unwrap_or_default();
        for d in &ready {
            self.release(&d.subject.key);
        }
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
        self.reap_exited();
    }

    /// Scores every signal whose deadline has passed as Unverified. The
    /// caller runs this on a timer.
    pub fn flush_expired(&mut self, cutoff: Instant) {
        let mut expired = Vec::new();
        for v in self.deferred.values_mut() {
            let (gone, keep): (Vec<_>, Vec<_>) = std::mem::take(v)
                .into_iter()
                .partition(|d| d.deadline <= cutoff);
            *v = keep;
            expired.extend(gone);
        }
        self.deferred.retain(|_, v| !v.is_empty());
        // In the order they happened, whichever verdict each waited on.
        expired.sort_by_key(|d| d.ts_ns);
        for d in &expired {
            self.release(&d.subject.key);
        }
        for d in expired {
            self.score(
                &d.subject,
                &d.ancestors,
                d.signal,
                d.target.as_deref(),
                d.ts_ns,
            );
        }
        self.reap_exited();
    }

    /// One of `key`'s deferred signals has left the queue.
    fn release(&mut self, key: &ProcKey) {
        self.deferred_len -= 1;
        if let Some(n) = self.held.get_mut(key) {
            *n -= 1;
            if *n == 0 {
                self.held.remove(key);
            }
        }
    }

    /// Drops a process from the scorer, scan detector and every queue.
    ///
    /// Deferred signals are kept: their snapshots don't need the table,
    /// and a payload that exits before its verdict must still be scored.
    /// Until they are, the process's scorer and group state stays too.
    fn forget(&mut self, key: &ProcKey) {
        for w in self.pending.values_mut() {
            w.retain(|(k, _)| k != key);
        }
        self.pending.retain(|_, w| !w.is_empty());
        if self.held.contains_key(key) {
            if !self.exited.contains(key) {
                self.exited.push(*key);
            }
            return;
        }
        self.drop_state(key);
    }

    fn drop_state(&mut self, key: &ProcKey) {
        self.scorer.on_exit(key);
        self.scan.on_exit(key);
        self.groups.remove(key);
    }

    /// Finishes forgetting exited processes once nothing of theirs is
    /// deferred any more.
    fn reap_exited(&mut self) {
        let done: Vec<ProcKey> = self
            .exited
            .iter()
            .copied()
            .filter(|k| !self.held.contains_key(k))
            .collect();
        self.exited.retain(|k| !done.contains(k));
        for k in done {
            self.drop_state(&k);
        }
    }

    /// Scores every deferred signal now, as Unverified where its verdict
    /// hasn't come. For shutdown, so nothing held back is lost.
    pub fn flush_all(&mut self) {
        self.flush_expired(Instant::now() + Duration::from_secs(365 * 86400));
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
        let mut d = self.scorer.observe(subject, &refs, sig, target, ts_ns);
        // pid 1 and 2 (kthreadd) are never incident subjects or members,
        // and never drag a child's incident into a kernel-rooted group.
        if matches!(subject.key.tgid, 1 | 2) {
            return;
        }
        // The incident this process belongs to: its own, else its nearest
        // ancestor's. An incident is opened only by a process that reaches
        // Throttle on its own score (inherited kinds included); a tree in
        // which no single process does opens none.
        let group = std::iter::once(subject)
            .chain(ancestors)
            .find_map(|p| self.groups.get(&p.key).cloned());
        if group.is_none() && verdict(d.tier).is_none() {
            self.debug_log(subject, &d);
            return;
        }
        // The loop names a new incident itself, so the first telemetry
        // record already carries the id the writer will create.
        let g = group.unwrap_or_else(|| loop {
            let id = new_incident_id();
            if !self.groups.values().any(|v| *v == id) {
                break id;
            }
        });
        self.groups.insert(subject.key, g.clone());
        // Once an incident exists its tier follows the incident score: per
        // kind, the strongest live member's component, summed. A chain
        // split across processes (scan in the shell, ptrace in a child)
        // is judged as one. Evidence stays per process.
        let inc = self.incident_score(&g, ts_ns);
        if inc > d.score {
            d.score = inc;
            d.tier = self.scorer.tier(inc);
        }
        self.debug_log(subject, &d);
        let Some(verdict) = verdict(d.tier) else {
            return;
        };
        if !self.worth_saying(&g, subject.key, &d, ts_ns) {
            self.incident_suppressed += 1;
            return;
        }
        let tree: Vec<ProcInfo> = std::iter::once(subject.clone())
            .chain(ancestors.iter().cloned())
            .filter(|p| !matches!(p.key.tgid, 1 | 2))
            .collect();
        self.record(&d, tree, &g);
        let incident = g;
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
            target: target.map(|t| t.as_os_str().as_encoded_bytes().to_vec()),
            reasons: d.evidence.iter().map(|e| e.reason.clone()).collect(),
        });
    }

    /// Whether incident `g` should record this decision: its tier rose,
    /// this process shows this signal kind for the first time, or the
    /// incident has been quiet for a heartbeat. Updates what it has said.
    fn worth_saying(&mut self, g: &str, key: ProcKey, d: &Decision, ts_ns: u64) -> bool {
        let kinds = || {
            d.evidence
                .iter()
                .map(move |e| (key, SignalKind::of(&e.signal)))
        };
        let s = self.spoken.entry(g.to_string()).or_insert_with(|| Spoken {
            tier: Tier::Log,
            seen: HashSet::new(),
            last_ns: None,
        });
        let first = s.last_ns.is_none();
        let rose = d.tier > s.tier;
        let new = kinds().next_back().is_some_and(|k| !s.seen.contains(&k));
        let beat = s
            .last_ns
            .is_some_and(|l| ts_ns.saturating_sub(l) >= HEARTBEAT_NS);
        if !(first || rose || new || beat) {
            return false;
        }
        s.tier = s.tier.max(d.tier);
        s.last_ns = Some(s.last_ns.unwrap_or(0).max(ts_ns));
        // Everything this record carries has now been said.
        s.seen.extend(kinds());
        true
    }

    /// Sum over kinds of the max decayed component across the live
    /// members of group `g`.
    // ponytail: scans every member of every group; index by group if
    // incidents ever hold thousands of processes.
    fn incident_score(&self, g: &str, now_ns: u64) -> f64 {
        let members: Vec<&ProcKey> = self
            .groups
            .iter()
            .filter(|(_, v)| *v == g)
            .map(|(k, _)| k)
            .collect();
        // Decay everyone to the same instant, the latest any member has
        // been scored at, so an older event for one member doesn't leave
        // another's components looking fresher than they are.
        let at = members
            .iter()
            .map(|k| self.scorer.last_ts(k))
            .fold(now_ns, u64::max);
        let mut best = [0.0f64; KINDS];
        for k in members {
            for (b, c) in best.iter_mut().zip(self.scorer.components(k, at)) {
                *b = b.max(c);
            }
        }
        best.iter().sum()
    }

    fn debug_log(&self, subject: &ProcInfo, d: &Decision) {
        if self.debug {
            let last = d.evidence.last().map_or("", |e| e.reason.as_str());
            eprintln!(
                "aegisd: debug: tgid {} comm {} score {:.1} tier {:?}: {last}",
                subject.key.tgid, subject.comm, d.score, d.tier
            );
        }
    }

    fn record(&mut self, d: &Decision, tree: Vec<ProcInfo>, id: &str) {
        match &self.incidents.tx {
            Some(tx) => match tx.try_send((d.clone(), tree, self.mode, id.to_string())) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => self.incident_dropped += 1,
                Err(TrySendError::Disconnected(_)) => {
                    self.incident_dropped += 1;
                    if !self.writer_gone_logged {
                        self.writer_gone_logged = true;
                        eprintln!(
                            "aegisd: error: incident writer thread is gone; \
                                 incidents are no longer recorded"
                        );
                    }
                }
            },
            None => {
                if let Err(e) = self
                    .incidents
                    .store
                    .record_as(d, &tree, self.mode, Some(id))
                {
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
/// differ by the time the host spent suspended, which
/// `boottime_offset_ns` corrects for.
pub fn proc_start_matches(tgid: u32, start_time_ns: u64) -> bool {
    let Some(got) = proc_start_ns(tgid) else {
        return false;
    };
    // The probe's start is CLOCK_MONOTONIC; /proc's is CLOCK_BOOTTIME,
    // which also counts time suspended. Shift by the current gap so a
    // host that has slept still matches its live processes. One clock
    // tick of slack, since the stat value is quantised to ticks.
    let want = start_time_ns.saturating_add(boottime_offset_ns());
    let tick = 1_000_000_000 / clk_tck();
    got.abs_diff(want) <= tick
}

/// CLOCK_BOOTTIME minus CLOCK_MONOTONIC, now: the time spent suspended
/// since boot. Read fresh each call (two vDSO reads), so a suspend after
/// startup is accounted for too.
fn boottime_offset_ns() -> u64 {
    let read = |clock| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes one timespec we own.
        unsafe { libc::clock_gettime(clock, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    };
    read(libc::CLOCK_BOOTTIME).saturating_sub(read(libc::CLOCK_MONOTONIC))
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

    fn exe_key(p: &str) -> ExeKey {
        (p.into(), (0, 0))
    }

    fn lookups(jobs: &[ExeKey]) -> Vec<PathBuf> {
        jobs.iter().map(|j| j.0.clone()).collect()
    }

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn pipeline(name: &str) -> (Pipeline, Dir) {
        pipeline_with(name, |_| Sinks::none())
    }

    fn pipeline_with(name: &str, sinks: impl FnOnce(&Path) -> Sinks) -> (Pipeline, Dir) {
        let d = std::env::temp_dir().join(format!("aegis-pipe-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let sinks = sinks(&d.with_extension("jsonl"));
        let store =
            IncidentStore::open_at(&d, Some("boot".into()), now_ns() / 1_000_000_000).unwrap();
        let mut cfg = Config::default();
        cfg.allowlist.memfd_callers = vec!["/usr/bin/runc".into()];
        // Only allowlisted paths are verified. These tests watch
        // verification of a few more, so list them where they forgive
        // nothing here: a scanner needs root at a terminal, and no test
        // process has a terminal.
        cfg.allowlist.scan_binaries = [
            "/usr/bin/bash",
            "/usr/bin/x",
            "/usr/bin/y",
            "/usr/bin/python3",
        ]
        .into_iter()
        .map(PathBuf::from)
        .chain((0..MAX_PENDING + 3).map(|i| format!("/usr/bin/x{i}").into()))
        .chain(std::env::current_exe().ok())
        .collect();
        let mut p = Pipeline::new(&cfg, Incidents::inline(store), sinks, Box::new(Pid1), false);
        // No real processes behind these tgids: give each a clean
        // environment.
        p.table.environ = |_, _| Some(b"PATH=/usr/bin\0".to_vec());
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
        assert_eq!(
            lookups(&std::mem::take(&mut p.to_verify)),
            paths(&["/usr/bin/bash"])
        );
        p.verified(&exe_key("/usr/bin/bash"), rpm("bash"));
        p.handle(&fork(50, 60));
        p.handle(&exec(60, "/usr/bin/runc", 0));
        assert_eq!(
            lookups(&std::mem::take(&mut p.to_verify)),
            paths(&["/usr/bin/runc"])
        );
        // runc's verdict is NOT back yet: the memfd signals must defer.
        p.handle(&ev(EventKind::MemfdCreate, 60));
        p.handle(&exec(
            60,
            "/memfd:runc_cloned (deleted)",
            EXEC_MEMFD | EXEC_FROM_TMP,
        ));
        assert!(p.to_verify.is_empty(), "a memfd is not verified");
        assert_eq!(p.deferred_len, 2, "memfd_create and memfd exec deferred");
        if let Some(v) = runc_verdict {
            p.verified(&exe_key("/usr/bin/runc"), v);
        } else {
            // Verdict never comes: the deadline fires them as Unverified.
            p.flush_expired(Instant::now() + DEFER_DEADLINE + Duration::from_secs(1));
        }
        assert_eq!(p.deferred_len, 0);
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
        assert_eq!((l[0].max_score, l[0].root_tgid), (85.0, 60));
    }

    #[test]
    fn a_payload_that_exits_before_its_verdict_is_still_scored() {
        let (mut p, _d) = pipeline("exit-early");
        p.handle(&exec(60, "/usr/bin/runc", 0));
        p.to_verify.clear();
        p.handle(&ev(EventKind::MemfdCreate, 60));
        p.handle(&exec(60, "/memfd:x (deleted)", EXEC_MEMFD | EXEC_FROM_TMP));
        assert_eq!(p.deferred_len, 2);
        // Gone before the verdict: its signals must not go with it.
        p.handle(&ev(EventKind::Exit, 60));
        assert!(p.table.get(&key(60)).is_none());
        assert_eq!(p.deferred_len, 2);
        p.flush_expired(Instant::now() + DEFER_DEADLINE + Duration::from_secs(1));
        let l = p.store().list();
        assert_eq!(l.len(), 1);
        assert_eq!(
            (l[0].verdict.as_str(), l[0].max_score),
            ("would_quarantine", 85.0)
        );
        // Scored, then forgotten: no state is left behind for the dead key.
        assert!(p.exited.is_empty());
        assert!(!p.groups.contains_key(&key(60)));
        assert_eq!(p.scorer.last_ts(&key(60)), 0);
    }

    #[test]
    fn shutdown_flush_scores_whatever_is_still_deferred() {
        let (mut p, _d) = pipeline("flush-all");
        p.handle(&exec(60, "/usr/bin/runc", 0));
        p.to_verify.clear();
        p.handle(&ev(EventKind::MemfdCreate, 60));
        p.handle(&exec(60, "/memfd:x (deleted)", EXEC_MEMFD | EXEC_FROM_TMP));
        p.flush_all();
        assert_eq!(p.deferred_len, 0);
        assert_eq!(p.store().open_count(), 1);
    }

    #[test]
    fn a_verdict_that_lands_in_time_forgives_the_memfd_clone() {
        // The same as the verified case, but proving the verdict path (not
        // the deadline) is what cleared it: nothing is ever expired.
        let (mut p, _d) = pipeline("intime");
        p.handle(&exec(60, "/usr/bin/runc", 0));
        p.to_verify.clear();
        p.handle(&ev(EventKind::MemfdCreate, 60));
        assert_eq!(p.deferred_len, 1);
        p.verified(&exe_key("/usr/bin/runc"), rpm("runc"));
        assert_eq!(p.store().open_count(), 0);
    }

    #[test]
    fn a_preloaded_runc_is_quarantined_even_once_verified() {
        let (mut p, _d) = pipeline("preload");
        p.table.environ = |_, _| Some(b"LD_PRELOAD=/tmp/evil.so\0".to_vec());
        runc_self_clone(&mut p, Some(rpm("runc")));
        let l = p.store().list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].verdict, "would_quarantine");
        let inc = p
            .store()
            .get(&crate::incident::IncidentId(l[0].id.clone()))
            .unwrap();
        assert!(
            inc.evidence
                .iter()
                .any(|e| e.reason.ends_with("allowlist withheld: LD_PRELOAD is set")),
            "{:?}",
            inc.evidence
        );
        // Shown as verified all the same.
        assert_eq!(inc.root.verification, "rpm_owned:runc");
    }

    #[test]
    fn a_ptraced_runc_is_quarantined_even_once_verified() {
        let (mut p, _d) = pipeline("traced");
        p.handle(&exec(60, "/usr/bin/runc", 0));
        p.verified(&exe_key("/usr/bin/runc"), rpm("runc"));
        let mut a = ev(EventKind::Ptrace, 99);
        a.ptrace_request = 0x4206;
        a.target_tgid = 60;
        p.handle(&a);
        p.handle(&ev(EventKind::MemfdCreate, 60));
        p.handle(&exec(60, "/memfd:x (deleted)", EXEC_MEMFD | EXEC_FROM_TMP));
        let l = p.store().list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].verdict, "would_quarantine");
    }

    #[test]
    fn only_allowlisted_executables_are_verified() {
        let (mut p, _d) = pipeline("not-listed");
        p.handle(&exec(60, "/usr/bin/zzz", 0));
        assert!(p.to_verify.is_empty());
        assert!(p.pending.is_empty());
        // Nothing to wait for, so nothing is deferred either.
        p.handle(&ev(EventKind::MemfdCreate, 60));
        assert_eq!(p.deferred_len, 0);
        p.handle(&exec(61, "/usr/bin/runc", 0));
        assert_eq!(lookups(&p.to_verify), paths(&["/usr/bin/runc"]));
    }

    #[test]
    fn the_deadline_outlasts_a_slow_verification() {
        let (mut p, _d) = pipeline("slow");
        p.handle(&exec(60, "/usr/bin/runc", 0));
        p.handle(&ev(EventKind::MemfdCreate, 60));
        // Two rpm calls at their timeout: still waiting.
        p.flush_expired(Instant::now() + 2 * RPM_TIMEOUT);
        assert_eq!(p.deferred_len, 1);
        p.verified(&exe_key("/usr/bin/runc"), rpm("runc"));
        assert_eq!(p.deferred_len, 0);
        assert_eq!(p.store().open_count(), 0);
    }

    #[test]
    fn deferred_queue_has_a_global_cap() {
        let (mut p, _d) = pipeline("global-cap");
        let procs = MAX_DEFERRED / MAX_DEFERRED_PER_PROC + 2;
        for t in 0..procs as u32 {
            p.handle(&exec(10_000 + t, "/usr/bin/x", 0));
            for _ in 0..MAX_DEFERRED_PER_PROC {
                p.handle(&ev(EventKind::MemfdCreate, 10_000 + t));
            }
        }
        assert_eq!(p.deferred_len, MAX_DEFERRED);
        assert_eq!(
            p.deferred_overflow as usize,
            procs * MAX_DEFERRED_PER_PROC - MAX_DEFERRED
        );
        assert_eq!(p.held.values().sum::<usize>(), MAX_DEFERRED);
        p.verified(&exe_key("/usr/bin/x"), rpm("x"));
        assert_eq!(p.deferred_len, 0);
        assert!(p.held.is_empty() && p.deferred.is_empty());
    }

    fn timeline_len(p: &Pipeline) -> usize {
        let l = p.store().list();
        assert_eq!(l.len(), 1, "{l:?}");
        p.store()
            .timeline(&crate::incident::IncidentId(l[0].id.clone()))
            .unwrap()
            .len()
    }

    #[test]
    fn an_open_incident_records_only_what_is_new() {
        let (mut p, d) = pipeline_with("quiet", Sinks::jsonl_at);
        let at = |mut e: Event, secs: u64| {
            e.ts_ns = secs * 1_000_000_000;
            e
        };
        let mx = || exec(60, "/memfd:x (deleted)", EXEC_MEMFD | EXEC_FROM_TMP);
        // Unverified memfd exec: 85, an incident at quarantine at once.
        p.handle(&exec(60, "/tmp/x", 0));
        p.handle(&at(ev(EventKind::MemfdCreate, 60), 1));
        p.handle(&at(mx(), 1));
        assert_eq!(timeline_len(&p), 1);
        // A thousand more of the same add nothing, though the tier stays
        // up: each memfd exec tops its kind back up to 65.
        for i in 0..1000 {
            p.handle(&at(mx(), 2 + i / 100));
        }
        assert_eq!(timeline_len(&p), 1);
        assert_eq!(p.incident_suppressed, 1000);
        // A process in the tree showing a kind for the first time is news.
        p.handle(&fork(60, 61));
        p.handle(&at(ev(EventKind::MemfdCreate, 61), 20));
        assert_eq!(timeline_len(&p), 2);
        // A minute after that, one heartbeat, then quiet again.
        p.handle(&at(mx(), 81));
        p.handle(&at(mx(), 82));
        assert_eq!(timeline_len(&p), 3);
        assert_eq!(p.incident_suppressed, 1001);
        // Telemetry follows the records one for one.
        let log = d.0.with_extension("jsonl");
        let n = std::fs::read_to_string(&log).unwrap().lines().count();
        let _ = std::fs::remove_file(&log);
        assert_eq!(n, 3);
    }

    #[test]
    fn a_rising_tier_is_always_recorded() {
        let (mut p, _d) = pipeline("rise");
        // Shell at 65 (throttle), then a ptrace in the same process: 110.
        split_chain(&mut p, 80, 81, 80);
        let tl = p
            .store()
            .timeline(&crate::incident::IncidentId(p.store().list()[0].id.clone()))
            .unwrap();
        let tiers: Vec<&str> = tl.iter().map(|l| l["tier"].as_str().unwrap()).collect();
        // The shell's scan opens it; the child's first tmp exec is news;
        // its ptrace lifts the incident to quarantine.
        assert_eq!(tiers, ["throttle", "throttle", "quarantine"], "{tl:?}");
        // Each line carries only the evidence that is new with it.
        assert!(tl
            .iter()
            .all(|l| l["evidence"].as_array().unwrap().len() == 1));
    }

    #[test]
    fn deferred_queue_overflow_scores_at_once_and_counts() {
        let (mut p, _d) = pipeline("overflow");
        p.handle(&exec(90, "/usr/bin/x", 0));
        p.to_verify.clear();
        for _ in 0..MAX_DEFERRED_PER_PROC + 5 {
            p.handle(&ev(EventKind::MemfdCreate, 90));
        }
        assert_eq!(p.deferred_len, MAX_DEFERRED_PER_PROC);
        assert_eq!(p.deferred_overflow, 5);
    }

    fn connect(tgid: u32, port: u16) -> Event {
        let mut e = ev(EventKind::Connect, tgid);
        e.family = 2;
        e.daddr[..4].copy_from_slice(&[127, 0, 0, 1]);
        e.dport = port;
        e.ret = -111;
        e
    }

    fn ptrace_pid1(tgid: u32) -> Event {
        let mut e = ev(EventKind::Ptrace, tgid);
        e.ptrace_request = 16;
        e.target_tgid = 1;
        e
    }

    /// A shell `parent` (exec'd from /tmp by verified bash 79) and a child
    /// `child` that execs /tmp/st and attaches to pid 1. The child forks
    /// from `child_parent` before the shell scans, so it never inherits
    /// the scan: no single process reaches quarantine.
    fn split_chain(p: &mut Pipeline, parent: u32, child: u32, child_parent: u32) {
        p.handle(&exec(79, "/usr/bin/bash", 0));
        p.verified(&exe_key("/usr/bin/bash"), rpm("bash"));
        p.handle(&fork(79, parent));
        p.handle(&exec(parent, "/tmp/xsh", EXEC_FROM_TMP));
        p.verified(&exe_key("/tmp/xsh"), Verification::Unverified);
        p.handle(&fork(child_parent, child));
        for port in 0..20 {
            p.handle(&connect(parent, 40000 + port));
        }
        p.handle(&exec(child, "/tmp/st", EXEC_FROM_TMP));
        p.verified(&exe_key("/tmp/st"), Verification::Unverified);
        p.handle(&ptrace_pid1(child));
        p.to_verify.clear();
        assert_eq!(p.deferred_len, 0);
    }

    #[test]
    fn chain_split_across_processes_is_judged_as_one_incident() {
        let (mut p, _d) = pipeline("split");
        // Shell: tmp exec 25 + scan 40 = 65. Child: tmp exec 25 (inherited
        // from the shell before its scan) + ptrace 45 = 70. Incident: the
        // strongest of each kind, 25 + 40 + 45 = 110.
        split_chain(&mut p, 80, 81, 80);
        let l = p.store().list();
        assert_eq!(l.len(), 1, "{l:?}");
        assert_eq!(l[0].verdict, "would_quarantine");
        assert_eq!(l[0].max_score, 110.0);
        // Evidence keeps per-process attribution: the ptrace is the child's.
        let inc = p
            .store()
            .get(&crate::incident::IncidentId(l[0].id.clone()))
            .unwrap();
        let tgids: Vec<u32> = inc.process_tree.iter().map(|m| m.tgid).collect();
        assert_eq!(tgids, [80, 81]);
    }

    #[test]
    fn first_telemetry_record_names_the_incident_dir() {
        // A real writer channel, drained only after the events: telemetry
        // is emitted before any incident directory exists, as in the daemon.
        let (mut p, d) = pipeline_with("tel", Sinks::jsonl_at);
        let (tx, rx) = std::sync::mpsc::sync_channel::<RecordJob>(256);
        p.incidents.tx = Some(tx);
        split_chain(&mut p, 80, 81, 80);
        for (dec, tree, mode, id) in rx.try_iter() {
            p.store().record_as(&dec, &tree, mode, Some(&id)).unwrap();
        }
        let log = d.0.with_extension("jsonl");
        let text = std::fs::read_to_string(&log).unwrap();
        let _ = std::fs::remove_file(&log);
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        let id = first["incident"].as_str().unwrap();
        assert!(!id.is_empty(), "{first}");
        assert!(d.0.join(id).join("incident.json").exists(), "{id}");
        // Every record of this one incident carries the same id.
        for l in text.lines() {
            let r: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(r["incident"], id);
        }
    }

    #[test]
    fn unrelated_incidents_do_not_aggregate() {
        let (mut p, _d) = pipeline("unrelated");
        // The child forks from bash, not the shell: two separate trees.
        split_chain(&mut p, 80, 81, 79);
        let mut l = p.store().list();
        l.sort_by_key(|i| i.root_tgid);
        assert_eq!(l.len(), 2, "{l:?}");
        assert_eq!(
            (l[0].root_tgid, l[0].verdict.as_str()),
            (80, "would_throttle")
        );
        assert_eq!(
            (l[1].root_tgid, l[1].verdict.as_str()),
            (81, "would_throttle")
        );
        assert_eq!((l[0].max_score, l[1].max_score), (65.0, 70.0));
    }

    #[test]
    fn pid_1_is_never_an_incident_member() {
        let (mut p, _d) = pipeline("pid1");
        p.handle(&fork(1, 85));
        p.handle(&exec(85, "/tmp/x", EXEC_FROM_TMP));
        p.verified(&exe_key("/tmp/x"), Verification::Unverified);
        p.handle(&ptrace_pid1(85));
        let l = p.store().list();
        assert_eq!(l.len(), 1);
        let inc = p
            .store()
            .get(&crate::incident::IncidentId(l[0].id.clone()))
            .unwrap();
        assert!(inc.process_tree.iter().all(|m| !matches!(m.tgid, 1 | 2)));
        assert!(p.groups.keys().all(|k| !matches!(k.tgid, 1 | 2)));
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
        assert_eq!(lookups(&p.to_verify), paths(&["/usr/bin/x", "/usr/bin/y"]));
        assert_eq!(
            p.table.get(&key(70)).unwrap().verification,
            Verification::Unverified
        );
        p.verified(&exe_key("/usr/bin/x"), rpm("x"));
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
            p.to_verify.last().map(|j| j.0.as_path()),
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
        assert_eq!(
            lookups(&std::mem::take(&mut p.to_verify)),
            std::slice::from_ref(&exe)
        );
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

    #[test]
    fn same_path_different_inode_is_verified_separately() {
        let (mut p, _d) = pipeline("inode");
        p.handle(&exec(80, "/usr/bin/python3", 0));
        // A second process shows the same path but runs another file.
        let mut e = exec(81, "/usr/bin/python3", 0);
        e.exe_ino = 81;
        p.handle(&e);
        assert_eq!(p.to_verify.len(), 2, "no shared verdict across inodes");
        p.verified(&exe_key("/usr/bin/python3"), rpm("python3"));
        assert_eq!(p.table.get(&key(80)).unwrap().verification, rpm("python3"));
        assert_eq!(
            p.table.get(&key(81)).unwrap().verification,
            Verification::Unverified
        );
    }

    #[test]
    fn a_verdict_lands_only_on_the_inode_it_was_for() {
        // Pid 90 runs the host's x (inode 1), then a chroot's x (inode 2).
        // Whichever verdict lands last, the host's must not stick to it.
        for host_last in [true, false] {
            let (mut p, _d) = pipeline(if host_last { "inode-a" } else { "inode-b" });
            let mut a = exec(90, "/usr/bin/x", 0);
            a.exe_ino = 1;
            p.handle(&a);
            let mut b = exec(90, "/usr/bin/x", 0);
            b.exe_ino = 2;
            p.handle(&b);
            let (ka, kb) = (
                (PathBuf::from("/usr/bin/x"), (0, 1)),
                (PathBuf::from("/usr/bin/x"), (0, 2)),
            );
            if host_last {
                p.verified(&kb, Verification::Unverified);
                p.verified(&ka, rpm("x"));
            } else {
                p.verified(&ka, rpm("x"));
                p.verified(&kb, Verification::Unverified);
            }
            assert_eq!(
                p.table.get(&key(90)).unwrap().verification,
                Verification::Unverified,
                "host_last={host_last}"
            );
        }
    }
}
