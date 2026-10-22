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
//! - **Enforcement** (enforce mode) is queued in `to_enforce` for the
//!   caller to hand to the enforcer thread.
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
use crate::enforce::enforcer::{target_set, EnforceJob};
use crate::incident::{new_incident_id, verdict, IncidentStore};
use crate::proctable::{env_taint, ProcInfo, ProcKey, ProcTable, UNREADABLE};
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
/// How long an environment answer may take before it counts as
/// unreadable: the kernel's ExecEnv (lost if the ring buffer was full),
/// or a /proc read, which a process can make block for good.
const ENV_DEADLINE: Duration = Duration::from_secs(1);
/// Environment answers awaited; past this a process is tainted at once.
const MAX_ENV_READS: usize = 256;
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

/// A signal held back until what its trust depends on is known: the
/// gate process's verdict, and the environment of the processes whose
/// allowlist entries it could earn.
struct Deferred {
    /// True when the verdict belongs to the parent (a TmpExec is judged
    /// by its parent), false when it belongs to the subject itself.
    gate_is_parent: bool,
    subject: ProcInfo,
    ancestors: Vec<ProcInfo>,
    signal: Signal,
    target: Option<PathBuf>,
    /// For an exec, the process as the new image: what it is recorded as
    /// in an incident, while `subject` stays the image that did the exec.
    image: Option<ProcInfo>,
    ts_ns: u64,
    deadline: Instant,
    waits_exe: Option<ExeKey>,
    waits_env: Vec<ProcKey>,
}

/// An awaited environment answer, and for a /proc read the job the
/// caller runs off the loop: the process, the image (dev, ino) the
/// answer must be about, and the request's sequence number. A re-exec
/// of the same file keeps the key and the image, so only the number
/// tells a superseded answer from the current.
pub type EnvJob = (ProcKey, (u64, u64), u64);

#[cfg(test)]
type EnvBytes = Vec<u8>;

/// Reads an environment: tgid, start time, the image it must still be.
pub type EnvReader = fn(u32, u64, (u64, u64)) -> Option<Vec<u8>>;

/// What an open incident has already said, so a repeat isn't said again.
#[derive(Default)]
struct Spoken {
    tier: Option<Tier>,
    /// Per member, the signal kinds already recorded, one bit per kind.
    seen: HashMap<ProcKey, u8>,
    last_ns: Option<u64>,
}

fn bit(k: SignalKind) -> u8 {
    1 << k as u8
}

pub struct Pipeline {
    pub table: ProcTable,
    scorer: Scorer,
    scan: ScanDetector,
    daemons: Box<dyn DaemonClassifier>,
    incidents: Incidents,
    /// Shared with the enforcer, which reports its failures here too.
    pub sinks: Arc<Sinks>,
    mode: Mode,
    /// Verifications in flight, by what is being verified: who is
    /// waiting, and the exe each had when it asked.
    pending: HashMap<ExeKey, Vec<(ProcKey, PathBuf)>>,
    /// Signals waiting, by id, and the ids waiting on each verdict and
    /// on each process's environment. An index may hold ids already gone.
    deferred: HashMap<u64, Deferred>,
    next_id: u64,
    by_exe: HashMap<ExeKey, Vec<u64>>,
    by_env: HashMap<ProcKey, Vec<u64>>,
    /// Signals in `deferred`, per subject process.
    held: HashMap<ProcKey, usize>,
    /// Environment answers awaited: the image each is about, when it
    /// stops waiting and counts as unreadable, and whether the answer is
    /// a /proc read (else the kernel's ExecEnv).
    env_reads: HashMap<ProcKey, (EnvJob, Instant, bool)>,
    env_seq: u64,
    /// Environment reads for the caller to run.
    pub to_read_env: Vec<EnvJob>,
    /// Tests: answer every environment read at once, as an instant
    /// worker would.
    #[cfg(test)]
    env_auto: Option<fn(ProcKey) -> Option<EnvBytes>>,
    /// The executables worth verifying: `Allowlist::verify_paths`.
    verify_paths: BTreeSet<PathBuf>,
    /// Per incident id, what it has recorded so far.
    // ponytail: one entry per incident for the daemon's life, like the
    // store's own map; evict both together if that ever matters.
    spoken: HashMap<String, Spoken>,
    /// Per incident id, the tier enforcement was last asked for and the
    /// processes it covered: each kind is sent once, and after that only
    /// a newcomer to a quarantined tree gets a job of its own.
    // ponytail: kept for the daemon's life, like `spoken`.
    enforced: HashMap<String, (Tier, HashSet<ProcKey>)>,
    /// Enforcement for the caller to queue (enforce mode only).
    pub to_enforce: Vec<EnforceJob>,
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
            sinks: Arc::new(sinks),
            mode: cfg.general.mode,
            pending: HashMap::new(),
            deferred: HashMap::new(),
            next_id: 0,
            by_exe: HashMap::new(),
            by_env: HashMap::new(),
            held: HashMap::new(),
            env_reads: HashMap::new(),
            env_seq: 0,
            to_read_env: Vec::new(),
            #[cfg(test)]
            env_auto: None,
            verify_paths: cfg.allowlist.verify_paths(),
            spoken: HashMap::new(),
            enforced: HashMap::new(),
            to_enforce: Vec::new(),
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
            // Found late, with its exe read from /proc: verify that. It
            // predates us, so no ExecEnv will come: read /proc for that
            // too. Unless this is the ExecEnv, which `apply` takes below.
            self.request_verification(key);
            if kind != Some(EventKind::ExecEnv) {
                self.request_env(key, true);
            }
        }
        let mut sigs = signals_for(ev, &self.table, &*self.daemons);
        if kind == Some(EventKind::Connect) {
            sigs.extend(self.scan.on_connect(ev));
        }
        // For an exec, the target is the new image; the subject stays the
        // pre-exec binary (allowlists judge what did the exec).
        let target = (kind == Some(EventKind::Exec)).then(|| exec_path(ev));
        let image = match kind {
            Some(EventKind::Exec) if !sigs.is_empty() => self.table.get(&key).map(|p| {
                let mut p = p.clone();
                p.apply_exec(ev);
                p
            }),
            _ => None,
        };
        for sig in sigs {
            self.consider(key, sig, target.clone(), image.clone(), ev.ts_ns);
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
        match kind {
            Some(EventKind::Exec) => {
                // A memfd has no path to open, and a truncated path is not
                // the file.
                if ev.flags & (EXEC_MEMFD | PATH_TRUNCATED) == 0 {
                    self.request_verification(key);
                }
                // The kernel's verdict follows in this exec's ExecEnv.
                self.request_env(key, false);
            }
            // `apply` has put the kernel's verdict on the table.
            Some(EventKind::ExecEnv) if self.env_reads.contains_key(&key) => {
                let taint = self.table.get(&key).and_then(|p| p.env_taint);
                self.env_resolve(&key, taint);
            }
            // The child has its parent's environment, but if that is still
            // awaited, the child needs its own answer, from the same place.
            Some(EventKind::Fork) if self.env_reads.contains_key(&key) => {
                let from_proc = self.env_reads[&key].2;
                self.request_env(
                    ProcKey {
                        tgid: ev.child_tgid,
                        start_time_ns: ev.child_start_time_ns,
                    },
                    from_proc,
                );
            }
            _ => {}
        }
    }

    /// Waits for this process's environment, if anything it could be
    /// trusted for depends on it: an allowlisted or pinned exe, or an
    /// excluded SELinux domain. Until the answer lands it is tainted.
    ///
    /// The answer is the kernel's ExecEnv for an exec we saw, or with
    /// `from_proc` a /proc read queued in `to_read_env`, for a process
    /// that started before us.
    fn request_env(&mut self, key: ProcKey, from_proc: bool) {
        let Some(p) = self.table.get(&key) else {
            return;
        };
        let wants = p
            .exe
            .as_ref()
            .is_some_and(|e| self.verify_paths.contains(e))
            || self.scorer.selinux_excluded(p);
        if !wants {
            return;
        }
        let Some(image) = p.exe_id else {
            self.table.set_env(&key, Some(UNREADABLE), false);
            return;
        };
        // An older read for this process was about an image it no longer
        // runs; whatever waited on it can't be told now.
        if self.env_reads.contains_key(&key) {
            self.env_resolve(&key, Some(UNREADABLE));
        }
        if self.env_reads.len() >= MAX_ENV_READS {
            self.table.set_env(&key, Some(UNREADABLE), false);
            return;
        }
        self.table.set_env(&key, None, true);
        let job = (key, image, self.env_seq);
        self.env_seq += 1;
        self.env_reads
            .insert(key, (job, Instant::now() + ENV_DEADLINE, from_proc));
        #[cfg(test)]
        if let Some(f) = self.env_auto {
            self.env_read(job, f(key));
            return;
        }
        if from_proc {
            self.to_read_env.push(job);
        }
    }

    /// The answer to a job queued in `to_read_env`: the environment, or
    /// None if it couldn't be read. Ignored if that read was superseded
    /// or timed out. Also how a wait past its deadline is given up.
    pub fn env_read(&mut self, job: EnvJob, env: Option<Vec<u8>>) {
        let (key, image, _) = job;
        if self.env_reads.get(&key).map(|r| r.0) != Some(job) {
            return;
        }
        let taint = env_taint(env.as_deref());
        if self
            .table
            .get(&key)
            .is_some_and(|p| p.exe_id == Some(image))
        {
            self.table.set_env(&key, taint, false);
        }
        self.env_resolve(&key, taint);
    }

    /// `key`'s environment is settled as `taint`: put it on every
    /// signal waiting for it, and score those with nothing left to wait on.
    fn env_resolve(&mut self, key: &ProcKey, taint: Option<&'static str>) {
        self.env_reads.remove(key);
        for id in self.by_env.remove(key).unwrap_or_default() {
            let Some(d) = self.deferred.get_mut(&id) else {
                continue;
            };
            for p in std::iter::once(&mut d.subject).chain(d.ancestors.first_mut()) {
                if p.key == *key {
                    p.env_taint = taint;
                    p.env_pending = false;
                }
            }
            d.waits_env.retain(|k| k != key);
            self.try_release(id);
        }
        self.reap_exited();
    }

    /// Scores deferred signal `id` if it no longer waits on anything.
    fn try_release(&mut self, id: u64) {
        let ready = self
            .deferred
            .get(&id)
            .is_some_and(|d| d.waits_exe.is_none() && d.waits_env.is_empty());
        if !ready {
            return;
        }
        let d = self.deferred.remove(&id).unwrap();
        self.release(&d.subject.key);
        self.score(
            &d.subject,
            &d.ancestors,
            d.signal,
            d.target.as_deref(),
            d.image.as_ref(),
            d.ts_ns,
        );
    }

    /// Scores a signal now, or defers it if the verdict it needs is still
    /// in flight.
    fn consider(
        &mut self,
        key: ProcKey,
        sig: Signal,
        target: Option<PathBuf>,
        image: Option<ProcInfo>,
        ts_ns: u64,
    ) {
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
        let waits_exe = gated
            .and_then(|p| Some((p.exe.clone()?, p.exe_id?)))
            .filter(|g| self.pending.contains_key(g));
        // Whose environment the modifiers depend on: the subject's (its own
        // lists, its SELinux domain) and, for a tmp exec, the parent's.
        let waits_env: Vec<ProcKey> = std::iter::once(&subject)
            .chain(ancestors.first().filter(|_| gate_is_parent))
            .filter(|p| p.env_pending)
            .map(|p| p.key)
            .collect();

        if waits_exe.is_some() || !waits_env.is_empty() {
            let held = self.held.get(&key).copied().unwrap_or(0);
            if held >= MAX_DEFERRED_PER_PROC || self.deferred.len() >= MAX_DEFERRED {
                self.deferred_overflow += 1;
            } else {
                let id = self.next_id;
                self.next_id += 1;
                *self.held.entry(key).or_default() += 1;
                if let Some(g) = &waits_exe {
                    self.by_exe.entry(g.clone()).or_default().push(id);
                }
                for k in &waits_env {
                    self.by_env.entry(*k).or_default().push(id);
                }
                self.deferred.insert(
                    id,
                    Deferred {
                        gate_is_parent,
                        subject,
                        ancestors,
                        signal: sig,
                        target,
                        image,
                        ts_ns,
                        deadline: Instant::now() + DEFER_DEADLINE,
                        waits_exe,
                        waits_env,
                    },
                );
                return;
            }
        }
        self.score(
            &subject,
            &ancestors,
            sig,
            target.as_deref(),
            image.as_ref(),
            ts_ns,
        );
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
        for id in self.by_exe.remove(path).unwrap_or_default() {
            let Some(d) = self.deferred.get_mut(&id) else {
                continue;
            };
            // The gate's verdict is known now; put it on the snapshot.
            let gated = if d.gate_is_parent {
                d.ancestors.first_mut()
            } else {
                Some(&mut d.subject)
            };
            if let Some(p) = gated {
                p.verification = v.clone();
            }
            d.waits_exe = None;
            self.try_release(id);
        }
        self.reap_exited();
    }

    /// Scores every signal whose deadline has passed, as Unverified or
    /// tainted for whatever it still waited on, and gives up on
    /// environment reads past theirs. The caller runs this on a timer.
    pub fn flush_expired(&mut self, cutoff: Instant) {
        let late: Vec<ProcKey> = self
            .env_reads
            .iter()
            .filter(|(_, (_, at, _))| *at <= cutoff)
            .map(|(k, _)| *k)
            .collect();
        for k in late {
            let job = self.env_reads[&k].0;
            self.env_read(job, None);
        }
        let mut expired: Vec<(u64, u64)> = self
            .deferred
            .iter()
            .filter(|(_, d)| d.deadline <= cutoff)
            .map(|(id, d)| (d.ts_ns, *id))
            .collect();
        // In the order they happened, whatever each waited on.
        expired.sort();
        for (_, id) in expired {
            let d = self.deferred.remove(&id).unwrap();
            self.release(&d.subject.key);
            self.score(
                &d.subject,
                &d.ancestors,
                d.signal,
                d.target.as_deref(),
                d.image.as_ref(),
                d.ts_ns,
            );
        }
        self.reap_exited();
    }

    /// One of `key`'s deferred signals has left the queue.
    fn release(&mut self, key: &ProcKey) {
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
        if let Some(g) = self.groups.remove(key) {
            if let Some(s) = self.spoken.get_mut(&g) {
                s.seen.remove(key);
            }
        }
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
        image: Option<&ProcInfo>,
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
        let tree: Vec<ProcInfo> = std::iter::once(image.unwrap_or(subject).clone())
            .chain(ancestors.iter().cloned())
            .filter(|p| !matches!(p.key.tgid, 1 | 2))
            .collect();
        // Dropped (writer queue full): nothing counts as said, so the
        // next decision tries again, telemetry included.
        if !self.record(&d, tree, &g) {
            return;
        }
        self.said(&g, subject.key, &d, ts_ns);
        if self.mode == Mode::Enforce {
            self.enforce(&g, subject.key, d.tier);
        }
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

    /// Queues enforcement for incident `g`, now at `tier` after `key`'s
    /// decision: the whole tree the first time it reaches each tier, and
    /// once quarantined, any process the quarantine didn't cover.
    fn enforce(&mut self, g: &str, key: ProcKey, tier: Tier) {
        let me = std::process::id();
        if let Some((Tier::Quarantine, covered)) = self.enforced.get_mut(g) {
            if covered.contains(&key) {
                return;
            }
            let pids: Vec<ProcKey> = target_set(&self.table, &[key], me)
                .into_iter()
                .filter(|k| !covered.contains(k))
                .collect();
            if !pids.is_empty() {
                covered.extend(&pids);
                self.to_enforce
                    .push(EnforceJob::Quarantine { id: g.into(), pids });
            }
            return;
        }
        if tier == Tier::Log || self.enforced.get(g).is_some_and(|e| e.0 >= tier) {
            return;
        }
        let members: Vec<ProcKey> = self
            .groups
            .iter()
            .filter(|(_, v)| *v == g)
            .map(|(k, _)| *k)
            .collect();
        let pids = target_set(&self.table, &members, me);
        if pids.is_empty() {
            return;
        }
        self.enforced
            .insert(g.into(), (tier, pids.iter().copied().collect()));
        let id = g.into();
        self.to_enforce.push(match tier {
            Tier::Quarantine => EnforceJob::Quarantine { id, pids },
            _ => EnforceJob::Throttle { id, pids },
        });
    }

    /// Whether incident `g` should record this decision: its first, a
    /// tier rise, this process showing this signal kind for the first
    /// time, or a heartbeat since the incident last recorded.
    fn worth_saying(&self, g: &str, key: ProcKey, d: &Decision, ts_ns: u64) -> bool {
        let Some(s) = self.spoken.get(g) else {
            return true;
        };
        let Some(last) = s.last_ns else {
            return true;
        };
        let rose = s.tier.is_none_or(|t| d.tier > t);
        let seen = s.seen.get(&key).copied().unwrap_or(0);
        let new = d
            .evidence
            .last()
            .is_some_and(|e| seen & bit(SignalKind::of(&e.signal)) == 0);
        let beat = ts_ns.saturating_sub(last) >= HEARTBEAT_NS;
        rose || new || beat
    }

    /// Notes what a recorded decision said: its tier, the time, and every
    /// signal kind it carries for this process.
    fn said(&mut self, g: &str, key: ProcKey, d: &Decision, ts_ns: u64) {
        let s = self.spoken.entry(g.to_string()).or_default();
        s.tier = s.tier.max(Some(d.tier));
        s.last_ns = Some(s.last_ns.unwrap_or(0).max(ts_ns));
        let seen = s.seen.entry(key).or_default();
        for e in &d.evidence {
            *seen |= bit(SignalKind::of(&e.signal));
        }
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

    /// Sends the decision to be recorded; false if it was dropped.
    fn record(&mut self, d: &Decision, tree: Vec<ProcInfo>, id: &str) -> bool {
        match &self.incidents.tx {
            Some(tx) => match tx.try_send((d.clone(), tree, self.mode, id.to_string())) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    self.incident_dropped += 1;
                    false
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.incident_dropped += 1;
                    if !self.writer_gone_logged {
                        self.writer_gone_logged = true;
                        eprintln!(
                            "aegisd: error: incident writer thread is gone; \
                                 incidents are no longer recorded"
                        );
                    }
                    false
                }
            },
            None => match self
                .incidents
                .store
                .record_as(d, &tree, self.mode, Some(id))
            {
                Ok(_) => true,
                Err(e) => {
                    self.incidents.errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "aegisd: recording incident for tgid {} failed: {e:#}",
                        d.key.tgid
                    );
                    false
                }
            },
        }
    }
}

/// Runs environment reads on their own threads, at most `max` at once. A
/// read can block for good (a FUSE-backed environment), so a stuck
/// thread is simply left behind; past the cap a job fails at once, and
/// the pipeline's deadline covers any answer that never comes. Either
/// way the process counts as tainted.
pub struct EnvReaders {
    inflight: Arc<std::sync::atomic::AtomicUsize>,
    max: usize,
    reader: EnvReader,
}

impl EnvReaders {
    pub fn new() -> Self {
        Self::with(crate::proctable::read_environ, 16)
    }

    pub fn with(reader: EnvReader, max: usize) -> Self {
        Self {
            inflight: Arc::default(),
            max,
            reader,
        }
    }

    /// Reads `job` off the caller's thread; `done` gets the answer.
    pub fn spawn(&self, job: EnvJob, done: impl FnOnce(EnvJob, Option<Vec<u8>>) + Send + 'static) {
        if self.inflight.fetch_add(1, Ordering::SeqCst) >= self.max {
            self.inflight.fetch_sub(1, Ordering::SeqCst);
            done(job, None);
            return;
        }
        let (n, read) = (self.inflight.clone(), self.reader);
        let r = std::thread::Builder::new()
            .name("aegis-env".into())
            .spawn(move || {
                let env = read(job.0.tgid, job.0.start_time_ns, job.1);
                n.fetch_sub(1, Ordering::SeqCst);
                done(job, env);
            });
        if r.is_err() {
            // No answer will come; the deadline taints it.
            self.inflight.fetch_sub(1, Ordering::SeqCst);
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
    use aegis_common::{ENV_LOADER_VAR, ENV_TRUNCATED, ENV_UNREADABLE, EXEC_FROM_TMP};

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
        p.env_auto = Some(|_| Some(b"PATH=/usr/bin\0".to_vec()));
        p.table.host_pidns = |_| true;
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

    fn exec_env(tgid: u32, flags: u32) -> Event {
        let mut e = ev(EventKind::ExecEnv, tgid);
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
        runc_self_clone_env(p, runc_verdict, None);
    }

    /// The same flow, with the kernel's environment verdict for runc's
    /// exec, if `env` is given, landing right behind it as it does live.
    fn runc_self_clone_env(p: &mut Pipeline, runc_verdict: Option<Verification>, env: Option<u32>) {
        p.handle(&exec(50, "/usr/bin/bash", 0));
        assert_eq!(
            lookups(&std::mem::take(&mut p.to_verify)),
            paths(&["/usr/bin/bash"])
        );
        p.verified(&exe_key("/usr/bin/bash"), rpm("bash"));
        p.handle(&fork(50, 60));
        p.handle(&exec(60, "/usr/bin/runc", 0));
        if let Some(flags) = env {
            p.handle(&exec_env(60, flags));
        }
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
        assert_eq!(p.deferred.len(), 2, "memfd_create and memfd exec deferred");
        let flushed = runc_verdict.is_none();
        if let Some(v) = runc_verdict {
            p.verified(&exe_key("/usr/bin/runc"), v);
        } else {
            // Verdict never comes: the deadline fires them as Unverified.
            p.flush_expired(Instant::now() + DEFER_DEADLINE + Duration::from_secs(1));
        }
        // Without an environment verdict the signals still wait for one.
        if p.env_auto.is_some() || env.is_some() || flushed {
            assert_eq!(p.deferred.len(), 0);
        }
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
        assert_eq!(p.deferred.len(), 2);
        // Gone before the verdict: its signals must not go with it.
        p.handle(&ev(EventKind::Exit, 60));
        assert!(p.table.get(&key(60)).is_none());
        assert_eq!(p.deferred.len(), 2);
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
        assert_eq!(p.deferred.len(), 0);
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
        assert_eq!(p.deferred.len(), 1);
        p.verified(&exe_key("/usr/bin/runc"), rpm("runc"));
        assert_eq!(p.store().open_count(), 0);
    }

    #[test]
    fn a_preloaded_runc_is_quarantined_even_once_verified() {
        let (mut p, _d) = pipeline("preload");
        p.env_auto = Some(|_| Some(b"LD_PRELOAD=/tmp/evil.so\0".to_vec()));
        runc_self_clone(&mut p, Some(rpm("runc")));
        let l = p.store().list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].verdict, "would_quarantine");
        let inc = p
            .store()
            .get(&crate::incident::IncidentId(l[0].id.clone()))
            .unwrap();
        assert!(
            inc.evidence.iter().any(|e| e
                .reason
                .ends_with("allowlist withheld: LD_PRELOAD, LD_AUDIT or LD_LIBRARY_PATH is set")),
            "{:?}",
            inc.evidence
        );
        // Recorded as the memfd it runs now, which nothing can verify.
        assert_eq!(
            inc.root.exe.as_deref(),
            Some("/memfd:runc_cloned (deleted)")
        );
        assert_eq!(inc.root.verification, "unverified");
    }

    fn evidence(p: &Pipeline) -> Vec<String> {
        let l = p.store().list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].verdict, "would_quarantine");
        let inc = p
            .store()
            .get(&crate::incident::IncidentId(l[0].id.clone()))
            .unwrap();
        inc.evidence.iter().map(|e| e.reason.clone()).collect()
    }

    #[test]
    fn preload_flag_on_exec_env_withholds_allowlist() {
        let (mut p, _d) = pipeline("exec-env-preload");
        p.env_auto = None;
        runc_self_clone_env(&mut p, Some(rpm("runc")), Some(ENV_LOADER_VAR));
        let ev = evidence(&p);
        assert!(
            ev.iter().any(|r| r
                .ends_with("allowlist withheld: LD_PRELOAD, LD_AUDIT or LD_LIBRARY_PATH is set")),
            "{ev:?}"
        );
    }

    #[test]
    fn clean_exec_env_forgives_verified_runc() {
        let (mut p, _d) = pipeline("exec-env-clean");
        p.env_auto = None;
        runc_self_clone_env(&mut p, Some(rpm("runc")), Some(0));
        assert_eq!(p.store().open_count(), 0);
    }

    #[test]
    fn missing_exec_env_fails_closed_at_deadline() {
        let (mut p, _d) = pipeline("exec-env-missing");
        p.env_auto = None;
        runc_self_clone_env(&mut p, Some(rpm("runc")), None);
        assert_eq!(p.deferred.len(), 2, "still waiting for the environment");
        p.flush_all();
        let ev = evidence(&p);
        assert!(ev.iter().any(|r| r.contains("could not be read")), "{ev:?}");
    }

    #[test]
    fn a_truncated_or_unreadable_exec_env_fails_closed() {
        for flags in [ENV_TRUNCATED, ENV_UNREADABLE] {
            let (mut p, _d) = pipeline(&format!("exec-env-{flags}"));
            p.env_auto = None;
            runc_self_clone_env(&mut p, Some(rpm("runc")), Some(flags));
            let ev = evidence(&p);
            assert!(ev.iter().any(|r| r.contains("could not be read")), "{ev:?}");
        }
    }

    #[test]
    fn live_exec_never_reads_proc_env() {
        let (mut p, _d) = pipeline("exec-env-noproc");
        p.env_auto = None;
        p.handle(&exec(60, "/usr/bin/runc", 0));
        assert!(p.table.get(&key(60)).unwrap().env_pending);
        p.handle(&exec_env(60, 0));
        assert!(p.to_read_env.is_empty());
        let me = p.table.get(&key(60)).unwrap();
        assert!(!me.env_pending);
        assert_eq!(me.taint(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn late_found_process_still_reads_proc_env() {
        // This test process stands in for one that predates the daemon:
        // its exe is on the verify list, and no ExecEnv will come for it.
        let (mut p, _d) = pipeline("late-env");
        p.env_auto = None;
        let me = std::process::id();
        let mut e = ev(EventKind::MemfdCreate, me);
        e.start_time_ns = proc_start_ns(me).unwrap();
        p.handle(&e);
        let jobs = std::mem::take(&mut p.to_read_env);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].0.tgid, me);
    }

    #[test]
    fn signals_wait_for_the_kernels_environment_verdict() {
        let (mut p, _d) = pipeline("env-async");
        p.env_auto = None;
        p.handle(&exec(60, "/usr/bin/runc", 0));
        assert!(p.table.get(&key(60)).unwrap().env_pending);
        p.verified(&exe_key("/usr/bin/runc"), rpm("runc"));
        p.handle(&ev(EventKind::MemfdCreate, 60));
        assert_eq!(p.deferred.len(), 1, "waits for the environment");
        p.handle(&exec_env(60, 0));
        assert_eq!(p.deferred.len(), 0);
        p.handle(&exec(60, "/memfd:x (deleted)", EXEC_MEMFD | EXEC_FROM_TMP));
        assert_eq!(p.store().open_count(), 0);
    }

    #[test]
    fn an_environment_verdict_that_never_comes_taints_after_its_deadline() {
        let (mut p, _d) = pipeline("env-stuck");
        p.env_auto = None;
        p.handle(&exec(60, "/usr/bin/runc", 0));
        p.verified(&exe_key("/usr/bin/runc"), rpm("runc"));
        p.handle(&ev(EventKind::MemfdCreate, 60));
        p.handle(&exec(60, "/memfd:x (deleted)", EXEC_MEMFD | EXEC_FROM_TMP));
        assert_eq!(p.deferred.len(), 2);
        // Not yet: the loop doesn't wait, it just hasn't heard.
        p.flush_expired(Instant::now());
        assert_eq!(p.deferred.len(), 2);
        p.flush_expired(Instant::now() + ENV_DEADLINE + Duration::from_millis(1));
        assert_eq!(p.deferred.len(), 0);
        let l = p.store().list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].verdict, "would_quarantine");
        // A late answer changes nothing.
        p.handle(&exec_env(60, 0));
        assert_eq!(p.store().list()[0].verdict, "would_quarantine");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_superseded_proc_read_for_the_same_image_is_ignored() {
        let (mut p, _d) = pipeline("env-seq");
        p.env_auto = None;
        let me = std::process::id();
        let st = proc_start_ns(me).unwrap();
        let mut e = ev(EventKind::MemfdCreate, me);
        e.start_time_ns = st;
        p.handle(&e);
        let old = std::mem::take(&mut p.to_read_env)[0];
        // It re-execs the very same file: same key, same image, and the
        // kernel answers for the new image instead.
        let exe = std::env::current_exe().unwrap();
        let md = std::fs::metadata(&exe).unwrap();
        let mut x = exec(me, exe.to_str().unwrap(), 0);
        x.start_time_ns = st;
        x.exe_ino = std::os::unix::fs::MetadataExt::ino(&md);
        let dev = std::os::unix::fs::MetadataExt::dev(&md);
        x.exe_dev = (libc::major(dev) << 20) | libc::minor(dev);
        p.handle(&x);
        assert!(p.to_read_env.is_empty());
        let k = old.0;
        assert_eq!(p.env_reads[&k].0 .1, old.1, "same image");
        // The old read lands late, and clean. It must not count.
        p.env_read(old, Some(b"PATH=/usr/bin\0".to_vec()));
        assert!(p.table.get(&k).unwrap().env_pending);
        // The kernel's does.
        let mut v = exec_env(me, 0);
        v.start_time_ns = st;
        p.handle(&v);
        assert_eq!(p.table.get(&k).unwrap().taint(), None);
    }

    #[test]
    fn a_reader_that_blocks_forever_never_blocks_the_caller() {
        fn stuck(_: u32, _: u64, _: (u64, u64)) -> Option<Vec<u8>> {
            loop {
                std::thread::park();
            }
        }
        let r = EnvReaders::with(stuck, 2);
        let (tx, rx) = std::sync::mpsc::channel();
        let t = Instant::now();
        for i in 0..4 {
            let tx = tx.clone();
            r.spawn((key(i), (0, 0), 0), move |j, env| {
                let _ = tx.send((j.0.tgid, env));
            });
        }
        assert!(t.elapsed() < Duration::from_secs(1));
        // Two threads are stuck; the two past the cap fail at once.
        let mut got: Vec<_> = rx.try_iter().collect();
        got.sort();
        assert_eq!(got, [(2, None), (3, None)]);
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
        assert_eq!(p.deferred.len(), 0);
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
        assert_eq!(p.deferred.len(), 1);
        p.verified(&exe_key("/usr/bin/runc"), rpm("runc"));
        assert_eq!(p.deferred.len(), 0);
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
        assert_eq!(p.deferred.len(), MAX_DEFERRED);
        assert_eq!(
            p.deferred_overflow as usize,
            procs * MAX_DEFERRED_PER_PROC - MAX_DEFERRED
        );
        assert_eq!(p.held.values().sum::<usize>(), MAX_DEFERRED);
        p.verified(&exe_key("/usr/bin/x"), rpm("x"));
        assert_eq!(p.deferred.len(), 0);
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
    fn a_decision_dropped_on_a_full_queue_is_not_taken_as_said() {
        let (mut p, _d) = pipeline("full");
        // A writer queue with room for one.
        let (tx, rx) = std::sync::mpsc::sync_channel::<RecordJob>(1);
        p.incidents.tx = Some(tx);
        let mx = || exec(60, "/memfd:x (deleted)", EXEC_MEMFD | EXEC_FROM_TMP);
        p.handle(&exec(60, "/tmp/x", 0));
        p.handle(&ev(EventKind::MemfdCreate, 60));
        // The opening record takes the one slot; nothing drains it.
        p.handle(&mx());
        // A new process with a new kind: news, but the queue is full.
        p.handle(&fork(60, 61));
        p.handle(&ev(EventKind::MemfdCreate, 61));
        assert_eq!(p.incident_dropped, 1);
        assert_eq!(p.incident_suppressed, 0);
        // Room again: the same news is still news, and gets through.
        assert_eq!(rx.try_iter().count(), 1, "the opening record");
        p.handle(&ev(EventKind::MemfdCreate, 61));
        assert_eq!(rx.try_iter().count(), 1);
        assert_eq!(p.incident_suppressed, 0);
        // Said now, so a repeat is not.
        p.handle(&ev(EventKind::MemfdCreate, 61));
        assert_eq!(p.incident_suppressed, 1);
    }

    #[test]
    fn an_exited_member_leaves_nothing_in_the_incident_state() {
        let (mut p, _d) = pipeline("prune");
        let mx = || exec(60, "/memfd:x (deleted)", EXEC_MEMFD | EXEC_FROM_TMP);
        p.handle(&exec(60, "/tmp/x", 0));
        p.handle(&ev(EventKind::MemfdCreate, 60));
        p.handle(&mx());
        p.handle(&fork(60, 61));
        p.handle(&ev(EventKind::MemfdCreate, 61));
        let g = p.groups[&key(61)].clone();
        assert!(p.spoken[&g].seen.contains_key(&key(61)));
        p.handle(&ev(EventKind::Exit, 61));
        assert!(!p.spoken[&g].seen.contains_key(&key(61)));
        assert!(p.spoken[&g].seen.contains_key(&key(60)));
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
        assert_eq!(p.deferred.len(), MAX_DEFERRED_PER_PROC);
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
        assert_eq!(p.deferred.len(), 0);
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
    fn member_joining_at_its_exec_is_recorded_as_the_new_image() {
        let (mut p, _d) = pipeline("image");
        // The child joins on the tmp exec of /tmp/st. Its member entry is
        // the image it runs from then on, not the shell it was forked as.
        split_chain(&mut p, 80, 81, 80);
        let l = p.store().list();
        let inc = p
            .store()
            .get(&crate::incident::IncidentId(l[0].id.clone()))
            .unwrap();
        let exes: Vec<_> = inc
            .process_tree
            .iter()
            .map(|m| m.exe.as_deref().unwrap())
            .collect();
        assert_eq!(exes, ["/tmp/xsh", "/tmp/st"]);
        // Evidence names its signal by the stable weight key, and the
        // detail a variant carries goes in the reason.
        let ev: Vec<_> = inc
            .evidence
            .iter()
            .map(|e| (e.signal.as_str(), e.reason.as_str()))
            .collect();
        assert_eq!(
            ev,
            [
                ("tmp_exec", "exec from a temp directory (/tmp/xsh)"),
                ("egress_scan", "egress scan (10 distinct targets)"),
                ("tmp_exec", "exec from a temp directory (/tmp/st)"),
                (
                    "ptrace_system_daemon",
                    "ptrace attach to a system daemon (pid 1)"
                ),
            ]
        );
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

    fn tgids(pids: &[ProcKey]) -> Vec<u32> {
        pids.iter().map(|k| k.tgid).collect()
    }

    #[test]
    fn audit_mode_emits_no_enforce_jobs() {
        let (mut p, _d) = pipeline("enf-audit");
        split_chain(&mut p, 80, 81, 80);
        assert!(p.to_enforce.is_empty());
    }

    #[test]
    fn enforce_mode_emits_throttle_then_quarantine_once() {
        let (mut p, _d) = pipeline("enf-on");
        p.mode = Mode::Enforce;
        split_chain(&mut p, 80, 81, 80);
        let id = p.store().list()[0].id.clone();
        // bash 79, the shell's parent, is never in either set.
        match &p.to_enforce[..] {
            [EnforceJob::Throttle { id: a, pids: t }, EnforceJob::Quarantine { id: b, pids: q }] => {
                assert_eq!((a, b), (&id, &id));
                assert_eq!(tgids(t), [80, 81]);
                assert_eq!(tgids(q), [80, 81]);
            }
            j => panic!("{j:?}"),
        }
    }

    #[test]
    fn newcomer_to_a_quarantined_incident_gets_its_own_job() {
        let (mut p, _d) = pipeline("enf-new");
        p.mode = Mode::Enforce;
        split_chain(&mut p, 80, 81, 80);
        p.to_enforce.clear();
        // Already covered: a member scoring again sends nothing.
        p.handle(&ptrace_pid1(81));
        assert!(p.to_enforce.is_empty());
        p.handle(&fork(80, 90));
        p.handle(&exec(90, "/tmp/z", EXEC_FROM_TMP));
        p.verified(&exe_key("/tmp/z"), Verification::Unverified);
        match &p.to_enforce[..] {
            [EnforceJob::Quarantine { pids, .. }] => assert_eq!(tgids(pids), [90]),
            j => panic!("{j:?}"),
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
