// SPDX-License-Identifier: MIT OR Apache-2.0
//! One probe event at a time: process table, scoring, incidents and
//! telemetry.
//!
//! Everything here is synchronous and owned by the main loop. The one
//! slow step, executable verification, is handed out: `handle` queues
//! paths in `to_verify`, the caller runs the Verifier off the event
//! loop, and hands each verdict back through `verified`. Until then the
//! process stays `Unverified`, which earns no allowlist offsets.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aegis_common::{Event, EventKind, EXEC_MEMFD, PATH_TRUNCATED};

use crate::config::{Config, Mode};
use crate::incident::{verdict, IncidentStore};
use crate::proctable::{ProcInfo, ProcKey, ProcTable};
use crate::scoring::{signals_for, DaemonClassifier, ScanDetector, Scorer, Signal};
use crate::telemetry::{now_ns, Sinks, TelemetryRecord};
use crate::verify::Verification;

/// Maps a process's exe path to the path aegisd should open to verify it.
pub type Resolve = fn(u32, &Path) -> Option<PathBuf>;

pub struct Pipeline {
    pub table: ProcTable,
    scorer: Scorer,
    scan: ScanDetector,
    daemons: Box<dyn DaemonClassifier>,
    pub incidents: IncidentStore,
    pub sinks: Sinks,
    mode: Mode,
    resolve: Resolve,
    /// Verifications in flight, by the path being verified: who is
    /// waiting, and the exe each had when it asked.
    pending: HashMap<PathBuf, Vec<(ProcKey, PathBuf)>>,
    /// Paths for the caller to verify. Each is queued once while in flight.
    pub to_verify: Vec<PathBuf>,
    pub events_total: u64,
    pub incident_errors: u64,
    debug: bool,
}

impl Pipeline {
    pub fn new(
        cfg: &Config,
        incidents: IncidentStore,
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
            to_verify: Vec::new(),
            events_total: 0,
            incident_errors: 0,
            debug,
        }
    }

    /// Takes a reloaded config. Scores and scan windows carry over.
    pub fn set_config(&mut self, cfg: &Config) {
        self.scorer.set_config(cfg);
        self.scan.set_config(cfg.scoring.scan.clone());
        self.mode = cfg.general.mode;
    }

    pub fn handle(&mut self, ev: &Event) {
        self.events_total += 1;
        let key = ProcKey {
            tgid: ev.tgid,
            start_time_ns: ev.start_time_ns,
        };
        let kind = EventKind::try_from(ev.kind).ok();
        // Score before applying: for an Exec the allowlists judge the
        // binary that did the exec, which is the table's view until
        // `apply` replaces it. Score after and runc's memfd self-clone,
        // judged as the memfd it starts, scores 60.
        if kind != Some(EventKind::Exit) && self.table.ensure(ev) && kind != Some(EventKind::Exec) {
            // Found late, with its exe read from /proc: verify that.
            self.request_verification(key);
        }
        let mut sigs = signals_for(ev, &self.table, &*self.daemons);
        if kind == Some(EventKind::Connect) {
            sigs.extend(self.scan.on_connect(ev));
        }
        for sig in sigs {
            self.score(key, sig, ev.ts_ns);
        }
        match kind {
            Some(EventKind::Exit) => {
                self.scorer.on_exit(&key);
                self.scan.on_exit(&key);
            }
            Some(EventKind::Fork) => {
                let child = ProcKey {
                    tgid: ev.child_tgid,
                    start_time_ns: ev.child_start_time_ns,
                };
                self.scorer.on_fork(&key, &child, ev.ts_ns);
                // A child forked while its parent's exe is being verified
                // shares the parent's image, so it waits on the same verdict.
                for w in self.pending.values_mut() {
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

    fn request_verification(&mut self, key: ProcKey) {
        let Some(exe) = self.table.get(&key).and_then(|p| p.exe.clone()) else {
            return;
        };
        if exe.as_os_str().is_empty() {
            return;
        }
        let Some(path) = (self.resolve)(key.tgid, &exe) else {
            return;
        };
        let waiting = self.pending.entry(path.clone()).or_default();
        if waiting.is_empty() {
            self.to_verify.push(path);
        }
        waiting.push((key, exe));
    }

    /// The verdict for a path queued in `to_verify`. Applied to every
    /// waiting process that still runs the exe it asked about.
    pub fn verified(&mut self, path: &Path, v: Verification) {
        for (k, exe) in self.pending.remove(path).unwrap_or_default() {
            if self.table.get(&k).and_then(|p| p.exe.as_ref()) == Some(&exe) {
                self.table.set_verification(&k, v.clone());
            }
        }
    }

    fn score(&mut self, key: ProcKey, sig: Signal, ts_ns: u64) {
        let Some(p) = self.table.get(&key).cloned() else {
            return;
        };
        let ancestors = self.table.parent_chain(&key);
        let d = self.scorer.observe(&p, &ancestors, sig, ts_ns);
        let last = d.evidence.last().map_or("", |e| e.reason.as_str());
        if self.debug {
            eprintln!(
                "aegisd: debug: tgid {} comm {} score {:.1} tier {:?}: {last}",
                p.key.tgid, p.comm, d.score, d.tier
            );
        }
        let Some(verdict) = verdict(d.tier) else {
            return;
        };
        let tree: Vec<ProcInfo> = std::iter::once(p.clone())
            .chain(ancestors.into_iter().cloned())
            .collect();
        let incident = match self.incidents.record(&d, &tree, self.mode) {
            Ok(id) => id.0,
            Err(e) => {
                self.incident_errors += 1;
                eprintln!(
                    "aegisd: recording incident for tgid {} failed: {e:#}",
                    p.key.tgid
                );
                String::new()
            }
        };
        // Sent even when the incident write failed: the record is all
        // that's left of it then.
        self.sinks.emit(&TelemetryRecord {
            ts_unix_ns: now_ns(),
            incident,
            tier: d.tier,
            verdict,
            score: d.score,
            mode: self.mode,
            tgid: p.key.tgid,
            comm: p.comm.clone(),
            exe: p
                .exe
                .as_ref()
                .map(|e| e.as_os_str().as_encoded_bytes().to_vec()),
            reasons: d.evidence.iter().map(|e| e.reason.clone()).collect(),
        });
    }
}

/// The path to verify `exe` by, for live process `tgid`.
///
/// An exe path is only meaningful in the mount namespace of the process
/// that ran it. A container (or a service with PrivateTmp and friends)
/// has its own, where `/usr/bin/x` may be a different file from ours.
/// For such a process we open the file through `/proc/<tgid>/root`,
/// which the kernel resolves in that process's namespace. The host
/// rpmdb doesn't own that path, so in practice a container process
/// stays `Unverified`, which is the safe answer: no allowlist offsets.
///
/// None when the process is already gone, since then we can't tell
/// which namespace its path belongs to; it stays `Unverified`.
///
/// Known limit: `tgid` may have been reused since the exec. The window
/// is the gap between the exec and this call, which follows its event.
pub fn resolve_exe(tgid: u32, exe: &Path) -> Option<PathBuf> {
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

    fn same_ns(_: u32, exe: &Path) -> Option<PathBuf> {
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
        let p = Pipeline::new(&cfg, store, Sinks::none(), Box::new(Pid1), same_ns, false);
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

    /// bash forks pid 60, which execs /usr/bin/runc; runc then creates a
    /// memfd and execs it, as it does on every container start.
    fn runc_self_clone(p: &mut Pipeline, runc_verifies: bool) {
        p.handle(&exec(50, "/usr/bin/bash", 0));
        assert_eq!(std::mem::take(&mut p.to_verify), paths(&["/usr/bin/bash"]));
        p.verified(Path::new("/usr/bin/bash"), rpm("bash"));
        p.handle(&fork(50, 60));
        p.handle(&exec(60, "/usr/bin/runc", 0));
        assert_eq!(std::mem::take(&mut p.to_verify), paths(&["/usr/bin/runc"]));
        if runc_verifies {
            p.verified(Path::new("/usr/bin/runc"), rpm("runc"));
        }
        p.handle(&ev(EventKind::MemfdCreate, 60));
        p.handle(&exec(
            60,
            "/memfd:runc_cloned (deleted)",
            EXEC_MEMFD | EXEC_FROM_TMP,
        ));
        assert!(p.to_verify.is_empty(), "a memfd is not verified");
    }

    #[test]
    fn verified_runc_memfd_self_clone_is_not_an_incident() {
        let (mut p, _d) = pipeline("runc");
        runc_self_clone(&mut p, true);
        assert_eq!(p.incidents.open_count(), 0);
        assert_eq!(p.events_total, 5);
        // The exec did land: the table now shows the memfd image.
        let after = p.table.get(&key(60)).unwrap();
        assert_eq!(
            after.exe.as_deref(),
            Some(Path::new("/memfd:runc_cloned (deleted)"))
        );
        assert_eq!(after.verification, Verification::Unverified);
    }

    #[test]
    fn unverified_runc_memfd_self_clone_is_quarantined() {
        let (mut p, _d) = pipeline("fake-runc");
        runc_self_clone(&mut p, false);
        let l = p.incidents.list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].verdict, "would_quarantine");
        assert_eq!((l[0].max_score, l[0].root_tgid), (80.0, 60));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn late_found_process_takes_its_exe_from_proc_and_is_verified() {
        let (mut p, _d) = pipeline("late");
        let me = std::process::id();
        let mut e = ev(EventKind::MemfdCreate, me);
        e.start_time_ns = 1;
        p.handle(&e);
        let exe = std::env::current_exe().unwrap();
        let k = ProcKey {
            tgid: me,
            start_time_ns: 1,
        };
        assert_eq!(p.table.get(&k).unwrap().exe.as_ref(), Some(&exe));
        assert_eq!(std::mem::take(&mut p.to_verify), std::slice::from_ref(&exe));
        p.verified(&exe, rpm("me"));
        assert_eq!(p.table.get(&k).unwrap().verification, rpm("me"));
        // An Exec's /proc view is the new image, so it isn't read.
        let mut x = exec(me, "/usr/bin/new", 0);
        x.start_time_ns = 2;
        p.handle(&x);
        assert_eq!(std::mem::take(&mut p.to_verify), paths(&["/usr/bin/new"]));
    }

    #[test]
    fn incident_write_failure_is_counted_not_fatal() {
        let (mut p, d) = pipeline("fail");
        std::fs::remove_dir_all(&d.0).unwrap();
        runc_self_clone(&mut p, false);
        assert!(p.incident_errors >= 1);
        assert_eq!(p.incidents.open_count(), 0);
        // And the pipeline keeps going.
        p.handle(&ev(EventKind::Exit, 60));
        assert!(p.table.get(&key(60)).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_exe_in_our_namespace_is_the_path_itself() {
        let me = std::process::id();
        let p = Path::new("/usr/bin/true");
        assert_eq!(resolve_exe(me, p).as_deref(), Some(p));
    }

    #[test]
    fn resolve_exe_of_a_dead_process_is_none() {
        // Pid numbers stop well short of u32::MAX.
        assert_eq!(resolve_exe(u32::MAX, Path::new("/usr/bin/true")), None);
    }
}
