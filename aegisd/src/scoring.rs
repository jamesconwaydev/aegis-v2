// SPDX-License-Identifier: MIT OR Apache-2.0
//! Decaying cumulative risk score per process.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use aegis_common::{Event, EventKind, EXEC_FROM_TMP, EXEC_MEMFD, PATH_TRUNCATED};

use crate::config::{Allowlist, Config, ScanConfig, Weights};
use crate::proctable::{ProcInfo, ProcKey, ProcTable};
use crate::verify::Verification;

#[derive(Clone, Debug, PartialEq)]
pub enum Signal {
    TmpExec,
    MemfdCreate,
    MemfdExec,
    /// `target` is advisory: the tgid is looked up in the process table,
    /// so it may name a process we never saw (start time 0) or, after pid
    /// reuse or across pid namespaces, the wrong one.
    PtraceSystemDaemon {
        target: ProcKey,
    },
    EgressScan {
        distinct_targets: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Log,
    Throttle,
    Quarantine,
}

#[derive(Clone, Debug)]
pub struct Decision {
    pub key: ProcKey,
    pub score: f64,
    pub tier: Tier,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub signal: Signal,
    pub base: f64,
    pub modifier: f64,
    pub reason: String,
    pub ts_ns: u64,
}

pub trait DaemonClassifier {
    fn is_system_daemon(&self, tgid: u32) -> bool;
}

/// Classifies by the host's /proc: pid 1, or a process in a systemd
/// service's cgroup.
///
/// Known limit: a ptrace `target_tgid` is a pid in the tracer's pid
/// namespace. For a tracer inside a container it may not name a host
/// process at all, or may name the wrong one. v0.1 looks it up in the
/// host /proc anyway and accepts that.
pub struct ProcDaemons;

impl DaemonClassifier for ProcDaemons {
    fn is_system_daemon(&self, tgid: u32) -> bool {
        tgid == 1
            || std::fs::read_to_string(format!("/proc/{tgid}/cgroup"))
                .is_ok_and(|s| is_service_cgroup(&s))
    }
}

/// The cgroup v2 line (`0::<path>`) puts it directly in a
/// `system.slice/*.service` unit.
fn is_service_cgroup(s: &str) -> bool {
    s.lines().filter_map(|l| l.strip_prefix("0::")).any(|p| {
        p.strip_prefix("/system.slice/")
            .is_some_and(|u| u.ends_with(".service"))
    })
}

const PTRACE_ATTACH: u32 = 16;
const PTRACE_SEIZE: u32 = 0x4206;
const EINPROGRESS: i32 = 115;

/// The signals one event raises. Connect raises none here: the caller
/// feeds it to `ScanDetector`, which may raise `EgressScan`.
pub fn signals_for(ev: &Event, table: &ProcTable, daemon: &dyn DaemonClassifier) -> Vec<Signal> {
    let sig = match EventKind::try_from(ev.kind) {
        // A memfd is tmpfs-backed, so EXEC_FROM_TMP comes with it. Count it
        // once, as the heavier signal.
        Ok(EventKind::Exec) if ev.flags & EXEC_MEMFD != 0 => Signal::MemfdExec,
        // A path too long to render at all can't be shown not to be in a
        // temp directory, so it scores as one.
        Ok(EventKind::Exec)
            if ev.flags & EXEC_FROM_TMP != 0
                || (ev.flags & PATH_TRUNCATED != 0 && ev.path_len == 0) =>
        {
            Signal::TmpExec
        }
        Ok(EventKind::MemfdCreate) => Signal::MemfdCreate,
        Ok(EventKind::Ptrace)
            if matches!(ev.ptrace_request, PTRACE_ATTACH | PTRACE_SEIZE)
                && daemon.is_system_daemon(ev.target_tgid) =>
        {
            let target = table.by_tgid(ev.target_tgid).map_or(
                ProcKey {
                    tgid: ev.target_tgid,
                    start_time_ns: 0,
                },
                |p| p.key,
            );
            Signal::PtraceSystemDaemon { target }
        }
        _ => return Vec::new(),
    };
    vec![sig]
}

// ponytail: newest 32 kept per process; raise it if incidents need more.
const MAX_EVIDENCE: usize = 32;

struct Entry {
    score: f64,
    at_ns: u64,
    evidence: Vec<Evidence>,
}

pub struct Scorer {
    weights: Weights,
    half_life_ns: f64,
    throttle: f64,
    quarantine: f64,
    allow: Allowlist,
    scores: HashMap<ProcKey, Entry>,
}

/// `exe` is on `list` and verifies. A name alone never counts.
fn trusted(p: &ProcInfo, list: &[PathBuf]) -> bool {
    matches!(
        p.verification,
        Verification::RpmOwned { .. } | Verification::Pinned
    ) && p.exe.as_ref().is_some_and(|e| list.contains(e))
}

impl Scorer {
    pub fn new(cfg: &Config) -> Self {
        let mut s = Self {
            weights: Weights::default(),
            half_life_ns: 0.0,
            throttle: 0.0,
            quarantine: 0.0,
            allow: Allowlist::default(),
            scores: HashMap::new(),
        };
        s.set_config(cfg);
        s
    }

    /// Takes a reloaded config. Live scores carry over; they decay at the
    /// new half-life from here on.
    pub fn set_config(&mut self, cfg: &Config) {
        self.weights = cfg.scoring.weights.clone();
        self.half_life_ns = cfg.scoring.half_life_secs * 1e9;
        self.throttle = cfg.general.score_threshold_throttle.into();
        self.quarantine = cfg.general.score_threshold_quarantine.into();
        self.allow = cfg.allowlist.clone();
    }

    fn decayed(&self, e: &Entry, now_ns: u64) -> f64 {
        e.score * 0.5f64.powf(now_ns.saturating_sub(e.at_ns) as f64 / self.half_life_ns)
    }

    /// The child starts from the parent's score as it stands now.
    pub fn on_fork(&mut self, parent: &ProcKey, child: &ProcKey, now_ns: u64) {
        if let Some(p) = self.scores.get(parent) {
            let e = Entry {
                score: self.decayed(p, now_ns),
                at_ns: now_ns,
                evidence: p.evidence.clone(),
            };
            self.scores.insert(*child, e);
        }
    }

    pub fn on_exit(&mut self, key: &ProcKey) {
        self.scores.remove(key);
    }

    /// Listed in excluded_selinux_domains, by type. unconfined_t never is.
    fn selinux_excluded(&self, p: &ProcInfo) -> bool {
        let Some(ctx) = p.selinux_domain.as_deref() else {
            return false;
        };
        // user:role:type:level; a bare type is taken as is.
        let ty = ctx.split(':').nth(2).unwrap_or(ctx);
        ty != "unconfined_t" && self.allow.excluded_selinux_domains.iter().any(|d| d == ty)
    }

    /// (base, modifier, reason).
    fn weigh(&self, p: &ProcInfo, ancestors: &[&ProcInfo], sig: &Signal) -> (f64, f64, String) {
        let w = &self.weights;
        let a = &self.allow;
        let selinux = || {
            self.selinux_excluded(p).then(|| {
                format!(
                    "domain {} is allowlisted",
                    p.selinux_domain.as_deref().unwrap()
                )
            })
        };
        let (base, what, why) = match sig {
            Signal::TmpExec => {
                let parent = ancestors
                    .first()
                    .filter(|q| trusted(q, &a.excluded_parent_processes))
                    .map(|q| {
                        format!(
                            "parent {} is allowlisted",
                            q.exe.as_ref().unwrap().display()
                        )
                    });
                (
                    w.tmp_exec,
                    "exec from a temp directory",
                    parent.or_else(selinux),
                )
            }
            Signal::MemfdCreate => {
                let caller = trusted(p, &a.memfd_callers).then(|| "caller is allowlisted".into());
                (w.memfd_create, "memfd_create", caller.or_else(selinux))
            }
            // `p` is the process as it was before the exec: the binary that
            // ran the memfd. runc and crun clone themselves this way.
            Signal::MemfdExec => (
                w.memfd_exec,
                "exec of a memfd",
                trusted(p, &a.memfd_callers).then(|| "executing binary is allowlisted".into()),
            ),
            Signal::PtraceSystemDaemon { .. } => (
                w.ptrace_system_daemon,
                "ptrace attach to a system daemon",
                trusted(p, &a.ptrace_tracers).then(|| "tracer is allowlisted".into()),
            ),
            Signal::EgressScan { .. } => (
                w.egress_scan,
                "egress scan",
                (trusted(p, &a.scan_binaries) && p.uid == 0 && p.has_tty)
                    .then(|| "allowlisted scanner run by root from a terminal".into()),
            ),
        };
        match why {
            // An allowlisted event is forgiven in full, whatever its weight.
            Some(why) => (base, -base, format!("{what}; {why}")),
            None => (base, 0.0, what.into()),
        }
    }

    /// For an Exec event, call this before `ProcTable::apply` and pass the
    /// pre-exec `ProcInfo`: allowlists judge the binary that did the exec,
    /// not the one it started.
    pub fn observe(
        &mut self,
        proc: &ProcInfo,
        ancestors: &[&ProcInfo],
        sig: Signal,
        now_ns: u64,
    ) -> Decision {
        let (base, modifier, reason) = self.weigh(proc, ancestors, &sig);
        let mut e = self.scores.remove(&proc.key).unwrap_or(Entry {
            score: 0.0,
            at_ns: now_ns,
            evidence: Vec::new(),
        });
        // A modifier cancels this event's contribution, never more.
        e.score = self.decayed(&e, now_ns) + (base + modifier).max(0.0);
        e.at_ns = e.at_ns.max(now_ns);
        if e.evidence.len() == MAX_EVIDENCE {
            e.evidence.remove(0);
        }
        e.evidence.push(Evidence {
            signal: sig,
            base,
            modifier,
            reason,
            ts_ns: now_ns,
        });
        let tier = if e.score >= self.quarantine {
            Tier::Quarantine
        } else if e.score >= self.throttle {
            Tier::Throttle
        } else {
            Tier::Log
        };
        let d = Decision {
            key: proc.key,
            score: e.score,
            tier,
            evidence: e.evidence.clone(),
        };
        self.scores.insert(proc.key, e);
        d
    }
}

type Target = (IpAddr, u16);

#[derive(Default)]
struct Window {
    /// (ts_ns, target, failed), oldest first.
    // ponytail: one entry per connect inside the window, so a process
    // connecting very fast holds that many; cap the deque if that bites.
    conns: VecDeque<(u64, Target, bool)>,
    targets: HashMap<Target, u32>,
    failed: u32,
    fired: bool,
}

/// Per process: distinct (daddr, dport) and failed connects inside the
/// window. Fires when either crosses its threshold, then stays quiet
/// until both have dropped back below.
pub struct ScanDetector {
    cfg: ScanConfig,
    procs: HashMap<ProcKey, Window>,
}

impl ScanDetector {
    pub fn new(cfg: ScanConfig) -> Self {
        Self {
            cfg,
            procs: HashMap::new(),
        }
    }

    /// Takes every Connect event: the SYN_SENT one (`ret` = -EINPROGRESS)
    /// and the outcome (0, or -errno on failure).
    pub fn on_connect(&mut self, ev: &Event) -> Option<Signal> {
        let addr = match ev.family {
            2 => IpAddr::V4(Ipv4Addr::new(
                ev.daddr[0],
                ev.daddr[1],
                ev.daddr[2],
                ev.daddr[3],
            )),
            _ => {
                let v6 = Ipv6Addr::from(ev.daddr);
                v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
            }
        };
        let key = ProcKey {
            tgid: ev.tgid,
            start_time_ns: ev.start_time_ns,
        };
        let window_ns = (self.cfg.window_secs * 1e9) as u64;
        let w = self.procs.entry(key).or_default();
        // A late event counts as arriving now, which keeps the deque sorted.
        let now = w.conns.back().map_or(ev.ts_ns, |c| c.0.max(ev.ts_ns));
        while let Some(&(ts, t, failed)) = w.conns.front() {
            if now - ts <= window_ns {
                break;
            }
            w.conns.pop_front();
            w.failed -= failed as u32;
            if let Some(n) = w.targets.get_mut(&t) {
                *n -= 1;
                if *n == 0 {
                    w.targets.remove(&t);
                }
            }
        }
        let (dt, fc) = (self.cfg.distinct_targets, self.cfg.failed_connects);
        if (w.targets.len() as u32) < dt && w.failed < fc {
            w.fired = false;
        }
        let t = (addr, ev.dport);
        let failed = ev.ret < 0 && ev.ret != -EINPROGRESS;
        w.conns.push_back((now, t, failed));
        *w.targets.entry(t).or_default() += 1;
        w.failed += failed as u32;
        let distinct = w.targets.len() as u32;
        if w.fired || (distinct < dt && w.failed < fc) {
            return None;
        }
        w.fired = true;
        Some(Signal::EgressScan {
            distinct_targets: distinct,
        })
    }

    /// Takes a reloaded config; windows in progress carry over.
    pub fn set_config(&mut self, cfg: ScanConfig) {
        self.cfg = cfg;
    }

    pub fn on_exit(&mut self, key: &ProcKey) {
        self.procs.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::Verification;
    use aegis_common::{EventKind, EXEC_FROM_TMP, EXEC_MEMFD, PATH_TRUNCATED};

    const S: u64 = 1_000_000_000;
    const JAVA: &str = "/usr/lib/jvm/java-21-openjdk/bin/java";

    fn cfg() -> Config {
        let mut c = Config::default();
        let a = &mut c.allowlist;
        a.excluded_parent_processes = vec!["/usr/bin/dnf".into()];
        a.memfd_callers = vec![JAVA.into()];
        a.ptrace_tracers = vec!["/usr/bin/gdb".into()];
        a.scan_binaries = vec!["/usr/bin/nmap".into()];
        c
    }

    fn rpm(pkg: &str) -> Verification {
        Verification::RpmOwned {
            package: pkg.into(),
        }
    }

    fn key(tgid: u32, st: u64) -> ProcKey {
        ProcKey {
            tgid,
            start_time_ns: st,
        }
    }

    fn proc(tgid: u32, exe: &str, comm: &str, v: Verification) -> ProcInfo {
        ProcInfo {
            key: key(tgid, 1),
            parent: None,
            exe: Some(exe.into()),
            comm: comm.into(),
            uid: 1000,
            has_tty: false,
            selinux_domain: None,
            verification: v,
            cgroup_id: 0,
        }
    }

    fn evil() -> ProcInfo {
        proc(100, "/tmp/x", "x", Verification::Unverified)
    }

    fn bash() -> ProcInfo {
        proc(99, "/usr/bin/bash", "bash", rpm("bash"))
    }

    fn ptrace_daemon() -> Signal {
        Signal::PtraceSystemDaemon { target: key(1, 0) }
    }

    fn scan() -> Signal {
        Signal::EgressScan {
            distinct_targets: 20,
        }
    }

    #[test]
    fn tmp_exec_unverified_scores_25_log() {
        let d = Scorer::new(&cfg()).observe(&evil(), &[&bash()], Signal::TmpExec, S);
        assert_eq!((d.score, d.tier), (25.0, Tier::Log));
        assert_eq!(d.evidence.len(), 1);
        assert_eq!(d.evidence[0].base, 25.0);
    }

    #[test]
    fn tmp_exec_then_ptrace_daemon_is_70_throttle() {
        let mut s = Scorer::new(&cfg());
        let (p, b) = (evil(), bash());
        s.observe(&p, &[&b], Signal::TmpExec, S);
        let d = s.observe(&p, &[&b], ptrace_daemon(), S);
        assert_eq!((d.score, d.tier), (70.0, Tier::Throttle));
    }

    #[test]
    fn tmp_exec_ptrace_scan_is_110_quarantine() {
        let mut s = Scorer::new(&cfg());
        let (p, b) = (evil(), bash());
        s.observe(&p, &[&b], Signal::TmpExec, S);
        s.observe(&p, &[&b], ptrace_daemon(), S);
        let d = s.observe(&p, &[&b], scan(), S);
        assert_eq!((d.score, d.tier), (110.0, Tier::Quarantine));
        assert_eq!(d.evidence.len(), 3);
    }

    #[test]
    fn memfd_create_then_memfd_exec_is_80_quarantine() {
        let mut s = Scorer::new(&cfg());
        let (p, b) = (evil(), bash());
        s.observe(&p, &[&b], Signal::MemfdCreate, S);
        let d = s.observe(&p, &[&b], Signal::MemfdExec, S);
        assert_eq!((d.score, d.tier), (80.0, Tier::Quarantine));
    }

    #[test]
    fn decay_halves_after_30s() {
        // A zero-weight signal reads the decayed score without adding to it.
        let mut c = cfg();
        c.scoring.weights.egress_scan = 0.0;
        let mut s = Scorer::new(&c);
        let (p, b) = (evil(), bash());
        s.observe(&p, &[&b], Signal::TmpExec, S);
        let d = s.observe(&p, &[&b], scan(), 31 * S);
        assert!((d.score - 12.5).abs() < 0.01, "{}", d.score);
    }

    #[test]
    fn tmp_exec_by_verified_dnf_parent_scores_0() {
        let dnf = proc(50, "/usr/bin/dnf", "dnf", rpm("dnf"));
        let d = Scorer::new(&cfg()).observe(&evil(), &[&dnf], Signal::TmpExec, S);
        assert_eq!(d.score, 0.0);
        assert_eq!(d.evidence[0].modifier, -25.0);
    }

    #[test]
    fn comm_dnf_unverified_parent_gets_no_modifier() {
        let fake = proc(50, "/usr/bin/dnf", "dnf", Verification::Unverified);
        let d = Scorer::new(&cfg()).observe(&evil(), &[&fake], Signal::TmpExec, S);
        assert_eq!(d.score, 25.0);
        // Nor does a verified binary at another path calling itself dnf.
        let other = proc(50, "/tmp/dnf", "dnf", rpm("dnf"));
        let d = Scorer::new(&cfg()).observe(&evil(), &[&other], Signal::TmpExec, S);
        assert_eq!(d.score, 25.0);
    }

    #[test]
    fn unconfined_t_never_reduces_score() {
        let mut c = cfg();
        c.allowlist.excluded_selinux_domains = vec!["unconfined_t".into(), "rpm_t".into()];
        let mut p = evil();
        p.selinux_domain = Some("unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023".into());
        let d = Scorer::new(&c).observe(&p, &[&bash()], Signal::TmpExec, S);
        assert_eq!(d.score, 25.0);
        // A listed confined domain does get the modifier.
        p.selinux_domain = Some("system_u:system_r:rpm_t:s0".into());
        let d = Scorer::new(&c).observe(&p, &[&bash()], Signal::MemfdCreate, S);
        assert_eq!(d.score, 0.0);
    }

    #[test]
    fn memfd_create_by_verified_java_scores_0() {
        let java = proc(70, JAVA, "java", rpm("java-21-openjdk-headless"));
        let d = Scorer::new(&cfg()).observe(&java, &[&bash()], Signal::MemfdCreate, S);
        assert_eq!(d.score, 0.0);
        let java = proc(70, JAVA, "java", Verification::Modified);
        let d = Scorer::new(&cfg()).observe(&java, &[&bash()], Signal::MemfdCreate, S);
        assert_eq!(d.score, 20.0);
    }

    #[test]
    fn verified_gdb_ptrace_of_daemon_scores_0() {
        let gdb = proc(80, "/usr/bin/gdb", "gdb", rpm("gdb"));
        let d = Scorer::new(&cfg()).observe(&gdb, &[&bash()], ptrace_daemon(), S);
        assert_eq!(d.score, 0.0);
    }

    fn nmap(tty: bool) -> ProcInfo {
        let mut p = proc(90, "/usr/bin/nmap", "nmap", rpm("nmap"));
        p.uid = 0;
        p.has_tty = tty;
        p
    }

    #[test]
    fn nmap_verified_root_tty_scan_scores_0() {
        let d = Scorer::new(&cfg()).observe(&nmap(true), &[&bash()], scan(), S);
        assert_eq!(d.score, 0.0);
    }

    #[test]
    fn nmap_verified_root_no_tty_scan_scores_40() {
        let d = Scorer::new(&cfg()).observe(&nmap(false), &[&bash()], scan(), S);
        assert_eq!(d.score, 40.0);
        let mut p = nmap(true);
        p.uid = 1000;
        let d = Scorer::new(&cfg()).observe(&p, &[&bash()], scan(), S);
        assert_eq!(d.score, 40.0);
    }

    #[test]
    fn child_inherits_parent_score_at_fork() {
        let mut s = Scorer::new(&cfg());
        let p = evil();
        s.observe(&p, &[&bash()], Signal::TmpExec, S);
        let ck = key(101, 5);
        s.on_fork(&p.key, &ck, 31 * S);
        let mut child = evil();
        child.key = ck;
        let d = s.observe(&child, &[&p], ptrace_daemon(), 31 * S);
        assert!((d.score - (12.5 + 45.0)).abs() < 0.01, "{}", d.score);
    }

    #[test]
    fn pid_reuse_does_not_inherit_score() {
        let mut s = Scorer::new(&cfg());
        let p = evil();
        s.observe(&p, &[&bash()], Signal::TmpExec, S);
        let mut reused = evil();
        reused.key = key(p.key.tgid, 999);
        let d = s.observe(&reused, &[&bash()], Signal::MemfdCreate, S);
        assert_eq!(d.score, 20.0);
        s.on_exit(&p.key);
        let d = s.observe(&p, &[&bash()], Signal::MemfdCreate, S);
        assert_eq!(d.score, 20.0);
    }

    fn connect(i: u32, ret: i32, ts: u64) -> Event {
        // SAFETY: Event is plain old data; all-zero is valid.
        let mut e: Event = unsafe { std::mem::zeroed() };
        e.kind = EventKind::Connect as u32;
        e.tgid = 100;
        e.start_time_ns = 1;
        e.family = 2;
        e.daddr[..4].copy_from_slice(&[10, 0, (i >> 8) as u8, i as u8]);
        e.dport = 22;
        e.ret = ret;
        e.ts_ns = ts;
        e
    }

    fn fires_at(n: u32) -> bool {
        let mut d = ScanDetector::new(ScanConfig::default());
        let mut fired = false;
        for i in 0..n {
            let ts = S + u64::from(i) * 50_000_000; // 50 ms apart, < 2 s total
            fired |= d.on_connect(&connect(i, -115, ts)).is_some();
            fired |= d.on_connect(&connect(i, 0, ts + 1)).is_some();
        }
        fired
    }

    #[test]
    fn scan_detector_fires_at_20_distinct_targets_in_2s() {
        assert!(fires_at(20));
    }

    #[test]
    fn scan_detector_not_at_19() {
        assert!(!fires_at(19));
    }

    #[test]
    fn scan_detector_fires_once_per_crossing_and_counts_failures() {
        let mut d = ScanDetector::new(ScanConfig::default());
        let mut n = 0;
        // Ten refused connects to one v4 target, the same one reached
        // through its IPv4-mapped v6 form: one target, ten failures.
        for i in 0..10u64 {
            let mut e = connect(0, -115, S + i);
            if i % 2 == 1 {
                e.family = 10;
                e.daddr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 0];
            }
            n += d.on_connect(&e).is_some() as u32;
            e.ret = -111;
            match d.on_connect(&e) {
                Some(Signal::EgressScan { distinct_targets }) => {
                    assert_eq!(distinct_targets, 1);
                    n += 1;
                }
                Some(s) => panic!("{s:?}"),
                None => {}
            }
        }
        assert_eq!(n, 1);
        // More failures inside the window don't fire again...
        assert!(d.on_connect(&connect(0, -111, S + 20)).is_none());
        // ...but after the window drains, a new crossing does.
        let later = 10 * S;
        let fired = (0..10).any(|i| d.on_connect(&connect(0, -111, later + i)).is_some());
        assert!(fired);
    }

    #[test]
    fn raised_weight_is_still_fully_forgiven() {
        let mut c = cfg();
        c.scoring.weights.tmp_exec = 40.0;
        let dnf = proc(50, "/usr/bin/dnf", "dnf", rpm("dnf"));
        let d = Scorer::new(&c).observe(&evil(), &[&dnf], Signal::TmpExec, S);
        assert_eq!(d.score, 0.0);
        assert_eq!(d.evidence[0].modifier, -40.0);
    }

    #[test]
    fn verified_runc_memfd_self_clone_scores_0() {
        let mut c = cfg();
        c.allowlist.memfd_callers = vec!["/usr/bin/runc".into()];
        let mut s = Scorer::new(&c);
        // The pre-exec view: runc itself, about to exec its memfd copy.
        let runc = proc(60, "/usr/bin/runc", "runc", rpm("runc"));
        s.observe(&runc, &[&bash()], Signal::MemfdCreate, S);
        let d = s.observe(&runc, &[&bash()], Signal::MemfdExec, S);
        assert_eq!((d.score, d.tier), (0.0, Tier::Log));
        // An unverified runc gets nothing.
        let fake = proc(61, "/usr/bin/runc", "runc", Verification::Modified);
        let d = Scorer::new(&c).observe(&fake, &[&bash()], Signal::MemfdExec, S);
        assert_eq!(d.score, 60.0);
    }

    #[test]
    fn scores_survive_set_config() {
        let mut s = Scorer::new(&cfg());
        let (p, b) = (evil(), bash());
        s.observe(&p, &[&b], Signal::TmpExec, S);
        let mut c = cfg();
        c.scoring.weights.memfd_create = 30.0;
        c.general.score_threshold_throttle = 40;
        s.set_config(&c);
        let d = s.observe(&p, &[&b], Signal::MemfdCreate, S);
        assert_eq!((d.score, d.tier), (55.0, Tier::Throttle));

        let mut det = ScanDetector::new(ScanConfig::default());
        for i in 0..5 {
            assert!(det
                .on_connect(&connect(i, -111, S + u64::from(i)))
                .is_none());
        }
        det.set_config(ScanConfig {
            failed_connects: 6,
            ..ScanConfig::default()
        });
        assert!(det.on_connect(&connect(9, -111, S + 9)).is_some());
    }

    #[test]
    fn scan_detector_rearms_when_counts_dip_below_thresholds() {
        let mut d = ScanDetector::new(ScanConfig::default());
        let burst = |d: &mut ScanDetector, base: u32, ts: u64| {
            (0..20).any(|i| {
                d.on_connect(&connect(base + i, -115, ts + u64::from(i)))
                    .is_some()
            })
        };
        assert!(burst(&mut d, 0, S));
        // One connect at 1.5 s keeps the window from ever emptying.
        assert!(d.on_connect(&connect(500, -115, S + S / 2 * 3)).is_none());
        // Just after 3 s the first burst has aged out and the 1.5 s one is
        // left: below both thresholds, so the next burst fires again.
        assert!(burst(&mut d, 100, 3 * S + 1000));
    }

    #[test]
    fn scan_detector_tolerates_out_of_order_timestamps() {
        let mut d = ScanDetector::new(ScanConfig::default());
        d.on_connect(&connect(0, -115, 10 * S));
        // Arrives late, stamped long before the window: it counts as now.
        d.on_connect(&connect(1, -115, S));
        let fired = (2..20).any(|i| d.on_connect(&connect(i, -115, 11 * S)).is_some());
        assert!(fired);
    }

    struct Daemons;
    impl DaemonClassifier for Daemons {
        fn is_system_daemon(&self, tgid: u32) -> bool {
            tgid == 1
        }
    }

    fn ev(kind: EventKind, flags: u32) -> Event {
        // SAFETY: Event is plain old data; all-zero is valid.
        let mut e: Event = unsafe { std::mem::zeroed() };
        e.kind = kind as u32;
        e.tgid = 100;
        e.flags = flags;
        e.path_len = 4;
        e
    }

    #[test]
    fn signals_for_maps_events() {
        let t = ProcTable::new();
        let sig = |e: &Event| signals_for(e, &t, &Daemons);
        assert_eq!(sig(&ev(EventKind::Exec, EXEC_FROM_TMP)), [Signal::TmpExec]);
        // memfd is tmpfs-backed, so both flags arrive; count it once.
        assert_eq!(
            sig(&ev(EventKind::Exec, EXEC_FROM_TMP | EXEC_MEMFD)),
            [Signal::MemfdExec]
        );
        assert_eq!(sig(&ev(EventKind::Exec, 0)), []);
        assert_eq!(sig(&ev(EventKind::Exec, PATH_TRUNCATED)), []);
        let mut e = ev(EventKind::Exec, PATH_TRUNCATED);
        e.path_len = 0;
        assert_eq!(sig(&e), [Signal::TmpExec]);
        assert_eq!(sig(&ev(EventKind::MemfdCreate, 0)), [Signal::MemfdCreate]);
        let mut e = ev(EventKind::Ptrace, 0);
        e.ptrace_request = 16;
        e.target_tgid = 1;
        assert_eq!(sig(&e), [Signal::PtraceSystemDaemon { target: key(1, 0) }]);
        e.ptrace_request = 0x4206;
        assert_eq!(sig(&e).len(), 1);
        e.target_tgid = 500;
        assert_eq!(sig(&e), []);
        assert_eq!(sig(&ev(EventKind::Connect, 0)), []);
    }

    #[test]
    fn system_service_cgroup_is_a_daemon() {
        assert!(is_service_cgroup("0::/system.slice/sshd.service\n"));
        assert!(!is_service_cgroup(
            "0::/user.slice/user-1000.slice/session-3.scope\n"
        ));
        assert!(!is_service_cgroup("0::/system.slice/podman.slice\n"));
        assert!(!is_service_cgroup(
            "0::/machine.slice/system.slice/x.service\n"
        ));
        assert!(!is_service_cgroup(
            "1:name=systemd:/system.slice/x.service\n"
        ));
    }
}
