// SPDX-License-Identifier: MIT OR Apache-2.0
//! Live process table, built from the probe event stream.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use aegis_common::{Event, EventKind, ENV_LOADER_VAR, ENV_TRUNCATED, ENV_UNREADABLE, HAS_TTY};

use crate::verify::Verification;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcKey {
    pub tgid: u32,
    pub start_time_ns: u64,
}

#[derive(Clone, Debug)]
pub struct ProcInfo {
    pub key: ProcKey,
    pub parent: Option<ProcKey>,
    pub exe: Option<PathBuf>,
    /// (dev, ino) of the file `exe` names, as the kernel saw it at exec,
    /// in `stat` encoding. Verification checks the host's file against it.
    pub exe_id: Option<(u64, u64)>,
    pub comm: String,
    pub uid: u32,
    pub has_tty: bool,
    pub selinux_domain: Option<String>,
    pub verification: Verification,
    pub cgroup_id: u64,
    /// Why the environment it was exec'd with voids allowlist trust
    /// (a loader variable, or no readable environment at all).
    pub env_taint: Option<&'static str>,
    /// Its environment's verdict is still to come: the kernel's, for an
    /// exec we saw, or a /proc read for a process that predates us.
    /// Until it lands the process counts as tainted.
    pub env_pending: bool,
    /// It was the target of a ptrace attach or seize. Inherited at
    /// fork, cleared at exec.
    pub ptraced: bool,
}

impl ProcInfo {
    /// Why code other than its own executable may be running in this
    /// process, which withholds every allowlist modifier from it.
    pub fn taint(&self) -> Option<&'static str> {
        if self.env_pending {
            return Some(UNREADABLE);
        }
        self.env_taint.or_else(|| {
            self.ptraced
                .then_some("it was the target of a ptrace attach")
        })
    }
}

impl ProcInfo {
    /// Becomes the image an Exec event started.
    pub fn apply_exec(&mut self, ev: &Event) {
        let n = (ev.path_len as usize).min(ev.path.len());
        // The new image's environment comes in its own ExecEnv event.
        self.env_taint = None;
        self.env_pending = false;
        // A tracer's hold on the old image doesn't carry over.
        self.ptraced = false;
        self.exe = Some(PathBuf::from(OsStr::from_bytes(&ev.path[..n])));
        self.exe_id = Some(exe_id(ev));
        self.comm = comm_str(&ev.comm);
        self.has_tty = ev.flags & HAS_TTY != 0;
        self.uid = ev.uid;
        self.cgroup_id = ev.cgroup_id;
        self.selinux_domain = selinux_domain(ev.tgid);
        // The old image's verdict no longer applies.
        self.verification = Verification::Unverified;
    }
}

impl ProcInfo {
    /// Takes the kernel's verdict on the environment its exec started
    /// with: an `ExecEnv` event's flags.
    pub fn apply_env(&mut self, flags: u32) {
        self.env_taint = if flags & ENV_LOADER_VAR != 0 {
            Some(LOADER_VAR)
        } else if flags & (ENV_TRUNCATED | ENV_UNREADABLE) != 0 {
            Some(UNREADABLE)
        } else {
            None
        };
        self.env_pending = false;
    }
}

pub const UNREADABLE: &str = "its environment could not be read";
const LOADER_VAR: &str = "LD_PRELOAD, LD_AUDIT or LD_LIBRARY_PATH is set";

pub struct ProcTable {
    procs: HashMap<ProcKey, ProcInfo>,
    /// Whether a tgid is in the host's pid namespace. Swappable so tests
    /// can run without real processes behind them.
    pub host_pidns: fn(u32) -> bool,
}

impl Default for ProcTable {
    fn default() -> Self {
        Self {
            procs: HashMap::new(),
            host_pidns: in_host_pidns,
        }
    }
}

/// Whether `tgid` shares pid 1's pid namespace, so a pid it names is a
/// host pid. Fails closed: if either link can't be read (a tracer that
/// attached, injected and exited before we got here), it counts as the
/// host's.
pub fn in_host_pidns(tgid: u32) -> bool {
    let ns = |p: &str| std::fs::read_link(format!("/proc/{p}/ns/pid")).ok();
    match (ns(&tgid.to_string()), ns("1")) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

/// `/proc/<tgid>/environ`, for a process that started before aegisd:
/// no ExecEnv will ever come for it. Read only once the start time shows
/// the pid hasn't been reused, and only if it still runs `image`.
/// Blocking, and a process can make it block for good (environment pages
/// backed by FUSE), so it only ever runs off the event loop.
pub fn read_environ(tgid: u32, start_time_ns: u64, image: (u64, u64)) -> Option<Vec<u8>> {
    if !crate::pipeline::proc_start_matches(tgid, start_time_ns) {
        return None;
    }
    let env = std::fs::read(format!("/proc/{tgid}/environ")).ok()?;
    let md = std::fs::metadata(format!("/proc/{tgid}/exe")).ok()?;
    ((md.dev(), md.ino()) == image).then_some(env)
}

/// Why an environment (NUL-separated `NAME=value` entries) voids
/// allowlist trust. The loader variables can put foreign code inside a
/// verified binary. An unreadable environment fails closed, and so does
/// an empty one: that is what a process that already exited shows.
pub fn env_taint(environ: Option<&[u8]>) -> Option<&'static str> {
    let Some(env) = environ.filter(|e| !e.is_empty()) else {
        return Some(UNREADABLE);
    };
    const LOADER: [&[u8]; 3] = [b"LD_PRELOAD=", b"LD_AUDIT=", b"LD_LIBRARY_PATH="];
    env.split(|&b| b == 0)
        .any(|v| LOADER.iter().any(|name| v.starts_with(name)))
        .then_some(LOADER_VAR)
}

/// The exec'd file's (dev, ino) from the event. The kernel's `s_dev` is
/// `major << 20 | minor`; `stat` encodes it differently.
pub fn exe_id(ev: &Event) -> (u64, u64) {
    let dev = libc::makedev(ev.exe_dev >> 20, ev.exe_dev & 0xf_ffff);
    (dev, ev.exe_ino)
}

fn comm_str(c: &[u8; 16]) -> String {
    let n = c.iter().position(|&b| b == 0).unwrap_or(c.len());
    String::from_utf8_lossy(&c[..n]).into_owned()
}

/// Best effort: the process may already be gone, or SELinux may be off.
// Known limit: `tgid` may have been reused since the event, and we cannot
// check. Our start time is CLOCK_MONOTONIC ns; /proc/<pid>/stat field 22
// is in clock ticks since boot (CLOCK_BOOTTIME), and the two clocks differ
// by the time spent suspended, so they cannot be compared reliably. The
// read follows the Exec event immediately, which keeps the window small.
fn selinux_domain(tgid: u32) -> Option<String> {
    let s = std::fs::read(format!("/proc/{tgid}/attr/current")).ok()?;
    let s = String::from_utf8_lossy(&s);
    let s = s.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    (!s.is_empty()).then(|| s.to_string())
}

impl ProcTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records where reading a process's environment stands.
    pub fn set_env(&mut self, k: &ProcKey, taint: Option<&'static str>, pending: bool) {
        if let Some(p) = self.procs.get_mut(k) {
            p.env_taint = taint;
            p.env_pending = pending;
        }
    }

    pub fn get(&self, k: &ProcKey) -> Option<&ProcInfo> {
        self.procs.get(k)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProcInfo> {
        self.procs.values()
    }

    /// The live process with this tgid, if we know it.
    // ponytail: linear scan; index by tgid if the table gets large.
    pub fn by_tgid(&self, tgid: u32) -> Option<&ProcInfo> {
        self.procs.values().find(|p| p.key.tgid == tgid)
    }

    /// Records the verdict for a process once the verifier has run.
    pub fn set_verification(&mut self, k: &ProcKey, v: Verification) {
        if let Some(p) = self.procs.get_mut(k) {
            p.verification = v;
        }
    }

    /// Every process whose exe currently verifies as `Pinned`. After a
    /// reload the pins may differ, so these need re-checking.
    pub fn pinned_keys(&self) -> Vec<ProcKey> {
        self.procs
            .values()
            .filter(|p| p.verification == Verification::Pinned)
            .map(|p| p.key)
            .collect()
    }

    /// Drops processes the kernel has reaped that we missed the exit for
    /// (a dropped Exit event), and returns their keys. A process is gone
    /// when /proc no longer shows it, or shows a different start time.
    pub fn sweep(&mut self) -> Vec<ProcKey> {
        let dead: Vec<ProcKey> = self
            .procs
            .keys()
            .copied()
            .filter(|k| !crate::pipeline::proc_start_matches(k.tgid, k.start_time_ns))
            .collect();
        for k in &dead {
            self.procs.remove(k);
        }
        dead
    }

    /// Ancestors of `k`, nearest first, not including `k`. Stops at the
    /// first parent that is no longer in the table.
    pub fn parent_chain(&self, k: &ProcKey) -> Vec<&ProcInfo> {
        let mut out = Vec::new();
        let mut cur = self.procs.get(k).and_then(|p| p.parent);
        // The depth cap is only a guard against a corrupt cycle.
        while let Some(p) = cur.and_then(|k| self.procs.get(&k)) {
            if out.len() >= 64 {
                break;
            }
            out.push(p);
            cur = p.parent;
        }
        out
    }

    pub fn apply(&mut self, ev: &Event) {
        let key = ProcKey {
            tgid: ev.tgid,
            start_time_ns: ev.start_time_ns,
        };
        let kind = EventKind::try_from(ev.kind).ok();
        if kind == Some(EventKind::Exit) {
            self.procs.remove(&key);
            return;
        }
        self.ensure(ev);
        match kind {
            Some(EventKind::Exec) => self.procs.get_mut(&key).unwrap().apply_exec(ev),
            Some(EventKind::ExecEnv) => self.procs.get_mut(&key).unwrap().apply_env(ev.flags),
            Some(EventKind::Fork) => {
                let ck = ProcKey {
                    tgid: ev.child_tgid,
                    start_time_ns: ev.child_start_time_ns,
                };
                let parent = self.procs[&key].clone();
                self.procs.entry(ck).or_insert_with(|| ProcInfo {
                    key: ck,
                    parent: Some(key),
                    exe: parent.exe,
                    exe_id: parent.exe_id,
                    selinux_domain: parent.selinux_domain,
                    verification: parent.verification,
                    ..parent
                });
            }
            // The probe reports only attaches that worked. `target_tgid`
            // is a pid in the tracer's pid namespace, so only a tracer in
            // the host's names a process we can find. Known limit: a
            // thread id finds nothing here.
            Some(EventKind::Ptrace) if (self.host_pidns)(ev.tgid) => {
                if let Some(t) = self
                    .procs
                    .values_mut()
                    .find(|p| p.key.tgid == ev.target_tgid)
                {
                    t.ptraced = true;
                }
            }
            _ => {}
        }
    }

    /// Creates the subject's entry if we missed its birth (it predates
    /// us), and says whether it did. `apply` does this itself; call it
    /// first only to look at the process before the event is applied.
    ///
    /// A late-found process gets its exe and SELinux domain from /proc,
    /// so pid 1 and other old daemons can match an allowlist once
    /// verified. Not for an Exec: /proc already shows the new image, and
    /// this entry is meant to be the old one.
    pub fn ensure(&mut self, ev: &Event) -> bool {
        let key = ProcKey {
            tgid: ev.tgid,
            start_time_ns: ev.start_time_ns,
        };
        if self.procs.contains_key(&key) {
            return false;
        }
        // Read /proc only for a late-found live process, and only once
        // its start time confirms the pid hasn't been reused since.
        let live = ev.kind != EventKind::Exec as u32
            && crate::pipeline::proc_start_matches(ev.tgid, ev.start_time_ns);
        let parent = (ev.ppid != 0)
            .then(|| self.by_tgid(ev.ppid).map(|p| p.key))
            .flatten();
        self.procs.insert(
            key,
            ProcInfo {
                key,
                parent,
                exe: live
                    .then(|| std::fs::read_link(format!("/proc/{}/exe", ev.tgid)).ok())
                    .flatten(),
                // What it runs now, read just after `exe` named it.
                exe_id: live
                    .then(|| std::fs::metadata(format!("/proc/{}/exe", ev.tgid)).ok())
                    .flatten()
                    .map(|m| (m.dev(), m.ino())),
                comm: comm_str(&ev.comm),
                uid: ev.uid,
                has_tty: ev.flags & HAS_TTY != 0,
                selinux_domain: live.then(|| selinux_domain(ev.tgid)).flatten(),
                verification: Verification::Unverified,
                cgroup_id: ev.cgroup_id,
                // The pipeline reads the environment when it matters. Found
                // at an Exec, this entry is the old image, whose
                // environment is already gone: never trusted.
                env_taint: (ev.kind == EventKind::Exec as u32).then_some(UNREADABLE),
                env_pending: false,
                ptraced: false,
            },
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::EXEC_FROM_TMP;

    fn ev(kind: EventKind, tgid: u32, st: u64) -> Event {
        // SAFETY: Event is plain old data; all-zero is valid.
        let mut e: Event = unsafe { std::mem::zeroed() };
        e.kind = kind as u32;
        e.tgid = tgid;
        e.start_time_ns = st;
        e
    }

    #[test]
    fn proctable_exit_before_read_is_unverified_not_error() {
        let mut t = ProcTable::new();
        let mut e = ev(EventKind::Exec, 4_000_000_000, 7);
        e.path[..9].copy_from_slice(b"/tmp/cago");
        e.path_len = 9;
        e.flags = EXEC_FROM_TMP;
        e.comm[..2].copy_from_slice(b"ca");
        t.apply(&e);
        let p = t
            .get(&ProcKey {
                tgid: 4_000_000_000,
                start_time_ns: 7,
            })
            .unwrap();
        assert_eq!(p.selinux_domain, None);
        assert_eq!(p.verification, Verification::Unverified);
        assert_eq!(p.exe.as_deref(), Some(std::path::Path::new("/tmp/cago")));
        assert_eq!(p.comm, "ca");
    }

    #[test]
    fn proctable_fork_links_parent() {
        let mut t = ProcTable::new();
        let mut f = ev(EventKind::Fork, 10, 100);
        f.child_tgid = 11;
        f.child_start_time_ns = 200;
        t.apply(&f);
        let (pk, ck) = (
            ProcKey {
                tgid: 10,
                start_time_ns: 100,
            },
            ProcKey {
                tgid: 11,
                start_time_ns: 200,
            },
        );
        assert_eq!(t.get(&ck).unwrap().parent, Some(pk));
        assert_eq!(t.parent_chain(&ck)[0].key, pk);
        // A late-discovered process links to its live parent by ppid.
        let mut x = ev(EventKind::Exec, 12, 300);
        x.ppid = 10;
        t.apply(&x);
        assert_eq!(
            t.get(&ProcKey {
                tgid: 12,
                start_time_ns: 300
            })
            .unwrap()
            .parent,
            Some(pk)
        );
        t.apply(&ev(EventKind::Exit, 11, 200));
        assert!(t.get(&ck).is_none());
    }

    #[test]
    fn loader_variables_and_unreadable_environments_taint() {
        let set = Some("LD_PRELOAD, LD_AUDIT or LD_LIBRARY_PATH is set");
        assert_eq!(env_taint(Some(b"PATH=/usr/bin\0HOME=/root\0")), None);
        assert_eq!(
            env_taint(Some(b"PATH=/usr/bin\0LD_PRELOAD=/tmp/x.so\0")),
            set
        );
        assert_eq!(env_taint(Some(b"LD_AUDIT=/tmp/a.so")), set);
        assert_eq!(env_taint(Some(b"A=1\0LD_LIBRARY_PATH=/tmp\0")), set);
        // A value that merely mentions one is not one.
        assert_eq!(env_taint(Some(b"X=LD_PRELOAD=/tmp/x.so\0")), None);
        assert_eq!(env_taint(None), Some("its environment could not be read"));
        assert_eq!(
            env_taint(Some(b"")),
            Some("its environment could not be read")
        );
    }

    #[test]
    fn exec_env_flags_set_the_taint_and_end_the_wait() {
        let mut t = table();
        t.apply(&ev(EventKind::Exec, 10, 1));
        let k = ProcKey {
            tgid: 10,
            start_time_ns: 1,
        };
        for (flags, want) in [
            (ENV_LOADER_VAR, Some(LOADER_VAR)),
            (ENV_LOADER_VAR | ENV_TRUNCATED, Some(LOADER_VAR)),
            (ENV_TRUNCATED, Some(UNREADABLE)),
            (ENV_UNREADABLE, Some(UNREADABLE)),
            (HAS_TTY, None),
        ] {
            let mut e = ev(EventKind::ExecEnv, 10, 1);
            e.flags = flags;
            t.set_env(&k, None, true);
            t.apply(&e);
            let p = t.get(&k).unwrap();
            assert!(!p.env_pending);
            assert_eq!(p.env_taint, want, "flags {flags}");
        }
    }

    fn table() -> ProcTable {
        ProcTable {
            host_pidns: |_| true,
            ..ProcTable::new()
        }
    }

    #[test]
    fn an_unreadable_pid_namespace_counts_as_the_hosts() {
        // A tracer that is already gone can't show it was contained.
        assert!(in_host_pidns(u32::MAX));
    }

    #[test]
    fn an_exec_leaves_the_environment_to_the_pipeline() {
        let mut t = table();
        t.apply(&ev(EventKind::Exec, 10, 1));
        let p = t
            .get(&ProcKey {
                tgid: 10,
                start_time_ns: 1,
            })
            .unwrap();
        assert!(!p.env_pending);
        assert_eq!(p.taint(), None);
    }

    #[test]
    fn a_tracer_outside_the_host_pid_namespace_taints_nothing() {
        let mut t = table();
        t.host_pidns = |_| false;
        t.apply(&ev(EventKind::Exec, 20, 20));
        let mut p = ev(EventKind::Ptrace, 30, 30);
        p.target_tgid = 20;
        t.apply(&p);
        let k = ProcKey {
            tgid: 20,
            start_time_ns: 20,
        };
        assert!(!t.get(&k).unwrap().ptraced);
    }

    #[test]
    fn a_ptrace_target_is_tainted_its_children_inherit_and_exec_clears() {
        let mut t = table();
        let k = |tgid| ProcKey {
            tgid,
            start_time_ns: tgid as u64,
        };
        t.apply(&ev(EventKind::Exec, 20, 20));
        t.apply(&ev(EventKind::Exec, 30, 30));
        let mut p = ev(EventKind::Ptrace, 30, 30);
        p.target_tgid = 20;
        t.apply(&p);
        assert!(t.get(&k(20)).unwrap().ptraced);
        assert!(!t.get(&k(30)).unwrap().ptraced, "the tracer isn't");
        let mut f = ev(EventKind::Fork, 20, 20);
        f.child_tgid = 21;
        f.child_start_time_ns = 21;
        t.apply(&f);
        assert_eq!(
            t.get(&k(21)).unwrap().taint(),
            Some("it was the target of a ptrace attach")
        );
        t.apply(&ev(EventKind::Exec, 21, 21));
        assert_eq!(t.get(&k(21)).unwrap().taint(), None);
        assert!(t.get(&k(20)).unwrap().ptraced, "the target's own stays");
    }

    #[test]
    fn exe_id_converts_the_kernel_dev_to_stat_encoding() {
        let mut e = ev(EventKind::Exec, 1, 1);
        // sda1 is 8:1, and a minor past 255 checks the high bits.
        e.exe_dev = (8 << 20) | 1;
        e.exe_ino = 42;
        assert_eq!(exe_id(&e), (libc::makedev(8, 1), 42));
        e.exe_dev = (259 << 20) | 300;
        assert_eq!(exe_id(&e).0, libc::makedev(259, 300));
    }
}
