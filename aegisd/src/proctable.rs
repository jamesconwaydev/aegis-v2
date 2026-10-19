// SPDX-License-Identifier: MIT OR Apache-2.0
//! Live process table, built from the probe event stream.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use aegis_common::{Event, EventKind, HAS_TTY};

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
    pub comm: String,
    pub uid: u32,
    pub has_tty: bool,
    pub selinux_domain: Option<String>,
    pub verification: Verification,
    pub cgroup_id: u64,
}

#[derive(Default)]
pub struct ProcTable {
    procs: HashMap<ProcKey, ProcInfo>,
}

fn comm_str(c: &[u8; 16]) -> String {
    let n = c.iter().position(|&b| b == 0).unwrap_or(c.len());
    String::from_utf8_lossy(&c[..n]).into_owned()
}

/// Best effort: the process may already be gone, or SELinux may be off.
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

    pub fn get(&self, k: &ProcKey) -> Option<&ProcInfo> {
        self.procs.get(k)
    }

    /// Records the verdict for a process once the verifier has run.
    pub fn set_verification(&mut self, k: &ProcKey, v: Verification) {
        if let Some(p) = self.procs.get_mut(k) {
            p.verification = v;
        }
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
        self.ensure(ev, key);
        match kind {
            Some(EventKind::Exec) => {
                let n = (ev.path_len as usize).min(ev.path.len());
                let p = self.procs.get_mut(&key).unwrap();
                p.exe = Some(PathBuf::from(OsStr::from_bytes(&ev.path[..n])));
                p.comm = comm_str(&ev.comm);
                p.has_tty = ev.flags & HAS_TTY != 0;
                p.selinux_domain = selinux_domain(ev.tgid);
                // The old image's verdict no longer applies.
                p.verification = Verification::Unverified;
            }
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
                    selinux_domain: parent.selinux_domain,
                    verification: parent.verification,
                    ..parent
                });
            }
            _ => {}
        }
    }

    /// Creates the subject's entry if we missed its birth (it predates us).
    fn ensure(&mut self, ev: &Event, key: ProcKey) {
        if self.procs.contains_key(&key) {
            return;
        }
        // ponytail: linear scan; index by tgid if the table gets large.
        let parent = self
            .procs
            .keys()
            .find(|k| k.tgid == ev.ppid && ev.ppid != 0)
            .copied();
        self.procs.insert(
            key,
            ProcInfo {
                key,
                parent,
                exe: None,
                comm: comm_str(&ev.comm),
                uid: ev.uid,
                has_tty: ev.flags & HAS_TTY != 0,
                selinux_domain: None,
                verification: Verification::Unverified,
                cgroup_id: ev.cgroup_id,
            },
        );
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
}
