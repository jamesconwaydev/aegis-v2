// SPDX-License-Identifier: MIT OR Apache-2.0
//! Host checks that run before (or without) aegisd.
//!
//! Every file is read under `root`, so tests point it at a fake tree.

use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Check {
    pub check: &'static str,
    pub status: Status,
    pub detail: String,
    pub fix: Option<String>,
}

impl Check {
    pub fn to_json(&self) -> Value {
        let mut v =
            json!({"check": self.check, "status": self.status.as_str(), "detail": self.detail});
        if let Some(f) = &self.fix {
            v["fix"] = json!(f);
        }
        v
    }
}

pub struct Preflight;

/// 0 all pass, 1 any FAIL, 2 only WARN.
pub fn exit_code(checks: &[Check]) -> u8 {
    if checks.iter().any(|c| c.status == Status::Fail) {
        1
    } else if checks.iter().any(|c| c.status == Status::Warn) {
        2
    } else {
        0
    }
}

fn under(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
}

fn read(root: &Path, abs: &str) -> Option<String> {
    fs::read_to_string(under(root, abs))
        .ok()
        .map(|s| s.trim().to_string())
}

fn mk(
    check: &'static str,
    ok: bool,
    bad: Status,
    good: String,
    bad_detail: String,
    fix: &str,
) -> Check {
    if ok {
        Check {
            check,
            status: Status::Pass,
            detail: good,
            fix: None,
        }
    } else {
        Check {
            check,
            status: bad,
            detail: bad_detail,
            fix: Some(fix.into()),
        }
    }
}

fn kernel_ok(rel: &str) -> bool {
    let mut n = rel
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty());
    let major: u32 = n.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = n.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor) >= (6, 12)
}

fn on_path(dirs: &[PathBuf], name: &str) -> bool {
    dirs.iter().any(|d| d.join(name).is_file())
}

impl Preflight {
    /// Checks against a fake or real root, with the standard bin dirs and
    /// the default socket, all under `root`.
    #[allow(dead_code)] // the tests use it; main passes its own PATH and socket
    pub fn run(root: &Path) -> Vec<Check> {
        let dirs: Vec<PathBuf> = [
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
        ]
        .iter()
        .map(|d| under(root, d))
        .collect();
        Self::run_with(root, &dirs, &under(root, aegis_proto::SOCKET))
    }

    pub fn run_with(root: &Path, path: &[PathBuf], socket: &Path) -> Vec<Check> {
        let mut out = Vec::new();

        let rel = read(root, "/proc/sys/kernel/osrelease");
        out.push(mk(
            "kernel",
            rel.as_deref().is_some_and(kernel_ok),
            Status::Fail,
            format!("{} (6.12 or newer needed)", rel.clone().unwrap_or_default()),
            match &rel {
                Some(r) => format!("{r} is older than 6.12"),
                None => "can't read the kernel version".into(),
            },
            "Boot a 6.12+ kernel (Rocky 10 ships one).",
        ));

        let cg = read(root, "/proc/mounts").is_some_and(|m| {
            m.lines().any(|l| {
                let f: Vec<_> = l.split_whitespace().collect();
                f.get(1) == Some(&"/sys/fs/cgroup") && f.get(2) == Some(&"cgroup2")
            })
        });
        out.push(mk(
            "cgroup2",
            cg,
            Status::Fail,
            "cgroup2 mounted at /sys/fs/cgroup".into(),
            "cgroup2 is not mounted at /sys/fs/cgroup".into(),
            "Remove systemd.unified_cgroup_hierarchy=0 from the kernel command line and reboot.",
        ));

        let btf = under(root, "/sys/kernel/btf/vmlinux").exists();
        out.push(mk(
            "btf",
            btf,
            Status::Fail,
            "/sys/kernel/btf/vmlinux present".into(),
            "/sys/kernel/btf/vmlinux is missing".into(),
            "Use a kernel built with CONFIG_DEBUG_INFO_BTF=y (Rocky's is).",
        ));

        let lsm = read(root, "/sys/kernel/security/lsm");
        let has_bpf = lsm
            .as_deref()
            .is_some_and(|l| l.split(',').any(|x| x == "bpf"));
        let cur = lsm.clone().unwrap_or_default();
        out.push(mk(
            "bpf-lsm",
            has_bpf,
            Status::Fail,
            format!("bpf is in the LSM list ({cur})"),
            match &lsm {
                Some(_) => format!("bpf is not in the LSM list ({cur})"),
                None => "can't read /sys/kernel/security/lsm".into(),
            },
            &format!("grubby --update-kernel=ALL --args=\"lsm={cur},bpf\" (reboot required)"),
        ));

        let enforcing = read(root, "/sys/fs/selinux/enforce").as_deref() == Some("1");
        out.push(mk(
            "selinux",
            enforcing,
            Status::Warn,
            "SELinux is enforcing".into(),
            "SELinux is not enforcing, or not readable".into(),
            "setenforce 1, and set SELINUX=enforcing in /etc/selinux/config.",
        ));

        out.push(mk(
            "nft",
            on_path(path, "nft"),
            Status::Fail,
            "nft found".into(),
            "nft not found".into(),
            "dnf install nftables",
        ));
        out.push(mk(
            "criu",
            on_path(path, "criu"),
            Status::Warn,
            "criu found".into(),
            "criu not found (needed from v0.4.0)".into(),
            "dnf install criu",
        ));

        // A root-only socket answers connect with EACCES for everyone
        // else; the daemon is still there.
        let up = match UnixStream::connect(socket) {
            Ok(_) => true,
            Err(e) => e.kind() == std::io::ErrorKind::PermissionDenied,
        };
        out.push(mk(
            "aegisd",
            up,
            Status::Warn,
            format!("aegisd is answering on {}", socket.display()),
            format!("aegisd is not running (no answer on {})", socket.display()),
            "systemctl enable --now aegisd (after installing the package).",
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    struct Fx {
        root: PathBuf,
        _sock: UnixListener,
    }

    fn put(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    /// A root where everything passes, with a live socket.
    fn fixture(name: &str) -> Fx {
        let root = std::env::temp_dir().join(format!("aegisctl-pf-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        put(
            &root,
            "proc/sys/kernel/osrelease",
            "6.12.0-211.el10.x86_64\n",
        );
        put(
            &root,
            "proc/mounts",
            "cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n",
        );
        put(&root, "sys/kernel/btf/vmlinux", "");
        put(
            &root,
            "sys/kernel/security/lsm",
            "lockdown,capability,yama,selinux,bpf\n",
        );
        put(&root, "sys/fs/selinux/enforce", "1");
        put(&root, "usr/bin/nft", "");
        put(&root, "usr/bin/criu", "");
        let s = under(&root, aegis_proto::SOCKET);
        fs::create_dir_all(s.parent().unwrap()).unwrap();
        Fx {
            _sock: UnixListener::bind(&s).unwrap(),
            root,
        }
    }

    fn get<'a>(c: &'a [Check], name: &str) -> &'a Check {
        c.iter().find(|c| c.check == name).unwrap()
    }

    #[test]
    fn all_pass_fixture_exits_0() {
        let f = fixture("pass");
        let c = Preflight::run(&f.root);
        assert_eq!(c.len(), 8);
        assert!(c.iter().all(|c| c.status == Status::Pass), "{c:?}");
        assert_eq!(exit_code(&c), 0);
    }

    #[test]
    fn lsm_missing_bpf_fails_with_grubby_hint() {
        let f = fixture("lsm");
        put(
            &f.root,
            "sys/kernel/security/lsm",
            "lockdown,capability,selinux\n",
        );
        let c = Preflight::run(&f.root);
        let l = get(&c, "bpf-lsm");
        assert_eq!(l.status, Status::Fail);
        let fix = l.fix.as_deref().unwrap();
        assert!(fix.contains(
            r#"grubby --update-kernel=ALL --args="lsm=lockdown,capability,selinux,bpf""#
        ));
        assert!(fix.contains("reboot required"));
        assert_eq!(exit_code(&c), 1);
    }

    #[test]
    fn old_kernel_fails() {
        let f = fixture("old");
        put(
            &f.root,
            "proc/sys/kernel/osrelease",
            "5.14.0-503.el9.x86_64\n",
        );
        let c = Preflight::run(&f.root);
        assert_eq!(get(&c, "kernel").status, Status::Fail);
        assert_eq!(exit_code(&c), 1);
    }

    #[test]
    fn warns_alone_exit_2() {
        let f = fixture("warn");
        fs::remove_file(f.root.join("usr/bin/criu")).unwrap();
        put(&f.root, "sys/fs/selinux/enforce", "0");
        let c = Preflight::run(&f.root);
        assert!(get(&c, "criu").detail.contains("needed from v0.4.0"));
        assert_eq!(exit_code(&c), 2);
    }
}
