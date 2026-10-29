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

/// The value of `key` in `[section]`, unquoted. Line-based and lenient:
/// preflight must work on a file aegisd would reject.
fn config_value(src: &str, section: &str, key: &str) -> Option<String> {
    let mut inside = false;
    for l in src.lines() {
        let l = l.split('#').next().unwrap_or("").trim();
        if l.starts_with('[') {
            inside = l.strip_prefix('[').and_then(|r| r.strip_suffix(']')) == Some(section);
        } else if inside {
            if let Some((k, v)) = l.split_once('=') {
                if k.trim() == key {
                    return Some(v.trim().trim_matches(|c| c == '"' || c == '\'').to_string());
                }
            }
        }
    }
    None
}

/// Whether `[general]` sets `mode = "enforce"`.
fn config_enforces(src: &str) -> bool {
    config_value(src, "general", "mode").as_deref() == Some("enforce")
}

/// Whether systemd says the unit is active. Preflight's one probe of
/// systemd, behind a function so tests can fake it.
pub fn systemd_active(unit: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .is_ok_and(|s| s.success())
}

/// The honeypot's socket unit and service user, as v0.3 packages them.
const HONEYPOT_UNIT: &str = "aegis-honeypot.socket";
const HONEYPOT_USER: &str = "aegis-honeypot";

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
        Self::run_with(root, &dirs, &under(root, aegis_proto::SOCKET), &|_| true)
    }

    pub fn run_with(
        root: &Path,
        path: &[PathBuf],
        socket: &Path,
        unit_active: &dyn Fn(&str) -> bool,
    ) -> Vec<Check> {
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

        let lsm = read(root, "/sys/kernel/security/lsm").filter(|l| !l.is_empty());
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
            &if cur.is_empty() {
                // lsm=bpf alone would drop SELinux and the rest.
                "Read the current list with `cat /sys/kernel/security/lsm`, then run \
                 grubby --update-kernel=ALL --args=\"lsm=<that list>,bpf\" \
                 (reboot required)"
                    .to_string()
            } else {
                format!("grubby --update-kernel=ALL --args=\"lsm={cur},bpf\" (reboot required)")
            },
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

        // Enforce mode needs nft; in audit mode it is only advice. A
        // missing or unreadable config counts as audit.
        let cfg = read(root, "/etc/aegis-v2/config.toml").unwrap_or_default();
        let enforce = config_enforces(&cfg);
        out.push(mk(
            "nft",
            on_path(path, "nft"),
            if enforce { Status::Fail } else { Status::Warn },
            "nft found".into(),
            if enforce {
                "nft not found, and the config sets mode = \"enforce\"".into()
            } else {
                "nft not found (needed for enforce mode, from v0.2.0)".into()
            },
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

        // Needed only for network = "honeypot", and only an enforce-mode
        // config acts on it; otherwise a gap is advice.
        let honeypot = config_value(&cfg, "quarantine", "network").as_deref() == Some("honeypot");
        let port = |k: &str, d: u16| {
            config_value(&cfg, "honeypot", k)
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        let (tcp, dns) = (port("tcp_port", 2580), port("dns_port", 2553));
        let mut missing = Vec::new();
        if !unit_active(HONEYPOT_UNIT) {
            missing.push(format!("{HONEYPOT_UNIT} is not active"));
        }
        if !aegis_proto::honeypot_listening(&under(root, "/proc"), tcp, dns).unwrap_or(false) {
            missing.push(format!(
                "nothing listens on 0.0.0.0 TCP {tcp} and UDP {dns}"
            ));
        }
        let user = read(root, "/etc/passwd").is_some_and(|p| {
            p.lines()
                .any(|l| l.split(':').next() == Some(HONEYPOT_USER))
        });
        if !user {
            missing.push(format!("user {HONEYPOT_USER} does not exist"));
        }
        out.push(mk(
            "honeypot",
            missing.is_empty(),
            if honeypot && enforce {
                Status::Fail
            } else {
                Status::Warn
            },
            format!("{HONEYPOT_UNIT} active, ports {tcp}/{dns} listening, {HONEYPOT_USER} exists"),
            format!(
                "{}{}",
                missing.join("; "),
                if honeypot {
                    ""
                } else {
                    " (needed only for network = \"honeypot\", from v0.3.0)"
                }
            ),
            "Install the aegis-v2 package, then systemctl enable --now aegis-honeypot.socket.",
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
        put(
            &root,
            "etc/passwd",
            "root:x:0:0::/root:/bin/bash\naegis-honeypot:x:990:990::/:/sbin/nologin\n",
        );
        put(
            &root,
            "proc/net/tcp",
            "sl local rem st\n0: 00000000:0A14 00000000:0000 0A 0:0\n",
        );
        put(
            &root,
            "proc/net/udp",
            "sl local rem st\n0: 00000000:09F9 00000000:0000 07 0:0\n",
        );
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
        assert_eq!(c.len(), 9);
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
    fn unreadable_lsm_list_never_suggests_a_bare_list() {
        let f = fixture("nolsm");
        fs::remove_file(f.root.join("sys/kernel/security/lsm")).unwrap();
        let c = Preflight::run(&f.root);
        let l = get(&c, "bpf-lsm");
        assert_eq!(l.status, Status::Fail);
        let fix = l.fix.as_deref().unwrap();
        assert!(!fix.contains("lsm=,bpf"), "{fix}");
        assert!(fix.contains("cat /sys/kernel/security/lsm"));
        assert!(fix.contains("lsm=<that list>,bpf"));
        assert!(fix.contains("reboot required"));
    }

    #[test]
    fn kernel_versions() {
        for (s, ok) in [
            ("6.12.0-211.el10.x86_64", true),
            ("6.12", true),
            ("6.13.1", true),
            ("7.0.0", true),
            ("6.11.9", false),
            ("5.14.0-503.el9", false),
            ("6", false),
            ("", false),
            ("garbage", false),
            ("v6.12", true),
            ("6.x", false),
        ] {
            assert_eq!(kernel_ok(s), ok, "{s:?}");
        }
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
        fs::remove_file(f.root.join("usr/bin/nft")).unwrap();
        put(&f.root, "sys/fs/selinux/enforce", "0");
        let c = Preflight::run(&f.root);
        assert!(get(&c, "criu").detail.contains("needed from v0.4.0"));
        // Audit mode never touches nftables: missing it is only a warning.
        assert_eq!(get(&c, "nft").status, Status::Warn);
        assert!(get(&c, "nft").detail.contains("enforce mode"));
        assert_eq!(exit_code(&c), 2);
    }

    #[test]
    fn missing_nft_fails_when_the_config_enforces() {
        let f = fixture("nft-enforce");
        fs::remove_file(f.root.join("usr/bin/nft")).unwrap();
        put(
            &f.root,
            "etc/aegis-v2/config.toml",
            "[scoring]\nmode = \"audit\"\n[general]\nmode = \"enforce\" # on\n",
        );
        let c = Preflight::run(&f.root);
        assert_eq!(get(&c, "nft").status, Status::Fail);
        assert_eq!(exit_code(&c), 1);
        // Unreadable or audit configs stay a warning.
        put(
            &f.root,
            "etc/aegis-v2/config.toml",
            "[general]\nmode = \"audit\"\n",
        );
        assert_eq!(get(&Preflight::run(&f.root), "nft").status, Status::Warn);
    }

    #[test]
    fn honeypot_line_follows_the_network_mode() {
        let f = fixture("hp");
        let sock = under(&f.root, aegis_proto::SOCKET);
        let run = |active: bool| Preflight::run_with(&f.root, &[], &sock, &|_| active);
        // Everything in place: pass.
        assert_eq!(get(&run(true), "honeypot").status, Status::Pass);
        // Unit down, no listeners, no user: one warning naming all three.
        fs::remove_file(f.root.join("proc/net/tcp")).unwrap();
        put(&f.root, "etc/passwd", "root:x:0:0::/root:/bin/bash\n");
        let c = run(false);
        let h = get(&c, "honeypot");
        assert_eq!(h.status, Status::Warn);
        for want in [
            "not active",
            "nothing listens",
            "does not exist",
            "from v0.3.0",
        ] {
            assert!(h.detail.contains(want), "{want}: {}", h.detail);
        }
        // network = "honeypot" in an audit config is still advice...
        put(
            &f.root,
            "etc/aegis-v2/config.toml",
            "[quarantine]\nnetwork = \"honeypot\"\n",
        );
        let h = get(&run(false), "honeypot").clone();
        assert_eq!(h.status, Status::Warn);
        assert!(!h.detail.contains("from v0.3.0"));
        // ...and a failure once the config enforces.
        put(
            &f.root,
            "etc/aegis-v2/config.toml",
            "[general]\nmode = \"enforce\"\n[quarantine]\nnetwork = \"honeypot\"\n",
        );
        assert_eq!(get(&run(false), "honeypot").status, Status::Fail);
    }

    #[test]
    fn honeypot_ports_come_from_the_config() {
        let f = fixture("hp-ports");
        let sock = under(&f.root, aegis_proto::SOCKET);
        put(
            &f.root,
            "etc/aegis-v2/config.toml",
            "[honeypot]\ntcp_port = 3000\ndns_port = 3001\n",
        );
        let c = Preflight::run_with(&f.root, &[], &sock, &|_| true);
        assert!(get(&c, "honeypot").detail.contains("TCP 3000 and UDP 3001"));
    }
}
