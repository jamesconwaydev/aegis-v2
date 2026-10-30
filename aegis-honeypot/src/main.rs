// SPDX-License-Identifier: MIT OR Apache-2.0
//! aegis-honeypot: answers whatever a quarantined tree under observation
//! tries to reach, and records it. Started by `aegis-honeypot.socket`,
//! which binds the ports as root and hands over the sockets; this
//! process never holds root or a capability, and refuses to start if it
//! does.

mod ca;
mod dispatch;
mod dns;
mod hello;
mod http;
mod mail;
mod pcap;
mod serve;
mod session;
mod shell;
mod smtp;
mod ssh;
mod udp;
mod upload;
mod web;

use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use aegis_proto::honeypot::{HoneypotConfig, Protocol};
use anyhow::{bail, Context, Result};
use serde::Deserialize;

use serve::{accept, Server};
use session::{Slots, FLOOR};

/// aegisd writes the `[honeypot]` table here, and only that: its own
/// config is root's alone and can hold secrets.
const CONFIG: &str = "/run/aegis-honeypot.toml";
/// The unit's StateDirectory, when systemd doesn't say.
const STATE: &str = "/var/lib/aegis-honeypot";

/// Why this process must not run, or None. Root (any uid or gid, or a
/// supplementary group 0) or any capability in the permitted, effective
/// or ambient set refuses; so does a status it can't read those from.
fn refusal(status: &str) -> Option<String> {
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix(':'))
            .map(str::trim)
    };
    // Real, effective, saved and filesystem uid.
    let uids: Vec<&str> = field("Uid").unwrap_or("").split_whitespace().collect();
    if uids.len() != 4 || uids.contains(&"0") {
        return Some(format!("refusing to run as root (Uid {uids:?})"));
    }
    let gids: Vec<&str> = field("Gid").unwrap_or("").split_whitespace().collect();
    if gids.len() != 4 || gids.contains(&"0") {
        return Some(format!("refusing to run in group root (Gid {gids:?})"));
    }
    match field("Groups") {
        Some(g) if !g.split_whitespace().any(|x| x == "0") => {}
        g => return Some(format!("refusing to run in group root (Groups {g:?})")),
    }
    ["CapPrm", "CapEff", "CapAmb"]
        .into_iter()
        .find_map(|k| match field(k) {
            Some(v) if !v.is_empty() && v.bytes().all(|b| b == b'0') => None,
            v => Some(format!(
                "refusing to run with capabilities ({k} {})",
                v.unwrap_or("missing")
            )),
        })
}

/// The file aegisd writes: `[honeypot]` and nothing else.
fn config(src: &str) -> Result<HoneypotConfig> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        #[serde(default)]
        honeypot: HoneypotConfig,
    }
    Ok(toml::from_str::<File>(src)?.honeypot)
}

/// The sockets systemd passed (sd_listen_fds(3)) as (name, fd).
fn listen_fds(
    pid: Option<&str>,
    fds: Option<&str>,
    names: Option<&str>,
    me: u32,
) -> Result<Vec<(String, RawFd)>> {
    if pid.and_then(|p| p.parse::<u32>().ok()) != Some(me) {
        bail!("no sockets from systemd; start aegis-honeypot.socket, not the service");
    }
    let n: usize = fds
        .and_then(|n| n.parse().ok())
        .context("LISTEN_FDS is not a count")?;
    let names: Vec<&str> = names
        .context("LISTEN_FDNAMES is not set")?
        .split(':')
        .collect();
    if names.len() != n {
        bail!("{n} sockets from systemd but {} names", names.len());
    }
    // sd_listen_fds(3): the first passed fd is always 3.
    Ok(names.into_iter().map(String::from).zip(3..).collect())
}

/// An int-valued SOL_SOCKET option of `fd`, or None when it has none.
fn sockopt(fd: RawFd, opt: libc::c_int) -> Option<libc::c_int> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `v`; a bad fd
    // is only an error.
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, opt, (&raw mut v).cast(), &mut len) };
    (r == 0).then_some(v)
}

/// Whether `fd` is a listening socket. A unit that passes anything else
/// would have the accept loop failing forever.
fn listening(fd: RawFd) -> bool {
    sockopt(fd, libc::SO_ACCEPTCONN) == Some(1)
}

/// Whether `fd` is a datagram socket, as dns-udp must be.
fn datagram(fd: RawFd) -> bool {
    sockopt(fd, libc::SO_TYPE) == Some(libc::SOCK_DGRAM)
}

/// systemd's StateDirectory, the first one when it lists several. The
/// CA lives here and the spool beneath it: aegisd walks only the spool.
fn state(dirs: Option<&str>) -> PathBuf {
    let first = dirs
        .and_then(|s| s.split(':').next())
        .filter(|s| !s.is_empty());
    PathBuf::from(first.unwrap_or(STATE))
}

/// What the fake shell says the host is: the real one, its name in
/// short form as a prompt shows it.
fn shell_host(hostname: &str, release: &str, version: &str) -> shell::Host {
    let name = hostname.trim();
    shell::Host {
        name: name.split('.').next().unwrap_or(name).to_string(),
        release: release.trim().to_string(),
        version: version.trim().to_string(),
        arch: std::env::consts::ARCH.to_string(),
    }
}

/// Why a task that should run for good stopped; never, for no task.
async fn ended(task: Option<tokio::task::JoinHandle<()>>) -> String {
    match task {
        Some(t) => t
            .await
            .map_or_else(|e| e.to_string(), |()| "stopped".into()),
        None => std::future::pending().await,
    }
}

fn run() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status").context("/proc/self/status")?;
    if let Some(why) = refusal(&status) {
        bail!(why);
    }
    let cfg = std::fs::read_to_string(CONFIG)
        .map_err(anyhow::Error::from)
        .and_then(|s| config(&s))
        .with_context(|| {
            format!("{CONFIG} (aegisd writes it when quarantine.network = \"honeypot\")")
        })?;
    let env = |k| std::env::var(k).ok();
    let fds = listen_fds(
        env("LISTEN_PID").as_deref(),
        env("LISTEN_FDS").as_deref(),
        env("LISTEN_FDNAMES").as_deref(),
        std::process::id(),
    )?;
    let fd = |name: &str| -> Result<Option<RawFd>> {
        let Some(&(_, fd)) = fds.iter().find(|(n, _)| n == name) else {
            return Ok(None);
        };
        if !listening(fd) {
            bail!("socket {name} (fd {fd}) is not listening; check aegis-honeypot.socket");
        }
        Ok(Some(fd))
    };
    let tcp = fd("tcp")?.context("systemd passed no socket named tcp")?;
    let dns = fd("dns-tcp")?;
    let dns_udp = match fds.iter().find(|(n, _)| n == "dns-udp") {
        Some(&(_, fd)) if datagram(fd) => {
            udp::pktinfo(fd).context("dns-udp: IP_PKTINFO")?;
            Some(fd)
        }
        Some(&(_, fd)) => {
            bail!("socket dns-udp (fd {fd}) is not a datagram socket; check aegis-honeypot.socket")
        }
        None => None,
    };
    // Once, here: each session checks free space on it before creating
    // anything of its own.
    let state = state(env("STATE_DIRECTORY").as_deref());
    let spool = state.join("spool");
    session::shared_dir(&spool).with_context(|| spool.display().to_string())?;
    let kernel = |f: &str| {
        let p = format!("/proc/sys/kernel/{f}");
        std::fs::read_to_string(&p).with_context(|| p)
    };
    let host = kernel("hostname")?;
    let tls = ca::config(ca::Certs::load(&state, host.trim())?)?;
    let shell = shell_host(&host, &kernel("osrelease")?, &kernel("version")?);
    let mail = format!("mail.{}", shell.name);
    let ssh = ssh::Ssh::load(&state, shell)?;
    let srv = Rc::new(Server {
        spool,
        max_bytes: cfg.max_session_bytes,
        max_time: Duration::from_secs(cfg.session_seconds),
        floor: FLOOR,
        slots: Slots::default(),
        udp_slots: udp::slots(),
        names: Default::default(),
        tls,
        mail,
        ssh,
        ssh_slots: ssh::slots(),
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tokio::task::LocalSet::new().block_on(&rt, async move {
        let listener = |fd: RawFd| -> Result<tokio::net::TcpListener> {
            // SAFETY: systemd passed this fd to us alone, and nothing else
            // in the process takes ownership of it.
            let l = unsafe { std::net::TcpListener::from_raw_fd(fd) };
            l.set_nonblocking(true)?;
            Ok(tokio::net::TcpListener::from_std(l)?)
        };
        // Nothing redirects to dns-tcp, but a client that finds the port
        // gets DNS.
        let dns_tcp = match dns {
            Some(d) => Some(tokio::task::spawn_local(accept(
                srv.clone(),
                listener(d)?,
                Some(Protocol::Dns),
            ))),
            None => None,
        };
        let dns_udp = match dns_udp {
            Some(d) => {
                // SAFETY: as for the listeners.
                let s = unsafe { std::net::UdpSocket::from_raw_fd(d) };
                s.set_nonblocking(true)?;
                let s = tokio::net::UdpSocket::from_std(s)?;
                Some(tokio::task::spawn_local(udp::serve(srv.clone(), s)))
            }
            None => None,
        };
        let tcp = listener(tcp)?;
        // Any of them stopping exits the process, so systemd restarts all
        // of it rather than it running on half-deaf.
        tokio::select! {
            () = accept(srv, tcp, None) => bail!("tcp: stopped"),
            why = ended(dns_tcp) => bail!("dns-tcp: {why}"),
            why = ended(dns_udp) => bail!("dns-udp: {why}"),
        }
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegis-honeypot: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\taegis-honeypot\nUmask:\t0022\nState:\tS (sleeping)\n\
        Uid:\t991\t991\t991\t991\nGid:\t991\t991\t991\t991\nGroups:\t991 \n\
        CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
        CapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\n\
        CapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";

    #[test]
    fn an_unprivileged_status_may_run() {
        assert_eq!(refusal(STATUS), None);
    }

    #[test]
    fn root_or_any_capability_refuses() {
        for (from, to) in [
            ("Uid:\t991\t991\t991\t991", "Uid:\t0\t0\t0\t0"),
            ("Uid:\t991\t991\t991\t991", "Uid:\t991\t0\t991\t991"),
            ("Uid:\t991\t991\t991\t991", "Uid:\t991\t991\t0\t991"),
            ("Gid:\t991\t991\t991\t991", "Gid:\t0\t991\t991\t991"),
            ("Gid:\t991\t991\t991\t991", "Gid:\t991\t991\t991\t0"),
            ("Groups:\t991 ", "Groups:\t991 0 "),
            ("Groups:\t991 ", "Groups:\t0"),
            ("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000400"),
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000002000"),
            ("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001"),
            // Unreadable is not "no".
            ("CapEff:\t0000000000000000\n", ""),
            ("Uid:\t991\t991\t991\t991\n", ""),
            ("Gid:\t991\t991\t991\t991\n", ""),
            ("Groups:\t991 \n", ""),
            ("CapPrm:\t0000000000000000", "CapPrm:\t"),
        ] {
            let s = STATUS.replace(from, to);
            assert_ne!(s, STATUS);
            assert!(refusal(&s).is_some(), "{to:?}");
        }
        // The bounding set alone grants nothing.
        assert_eq!(refusal(&STATUS.replace("000001ffffffffff", "0")), None);
    }

    #[test]
    fn config_reads_what_aegisd_writes() {
        let want = HoneypotConfig {
            max_session_bytes: 10,
            session_seconds: 20,
            ..HoneypotConfig::default()
        };
        // What aegisd writes; its own test checks it writes this shape.
        let text = "[honeypot]\ntcp_port = 2580\ndns_port = 2553\nmax_session_bytes = 10\n\
                    session_seconds = 20\nmax_tasks = 256\nmax_incidents = 32\n";
        assert_eq!(config(text).unwrap(), want);
        assert_eq!(config("").unwrap(), HoneypotConfig::default());
        // Anything but [honeypot] means the wrong file, so it's refused.
        let e = format!("{:#}", config("[telemetry]\njsonl = \"/x\"\n").unwrap_err());
        assert!(e.contains("telemetry"), "{e}");
    }

    #[test]
    fn only_listening_sockets_are_served() {
        use std::os::fd::AsRawFd;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(listening(l.as_raw_fd()));
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        assert!(!listening(c.as_raw_fd()));
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(!listening(u.as_raw_fd()));
        assert!(!listening(-1));
    }

    #[test]
    fn only_datagram_sockets_are_served_as_dns_udp() {
        use std::os::fd::AsRawFd;
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(datagram(u.as_raw_fd()));
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(!datagram(l.as_raw_fd()));
        assert!(!datagram(-1));
    }

    #[tokio::test]
    async fn a_dns_task_that_stops_is_noticed() {
        use std::time::Duration;
        use tokio::time::timeout;
        let wait = Duration::from_secs(1);
        tokio::task::LocalSet::new()
            .run_until(async {
                let h = tokio::task::spawn_local(async { panic!("boom") });
                let why = timeout(wait, ended(Some(h)))
                    .await
                    .expect("a panic went unnoticed");
                assert!(why.contains("panicked"), "{why}");
                let h = tokio::task::spawn_local(async {});
                let why = timeout(wait, ended(Some(h)))
                    .await
                    .expect("a return went unnoticed");
                assert_eq!(why, "stopped");
                // No socket, no task: nothing to wait for.
                assert!(timeout(Duration::from_millis(10), ended(None))
                    .await
                    .is_err());
            })
            .await;
    }

    #[test]
    fn the_shell_names_the_host_in_short_form() {
        let h = shell_host("web1.example.com\n", "6.12.0\n", "#1 SMP\n");
        assert_eq!(
            (h.name.as_str(), h.release.as_str(), h.version.as_str()),
            ("web1", "6.12.0", "#1 SMP")
        );
        assert_eq!(shell_host("web1", "", "").name, "web1");
    }

    #[test]
    fn spool_sits_under_the_first_state_directory() {
        for (state, want) in [
            (None, "/var/lib/aegis-honeypot/spool"),
            (Some(""), "/var/lib/aegis-honeypot/spool"),
            (Some("/s"), "/s/spool"),
            (Some("/s:/t"), "/s/spool"),
        ] {
            assert_eq!(
                super::state(state).join("spool"),
                PathBuf::from(want),
                "{state:?}"
            );
        }
    }

    #[test]
    fn config_keeps_aegisds_bounds() {
        for (body, msg) in [
            ("[honeypot]\nmax_session_bytes = 0\n", "at least 1"),
            ("[honeypot]\nsession_seconds = 0\n", "at least 1"),
            ("[honeypot]\ntcp_port = 80\n", "1024 to 65535"),
            ("[honeypot]\nbogus = 1\n", "bogus"),
            ("[honeypot\n", ""),
        ] {
            let e = format!("{:#}", config(body).unwrap_err());
            assert!(e.contains(msg), "{body:?}: {e}");
        }
    }

    #[test]
    fn systemd_sockets_by_name() {
        let got = listen_fds(Some("42"), Some("3"), Some("tcp:dns-tcp:dns-udp"), 42).unwrap();
        assert_eq!(
            got,
            [
                ("tcp".to_string(), 3),
                ("dns-tcp".to_string(), 4),
                ("dns-udp".to_string(), 5)
            ]
        );
    }

    #[test]
    fn sockets_for_someone_else_or_miscounted_are_refused() {
        for (pid, n, names) in [
            (None, Some("1"), Some("tcp")),
            (Some("41"), Some("1"), Some("tcp")),
            (Some("42"), None, Some("tcp")),
            (Some("42"), Some("x"), Some("tcp")),
            (Some("42"), Some("2"), Some("tcp")),
            (Some("42"), Some("1"), Some("tcp:dns-tcp")),
            (Some("42"), Some("1"), None),
        ] {
            assert!(
                listen_fds(pid, n, names, 42).is_err(),
                "{pid:?} {n:?} {names:?}"
            );
        }
    }
}
