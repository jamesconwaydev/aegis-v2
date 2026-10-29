// SPDX-License-Identifier: MIT OR Apache-2.0
//! aegis-honeypot: answers whatever a quarantined tree under observation
//! tries to reach, and records it. Started by `aegis-honeypot.socket`,
//! which binds the ports as root and hands over the sockets; this
//! process never holds root or a capability, and refuses to start if it
//! does.

mod dispatch;
mod pcap;
mod serve;
mod session;

use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use aegis_proto::honeypot::{HoneypotConfig, Protocol};
use anyhow::{bail, Context, Result};
use serde::Deserialize;

use serve::{accept, Server};
use session::Slots;

/// aegisd's config. One file configures both; only `[honeypot]` is
/// read here.
const CONFIG: &str = "/etc/aegis-v2/config.toml";
/// The unit's StateDirectory, when systemd doesn't say.
const STATE: &str = "/var/lib/aegis-v2/honeypot";

/// Why this process must not run, or None. Root or any capability in
/// the permitted, effective or ambient set refuses; so does a status it
/// can't read those from.
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

/// The `[honeypot]` section of aegisd's config. Other sections are
/// aegisd's to check, so they're skipped, not refused.
fn config(src: &str) -> Result<HoneypotConfig> {
    #[derive(Deserialize)]
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

fn run() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status").context("/proc/self/status")?;
    if let Some(why) = refusal(&status) {
        bail!(why);
    }
    let cfg = std::fs::read_to_string(CONFIG)
        .map_err(anyhow::Error::from)
        .and_then(|s| config(&s))
        .with_context(|| CONFIG.to_string())?;
    let env = |k| std::env::var(k).ok();
    let fds = listen_fds(
        env("LISTEN_PID").as_deref(),
        env("LISTEN_FDS").as_deref(),
        env("LISTEN_FDNAMES").as_deref(),
        std::process::id(),
    )?;
    let fd = |name: &str| fds.iter().find(|(n, _)| n == name).map(|&(_, fd)| fd);
    let spool = PathBuf::from(env("STATE_DIRECTORY").unwrap_or_else(|| STATE.into())).join("spool");
    let srv = Rc::new(Server {
        spool,
        max_bytes: cfg.max_session_bytes,
        max_time: Duration::from_secs(cfg.session_seconds),
        slots: Slots::default(),
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
        let tcp = listener(fd("tcp").context("systemd passed no socket named tcp")?)?;
        let main = accept(srv.clone(), tcp, None);
        // Nothing redirects to dns-tcp, but a client that finds the port
        // gets DNS.
        match fd("dns-tcp") {
            Some(d) => {
                let dns = accept(srv, listener(d)?, Some(Protocol::Dns));
                tokio::join!(main, dns);
            }
            None => main.await,
        }
        Ok(())
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
        Uid:\t991\t991\t991\t991\nGid:\t991\t991\t991\t991\n\
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
            ("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000400"),
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000002000"),
            ("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001"),
            // Unreadable is not "no".
            ("CapEff:\t0000000000000000\n", ""),
            ("Uid:\t991\t991\t991\t991\n", ""),
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
    fn config_reads_honeypot_and_skips_the_rest() {
        let c = config(
            "[general]\nmode = \"enforce\"\n[scoring.weights]\ntmp_exec = 3.0\n\
             [anything]\nx = [1, \"a\"]\n[honeypot]\nmax_session_bytes = 10\n\
             session_seconds = 20\n",
        )
        .unwrap();
        assert_eq!((c.max_session_bytes, c.session_seconds), (10, 20));
        assert_eq!(c.tcp_port, 2580);
        assert_eq!(config("").unwrap(), HoneypotConfig::default());
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
