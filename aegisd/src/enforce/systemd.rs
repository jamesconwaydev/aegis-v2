// SPDX-License-Identifier: MIT OR Apache-2.0
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::proctable::ProcKey;

/// A hung systemd or nft must not wedge the enforcer thread.
const CMD_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs a command: program, args. Tests pass a fake.
pub type Run = fn(&str, &[String]) -> Result<String>;
/// Is this tgid still the process that started at this time?
pub type Alive = fn(u32, u64) -> bool;

/// Runs `prog args`, returning stdout; errors on spawn failure, timeout
/// or a non-zero exit (with stderr).
pub fn run_cmd(prog: &str, args: &[String]) -> Result<String> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {prog}"))?;
    // One reader per pipe, so neither can fill up and stall the child.
    let drain = |mut p: Box<dyn Read + Send>| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = p.read_to_end(&mut s);
            let _ = tx.send(s);
        });
        rx
    };
    let out = drain(Box::new(child.stdout.take().context("no stdout")?));
    let err = drain(Box::new(child.stderr.take().context("no stderr")?));
    let deadline = Instant::now() + CMD_TIMEOUT;
    let left = || deadline.saturating_duration_since(Instant::now());
    if let (Ok(o), Ok(e)) = (out.recv_timeout(left()), err.recv_timeout(left())) {
        while Instant::now() < deadline {
            if let Some(st) = child.try_wait()? {
                if st.success() {
                    return Ok(String::from_utf8_lossy(&o).into_owned());
                }
                bail!(
                    "{prog} {}: {st}: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&e).trim()
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    bail!("{prog} {}: timed out", args.join(" "))
}

pub struct Limits {
    pub cpu_quota_percent: u32,
    pub memory_high_bytes: u64,
}

pub struct Systemd {
    run: Run,
    alive: Alive,
}

impl Systemd {
    pub fn new() -> Self {
        Self::with(run_cmd, crate::pipeline::proc_start_matches)
    }

    pub fn with(run: Run, alive: Alive) -> Self {
        Self { run, alive }
    }

    /// Moves `pids` into a new transient scope under `slice`. A pid that
    /// exits before systemd looks fails the whole call, so on failure
    /// the dead ones are dropped and it is tried once more.
    pub fn start_scope(
        &self,
        name: &str,
        slice: &str,
        pids: &[ProcKey],
        limits: Option<Limits>,
    ) -> Result<()> {
        let first = self.call_start(name, slice, pids, &limits);
        let Err(e) = first else { return Ok(()) };
        let live: Vec<ProcKey> = pids
            .iter()
            .copied()
            .filter(|k| (self.alive)(k.tgid, k.start_time_ns))
            .collect();
        if live.len() == pids.len() {
            return Err(e);
        }
        if live.is_empty() {
            return Err(e.context("the process tree had already exited"));
        }
        self.call_start(name, slice, &live, &limits)
    }

    fn call_start(
        &self,
        name: &str,
        slice: &str,
        pids: &[ProcKey],
        limits: &Option<Limits>,
    ) -> Result<()> {
        let id = name.strip_prefix("aegis-incident-").unwrap_or(name);
        let id = id.strip_suffix(".scope").unwrap_or(id);
        let mut a: Vec<String> = [
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            name,
            "fail",
        ]
        .map(String::from)
        .into();
        a.push(if limits.is_some() { "5" } else { "3" }.into());
        a.extend(["PIDs", "au"].map(String::from));
        a.push(pids.len().to_string());
        a.extend(pids.iter().map(|k| k.tgid.to_string()));
        a.extend(["Slice", "s", slice].map(String::from));
        if let Some(l) = limits {
            // CPUQuotaPerSecUSec: 1% of a CPU is 10 000 us per second.
            a.extend(["CPUQuotaPerSecUSec", "t"].map(String::from));
            a.push((u64::from(l.cpu_quota_percent) * 10_000).to_string());
            a.extend(["MemoryHigh", "t"].map(String::from));
            a.push(l.memory_high_bytes.to_string());
        }
        a.extend(["Description", "s"].map(String::from));
        a.push(format!("Aegis incident {id}"));
        a.push("0".into());
        (self.run)("busctl", &a).map(drop)
    }

    fn ctl(&self, args: &[&str]) -> Result<()> {
        let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        (self.run)("systemctl", &a).map(drop)
    }

    pub fn freeze(&self, unit: &str) -> Result<()> {
        self.ctl(&["freeze", unit])
    }

    pub fn thaw(&self, unit: &str) -> Result<()> {
        self.ctl(&["thaw", unit])
    }

    pub fn kill(&self, unit: &str) -> Result<()> {
        self.ctl(&["kill", "--signal=SIGKILL", unit])
    }

    pub fn lift_limits(&self, unit: &str) -> Result<()> {
        self.ctl(&[
            "set-property",
            "--runtime",
            unit,
            "CPUQuota=",
            "MemoryHigh=infinity",
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! { static CALLS: RefCell<Vec<Vec<String>>> = const { RefCell::new(Vec::new()) }; }

    fn ok(_: &str, a: &[String]) -> Result<String> {
        CALLS.with(|c| c.borrow_mut().push(a.to_vec()));
        Ok(String::new())
    }
    fn fail_once(_: &str, a: &[String]) -> Result<String> {
        let n = CALLS.with(|c| {
            c.borrow_mut().push(a.to_vec());
            c.borrow().len()
        });
        if n == 1 {
            bail!("No such process")
        } else {
            Ok(String::new())
        }
    }
    fn alive_10(tgid: u32, _: u64) -> bool {
        tgid == 10
    }
    fn k(tgid: u32) -> ProcKey {
        ProcKey {
            tgid,
            start_time_ns: 1,
        }
    }
    fn take() -> Vec<Vec<String>> {
        CALLS.with(|c| c.take())
    }
    const HEAD: [&str; 8] = [
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StartTransientUnit",
        "ssa(sv)a(sa(sv))",
        "aegis-incident-AEG-x-q.scope",
        "fail",
    ];

    #[test]
    fn start_scope_builds_busctl_argv() {
        take();
        Systemd::with(ok, alive_10)
            .start_scope(
                "aegis-incident-AEG-x-q.scope",
                "aegis-quarantine.slice",
                &[k(10), k(11)],
                None,
            )
            .unwrap();
        let mut want: Vec<&str> = HEAD.to_vec();
        want.extend([
            "3",
            "PIDs",
            "au",
            "2",
            "10",
            "11",
            "Slice",
            "s",
            "aegis-quarantine.slice",
            "Description",
            "s",
            "Aegis incident AEG-x-q",
            "0",
        ]);
        assert_eq!(take(), vec![want]);
    }

    #[test]
    fn start_scope_encodes_limits() {
        take();
        let l = Limits {
            cpu_quota_percent: 25,
            memory_high_bytes: 268435456,
        };
        Systemd::with(ok, alive_10)
            .start_scope("aegis-incident-AEG-x-q.scope", "s.slice", &[k(10)], Some(l))
            .unwrap();
        let c = take();
        let j = c[0].join(" ");
        assert!(
            j.contains("CPUQuotaPerSecUSec t 250000 MemoryHigh t 268435456"),
            "{j}"
        );
        assert_eq!(c[0][8], "5");
    }

    #[test]
    fn scope_start_retries_without_dead_pids() {
        take();
        Systemd::with(fail_once, alive_10)
            .start_scope(
                "aegis-incident-AEG-x-q.scope",
                "s.slice",
                &[k(10), k(11)],
                None,
            )
            .unwrap();
        let c = take();
        assert_eq!(c.len(), 2);
        assert_eq!(&c[1][10..13], ["au", "1", "10"]);
    }

    #[test]
    fn scope_start_errors_when_all_pids_dead() {
        take();
        let e = Systemd::with(fail_once, alive_10)
            .start_scope("n.scope", "s.slice", &[k(11)], None)
            .unwrap_err();
        assert!(format!("{e:#}").contains("already exited"));
        assert_eq!(take().len(), 1);
    }
}
