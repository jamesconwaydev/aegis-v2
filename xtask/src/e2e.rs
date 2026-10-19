// SPDX-License-Identifier: MIT OR Apache-2.0
//! `cargo xtask e2e`: build the RPMs and the test simulator for a host's
//! architecture, install them cleanly, run every scenario in
//! tests/e2e/scenarios.toml, and assert what aegisd recorded.
//!
//! Each scenario is judged alone: incidents are cleared between them. The
//! harness also checks that no SELinux denial mentioning aegis was
//! raised and that /etc is byte-for-byte unchanged, since v0.1 only
//! audits and must never touch the host.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use serde::Deserialize;

use crate::{engine, in_container, root, rpm::rpm, Arch};

#[derive(clap::Args)]
pub struct Args {
    /// SSH destination, e.g. root@198.211.115.158 or james@127.0.0.1.
    #[arg(long)]
    host: String,
    /// SSH identity file.
    #[arg(long)]
    key: Option<PathBuf>,
    /// SSH client config file, for a Lima VM:
    /// `limactl show-ssh --format=config aegis-rocky10 > cfg`.
    #[arg(long)]
    ssh_config: Option<PathBuf>,
    /// Port, when neither --host nor --ssh-config carries it.
    #[arg(long)]
    port: Option<u16>,
    /// Run every remote command through sudo (a non-root login user, as
    /// on a Lima VM).
    #[arg(long)]
    sudo: bool,
    /// Leave the aegis packages and prerequisites installed afterwards.
    #[arg(long)]
    keep: bool,
    /// Run on a host without the /etc/aegis-e2e-host marker file. The
    /// run reinstalls aegis-v2, deletes /var/lib/aegis-v2, installs and
    /// removes packages and flips SELinux to enforcing: never point it
    /// at a machine you care about.
    #[arg(long)]
    yes_wipe: bool,
}

/// A host that says it is a disposable test machine.
const MARKER: &str = "/etc/aegis-e2e-host";

#[derive(Deserialize)]
struct Scenarios {
    scenario: Vec<Scenario>,
}

#[derive(Deserialize)]
struct Scenario {
    name: String,
    run: String,
    expect: String,
}

/// An SSH connection to the host. Every command is a fresh connection
/// (no multiplexing), so a scenario that runs `true` still exercises a
/// full login.
struct Remote {
    opts: Vec<String>,
    host: String,
    sudo: bool,
}

impl Remote {
    fn new(a: &Args) -> Self {
        let mut opts = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ControlMaster=no".into(),
            "-o".into(),
            "ControlPath=none".into(),
            "-o".into(),
            "ConnectTimeout=20".into(),
        ];
        if let Some(k) = &a.key {
            opts.push("-i".into());
            opts.push(k.display().to_string());
        }
        if let Some(c) = &a.ssh_config {
            opts.push("-F".into());
            opts.push(c.display().to_string());
        }
        if let Some(p) = a.port {
            opts.push("-p".into());
            opts.push(p.to_string());
        }
        Self {
            opts,
            host: a.host.clone(),
            sudo: a.sudo,
        }
    }

    fn ssh(&self) -> Command {
        let mut c = Command::new("ssh");
        c.args(&self.opts).arg("--").arg(&self.host);
        c
    }

    /// The command line sent to the remote login shell, under sudo when
    /// the login user isn't root.
    fn wrap(&self, cmd: &str) -> String {
        if self.sudo {
            format!("sudo -n bash -c {}", shq(cmd))
        } else {
            cmd.to_string()
        }
    }

    /// Run a command; return (success, stdout, stderr). Never errors on a
    /// non-zero exit.
    fn try_run(&self, cmd: &str) -> Result<(bool, String, String)> {
        let out = self
            .ssh()
            .arg(self.wrap(cmd))
            .output()
            .with_context(|| format!("ssh {cmd}"))?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    /// Run a command, returning its stdout; error on a non-zero exit.
    fn check(&self, cmd: &str) -> Result<String> {
        let (ok, out, err) = self.try_run(cmd)?;
        if !ok {
            bail!("remote `{cmd}` failed: {}", err.trim());
        }
        Ok(out)
    }

    /// Stream a local file to a remote path (as the login user, into a
    /// world-writable dir), then set its mode.
    fn upload(&self, local: &Path, remote_path: &str, mode: &str) -> Result<()> {
        let f = File::open(local).with_context(|| format!("opening {}", local.display()))?;
        let status = self
            .ssh()
            .arg(format!("cat > {}", shq(remote_path)))
            .stdin(Stdio::from(f))
            .status()
            .context("ssh upload")?;
        if !status.success() {
            bail!("uploading {} failed", local.display());
        }
        self.check(&format!("chmod {mode} {}", shq(remote_path)))?;
        Ok(())
    }
}

/// Single-quote a string for a POSIX shell.
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn shq_all(v: &[String]) -> String {
    v.iter().map(|s| shq(s)).collect::<Vec<_>>().join(" ")
}

/// What `aegisctl incidents list --json` holds, as the table shows it:
/// "none", the single incident's verdict, or "N incidents: v1,v2".
fn summarize(json: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(json).context("incidents list --json")?;
    let arr = v.as_array().context("expected a JSON array")?;
    let verdicts: Vec<&str> = arr
        .iter()
        .map(|i| i["verdict"].as_str().unwrap_or("?"))
        .collect();
    Ok(match verdicts.as_slice() {
        [] => "none".into(),
        [one] => (*one).into(),
        many => format!("{} incidents: {}", many.len(), many.join(",")),
    })
}

/// True if SELinux logged a denial mentioning aegis since `marker`
/// (`date '+%x %T'` on the host). Fails closed: an ssh failure, a
/// missing ausearch or any ausearch failure other than "no matches" is
/// an error, never a clean result.
fn avc_since(remote: &Remote, marker: &str) -> Result<bool> {
    let (ok, out, err) = remote.try_run(&format!(
        "command -v ausearch >/dev/null || {{ echo 'ausearch not found' >&2; exit 2; }}; \
         ausearch -m AVC,USER_AVC,SELINUX_ERR -ts {marker}"
    ))?;
    judge_ausearch(ok, &out, &err)
}

/// ausearch exits 1 both for "no matches" and for real failures (a bad
/// time, an unreadable log), so only its own `<no matches>` line makes a
/// non-zero exit clean.
fn judge_ausearch(ok: bool, out: &str, err: &str) -> Result<bool> {
    if ok {
        return Ok(out.to_lowercase().contains("aegis"));
    }
    if err.lines().any(|l| l.trim() == "<no matches>") {
        return Ok(false);
    }
    bail!("ausearch failed: {}", err.trim())
}

fn marker(remote: &Remote) -> Result<String> {
    Ok(remote.check("date '+%x %T'")?.trim().to_string())
}

const SHA_ETC: &str = "find /etc -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum";
const PREREQS: [&str; 4] = ["gdb", "podman", "python3-pip", "strace"];
const INCIDENTS: &str = "/var/lib/aegis-v2/incidents";
/// How long "no incident" must hold before it counts: past aegisd's 6 s
/// verification hold, so a signal still waiting on a verdict is scored.
const SETTLE: Duration = Duration::from_secs(8);
/// How long to wait for an expected incident to appear.
const DEADLINE: Duration = Duration::from_secs(15);

struct Row {
    name: String,
    expect: String,
    got: String,
    avc: bool,
    etc_ok: bool,
    ran: bool,
    pass: bool,
}

pub fn run(args: Args) -> Result<()> {
    let remote = Remote::new(&args);
    check_disposable(&remote, args.yes_wipe)?;

    // Which architecture the host wants, and build for it (never on the host).
    let machine = remote.check("uname -m")?.trim().to_string();
    let arch = match machine.as_str() {
        "x86_64" => Arch::X86_64,
        "aarch64" | "arm64" => Arch::Aarch64,
        other => bail!("unsupported host arch {other}"),
    };
    println!("host {} is {arch}; building", args.host);
    let engine = engine(arch)?;
    rpm(&engine, arch)?; // builds release binaries into dist/<arch>/ too
    build_sim(&engine, arch)?;

    // The RPMs for this arch and version (plus the noarch SELinux module).
    let rpms = rpms_for(&root().join("dist/rpm"), arch)?;
    let remote_rpms: Vec<String> = rpms
        .iter()
        .map(|r| format!("/tmp/{}", r.file_name().unwrap().to_string_lossy()))
        .collect();

    // Read-only facts cleanup needs; every change to the host happens
    // inside the closure, so a failure part-way still cleans up.
    let orig_enforce = remote.check("getenforce")?.trim().to_string();
    // Record which prerequisites we add, so cleanup removes only those
    // (an unanswered query counts as present: never remove what we
    // didn't add).
    let added: Vec<&str> = PREREQS
        .iter()
        .copied()
        .filter(|p| {
            !remote
                .try_run(&format!("rpm -q {p}"))
                .map(|r| r.0)
                .unwrap_or(true)
        })
        .collect();

    let result = (|| -> Result<(Vec<Row>, bool)> {
        for (r, dest) in rpms.iter().zip(&remote_rpms) {
            remote.upload(r, dest, "0644")?;
        }
        // /tmp/aegis-sim carries the temp-dir exec signal for the
        // scenarios that want it; /usr/local/bin/aegis-sim for the ones
        // that don't.
        remote.upload(
            &root().join(format!("dist/{arch}/aegis-sim")),
            "/tmp/aegis-sim",
            "0755",
        )?;
        remote.check("install -m 0755 /tmp/aegis-sim /usr/local/bin/aegis-sim")?;
        // Enforcing for the run; Lima boots permissive.
        if orig_enforce == "Permissive" {
            remote.check("setenforce 1")?;
        }

        // Covers the whole run, installs included.
        let run_marker = marker(&remote)?;
        remote.check(&format!("dnf -y install {}", PREREQS.join(" ")))?;
        remote.try_run("dnf -y remove aegis-v2 aegis-v2-selinux")?;
        remote.check(&format!("dnf -y install {}", shq_all(&remote_rpms)))?;
        remote.check("systemctl enable --now aegisd")?;

        let scenarios = load_scenarios()?;
        let mut rows = Vec::new();
        for s in &scenarios {
            rows.push(run_scenario(&remote, s)?);
        }
        let run_avc = avc_since(&remote, &run_marker)?;
        Ok((rows, run_avc))
    })();

    // Always clean up, whatever happened above.
    cleanup(&remote, &remote_rpms, &added, &orig_enforce, args.keep);

    let (rows, run_avc) = result?;
    print_table(&rows);
    println!(
        "whole-run AVC check: {}",
        if run_avc {
            "DENY (see ausearch on the host)"
        } else {
            "ok"
        }
    );
    if run_avc || rows.iter().any(|r| !r.pass) {
        bail!("one or more scenarios failed");
    }
    println!("\nall scenarios passed");
    Ok(())
}

/// Refuses a host that hasn't been marked as a test machine, unless the
/// caller said `--yes-wipe`.
fn check_disposable(remote: &Remote, yes_wipe: bool) -> Result<()> {
    if yes_wipe {
        return Ok(());
    }
    let (marked, _, _) = remote.try_run(&format!("test -f {MARKER}"))?;
    if !marked {
        bail!(
            "{host} has no {MARKER}, so it isn't marked as a disposable test host.\n\
             The e2e run reinstalls aegis-v2, deletes /var/lib/aegis-v2, installs \
             and removes packages and sets SELinux enforcing.\n\
             If that's fine, mark the host (ssh {host} touch {MARKER}) or pass --yes-wipe.",
            host = remote.host
        );
    }
    Ok(())
}

fn build_sim(engine: &str, arch: Arch) -> Result<()> {
    in_container(
        engine,
        arch,
        &format!(
            "cargo build --locked -p aegis-sim --release \
             && cp /target/release/aegis-sim dist/{arch}/"
        ),
    )?;
    println!("built dist/{arch}/aegis-sim");
    Ok(())
}

/// This version's RPMs for `arch`, plus the noarch ones; stale builds of
/// other versions in the same dir are left out.
fn rpms_for(dir: &Path, arch: Arch) -> Result<Vec<PathBuf>> {
    let want_arch = format!(".{arch}.rpm");
    let want_ver = format!("-{}-", env!("CARGO_PKG_VERSION"));
    let mut out = Vec::new();
    for ent in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let p = ent?.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.contains(&want_ver) && (name.ends_with(&want_arch) || name.ends_with(".noarch.rpm"))
        {
            out.push(p);
        }
    }
    if out.is_empty() {
        bail!("no RPMs for {arch} in {}", dir.display());
    }
    Ok(out)
}

fn load_scenarios() -> Result<Vec<Scenario>> {
    let path = root().join("tests/e2e/scenarios.toml");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let s: Scenarios = toml::from_str(&text).context("parsing scenarios.toml")?;
    for sc in &s.scenario {
        if !matches!(
            sc.expect.as_str(),
            "none" | "would_throttle" | "would_quarantine"
        ) {
            bail!("scenario {}: bad expect `{}`", sc.name, sc.expect);
        }
    }
    Ok(s.scenario)
}

fn run_scenario(remote: &Remote, s: &Scenario) -> Result<Row> {
    // Clear incidents and restart so this scenario is judged alone.
    remote.check("systemctl stop aegisd")?;
    remote.check(&format!("rm -rf {INCIDENTS}"))?;
    remote.check("systemctl start aegisd")?;

    let etc_before = remote.check(SHA_ETC)?;
    let marker = marker(remote)?;

    // Run the scenario itself. A command that fails fails the scenario.
    let (ran, _out, err) = remote.try_run(&s.run)?;
    if !ran {
        eprintln!("  {}: command exited non-zero: {}", s.name, err.trim());
    }

    // Poll until the expected result shows up or the deadline passes.
    // An absence can't be seen early, so "none" is only taken once the
    // settle time (probe drain plus the verification hold) is up.
    let start = Instant::now();
    let got = loop {
        let got = summarize(&remote.check("aegisctl incidents list --json")?)?;
        let settled = start.elapsed() >= SETTLE;
        if (got == s.expect && (s.expect != "none" || settled)) || start.elapsed() >= DEADLINE {
            break got;
        }
        std::thread::sleep(Duration::from_millis(500));
    };

    let avc = avc_since(remote, &marker).unwrap_or_else(|e| {
        eprintln!(
            "  {}: AVC check failed, counting it as a denial: {e:#}",
            s.name
        );
        true
    });

    let etc_after = remote.check(SHA_ETC)?;
    let etc_ok = etc_before == etc_after;

    let verdict_ok = got == s.expect;
    let pass = ran && verdict_ok && !avc && etc_ok;

    Ok(Row {
        name: s.name.clone(),
        expect: s.expect.clone(),
        got,
        avc,
        etc_ok,
        ran,
        pass,
    })
}

fn cleanup(
    remote: &Remote,
    remote_rpms: &[String],
    added: &[&str],
    orig_enforce: &str,
    keep: bool,
) {
    if !keep {
        let _ = remote.try_run("systemctl stop aegisd");
        let _ = remote.try_run("dnf -y remove aegis-v2 aegis-v2-selinux");
        // Runtime-created state rpm doesn't own, so erase leaves it behind.
        let _ = remote.try_run("rm -rf /var/lib/aegis-v2");
        if !added.is_empty() {
            let _ = remote.try_run(&format!("dnf -y remove {}", added.join(" ")));
        }
        let _ = remote.try_run(&format!(
            "rm -f /tmp/aegis-sim /usr/local/bin/aegis-sim /tmp/aegis-sim-dropped.* \
             /tmp/aegis-strace.* {}",
            shq_all(remote_rpms)
        ));
    }
    if orig_enforce == "Permissive" {
        let _ = remote.try_run("setenforce 0");
    }
}

fn print_table(rows: &[Row]) {
    println!(
        "\n{:<16} {:<17} {:<17} {:<5} {:<5} {:<4} result",
        "scenario", "expect", "got", "avc", "etc", "ran"
    );
    for r in rows {
        println!(
            "{:<16} {:<17} {:<17} {:<5} {:<5} {:<4} {}",
            r.name,
            r.expect,
            r.got,
            if r.avc { "DENY" } else { "ok" },
            if r.etc_ok { "ok" } else { "CHG" },
            if r.ran { "ok" } else { "err" },
            if r.pass { "PASS" } else { "FAIL" },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ausearch_outcomes() {
        assert!(!judge_ausearch(false, "", "<no matches>\n").unwrap());
        assert!(judge_ausearch(true, "type=AVC ... comm=\"aegisd\"", "").unwrap());
        assert!(!judge_ausearch(true, "type=AVC ... comm=\"sshd\"", "").unwrap());
        // Any other failure fails the check rather than reading clean.
        assert!(judge_ausearch(false, "", "Invalid start time\n").is_err());
        assert!(judge_ausearch(false, "", "ausearch not found\n").is_err());
        assert!(judge_ausearch(false, "", "").is_err());
    }
}
