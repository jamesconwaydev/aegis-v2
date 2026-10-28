// SPDX-License-Identifier: MIT OR Apache-2.0
//! `cargo xtask e2e`: build the RPMs and the test simulator for a host's
//! architecture, install them cleanly, run every scenario in
//! tests/e2e/scenarios.toml, and assert what aegisd recorded.
//!
//! Each scenario is judged alone: incidents are cleared between them. The
//! harness also checks that no SELinux denial mentioning aegis was
//! raised and that /etc is byte-for-byte unchanged: aegisd must never
//! touch it, in audit or enforce mode.
//!
//! An enforce-mode scenario switches the config to enforce before the
//! /etc hash is taken. Afterwards it releases or kills every incident
//! the scenario left, puts the config back, and sweeps away any scope,
//! nft table or process still standing, whether the scenario passed or
//! not.

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
    #[serde(default = "audit")]
    mode: String,
    /// Shell run under `set -e` once the verdict settles; must exit 0.
    check: Option<String>,
}

fn audit() -> String {
    "audit".into()
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
///
/// Without a terminal ausearch reads stdin, not the audit log, and
/// answers `<no matches>` to everything; `--input-logs` stops that. As
/// a guard against any other way it could read nothing, it must first
/// find some event since the marker: every ssh login in between writes
/// several, so an empty answer there means the log isn't being read.
fn avc_since(remote: &Remote, marker: &str) -> Result<bool> {
    let (ok, out, err) = remote.try_run(&format!(
        "command -v ausearch >/dev/null || {{ echo 'ausearch not found' >&2; exit 2; }}; \
         ausearch --input-logs -ts {marker} </dev/null >/dev/null 2>&1 \
           || {{ echo 'ausearch saw no events at all since the marker' >&2; exit 2; }}; \
         ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts {marker} </dev/null"
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

const CONFIG: &str = "/etc/aegis-v2/config.toml";
/// The installed config, kept so an enforce scenario can put it back.
const CONFIG_ORIG: &str = "/var/tmp/aegis-e2e-config.toml";
/// What an enforce scenario may leave behind, removed after each one
/// and again at the end: incident scopes (killed first, since a frozen
/// one would sit out the stop timeout), the scenarios' ptrace target,
/// aegisd's nft table, the simulator's pid file and the strace copies.
const SWEEP: &str = "systemctl kill -s KILL 'aegis-incident-*' 2>/dev/null; \
     systemctl stop 'aegis-incident-*' 2>/dev/null; \
     systemctl stop aegis-e2e-target 2>/dev/null; \
     systemctl reset-failed 'aegis-incident-*' aegis-e2e-target 2>/dev/null; \
     nft delete table inet aegis 2>/dev/null; \
     rm -f /run/aegis-sim.pid /tmp/aegis-strace.*; true";
/// Exits non-zero if the sweep left anything.
const SWEPT: &str = "! systemctl list-units --all --no-legend 'aegis-incident-*' \
     aegis-e2e-target.service | grep -q . && ! nft list table inet aegis >/dev/null 2>&1";
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
    /// The scenario's check passed (true when it has none).
    check_ok: bool,
    /// Enforce mode only: every incident left was released or killed,
    /// and the config and host were put back.
    ended: bool,
    /// Enforce mode only: no incident recorded a failed action.
    acts_ok: bool,
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
        remote.check(&format!("cp -p {CONFIG} {CONFIG_ORIG}"))?;

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
            "none" | "would_throttle" | "would_quarantine" | "throttled" | "quarantined"
        ) {
            bail!("scenario {}: bad expect `{}`", sc.name, sc.expect);
        }
        if !matches!(sc.mode.as_str(), "audit" | "enforce") {
            bail!("scenario {}: bad mode `{}`", sc.name, sc.mode);
        }
    }
    Ok(s.scenario)
}

fn run_scenario(remote: &Remote, s: &Scenario) -> Result<Row> {
    // Clear incidents and restart so this scenario is judged alone.
    remote.check("systemctl stop aegisd")?;
    remote.check(&format!("rm -rf {INCIDENTS}"))?;
    remote.check("systemctl start aegisd")?;

    if s.mode != "enforce" {
        return judge(remote, s);
    }
    // A run killed part-way may have left a target or scope behind.
    let _ = remote.try_run(SWEEP);
    // Whatever happens in the scenario, the host is put back after it.
    let row = set_mode(remote, "enforce").and_then(|()| judge(remote, s));
    let ended = end_enforce(remote).map_err(|e| eprintln!("  {}: ending: {e:#}", s.name));
    let mut row = row?;
    row.ended = ended.is_ok();
    // Read after the ending, so a failed release or kill counts too.
    // Fails closed: anything that can't be read is a failure.
    row.acts_ok = match remote
        .check(&format!(
            "for f in {INCIDENTS}/*/incident.json; do [ -e \"$f\" ] || continue; \
             cat \"$f\" || exit 1; done"
        ))
        .and_then(|t| failed_actions(&t))
    {
        Ok(f) if f.is_empty() => true,
        Ok(f) => {
            for a in f {
                eprintln!("  {}: failed action: {a}", s.name);
            }
            false
        }
        Err(e) => {
            eprintln!("  {}: reading the actions: {e:#}", s.name);
            false
        }
    };
    row.pass &= row.ended && row.acts_ok;
    Ok(row)
}

/// Each failed action in `text`, one or more `incident.json` documents
/// back to back. Enforce mode records every step it takes, and a step
/// that failed means the scenario didn't do what its verdict says, even
/// when the check's own pids look right.
fn failed_actions(text: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for inc in serde_json::Deserializer::from_str(text).into_iter::<serde_json::Value>() {
        let inc = inc.context("incident.json")?;
        let acts = inc["actions"]
            .as_array()
            .with_context(|| format!("{}: no actions array", inc["id"]))?;
        for a in acts {
            if a["ok"] != true {
                out.push(format!(
                    "{} {}: {}",
                    inc["id"].as_str().unwrap_or("?"),
                    a["kind"].as_str().unwrap_or("?"),
                    a["error"].as_str().unwrap_or("")
                ));
            }
        }
    }
    Ok(out)
}

fn judge(remote: &Remote, s: &Scenario) -> Result<Row> {
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

    // Straight after the verdict: a scenario's process stays only so long.
    let check_ok = match &s.check {
        None => true,
        Some(c) => {
            let (ok, out, err) = remote.try_run(&format!("set -e\n{c}"))?;
            if !ok {
                eprintln!("  {}: check failed: {} {}", s.name, out.trim(), err.trim());
            }
            ok
        }
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
    let pass = ran && verdict_ok && check_ok && !avc && etc_ok;

    Ok(Row {
        name: s.name.clone(),
        expect: s.expect.clone(),
        got,
        avc,
        etc_ok,
        ran,
        check_ok,
        ended: true,
        acts_ok: true,
        pass,
    })
}

/// Writes the installed config with `mode` swapped in, reloads, and
/// waits for aegisd to report the mode. The file is rewritten in place,
/// so it keeps its SELinux label.
fn set_mode(remote: &Remote, mode: &str) -> Result<()> {
    remote.check(&format!(
        "sed 's/^mode = .*/mode = \"{mode}\"/' {CONFIG_ORIG} > {CONFIG} \
         && grep -qx 'mode = \"{mode}\"' {CONFIG} && systemctl reload aegisd"
    ))?;
    wait_mode(remote, mode)
}

fn wait_mode(remote: &Remote, mode: &str) -> Result<()> {
    let start = Instant::now();
    loop {
        let st = remote.check("aegisctl status")?;
        if st
            .lines()
            .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["mode", mode])
        {
            return Ok(());
        }
        if start.elapsed() >= DEADLINE {
            bail!("aegisd never reported mode {mode} after the reload");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// After an enforce scenario: release or kill every incident still
/// enforced, put the config back, then sweep. Each step runs even if
/// an earlier one failed; any failure is returned.
fn end_enforce(remote: &Remote) -> Result<()> {
    let mut errs = Vec::new();
    match remote
        .check("aegisctl incidents list --json")
        .and_then(|j| enforced(&j))
    {
        Ok(left) => {
            for (id, verb) in &left {
                match remote.try_run(&format!("aegisctl incidents {verb} {id}")) {
                    Ok((false, out, err)) => {
                        errs.push(format!("{verb} {id}: {} {}", out.trim(), err.trim()))
                    }
                    Ok(_) => {}
                    Err(e) => errs.push(format!("{verb} {id}: {e:#}")),
                }
            }
            // A STATE that was wrong would let the sweep hide it.
            let ids: Vec<String> = left.into_iter().map(|(id, _)| id).collect();
            if let Err(e) = remote
                .check("aegisctl incidents list --json")
                .and_then(|j| all_ended(&j, &ids))
            {
                errs.push(format!("after ending: {e:#}"));
            }
        }
        Err(e) => errs.push(format!("listing incidents: {e:#}")),
    }
    if let Err(e) = remote
        .check(&format!(
            "cat {CONFIG_ORIG} > {CONFIG} && systemctl reload aegisd"
        ))
        .and_then(|_| wait_mode(remote, "audit"))
    {
        errs.push(format!("restoring the config: {e:#}"));
    }
    let _ = remote.try_run(SWEEP);
    if !remote.try_run(SWEPT).is_ok_and(|r| r.0) {
        errs.push("the sweep left a scope, the target or the nft table".into());
    }
    if errs.is_empty() {
        Ok(())
    } else {
        bail!("{}", errs.join("; "))
    }
}

/// Each incident aegisd still throttles or quarantines, with the command
/// that ends it: a quarantine is killed, a throttle released. One the
/// scenario ended itself (release-enforce, say) is left alone. Any
/// other state on a throttled or quarantined verdict, or none, is an
/// error: skipping it would let the sweep hide it.
fn enforced(json: &str) -> Result<Vec<(String, &'static str)>> {
    let v: serde_json::Value = serde_json::from_str(json).context("incidents list --json")?;
    let mut out = Vec::new();
    for i in v.as_array().context("expected a JSON array")? {
        let id = i["id"].as_str().context("incident without an id")?;
        if !matches!(i["verdict"].as_str(), Some("quarantined" | "throttled")) {
            continue;
        }
        let verb = match i["state"].as_str() {
            Some("quarantined") => "kill",
            Some("throttled") => "release",
            Some("released" | "killed") => continue,
            Some(s) => bail!("{id}: an enforced verdict with state {s}"),
            None => bail!("{id}: incidents list --json has no state"),
        };
        out.push((id.to_string(), verb));
    }
    Ok(out)
}

/// Fails unless every incident in `ids` now reads killed or released.
fn all_ended(json: &str, ids: &[String]) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(json).context("incidents list --json")?;
    let list = v.as_array().context("expected a JSON array")?;
    let bad: Vec<String> = ids
        .iter()
        .filter_map(|id| {
            let state = list
                .iter()
                .find(|i| i["id"] == id.as_str())
                .and_then(|i| i["state"].as_str());
            (!matches!(state, Some("killed" | "released")))
                .then(|| format!("{id} is {}", state.unwrap_or("missing")))
        })
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        bail!("not ended: {}", bad.join(", "))
    }
}

fn cleanup(
    remote: &Remote,
    remote_rpms: &[String],
    added: &[&str],
    orig_enforce: &str,
    keep: bool,
) {
    // In case a run stopped part-way through an enforce scenario.
    let _ = remote.try_run(&format!(
        "if [ -f {CONFIG_ORIG} ]; then cat {CONFIG_ORIG} > {CONFIG}; \
         systemctl reload aegisd; rm -f {CONFIG_ORIG}; fi"
    ));
    let _ = remote.try_run(SWEEP);
    if !keep {
        let _ = remote.try_run("systemctl stop aegisd");
        let _ = remote.try_run("dnf -y remove aegis-v2 aegis-v2-selinux");
        // The slices enforce mode created outlive the package, and
        // systemd still has the removed unit loaded.
        let _ = remote.try_run("systemctl stop aegis.slice; systemctl daemon-reload");
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
        "\n{:<26} {:<17} {:<17} {:<5} {:<5} {:<4} {:<5} {:<5} {:<5} result",
        "scenario", "expect", "got", "avc", "etc", "ran", "check", "end", "acts"
    );
    for r in rows {
        println!(
            "{:<26} {:<17} {:<17} {:<5} {:<5} {:<4} {:<5} {:<5} {:<5} {}",
            r.name,
            r.expect,
            r.got,
            if r.avc { "DENY" } else { "ok" },
            if r.etc_ok { "ok" } else { "CHG" },
            if r.ran { "ok" } else { "err" },
            if r.check_ok { "ok" } else { "FAIL" },
            if r.ended { "ok" } else { "FAIL" },
            if r.acts_ok { "ok" } else { "FAIL" },
            if r.pass { "PASS" } else { "FAIL" },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenarios_file_parses() {
        let s = load_scenarios().unwrap();
        assert!(s.iter().any(|s| s.mode == "enforce" && s.check.is_some()));
    }

    #[test]
    fn enforced_incidents_and_how_they_end() {
        let j = r#"[{"id":"AEG-1","verdict":"quarantined","state":"quarantined"},
                   {"id":"AEG-2","verdict":"throttled","state":"throttled"},
                   {"id":"AEG-3","verdict":"would_quarantine","state":"held"},
                   {"id":"AEG-4","verdict":"quarantined","state":"released"},
                   {"id":"AEG-5","verdict":"quarantined","state":"killed"},
                   {"id":"AEG-6","verdict":"would_quarantine","state":"expired"},
                   {"id":"AEG-7","verdict":"would_throttle","state":null}]"#;
        assert_eq!(
            enforced(j).unwrap(),
            [("AEG-1".into(), "kill"), ("AEG-2".into(), "release")]
        );
        assert!(enforced("{}").is_err());
        // An enforced verdict without a state: an older or broken daemon.
        assert!(enforced(r#"[{"id":"AEG-1","verdict":"quarantined"}]"#).is_err());
        assert!(enforced(r#"[{"id":"AEG-1","verdict":"throttled","state":null}]"#).is_err());
        // A state that can't follow an enforced verdict fails closed.
        for st in ["held", "expired", "bogus"] {
            let j = format!(r#"[{{"id":"AEG-1","verdict":"quarantined","state":"{st}"}}]"#);
            assert!(enforced(&j).is_err(), "{st}");
        }
    }

    #[test]
    fn ended_incidents_must_read_killed_or_released() {
        let ids = ["AEG-1".to_string(), "AEG-2".to_string()];
        let j = r#"[{"id":"AEG-1","state":"killed"},{"id":"AEG-2","state":"released"}]"#;
        assert!(all_ended(j, &ids).is_ok());
        let j = r#"[{"id":"AEG-1","state":"killed"},{"id":"AEG-2","state":"throttled"}]"#;
        let e = all_ended(j, &ids).unwrap_err().to_string();
        assert!(e.contains("AEG-2 is throttled"), "{e}");
        assert!(all_ended(r#"[{"id":"AEG-1","state":"killed"}]"#, &ids).is_err());
    }

    #[test]
    fn any_failed_action_fails_the_scenario() {
        let ok = r#"{"id":"AEG-1","actions":[{"kind":"scope","ok":true}]}"#;
        let bad = r#"{"id":"AEG-2","actions":[{"kind":"attach","ok":false,
            "error":"Process migration not available on non-delegated units."}]}"#;
        assert!(failed_actions(ok).unwrap().is_empty());
        assert!(failed_actions("").unwrap().is_empty());
        let f = failed_actions(&format!("{ok}\n{bad}")).unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].starts_with("AEG-2 attach: Process migration"), "{f:?}");
        assert!(failed_actions("{").is_err());
        assert!(failed_actions(r#"{"id":"AEG-3"}"#).is_err());
    }

    #[test]
    fn ausearch_outcomes() {
        assert!(!judge_ausearch(false, "", "<no matches>\n").unwrap());
        assert!(judge_ausearch(true, "type=AVC ... comm=\"aegisd\"", "").unwrap());
        assert!(!judge_ausearch(true, "type=AVC ... comm=\"sshd\"", "").unwrap());
        // Any other failure fails the check rather than reading clean.
        assert!(judge_ausearch(false, "", "Invalid start time\n").is_err());
        assert!(judge_ausearch(false, "", "ausearch not found\n").is_err());
        assert!(judge_ausearch(
            false,
            "",
            "ausearch saw no events at all since the marker\n"
        )
        .is_err());
        assert!(judge_ausearch(false, "", "").is_err());
    }
}
