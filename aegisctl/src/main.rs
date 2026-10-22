// SPDX-License-Identifier: MIT OR Apache-2.0
//! `aegisctl`: ask a running aegisd what it's seen, and check a host
//! before you install it.

mod preflight;
mod render;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use aegis_proto::{Request, Response};
use clap::{Parser, Subcommand};
use serde_json::Value;

#[derive(Parser)]
#[command(version, about = "Talk to aegisd and check a host for it.")]
struct Cli {
    /// aegisd's control socket.
    #[arg(long, global = true, default_value = aegis_proto::SOCKET)]
    socket: PathBuf,
    /// Print JSON instead of a table.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the daemon's mode, probes and counters.
    Status,
    /// Look at incidents.
    #[command(subcommand)]
    Incidents(Inc),
    /// Check this host can run aegisd. Works before it's installed.
    /// Exits 0 if all pass, 1 on any FAIL, 2 if there are only warnings.
    Preflight,
}

#[derive(Subcommand)]
enum Inc {
    /// List every incident.
    List,
    /// Show one incident in full.
    Show { id: String },
    /// Show what happened in an incident, one line per decision.
    Timeline { id: String },
    /// Thaw a quarantined tree and restore its network, or lift a
    /// throttle's limits. From v0.2.0.
    Release { id: String },
    /// SIGKILL a quarantined tree. From v0.2.0.
    Kill { id: String },
}

const MAX_REPLY: usize = 16 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);

/// Read one line, at most MAX_REPLY bytes, within DEADLINE overall.
fn read_reply(s: &mut UnixStream) -> Result<Vec<u8>, String> {
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let left = DEADLINE
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or("no reply from aegisd within 30 s")?;
        s.set_read_timeout(Some(left.min(Duration::from_secs(10))))
            .map_err(|e| e.to_string())?;
        let n = match s.read(&mut chunk) {
            Ok(0) => return Err("aegisd closed the connection without a full reply".into()),
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) => return Err(format!("no reply from aegisd: {e}")),
        };
        if let Some(i) = chunk[..n].iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&chunk[..i]);
            return if buf.len() > MAX_REPLY {
                Err(too_big())
            } else {
                Ok(buf)
            };
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REPLY {
            return Err(too_big());
        }
    }
}

fn too_big() -> String {
    "aegisd's reply is over 16 MiB; refusing to read it".into()
}

/// Send one request, read one reply. Errors are ready to print.
fn call(socket: &Path, req: &Request) -> Result<Response, String> {
    let t = Some(Duration::from_secs(10));
    let mut s = UnixStream::connect(socket).map_err(|e| match e.kind() {
        ErrorKind::NotFound | ErrorKind::ConnectionRefused => format!(
            "aegisd is not running (no socket at {})",
            render::clean(&socket.display().to_string())
        ),
        ErrorKind::PermissionDenied => "aegisctl must run as root".into(),
        _ => format!(
            "can't connect to {}: {e}",
            render::clean(&socket.display().to_string())
        ),
    })?;
    s.set_write_timeout(t).map_err(|e| e.to_string())?;
    let mut line = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    line.push(b'\n');
    s.write_all(&line)
        .map_err(|e| format!("send failed: {e}"))?;
    let reply = read_reply(&mut s)?;
    match serde_json::from_slice(&reply)
        .map_err(|e| format!("unreadable reply from aegisd: {e}"))?
    {
        Response::Error(m) if m == "permission denied" => Err("aegisctl must run as root".into()),
        Response::Error(m) => Err(format!("aegisd: {}", render::clean(&m))),
        r => Ok(r),
    }
}

/// `{"Variant": payload}` to `payload`, for --json.
fn payload(r: &Response) -> Value {
    match serde_json::to_value(r) {
        Ok(Value::Object(m)) if m.len() == 1 => m.into_iter().next().unwrap().1,
        Ok(v) => v,
        Err(_) => Value::Null,
    }
}

/// What to print and the exit code.
fn run(cli: &Cli) -> Result<(String, u8), String> {
    let wrong = || "aegisd sent a reply this aegisctl doesn't understand".to_string();
    let pretty = |v: &Value| serde_json::to_string_pretty(v).unwrap() + "\n";
    let mut id = String::new();
    let req = match &cli.cmd {
        Cmd::Preflight => {
            let path: Vec<PathBuf> =
                std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
            let c = preflight::Preflight::run_with(Path::new("/"), &path, &cli.socket);
            let out = if cli.json {
                pretty(&Value::Array(c.iter().map(|c| c.to_json()).collect()))
            } else {
                render::preflight(&c, render::use_colour())
            };
            return Ok((out, preflight::exit_code(&c)));
        }
        Cmd::Status => Request::Status,
        Cmd::Incidents(Inc::List) => Request::IncidentsList,
        Cmd::Incidents(
            Inc::Show { id: i }
            | Inc::Timeline { id: i }
            | Inc::Release { id: i }
            | Inc::Kill { id: i },
        ) if !aegis_proto::is_incident_id(i) => {
            return Err(format!(
                "{i} is not an incident id (AEG-YYYYMMDD-HHMMSS- and 16 hex digits)"
            ));
        }
        Cmd::Incidents(Inc::Show { id }) => Request::IncidentShow { id: id.clone() },
        Cmd::Incidents(Inc::Release { id }) => Request::IncidentRelease { id: id.clone() },
        Cmd::Incidents(Inc::Kill { id }) => Request::IncidentKill { id: id.clone() },
        Cmd::Incidents(Inc::Timeline { id: i }) => {
            id = i.clone();
            Request::IncidentTimeline { id: i.clone() }
        }
    };
    let resp = call(&cli.socket, &req)?;
    let out = match (&resp, cli.json) {
        (Response::Done(m), true) => pretty(&serde_json::json!({ "done": m })),
        (Response::Done(m), false) => render::done(m),
        (Response::Timeline(lines), true) => pretty(&Value::Array(lines.clone())),
        (_, true) => pretty(&payload(&resp)),
        (Response::Status { .. }, false) => render::status(&resp).unwrap(),
        (Response::Incidents(l), false) => render::incidents(l),
        (Response::Incident(v), false) => render::incident(v, render::current_boot_id().as_deref()),
        (Response::Timeline(l), false) => {
            // Best effort: names come from the incident, lines print without them.
            let v = match call(&cli.socket, &Request::IncidentShow { id }) {
                Ok(Response::Incident(v)) => Some(v),
                _ => None,
            };
            render::timeline(l, v.as_ref())
        }
        (Response::Error(_), _) => return Err(wrong()),
    };
    Ok((out, 0))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok((out, code)) => {
            match std::io::stdout().lock().write_all(out.as_bytes()) {
                Err(e) if e.kind() != ErrorKind::BrokenPipe => {
                    eprintln!("aegisctl: write failed: {e}");
                    return ExitCode::from(1);
                }
                _ => {}
            }
            ExitCode::from(code)
        }
        Err(e) => {
            eprintln!("aegisctl: {}", render::clean(&e));
            ExitCode::from(1)
        }
    }
}
