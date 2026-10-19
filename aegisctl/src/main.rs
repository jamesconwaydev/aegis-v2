// SPDX-License-Identifier: MIT OR Apache-2.0
//! `aegisctl`: ask a running aegisd what it's seen, and check a host
//! before you install it.

mod preflight;
mod render;

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

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
}

/// Send one request, read one reply. Errors are ready to print.
fn call(socket: &Path, req: &Request) -> Result<Response, String> {
    let t = Some(Duration::from_secs(10));
    let mut s = UnixStream::connect(socket).map_err(|e| match e.kind() {
        ErrorKind::NotFound | ErrorKind::ConnectionRefused => {
            format!("aegisd is not running (no socket at {})", socket.display())
        }
        ErrorKind::PermissionDenied => "aegisctl must run as root".into(),
        _ => format!("can't connect to {}: {e}", socket.display()),
    })?;
    s.set_read_timeout(t)
        .and_then(|_| s.set_write_timeout(t))
        .map_err(|e| e.to_string())?;
    let mut line = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    line.push(b'\n');
    s.write_all(&line)
        .map_err(|e| format!("send failed: {e}"))?;
    let mut reply = String::new();
    BufReader::new(s)
        .read_line(&mut reply)
        .map_err(|e| format!("no reply from aegisd: {e}"))?;
    match serde_json::from_str(&reply).map_err(|e| format!("unreadable reply from aegisd: {e}"))? {
        Response::Error(m) if m == "permission denied" => Err("aegisctl must run as root".into()),
        Response::Error(m) => Err(format!("aegisd: {m}")),
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

fn run(cli: &Cli) -> Result<u8, String> {
    let wrong = || "aegisd sent a reply this aegisctl doesn't understand".to_string();
    let req = match &cli.cmd {
        Cmd::Preflight => {
            let path: Vec<PathBuf> =
                std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
            let c = preflight::Preflight::run_with(Path::new("/"), &path, &cli.socket);
            if cli.json {
                let v: Vec<Value> = c.iter().map(|c| c.to_json()).collect();
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                print!("{}", render::preflight(&c, render::use_colour()));
            }
            return Ok(preflight::exit_code(&c));
        }
        Cmd::Status => Request::Status,
        Cmd::Incidents(Inc::List) => Request::IncidentsList,
        Cmd::Incidents(Inc::Show { id }) => Request::IncidentShow { id: id.clone() },
        Cmd::Incidents(Inc::Timeline { id }) => Request::IncidentTimeline { id: id.clone() },
    };
    let resp = call(&cli.socket, &req)?;
    match (&resp, cli.json) {
        (Response::Timeline(lines), true) => lines.iter().for_each(|l| println!("{l}")),
        (_, true) => println!("{}", serde_json::to_string_pretty(&payload(&resp)).unwrap()),
        (Response::Status { .. }, false) => print!("{}", render::status(&resp).unwrap()),
        (Response::Incidents(l), false) => print!("{}", render::incidents(l)),
        (Response::Incident(v), false) => print!("{}", render::incident(v)),
        (Response::Timeline(l), false) => print!("{}", render::timeline(l)),
        (Response::Error(_), _) => return Err(wrong()),
    }
    Ok(0)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(c) => ExitCode::from(c),
        Err(e) => {
            eprintln!("aegisctl: {e}");
            ExitCode::from(1)
        }
    }
}
