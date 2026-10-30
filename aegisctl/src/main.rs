// SPDX-License-Identifier: MIT OR Apache-2.0
//! `aegisctl`: ask a running aegisd what it's seen, and check a host
//! before you install it.

mod preflight;
mod render;

use std::io::{ErrorKind, IsTerminal, Read, Write};
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
    /// Write every honeypot session's packets, merged into one pcap, to
    /// stdout, which must not be a terminal. From v0.3.0.
    Pcap { id: String },
    /// Print a STIX 2.1 bundle of what the incident saw. From v0.3.0.
    Stix { id: String },
}

const MAX_REPLY: usize = 16 * 1024 * 1024;
const DEADLINE: Duration = aegis_proto::REPLY_DEADLINE;

/// Read one line, at most MAX_REPLY bytes, within DEADLINE overall. Also
/// what came after the newline in the same read.
fn read_reply(s: &mut UnixStream) -> Result<(Vec<u8>, Vec<u8>), String> {
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let left = DEADLINE
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| format!("no reply from aegisd within {} s", DEADLINE.as_secs()))?;
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
                Ok((buf, chunk[i + 1..n].to_vec()))
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

/// Connect and send one request. Errors are ready to print.
fn send(socket: &Path, req: &Request) -> Result<UnixStream, String> {
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
    Ok(s)
}

/// A reply line, with the daemon's errors ready to print.
fn parse_reply(line: &[u8]) -> Result<Response, String> {
    match serde_json::from_slice(line).map_err(|e| format!("unreadable reply from aegisd: {e}"))? {
        Response::Error(m) if m == "permission denied" => Err("aegisctl must run as root".into()),
        // serde's words for a request this daemon predates.
        Response::Error(m) if m.starts_with("bad request: unknown variant") => Err(
            "aegisd is older than this aegisctl and can't answer that; it needs v0.3.0 or later"
                .into(),
        ),
        Response::Error(m) => Err(format!("aegisd: {}", render::clean(&m))),
        r => Ok(r),
    }
}

/// Send one request, read one reply. Errors are ready to print.
fn call(socket: &Path, req: &Request) -> Result<Response, String> {
    let mut s = send(socket, req)?;
    parse_reply(&read_reply(&mut s)?.0)
}

/// `incidents pcap` writes binary, so not to a terminal.
fn pcap_target(tty: bool) -> Result<(), String> {
    if tty {
        Err("stdout is a terminal; redirect it to a file (> incident.pcap)".into())
    } else {
        Ok(())
    }
}

/// Copies exactly `n` bytes, or says how far it got.
fn copy_exact(r: impl Read, w: &mut impl Write, n: u64) -> Result<(), String> {
    let got = std::io::copy(&mut r.take(n), w).map_err(|e| match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => {
            format!("aegisd stopped sending for {} s", DEADLINE.as_secs())
        }
        _ => format!("pcap not written whole: {e}"),
    })?;
    if got == n {
        Ok(())
    } else {
        Err(format!(
            "aegisd stopped after {got} of {n} bytes; the pcap is cut short"
        ))
    }
}

/// The merged pcap of incident `id`, to `out`; why any sessions were
/// left out of it.
fn pcap(socket: &Path, id: &str, out: &mut impl Write) -> Result<Vec<String>, String> {
    let mut s = send(socket, &Request::IncidentPcap { id: id.into() })?;
    let (line, rest) = read_reply(&mut s)?;
    let Response::Pcap {
        bytes,
        sessions,
        notes,
        ..
    } = parse_reply(&line)?
    else {
        return Err("aegisd sent a reply this aegisctl doesn't understand".into());
    };
    // A header and nothing else is no capture: say so, write nothing.
    if sessions == 0 {
        let why: Vec<String> = notes.iter().map(|n| render::clean(n)).collect();
        return Err(format!("nothing to export: {}", why.join("; ")));
    }
    // Each read may wait this long; the whole pcap may take longer.
    s.set_read_timeout(Some(DEADLINE))
        .map_err(|e| e.to_string())?;
    copy_exact(std::io::Cursor::new(rest).chain(s), out, bytes)?;
    out.flush()
        .map_err(|e| format!("pcap not written whole: {e}"))?;
    Ok(notes)
}

/// JSON for stdout: pretty, and with nothing a terminal would act on.
fn json_text(v: &Value) -> String {
    aegis_proto::clean_json(&serde_json::to_string_pretty(v).unwrap_or_default()) + "\n"
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
    let pretty = json_text;
    let mut id = String::new();
    let req = match &cli.cmd {
        Cmd::Preflight => {
            let path: Vec<PathBuf> =
                std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
            let c = preflight::Preflight::run_with(
                Path::new("/"),
                &path,
                &cli.socket,
                &preflight::systemd_active,
            );
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
            | Inc::Kill { id: i }
            | Inc::Pcap { id: i }
            | Inc::Stix { id: i },
        ) if !aegis_proto::is_incident_id(i) => {
            return Err(format!(
                "{i} is not an incident id (AEG-YYYYMMDD-HHMMSS- and 16 hex digits)"
            ));
        }
        Cmd::Incidents(Inc::Show { id }) => Request::IncidentShow { id: id.clone() },
        Cmd::Incidents(Inc::Release { id }) => Request::IncidentRelease { id: id.clone() },
        Cmd::Incidents(Inc::Kill { id }) => Request::IncidentKill { id: id.clone() },
        Cmd::Incidents(Inc::Stix { id }) => Request::IncidentStix { id: id.clone() },
        Cmd::Incidents(Inc::Pcap { id }) => {
            pcap_target(std::io::stdout().is_terminal())?;
            let out = std::io::stdout().lock();
            for n in pcap(&cli.socket, id, &mut std::io::BufWriter::new(out))? {
                eprintln!("aegisctl: left out of the pcap: {}", render::clean(&n));
            }
            return Ok((String::new(), 0));
        }
        Cmd::Incidents(Inc::Timeline { id: i }) => {
            id = i.clone();
            Request::IncidentTimeline { id: i.clone() }
        }
    };
    let resp = call(&cli.socket, &req)?;
    let out = match (&resp, cli.json) {
        (Response::Done(m), true) => pretty(&serde_json::json!({ "done": m })),
        (Response::Done(m), false) => render::done(m),
        (Response::Stix(v), _) => pretty(v),
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
        (Response::Error(_) | Response::Pcap { .. }, _) => return Err(wrong()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::net::UnixListener;

    /// A daemon that answers one request with `reply`, in one write.
    fn fake(name: &str, reply: Vec<u8>) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegisctl-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("s");
        let l = UnixListener::bind(&p).unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 4096];
            let _ = s.read(&mut b);
            let _ = s.write_all(&reply);
        });
        p
    }

    #[test]
    fn pcap_writes_exactly_what_the_reply_line_promised() {
        let body: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let mut r = br#"{"Pcap":{"bytes":200000,"sessions":2,"left_out":0}}"#.to_vec();
        r.push(b'\n');
        r.extend(&body);
        let mut out = Vec::new();
        assert!(pcap(&fake("pcap", r), "AEG-x", &mut out)
            .unwrap()
            .is_empty());
        assert_eq!(out, body);
    }

    #[test]
    fn pcap_passes_on_why_sessions_were_left_out() {
        let mut r = br#"{"Pcap":{"bytes":3,"sessions":1,"left_out":2,"notes":["2 newer sessions past the 256 MiB or 1048576-record cap"]}}"#.to_vec();
        r.extend(b"\nabc");
        let notes = pcap(&fake("notes", r), "AEG-x", &mut Vec::new()).unwrap();
        assert_eq!(
            notes,
            ["2 newer sessions past the 256 MiB or 1048576-record cap"]
        );
    }

    #[test]
    fn a_pcap_of_no_sessions_is_an_error_and_writes_nothing() {
        let mut r = br#"{"Pcap":{"bytes":24,"sessions":0,"left_out":1,"notes":["x"]}}"#.to_vec();
        r.push(b'\n');
        r.extend([0u8; 24]);
        let mut out = Vec::new();
        let e = pcap(&fake("zero", r), "AEG-x", &mut out).unwrap_err();
        assert!(e.contains("nothing to export") && e.contains('x'), "{e}");
        assert!(out.is_empty());
    }

    #[test]
    fn pcap_cut_short_is_an_error() {
        let mut r = br#"{"Pcap":{"bytes":10,"sessions":1,"left_out":0}}"#.to_vec();
        r.extend(b"\nabc");
        let e = pcap(&fake("short", r), "AEG-x", &mut Vec::new()).unwrap_err();
        assert!(e.contains("3 of 10 bytes"), "{e}");
    }

    #[test]
    fn pcap_with_nothing_to_export_is_the_daemons_error() {
        let r = b"{\"error\":\"nothing to export: no honeypot sessions\"}\n".to_vec();
        let e = pcap(&fake("none", r), "AEG-x", &mut Vec::new()).unwrap_err();
        assert_eq!(e, "aegisd: nothing to export: no honeypot sessions");
    }

    #[test]
    fn pcap_refuses_a_terminal() {
        assert!(pcap_target(true).unwrap_err().contains("redirect"));
        assert!(pcap_target(false).is_ok());
    }

    #[test]
    fn an_older_daemon_is_named_as_the_problem() {
        let e = parse_reply(
            br#"{"error":"bad request: unknown variant `IncidentStix`, expected one of `Status`"}"#,
        )
        .unwrap_err();
        assert!(e.contains("older") && e.contains("v0.3.0"), "{e}");
    }

    #[test]
    fn json_output_has_no_raw_controls_and_is_the_same_json() {
        let v = json!({"k": "\u{1b}]0;pwn\u{7} \u{1b}[2J \u{9b}31m \u{202e}"});
        let o = json_text(&v);
        assert!(o.chars().all(|c| c == '\n' || !c.is_control()), "{o:?}");
        assert!(!o.contains('\u{202e}'));
        assert_eq!(serde_json::from_str::<Value>(&o).unwrap(), v);
    }
}
