// SPDX-License-Identifier: MIT OR Apache-2.0
mod config;
mod ebpf;
mod incident;
mod ipc;
mod pipeline;
mod proctable;
mod scoring;
mod telemetry;
mod verify;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_common::{
    Event, EventKind, EXEC_FALLBACK, EXEC_FROM_TMP, EXEC_MEMFD, HAS_TTY, PATH_TRUNCATED,
};
use aegis_proto::{Request, Response};
use anyhow::{Context as _, Result};
use clap::Parser;
use serde_json::{json, Value};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

use crate::config::ConfigHandle;
use crate::incident::{IncidentId, IncidentStore};
use crate::pipeline::Pipeline;
use crate::telemetry::{mode_str, Sinks};
use crate::verify::{Rpm, Verification, Verifier};

/// sysexits.h EX_CONFIG.
const EX_CONFIG: u8 = 78;
/// Verifications run on at most this many threads; the rest queue.
const VERIFY_THREADS: usize = 4;

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Main configuration file.
    #[arg(long, default_value = "/etc/aegis-v2/config.toml")]
    config: PathBuf,
    /// Allowlist drop-in directory [default: allowlist.d beside --config].
    #[arg(long)]
    allowlist_dir: Option<PathBuf>,
    /// Control socket.
    #[arg(long, default_value = aegis_proto::SOCKET)]
    socket: PathBuf,
    /// Load and check the configuration, print any warnings, and exit.
    #[arg(long)]
    check_config: bool,
    /// Log every scoring decision to stderr.
    #[arg(long)]
    debug: bool,
    /// Print every probe event as a JSON line until interrupted.
    #[arg(long, hide = true)]
    dump_events: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(VERIFY_THREADS)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("aegisd: starting runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let res = if cli.dump_events {
        rt.block_on(dump_events())
    } else {
        let dropins = cli.allowlist_dir.clone().unwrap_or_else(|| {
            cli.config
                .parent()
                .unwrap_or(Path::new("/"))
                .join("allowlist.d")
        });
        let cfg = match ConfigHandle::new(cli.config.clone(), dropins) {
            Ok((cfg, warnings)) => {
                for w in warnings {
                    eprintln!("aegisd: warning: {w}");
                }
                cfg
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(EX_CONFIG);
            }
        };
        if cli.check_config {
            return ExitCode::SUCCESS;
        }
        rt.block_on(run(&cli, cfg))
    };
    // A verification may be waiting on rpm; don't hang on it.
    rt.shutdown_timeout(Duration::from_secs(3));
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegisd: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Tells systemd, if it is listening (`Type=notify`).
fn sd_notify(msg: &str) {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let Some(path) = std::env::var_os("NOTIFY_SOCKET").filter(|p| !p.is_empty()) else {
        return;
    };
    let r = UnixDatagram::unbound().and_then(|s| {
        let addr = match path.as_bytes().strip_prefix(b"@") {
            Some(name) => SocketAddr::from_abstract_name(name)?,
            None => SocketAddr::from_pathname(&path)?,
        };
        s.send_to_addr(msg.as_bytes(), &addr)
    });
    if let Err(e) = r {
        eprintln!("aegisd: sd_notify {msg}: {e}");
    }
}

/// Runs the Verifier off the event loop.
struct Verifying {
    verifier: Arc<Verifier<Rpm>>,
    pinned: Arc<Vec<(PathBuf, [u8; 32])>>,
    done: mpsc::UnboundedSender<(PathBuf, Verification)>,
}

impl Verifying {
    fn spawn(&self, path: PathBuf) {
        let (v, pins, done) = (
            self.verifier.clone(),
            self.pinned.clone(),
            self.done.clone(),
        );
        tokio::task::spawn_blocking(move || {
            let r = v.verify(&path, &pins);
            let _ = done.send((path, r));
        });
    }
}

async fn run(cli: &Cli, cfg: ConfigHandle) -> Result<()> {
    let started = Instant::now();
    let c = cfg.current();
    let incidents = IncidentStore::open(&c.incidents.dir)
        .with_context(|| format!("opening incident store {}", c.incidents.dir.display()))?;
    let mut pipe = Pipeline::new(
        &c,
        incidents,
        Sinks::new(&c.telemetry),
        Box::new(scoring::ProcDaemons),
        pipeline::resolve_exe,
        cli.debug,
    );
    let (done_tx, mut done) = mpsc::unbounded_channel();
    let mut verifying = Verifying {
        verifier: Arc::new(Verifier::new(Rpm)),
        pinned: Arc::new(c.allowlist.pinned.clone()),
        done: done_tx,
    };
    let mut hup = signal(SignalKind::hangup())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;

    // Socket first: a second aegisd stops here, before loading probes.
    let listener = ipc::bind(&cli.socket)?;
    let (handle, mut events) = match ebpf::start(&ebpf::Config {
        channel_capacity: 4096,
    }) {
        Ok(x) => x,
        Err(e) => {
            let _ = std::fs::remove_file(&cli.socket);
            return Err(e);
        }
    };
    let (call_tx, mut calls) = mpsc::channel::<ipc::Call>(16);
    let server = tokio::spawn(ipc::serve(listener, call_tx, 0));
    sd_notify("READY=1");
    eprintln!(
        "aegisd {} running: mode {}, {} probes, socket {}",
        env!("CARGO_PKG_VERSION"),
        mode_str(c.general.mode),
        handle.probes().len(),
        cli.socket.display()
    );
    drop(c);

    loop {
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else {
                    eprintln!("aegisd: probe event stream ended");
                    break;
                };
                pipe.handle(&ev);
                for p in pipe.to_verify.drain(..) {
                    verifying.spawn(p);
                }
            }
            Some((path, v)) = done.recv() => pipe.verified(&path, v),
            Some((req, reply)) = calls.recv() => {
                let r = answer(req, &pipe, &handle, &cfg, started);
                let _ = reply.send(r);
            }
            _ = hup.recv() => {
                let old = cfg.current();
                match cfg.reload() {
                    Ok(warnings) => {
                        for w in warnings {
                            eprintln!("aegisd: warning: {w}");
                        }
                        let c = cfg.current();
                        pipe.set_config(&c);
                        // Pins may have changed, and the cache holds verdicts
                        // made with the old ones. A verification already in
                        // flight still lands with its old-pin verdict.
                        verifying.verifier = Arc::new(Verifier::new(Rpm));
                        verifying.pinned = Arc::new(c.allowlist.pinned.clone());
                        if c.telemetry != old.telemetry || c.incidents != old.incidents {
                            eprintln!(
                                "aegisd: telemetry and incident settings take effect at restart"
                            );
                        }
                        eprintln!("aegisd: configuration reloaded");
                    }
                    Err(e) => eprintln!("aegisd: reload failed, keeping the old configuration: {e}"),
                }
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }

    sd_notify("STOPPING=1");
    eprintln!("aegisd: stopping");
    server.abort();
    // Detaches every probe.
    drop(handle);
    let _ = std::fs::remove_file(&cli.socket);
    Ok(())
}

fn answer(
    req: Request,
    pipe: &Pipeline,
    probes: &ebpf::EbpfHandle,
    cfg: &ConfigHandle,
    started: Instant,
) -> Response {
    let missing = || Response::Error("no such incident".into());
    match req {
        Request::Status => Response::Status {
            version: env!("CARGO_PKG_VERSION").into(),
            mode: mode_str(cfg.current().general.mode).into(),
            uptime_s: started.elapsed().as_secs(),
            events_total: pipe.events_total,
            dropped_events: probes.dropped_events(),
            probes: probes.probes().to_vec(),
            incidents_open: pipe.incidents.open_count() as u64,
            incident_errors: pipe.incident_errors,
            telemetry_dropped: pipe.sinks.dropped(),
        },
        Request::IncidentsList => Response::Incidents(pipe.incidents.list()),
        Request::IncidentShow { id } => pipe
            .incidents
            .get(&IncidentId(id))
            .and_then(|i| serde_json::to_value(i).ok())
            .map_or_else(missing, Response::Incident),
        Request::IncidentTimeline { id } => pipe
            .incidents
            .timeline(&IncidentId(id))
            .map_or_else(missing, Response::Timeline),
    }
}

async fn dump_events() -> Result<()> {
    let (handle, mut rx) = ebpf::start(&ebpf::Config {
        channel_capacity: 4096,
    })?;
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => println!("{}", event_json(&ev)),
                None => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    eprintln!("dropped events: {}", handle.dropped_events());
    Ok(())
}

fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn event_json(ev: &Event) -> Value {
    let flags: Vec<&str> = [
        (EXEC_FROM_TMP, "exec_from_tmp"),
        (EXEC_MEMFD, "exec_memfd"),
        (PATH_TRUNCATED, "path_truncated"),
        (HAS_TTY, "has_tty"),
        (EXEC_FALLBACK, "exec_fallback"),
    ]
    .into_iter()
    .filter(|(bit, _)| ev.flags & bit != 0)
    .map(|(_, name)| name)
    .collect();
    let mut v = json!({
        "tgid": ev.tgid,
        "pid": ev.pid,
        "ppid": ev.ppid,
        "uid": ev.uid,
        "start_time_ns": ev.start_time_ns,
        "ts_ns": ev.ts_ns,
        "cgroup_id": ev.cgroup_id,
        "comm": text(&ev.comm),
        "flags": flags,
    });
    let path = || text(&ev.path[..ev.path.len().min(ev.path_len as usize)]);
    let (kind, extra) = match EventKind::try_from(ev.kind) {
        Ok(EventKind::Exec) => ("exec", json!({ "path": path() })),
        Ok(EventKind::Fork) => (
            "fork",
            json!({
                "child_tgid": ev.child_tgid,
                "child_start_time_ns": ev.child_start_time_ns,
            }),
        ),
        Ok(EventKind::Exit) => ("exit", json!({})),
        Ok(EventKind::Ptrace) => (
            "ptrace",
            json!({ "target_tgid": ev.target_tgid, "request": ev.ptrace_request }),
        ),
        Ok(EventKind::MemfdCreate) => ("memfd_create", json!({ "name": path() })),
        Ok(EventKind::Connect) => {
            let daddr = match ev.family {
                2 => Ipv4Addr::from(<[u8; 4]>::try_from(&ev.daddr[..4]).unwrap()).to_string(),
                _ => Ipv6Addr::from(ev.daddr).to_string(),
            };
            (
                "connect",
                json!({ "family": ev.family, "daddr": daddr, "dport": ev.dport, "ret": ev.ret }),
            )
        }
        Err(_) => ("unknown", json!({ "raw_kind": ev.kind })),
    };
    v["kind"] = kind.into();
    if let (Value::Object(v), Value::Object(extra)) = (&mut v, extra) {
        v.extend(extra);
    }
    v
}
