// SPDX-License-Identifier: MIT OR Apache-2.0
mod config;
mod ebpf;
mod enforce;
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_common::{
    Event, EventKind, ENV_LOADER_VAR, ENV_TRUNCATED, ENV_UNREADABLE, EXEC_FALLBACK, EXEC_FROM_TMP,
    EXEC_MEMFD, HAS_TTY, PATH_TRUNCATED,
};
use aegis_proto::{Request, Response};
use anyhow::{Context as _, Result};
use clap::Parser;
use serde_json::{json, Value};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, oneshot};

use crate::config::{Config, ConfigHandle};
use crate::enforce::enforcer::{
    freeze_marked, spawn_enforcer, Backends, EnforceJob, EnforcerHandle, Honeypot, HoneypotParts,
    MARKS,
};
use crate::enforce::nft::Nft;
use crate::enforce::systemd::{Limits, Systemd};
use crate::incident::{IncidentId, IncidentStore};
use crate::pipeline::{EnvReaders, ExeKey, Incidents, Pipeline};
use crate::telemetry::{mode_str, Sinks};
use crate::verify::{Rpm, Verification, Verifier};

/// Incident writes queued to the writer thread at once.
const INCIDENT_QUEUE: usize = 256;
/// How often the loop flushes expired deferred signals.
const TICK: Duration = Duration::from_millis(500);
/// How often counters go out as OTLP metrics.
const METRICS_EVERY: Duration = Duration::from_secs(60);
/// Every this many ticks, sweep the process table (so ~60 s).
const SWEEP_TICKS: u64 = 120;
/// Every this many ticks (10 s), check that each quarantined tree still
/// has its nft drop rule. Cheap with nothing quarantined: no nft call.
const REASSERT_TICKS: u64 = 20;

/// How long shutdown waits for the enforcer to finish its jobs.
const ENFORCER_STOP: Duration = Duration::from_secs(5);

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
    done: mpsc::UnboundedSender<(ExeKey, Verification)>,
}

impl Verifying {
    /// Verifies the file a process executed, by the name it ran it as.
    fn spawn(&self, key: ExeKey) {
        let (v, pins, done) = (
            self.verifier.clone(),
            self.pinned.clone(),
            self.done.clone(),
        );
        tokio::task::spawn_blocking(move || {
            let r = v.verify(&key.0, key.1, &pins);
            let _ = done.send((key, r));
        });
    }

    /// Verifies the host's file at `path`, so a later exec of it hits the
    /// cache.
    fn spawn_host(&self, path: PathBuf) {
        let (v, pins, done) = (
            self.verifier.clone(),
            self.pinned.clone(),
            self.done.clone(),
        );
        tokio::task::spawn_blocking(move || {
            if let Some((id, r)) = v.verify_host(&path, &pins) {
                let _ = done.send(((path, id), r));
            }
        });
    }

    /// Verifies every allowlisted path in the background so its verdict
    /// is a warm cache hit by the time a process execs it. Runs at start
    /// and on SIGHUP only. Without it, the first container start after
    /// either races its own verdict, and its memfd signals wait in the
    /// defer queue for it.
    fn warm(&self, cfg: &Config) {
        for p in cfg.allowlist.verify_paths() {
            self.spawn_host(p);
        }
    }
}

/// Hands the honeypot its settings, in honeypot mode only. A failure
/// leaves the honeypot on what it last read, so it warns, not stops.
fn hand_honeypot(c: &Config) {
    let path = Path::new(config::HONEYPOT_FILE);
    match config::write_honeypot_file(c, path, config::honeypot_gid) {
        Ok(None) => {}
        Ok(Some(w)) => eprintln!("aegisd: warning: {w}"),
        Err(e) => eprintln!("aegisd: warning: writing {}: {e}", path.display()),
    }
}

async fn run(cli: &Cli, cfg: ConfigHandle) -> Result<()> {
    let started = Instant::now();
    let c = cfg.current();
    hand_honeypot(&c);
    let store = Arc::new(
        IncidentStore::open(&c.incidents.dir)
            .with_context(|| format!("opening incident store {}", c.incidents.dir.display()))?,
    );
    // Incident writes fsync, so they go to a thread: the event loop
    // never blocks on the disk, and a decision is dropped (and counted)
    // only if the writer falls far enough behind to fill the queue.
    let errors = Arc::new(AtomicU64::new(0));
    let (inc_tx, inc_rx) = sync_channel::<pipeline::RecordJob>(INCIDENT_QUEUE);
    let writer = {
        let (store, errors) = (store.clone(), errors.clone());
        std::thread::spawn(move || {
            while let Ok((d, tree, mode, id)) = inc_rx.recv() {
                if let Err(e) = store.record_as(&d, &tree, mode, Some(&id)) {
                    errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "aegisd: recording incident for tgid {} failed: {e:#}",
                        d.key.tgid
                    );
                }
            }
        })
    };
    let mut pipe = Pipeline::new(
        &c,
        Incidents {
            store: store.clone(),
            tx: Some(inc_tx),
            errors,
        },
        Sinks::new(&c.telemetry),
        Box::new(scoring::ProcDaemons),
        cli.debug,
    );
    let (done_tx, mut done) = mpsc::unbounded_channel();
    // /proc environment reads, for processes that predate us, can block
    // for good; they run on their own threads and answer here.
    let env_readers = EnvReaders::new();
    let (env_tx, mut env_done) = mpsc::unbounded_channel();
    let mut verifying = Verifying {
        verifier: Arc::new(Verifier::new(Rpm)),
        pinned: Arc::new(c.allowlist.pinned.clone()),
        done: done_tx,
    };
    let mut hup = signal(SignalKind::hangup())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;

    // Socket first: a second aegisd stops here, before loading probes.
    // The lock is held for the daemon's life; dropping it frees the path.
    let (listener, _lock) = ipc::bind(&cli.socket)?;
    let (mut handle, mut events) = match ebpf::start(&ebpf::Config {
        channel_capacity: 4096,
    }) {
        Ok(x) => x,
        Err(e) => {
            let _ = std::fs::remove_file(&cli.socket);
            return Err(e);
        }
    };
    // Runs in audit mode too, idle: the pipeline only queues jobs in
    // enforce mode, and a reload can switch modes.
    let honeypot = Arc::new(std::sync::Mutex::new(Honeypot::from_config(&c)));
    let guard = handle.guard.take().context("no egress guard")?;
    let enforcer = spawn_enforcer(
        store.clone(),
        Backends {
            holds: std::mem::take(&mut handle.holds),
            sys: Systemd::new(),
            nft: Nft::new(),
        },
        Limits {
            cpu_quota_percent: c.throttle.cpu_quota_percent,
            memory_high_bytes: u64::from(c.throttle.memory_high_mb) << 20,
        },
        pipe.sinks.clone(),
        pipe.enforcing.clone(),
        HoneypotParts {
            settings: honeypot.clone(),
            guard: Box::new(guard),
        },
    );
    let (call_tx, mut calls) = mpsc::channel::<ipc::Call>(16);
    let server = tokio::spawn(ipc::serve(listener, call_tx, 0));
    verifying.warm(&c);
    sd_notify("READY=1");
    eprintln!(
        "aegisd {} running: mode {}, {} probes, socket {}",
        env!("CARGO_PKG_VERSION"),
        mode_str(c.general.mode),
        handle.probes().len(),
        cli.socket.display()
    );
    drop(c);

    let mut ticker = tokio::time::interval(TICK);
    let mut ticks: u64 = 0;
    let mut metrics_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + METRICS_EVERY, METRICS_EVERY);
    // Ok on SIGTERM or SIGINT. Anything else that ends the loop is a
    // failure, so systemd restarts us.
    let mut outcome = Ok(());
    loop {
        tokio::select! {
            ev = events.recv() => {
                let Some(ev) = ev else {
                    outcome = Err(anyhow::anyhow!("probe event stream ended"));
                    break;
                };
                pipe.handle(&ev);
                for p in pipe.to_verify.drain(..) {
                    verifying.spawn(p);
                }
                for job in pipe.to_read_env.drain(..) {
                    let tx = env_tx.clone();
                    env_readers.spawn(job, move |job, env| {
                        let _ = tx.send((job, env));
                    });
                }
            }
            Some((path, v)) = done.recv() => pipe.verified(&path, v),
            Some((job, env)) = env_done.recv() => pipe.env_read(job, env),
            Some((req, reply)) = calls.recv() => match req {
                // Disk reads: answer off the loop.
                Request::IncidentShow { .. } | Request::IncidentTimeline { .. } => {
                    let store = store.clone();
                    tokio::task::spawn_blocking(move || {
                        let _ = reply.send(answer_disk(req, &store));
                    });
                }
                Request::IncidentRelease { ref id } | Request::IncidentKill { ref id } => {
                    pipe.enforcement_ended(id);
                    enforce_admin(req, &enforcer, reply);
                }
                _ => {
                    let _ = reply.send(answer(req, &pipe, &handle, &enforcer, &cfg, started));
                }
            },
            _ = ticker.tick() => {
                pipe.flush_expired(Instant::now());
                ticks += 1;
                if ticks.is_multiple_of(SWEEP_TICKS) {
                    pipe.sweep();
                }
                if ticks.is_multiple_of(REASSERT_TICKS) {
                    // Queued, never waited on: nft runs on the enforcer.
                    enforcer.queue(EnforceJob::Reassert);
                }
            }
            _ = metrics_tick.tick() => {
                if pipe.sinks.exports_metrics() {
                    pipe.sinks.metrics(&metrics_snapshot(&pipe, &handle, &enforcer));
                }
            }
            _ = hup.recv() => {
                let old = cfg.current();
                match cfg.reload() {
                    Ok(warnings) => {
                        for w in warnings {
                            eprintln!("aegisd: warning: {w}");
                        }
                        let c = cfg.current();
                        hand_honeypot(&c);
                        pipe.set_config(&c);
                        *honeypot.lock().unwrap_or_else(|e| e.into_inner()) =
                            Honeypot::from_config(&c);
                        // Pins may have changed, and the cache holds verdicts
                        // made with the old ones. A verification already in
                        // flight still lands with its old-pin verdict.
                        verifying.verifier = Arc::new(Verifier::new(Rpm));
                        verifying.pinned = Arc::new(c.allowlist.pinned.clone());
                        verifying.warm(&c);
                        pipe.reverify_pinned();
                        for p in pipe.to_verify.drain(..) {
                            verifying.spawn(p);
                        }
                        if c.telemetry != old.telemetry
                            || c.incidents != old.incidents
                            || c.throttle != old.throttle
                        {
                            eprintln!(
                                "aegisd: telemetry, incident and throttle settings take effect at restart"
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
        // Any arm can score (a verdict or deadline releases a deferred
        // signal), so jobs are handed over after each, never waited on.
        for job in std::mem::take(&mut pipe.to_enforce) {
            enforcer.queue_about(job, |id, k| pipe.about(id, k));
        }
    }

    sd_notify("STOPPING=1");
    eprintln!("aegisd: stopping");
    // Anything still waiting on a verdict is scored now, as Unverified,
    // and reaches the writer before its channel closes. An escalation
    // this scores is recorded but not enforced: its job is never queued,
    // so the incident stays at would_* and nothing is done to the tree.
    pipe.flush_all();
    server.abort();
    // A job cut off mid-way could leave a tree moved or frozen with
    // nothing recorded. Queued jobs run too, until the cap.
    if !enforcer.shutdown(ENFORCER_STOP) {
        eprintln!(
            "aegisd: enforcer still busy after {} s; stopping without it",
            ENFORCER_STOP.as_secs()
        );
    }
    // An observed tree runs on holds that end with the probes: freeze it
    // first. The HELD map lives as long as the probes using it.
    for e in freeze_marked(Path::new(MARKS), &Systemd::new()) {
        eprintln!("aegisd: could not freeze {e}; ExecStopPost tries again");
    }
    // Detaches every probe.
    drop(handle);
    // Closes the writer's channel so it drains and exits.
    drop(pipe);
    let _ = writer.join();
    let _ = std::fs::remove_file(&cli.socket);
    outcome
}

/// Cheap enough for the loop: atomics, a count, and one pass over the
/// incident summaries. The POST happens on the exporter thread.
fn metrics_snapshot(
    pipe: &Pipeline,
    probes: &ebpf::EbpfHandle,
    enforcer: &EnforcerHandle,
) -> telemetry::otlp::MetricsSnapshot {
    let mut by_verdict = std::collections::BTreeMap::new();
    let list = pipe.store().list();
    for i in &list {
        *by_verdict.entry(i.verdict.clone()).or_insert(0u64) += 1;
    }
    let d = pipe.sinks.dropped();
    telemetry::otlp::MetricsSnapshot {
        events_total: pipe.events_total,
        dropped_events: probes.dropped_events(),
        incidents_open: list.len() as u64,
        incidents_by_verdict: by_verdict,
        enforce_actions_ok: enforcer.actions_ok.load(Ordering::Relaxed),
        enforce_actions_failed: enforcer.actions_failed.load(Ordering::Relaxed),
        telemetry_dropped: d.journald
            + d.otlp_queue_full
            + d.otlp_export_failed
            + d.otlp_disconnected
            + d.webhook_queue_full
            + d.webhook_failed,
    }
}

fn answer(
    req: Request,
    pipe: &Pipeline,
    probes: &ebpf::EbpfHandle,
    enforcer: &EnforcerHandle,
    cfg: &ConfigHandle,
    started: Instant,
) -> Response {
    match req {
        Request::Status => Response::Status {
            version: env!("CARGO_PKG_VERSION").into(),
            mode: mode_str(cfg.current().general.mode).into(),
            uptime_s: started.elapsed().as_secs(),
            events_total: pipe.events_total,
            dropped_events: probes.dropped_events(),
            probes: probes.probes().to_vec(),
            incidents_open: pipe.store().open_count() as u64,
            incident_errors: pipe.incident_errors(),
            incident_dropped: pipe.incident_dropped,
            verify_skipped: pipe.verify_skipped,
            deferred_overflow: pipe.deferred_overflow,
            incident_suppressed: pipe.incident_suppressed,
            enforce_dropped: enforcer.dropped.load(Ordering::Relaxed),
            network: cfg.current().quarantine.network.as_str().into(),
            incidents_observing: pipe
                .store()
                .list()
                .iter()
                .filter(|i| i.state.as_deref() == Some("observing"))
                .count() as u64,
            telemetry_dropped: pipe.sinks.dropped(),
        },
        Request::IncidentsList => Response::Incidents(pipe.store().list()),
        // Handled off the loop in `answer_disk`.
        _ => Response::Error("internal: wrong handler".into()),
    }
}

/// How long a release or kill may wait for the enforcer, which runs one
/// job at a time and may be mid-way through a quarantine. It must stay
/// under aegisctl's reply deadline, which starts earlier: otherwise the
/// client gives up first and never sees "still queued".
const ENFORCER_WAIT: Duration = Duration::from_secs(25);
const _: () = assert!(ENFORCER_WAIT.as_secs() + 5 <= aegis_proto::REPLY_DEADLINE.as_secs());

/// Hands a release or kill to the enforcer and answers when it does.
/// The wait is in its own task so the event loop never blocks on it. It
/// acts on recorded actions, so it works in audit mode too.
fn enforce_admin(req: Request, enforcer: &EnforcerHandle, reply: oneshot::Sender<Response>) {
    enforce_admin_in(req, &enforcer.tx, ENFORCER_WAIT, reply);
}

fn enforce_admin_in(
    req: Request,
    queue: &std::sync::mpsc::SyncSender<EnforceJob>,
    wait: Duration,
    reply: oneshot::Sender<Response>,
) {
    let (id, kill) = match req {
        Request::IncidentRelease { id } => (id, false),
        Request::IncidentKill { id } => (id, true),
        _ => return,
    };
    if !aegis_proto::is_incident_id(&id) {
        let _ = reply.send(Response::Error("not an incident id".into()));
        return;
    }
    let queued = format!("still queued; check `aegisctl incidents show {id}` shortly");
    let (tx, rx) = oneshot::channel();
    let reply_to = Some(tx);
    let job = if kill {
        EnforceJob::Kill {
            id,
            reply: reply_to,
        }
    } else {
        EnforceJob::Release {
            id,
            reply: reply_to,
        }
    };
    if queue.try_send(job).is_err() {
        let _ = reply.send(Response::Error("enforcer busy, try again".into()));
        return;
    }
    tokio::spawn(async move {
        let r = match tokio::time::timeout(wait, rx).await {
            Ok(Ok(Ok(done))) => Response::Done(done),
            Ok(Ok(Err(e))) => Response::Error(e),
            Ok(Err(_)) => Response::Error("the enforcer stopped before answering".into()),
            // The job still runs once the enforcer gets to it, so the
            // admin must not be told to send it again.
            Err(_) => Response::Error(queued),
        };
        let _ = reply.send(r);
    });
}

/// The incident requests that read from disk.
fn answer_disk(req: Request, store: &IncidentStore) -> Response {
    let missing = || Response::Error("no such incident".into());
    match req {
        Request::IncidentShow { id } => store
            .get(&IncidentId(id))
            .and_then(|i| serde_json::to_value(i).ok())
            .map_or_else(missing, Response::Incident),
        Request::IncidentTimeline { id } => store
            .timeline(&IncidentId(id))
            .map_or_else(missing, Response::Timeline),
        _ => Response::Error("internal: wrong handler".into()),
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
        (ENV_LOADER_VAR, "env_loader_var"),
        (ENV_TRUNCATED, "env_truncated"),
        (ENV_UNREADABLE, "env_unreadable"),
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
        Ok(EventKind::ExecEnv) => ("exec_env", json!({})),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    const ID: &str = "AEG-20261021-000000-0123456789abcdef";

    async fn ask(
        id: &str,
        queue: &std::sync::mpsc::SyncSender<EnforceJob>,
        wait: Duration,
    ) -> Response {
        let (tx, rx) = oneshot::channel();
        enforce_admin_in(Request::IncidentKill { id: id.into() }, queue, wait, tx);
        rx.await.unwrap()
    }

    #[tokio::test]
    async fn admin_requests_refuse_bad_ids_and_a_full_queue() {
        let (q, _rx) = sync_channel(0);
        let r = ask("../etc", &q, Duration::from_secs(1)).await;
        assert_eq!(r, Response::Error("not an incident id".into()));
        // Nothing is receiving on a zero-capacity queue: full.
        let r = ask(ID, &q, Duration::from_secs(1)).await;
        assert_eq!(r, Response::Error("enforcer busy, try again".into()));
    }

    #[tokio::test]
    async fn admin_requests_time_out_and_relay_answers() {
        let (q, rx) = sync_channel(2);
        let r = ask(ID, &q, Duration::from_millis(20)).await;
        // Not "timed out": the job still runs, so asking again would
        // queue it twice.
        assert_eq!(
            r,
            Response::Error(format!(
                "still queued; check `aegisctl incidents show {ID}` shortly"
            ))
        );
        // The first job is still queued; answer the second one.
        let _stale = rx.recv().unwrap();
        let (tx, answer) = oneshot::channel();
        enforce_admin_in(
            Request::IncidentKill { id: ID.into() },
            &q,
            Duration::from_secs(5),
            tx,
        );
        let EnforceJob::Kill { reply: Some(r), .. } = rx.recv().unwrap() else {
            panic!("not a kill")
        };
        r.send(Ok(format!("killed {ID}"))).unwrap();
        assert_eq!(
            answer.await.unwrap(),
            Response::Done(format!("killed {ID}"))
        );
    }
}
