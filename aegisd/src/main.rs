// SPDX-License-Identifier: MIT OR Apache-2.0
// Wired into the daemon in a later task.
#[allow(dead_code)]
mod config;
mod ebpf;
// Wired into the pipeline in a later task.
#[allow(dead_code)]
mod proctable;
#[allow(dead_code)]
mod verify;

use std::net::{Ipv4Addr, Ipv6Addr};

use aegis_common::{
    Event, EventKind, EXEC_FALLBACK, EXEC_FROM_TMP, EXEC_MEMFD, HAS_TTY, PATH_TRUNCATED,
};
use anyhow::Result;
use clap::Parser;
use serde_json::{json, Value};

#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Print every probe event as a JSON line until interrupted.
    #[arg(long, hide = true)]
    dump_events: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.dump_events {
        dump_events().await?;
    }
    Ok(())
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
