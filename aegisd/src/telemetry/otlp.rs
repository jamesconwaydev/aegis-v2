// SPDX-License-Identifier: MIT OR Apache-2.0
//! OTLP logs over HTTP with a JSON body (`POST /v1/logs`), plain HTTP only.
//!
//! `emit` never blocks: records go through a bounded channel to one
//! background thread. When the channel is full the record is dropped and
//! counted. ponytail: no batching, one POST per record, and no TLS; add
//! both (or opentelemetry-otlp) when a collector needs them.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::{Sink, TelemetryRecord};
use crate::scoring::Tier;

pub const QUEUE: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(2);

pub struct Otlp {
    tx: SyncSender<Value>,
    dropped: Arc<AtomicU64>,
}

impl Otlp {
    pub fn new(endpoint: &str) -> Self {
        let (tx, rx) = sync_channel::<Value>(QUEUE);
        let target = parse(endpoint);
        if target.is_none() {
            eprintln!("aegisd: otlp endpoint {endpoint:?} unsupported (need http://host:port)");
        }
        let dropped = Arc::new(AtomicU64::new(0));
        let d = dropped.clone();
        std::thread::spawn(move || {
            let mut failing = false;
            for body in rx {
                let ok = target.as_ref().is_some_and(|t| post(t, &body).is_ok());
                if !ok {
                    d.fetch_add(1, Ordering::Relaxed);
                }
                // Log the transition only, not every record.
                if !ok && !failing {
                    eprintln!("aegisd: otlp export failing; dropping records");
                }
                failing = !ok;
            }
        });
        Self { tx, dropped }
    }

    /// Records lost to a full queue or a failed export.
    pub fn dropped_records(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Sink for Otlp {
    fn emit(&self, rec: &TelemetryRecord) {
        match self.tx.try_send(body(rec)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

struct Target {
    host_port: String,
    path: String,
}

fn parse(endpoint: &str) -> Option<Target> {
    let rest = endpoint.strip_prefix("http://")?;
    let (hp, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].trim_end_matches('/').to_string()),
        None => (rest, String::new()),
    };
    let path = if path.ends_with("/v1/logs") {
        path
    } else {
        format!("{path}/v1/logs")
    };
    Some(Target {
        host_port: hp.to_string(),
        path,
    })
}

fn post(t: &Target, body: &Value) -> std::io::Result<()> {
    let addr = t
        .host_port
        .to_socket_addrs()?
        .next()
        .ok_or(std::io::ErrorKind::NotFound)?;
    let mut s = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    s.set_write_timeout(Some(TIMEOUT))?;
    s.set_read_timeout(Some(TIMEOUT))?;
    let b = body.to_string();
    write!(
        s,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{b}",
        t.path,
        t.host_port,
        b.len()
    )?;
    let mut head = [0u8; 12];
    s.read_exact(&mut head)?;
    if &head[9..12] == b"200" {
        Ok(())
    } else {
        Err(std::io::ErrorKind::InvalidData.into())
    }
}

fn kv(k: &str, v: String) -> Value {
    json!({"key": k, "value": {"stringValue": v}})
}

pub fn body(rec: &TelemetryRecord) -> Value {
    let (num, text) = match rec.tier {
        Tier::Log => (9, "INFO"),
        Tier::Throttle => (13, "WARN"),
        Tier::Quarantine => (17, "ERROR"),
    };
    json!({"resourceLogs": [{
        "resource": {"attributes": [kv("service.name", "aegisd".into())]},
        "scopeLogs": [{"scope": {"name": "aegisd"}, "logRecords": [{
            "timeUnixNano": rec.ts_unix_ns.to_string(),
            "severityNumber": num,
            "severityText": text,
            "body": {"stringValue": rec.message()},
            "attributes": [
                kv("aegis.incident", rec.incident.clone()),
                kv("aegis.verdict", rec.verdict.into()),
                kv("aegis.tier", rec.tier_str().into()),
                kv("aegis.score", format!("{:.1}", rec.score)),
                kv("aegis.path", rec.exe_lossy()),
                kv("aegis.path_b64", rec.exe_b64()),
            ],
        }]}],
    }]})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;

    #[test]
    fn otlp_sink_unreachable_does_not_block() {
        // Bind then drop to get a port nothing listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let sink = Otlp::new(&format!("http://127.0.0.1:{port}"));
        let rec = TelemetryRecord {
            ts_unix_ns: 0,
            incident: "AEG-1".into(),
            tier: Tier::Throttle,
            verdict: "would_throttle",
            score: 6.0,
            mode: Mode::Audit,
            tgid: 1,
            comm: "c".into(),
            exe: None,
            reasons: vec![],
        };
        let t = std::time::Instant::now();
        for _ in 0..10_000 {
            sink.emit(&rec);
        }
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        // Whatever the worker has not drained yet is still accounted for.
        std::thread::sleep(Duration::from_millis(500));
        assert!(sink.dropped_records() > 0);
    }

    #[test]
    fn endpoint_parsing() {
        assert_eq!(parse("http://h:4318").unwrap().path, "/v1/logs");
        assert_eq!(parse("http://h:4318/x/").unwrap().path, "/x/v1/logs");
        assert!(parse("https://h").is_none());
    }
}
