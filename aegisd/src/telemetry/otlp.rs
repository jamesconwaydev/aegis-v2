// SPDX-License-Identifier: MIT OR Apache-2.0
//! OTLP logs and metrics over HTTP(S) with a JSON body (`POST
//! <endpoint>/v1/logs`, `/v1/metrics`).
//!
//! `emit` never blocks: records go through a bounded channel to one
//! worker thread, which sends up to `BATCH` records (or one second's
//! worth) per POST. When the channel is full the record is dropped and
//! counted. A metrics snapshot rides the same channel and gets its own
//! POST. TLS is rustls, trusting the system CA bundle (on Rocky,
//! /etc/pki/tls/certs/ca-bundle.crt, or `SSL_CERT_FILE`).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use ureq::tls::{RootCerts, TlsConfig};

use super::{Sink, TelemetryRecord};
use crate::config::OtlpConfig;
use crate::scoring::Tier;

pub const QUEUE: usize = 4096;
const BATCH: usize = 512;
const FLUSH: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Counters {
    queue_full: AtomicU64,
    /// Worker thread gone (it panicked); nothing will drain the queue.
    disconnected: AtomicU64,
    export_failed: AtomicU64,
}

/// What the worker sends: a log record to batch, or a finished
/// metrics body to post as is.
enum Job {
    Log(Value),
    Metrics(Value),
}

/// Counters and gauges aegisd exports every 60 s.
#[derive(Default, Clone, Debug)]
pub struct MetricsSnapshot {
    pub events_total: u64,
    pub dropped_events: u64,
    pub incidents_open: u64,
    pub incidents_by_verdict: BTreeMap<String, u64>,
    pub enforce_actions_ok: u64,
    pub enforce_actions_failed: u64,
    pub telemetry_dropped: u64,
    /// Honeypot sessions filed, unmatched and rejected.
    pub honeypot_sessions: [u64; 3],
}

pub struct Otlp {
    tx: SyncSender<Job>,
    counters: Arc<Counters>,
    resource: Value,
    /// Cumulative sums count from here.
    start_ns: u64,
}

impl Otlp {
    pub fn new(cfg: &OtlpConfig) -> Self {
        Self::with_roots(cfg, RootCerts::PlatformVerifier)
    }

    pub fn with_roots(cfg: &OtlpConfig, roots: RootCerts) -> Self {
        let (tx, rx) = sync_channel::<Job>(QUEUE);
        let counters = Arc::new(Counters::default());
        let c = counters.clone();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(cfg.timeout_secs)))
            .tls_config(TlsConfig::builder().root_certs(roots).build())
            .build()
            .into();
        // The endpoint may be given as the logs URL; metrics sit beside it.
        let base = cfg.endpoint.trim_end_matches('/');
        let base = base.strip_suffix("/v1/logs").unwrap_or(base);
        let url = format!("{base}/v1/logs");
        let metrics_url = format!("{base}/v1/metrics");
        let headers = cfg.headers.clone();
        let resource = resource();
        let worker_resource = resource.clone();
        std::thread::spawn(move || {
            let mut failing = false;
            let mut post = |url: &str, body: String, n: u64| {
                let mut req = agent.post(url).header("Content-Type", "application/json");
                for (k, v) in &headers {
                    req = req.header(k, v);
                }
                match req.send(body) {
                    Ok(_) => failing = false,
                    Err(e) => {
                        c.export_failed.fetch_add(n, Ordering::Relaxed);
                        // Log the transition only; ureq's Display can quote the URL.
                        if !failing {
                            eprintln!(
                                "aegisd: otlp export failing, dropping records: {}",
                                super::webhook::error_kind(&e)
                            );
                        }
                        failing = true;
                    }
                }
            };
            while let Ok(first) = rx.recv() {
                let mut batch = Vec::new();
                let mut metrics = Vec::new();
                let mut take = |j, batch: &mut Vec<Value>| match j {
                    Job::Log(r) => batch.push(r),
                    Job::Metrics(m) => metrics.push(m),
                };
                take(first, &mut batch);
                let deadline = Instant::now() + FLUSH;
                while batch.len() < BATCH {
                    match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                        Ok(j) => take(j, &mut batch),
                        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
                    }
                }
                for m in metrics {
                    post(&metrics_url, m.to_string(), 1);
                }
                if !batch.is_empty() {
                    let n = batch.len() as u64;
                    post(&url, envelope(&worker_resource, batch).to_string(), n);
                }
            }
        });
        Self {
            tx,
            counters,
            resource,
            start_ns: now_ns(),
        }
    }

    /// Records lost to a full queue or a failed export.
    #[cfg(test)]
    pub fn dropped_records(&self) -> u64 {
        self.dropped_queue_full()
            + self.dropped_disconnected()
            + self.counters.export_failed.load(Ordering::Relaxed)
    }

    pub fn dropped_disconnected(&self) -> u64 {
        self.counters.disconnected.load(Ordering::Relaxed)
    }

    pub fn dropped_queue_full(&self) -> u64 {
        self.counters.queue_full.load(Ordering::Relaxed)
    }

    pub fn dropped_export_failed(&self) -> u64 {
        self.counters.export_failed.load(Ordering::Relaxed)
    }
}

impl Otlp {
    /// Queues a metrics snapshot; shares the logs' queue and drop counts.
    pub fn metrics(&self, s: &MetricsSnapshot) {
        let body = metrics_body(&self.resource, self.start_ns, now_ns(), s);
        match self.tx.try_send(Job::Metrics(body)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.counters.queue_full.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.counters.disconnected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Sink for Otlp {
    fn emit(&self, rec: &TelemetryRecord) {
        match self.tx.try_send(Job::Log(log_record(rec))) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.counters.queue_full.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.counters.disconnected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn kv(k: &str, v: String) -> Value {
    json!({"key": k, "value": {"stringValue": v}})
}

fn kv_list(k: &str, v: &[String]) -> Value {
    let values: Vec<Value> = v.iter().map(|s| json!({"stringValue": s})).collect();
    json!({"key": k, "value": {"arrayValue": {"values": values}}})
}

fn resource() -> Value {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    json!({"attributes": [
        kv("service.name", "aegisd".into()),
        kv("service.version", env!("CARGO_PKG_VERSION").into()),
        kv("host.name", host),
    ]})
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// OTLP/JSON: int64 values travel as strings, enum 2 is cumulative.
fn metrics_body(resource: &Value, start_ns: u64, now_ns: u64, s: &MetricsSnapshot) -> Value {
    let point = |v: u64, attrs: Vec<Value>| {
        json!({
            "attributes": attrs,
            "startTimeUnixNano": start_ns.to_string(),
            "timeUnixNano": now_ns.to_string(),
            "asInt": v.to_string(),
        })
    };
    let sum = |name: &str, points: Vec<Value>| {
        json!({"name": name, "sum": {
            "dataPoints": points,
            "aggregationTemporality": 2,
            "isMonotonic": true,
        }})
    };
    let gauge =
        |name: &str, points: Vec<Value>| json!({"name": name, "gauge": {"dataPoints": points}});
    let by_verdict = s
        .incidents_by_verdict
        .iter()
        .map(|(v, n)| point(*n, vec![kv("verdict", v.clone())]))
        .collect();
    let mut metrics = vec![
        sum("aegis.events", vec![point(s.events_total, vec![])]),
        sum(
            "aegis.events.dropped",
            vec![point(s.dropped_events, vec![])],
        ),
        sum(
            "aegis.enforce.actions",
            vec![
                point(s.enforce_actions_ok, vec![kv("result", "ok".into())]),
                point(
                    s.enforce_actions_failed,
                    vec![kv("result", "failed".into())],
                ),
            ],
        ),
        sum(
            "aegis.telemetry.dropped",
            vec![point(s.telemetry_dropped, vec![])],
        ),
        gauge(
            "aegis.incidents.open",
            vec![point(s.incidents_open, vec![])],
        ),
        gauge("aegis.incidents", by_verdict),
    ];
    // Only once there is one: drop mode's metrics stay as they were.
    if s.honeypot_sessions != [0; 3] {
        let results = ["filed", "unmatched", "rejected"];
        let points = results
            .iter()
            .zip(s.honeypot_sessions)
            .map(|(r, n)| point(n, vec![kv("result", (*r).into())]))
            .collect();
        metrics.push(sum("aegis.honeypot.sessions", points));
    }
    json!({"resourceMetrics": [{
        "resource": resource,
        "scopeMetrics": [{"scope": {"name": "aegisd"}, "metrics": metrics}],
    }]})
}

fn envelope(resource: &Value, records: Vec<Value>) -> Value {
    json!({"resourceLogs": [{
        "resource": resource,
        "scopeLogs": [{"scope": {"name": "aegisd"}, "logRecords": records}],
    }]})
}

pub fn log_record(rec: &TelemetryRecord) -> Value {
    let (num, text) = match rec.tier {
        Tier::Log => (9, "INFO"),
        Tier::Throttle => (13, "WARN"),
        Tier::Quarantine => (17, "ERROR"),
    };
    let mut attrs = vec![
        kv("aegis.incident", rec.incident.clone()),
        kv("aegis.verdict", rec.verdict.into()),
        kv("aegis.tier", rec.tier_str().into()),
        kv("aegis.score", format!("{:.1}", rec.score)),
        kv("aegis.mode", rec.mode_str().into()),
        kv("aegis.tgid", rec.tgid.to_string()),
        kv("aegis.comm", rec.comm.clone()),
        kv("aegis.path", rec.exe_lossy()),
        kv("aegis.path_b64", rec.exe_b64()),
        kv_list("aegis.reasons", &rec.reasons),
    ];
    if let (Some(t), Some(t64)) = (rec.target_lossy(), rec.target_b64()) {
        attrs.push(kv("aegis.target", t));
        attrs.push(kv("aegis.target_b64", t64));
    }
    json!({
        "timeUnixNano": rec.ts_unix_ns.to_string(),
        "severityNumber": num,
        "severityText": text,
        "body": {"stringValue": rec.message()},
        "attributes": attrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn rec() -> TelemetryRecord {
        TelemetryRecord {
            ts_unix_ns: 0,
            incident: "AEG-1".into(),
            tier: Tier::Throttle,
            verdict: "would_throttle",
            score: 6.0,
            mode: Mode::Audit,
            tgid: 1,
            comm: "c".into(),
            exe: None,
            target: None,
            reasons: vec![],
        }
    }

    fn cfg(endpoint: String) -> OtlpConfig {
        OtlpConfig {
            endpoint,
            headers: BTreeMap::from([("Authorization".into(), "Bearer tok".into())]),
            timeout_secs: 2,
        }
    }

    #[test]
    fn log_record_carries_reasons_and_target() {
        let mut r = rec();
        r.target = Some(b"/tmp/p".to_vec());
        r.reasons = vec!["exec from a temp directory (/tmp/p)".into()];
        let v = log_record(&r);
        let attr = |k: &str| {
            v["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["key"] == k)
                .map(|a| a["value"].clone())
                .unwrap_or_else(|| panic!("{k} missing: {v}"))
        };
        assert_eq!(attr("aegis.target")["stringValue"], "/tmp/p");
        assert_eq!(attr("aegis.target_b64")["stringValue"], "L3RtcC9w");
        assert_eq!(
            attr("aegis.reasons")["arrayValue"]["values"][0]["stringValue"],
            "exec from a temp directory (/tmp/p)"
        );
        assert!(v["body"]["stringValue"]
            .as_str()
            .unwrap()
            .ends_with(" target /tmp/p"));
    }

    #[test]
    fn metrics_body_has_sums_and_gauges() {
        // Plain HTTP server that hands back the first request it gets.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = c.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                let t = String::from_utf8_lossy(&buf).into_owned();
                if let Some((h, b)) = t.split_once("\r\n\r\n") {
                    let len: usize = h
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if b.len() >= len {
                        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                        tx.send((h.to_string(), b.to_string())).unwrap();
                        return;
                    }
                }
            }
        });
        let sink = Otlp::new(&cfg(format!("http://127.0.0.1:{port}/v1/logs")));
        sink.metrics(&MetricsSnapshot {
            events_total: 7,
            dropped_events: 1,
            incidents_open: 2,
            incidents_by_verdict: BTreeMap::from([("would_throttle".into(), 2)]),
            enforce_actions_ok: 3,
            enforce_actions_failed: 4,
            telemetry_dropped: 5,
            honeypot_sessions: [0; 3],
        });
        let (head, body) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(head.starts_with("POST /v1/metrics "), "{head}");
        let v: Value = serde_json::from_str(&body).unwrap();
        let ms = v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap();
        let m = |n: &str| {
            ms.iter()
                .find(|m| m["name"] == n)
                .unwrap_or_else(|| panic!("{n}"))
        };
        for n in [
            "aegis.events",
            "aegis.events.dropped",
            "aegis.enforce.actions",
            "aegis.telemetry.dropped",
        ] {
            assert_eq!(m(n)["sum"]["isMonotonic"], true, "{n}");
            assert_eq!(m(n)["sum"]["aggregationTemporality"], 2, "{n}");
        }
        let ev = &m("aegis.events")["sum"]["dataPoints"][0];
        assert_eq!(ev["asInt"], "7");
        assert!(ev["startTimeUnixNano"].is_string() && ev["timeUnixNano"].is_string());
        let acts = m("aegis.enforce.actions")["sum"]["dataPoints"].to_string();
        assert!(
            acts.contains(r#""stringValue":"ok""#) && acts.contains(r#""stringValue":"failed""#),
            "{acts}"
        );
        assert_eq!(
            m("aegis.incidents.open")["gauge"]["dataPoints"][0]["asInt"],
            "2"
        );
        let by = &m("aegis.incidents")["gauge"]["dataPoints"][0];
        assert_eq!(by["attributes"][0]["key"], "verdict");
        assert_eq!(
            by["attributes"][0]["value"]["stringValue"],
            "would_throttle"
        );
        assert_eq!(sink.dropped_records(), 0);
    }

    #[test]
    fn otlp_sink_unreachable_does_not_block() {
        // Bind then drop to get a port nothing listens on.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let sink = Otlp::new(&cfg(format!("http://127.0.0.1:{port}")));
        let r = rec();
        let t = Instant::now();
        for _ in 0..10_000 {
            sink.emit(&r);
        }
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        let t = Instant::now();
        while sink.dropped_records() == 0 && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(sink.dropped_records() > 0);
    }

    #[test]
    fn stalled_collector_fills_queue_and_counts_drops() {
        // Accepts connections (kernel backlog) but never answers.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let sink = Otlp::new(&cfg(format!("http://{}", l.local_addr().unwrap())));
        let r = rec();
        let t = Instant::now();
        for _ in 0..10_000 {
            sink.emit(&r);
        }
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        // At most QUEUE + BATCH (+1 in flight) records can be held.
        let full = sink.dropped_queue_full();
        assert!(full >= 10_000 - (QUEUE + BATCH + 1) as u64, "{full}");
        drop(l);
    }

    /// One-connection-at-a-time HTTPS server; sends each request body
    /// and header block over the channel.
    fn tls_server(
        cert_pem: &str,
        key_der: Vec<u8>,
        cert_der: Vec<u8>,
    ) -> (u16, mpsc::Receiver<(String, String)>) {
        let _ = cert_pem;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let sc = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der.into()],
                rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap(),
            )
            .unwrap();
        let sc = Arc::new(sc);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for tcp in l.incoming() {
                let mut tcp = tcp.unwrap();
                let mut conn = rustls::ServerConnection::new(sc.clone()).unwrap();
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let body = loop {
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some((h, b)) = text.split_once("\r\n\r\n") {
                        let len: usize = h
                            .lines()
                            .find_map(|l| {
                                l.to_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(str::to_owned)
                            })
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        if b.len() >= len {
                            break Some((h.to_string(), b.to_string()));
                        }
                    }
                };
                if let Some(r) = body {
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                    let _ = tx.send(r);
                }
            }
        });
        (port, rx)
    }

    #[test]
    fn https_batch_with_headers_and_ca_trust() {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let (port, rx) = tls_server(
            &ck.cert.pem(),
            ck.signing_key.serialize_der(),
            ck.cert.der().to_vec(),
        );
        let endpoint = format!("https://127.0.0.1:{port}");

        // Untrusted self-signed cert: handshake fails, records are counted.
        let bad = Otlp::new(&cfg(endpoint.clone()));
        bad.emit(&rec());
        let t = Instant::now();
        while bad.dropped_records() == 0 && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(bad.dropped_records(), 1);
        assert!(rx.try_recv().is_err());

        // Trusted: three records arrive in one POST.
        let root = ureq::tls::Certificate::from_pem(ck.cert.pem().as_bytes()).unwrap();
        let sink = Otlp::with_roots(&cfg(endpoint), RootCerts::new_with_certs(&[root]));
        for _ in 0..3 {
            sink.emit(&rec());
        }
        let (head, body) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(head.starts_with("POST /v1/logs "), "{head}");
        assert!(head.to_lowercase().contains("authorization: bearer tok"));
        let v: Value = serde_json::from_str(&body).unwrap();
        let attrs = v["resourceLogs"][0]["resource"]["attributes"].to_string();
        for k in ["service.name", "service.version", "host.name"] {
            assert!(attrs.contains(k), "{attrs}");
        }
        assert_eq!(
            v["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(sink.dropped_records(), 0);
    }

    #[test]
    fn honeypot_sessions_are_a_metric_only_once_there_are_some() {
        let mut s = MetricsSnapshot {
            events_total: 0,
            dropped_events: 0,
            incidents_open: 0,
            incidents_by_verdict: BTreeMap::new(),
            enforce_actions_ok: 0,
            enforce_actions_failed: 0,
            telemetry_dropped: 0,
            honeypot_sessions: [0; 3],
        };
        let names = |s: &MetricsSnapshot| -> Vec<Value> {
            metrics_body(&json!({}), 0, 0, s)["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
                .as_array()
                .unwrap()
                .clone()
        };
        let drop_mode = names(&s);
        assert!(!drop_mode
            .iter()
            .any(|m| m["name"] == "aegis.honeypot.sessions"));
        s.honeypot_sessions = [3, 2, 1];
        let all = names(&s);
        assert_eq!(all.len(), drop_mode.len() + 1);
        let pts = &all.last().unwrap()["sum"]["dataPoints"];
        assert_eq!(pts[0]["asInt"], "3");
        assert_eq!(pts[2]["attributes"][0]["value"]["stringValue"], "rejected");
    }
}
