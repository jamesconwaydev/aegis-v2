// SPDX-License-Identifier: MIT OR Apache-2.0
//! OTLP logs over HTTP(S) with a JSON body (`POST <endpoint>/v1/logs`).
//!
//! `emit` never blocks: records go through a bounded channel to one
//! worker thread, which sends up to `BATCH` records (or one second's
//! worth) per POST. When the channel is full the record is dropped and
//! counted. TLS is rustls, trusting the system CA bundle (on Rocky,
//! /etc/pki/tls/certs/ca-bundle.crt, or `SSL_CERT_FILE`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

pub struct Otlp {
    tx: SyncSender<Value>,
    counters: Arc<Counters>,
}

impl Otlp {
    pub fn new(cfg: &OtlpConfig) -> Self {
        Self::with_roots(cfg, RootCerts::PlatformVerifier)
    }

    pub fn with_roots(cfg: &OtlpConfig, roots: RootCerts) -> Self {
        let (tx, rx) = sync_channel::<Value>(QUEUE);
        let counters = Arc::new(Counters::default());
        let c = counters.clone();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(cfg.timeout_secs)))
            .tls_config(TlsConfig::builder().root_certs(roots).build())
            .build()
            .into();
        let url = if cfg.endpoint.trim_end_matches('/').ends_with("/v1/logs") {
            cfg.endpoint.clone()
        } else {
            format!("{}/v1/logs", cfg.endpoint.trim_end_matches('/'))
        };
        let headers = cfg.headers.clone();
        let resource = resource();
        std::thread::spawn(move || {
            let mut failing = false;
            while let Ok(first) = rx.recv() {
                let mut batch = vec![first];
                let deadline = Instant::now() + FLUSH;
                while batch.len() < BATCH {
                    match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                        Ok(r) => batch.push(r),
                        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
                    }
                }
                let n = batch.len() as u64;
                let body = envelope(&resource, batch).to_string();
                let mut req = agent.post(&url).header("Content-Type", "application/json");
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
            }
        });
        Self { tx, counters }
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

impl Sink for Otlp {
    fn emit(&self, rec: &TelemetryRecord) {
        match self.tx.try_send(log_record(rec)) {
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
    use std::collections::BTreeMap;
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
}
