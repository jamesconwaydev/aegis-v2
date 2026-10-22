// SPDX-License-Identifier: MIT OR Apache-2.0
//! Webhooks: one POST when an incident first reaches throttle, one when
//! it first reaches quarantine, and one for every enforcement failure.
//!
//! `emit` never blocks. Each webhook has a queue of `QUEUE` bodies and
//! one worker thread; a body gets up to `ATTEMPTS` tries with `BACKOFF`
//! between them. A full queue drops and counts the new record.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use serde_json::json;
use ureq::tls::{RootCerts, TlsConfig};

use super::{rfc3339, Sink, TelemetryRecord};
use crate::config::{WebhookConfig, WebhookFormat};
use crate::scoring::Tier;

pub const QUEUE: usize = 256;
const ATTEMPTS: usize = 3;
const BACKOFF: [Duration; ATTEMPTS - 1] = [Duration::from_secs(1), Duration::from_secs(2)];
/// Incidents remembered for the tier-rise check.
const MAX_TRACKED: usize = 4096;

#[derive(Default)]
struct Counters {
    queue_full: AtomicU64,
    /// Bodies that failed every attempt, or lost to a dead worker.
    failed: AtomicU64,
}

pub struct Webhook {
    tx: SyncSender<String>,
    counters: Arc<Counters>,
    format: WebhookFormat,
    /// Highest tier already sent per incident.
    // ponytail: cleared when full, so a very old incident may notify
    // again; keep it in the incident store if that ever matters.
    sent: Mutex<HashMap<String, Tier>>,
}

impl Webhook {
    pub fn new(cfg: &WebhookConfig) -> anyhow::Result<Self> {
        Self::with_backoff(cfg, BACKOFF)
    }

    fn with_backoff(
        cfg: &WebhookConfig,
        backoff: [Duration; ATTEMPTS - 1],
    ) -> anyhow::Result<Self> {
        let (tx, rx) = sync_channel::<String>(QUEUE);
        let counters = Arc::new(Counters::default());
        let c = counters.clone();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(cfg.timeout_secs)))
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .into();
        let (url, headers) = (cfg.url.clone(), cfg.headers.clone());
        std::thread::Builder::new()
            .name("aegis-webhook".into())
            .spawn(move || {
                let mut failing = false;
                while let Ok(body) = rx.recv() {
                    let mut last = None;
                    for i in 0..ATTEMPTS {
                        let mut req = agent.post(&url).header("Content-Type", "application/json");
                        for (k, v) in &headers {
                            req = req.header(k, v);
                        }
                        match req.send(&body) {
                            Ok(_) => {
                                last = None;
                                break;
                            }
                            Err(e) => last = Some(e),
                        }
                        if let Some(d) = backoff.get(i) {
                            std::thread::sleep(*d);
                        }
                    }
                    match last {
                        None => failing = false,
                        Some(e) => {
                            c.failed.fetch_add(1, Ordering::Relaxed);
                            // Log the transition only. The URL can be a
                            // secret (Slack), so it is not in the message.
                            if !failing {
                                eprintln!(
                                    "aegisd: webhook failing, dropping records: {}",
                                    error_kind(&e)
                                );
                            }
                            failing = true;
                        }
                    }
                }
            })
            .context("starting the webhook thread")?;
        Ok(Self {
            tx,
            counters,
            format: cfg.format,
            sent: Mutex::default(),
        })
    }

    pub fn dropped_queue_full(&self) -> u64 {
        self.counters.queue_full.load(Ordering::Relaxed)
    }

    pub fn dropped_failed(&self) -> u64 {
        self.counters.failed.load(Ordering::Relaxed)
    }

    /// Enforcement failures always go; anything else only when its tier
    /// is higher than any already sent for the incident.
    fn worth_sending(&self, rec: &TelemetryRecord) -> bool {
        if is_failure(rec) {
            return true;
        }
        if rec.tier < Tier::Throttle {
            return false;
        }
        let mut sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
        if sent.len() >= MAX_TRACKED && !sent.contains_key(&rec.incident) {
            sent.clear();
        }
        if sent.get(&rec.incident).is_some_and(|t| *t >= rec.tier) {
            return false;
        }
        sent.insert(rec.incident.clone(), rec.tier);
        true
    }

    fn body(&self, rec: &TelemetryRecord) -> String {
        match self.format {
            WebhookFormat::Slack => {
                let mut text = rec.message();
                if is_failure(rec) {
                    text += &format!(": {}", aegis_proto::clean(&rec.reasons[0]));
                }
                json!({ "text": text })
            }
            WebhookFormat::Json => json!({
                "incident": rec.incident,
                "verdict": rec.verdict,
                "score": rec.score,
                "mode": rec.mode_str(),
                "tgid": rec.tgid,
                "comm": rec.comm,
                "exe": rec.exe_lossy(),
                "reasons": rec.reasons,
                "ts": rfc3339(rec.ts_unix_ns),
            }),
        }
        .to_string()
    }
}

/// What went wrong, without anything that could carry the request URL:
/// ureq's Display for `Http`, `BadUri`, `RequireHttpsOnly` and `Other`
/// can quote it. The status code, the io error kind or the variant name
/// is enough to act on.
pub fn error_kind(e: &ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(c) => format!("http status {c}"),
        ureq::Error::Io(e) => format!("io: {:?}", e.kind()),
        ureq::Error::Timeout(t) => format!("timeout: {t}"),
        other => {
            let d = format!("{other:?}");
            d.split(['(', ' ']).next().unwrap_or("error").to_string()
        }
    }
}

/// The enforcer's reports start `enforcement failed:` or `enforcement
/// skipped:` in the first reason.
fn is_failure(rec: &TelemetryRecord) -> bool {
    rec.reasons
        .first()
        .is_some_and(|r| r.starts_with("enforcement "))
}

impl Sink for Webhook {
    fn emit(&self, rec: &TelemetryRecord) {
        if !self.worth_sending(rec) {
            return;
        }
        match self.tx.try_send(self.body(rec)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.counters.queue_full.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.counters.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;
    use serde_json::Value;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Instant;

    fn rec(incident: &str, tier: Tier) -> TelemetryRecord {
        TelemetryRecord {
            ts_unix_ns: 1_000_000_000,
            incident: incident.into(),
            tier,
            verdict: if tier == Tier::Quarantine {
                "would_quarantine"
            } else {
                "would_throttle"
            },
            score: 6.0,
            mode: Mode::Audit,
            tgid: 7,
            comm: "c".into(),
            exe: Some(b"/tmp/x".to_vec()),
            target: None,
            reasons: vec!["exec from a temp directory (/tmp/x)".into()],
        }
    }

    fn cfg(url: String, format: WebhookFormat) -> WebhookConfig {
        WebhookConfig {
            url,
            format,
            headers: [("X-Token".to_string(), "t".to_string())].into(),
            timeout_secs: 2,
        }
    }

    /// Answers 200 to each request; sends (head, body) over the channel.
    fn server() -> (String, mpsc::Receiver<(String, String)>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", l.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for tcp in l.incoming() {
                let mut tcp = tcp.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let got = loop {
                    match tcp.read(&mut chunk) {
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
                if let Some(r) = got {
                    let _ = tcp.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    let _ = tx.send(r);
                }
            }
        });
        (url, rx)
    }

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn webhook_posts_json_on_tier_rise() {
        let (url, rx) = server();
        let w = Webhook::new(&cfg(url, WebhookFormat::Json)).unwrap();
        w.emit(&rec("AEG-1", Tier::Throttle));
        let (head, body) = rx.recv_timeout(WAIT).unwrap();
        assert!(head.starts_with("POST /hook "), "{head}");
        assert!(head.to_lowercase().contains("x-token: t"));
        assert!(head
            .to_lowercase()
            .contains("content-type: application/json"));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v,
            json!({
                "incident": "AEG-1", "verdict": "would_throttle", "score": 6.0,
                "mode": "audit", "tgid": 7, "comm": "c", "exe": "/tmp/x",
                "reasons": ["exec from a temp directory (/tmp/x)"],
                "ts": "1970-01-01T00:00:01Z",
            })
        );
        // The rise to quarantine sends again.
        w.emit(&rec("AEG-1", Tier::Quarantine));
        let (_, body) = rx.recv_timeout(WAIT).unwrap();
        assert!(body.contains("would_quarantine"), "{body}");
    }

    #[test]
    fn webhook_slack_format_has_text_only() {
        let (url, rx) = server();
        let w = Webhook::new(&cfg(url, WebhookFormat::Slack)).unwrap();
        let r = rec("AEG-1", Tier::Throttle);
        w.emit(&r);
        let (_, body) = rx.recv_timeout(WAIT).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({ "text": r.message() })
        );
    }

    #[test]
    fn webhook_skips_repeat_at_same_tier() {
        let (url, rx) = server();
        let w = Webhook::new(&cfg(url, WebhookFormat::Json)).unwrap();
        w.emit(&rec("AEG-1", Tier::Throttle));
        w.emit(&rec("AEG-1", Tier::Throttle));
        w.emit(&rec("AEG-1", Tier::Log));
        w.emit(&rec("AEG-2", Tier::Log));
        w.emit(&rec("AEG-3", Tier::Throttle));
        // Only AEG-1 and AEG-3 get through, in order.
        let first = rx.recv_timeout(WAIT).unwrap().1;
        let second = rx.recv_timeout(WAIT).unwrap().1;
        assert!(first.contains("AEG-1") && second.contains("AEG-3"));
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
        // A throttle after quarantine is not a rise either.
        w.emit(&rec("AEG-3", Tier::Quarantine));
        w.emit(&rec("AEG-3", Tier::Throttle));
        rx.recv_timeout(WAIT).unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    }

    #[test]
    fn webhook_enforcement_failure_always_sends() {
        let (url, rx) = server();
        let w = Webhook::new(&cfg(url, WebhookFormat::Slack)).unwrap();
        w.emit(&rec("AEG-1", Tier::Quarantine));
        rx.recv_timeout(WAIT).unwrap();
        for _ in 0..2 {
            let mut f = rec("AEG-1", Tier::Quarantine);
            f.reasons = vec!["enforcement failed: nft: no table".into()];
            w.emit(&f);
            let (_, body) = rx.recv_timeout(WAIT).unwrap();
            assert!(body.contains("enforcement failed: nft: no table"), "{body}");
        }
    }

    #[test]
    fn webhook_queue_full_counts_and_drops() {
        // Accepts connections but never answers.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let w = Webhook::new(&cfg(
            format!("http://{}/", l.local_addr().unwrap()),
            WebhookFormat::Json,
        ))
        .unwrap();
        let t = Instant::now();
        // The worker holds one body, the queue 256; more than 257 sends
        // are needed to be sure of an overflow.
        for i in 0..300 {
            w.emit(&rec(&format!("AEG-{i}"), Tier::Throttle));
        }
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        assert!(w.dropped_queue_full() >= 1);
        drop(l);
    }

    #[test]
    fn webhook_failed_after_all_attempts_is_counted() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let w = Webhook::with_backoff(
            &cfg(format!("http://127.0.0.1:{port}/"), WebhookFormat::Json),
            [Duration::from_millis(10); ATTEMPTS - 1],
        )
        .unwrap();
        w.emit(&rec("AEG-1", Tier::Throttle));
        let t = Instant::now();
        while w.dropped_failed() == 0 && t.elapsed() < WAIT {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(w.dropped_failed(), 1);
    }

    #[test]
    fn failure_log_text_never_carries_the_url_path() {
        const PATH: &str = "/services/T000/B000/XXXX";
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let refused = ureq::get(format!("http://127.0.0.1:{port}{PATH}?k=XXXX"))
            .call()
            .unwrap_err();
        // A server that answers 500.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}{PATH}?k=XXXX", l.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((mut t, _)) = l.accept() {
                let _ = t.read(&mut [0u8; 1024]);
                let _ = t.write_all(
                    b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let status = ureq::get(&url).call().unwrap_err();
        assert_eq!(error_kind(&status), "http status 500");
        // Other variants that quote a URL in ureq's Display.
        let quoting = [
            ureq::Error::BadUri(format!("http://h{PATH}")),
            ureq::Error::RequireHttpsOnly(format!("http://h{PATH}")),
            ureq::Error::Other(format!("http://h{PATH}").into()),
        ];
        for e in std::iter::once(refused).chain(quoting) {
            let k = error_kind(&e);
            assert!(!k.contains("XXXX") && !k.contains("services"), "{k}");
        }
        assert!(error_kind(&status).find("XXXX").is_none());
    }

    #[test]
    fn webhook_url_with_credentials_rejected() {
        let c = cfg("https://user:pw@h/x".into(), WebhookFormat::Json);
        assert!(c.validate().unwrap_err().contains("user:pass@"));
    }
}
