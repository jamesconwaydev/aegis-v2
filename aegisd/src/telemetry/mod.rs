// SPDX-License-Identifier: MIT OR Apache-2.0
//! Telemetry sinks. Every sink is best effort: a failing sink logs to
//! stderr and never stops the pipeline.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{Mode, TelemetryConfig};
use crate::scoring::Tier;

pub mod journald;
pub mod jsonl;
pub mod otlp;
pub mod webhook;

pub struct TelemetryRecord {
    pub ts_unix_ns: u64,
    pub incident: String,
    pub tier: Tier,
    pub verdict: &'static str,
    pub score: f64,
    pub mode: Mode,
    pub tgid: u32,
    pub comm: String,
    /// Exact path bytes. Emitted as lossy `path` plus exact `path_b64`.
    pub exe: Option<Vec<u8>>,
    /// For an exec, the file it started, exact bytes like `exe`.
    pub target: Option<Vec<u8>>,
    /// The process's evidence reasons, oldest first.
    pub reasons: Vec<String>,
}

impl TelemetryRecord {
    pub fn exe_lossy(&self) -> String {
        self.exe
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    }

    pub fn exe_b64(&self) -> String {
        self.exe.as_deref().map(b64).unwrap_or_default()
    }

    pub fn target_lossy(&self) -> Option<String> {
        self.target
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }

    pub fn target_b64(&self) -> Option<String> {
        self.target.as_deref().map(b64)
    }

    /// One line, whatever the process called itself: comm, exe and the
    /// target are escaped (the exact bytes are in the `*_B64` fields).
    pub fn message(&self) -> String {
        let mut m = format!(
            "aegis {} incident {} score {:.1} tgid {} comm {} exe {}",
            self.verdict,
            self.incident,
            self.score,
            self.tgid,
            aegis_proto::clean(&self.comm),
            aegis_proto::clean(&self.exe_lossy())
        );
        if let Some(t) = self.target_lossy() {
            m += &format!(" target {}", aegis_proto::clean(&t));
        }
        m
    }

    pub fn tier_str(&self) -> &'static str {
        match self.tier {
            Tier::Log => "log",
            Tier::Throttle => "throttle",
            Tier::Quarantine => "quarantine",
        }
    }

    pub fn mode_str(&self) -> &'static str {
        mode_str(self.mode)
    }
}

pub trait Sink: Send + Sync {
    fn emit(&self, rec: &TelemetryRecord);
}

/// The configured sinks. journald is always on; the others follow the
/// config.
pub struct Sinks {
    journald: journald::Journald,
    jsonl: Option<jsonl::JsonLines>,
    otlp: Option<otlp::Otlp>,
    webhooks: Vec<webhook::Webhook>,
}

impl Sinks {
    pub fn new(cfg: &TelemetryConfig) -> Self {
        let jsonl = cfg.jsonl.as_ref().and_then(|p| {
            jsonl::JsonLines::open(p)
                .inspect_err(|e| eprintln!("aegisd: telemetry jsonl {}: {e}", p.display()))
                .ok()
        });
        Self {
            journald: journald::Journald::new(),
            jsonl,
            otlp: cfg.otlp.as_ref().map(otlp::Otlp::new),
            webhooks: cfg
                .webhook
                .iter()
                .filter_map(|w| {
                    webhook::Webhook::new(w)
                        .inspect_err(|e| eprintln!("aegisd: telemetry webhook: {e:#}"))
                        .ok()
                })
                .collect(),
        }
    }

    /// No journal, no extras: for tests.
    #[cfg(test)]
    pub fn none() -> Self {
        Self {
            journald: journald::Journald::with_socket(None),
            jsonl: None,
            otlp: None,
            webhooks: vec![],
        }
    }

    /// Only a JSON lines file at `p`: for tests that read the records.
    #[cfg(test)]
    pub fn jsonl_at(p: &std::path::Path) -> Self {
        Self {
            journald: journald::Journald::with_socket(None),
            jsonl: Some(jsonl::JsonLines::open(p).unwrap()),
            otlp: None,
            webhooks: vec![],
        }
    }

    pub fn emit(&self, rec: &TelemetryRecord) {
        self.journald.emit(rec);
        if let Some(s) = &self.jsonl {
            s.emit(rec);
        }
        if let Some(s) = &self.otlp {
            s.emit(rec);
        }
        for w in &self.webhooks {
            w.emit(rec);
        }
    }

    /// True when metrics have somewhere to go.
    pub fn exports_metrics(&self) -> bool {
        self.otlp.is_some()
    }

    pub fn metrics(&self, s: &otlp::MetricsSnapshot) {
        if let Some(o) = &self.otlp {
            o.metrics(s);
        }
    }

    pub fn dropped(&self) -> aegis_proto::TelemetryDropped {
        let o = self.otlp.as_ref();
        aegis_proto::TelemetryDropped {
            journald: self.journald.dropped_records(),
            otlp_queue_full: o.map_or(0, |o| o.dropped_queue_full()),
            otlp_export_failed: o.map_or(0, |o| o.dropped_export_failed()),
            otlp_disconnected: o.map_or(0, |o| o.dropped_disconnected()),
            webhook_queue_full: self.webhooks.iter().map(|w| w.dropped_queue_full()).sum(),
            webhook_failed: self.webhooks.iter().map(|w| w.dropped_failed()).sum(),
        }
    }
}

pub fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::Audit => "audit",
        Mode::Enforce => "enforce",
    }
}

pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// Standard base64 with padding.
pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `2026-10-18T09:30:00Z`
pub fn rfc3339(ts_ns: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(ts_ns / 1_000_000_000);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Seconds since the epoch of an `rfc3339` timestamp.
pub fn unix_secs(ts: &str) -> Option<u64> {
    let b = ts.as_bytes();
    let shape = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'Z'),
    ];
    if b.len() != 20 || shape.iter().any(|&(i, c)| b[i] != c) {
        return None;
    }
    let n = |i: usize, w: usize| -> Option<u64> {
        let s = &ts[i..i + w];
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    let (y, mo, d) = (n(0, 4)?, n(5, 2)?, n(8, 2)?);
    let (h, mi, s) = (n(11, 2)?, n(14, 2)?, n(17, 2)?);
    if y < 1970 || !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60
    {
        return None;
    }
    // Civil date to days, after Howard Hinnant, as `civil` inverted.
    let y = if mo <= 2 { y - 1 } else { y };
    let (era, yoe) = (y / 400, y % 400);
    let doy = (153 * ((mo + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    Some(days * 86400 + h * 3600 + mi * 60 + s)
}

/// (year, month, day, hour, minute, second) in UTC.
pub fn civil(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    // Days to civil date, after Howard Hinnant.
    let z = secs / 86400 + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as u64;
    let r = secs % 86400;
    (y, m, d, r / 3600, r % 3600 / 60, r % 60)
}

#[cfg(test)]
pub(crate) fn unb64(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    } as u32;
    let mut out = Vec::new();
    for c in s.as_bytes().chunks(4) {
        let pad = c.iter().filter(|&&b| b == b'=').count();
        let n = c[..4 - pad].iter().fold(0, |a, &b| a << 6 | val(b)) << (6 * pad);
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_dates() {
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foob"), "Zm9vYg==");
        assert_eq!(unb64(&b64(b"\xff\x00a\n")), b"\xff\x00a\n");
        assert_eq!(rfc3339(1_781_775_000_000_000_000), "2026-06-18T09:30:00Z");
        assert_eq!(rfc3339(951_782_400_000_000_000), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn rfc3339_reads_back() {
        assert_eq!(unix_secs("2026-06-18T09:30:00Z"), Some(1_781_775_000));
        for s in [0, 951_782_400, 1_781_775_000, 4_102_444_799] {
            assert_eq!(unix_secs(&rfc3339(s * 1_000_000_000)), Some(s), "{s}");
        }
        for bad in [
            "",
            "2026-06-18",
            "2026-13-01T00:00:00Z",
            "x026-06-18T09:30:00Z",
        ] {
            assert_eq!(unix_secs(bad), None, "{bad}");
        }
    }
}
