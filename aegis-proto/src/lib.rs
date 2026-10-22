// SPDX-License-Identifier: MIT OR Apache-2.0
//! The aegisd control protocol.
//!
//! Newline-delimited JSON over `/run/aegis-v2/aegisd.sock`. A client
//! writes one `Request` per line and reads one `Response` line back,
//! as many times as it likes on one connection. A request line longer
//! than `MAX_REQUEST` bytes is refused and the connection closed. Only
//! root may connect; anyone else gets `{"error":"permission denied"}`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SOCKET: &str = "/run/aegis-v2/aegisd.sock";

/// Longest request line, newline excluded.
pub const MAX_REQUEST: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Request {
    Status,
    IncidentsList,
    IncidentShow {
        id: String,
    },
    IncidentTimeline {
        id: String,
    },
    /// Thaw a quarantined tree and restore its network, or lift a
    /// throttle's limits. From v0.2.0.
    IncidentRelease {
        id: String,
    },
    /// SIGKILL a quarantined tree. From v0.2.0.
    IncidentKill {
        id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Response {
    Status {
        version: String,
        mode: String,
        uptime_s: u64,
        /// Probe events the daemon has processed.
        events_total: u64,
        /// Events the probes could not fit in the kernel ring buffer.
        dropped_events: u64,
        probes: Vec<ProbeStatus>,
        incidents_open: u64,
        /// `IncidentStore` writes that failed.
        incident_errors: u64,
        /// Decisions dropped because the incident writer's queue was full.
        incident_dropped: u64,
        /// Execs left unverified because the verification backlog was full.
        verify_skipped: u64,
        /// Signals scored as unverified because a defer queue (one
        /// process's, or the global one) overflowed.
        deferred_overflow: u64,
        /// Decisions inside an open incident that were not recorded or
        /// sent to telemetry because they added nothing new.
        #[serde(default)]
        incident_suppressed: u64,
        /// Enforcement jobs dropped because the enforcer's queue was full.
        #[serde(default)]
        enforce_dropped: u64,
        telemetry_dropped: TelemetryDropped,
    },
    Incidents(Vec<IncidentSummary>),
    /// The incident's `incident.json`.
    Incident(Value),
    /// The incident's `timeline.jsonl`, one value per line.
    Timeline(Vec<Value>),
    /// What a release or kill did, one line.
    Done(String),
    #[serde(rename = "error")]
    Error(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeStatus {
    pub name: String,
    /// Where it is attached, e.g. `lsm/bprm_committed_creds`.
    pub hook: String,
}

/// Telemetry records lost, per sink and cause.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TelemetryDropped {
    pub journald: u64,
    pub otlp_queue_full: u64,
    pub otlp_export_failed: u64,
    pub otlp_disconnected: u64,
    #[serde(default)]
    pub webhook_queue_full: u64,
    #[serde(default)]
    pub webhook_failed: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentSummary {
    pub id: String,
    pub created: String,
    pub updated: String,
    pub verdict: String,
    pub max_score: f64,
    pub root_tgid: u32,
    /// Enforcer actions recorded so far; 0 from a pre-v0.2 daemon.
    #[serde(default)]
    pub actions: usize,
}

/// Whether `id` has the shape of an incident id,
/// `AEG-<YYYYMMDD>-<HHMMSS>-<16 lowercase hex>`. Ids name directories,
/// so nothing else is ever looked up.
pub fn is_incident_id(id: &str) -> bool {
    let b = id.as_bytes();
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    b.len() == 36
        && b.starts_with(b"AEG-")
        && digits(4..12)
        && b[12] == b'-'
        && digits(13..19)
        && b[19] == b'-'
        && b[20..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// Makes daemon- and attacker-supplied text safe to print or log on one
/// line: control characters (C0, DEL, C1), line and paragraph
/// separators, and bidi, zero-width and invisible marks become visible
/// escapes like `\x1b` or `\u{202e}`.
pub fn clean(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        let bad = c.is_control()
            || matches!(
                c,
                '\u{061c}'
                    | '\u{180e}'
                    | '\u{200b}'..='\u{200f}'
                    | '\u{2028}'..='\u{202e}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{feff}'
            );
        if !bad {
            o.push(c);
        } else if (c as u32) < 0x100 {
            o += &format!("\\x{:02x}", c as u32);
        } else {
            o += &format!("\\u{{{:x}}}", c as u32);
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_and_kill_wire_format() {
        let r: Request = serde_json::from_str(r#"{"IncidentKill":{"id":"AEG-1"}}"#).unwrap();
        assert_eq!(r, Request::IncidentKill { id: "AEG-1".into() });
        let line = serde_json::to_string(&Response::Done("killed AEG-1".into())).unwrap();
        assert_eq!(line, r#"{"Done":"killed AEG-1"}"#);
    }

    #[test]
    fn wire_format() {
        let r: Request = serde_json::from_str(r#""Status""#).unwrap();
        assert_eq!(r, Request::Status);
        let r: Request = serde_json::from_str(r#"{"Status":null}"#).unwrap();
        assert_eq!(r, Request::Status);
        let r: Request = serde_json::from_str(r#"{"IncidentShow":{"id":"AEG-1"}}"#).unwrap();
        assert_eq!(r, Request::IncidentShow { id: "AEG-1".into() });
        assert_eq!(
            serde_json::to_string(&Response::Error("permission denied".into())).unwrap(),
            r#"{"error":"permission denied"}"#
        );
    }

    #[test]
    fn incident_ids() {
        assert!(is_incident_id("AEG-20261018-093000-0123456789abcdef"));
        for bad in [
            "AEG-20261018-093000-a1b2",
            "AEG-20261018-093000-0123456789ABCDEF",
            "AEG-2026101x-093000-0123456789abcdef",
            "AEG-20261018_093000-0123456789abcdef",
            "../20261018-093000-0123456789abcdef",
            "AEG-20261018-093000-0123456789abcdef0",
            "",
        ] {
            assert!(!is_incident_id(bad), "{bad}");
        }
    }

    #[test]
    fn clean_escapes_controls_separators_and_invisibles() {
        assert_eq!(clean("a\nb\x1b[2J"), "a\\x0ab\\x1b[2J");
        for (c, esc) in [
            ('\u{061c}', "\\u{61c}"),
            ('\u{180e}', "\\u{180e}"),
            ('\u{2028}', "\\u{2028}"),
            ('\u{2029}', "\\u{2029}"),
            ('\u{202e}', "\\u{202e}"),
            ('\u{200b}', "\\u{200b}"),
            ('\u{0085}', "\\x85"),
        ] {
            assert_eq!(clean(&format!("x{c}y")), format!("x{esc}y"));
        }
        assert_eq!(clean("plain /usr/bin/ünï"), "plain /usr/bin/ünï");
    }
}
