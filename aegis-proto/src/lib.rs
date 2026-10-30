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

pub mod honeypot;
mod listen;
pub use listen::honeypot_listening;

pub const SOCKET: &str = "/run/aegis-v2/aegisd.sock";

/// Longest request line, newline excluded.
pub const MAX_REQUEST: usize = 64 * 1024;
/// How long aegisctl waits for a whole reply. A daemon-side wait that
/// answers the client must finish well inside it.
pub const REPLY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

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
    /// Every honeypot session's packets as one pcap. From v0.3.0.
    IncidentPcap {
        id: String,
    },
    /// A STIX 2.1 bundle of what the incident saw. From v0.3.0.
    IncidentStix {
        id: String,
    },
}

fn default_network() -> String {
    "drop".into()
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
        /// `drop` or `honeypot`: what quarantine does with the network.
        /// Absent from a pre-v0.3 daemon, which only drops.
        #[serde(default = "default_network")]
        network: String,
        /// Incidents being observed in the honeypot right now.
        #[serde(default)]
        incidents_observing: u64,
        telemetry_dropped: TelemetryDropped,
    },
    Incidents(Vec<IncidentSummary>),
    /// The incident's `incident.json`.
    Incident(Value),
    /// The incident's `timeline.jsonl`, one value per line.
    Timeline(Vec<Value>),
    /// What a release or kill did, one line.
    Done(String),
    /// The answer to `IncidentPcap`: exactly `bytes` bytes of pcap follow
    /// this line on the socket, then the next reply. `sessions` were
    /// merged and `left_out` were not; `notes` says why, one reason a
    /// line.
    Pcap {
        bytes: u64,
        sessions: u64,
        left_out: u64,
        #[serde(default)]
        notes: Vec<String>,
    },
    /// The answer to `IncidentStix`.
    Stix(Value),
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
    /// What enforcement left in place now: `throttled`, `quarantined`,
    /// `held`, `released`, `killed` or `expired`. None if nothing was
    /// enforced (audit mode), or from a pre-v0.2.1 daemon.
    #[serde(default)]
    pub state: Option<String>,
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
        if !unsafe_char(c) {
            o.push(c);
        } else if (c as u32) < 0x100 {
            o += &format!("\\x{:02x}", c as u32);
        } else {
            o += &format!("\\u{{{:x}}}", c as u32);
        }
    }
    o
}

fn unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2069}'
                | '\u{feff}'
                // Soft hyphen, Mongolian and other variation selectors,
                // interlinear annotation and tags: all print as nothing.
                | '\u{ad}'
                | '\u{180b}'..='\u{180d}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{e0000}'..='\u{e007f}'
                | '\u{e0100}'..='\u{e01ef}'
                // Hangul fillers, blank but not whitespace.
                | '\u{115f}'
                | '\u{1160}'
                | '\u{3164}'
                | '\u{ffa0}'
        )
}

/// `clean` for JSON text: the characters it would escape become `\uXXXX`
/// instead, which leaves the same JSON. serde_json already escapes C0
/// controls, but not DEL, C1 or the invisible marks. Newlines between
/// tokens stay, so pretty output stays pretty.
pub fn clean_json(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if c != '\n' && unsafe_char(c) {
            // JSON escapes UTF-16 units: one in the BMP, a pair past it.
            let mut u = [0u16; 2];
            for unit in c.encode_utf16(&mut u) {
                o += &format!("\\u{unit:04x}");
            }
        } else {
            o.push(c);
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
    fn old_status_reply_still_parses() {
        // A v0.2 daemon: no network, no incidents_observing.
        let old = r#"{"Status":{"version":"0.2.3","mode":"enforce","uptime_s":1,
            "events_total":2,"dropped_events":0,"probes":[],"incidents_open":0,
            "incident_errors":0,"incident_dropped":0,"verify_skipped":0,
            "deferred_overflow":0,"telemetry_dropped":{"journald":0,
            "otlp_queue_full":0,"otlp_export_failed":0,"otlp_disconnected":0}}}"#;
        match serde_json::from_str::<Response>(old).unwrap() {
            Response::Status {
                network,
                incidents_observing,
                ..
            } => assert_eq!((network.as_str(), incidents_observing), ("drop", 0)),
            r => panic!("{r:?}"),
        }
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
    fn honeypot_requests_and_replies_wire_format() {
        let r: Request = serde_json::from_str(r#"{"IncidentPcap":{"id":"AEG-1"}}"#).unwrap();
        assert_eq!(r, Request::IncidentPcap { id: "AEG-1".into() });
        let r: Request = serde_json::from_str(r#"{"IncidentStix":{"id":"AEG-1"}}"#).unwrap();
        assert_eq!(r, Request::IncidentStix { id: "AEG-1".into() });
        let head = Response::Pcap {
            bytes: 24,
            sessions: 2,
            left_out: 1,
            notes: vec!["1 newer session past the cap".into()],
        };
        let line = serde_json::to_string(&head).unwrap();
        assert_eq!(
            line,
            r#"{"Pcap":{"bytes":24,"sessions":2,"left_out":1,"notes":["1 newer session past the cap"]}}"#
        );
        assert_eq!(serde_json::from_str::<Response>(&line).unwrap(), head);
        let bare = r#"{"Pcap":{"bytes":24,"sessions":2,"left_out":0}}"#;
        assert!(matches!(
            serde_json::from_str::<Response>(bare).unwrap(),
            Response::Pcap { notes, .. } if notes.is_empty()
        ));
        let line = serde_json::to_string(&Response::Stix(serde_json::json!({"type": "bundle"})));
        assert_eq!(line.unwrap(), r#"{"Stix":{"type":"bundle"}}"#);
    }

    #[test]
    fn clean_json_escapes_like_clean_and_stays_the_same_json() {
        let v = serde_json::json!({"k": "a\x1b]0;pwn\x07 \u{9b}2J \u{202e}x \u{7f} ü"});
        let raw = serde_json::to_string_pretty(&v).unwrap();
        let out = clean_json(&raw);
        assert!(
            !out.chars()
                .any(|c| clean(&c.to_string()) != c.to_string() && c != '\n'),
            "{out}"
        );
        assert!(
            out.contains("\\u009b") && out.contains("\\u202e") && out.contains("\\u007f"),
            "{out}"
        );
        assert!(out.contains('ü'));
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), v);
    }

    #[test]
    fn hidden_marks_are_escaped_and_non_bmp_becomes_a_surrogate_pair() {
        for c in [
            '\u{e0041}',
            '\u{e007f}',
            '\u{e0000}',
            '\u{fff9}',
            '\u{fffb}',
            '\u{ad}',
            '\u{180b}',
            '\u{180d}',
            '\u{fe00}',
            '\u{fe0f}',
            '\u{e0100}',
            '\u{e01ef}',
            '\u{115f}',
            '\u{1160}',
            '\u{3164}',
            '\u{ffa0}',
        ] {
            let want = match c as u32 {
                n @ ..0x100 => format!("\\x{n:02x}"),
                n => format!("\\u{{{n:x}}}"),
            };
            assert_eq!(clean(&c.to_string()), want);
        }
        let v = serde_json::json!({"k": "a\u{e0041}b\u{fe0f}"});
        let out = clean_json(&serde_json::to_string(&v).unwrap());
        assert_eq!(out, r#"{"k":"a\udb40\udc41b\ufe0f"}"#);
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), v);
        assert_eq!(clean("emoji \u{1f600} stays"), "emoji \u{1f600} stays");
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
