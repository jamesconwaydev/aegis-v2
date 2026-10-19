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
    IncidentShow { id: String },
    IncidentTimeline { id: String },
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
        telemetry_dropped: TelemetryDropped,
    },
    Incidents(Vec<IncidentSummary>),
    /// The incident's `incident.json`.
    Incident(Value),
    /// The incident's `timeline.jsonl`, one value per line.
    Timeline(Vec<Value>),
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
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IncidentSummary {
    pub id: String,
    pub created: String,
    pub updated: String,
    pub verdict: String,
    pub max_score: f64,
    pub root_tgid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
