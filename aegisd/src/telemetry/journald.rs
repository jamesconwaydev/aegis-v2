// SPDX-License-Identifier: MIT OR Apache-2.0
//! journald via the native datagram protocol. Without a journal socket
//! (a Mac, a container) every emit is a no-op.

use std::os::unix::net::UnixDatagram;

use super::{Sink, TelemetryRecord};
use crate::scoring::Tier;

const SOCKET: &str = "/run/systemd/journal/socket";

pub struct Journald {
    sock: Option<UnixDatagram>,
}

impl Journald {
    pub fn new() -> Self {
        let sock = UnixDatagram::unbound()
            .and_then(|s| s.connect(SOCKET).map(|()| s))
            .ok();
        Self { sock }
    }
}

fn field(buf: &mut Vec<u8>, k: &str, v: &[u8]) {
    buf.extend_from_slice(k.as_bytes());
    if v.contains(&b'\n') {
        // Binary-safe form: name, newline, u64 LE length, value.
        buf.push(b'\n');
        buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
    } else {
        buf.push(b'=');
    }
    buf.extend_from_slice(v);
    buf.push(b'\n');
}

pub fn encode(rec: &TelemetryRecord) -> Vec<u8> {
    let prio = match rec.tier {
        Tier::Log => "6",
        Tier::Throttle => "4",
        Tier::Quarantine => "2",
    };
    let mut b = Vec::new();
    field(&mut b, "MESSAGE", rec.message().as_bytes());
    field(&mut b, "PRIORITY", prio.as_bytes());
    field(&mut b, "SYSLOG_IDENTIFIER", b"aegisd");
    field(&mut b, "AEGIS_INCIDENT", rec.incident.as_bytes());
    field(
        &mut b,
        "AEGIS_SCORE",
        format!("{:.1}", rec.score).as_bytes(),
    );
    field(&mut b, "AEGIS_TIER", rec.tier_str().as_bytes());
    field(&mut b, "AEGIS_VERDICT", rec.verdict.as_bytes());
    field(&mut b, "AEGIS_EXE_B64", rec.exe_b64().as_bytes());
    b
}

impl Sink for Journald {
    fn emit(&self, rec: &TelemetryRecord) {
        if let Some(s) = &self.sock {
            // Best effort: journald being busy must not stall detection.
            let _ = s.send(&encode(rec));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;

    #[test]
    fn encodes_fields_and_binary_values() {
        let rec = TelemetryRecord {
            ts_unix_ns: 0,
            incident: "AEG-1".into(),
            tier: Tier::Quarantine,
            verdict: "would_quarantine",
            score: 12.0,
            mode: Mode::Audit,
            tgid: 7,
            comm: "x\ny".into(),
            exe: Some(b"/tmp/a\nb".to_vec()),
            reasons: vec![],
        };
        let out = encode(&rec);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("PRIORITY=2\n"));
        assert!(s.contains("AEGIS_INCIDENT=AEG-1\n"));
        assert!(s.contains("AEGIS_SCORE=12.0\n"));
        assert!(s.contains("AEGIS_TIER=quarantine\n"));
        assert!(s.contains("AEGIS_EXE_B64=L3RtcC9hCmI=\n"));
        assert!(out.windows(8).any(|w| w == b"MESSAGE\n"));
        Journald { sock: None }.emit(&rec);
    }
}
