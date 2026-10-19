// SPDX-License-Identifier: MIT OR Apache-2.0
//! journald via the native datagram protocol. Without a journal socket
//! (a Mac, a container) every emit is a no-op.

use std::io::ErrorKind;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{Sink, TelemetryRecord};
use crate::scoring::Tier;

const SOCKET: &str = "/run/systemd/journal/socket";

pub struct Journald {
    sock: Mutex<Option<UnixDatagram>>,
    path: Option<PathBuf>,
    last_reconnect: Mutex<Option<Instant>>,
    dropped: AtomicU64,
    /// Without a journal at all (a Mac, a container) there is nothing to
    /// lose, so only count drops once we have had a socket.
    ever_connected: AtomicBool,
}

fn connect(path: &Path) -> Option<UnixDatagram> {
    UnixDatagram::unbound()
        .and_then(|s| s.connect(path).map(|()| s))
        .ok()
        // Non-blocking: a stuck journald must cost a record, never stall
        // the pipeline.
        .filter(|s| s.set_nonblocking(true).is_ok())
}

impl Journald {
    pub fn new() -> Self {
        Self::at(SOCKET.as_ref())
    }

    pub fn at(path: &Path) -> Self {
        let sock = connect(path);
        Self {
            ever_connected: AtomicBool::new(sock.is_some()),
            sock: Mutex::new(sock),
            path: Some(path.into()),
            last_reconnect: Mutex::new(None),
            dropped: AtomicU64::new(0),
        }
    }

    /// A fixed socket that is never reconnected.
    #[cfg(test)]
    pub fn with_socket(sock: Option<UnixDatagram>) -> Self {
        let sock = sock.filter(|s| s.set_nonblocking(true).is_ok());
        Self {
            ever_connected: AtomicBool::new(sock.is_some()),
            sock: Mutex::new(sock),
            path: None,
            last_reconnect: Mutex::new(None),
            dropped: AtomicU64::new(0),
        }
    }

    /// Records lost to a full socket buffer, an oversize datagram or a
    /// journald that is away.
    pub fn dropped_records(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// After journald restarts our socket is dead. Reconnect at most once
    /// a second.
    fn reconnect(&self) -> bool {
        let Some(path) = &self.path else { return false };
        let mut last = self
            .last_reconnect
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
            return false;
        }
        *last = Some(Instant::now());
        let new = connect(path);
        let ok = new.is_some();
        if ok {
            self.ever_connected.store(true, Ordering::Relaxed);
        }
        *self.sock.lock().unwrap_or_else(|e| e.into_inner()) = new;
        ok
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
    field(&mut b, "AEGIS_MODE", rec.mode_str().as_bytes());
    field(&mut b, "AEGIS_TGID", rec.tgid.to_string().as_bytes());
    field(&mut b, "AEGIS_COMM", rec.comm.as_bytes());
    field(&mut b, "AEGIS_EXE", rec.exe_lossy().as_bytes());
    field(&mut b, "AEGIS_EXE_B64", rec.exe_b64().as_bytes());
    if let (Some(t), Some(t64)) = (rec.target_lossy(), rec.target_b64()) {
        field(&mut b, "AEGIS_TARGET", t.as_bytes());
        field(&mut b, "AEGIS_TARGET_B64", t64.as_bytes());
    }
    // journald keeps every value of a repeated field.
    for r in &rec.reasons {
        field(&mut b, "AEGIS_REASON", r.as_bytes());
    }
    b
}

impl Sink for Journald {
    fn emit(&self, rec: &TelemetryRecord) {
        let data = encode(rec);
        let send = || {
            let g = self.sock.lock().unwrap_or_else(|e| e.into_inner());
            g.as_ref().map(|s| s.send(&data))
        };
        let res = match send() {
            None => {
                // No socket: only worth trying again if we have a path.
                if self.reconnect() {
                    send()
                } else {
                    None
                }
            }
            Some(Err(e))
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionRefused | ErrorKind::NotConnected
                ) && self.reconnect() =>
            {
                send()
            }
            r => r,
        };
        // WouldBlock (buffer full) and EMSGSIZE land here too.
        if matches!(res, Some(Err(_)))
            || (res.is_none() && self.ever_connected.load(Ordering::Relaxed))
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
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
            target: Some("/tmp/p\nx\u{2028}".as_bytes().to_vec()),
            reasons: vec!["exec from a temp directory".into(), "egress scan".into()],
        };
        let out = encode(&rec);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("PRIORITY=2\n"));
        assert!(s.contains("AEGIS_INCIDENT=AEG-1\n"));
        assert!(s.contains("AEGIS_SCORE=12.0\n"));
        assert!(s.contains("AEGIS_TIER=quarantine\n"));
        assert!(s.contains("AEGIS_EXE_B64=L3RtcC9hCmI=\n"));
        assert!(s.contains("AEGIS_COMM"));
        assert!(out.windows(9).any(|w| w == b"AEGIS_EXE"));
        assert!(s.contains("AEGIS_TGID=7\n"));
        assert!(s.contains("AEGIS_MODE=audit\n"));
        assert!(s.contains("AEGIS_TARGET_B64=L3RtcC9wCnjigKg=\n"));
        assert!(s.contains("AEGIS_REASON=exec from a temp directory\n"));
        assert!(s.contains("AEGIS_REASON=egress scan\n"));
        // MESSAGE stays one plain line: the hostile bytes are escaped, so
        // it never needs the binary form and can't forge a second line.
        let msg = s
            .lines()
            .find_map(|l| l.strip_prefix("MESSAGE="))
            .expect("MESSAGE in plain form");
        assert_eq!(
            msg,
            "aegis would_quarantine incident AEG-1 score 12.0 tgid 7 \
             comm x\\x0ay exe /tmp/a\\x0ab target /tmp/p\\x0ax\\u{2028}"
        );
        let j = Journald::with_socket(None);
        j.emit(&rec);
        assert_eq!(j.dropped_records(), 0);
    }

    #[test]
    fn full_socket_drops_instead_of_blocking() {
        let (a, _b) = UnixDatagram::pair().unwrap();
        let j = Journald::with_socket(Some(a));
        let rec = TelemetryRecord {
            ts_unix_ns: 0,
            incident: "AEG-1".into(),
            tier: Tier::Throttle,
            verdict: "would_throttle",
            score: 1.0,
            mode: Mode::Audit,
            tgid: 7,
            comm: "c".into(),
            exe: Some(vec![b'x'; 4000]),
            target: None,
            reasons: vec![],
        };
        // A blocking send would hang the thread; a drop shows up as a
        // counted record. Judged by completion, not by wall-clock speed, so
        // a slow or emulated build host can't fail it.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for _ in 0..5000 {
                j.emit(&rec);
                if j.dropped_records() > 0 {
                    break;
                }
            }
            let _ = tx.send(j.dropped_records());
        });
        let dropped = rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("emit blocked on a full socket");
        assert!(dropped > 0);
    }

    #[test]
    fn reconnects_after_journald_restart() {
        let dir = std::env::temp_dir().join(format!("aegis-jd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket");
        let l1 = UnixDatagram::bind(&path).unwrap();
        let j = Journald::at(&path);
        let rec = || TelemetryRecord {
            ts_unix_ns: 0,
            incident: "AEG-1".into(),
            tier: Tier::Throttle,
            verdict: "would_throttle",
            score: 1.0,
            mode: Mode::Audit,
            tgid: 7,
            comm: "c".into(),
            exe: None,
            target: None,
            reasons: vec![],
        };
        j.emit(&rec());
        l1.recv(&mut [0u8; 4096]).unwrap();
        // journald restarts: old socket gone, new one at the same path.
        drop(l1);
        std::fs::remove_file(&path).unwrap();
        let l2 = UnixDatagram::bind(&path).unwrap();
        l2.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        j.emit(&rec());
        l2.recv(&mut [0u8; 4096]).unwrap();
        assert_eq!(j.dropped_records(), 0);
    }
}
