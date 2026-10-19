// SPDX-License-Identifier: MIT OR Apache-2.0
//! Append-only JSON lines file, mode 0600.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;

use serde_json::json;

use super::{rfc3339, Sink, TelemetryRecord};

pub struct JsonLines {
    file: Mutex<File>,
}

impl JsonLines {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            file: Mutex::new(f),
        })
    }
}

pub fn line(rec: &TelemetryRecord) -> String {
    json!({
        "ts": rfc3339(rec.ts_unix_ns),
        "incident": rec.incident,
        "verdict": rec.verdict,
        "tier": rec.tier_str(),
        "score": rec.score,
        "mode": rec.mode_str(),
        "tgid": rec.tgid,
        "comm": rec.comm,
        "path": rec.exe_lossy(),
        "path_b64": rec.exe_b64(),
        "reasons": rec.reasons,
    })
    .to_string()
}

impl Sink for JsonLines {
    fn emit(&self, rec: &TelemetryRecord) {
        let mut l = line(rec);
        l.push('\n');
        let r = self.file.lock().map(|mut f| f.write_all(l.as_bytes()));
        if !matches!(r, Ok(Ok(()))) {
            eprintln!("aegisd: telemetry jsonl write failed");
        }
    }
}
