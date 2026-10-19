// SPDX-License-Identifier: MIT OR Apache-2.0
//! Human-readable output. Colour only on a terminal, and never with NO_COLOR.

use std::io::IsTerminal;

use aegis_proto::{IncidentSummary, Response};
use serde_json::Value;

use crate::preflight::{Check, Status};

pub fn use_colour() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn paint(s: &str, code: &str, on: bool) -> String {
    if on {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Rows of cells as left-aligned columns, two spaces apart. The last
/// column is not padded.
fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let w: Vec<usize> = (0..cols)
        .map(|i| {
            rows.iter()
                .filter_map(|r| r.get(i))
                .map(|c| c.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for r in rows {
        let line: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i + 1 == r.len() {
                    c.clone()
                } else {
                    format!("{c:<0$}", w[i])
                }
            })
            .collect();
        out += line.join("  ").trim_end();
        out.push('\n');
    }
    out
}

fn duration(s: u64) -> String {
    let (d, h, m) = (s / 86400, s % 86400 / 3600, s % 3600 / 60);
    match (d, h) {
        (0, 0) => format!("{m}m {}s", s % 60),
        (0, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h {m}m"),
    }
}

pub fn status(r: &Response) -> Option<String> {
    let Response::Status {
        version,
        mode,
        uptime_s,
        events_total,
        dropped_events,
        probes,
        incidents_open,
        incident_errors,
        incident_dropped,
        verify_skipped,
        deferred_overflow,
        telemetry_dropped: t,
    } = r
    else {
        return None;
    };
    let kv = |k: &str, v: String| vec![k.to_string(), v];
    let mut rows = vec![
        kv("version", version.clone()),
        kv("mode", mode.clone()),
        kv("uptime", duration(*uptime_s)),
        kv("events", events_total.to_string()),
        kv("dropped events", dropped_events.to_string()),
        kv("open incidents", incidents_open.to_string()),
        kv("incident write errors", incident_errors.to_string()),
        kv("incidents dropped", incident_dropped.to_string()),
        kv("verifications skipped", verify_skipped.to_string()),
        kv("defer queue overflows", deferred_overflow.to_string()),
        kv("telemetry dropped: journald", t.journald.to_string()),
        kv(
            "telemetry dropped: otlp queue full",
            t.otlp_queue_full.to_string(),
        ),
        kv(
            "telemetry dropped: otlp export failed",
            t.otlp_export_failed.to_string(),
        ),
        kv(
            "telemetry dropped: otlp disconnected",
            t.otlp_disconnected.to_string(),
        ),
    ];
    let mut out = table(&rows);
    rows = probes
        .iter()
        .map(|p| vec![p.name.clone(), p.hook.clone()])
        .collect();
    out += "\nprobes\n";
    out += &table(
        &rows
            .iter()
            .map(|r| [vec![String::new()], r.clone()].concat())
            .collect::<Vec<_>>(),
    );
    Some(out)
}

pub fn incidents(list: &[IncidentSummary]) -> String {
    if list.is_empty() {
        return "No incidents.\n".into();
    }
    let mut rows = vec![["ID", "VERDICT", "SCORE", "ROOT PID", "CREATED", "UPDATED"]
        .map(String::from)
        .to_vec()];
    for i in list {
        rows.push(vec![
            i.id.clone(),
            i.verdict.clone(),
            format!("{:.1}", i.max_score),
            i.root_tgid.to_string(),
            i.created.clone(),
            i.updated.clone(),
        ]);
    }
    table(&rows)
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("-")
}

fn n(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}

/// Evidence times are Unix ns in some records and ns since boot in
/// others; show whichever it looks like.
fn when(ns: u64) -> String {
    if ns > 1_000_000_000_000_000_000 {
        let secs = ns / 1_000_000_000;
        let z = secs / 86400 + 719_468;
        let (era, doe) = (z / 146_097, z % 146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + (m <= 2) as u64;
        let r = secs % 86400;
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            r / 3600,
            r % 3600 / 60,
            r % 60
        )
    } else {
        format!("boot+{:.3}s", ns as f64 / 1e9)
    }
}

fn proc_line(p: &Value) -> String {
    format!(
        "{} ({}) uid {}",
        s(p, "exe"),
        s(p, "comm"),
        p.get("uid").and_then(Value::as_u64).unwrap_or(0)
    )
}

pub fn incident(v: &Value) -> String {
    let mut o = String::new();
    let kv = [
        ("id", s(v, "id").to_string()),
        ("verdict", s(v, "verdict").to_string()),
        ("mode", s(v, "mode").to_string()),
        (
            "score",
            format!("{:.1} (peak {:.1})", n(v, "score"), n(v, "max_score")),
        ),
        ("created", s(v, "created").to_string()),
        ("updated", s(v, "updated").to_string()),
        (
            "root process",
            v.get("root").map_or("-".into(), |r| {
                format!(
                    "pid {}  {}  {}",
                    r["tgid"],
                    proc_line(r),
                    s(r, "verification")
                )
            }),
        ),
    ];
    o += &table(&kv.map(|(k, v)| vec![k.to_string(), v]));
    let empty = vec![];
    let members = v
        .get("process_tree")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    o += &format!("\nmembers ({})\n", members.len());
    let rows: Vec<_> = members
        .iter()
        .map(|p| {
            vec![
                String::new(),
                p["tgid"].to_string(),
                s(p, "exe").to_string(),
                s(p, "verification").to_string(),
            ]
        })
        .collect();
    o += &table(&rows);
    let ev = v
        .get("evidence")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    o += &format!(
        "\nevidence ({}{})\n",
        ev.len(),
        if v["evidence_truncated"] == true {
            ", truncated"
        } else {
            ""
        }
    );
    let mut rows = vec![["", "TIME", "SIGNAL", "BASE", "MOD", "REASON"]
        .map(String::from)
        .to_vec()];
    for e in ev {
        rows.push(vec![
            String::new(),
            when(e.get("ts_ns").and_then(Value::as_u64).unwrap_or(0)),
            s(e, "signal").to_string(),
            format!("{:.1}", n(e, "base")),
            format!("{:.2}", n(e, "modifier")),
            s(e, "reason").to_string(),
        ]);
    }
    o += &table(&rows);
    o
}

/// One line per timeline record: time, process, signals, score, tier.
pub fn timeline(lines: &[Value]) -> String {
    let rows: Vec<_> = lines
        .iter()
        .map(|l| {
            let sig: Vec<&str> = l["evidence"]
                .as_array()
                .map(|a| a.iter().map(|e| s(e, "signal")).collect())
                .unwrap_or_default();
            vec![
                s(l, "ts").to_string(),
                format!("pid {}", l["tgid"]),
                if sig.is_empty() {
                    "-".into()
                } else {
                    sig.join(",")
                },
                format!("{:.1}", n(l, "score")),
                s(l, "tier").to_string(),
            ]
        })
        .collect();
    if rows.is_empty() {
        "No timeline records.\n".into()
    } else {
        table(&rows)
    }
}

pub fn preflight(checks: &[Check], colour: bool) -> String {
    let mut o = String::new();
    let w = checks.iter().map(|c| c.check.len()).max().unwrap_or(0);
    for c in checks {
        let code = match c.status {
            Status::Pass => "32",
            Status::Warn => "33",
            Status::Fail => "31",
        };
        // Pad before painting, so the escape codes don't skew columns.
        let tag = paint(c.status.as_str(), code, colour);
        o += &format!("{:<w$}  {tag}  {}\n", c.check, c.detail);
        if let (Some(f), false) = (&c.fix, c.status == Status::Pass) {
            o += &format!("{:<w$}        fix: {f}\n", "");
        }
    }
    o
}
