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

pub use aegis_proto::clean;

/// Rows of cells as left-aligned columns, two spaces apart. The last
/// column is not padded.
fn table(rows: &[Vec<String>]) -> String {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| clean(c)).collect())
        .collect();
    let rows = &rows[..];
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
        incident_suppressed,
        enforce_dropped,
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
        kv(
            "incident repeats not recorded",
            incident_suppressed.to_string(),
        ),
        kv("enforce jobs dropped", enforce_dropped.to_string()),
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
        kv(
            "telemetry dropped: webhook queue full",
            t.webhook_queue_full.to_string(),
        ),
        kv(
            "telemetry dropped: webhook failed",
            t.webhook_failed.to_string(),
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

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out-pointer.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Wall-clock UTC for a monotonic timestamp, given the two clocks now.
fn wall(ts: u64, real_now: u64, mono_now: u64) -> String {
    let ns = real_now.saturating_sub(mono_now.saturating_sub(ts));
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
}

/// Probe timestamps are CLOCK_MONOTONIC ns since boot. Convert with the
/// clocks as they read now; approximate if the host has suspended since.
/// Only meaningful for the boot the incident was recorded in.
fn when(ts: Option<u64>, same_boot: Option<bool>) -> String {
    let Some(ts) = ts else { return "-".into() };
    match same_boot {
        Some(true) => wall(
            ts,
            clock_ns(libc::CLOCK_REALTIME),
            clock_ns(libc::CLOCK_MONOTONIC),
        ),
        Some(false) => format!("boot+{}s (previous boot)", ts / 1_000_000_000),
        None => format!("boot+{}s (boot unknown)", ts / 1_000_000_000),
    }
}

pub fn current_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
}

fn proc_line(p: &Value) -> String {
    format!(
        "{} ({}) uid {}",
        s(p, "exe"),
        s(p, "comm"),
        p.get("uid").and_then(Value::as_u64).unwrap_or(0)
    )
}

pub fn incident(v: &Value, cur_boot: Option<&str>) -> String {
    let same_boot = match (v.get("boot_id").and_then(Value::as_str), cur_boot) {
        (Some(b), Some(c)) if !b.is_empty() => Some(b == c),
        _ => None,
    };
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
            when(e.get("ts_ns").and_then(Value::as_u64), same_boot),
            s(e, "signal").to_string(),
            format!("{:.1}", n(e, "base")),
            format!("{:.2}", n(e, "modifier")),
            s(e, "reason").to_string(),
        ]);
    }
    o += &table(&rows);
    let acts = v.get("actions").and_then(Value::as_array).unwrap_or(&empty);
    if !acts.is_empty() {
        o += &format!("\nactions ({})\n", acts.len());
        let rows: Vec<_> = acts
            .iter()
            .map(|a| {
                let detail = [
                    a.get("unit").and_then(Value::as_str).map(String::from),
                    a.get("nft_handle")
                        .and_then(Value::as_u64)
                        .map(|h| format!("nft handle {h}")),
                    a.get("detail").and_then(Value::as_str).map(String::from),
                    a.get("error")
                        .and_then(Value::as_str)
                        .map(|e| format!("error: {e}")),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("  ");
                vec![
                    String::new(),
                    s(a, "ts").to_string(),
                    s(a, "kind").to_string(),
                    if a["ok"] == true { "ok" } else { "failed" }.to_string(),
                    detail,
                ]
            })
            .collect();
        o += &table(&rows);
    }
    o
}

/// One line per timeline record: time, process, signals, score, tier.
/// A line of enforcement actions takes the same columns: "enforcement",
/// what was done (a failed step marked so), no score, and the verdict.
pub fn timeline(lines: &[Value], incident: Option<&Value>) -> String {
    // Records carry only tgid; the incident knows the names.
    let name = |tgid: &Value| {
        let p = incident?
            .get("process_tree")?
            .as_array()?
            .iter()
            .find(|p| &p["tgid"] == tgid)?;
        Some(s(p, "comm").to_string())
    };
    let rows: Vec<_> = lines
        .iter()
        .map(|l| {
            if l["truncated"] == true {
                return vec![s(l, "ts").to_string(), s(l, "note").to_string()];
            }
            if let Some(acts) = l["actions"].as_array() {
                let done: Vec<String> = acts
                    .iter()
                    .map(|a| {
                        let k = s(a, "kind").replace('_', " ");
                        if a["ok"] == true {
                            k
                        } else {
                            format!("{k} (failed)")
                        }
                    })
                    .collect();
                return vec![
                    s(l, "ts").to_string(),
                    "enforcement".into(),
                    done.join(", "),
                    "-".into(),
                    s(l, "verdict").to_string(),
                ];
            }
            let sig: Vec<&str> = l["evidence"]
                .as_array()
                .map(|a| a.iter().map(|e| s(e, "signal")).collect())
                .unwrap_or_default();
            vec![
                s(l, "ts").to_string(),
                match name(&l["tgid"]) {
                    Some(c) => format!("{c} ({})", l["tgid"]),
                    None => format!("pid {}", l["tgid"]),
                },
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

/// What a release or kill reports, safe to print.
pub fn done(msg: &str) -> String {
    clean(msg) + "\n"
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
        o += &format!("{:<w$}  {tag}  {}\n", c.check, clean(&c.detail));
        if let (Some(f), false) = (&c.fix, c.status == Status::Pass) {
            o += &format!("{:<w$}        fix: {}\n", "", clean(f));
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn render_release_done() {
        assert_eq!(
            done("released AEG-1: thawed, network restored"),
            "released AEG-1: thawed, network restored\n"
        );
        assert_eq!(done("killed\x1b[2J"), "killed\\x1b[2J\n");
    }

    #[test]
    fn monotonic_to_wall() {
        // Booted at Unix 1_000_000_000 s; event 10 s in, now 100 s in.
        let s = wall(10_000_000_000, 1_000_000_100_000_000_000, 100_000_000_000);
        assert_eq!(s, "2001-09-09T01:46:50Z");
    }

    fn incident_json() -> Value {
        json!({"id":"AEG-1","verdict":"would_quarantine","mode":"audit","score":90.0,"max_score":95.0,
            "created":"c","updated":"u","boot_id":"boot-a",
            "root":{"tgid":7,"exe":"\u{1b}[2J\nFAKE","comm":"x\u{202e}y","uid":0,"verification":"un\u{9b}verified"},
            "process_tree":[{"tgid":7,"exe":"\u{1b}[2J\nFAKE","comm":"c","verification":"unverified"}],
            "evidence":[{"signal":"TmpExec","base":25.0,"modifier":1.0,"reason":"r\u{7}\nFAKE ROW","ts_ns":5_000_000_000u64},
                        {"signal":"NoTs","base":1.0,"modifier":1.0,"reason":"-"}]})
    }

    #[test]
    fn hostile_text_has_no_control_chars_or_extra_rows() {
        let v = incident_json();
        let o = incident(&v, Some("boot-a"));
        assert!(!o.chars().any(|c| c.is_control() && c != '\n'), "{o:?}");
        assert!(!o.contains('\u{202e}'));
        assert!(o.contains("\\x1b[2J\\x0aFAKE"));
        // 7 summary rows, 3 for members, 5 for evidence: nothing smuggled in.
        assert_eq!(o.lines().count(), 15, "{o}");
        assert!(!o.lines().any(|l| l.trim_start().starts_with("FAKE")));
        let t = timeline(
            &[json!({"ts":"t\u{1b}","tgid":7,"tier":"x\ny","score":1.0})],
            Some(&v),
        );
        assert_eq!(t.lines().count(), 1);
        assert!(!t.contains('\u{1b}'));
    }

    #[test]
    fn evidence_time_depends_on_boot() {
        let v = incident_json();
        let prev = incident(&v, Some("boot-b"));
        assert!(prev.contains("boot+5s (previous boot)"), "{prev}");
        let unk = incident(
            &json!({"evidence":[{"ts_ns":2_000_000_000u64}]}),
            Some("boot-b"),
        );
        assert!(unk.contains("boot+2s (boot unknown)"), "{unk}");
        let same = incident(&v, Some("boot-a"));
        assert!(same.contains('Z') && !same.contains("boot+"));
        // the evidence row without ts_ns shows "-"
        assert!(
            same.lines()
                .any(|l| l.contains("NoTs") && l.contains("  -  ")),
            "{same}"
        );
    }

    #[test]
    fn status_shows_every_counter() {
        let r = Response::Status {
            version: "0.1.0".into(),
            mode: "audit".into(),
            uptime_s: 93784,
            events_total: 15401,
            dropped_events: 3,
            probes: vec![aegis_proto::ProbeStatus {
                name: "p".into(),
                hook: "h".into(),
            }],
            incidents_open: 1,
            incident_errors: 4,
            incident_dropped: 5,
            verify_skipped: 6,
            deferred_overflow: 7,
            incident_suppressed: 12,
            enforce_dropped: 13,
            telemetry_dropped: aegis_proto::TelemetryDropped {
                journald: 8,
                otlp_queue_full: 9,
                otlp_export_failed: 10,
                otlp_disconnected: 11,
                webhook_queue_full: 14,
                webhook_failed: 15,
            },
        };
        let o = status(&r).unwrap();
        for (k, v) in [
            ("uptime", "1d 2h 3m"),
            ("events", "15401"),
            ("dropped events", "3"),
            ("incident write errors", "4"),
            ("incidents dropped", "5"),
            ("verifications skipped", "6"),
            ("defer queue overflows", "7"),
            ("incident repeats not recorded", "12"),
            ("enforce jobs dropped", "13"),
            ("journald", "8"),
            ("otlp queue full", "9"),
            ("otlp export failed", "10"),
            ("otlp disconnected", "11"),
            ("webhook queue full", "14"),
            ("webhook failed", "15"),
        ] {
            assert!(
                o.lines()
                    .any(|l| l.contains(k) && l.trim_end().ends_with(v)),
                "{k}: {o}"
            );
        }
    }

    #[test]
    fn timeline_shows_the_truncation_marker() {
        let t = timeline(
            &[
                json!({"ts":"t1","tgid":7,"tier":"throttle","score":60.0,"evidence":[{"signal":"TmpExec"}]}),
                json!({"ts":"t2","truncated":true,"note":"timeline truncated at 10000 lines"}),
            ],
            None,
        );
        assert!(
            t.lines()
                .nth(1)
                .unwrap()
                .contains("timeline truncated at 10000 lines"),
            "{t}"
        );
    }

    #[test]
    fn timeline_shows_enforcement_lines() {
        let t = timeline(
            &[
                json!({"ts":"t1","tgid":7,"tier":"quarantine","score":110.0,"evidence":[{"signal":"tmp_exec"}]}),
                json!({"ts":"t2","verdict":"quarantined","actions":[
                    {"kind":"hold","ok":true},{"kind":"scope","ok":true},
                    {"kind":"freeze","ok":true},{"kind":"nft_drop","ok":true}]}),
                json!({"ts":"t3","verdict":"would_quarantine","actions":[
                    {"kind":"attach","ok":false,"error":"boom"}]}),
            ],
            None,
        );
        let l: Vec<&str> = t.lines().collect();
        assert!(!t.contains("pid null"), "{t}");
        let words = |l: &str| l.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(
            words(l[1]),
            "t2 enforcement hold, scope, freeze, nft drop - quarantined"
        );
        assert_eq!(
            words(l[2]),
            "t3 enforcement attach (failed) - would_quarantine"
        );
    }

    #[test]
    fn incident_table_is_aligned() {
        let o = incident(&incident_json(), Some("boot-a"));
        let l = o.lines().find(|l| l.starts_with("verdict")).unwrap();
        let m = o.lines().find(|l| l.starts_with("created")).unwrap();
        assert_eq!(l.find("would"), m.rfind('c'));
    }
}
