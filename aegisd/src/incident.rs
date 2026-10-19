// SPDX-License-Identifier: MIT OR Apache-2.0
//! Incident store: one directory per incident under the incident dir.
//!
//! ```text
//! <dir>/AEG-20261018-093000-a1b2/incident.json   rewritten atomically
//! <dir>/AEG-20261018-093000-a1b2/timeline.jsonl  one line per decision
//! ```
//!
//! Grouping rule: a decision joins the incident of its nearest ancestor
//! (per the `tree` passed in) that is already a member of an open incident.
//! With no such ancestor, the decision's process is the root of a new
//! incident. Incidents have no close yet, so every incident is open.
//! Members are only processes that were themselves decided on.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::Mode;
use crate::proctable::{ProcInfo, ProcKey};
use crate::scoring::{Decision, Evidence, Tier};
use crate::telemetry::{b64, civil, mode_str, now_ns, rfc3339};
use crate::verify::Verification;

const MAX_EVIDENCE: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IncidentId(pub String);

impl std::fmt::Display for IncidentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcSummary {
    pub tgid: u32,
    pub start_time_ns: u64,
    /// Lossy UTF-8; `exe_b64` has the exact bytes.
    pub exe: Option<String>,
    pub exe_b64: Option<String>,
    pub comm: String,
    pub uid: u32,
    pub selinux_domain: Option<String>,
    pub verification: String,
}

impl ProcSummary {
    fn new(p: &ProcInfo) -> Self {
        let bytes = p.exe.as_ref().map(|e| e.as_os_str().as_bytes());
        Self {
            tgid: p.key.tgid,
            start_time_ns: p.key.start_time_ns,
            exe: bytes.map(|b| String::from_utf8_lossy(b).into_owned()),
            exe_b64: bytes.map(b64),
            comm: p.comm.clone(),
            uid: p.uid,
            selinux_domain: p.selinux_domain.clone(),
            verification: match &p.verification {
                Verification::RpmOwned { package } => format!("rpm_owned:{package}"),
                Verification::Pinned => "pinned".into(),
                Verification::Modified => "modified".into(),
                Verification::Unverified => "unverified".into(),
            },
        }
    }

    fn key(&self) -> ProcKey {
        ProcKey {
            tgid: self.tgid,
            start_time_ns: self.start_time_ns,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub signal: String,
    pub base: f64,
    pub modifier: f64,
    pub reason: String,
    pub ts_ns: u64,
}

impl EvidenceRecord {
    fn new(e: &Evidence) -> Self {
        Self {
            signal: format!("{:?}", e.signal),
            base: e.base,
            modifier: e.modifier,
            reason: e.reason.clone(),
            ts_ns: e.ts_ns,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub created: String,
    pub updated: String,
    pub mode: String,
    pub verdict: String,
    pub max_score: f64,
    pub score: f64,
    pub root: ProcSummary,
    /// Every member process, root first.
    pub process_tree: Vec<ProcSummary>,
    pub evidence: Vec<EvidenceRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IncidentSummary {
    pub id: IncidentId,
    pub created: String,
    pub updated: String,
    pub verdict: String,
    pub max_score: f64,
    pub root_tgid: u32,
}

pub fn verdict(t: Tier) -> Option<&'static str> {
    match t {
        Tier::Log => None,
        Tier::Throttle => Some("would_throttle"),
        Tier::Quarantine => Some("would_quarantine"),
    }
}

#[derive(Default)]
struct Inner {
    incidents: BTreeMap<String, Incident>,
    index: HashMap<ProcKey, String>,
}

pub struct IncidentStore {
    dir: PathBuf,
    inner: Mutex<Inner>,
}

fn private_dir(p: &Path) -> Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn private_append(p: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(p)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(f)
}

fn new_id(taken: &BTreeMap<String, Incident>) -> String {
    let (y, mo, d, h, mi, s) = civil(now_ns() / 1_000_000_000);
    loop {
        let r = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish() as u16;
        let id = format!("AEG-{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}-{r:04x}");
        if !taken.contains_key(&id) {
            return id;
        }
    }
}

impl IncidentStore {
    /// Create the directory if needed and reload open incidents from it.
    pub fn open(dir: &Path) -> Result<Self> {
        private_dir(dir)?;
        let mut inner = Inner::default();
        for ent in fs::read_dir(dir)? {
            let p = ent?.path().join("incident.json");
            let Ok(raw) = fs::read(&p) else { continue };
            match serde_json::from_slice::<Incident>(&raw) {
                Ok(inc) => {
                    for m in &inc.process_tree {
                        inner.index.insert(m.key(), inc.id.clone());
                    }
                    inner.incidents.insert(inc.id.clone(), inc);
                }
                Err(e) => eprintln!("aegisd: skipping {}: {e}", p.display()),
            }
        }
        Ok(Self {
            dir: dir.into(),
            inner: Mutex::new(inner),
        })
    }

    /// `tree` holds the decision's process and its ancestors, nearest
    /// first, as `ProcTable::parent_chain` returns them.
    pub fn record(&self, d: &Decision, tree: &[ProcInfo], mode: Mode) -> Result<IncidentId> {
        let Some(verdict) = verdict(d.tier) else {
            bail!("tier log is not an incident");
        };
        let me = tree
            .iter()
            .find(|p| p.key == d.key)
            .context("decision process missing from tree")?;
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let existing = tree
            .iter()
            .filter(|p| p.key != d.key)
            .find_map(|p| g.index.get(&p.key))
            .or_else(|| g.index.get(&d.key))
            .cloned();
        let now = now_ns();
        let ts = rfc3339(now);

        let mut inc = match existing {
            Some(id) => g.incidents[&id].clone(),
            None => {
                let root = ProcSummary::new(me);
                Incident {
                    id: new_id(&g.incidents),
                    created: ts.clone(),
                    updated: ts.clone(),
                    mode: mode_str(mode).into(),
                    verdict: verdict.into(),
                    max_score: d.score,
                    score: d.score,
                    root: root.clone(),
                    process_tree: vec![root],
                    evidence: vec![],
                }
            }
        };
        let dir = self.dir.join(&inc.id);
        private_dir(&dir)?;

        if !inc.process_tree.iter().any(|m| m.key() == d.key) {
            inc.process_tree.push(ProcSummary::new(me));
        }
        // Upgrade only: a quarantine verdict never goes back to throttle.
        if verdict == "would_quarantine" {
            inc.verdict = verdict.into();
        }
        inc.updated = ts.clone();
        inc.score = d.score;
        inc.max_score = inc.max_score.max(d.score);
        for e in d.evidence.iter().map(EvidenceRecord::new) {
            let seen = inc
                .evidence
                .iter()
                .any(|x| (x.ts_ns, &x.signal, &x.reason) == (e.ts_ns, &e.signal, &e.reason));
            if !seen && inc.evidence.len() < MAX_EVIDENCE {
                inc.evidence.push(e);
            }
        }

        let line = json!({
            "ts": ts,
            "tgid": d.key.tgid,
            "start_time_ns": d.key.start_time_ns,
            "tier": format!("{:?}", d.tier).to_lowercase(),
            "verdict": verdict,
            "score": d.score,
            "evidence": d.evidence.iter().map(EvidenceRecord::new).collect::<Vec<_>>(),
        });
        writeln!(private_append(&dir.join("timeline.jsonl"))?, "{line}")?;

        let tmp = dir.join("incident.json.tmp");
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(&serde_json::to_vec_pretty(&inc)?)?;
        fs::rename(&tmp, dir.join("incident.json"))?;

        let id = inc.id.clone();
        g.index.insert(d.key, id.clone());
        g.incidents.insert(id.clone(), inc);
        Ok(IncidentId(id))
    }

    pub fn list(&self) -> Vec<IncidentSummary> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.incidents
            .values()
            .map(|i| IncidentSummary {
                id: IncidentId(i.id.clone()),
                created: i.created.clone(),
                updated: i.updated.clone(),
                verdict: i.verdict.clone(),
                max_score: i.max_score,
                root_tgid: i.root.tgid,
            })
            .collect()
    }

    pub fn get(&self, id: &IncidentId) -> Option<Incident> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.incidents.get(&id.0).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::Signal;
    use crate::telemetry::{jsonl, unb64, TelemetryRecord};
    use std::os::unix::fs::MetadataExt;

    extern "C" {
        fn umask(m: u32) -> u32;
    }

    fn key(tgid: u32) -> ProcKey {
        ProcKey {
            tgid,
            start_time_ns: 100 + tgid as u64,
        }
    }

    fn proc(tgid: u32, parent: Option<u32>, exe: &[u8]) -> ProcInfo {
        ProcInfo {
            key: key(tgid),
            parent: parent.map(key),
            exe: Some(PathBuf::from(std::ffi::OsStr::from_bytes(exe))),
            comm: "c".into(),
            uid: 1000,
            has_tty: false,
            selinux_domain: Some("unconfined_t".into()),
            verification: Verification::Unverified,
            cgroup_id: 0,
        }
    }

    fn dec(tgid: u32, tier: Tier, score: f64) -> Decision {
        Decision {
            key: key(tgid),
            score,
            tier,
            evidence: vec![Evidence {
                signal: Signal::TmpExec,
                base: 5.0,
                modifier: 1.0,
                reason: format!("tmp exec {tgid}"),
                ts_ns: tgid as u64,
            }],
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("aegis-inc-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn record_creates_incident_json_and_timeline() {
        let dir = tmp("create");
        let st = IncidentStore::open(&dir).unwrap();
        let id = st
            .record(
                &dec(10, Tier::Throttle, 6.0),
                &[proc(10, None, b"/tmp/x")],
                Mode::Audit,
            )
            .unwrap();
        assert!(id.0.starts_with("AEG-") && id.0.len() == "AEG-20261018-093000-a1b2".len());
        let v: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(&id.0).join("incident.json")).unwrap())
                .unwrap();
        assert_eq!(v["verdict"], "would_throttle");
        assert_eq!(v["mode"], "audit");
        assert_eq!(v["max_score"], 6.0);
        assert_eq!(v["root"]["exe"], "/tmp/x");
        assert_eq!(v["evidence"].as_array().unwrap().len(), 1);
        let tl = fs::read_to_string(dir.join(&id.0).join("timeline.jsonl")).unwrap();
        assert_eq!(tl.lines().count(), 1);
        // Reopening rebuilds the index: a child still joins.
        let st = IncidentStore::open(&dir).unwrap();
        assert_eq!(st.list().len(), 1);
        let again = st
            .record(
                &dec(11, Tier::Throttle, 7.0),
                &[proc(11, Some(10), b"/tmp/y"), proc(10, None, b"/tmp/x")],
                Mode::Audit,
            )
            .unwrap();
        assert_eq!(again, id);
    }

    #[test]
    fn same_tree_appends_not_duplicates() {
        let dir = tmp("tree");
        let st = IncidentStore::open(&dir).unwrap();
        let root = proc(10, None, b"/tmp/x");
        let kid = proc(11, Some(10), b"/tmp/y");
        let a = st
            .record(
                &dec(10, Tier::Quarantine, 12.0),
                std::slice::from_ref(&root),
                Mode::Audit,
            )
            .unwrap();
        let b = st
            .record(
                &dec(11, Tier::Throttle, 6.0),
                &[kid, root.clone()],
                Mode::Audit,
            )
            .unwrap();
        let c = st
            .record(&dec(10, Tier::Throttle, 13.0), &[root], Mode::Audit)
            .unwrap();
        assert_eq!((&a, &a), (&b, &c));
        assert_eq!(st.list().len(), 1);
        let inc = st.get(&a).unwrap();
        assert_eq!(inc.verdict, "would_quarantine");
        assert_eq!((inc.max_score, inc.score), (13.0, 13.0));
        assert_eq!(inc.process_tree.len(), 2);
        assert_eq!(inc.evidence.len(), 2);
        let tl = fs::read_to_string(dir.join(&a.0).join("timeline.jsonl")).unwrap();
        assert_eq!(tl.lines().count(), 3);
        // An unrelated process gets its own incident.
        let other = st
            .record(
                &dec(50, Tier::Throttle, 6.0),
                &[proc(50, None, b"/tmp/z")],
                Mode::Audit,
            )
            .unwrap();
        assert_ne!(other, a);
        assert!(st
            .record(
                &dec(60, Tier::Log, 1.0),
                &[proc(60, None, b"/a")],
                Mode::Audit
            )
            .is_err());
    }

    #[test]
    fn permissions_are_0700_0600() {
        let dir = tmp("perm");
        // SAFETY: umask only changes this process's file creation mask.
        let old = unsafe { umask(0) };
        let st = IncidentStore::open(&dir).unwrap();
        let id = st
            .record(
                &dec(10, Tier::Throttle, 6.0),
                &[proc(10, None, b"/tmp/x")],
                Mode::Audit,
            )
            .unwrap();
        let j = jsonl::JsonLines::open(&dir.join("t.jsonl")).unwrap();
        unsafe { umask(old) };
        drop(j);
        let mode = |p: PathBuf| fs::metadata(p).unwrap().mode() & 0o777;
        assert_eq!(mode(dir.clone()), 0o700);
        assert_eq!(mode(dir.join(&id.0)), 0o700);
        assert_eq!(mode(dir.join(&id.0).join("incident.json")), 0o600);
        assert_eq!(mode(dir.join(&id.0).join("timeline.jsonl")), 0o600);
        assert_eq!(mode(dir.join("t.jsonl")), 0o600);
    }

    #[test]
    fn hostile_path_round_trips() {
        let raw: &[u8] = b"/tmp/a\nb\"c\xff";
        let dir = tmp("hostile");
        let st = IncidentStore::open(&dir).unwrap();
        let id = st
            .record(
                &dec(10, Tier::Throttle, 6.0),
                &[proc(10, None, raw)],
                Mode::Audit,
            )
            .unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(&id.0).join("incident.json")).unwrap())
                .unwrap();
        assert_eq!(unb64(v["root"]["exe_b64"].as_str().unwrap()), raw);
        assert_eq!(v["root"]["exe"], "/tmp/a\nb\"c\u{fffd}");

        let rec = TelemetryRecord {
            ts_unix_ns: 0,
            incident: id.0,
            tier: Tier::Throttle,
            verdict: "would_throttle",
            score: 6.0,
            mode: Mode::Audit,
            tgid: 10,
            comm: "c".into(),
            exe: Some(raw.to_vec()),
            reasons: vec![],
        };
        let l: serde_json::Value = serde_json::from_str(&jsonl::line(&rec)).unwrap();
        assert_eq!(unb64(l["path_b64"].as_str().unwrap()), raw);
    }
}
