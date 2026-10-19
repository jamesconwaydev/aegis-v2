// SPDX-License-Identifier: MIT OR Apache-2.0
//! Incident store: one directory per incident under the incident dir.
//!
//! ```text
//! <dir>/AEG-20261018-093000-0123456789abcdef/incident.json   rewritten atomically
//! <dir>/AEG-20261018-093000-0123456789abcdef/timeline.jsonl  one line per decision
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

use aegis_proto::IncidentSummary;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::Mode;
use crate::proctable::{ProcInfo, ProcKey};
use crate::scoring::{Decision, Evidence, Tier};
use crate::telemetry::{b64, civil, mode_str, now_ns, rfc3339};
use crate::verify::Verification;

const MAX_EVIDENCE: usize = 256;
/// Timeline lines per incident; one "truncated" marker follows, then
/// nothing more.
pub const MAX_TIMELINE: u64 = 10_000;
/// Members listed in `process_tree`; past this the flag is set. Later
/// members still join the incident while aegisd runs, but aren't listed,
/// so after a restart they aren't known to belong.
pub const MAX_TREE: usize = 4096;

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
    /// `updated` as Unix nanoseconds; the load window works from this.
    #[serde(default)]
    pub updated_ns: u64,
    /// Boot the member `ProcKey`s belong to; empty when unknown.
    #[serde(default)]
    pub boot_id: String,
    pub mode: String,
    pub verdict: String,
    pub max_score: f64,
    pub score: f64,
    pub root: ProcSummary,
    /// Every member process, root first.
    pub process_tree: Vec<ProcSummary>,
    pub evidence: Vec<EvidenceRecord>,
    /// Set once the evidence cap dropped something.
    #[serde(default)]
    pub evidence_truncated: bool,
    /// Set once `MAX_TREE` kept a member out of `process_tree`.
    #[serde(default)]
    pub process_tree_truncated: bool,
    /// Lines in `timeline.jsonl`, the truncation marker included.
    #[serde(default)]
    pub timeline_lines: u64,
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
    boot_id: Option<String>,
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

fn fsync_dir(p: &Path) -> Result<()> {
    File::open(p)?.sync_all()?;
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

/// Write `path` through a temp file: data synced, renamed over, then the
/// directory synced so the rename itself survives a crash.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let res = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res?;
    fsync_dir(path.parent().context("no parent")?)
}

/// A fresh id: `AEG-<UTC date>-<time>-<64 random bits as 16 hex>`.
pub fn new_incident_id() -> String {
    let (y, mo, d, h, mi, s) = civil(now_ns() / 1_000_000_000);
    let mut r = [0u8; 8];
    // SAFETY: getrandom writes at most r.len() bytes into r.
    let n = unsafe { libc::getrandom(r.as_mut_ptr().cast(), r.len(), 0) };
    if n != r.len() as isize {
        // Only before the kernel's pool is ready, which a daemon started
        // after boot never sees. RandomState is seeded from it anyway.
        r = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
            .to_ne_bytes();
    }
    let r = u64::from_ne_bytes(r);
    format!("AEG-{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}-{r:016x}")
}

/// Create a fresh incident dir under `root`: `want` first when given,
/// then random ids, retrying on a clash.
fn create_incident_dir(
    root: &Path,
    taken: &dyn Fn(&str) -> bool,
    want: Option<&str>,
) -> Result<String> {
    let mut want = want.filter(|w| valid_id(w)).map(String::from);
    for _ in 0..32 {
        let id = want.take().unwrap_or_else(new_incident_id);
        if taken(&id) {
            continue;
        }
        match DirBuilder::new().mode(0o700).create(root.join(&id)) {
            Ok(()) => {
                fs::set_permissions(root.join(&id), fs::Permissions::from_mode(0o700))?;
                fsync_dir(root)?;
                return Ok(id);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("could not find a free incident id")
}

/// Identity of the current boot. `ProcKey` start times only mean
/// something within one boot, so incidents are matched by this, not by a
/// clock comparison.
pub fn current_boot_id() -> Option<String> {
    let id = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    Some(id.trim().to_string()).filter(|i| !i.is_empty())
}

const KEEP_SECS: u64 = 30 * 86400;

fn valid_id(id: &str) -> bool {
    aegis_proto::is_incident_id(id)
}

impl IncidentStore {
    /// Create the directory if needed and reload recent incidents.
    pub fn open(dir: &Path) -> Result<Self> {
        Self::open_at(dir, current_boot_id(), now_ns() / 1_000_000_000)
    }

    /// `open` with the boot id and the current time injected.
    ///
    /// Only incidents updated in the last 30 days are loaded into memory,
    /// and only those from this boot (same `boot_id`) feed the process index. Older
    /// ones stay on disk: `get` still finds them, `list` does not.
    /// ponytail: no eviction while running and `list` is recent-only; add
    /// an eviction pass and a disk scan if either matters.
    pub fn open_at(dir: &Path, boot_id: Option<String>, now_secs: u64) -> Result<Self> {
        private_dir(dir)?;
        let mut inner = Inner {
            boot_id: boot_id.clone(),
            ..Inner::default()
        };
        let (mut warned_ts, mut warned_boot) = (false, false);
        for ent in fs::read_dir(dir)? {
            let ent = ent?;
            let name = ent.file_name().to_string_lossy().into_owned();
            let p = ent.path().join("incident.json");
            let inc = match fs::read(&p)
                .map_err(anyhow::Error::from)
                .and_then(|raw| Ok(serde_json::from_slice::<Incident>(&raw)?))
            {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("aegisd: ignoring incident {name}: {}: {e}", p.display());
                    continue;
                }
            };
            if inc.id != name {
                eprintln!("aegisd: ignoring {name}: incident.json says id {}", inc.id);
                continue;
            }
            if inc.updated_ns == 0 && !std::mem::replace(&mut warned_ts, true) {
                eprintln!("aegisd: {name}: no updated_ns, treating it (and any like it) as old");
            }
            let updated = inc.updated_ns / 1_000_000_000;
            if updated + KEEP_SECS < now_secs {
                continue;
            }
            if inc.boot_id.is_empty() && !std::mem::replace(&mut warned_boot, true) {
                eprintln!("aegisd: {name}: no boot_id, not indexing it (and any like it)");
            }
            if !inc.boot_id.is_empty() && Some(&inc.boot_id) == boot_id.as_ref() {
                for m in &inc.process_tree {
                    inner.index.insert(m.key(), inc.id.clone());
                }
            }
            inner.incidents.insert(inc.id.clone(), inc);
        }
        Ok(Self {
            dir: dir.into(),
            inner: Mutex::new(inner),
        })
    }

    /// `tree` holds the decision's process and its ancestors, nearest
    /// first, as `ProcTable::parent_chain` returns them.
    ///
    /// Order on failure: `incident.json` is written first, then the
    /// timeline line, and memory is updated last. A failed call leaves
    /// disk at worst one step ahead; the next record rewrites it.
    #[cfg(test)]
    pub fn record(&self, d: &Decision, tree: &[ProcInfo], mode: Mode) -> Result<IncidentId> {
        self.record_as(d, tree, mode, None)
    }

    /// `record`, with the id a new incident should get. The event loop
    /// picks it so telemetry can name the incident before the write is
    /// done. Ignored when the process already belongs to an incident; on
    /// the rare clash with an old directory a random id is used instead.
    pub fn record_as(
        &self,
        d: &Decision,
        tree: &[ProcInfo],
        mode: Mode,
        want: Option<&str>,
    ) -> Result<IncidentId> {
        let Some(verdict) = verdict(d.tier) else {
            bail!("tier log is not an incident");
        };
        let me = tree
            .iter()
            .find(|p| p.key == d.key)
            .context("decision process missing from tree")?;
        // The lock is held only to read and, at the end, to commit, never
        // across the disk I/O in between: readers on the event loop (Status,
        // IncidentsList) must not wait on an fsync. That is safe because
        // one writer thread is the only caller of this method, so nothing
        // else changes an incident between the read and the commit.
        let (existing, boot_id) = {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            // The process's own membership wins; then the nearest ancestor's.
            let existing = g.index.get(&d.key).cloned().or_else(|| {
                tree.iter()
                    .filter(|p| p.key != d.key)
                    .find_map(|p| g.index.get(&p.key))
                    .cloned()
            });
            let existing = existing.map(|id| g.incidents[&id].clone());
            (existing, g.boot_id.clone().unwrap_or_default())
        };
        let now = now_ns();
        let ts = rfc3339(now);

        let mut inc = match existing {
            Some(inc) => inc,
            None => {
                let root = ProcSummary::new(me);
                let taken = |id: &str| {
                    let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    g.incidents.contains_key(id)
                };
                Incident {
                    id: create_incident_dir(&self.dir, &taken, want)?,
                    created: ts.clone(),
                    updated: ts.clone(),
                    updated_ns: now,
                    boot_id,
                    mode: mode_str(mode).into(),
                    verdict: verdict.into(),
                    max_score: d.score,
                    score: d.score,
                    root: root.clone(),
                    process_tree: vec![root],
                    evidence: vec![],
                    evidence_truncated: false,
                    process_tree_truncated: false,
                    timeline_lines: 0,
                }
            }
        };
        let dir = self.dir.join(&inc.id);

        if !inc.process_tree.iter().any(|m| m.key() == d.key) {
            if inc.process_tree.len() < MAX_TREE {
                inc.process_tree.push(ProcSummary::new(me));
            } else {
                inc.process_tree_truncated = true;
            }
        }
        // Upgrade only: a quarantine verdict never goes back to throttle.
        if verdict == "would_quarantine" {
            inc.verdict = verdict.into();
        }
        inc.updated = ts.clone();
        inc.updated_ns = now;
        inc.score = d.score;
        inc.max_score = inc.max_score.max(d.score);
        for e in d.evidence.iter().map(EvidenceRecord::new) {
            let seen = inc
                .evidence
                .iter()
                .any(|x| (x.ts_ns, &x.signal, &x.reason) == (e.ts_ns, &e.signal, &e.reason));
            if seen {
                continue;
            }
            if inc.evidence.len() < MAX_EVIDENCE {
                inc.evidence.push(e);
            } else {
                inc.evidence_truncated = true;
            }
        }

        // Past the cap, one marker and then silence: incident.json still
        // tracks the score, the timeline stops growing.
        let line = match inc.timeline_lines {
            n if n < MAX_TIMELINE => Some(json!({
                "ts": ts,
                "tgid": d.key.tgid,
                "start_time_ns": d.key.start_time_ns,
                "tier": format!("{:?}", d.tier).to_lowercase(),
                "verdict": verdict,
                "score": d.score,
                // Only the evidence this decision added; the earlier
                // entries are on earlier lines.
                "evidence": d.evidence.last().map(EvidenceRecord::new).into_iter().collect::<Vec<_>>(),
            })),
            MAX_TIMELINE => Some(json!({
                "ts": ts,
                "truncated": true,
                "note": format!("timeline truncated at {MAX_TIMELINE} lines"),
            })),
            _ => None,
        };
        if line.is_some() {
            inc.timeline_lines += 1;
        }
        write_atomic(
            &dir.join("incident.json"),
            &serde_json::to_vec_pretty(&inc)?,
        )?;
        if let Some(line) = line {
            writeln!(private_append(&dir.join("timeline.jsonl"))?, "{line}")?;
        }

        let id = inc.id.clone();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.index.insert(d.key, id.clone());
        g.incidents.insert(id.clone(), inc);
        Ok(IncidentId(id))
    }

    pub fn list(&self) -> Vec<IncidentSummary> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.incidents
            .values()
            .map(|i| IncidentSummary {
                id: i.id.clone(),
                created: i.created.clone(),
                updated: i.updated.clone(),
                verdict: i.verdict.clone(),
                max_score: i.max_score,
                root_tgid: i.root.tgid,
            })
            .collect()
    }

    /// Process memberships loaded at open, for the event loop to seed
    /// its own grouping from once at startup.
    pub fn memberships(&self) -> Vec<(ProcKey, String)> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.index.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// Every incident in memory is open: there is no close yet.
    pub fn open_count(&self) -> usize {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.incidents.len()
    }

    /// The incident's timeline, one value per line; None if it has none.
    /// A line that doesn't parse is skipped.
    pub fn timeline(&self, id: &IncidentId) -> Option<Vec<serde_json::Value>> {
        if !valid_id(&id.0) {
            return None;
        }
        let raw = fs::read(self.dir.join(&id.0).join("timeline.jsonl")).ok()?;
        Some(
            raw.split(|&b| b == b'\n')
                .filter_map(|l| serde_json::from_slice(l).ok())
                .collect(),
        )
    }

    /// Memory first, then disk (incidents older than the load window).
    pub fn get(&self, id: &IncidentId) -> Option<Incident> {
        // Memory under the lock; the disk read after it is released.
        let hit = {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.incidents.get(&id.0).cloned()
        };
        if hit.is_some() {
            return hit;
        }
        if !valid_id(&id.0) {
            return None;
        }
        let raw = fs::read(self.dir.join(&id.0).join("incident.json")).ok()?;
        serde_json::from_slice(&raw)
            .ok()
            .filter(|i: &Incident| i.id == id.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::Signal;
    use crate::telemetry::{jsonl, unb64, TelemetryRecord};
    use std::os::unix::fs::MetadataExt;

    /// umask is process-wide, so permission tests take turns.
    static UMASK: Mutex<()> = Mutex::new(());

    fn with_umask<T>(mask: libc::mode_t, f: impl FnOnce() -> T) -> T {
        let _g = UMASK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: umask only changes this process's file creation mask.
        let old = unsafe { libc::umask(mask) };
        let r = f();
        unsafe { libc::umask(old) };
        r
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
            exe_id: None,
            comm: "c".into(),
            uid: 1000,
            has_tty: false,
            selinux_domain: Some("unconfined_t".into()),
            verification: Verification::Unverified,
            cgroup_id: 0,
            env_taint: None,
            env_pending: false,
            ptraced: false,
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
        assert!(
            id.0.starts_with("AEG-") && id.0.len() == "AEG-20261018-093000-0123456789abcdef".len(),
            "{id}"
        );
        assert!(valid_id(&id.0));
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
        let (st, id, j) = with_umask(0, || {
            let st = IncidentStore::open(&dir).unwrap();
            let id = st
                .record(
                    &dec(10, Tier::Throttle, 6.0),
                    &[proc(10, None, b"/tmp/x")],
                    Mode::Audit,
                )
                .unwrap();
            let j = jsonl::JsonLines::open(&dir.join("t.jsonl")).unwrap();
            (st, id, j)
        });
        drop((st, j));
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
            target: Some(raw.to_vec()),
            reasons: vec![],
        };
        let l: serde_json::Value = serde_json::from_str(&jsonl::line(&rec)).unwrap();
        assert_eq!(unb64(l["path_b64"].as_str().unwrap()), raw);
        assert_eq!(unb64(l["target_b64"].as_str().unwrap()), raw);
    }

    #[test]
    fn own_membership_beats_ancestor() {
        let dir = tmp("own");
        let st = IncidentStore::open(&dir).unwrap();
        let child = proc(11, Some(10), b"/tmp/c");
        let parent = proc(10, None, b"/tmp/p");
        // Child is decided first with no incident above it, then the
        // parent roots its own; the child must stay in its original one.
        let a = st
            .record(
                &dec(11, Tier::Throttle, 6.0),
                std::slice::from_ref(&child),
                Mode::Audit,
            )
            .unwrap();
        let b = st
            .record(
                &dec(10, Tier::Throttle, 6.0),
                std::slice::from_ref(&parent),
                Mode::Audit,
            )
            .unwrap();
        assert_ne!(a, b);
        let c = st
            .record(&dec(11, Tier::Throttle, 7.0), &[child, parent], Mode::Audit)
            .unwrap();
        assert_eq!(c, a);
        assert_eq!(st.get(&b).unwrap().process_tree.len(), 1);
    }

    #[test]
    fn open_logs_and_skips_bad_dirs_and_applies_windows() {
        let dir = tmp("open");
        let st = IncidentStore::open(&dir).unwrap();
        let id = st
            .record(
                &dec(10, Tier::Throttle, 6.0),
                &[proc(10, None, b"/tmp/x")],
                Mode::Audit,
            )
            .unwrap();
        fs::create_dir(dir.join("AEG-empty")).unwrap();
        fs::create_dir(dir.join("AEG-corrupt")).unwrap();
        fs::write(dir.join("AEG-corrupt/incident.json"), b"{nope").unwrap();
        // Right content, wrong directory name.
        fs::create_dir(dir.join("AEG-moved")).unwrap();
        fs::copy(
            dir.join(&id.0).join("incident.json"),
            dir.join("AEG-moved/incident.json"),
        )
        .unwrap();
        let now = now_ns() / 1_000_000_000;

        let st = IncidentStore::open_at(&dir, current_boot_id(), now).unwrap();
        assert_eq!(st.list().len(), 1);

        // A different boot: listed, but not indexed.
        let st = IncidentStore::open_at(&dir, Some("other-boot".into()), now).unwrap();
        assert_eq!(st.list().len(), 1);
        let again = st
            .record(
                &dec(10, Tier::Throttle, 6.0),
                &[proc(10, None, b"/tmp/x")],
                Mode::Audit,
            )
            .unwrap();
        assert_ne!(again, id);

        // Older than 30 days: not loaded, but get() still reads it.
        let st = IncidentStore::open_at(&dir, current_boot_id(), now + 31 * 86400).unwrap();
        assert!(st.list().is_empty());
        assert!(st.get(&id).is_some());
        assert!(st.get(&IncidentId("../x".into())).is_none());
    }

    #[test]
    fn timeline_stops_at_the_cap_with_one_marker() {
        let dir = tmp("tlcap");
        let st = IncidentStore::open(&dir).unwrap();
        let tree = [proc(10, None, b"/tmp/x")];
        let id = st
            .record(&dec(10, Tier::Throttle, 60.0), &tree, Mode::Audit)
            .unwrap();
        // Skip ahead to one line short of the cap.
        st.inner
            .lock()
            .unwrap()
            .incidents
            .get_mut(&id.0)
            .unwrap()
            .timeline_lines = MAX_TIMELINE - 1;
        for _ in 0..3 {
            st.record(&dec(10, Tier::Quarantine, 90.0), &tree, Mode::Audit)
                .unwrap();
        }
        let tl = st.timeline(&id).unwrap();
        assert_eq!(tl.len(), 3, "{tl:?}");
        assert_eq!(tl[1]["tier"], "quarantine");
        assert_eq!(tl[2]["truncated"], true);
        assert_eq!(tl[2]["note"], "timeline truncated at 10000 lines");
        // incident.json keeps up all the same.
        let inc = st.get(&id).unwrap();
        assert_eq!(
            (inc.max_score, inc.timeline_lines),
            (90.0, MAX_TIMELINE + 1)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_tree_stops_at_the_cap_and_says_so() {
        let dir = tmp("treecap");
        let st = IncidentStore::open(&dir).unwrap();
        let root = proc(10, None, b"/tmp/x");
        let id = st
            .record(
                &dec(10, Tier::Throttle, 60.0),
                std::slice::from_ref(&root),
                Mode::Audit,
            )
            .unwrap();
        // Fill the tree to the cap without a write per member.
        {
            let mut g = st.inner.lock().unwrap();
            let inc = g.incidents.get_mut(&id.0).unwrap();
            while inc.process_tree.len() < MAX_TREE {
                let mut m = inc.process_tree[0].clone();
                m.tgid = 100_000 + inc.process_tree.len() as u32;
                inc.process_tree.push(m);
            }
        }
        let child = proc(11, Some(10), b"/tmp/y");
        let got = st
            .record(&dec(11, Tier::Throttle, 60.0), &[child, root], Mode::Audit)
            .unwrap();
        assert_eq!(got, id, "still joins the incident");
        let inc = st.get(&id).unwrap();
        assert_eq!(inc.process_tree.len(), MAX_TREE);
        assert!(inc.process_tree_truncated);
        assert!(inc.process_tree.iter().all(|m| m.tgid != 11));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_write_leaves_no_tmp_and_evidence_cap_is_flagged() {
        let dir = tmp("fail");
        let st = IncidentStore::open(&dir).unwrap();
        let root = proc(10, None, b"/tmp/x");
        let mut d = dec(10, Tier::Throttle, 6.0);
        d.evidence = (0..300)
            .map(|i| Evidence {
                ts_ns: i,
                ..d.evidence[0].clone()
            })
            .collect();
        let id = st
            .record(&d, std::slice::from_ref(&root), Mode::Audit)
            .unwrap();
        let inc = st.get(&id).unwrap();
        assert_eq!(inc.evidence.len(), MAX_EVIDENCE);
        assert!(inc.evidence_truncated);

        let j = dir.join(&id.0).join("incident.json");
        fs::remove_file(&j).unwrap();
        fs::create_dir_all(j.join("blocker")).unwrap();
        assert!(st.record(&d, &[root], Mode::Audit).is_err());
        assert!(!dir.join(&id.0).join("incident.json.tmp").exists());
        assert_eq!(
            fs::read_to_string(dir.join(&id.0).join("timeline.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }

    #[test]
    fn boot_id_gates_the_index() {
        let dir = tmp("bootid");
        let st = IncidentStore::open_at(&dir, Some("boot-a".into()), 1).unwrap();
        let root = proc(10, None, b"/tmp/x");
        let id = st
            .record(
                &dec(10, Tier::Throttle, 6.0),
                std::slice::from_ref(&root),
                Mode::Audit,
            )
            .unwrap();
        assert_eq!(st.get(&id).unwrap().boot_id, "boot-a");
        let now = now_ns() / 1_000_000_000;
        let same = IncidentStore::open_at(&dir, Some("boot-a".into()), now).unwrap();
        let again = same
            .record(
                &dec(10, Tier::Throttle, 6.0),
                std::slice::from_ref(&root),
                Mode::Audit,
            )
            .unwrap();
        assert_eq!(again, id);
        for boot in [Some("boot-b".to_string()), None] {
            let st = IncidentStore::open_at(&dir, boot, now).unwrap();
            let fresh = st
                .record(
                    &dec(10, Tier::Throttle, 6.0),
                    std::slice::from_ref(&root),
                    Mode::Audit,
                )
                .unwrap();
            assert_ne!(fresh, id);
        }
        // An incident.json from before boot_id existed is never indexed.
        let j = dir.join(&id.0).join("incident.json");
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&j).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("boot_id");
        fs::write(&j, v.to_string()).unwrap();
        let old = tmp("bootid-old");
        fs::create_dir_all(old.join(&id.0)).unwrap();
        fs::copy(&j, old.join(&id.0).join("incident.json")).unwrap();
        let st = IncidentStore::open_at(&old, Some("boot-a".into()), now).unwrap();
        let fresh = st
            .record(&dec(10, Tier::Throttle, 6.0), &[root], Mode::Audit)
            .unwrap();
        assert_ne!(fresh, id);
    }
}
