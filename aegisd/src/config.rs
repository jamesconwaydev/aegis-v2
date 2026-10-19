// SPDX-License-Identifier: MIT OR Apache-2.0
//! Configuration: one main file plus `allowlist.d/*.toml` drop-ins.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::de::{self, DeserializeOwned, Deserializer};
use serde::Deserialize;
use toml::Spanned;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Audit,
    Enforce,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    pub mode: Mode,
    pub score_threshold_quarantine: u32,
    pub score_threshold_throttle: u32,
}

impl Default for General {
    fn default() -> Self {
        Self {
            mode: Mode::Audit,
            score_threshold_quarantine: 80,
            score_threshold_throttle: 50,
        }
    }
}

fn non_negative<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    let v = f64::deserialize(d)?;
    if v.is_finite() && v >= 0.0 {
        Ok(v)
    } else {
        Err(de::Error::custom(format!(
            "must be a finite number >= 0, got {v}"
        )))
    }
}

fn at_least_one<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default + PartialEq>(
    d: D,
) -> Result<T, D::Error> {
    let v = T::deserialize(d)?;
    if v == T::default() {
        Err(de::Error::custom("must be at least 1"))
    } else {
        Ok(v)
    }
}

fn positive<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    let v = f64::deserialize(d)?;
    if v.is_finite() && v > 0.0 {
        Ok(v)
    } else {
        Err(de::Error::custom(format!(
            "must be a finite number > 0, got {v}"
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Weights {
    #[serde(deserialize_with = "non_negative")]
    pub tmp_exec: f64,
    #[serde(deserialize_with = "non_negative")]
    pub memfd_create: f64,
    #[serde(deserialize_with = "non_negative")]
    pub memfd_exec: f64,
    #[serde(deserialize_with = "non_negative")]
    pub ptrace_system_daemon: f64,
    #[serde(deserialize_with = "non_negative")]
    pub egress_scan: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            tmp_exec: 25.0,
            memfd_create: 20.0,
            memfd_exec: 60.0,
            ptrace_system_daemon: 45.0,
            egress_scan: 40.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    #[serde(deserialize_with = "positive")]
    pub window_secs: f64,
    #[serde(deserialize_with = "at_least_one")]
    pub distinct_targets: u32,
    #[serde(deserialize_with = "at_least_one")]
    pub failed_connects: u32,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            window_secs: 2.0,
            distinct_targets: 20,
            failed_connects: 10,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScoringConfig {
    pub weights: Weights,
    #[serde(deserialize_with = "positive")]
    pub half_life_secs: f64,
    pub scan: ScanConfig,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            weights: Weights::default(),
            half_life_secs: 30.0,
            scan: ScanConfig::default(),
        }
    }
}

/// An absolute path. Names are refused: a process picks its own name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
struct AbsPath(PathBuf);

impl TryFrom<String> for AbsPath {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        if s.starts_with('/') {
            Ok(Self(PathBuf::from(s)))
        } else {
            Err(format!(
                "{s:?} is not an absolute path; use the full path of the executable, \
                 because process names can be spoofed"
            ))
        }
    }
}

fn abs_paths<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PathBuf>, D::Error> {
    Ok(Vec::<AbsPath>::deserialize(d)?
        .into_iter()
        .map(|p| p.0)
        .collect())
}

/// Exactly 64 hex characters.
#[derive(Deserialize)]
#[serde(try_from = "String")]
struct Sha256Hex([u8; 32]);

impl TryFrom<String> for Sha256Hex {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        let b = s.as_bytes();
        if b.len() != 64 || !b.iter().all(u8::is_ascii_hexdigit) {
            return Err(format!(
                "a SHA-256 pin must be exactly 64 hex characters, got {} characters",
                s.chars().count()
            ));
        }
        let nib = |c: u8| (c as char).to_digit(16).unwrap() as u8;
        let mut out = [0u8; 32];
        for (o, pair) in out.iter_mut().zip(b.chunks(2)) {
            *o = nib(pair[0]) << 4 | nib(pair[1]);
        }
        Ok(Self(out))
    }
}

fn pins<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(PathBuf, [u8; 32])>, D::Error> {
    let m = BTreeMap::<AbsPath, Sha256Hex>::deserialize(d)?;
    Ok(m.into_iter().map(|(k, v)| (k.0, v.0)).collect())
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Allowlist {
    /// Verified executables whose children are not scored for tmp exec.
    #[serde(deserialize_with = "abs_paths")]
    pub excluded_parent_processes: Vec<PathBuf>,
    pub excluded_selinux_domains: Vec<String>,
    /// Path and SHA-256, as `Verifier::verify` takes them. When files
    /// disagree, the last one read wins, and drop-ins are read after the
    /// main file, so a drop-in can re-pin a path the main file pinned.
    #[serde(deserialize_with = "pins")]
    pub pinned: Vec<(PathBuf, [u8; 32])>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuarantineConfig {
    #[serde(deserialize_with = "at_least_one")]
    pub overlay_max_size_mb: u32,
    #[serde(deserialize_with = "at_least_one")]
    pub auto_expire_seconds: u64,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            overlay_max_size_mb: 512,
            auto_expire_seconds: 3600,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpConfig {
    pub endpoint: String,
}

/// journald is always on and has no switch.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub jsonl: Option<PathBuf>,
    pub otlp: Option<OtlpConfig>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IncidentConfig {
    pub dir: PathBuf,
}

impl Default for IncidentConfig {
    fn default() -> Self {
        Self {
            dir: "/var/lib/aegis-v2/incidents".into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub scoring: ScoringConfig,
    pub allowlist: Allowlist,
    pub quarantine: QuarantineConfig,
    pub telemetry: TelemetryConfig,
    pub incidents: IncidentConfig,
}

/// Drop-ins may only carry allowlist rules.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DropIn {
    #[serde(default)]
    allowlist: Allowlist,
}

/// Displays as `path:line:col: message`, or `path: message` when the
/// problem has no single place in the file.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub path: PathBuf,
    pub line_col: Option<(usize, usize)>,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())?;
        if let Some((l, c)) = self.line_col {
            write!(f, ":{l}:{c}")?;
        }
        write!(f, ": {}", self.message)
    }
}

impl std::error::Error for ConfigError {}

impl ConfigError {
    fn at(path: &Path, src: &str, offset: Option<usize>, message: impl Into<String>) -> Self {
        let line_col = offset.map(|o| {
            let before = &src[..o.min(src.len())];
            let line = before.matches('\n').count() + 1;
            let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
            (line, col)
        });
        Self {
            path: path.to_owned(),
            line_col,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub path: PathBuf,
    pub message: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

fn read(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|e| ConfigError {
        path: path.to_owned(),
        line_col: None,
        message: e.to_string(),
    })
}

fn parse<T: DeserializeOwned>(path: &Path, src: &str) -> Result<T, ConfigError> {
    toml::from_str(src)
        .map_err(|e| ConfigError::at(path, src, e.span().map(|s| s.start), e.message()))
}

/// A second look at the main file, only to get exact spans for the
/// checks that need more than one field.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Spans {
    general: SpanGeneral,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SpanGeneral {
    mode: Option<Spanned<Mode>>,
    score_threshold_throttle: Option<Spanned<u32>>,
    score_threshold_quarantine: Option<Spanned<u32>>,
}

fn unconfined_warning(path: &Path, a: &Allowlist) -> Option<Warning> {
    a.excluded_selinux_domains
        .iter()
        .any(|d| d == "unconfined_t")
        .then(|| Warning {
            path: path.to_owned(),
            message: "unconfined_t is in excluded_selinux_domains; every root shell and \
                      many services run in it, so this lets an attacker skip scoring"
                .into(),
        })
}

impl Config {
    pub fn load(main: &Path, dropin_dir: &Path) -> Result<Config, ConfigError> {
        Self::load_checked(main, dropin_dir).map(|(c, _)| c)
    }

    /// Like `load`, plus warnings for settings that are legal but unwise.
    /// Drop-ins (`*.toml` in `dropin_dir`, lexical order) add to the
    /// allowlist lists. A pin in a later file replaces an earlier pin for
    /// the same path, including one from the main file.
    pub fn load_checked(
        main: &Path,
        dropin_dir: &Path,
    ) -> Result<(Config, Vec<Warning>), ConfigError> {
        let src = read(main)?;
        let mut cfg: Config = parse(main, &src)?;

        let spans: Spans = parse(main, &src)?;
        let start = |o: &Option<Spanned<_>>| o.as_ref().map(|v| v.span().start);
        if cfg.general.mode == Mode::Enforce {
            return Err(ConfigError::at(
                main,
                &src,
                spans.general.mode.as_ref().map(|v| v.span().start),
                "enforce mode is not available in this release (planned for v0.2.0)",
            ));
        }
        let (thr, quar) = (
            cfg.general.score_threshold_throttle,
            cfg.general.score_threshold_quarantine,
        );
        if thr >= quar {
            let at = start(&spans.general.score_threshold_throttle)
                .or(start(&spans.general.score_threshold_quarantine));
            return Err(ConfigError::at(
                main,
                &src,
                at,
                format!(
                    "score_threshold_throttle ({thr}) must be below \
                     score_threshold_quarantine ({quar})"
                ),
            ));
        }
        let mut warnings: Vec<Warning> = unconfined_warning(main, &cfg.allowlist)
            .into_iter()
            .collect();

        let mut files: Vec<PathBuf> = match std::fs::read_dir(dropin_dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.extension().is_some_and(|x| x == "toml")
                        && !p
                            .file_name()
                            .is_some_and(|n| n.as_encoded_bytes()[0] == b'.')
                        && p.metadata().is_ok_and(|m| m.is_file())
                })
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                return Err(ConfigError {
                    path: dropin_dir.to_owned(),
                    line_col: None,
                    message: e.to_string(),
                })
            }
        };
        files.sort();
        for f in files {
            let d: DropIn = parse(&f, &read(&f)?)?;
            warnings.extend(unconfined_warning(&f, &d.allowlist));
            let a = &mut cfg.allowlist;
            a.excluded_parent_processes
                .extend(d.allowlist.excluded_parent_processes);
            a.excluded_selinux_domains
                .extend(d.allowlist.excluded_selinux_domains);
            for (p, h) in d.allowlist.pinned {
                a.pinned.retain(|(q, _)| *q != p);
                a.pinned.push((p, h));
            }
        }

        Ok((cfg, warnings))
    }
}

/// The running config. A reload that fails leaves the old one in place.
pub struct ConfigHandle {
    main: PathBuf,
    dropin_dir: PathBuf,
    cur: RwLock<Arc<Config>>,
}

impl ConfigHandle {
    pub fn new(main: PathBuf, dropin_dir: PathBuf) -> Result<(Self, Vec<Warning>), ConfigError> {
        let (cfg, warnings) = Config::load_checked(&main, &dropin_dir)?;
        let h = Self {
            main,
            dropin_dir,
            cur: RwLock::new(Arc::new(cfg)),
        };
        Ok((h, warnings))
    }

    pub fn current(&self) -> Arc<Config> {
        self.cur.read().unwrap().clone()
    }

    pub fn reload(&self) -> Result<Vec<Warning>, ConfigError> {
        let (cfg, warnings) = Config::load_checked(&self.main, &self.dropin_dir)?;
        *self.cur.write().unwrap() = Arc::new(cfg);
        Ok(warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);
    impl Dir {
        fn new(name: &str) -> Self {
            let d = std::env::temp_dir().join(format!("aegis-cfg-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(d.join("allowlist.d")).unwrap();
            Self(d)
        }
        fn main(&self, body: &str) -> PathBuf {
            let p = self.0.join("config.toml");
            std::fs::write(&p, body).unwrap();
            p
        }
        fn dropin(&self, name: &str, body: &str) {
            std::fs::write(self.0.join("allowlist.d").join(name), body).unwrap();
        }
        fn dir(&self) -> PathBuf {
            self.0.join("allowlist.d")
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn load(t: &Dir, body: &str) -> Result<Config, ConfigError> {
        Config::load(&t.main(body), &t.dir())
    }

    #[test]
    fn defaults_match_spec() {
        let t = Dir::new("defaults");
        let c = load(&t, "").unwrap();
        assert_eq!(c.general.mode, Mode::Audit);
        assert_eq!(c.general.score_threshold_throttle, 50);
        assert_eq!(c.general.score_threshold_quarantine, 80);
        assert_eq!(c.quarantine.overlay_max_size_mb, 512);
        assert_eq!(c.quarantine.auto_expire_seconds, 3600);
        assert_eq!(c.scoring.half_life_secs, 30.0);
        assert_eq!(c.scoring.weights.tmp_exec, 25.0);
        let w = &c.scoring.weights;
        assert_eq!(
            (
                w.tmp_exec,
                w.memfd_create,
                w.memfd_exec,
                w.ptrace_system_daemon,
                w.egress_scan
            ),
            (25.0, 20.0, 60.0, 45.0, 40.0)
        );
        let sc = &c.scoring.scan;
        assert_eq!(
            (sc.window_secs, sc.distinct_targets, sc.failed_connects),
            (2.0, 20, 10)
        );
        assert_eq!(
            c.incidents.dir,
            PathBuf::from("/var/lib/aegis-v2/incidents")
        );
        assert_eq!(
            c.telemetry,
            TelemetryConfig {
                jsonl: None,
                otlp: None
            }
        );
        assert_eq!(c.allowlist, Allowlist::default());
        assert_eq!(c, Config::default());
    }

    #[test]
    fn enforce_rejected_in_v0_1() {
        let t = Dir::new("enforce");
        let e = load(&t, "[general]\nmode = \"enforce\"\n").unwrap_err();
        assert_eq!(
            e.message,
            "enforce mode is not available in this release (planned for v0.2.0)"
        );
        assert_eq!(e.line_col, Some((2, 8)));
    }

    #[test]
    fn throttle_must_be_below_quarantine() {
        let t = Dir::new("thresholds");
        let e = load(
            &t,
            "[general]\nscore_threshold_throttle = 90\nscore_threshold_quarantine = 80\n",
        )
        .unwrap_err();
        assert!(e.message.contains("must be below"), "{e}");
        assert_eq!(e.line_col.unwrap().0, 2);
    }

    #[test]
    fn unknown_key_is_error_with_line_number() {
        let t = Dir::new("unknown");
        let e = load(&t, "[general]\nmode = \"audit\"\nbogus = 1\n").unwrap_err();
        assert_eq!(e.line_col.unwrap().0, 3, "{e}");
        assert!(e.to_string().contains("config.toml:3:"), "{e}");
        assert!(e.message.contains("bogus"), "{e}");
    }

    #[test]
    fn dropins_merge_in_lexical_order() {
        let t = Dir::new("dropins");
        t.dropin(
            "10-b.toml",
            "[allowlist]\nexcluded_parent_processes = [\"/usr/bin/b\"]\n",
        );
        t.dropin(
            "00-a.toml",
            "[allowlist]\nexcluded_parent_processes = [\"/usr/bin/a\"]\n",
        );
        t.dropin("ignored.txt", "not toml at all");
        let c = load(&t, "").unwrap();
        assert_eq!(
            c.allowlist.excluded_parent_processes,
            [PathBuf::from("/usr/bin/a"), PathBuf::from("/usr/bin/b")]
        );
    }

    #[test]
    fn later_dropin_replaces_pin_for_same_path() {
        let t = Dir::new("pins");
        let h = |c: char| c.to_string().repeat(64);
        t.dropin(
            "00.toml",
            &format!("[allowlist.pinned]\n\"/opt/x\" = \"{}\"\n", h('a')),
        );
        t.dropin(
            "10.toml",
            &format!("[allowlist.pinned]\n\"/opt/x\" = \"{}\"\n", h('B')),
        );
        let c = load(&t, "").unwrap();
        assert_eq!(c.allowlist.pinned, [(PathBuf::from("/opt/x"), [0xBB; 32])]);
    }

    #[test]
    fn bad_pin_hex_is_error_with_location() {
        let t = Dir::new("badpin");
        t.dropin("00.toml", "[allowlist.pinned]\n\"/opt/x\" = \"abc\"\n");
        let e = load(&t, "").unwrap_err();
        assert!(e.message.contains("64 hex"), "{e}");
        assert_eq!(e.line_col.unwrap().0, 2);
        assert!(e.path.ends_with("00.toml"));
        t.dropin(
            "00.toml",
            &format!("[allowlist.pinned]\n\"/opt/x\" = \"{}\"\n", "g".repeat(64)),
        );
        assert!(load(&t, "").is_err());
    }

    #[test]
    fn bare_parent_name_is_error() {
        let t = Dir::new("barename");
        let e = load(&t, "[allowlist]\nexcluded_parent_processes = [\"dnf\"]\n").unwrap_err();
        assert!(
            e.message.contains("absolute path") && e.message.contains("spoofed"),
            "{e}"
        );
        assert_eq!(e.line_col.unwrap().0, 2);
    }

    #[test]
    fn bad_scoring_values_rejected() {
        let t = Dir::new("scoring");
        assert!(load(&t, "[scoring.weights]\ntmp_exec = -1.0\n").is_err());
        assert!(load(&t, "[scoring.weights]\ntmp_exec = nan\n").is_err());
        assert!(load(&t, "[scoring]\nhalf_life_secs = 0.0\n").is_err());
        assert!(load(&t, "[scoring.weights]\ntmp_exec = 0.0\n").is_ok());
    }

    #[test]
    fn unconfined_t_in_allowlist_warns() {
        let t = Dir::new("unconfined");
        let m = t.main("[allowlist]\nexcluded_selinux_domains = [\"unconfined_t\"]\n");
        let (c, w) = Config::load_checked(&m, &t.dir()).unwrap();
        assert_eq!(c.allowlist.excluded_selinux_domains, ["unconfined_t"]);
        assert_eq!(w.len(), 1);
        assert!(w[0].message.contains("unconfined_t"));
    }

    #[test]
    fn reload_failure_keeps_previous() {
        let t = Dir::new("reload");
        let m = t.main("[quarantine]\noverlay_max_size_mb = 100\n");
        let h = ConfigHandle::new(m.clone(), t.dir()).unwrap().0;
        assert_eq!(h.current().quarantine.overlay_max_size_mb, 100);

        t.main("[quarantine]\noverlay_max_size_mb = 200\n");
        h.reload().unwrap();
        assert_eq!(h.current().quarantine.overlay_max_size_mb, 200);

        t.main("[quarantine]\noverlay_max_size_mb = \n");
        assert!(h.reload().is_err());
        assert_eq!(h.current().quarantine.overlay_max_size_mb, 200);
    }

    #[test]
    fn shipped_config_equals_defaults() {
        let t = Dir::new("shipped");
        let c = load(&t, include_str!("../../packaging/config.toml")).unwrap();
        assert_eq!(c, Config::default());

        // Serde fills missing keys, so equality alone would pass on a
        // file that left one out. Every key must be written down.
        let table: toml::Table = include_str!("../../packaging/config.toml").parse().unwrap();
        for key in [
            "general.mode",
            "general.score_threshold_throttle",
            "general.score_threshold_quarantine",
            "scoring.half_life_secs",
            "scoring.weights.tmp_exec",
            "scoring.weights.memfd_create",
            "scoring.weights.memfd_exec",
            "scoring.weights.ptrace_system_daemon",
            "scoring.weights.egress_scan",
            "scoring.scan.window_secs",
            "scoring.scan.distinct_targets",
            "scoring.scan.failed_connects",
            "quarantine.overlay_max_size_mb",
            "quarantine.auto_expire_seconds",
            "incidents.dir",
        ] {
            let mut v = Some(&table);
            let mut leaf = None;
            for part in key.split('.') {
                leaf = v.and_then(|t| t.get(part));
                v = leaf.and_then(|x| x.as_table());
            }
            assert!(leaf.is_some(), "packaging/config.toml is missing {key}");
        }
    }

    #[test]
    fn dropin_unconfined_t_warns_with_its_own_path() {
        let t = Dir::new("dropin-unconfined");
        t.dropin(
            "00.toml",
            "[allowlist]\nexcluded_selinux_domains = [\"unconfined_t\"]\n",
        );
        let m = t.main("");
        let (_, w) = Config::load_checked(&m, &t.dir()).unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].path.ends_with("allowlist.d/00.toml"), "{}", w[0]);
    }

    #[test]
    fn handle_new_returns_startup_warnings() {
        let t = Dir::new("handle-warn");
        let m = t.main("[allowlist]\nexcluded_selinux_domains = [\"unconfined_t\"]\n");
        let (_, w) = ConfigHandle::new(m, t.dir()).unwrap();
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn spans_are_exact_for_inline_tables() {
        let t = Dir::new("spans");
        let e = load(
            &t,
            "[general]\nscore_threshold_quarantine = 60\n\"score_threshold_throttle\" = 70\n",
        )
        .unwrap_err();
        assert_eq!(e.line_col.unwrap().0, 3, "{e}");
        let e = load(&t, "x = 1\n[scoring]\n[general]\nmode = \"enforce\"\n").unwrap_err();
        assert!(e.line_col.is_some());
        let e = load(&t, "general = { mode = \"enforce\" }\n").unwrap_err();
        assert_eq!(e.line_col.unwrap().0, 1);
    }

    #[test]
    fn dotfiles_and_directories_are_not_dropins() {
        let t = Dir::new("skip");
        t.dropin(".hidden.toml", "garbage ][");
        std::fs::create_dir(t.dir().join("dir.toml")).unwrap();
        assert!(load(&t, "").is_ok());
    }

    #[test]
    fn zero_counts_rejected() {
        let t = Dir::new("zero");
        for body in [
            "[scoring.scan]\ndistinct_targets = 0\n",
            "[scoring.scan]\nfailed_connects = 0\n",
            "[quarantine]\noverlay_max_size_mb = 0\n",
            "[quarantine]\nauto_expire_seconds = 0\n",
        ] {
            let e = load(&t, body).unwrap_err();
            assert!(e.message.contains("at least 1"), "{e}");
        }
    }

    #[test]
    fn shipped_dropin_has_expected_parents_and_no_unconfined() {
        let t = Dir::new("shipped-dropin");
        t.dropin(
            "00-default.toml",
            include_str!("../../packaging/allowlist.d/00-default.toml"),
        );
        let m = t.main("");
        let (c, w) = Config::load_checked(&m, &t.dir()).unwrap();
        assert!(w.is_empty());
        let names: Vec<_> = c
            .allowlist
            .excluded_parent_processes
            .iter()
            .map(|p| p.to_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "/usr/bin/ansible-playbook",
                "/usr/bin/dnf",
                "/usr/bin/rpm",
                "/usr/bin/podman",
                "/usr/bin/cargo",
                "/usr/bin/pip3"
            ]
        );
        assert!(c.allowlist.excluded_selinux_domains.is_empty());
    }
}
