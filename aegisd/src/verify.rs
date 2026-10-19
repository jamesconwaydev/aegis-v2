// SPDX-License-Identifier: MIT OR Apache-2.0
//! Executable verification against the RPM database.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verification {
    RpmOwned { package: String },
    Pinned,
    Modified,
    Unverified,
}

pub trait RpmDb {
    /// Name of the package that owns `p`, if any.
    fn owner(&self, p: &Path) -> Option<String>;
    /// True if `p` still matches the database (digest, size and mode).
    fn verify(&self, p: &Path) -> bool;
}

/// (dev, ino, mtime sec, mtime nsec): a replaced file gets a new key.
type FileId = (u64, u64, i64, i64);

pub struct Verifier<D: RpmDb> {
    db: D,
    cache: Mutex<HashMap<FileId, Verification>>,
}

impl<D: RpmDb> Verifier<D> {
    pub fn new(db: D) -> Self {
        Self {
            db,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// A pinned path whose hash matches is `Pinned`; one whose hash does
    /// not is `Modified`. Everything else defers to the rpmdb. Results are
    /// cached per file identity, so `pinned` must not change between calls.
    pub fn verify(&self, exe: &Path, pinned: &[(PathBuf, [u8; 32])]) -> Verification {
        let id = std::fs::metadata(exe)
            .ok()
            .map(|m| (m.dev(), m.ino(), m.mtime(), m.mtime_nsec()));
        if let Some(v) = id.and_then(|id| self.cache.lock().unwrap().get(&id).cloned()) {
            return v;
        }
        let v = self.compute(exe, pinned);
        if let Some(id) = id {
            self.cache.lock().unwrap().insert(id, v.clone());
        }
        v
    }

    fn compute(&self, exe: &Path, pinned: &[(PathBuf, [u8; 32])]) -> Verification {
        if let Some((_, want)) = pinned.iter().find(|(p, _)| p == exe) {
            return match sha256_file(exe) {
                Some(got) if got == *want => Verification::Pinned,
                _ => Verification::Modified,
            };
        }
        match self.db.owner(exe) {
            Some(package) if self.db.verify(exe) => Verification::RpmOwned { package },
            Some(_) => Verification::Modified,
            None => Verification::Unverified,
        }
    }
}

fn sha256_file(p: &Path) -> Option<[u8; 32]> {
    let mut f = std::fs::File::open(p).ok()?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            return Some(h.finalize().into());
        }
        h.update(&buf[..n]);
    }
}

/// The real thing: shells out to `rpm`, 2 s per call.
pub struct Rpm;

const RPM_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs `rpm args`, returning stdout, or None on spawn failure, timeout
/// or a non-UTF-8 reply. A non-zero exit still returns the output, since
/// `rpm -V` exits non-zero when it finds a difference.
fn rpm(args: &[&std::ffi::OsStr]) -> Option<(bool, String)> {
    let mut child = Command::new("rpm")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        let _ = tx.send(s);
    });
    match rx.recv_timeout(RPM_TIMEOUT) {
        Ok(s) => Some((child.wait().ok()?.success(), s)),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

impl RpmDb for Rpm {
    fn owner(&self, p: &Path) -> Option<String> {
        let (ok, out) = rpm(&[
            "-qf".as_ref(),
            "--qf".as_ref(),
            "%{NAME}\n".as_ref(),
            p.as_os_str(),
        ])?;
        // A file shared by several packages prints several names; take the first.
        let name = out.lines().next()?.trim();
        (ok && !name.is_empty()).then(|| name.to_string())
    }

    fn verify(&self, p: &Path) -> bool {
        // -Vf checks the whole owning package, so keep only p's own line.
        let Some((_, out)) = rpm(&["-Vf".as_ref(), p.as_os_str()]) else {
            return false; // couldn't tell: don't vouch for it
        };
        !out.lines().any(|l| line_modifies(l, p))
    }
}

/// True if a `rpm -V` line reports a size, mode or digest failure for `p`.
fn line_modifies(line: &str, p: &Path) -> bool {
    let Some((flags, rest)) = line.split_once(' ') else {
        return false;
    };
    if flags.len() != 9 {
        return false; // "missing", or noise
    }
    // The path is the last field; a config marker (c, d, g, l, r) may precede it.
    let path = rest.trim_start();
    let path = match path.split_once(' ') {
        Some((m, r)) if m.len() == 1 => r.trim_start(),
        _ => path,
    };
    Path::new(path) == p
        && flags
            .bytes()
            .take(3)
            .any(|b| matches!(b, b'S' | b'M' | b'5'))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        owner: Option<&'static str>,
        ok: bool,
    }
    impl RpmDb for Fake {
        fn owner(&self, _: &Path) -> Option<String> {
            self.owner.map(String::from)
        }
        fn verify(&self, _: &Path) -> bool {
            self.ok
        }
    }

    fn v(owner: Option<&'static str>, ok: bool, p: &str) -> Verification {
        Verifier::new(Fake { owner, ok }).verify(Path::new(p), &[])
    }

    #[test]
    fn verify_rpm_owned_unmodified() {
        assert_eq!(
            v(Some("bash"), true, "/usr/bin/bash"),
            Verification::RpmOwned {
                package: "bash".into()
            }
        );
    }

    #[test]
    fn verify_comm_named_cargo_in_tmp_is_unverified() {
        assert_eq!(v(None, false, "/tmp/cargo"), Verification::Unverified);
    }

    #[test]
    fn verify_modified_binary() {
        assert_eq!(
            v(Some("bash"), false, "/usr/bin/bash"),
            Verification::Modified
        );
    }

    #[test]
    fn verify_pinned_hash() {
        let p = std::env::temp_dir().join(format!("aegis-pin-{}", std::process::id()));
        std::fs::write(&p, b"hello").unwrap();
        let good: [u8; 32] = Sha256::digest(b"hello").into();
        let ver = Verifier::new(Fake {
            owner: None,
            ok: false,
        });
        assert_eq!(ver.verify(&p, &[(p.clone(), good)]), Verification::Pinned);
        let ver = Verifier::new(Fake {
            owner: None,
            ok: false,
        });
        assert_eq!(
            ver.verify(&p, &[(p.clone(), [0; 32])]),
            Verification::Modified
        );
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn rpm_verify_line_parsing() {
        let p = Path::new("/usr/bin/x");
        assert!(line_modifies("S.5....T.    /usr/bin/x", p));
        assert!(line_modifies(".M.......    /usr/bin/x", p));
        assert!(!line_modifies(".......T.    /usr/bin/x", p));
        assert!(!line_modifies("S.5....T.  c /usr/bin/other", p));
        assert!(line_modifies("S.5....T.  c /usr/bin/x", p));
        assert!(!line_modifies("missing     /usr/bin/x", p));
    }
}
