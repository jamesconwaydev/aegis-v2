// SPDX-License-Identifier: MIT OR Apache-2.0
//! Executable verification against the RPM database.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
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
    /// Whether `p` still matches the database (digest, size and mode).
    /// `None` means we couldn't tell (rpm failed, timed out, or the
    /// database has nothing usable for the file).
    fn verify(&self, p: &Path) -> Option<bool>;
}

/// (dev, ino, size, mtime sec/nsec, ctime sec/nsec). ctime can't be set
/// from userspace, so rewriting a file in place and resetting its mtime
/// still changes the key.
type FileId = (u64, u64, u64, i64, i64, i64, i64);

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
        let id = std::fs::metadata(exe).ok().map(|m| {
            (
                m.dev(),
                m.ino(),
                m.size(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        });
        if let Some(v) = id.and_then(|id| self.cache.lock().unwrap().get(&id).cloned()) {
            return v;
        }
        let (v, cacheable) = self.compute(exe, pinned);
        if let (Some(id), true) = (id, cacheable) {
            // ponytail: unbounded, but bounded by the number of distinct
            // executables seen; add an LRU if it ever grows.
            self.cache.lock().unwrap().insert(id, v.clone());
        }
        v
    }

    /// The verdict, and whether it is safe to cache (indeterminate
    /// answers are not).
    fn compute(&self, exe: &Path, pinned: &[(PathBuf, [u8; 32])]) -> (Verification, bool) {
        if let Some((_, want)) = pinned.iter().find(|(p, _)| p == exe) {
            return match sha256_file(exe) {
                Some(got) if got == *want => (Verification::Pinned, true),
                _ => (Verification::Modified, true),
            };
        }
        match self.db.owner(exe) {
            Some(package) => match self.db.verify(exe) {
                Some(true) => (Verification::RpmOwned { package }, true),
                Some(false) => (Verification::Modified, true),
                None => (Verification::Unverified, false),
            },
            None => (Verification::Unverified, true),
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

/// Runs `rpm args`, returning (exit ok, stdout bytes), or None on spawn
/// failure or timeout.
fn rpm(args: &[&std::ffi::OsStr]) -> Option<(bool, Vec<u8>)> {
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
        let mut s = Vec::new();
        let r = out.read_to_end(&mut s);
        let _ = tx.send(r.ok().map(|_| s));
    });
    match rx.recv_timeout(RPM_TIMEOUT) {
        Ok(Some(s)) => Some((child.wait().ok()?.success(), s)),
        _ => {
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
            "--".as_ref(),
            p.as_os_str(),
        ])?;
        // A file shared by several packages prints several names; take the first.
        let name = String::from_utf8_lossy(out.split(|&b| b == b'\n').next()?)
            .trim()
            .to_string();
        (ok && !name.is_empty()).then_some(name)
    }

    fn verify(&self, p: &Path) -> Option<bool> {
        let (ok, out) = rpm(&[
            "-qf".as_ref(),
            "--dump".as_ref(),
            "--".as_ref(),
            p.as_os_str(),
        ])?;
        if !ok {
            return None;
        }
        let md = std::fs::metadata(p).ok()?;
        dump_matches(&out, p, md.len(), md.mode(), || sha256_file(p))
    }
}

/// Checks `p` against its `rpm -qf --dump` line (path size mtime digest
/// mode owner group isconfig isdoc rdev symlink). None if the line is
/// absent or the digest isn't a sha256.
fn dump_matches(
    dump: &[u8],
    p: &Path,
    size: u64,
    mode: u32,
    hash: impl FnOnce() -> Option<[u8; 32]>,
) -> Option<bool> {
    let want = p.as_os_str().as_bytes();
    let line = dump
        .split(|&b| b == b'\n')
        .find(|l| l.len() > want.len() && l.starts_with(want) && l[want.len()] == b' ')?;
    let rest = std::str::from_utf8(&line[want.len() + 1..]).ok()?;
    let mut f = rest.split(' ');
    let (rsize, _mtime, digest, rmode) = (f.next()?, f.next()?, f.next()?, f.next()?);
    let rsize: u64 = rsize.parse().ok()?;
    let rmode = u32::from_str_radix(rmode, 8).ok()?;
    if rsize != size || rmode != mode {
        return Some(false);
    }
    if digest.len() != 64 {
        return None; // not sha256 (or no digest recorded)
    }
    let mut want_d = [0u8; 32];
    for (i, b) in want_d.iter_mut().enumerate() {
        *b = u8::from_str_radix(digest.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(hash()? == want_d)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        owner: Option<&'static str>,
        ok: Option<bool>,
    }
    impl RpmDb for Fake {
        fn owner(&self, _: &Path) -> Option<String> {
            self.owner.map(String::from)
        }
        fn verify(&self, _: &Path) -> Option<bool> {
            self.ok
        }
    }

    fn v(owner: Option<&'static str>, ok: Option<bool>, p: &str) -> Verification {
        Verifier::new(Fake { owner, ok }).verify(Path::new(p), &[])
    }

    #[test]
    fn verify_rpm_owned_unmodified() {
        assert_eq!(
            v(Some("bash"), Some(true), "/usr/bin/bash"),
            Verification::RpmOwned {
                package: "bash".into()
            }
        );
    }

    #[test]
    fn verify_comm_named_cargo_in_tmp_is_unverified() {
        assert_eq!(v(None, None, "/tmp/cargo"), Verification::Unverified);
    }

    #[test]
    fn verify_modified_binary() {
        assert_eq!(
            v(Some("bash"), Some(false), "/usr/bin/bash"),
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
            ok: None,
        });
        assert_eq!(ver.verify(&p, &[(p.clone(), good)]), Verification::Pinned);
        let ver = Verifier::new(Fake {
            owner: None,
            ok: None,
        });
        assert_eq!(
            ver.verify(&p, &[(p.clone(), [0; 32])]),
            Verification::Modified
        );
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn indeterminate_verify_is_unverified_and_not_cached() {
        let p = std::env::temp_dir().join(format!("aegis-ind-{}", std::process::id()));
        std::fs::write(&p, b"x").unwrap();
        let ver = Verifier::new(Fake {
            owner: Some("bash"),
            ok: None,
        });
        assert_eq!(ver.verify(&p, &[]), Verification::Unverified);
        assert!(ver.cache.lock().unwrap().is_empty());
        std::fs::remove_file(&p).unwrap();
    }

    // Captured from `rpm -qf --dump -- /usr/bin/true` (coreutils, Rocky 10.2,
    // rpm 4.19.1.1), run in the pinned build container.
    const TRUE_LINE: &[u8] = b"/usr/bin/[ 48 1768435200 afd97bbd643bfe1473794af167cd5c6f44fe449681033e3584b40b836f624b4b 0100555 root root 0 0 0 X\n\
/usr/bin/true 51 1768435200 c73afb60197c9c64805d2b4ab95efdee8646f8248ff800de2575a11eed8f9f08 0100555 root root 0 0 0 X\n";
    const TRUE_SHA: &str = "c73afb60197c9c64805d2b4ab95efdee8646f8248ff800de2575a11eed8f9f08";

    fn sha(h: &str) -> [u8; 32] {
        let mut d = [0u8; 32];
        for i in 0..32 {
            d[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
        d
    }

    #[test]
    fn dump_digest_match_and_mismatch() {
        let p = Path::new("/usr/bin/true");
        assert_eq!(
            dump_matches(TRUE_LINE, p, 51, 0o100555, || Some(sha(TRUE_SHA))),
            Some(true)
        );
        assert_eq!(
            dump_matches(TRUE_LINE, p, 51, 0o100555, || Some([0; 32])),
            Some(false)
        );
        assert_eq!(
            dump_matches(TRUE_LINE, p, 52, 0o100555, || unreachable!()),
            Some(false)
        );
        assert_eq!(
            dump_matches(TRUE_LINE, p, 51, 0o100755, || unreachable!()),
            Some(false)
        );
    }

    #[test]
    fn dump_absent_line_or_garbage_is_indeterminate() {
        let p = Path::new("/usr/bin/other");
        assert_eq!(dump_matches(TRUE_LINE, p, 51, 0o100555, || None), None);
        assert_eq!(dump_matches(b"", p, 1, 1, || None), None);
        // prefix of a longer path must not match
        assert_eq!(
            dump_matches(TRUE_LINE, Path::new("/usr/bin/tru"), 51, 0o100555, || None),
            None
        );
        // non-UTF-8 elsewhere in the dump is fine
        let mut d = b"/bin/\xff 1 1 aa 0100555 r r 0 0 0 X\n".to_vec();
        d.extend_from_slice(TRUE_LINE);
        assert_eq!(
            dump_matches(&d, Path::new("/usr/bin/true"), 51, 0o100555, || Some(sha(
                TRUE_SHA
            ))),
            Some(true)
        );
    }

    #[test]
    fn rpm_failure_is_indeterminate() {
        // Rpm::verify on a path rpm can't resolve (or no rpm installed): not Some.
        assert_eq!(Rpm.verify(Path::new("/nonexistent/aegis-test")), None);
    }
}
