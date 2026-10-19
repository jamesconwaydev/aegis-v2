// SPDX-License-Identifier: MIT OR Apache-2.0
//! Executable verification against the RPM database.

use std::collections::HashMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::Duration;
use std::time::Instant;

use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verification {
    RpmOwned { package: String },
    Pinned,
    Modified,
    Unverified,
}

/// What `rpm -qf` said about a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    Owned(String),
    /// rpm ran and said so: exit 1 and "is not owned by any package".
    NotOwned,
    /// Anything else: a timeout, a spawn failure, another exit or
    /// message. Never cached.
    Indeterminate,
}

pub trait RpmDb {
    /// Which package owns `p`.
    fn owner(&self, p: &Path) -> Owner;
    /// Whether the file still matches the database (digest, size and
    /// mode). `p` is only for the database lookup; `f` and `md` are the
    /// one handle the Verifier opened, and must be what gets hashed and
    /// compared, so the file can't be swapped between check and hash.
    /// `None` means we couldn't tell (rpm failed, timed out, or the
    /// database has nothing usable for the file).
    fn verify(&self, p: &Path, f: &File, md: &Metadata) -> Option<bool>;
}

/// (dev, ino, size, mtime sec/nsec, ctime sec/nsec). ctime can't be set
/// from userspace, so rewriting a file in place and resetting its mtime
/// still changes the key.
type FileId = (u64, u64, u64, i64, i64, i64, i64);

/// The host's root, seen from aegisd: pid 1's. aegisd's own may differ
/// (ProtectSystem=strict, PrivateTmp), and a process's may differ more.
pub const HOST_ROOT: &str = "/proc/1/root";

/// `exe` (absolute) in the host's tree under `root`.
pub fn on_host(root: &Path, exe: &Path) -> PathBuf {
    root.join(exe.strip_prefix("/").unwrap_or(exe))
}

pub struct Verifier<D: RpmDb> {
    db: D,
    cache: Mutex<HashMap<FileId, Verification>>,
    host_root: PathBuf,
}

impl<D: RpmDb> Verifier<D> {
    pub fn new(db: D) -> Self {
        Self::with_root(db, HOST_ROOT)
    }

    /// Checks names against the tree at `root` instead of pid 1's.
    pub fn with_root(db: D, root: impl Into<PathBuf>) -> Self {
        Self {
            db,
            cache: Mutex::new(HashMap::new()),
            host_root: root.into(),
        }
    }

    /// Judges the file a process executed: inode `id` (dev, ino), which
    /// it ran under the name `exe`. A pinned path whose hash matches is
    /// `Pinned`; one whose hash does not is `Modified`. Everything else
    /// defers to the rpmdb. Results are cached per file identity, so
    /// `pinned` must not change between calls.
    ///
    /// `exe` is only a name. Inside a chroot or a container a process can
    /// run any file under a trusted one, so unless the host's file at
    /// `exe` is inode `id` itself, the answer is `Unverified`.
    pub fn verify(
        &self,
        exe: &Path,
        id: (u64, u64),
        pinned: &[(PathBuf, [u8; 32])],
    ) -> Verification {
        match self.open_on_host(exe) {
            Some((f, md)) if (md.dev(), md.ino()) == id => self.judge(exe, &f, &md, pinned),
            _ => Verification::Unverified,
        }
    }

    /// Verifies the host's file at `exe` when no process is running it
    /// yet, returning its (dev, ino) with the verdict.
    pub fn verify_host(
        &self,
        exe: &Path,
        pinned: &[(PathBuf, [u8; 32])],
    ) -> Option<((u64, u64), Verification)> {
        let (f, md) = self.open_on_host(exe)?;
        Some(((md.dev(), md.ino()), self.judge(exe, &f, &md, pinned)))
    }

    /// Opens without following a final symlink and without blocking: a
    /// FIFO or a device at a trusted path must never stall a verifier
    /// thread. Only a regular file is worth asking rpm about or hashing.
    fn open_on_host(&self, exe: &Path) -> Option<(File, Metadata)> {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(on_host(&self.host_root, exe))
            .ok()?;
        let md = f.metadata().ok()?;
        md.file_type().is_file().then_some((f, md))
    }

    /// The key, the size/mode and the hash all come from the one handle
    /// `f`, so a swap after it was opened can't change what we vouch for.
    fn judge(
        &self,
        exe: &Path,
        f: &File,
        md: &Metadata,
        pinned: &[(PathBuf, [u8; 32])],
    ) -> Verification {
        let id = (
            md.dev(),
            md.ino(),
            md.size(),
            md.mtime(),
            md.mtime_nsec(),
            md.ctime(),
            md.ctime_nsec(),
        );
        if let Some(v) = self.cache.lock().unwrap().get(&id).cloned() {
            return v;
        }
        let (v, cacheable) = self.compute(exe, f, md, pinned);
        if cacheable {
            // ponytail: unbounded, but bounded by the number of distinct
            // executables seen; add an LRU if it ever grows.
            self.cache.lock().unwrap().insert(id, v.clone());
        }
        v
    }

    /// The verdict, and whether it is safe to cache (indeterminate
    /// answers are not).
    fn compute(
        &self,
        exe: &Path,
        f: &File,
        md: &Metadata,
        pinned: &[(PathBuf, [u8; 32])],
    ) -> (Verification, bool) {
        if let Some((_, want)) = pinned.iter().find(|(p, _)| p == exe) {
            return match sha256_file(f) {
                Some(got) if got == *want => (Verification::Pinned, true),
                _ => (Verification::Modified, true),
            };
        }
        match self.db.owner(exe) {
            Owner::Owned(package) => match self.db.verify(exe, f, md) {
                Some(true) => (Verification::RpmOwned { package }, true),
                Some(false) => (Verification::Modified, true),
                None => (Verification::Unverified, false),
            },
            Owner::NotOwned => (Verification::Unverified, true),
            Owner::Indeterminate => (Verification::Unverified, false),
        }
    }
}

fn sha256_file(mut f: &File) -> Option<[u8; 32]> {
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

/// The real thing: shells out to `/usr/bin/rpm`, 2 s per call.
pub struct Rpm;

/// By absolute path, so `PATH` never picks the binary we trust.
const RPM: &str = "/usr/bin/rpm";
pub const RPM_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs `rpm args`, returning (exit code, stdout bytes), or None on spawn
/// failure or timeout. The code is None when rpm died on a signal.
fn rpm(args: &[&std::ffi::OsStr]) -> Option<(Option<i32>, Vec<u8>)> {
    let mut child = Command::new(RPM)
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
    let deadline = Instant::now() + RPM_TIMEOUT;
    if let Ok(Some(s)) = rx.recv_timeout(RPM_TIMEOUT) {
        // EOF doesn't mean exited; don't block on wait() forever.
        while Instant::now() < deadline {
            if let Ok(Some(st)) = child.try_wait() {
                return Some((st.code(), s));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

impl RpmDb for Rpm {
    fn owner(&self, p: &Path) -> Owner {
        let r = rpm(&[
            "-qf".as_ref(),
            "--qf".as_ref(),
            "%{NAME}\n".as_ref(),
            "--".as_ref(),
            p.as_os_str(),
        ]);
        classify_owner(p, r)
    }

    fn verify(&self, p: &Path, f: &File, md: &Metadata) -> Option<bool> {
        let (code, out) = rpm(&[
            "-qf".as_ref(),
            "--dump".as_ref(),
            "--".as_ref(),
            p.as_os_str(),
        ])?;
        if code != Some(0) {
            return None;
        }
        dump_matches(&out, p, md.len(), md.mode(), || sha256_file(f))
    }
}

/// Reads `rpm -qf --qf '%{NAME}\n' -- p`'s outcome. Only exit 0 with a
/// name is owned, and only exit 1 with rpm's own "not owned" line for
/// `p` is not owned; everything else is indeterminate.
fn classify_owner(p: &Path, r: Option<(Option<i32>, Vec<u8>)>) -> Owner {
    let Some((code, out)) = r else {
        return Owner::Indeterminate;
    };
    let mut lines = out.split(|&b| b == b'\n');
    match code {
        Some(0) => {
            // A file shared by several packages prints several names; take
            // the first.
            let name = String::from_utf8_lossy(lines.next().unwrap_or_default())
                .trim()
                .to_string();
            if name.is_empty() {
                Owner::Indeterminate
            } else {
                Owner::Owned(name)
            }
        }
        Some(1) => {
            let mut want = b"file ".to_vec();
            want.extend_from_slice(p.as_os_str().as_bytes());
            want.extend_from_slice(b" is not owned by any package");
            if lines.any(|l| l == want) {
                Owner::NotOwned
            } else {
                Owner::Indeterminate
            }
        }
        _ => Owner::Indeterminate,
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
        fn owner(&self, _: &Path) -> Owner {
            self.owner
                .map_or(Owner::NotOwned, |o| Owner::Owned(o.into()))
        }
        fn verify(&self, _: &Path, _: &File, _: &Metadata) -> Option<bool> {
            self.ok
        }
    }

    /// A real file (the Verifier opens it), removed on drop.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(name: &str, body: &[u8]) -> Self {
            let p = std::env::temp_dir().join(format!("aegis-{name}-{}", std::process::id()));
            std::fs::write(&p, body).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A Verifier whose "host" is our own root, so the temp files count.
    fn ver<D: RpmDb>(db: D) -> Verifier<D> {
        Verifier::with_root(db, "/")
    }

    /// Verifies `p` as a process running that very file would.
    fn check<D: RpmDb>(ver: &Verifier<D>, p: &Path, pins: &[(PathBuf, [u8; 32])]) -> Verification {
        ver.verify(p, ino(p), pins)
    }

    fn ino(p: &Path) -> (u64, u64) {
        let md = std::fs::metadata(p).unwrap();
        (md.dev(), md.ino())
    }

    fn v(name: &str, owner: Option<&'static str>, ok: Option<bool>) -> Verification {
        let t = Tmp::new(name, b"x");
        check(&ver(Fake { owner, ok }), &t.0, &[])
    }

    #[test]
    fn a_lookalike_under_a_trusted_name_is_unverified() {
        // What a chroot shows as /usr/bin/python3 is a copy, not the
        // host's file. Same name, same bytes, different inode.
        let host = Tmp::new("host-py", b"python");
        let copy = Tmp::new("chroot-py", b"python");
        let ver = ver(Fake {
            owner: Some("python3"),
            ok: Some(true),
        });
        let run = ino(&copy.0);
        assert_eq!(ver.verify(&host.0, run, &[]), Verification::Unverified);
        let pin: [u8; 32] = Sha256::digest(b"python").into();
        assert_eq!(
            ver.verify(&host.0, run, &[(host.0.clone(), pin)]),
            Verification::Unverified,
            "a pin names the host's file too"
        );
        assert!(ver.cache.lock().unwrap().is_empty());
        // The host's own file still verifies.
        assert_eq!(
            check(&ver, &host.0, &[]),
            Verification::RpmOwned {
                package: "python3".into()
            }
        );
    }

    #[test]
    fn a_name_missing_on_the_host_is_unverified() {
        let t = Tmp::new("nohost", b"x");
        let ver = Verifier::with_root(
            Fake {
                owner: Some("bash"),
                ok: Some(true),
            },
            std::env::temp_dir().join("aegis-no-such-root"),
        );
        assert_eq!(check(&ver, &t.0, &[]), Verification::Unverified);
    }

    #[test]
    fn verify_rpm_owned_unmodified() {
        assert_eq!(
            v("owned", Some("bash"), Some(true)),
            Verification::RpmOwned {
                package: "bash".into()
            }
        );
    }

    #[test]
    fn verify_comm_named_cargo_in_tmp_is_unverified() {
        assert_eq!(v("cargo", None, None), Verification::Unverified);
    }

    #[test]
    fn verify_modified_binary() {
        assert_eq!(v("mod", Some("bash"), Some(false)), Verification::Modified);
    }

    #[test]
    fn verify_pinned_hash() {
        let t = Tmp::new("pin", b"hello");
        let p = t.0.clone();
        let good: [u8; 32] = Sha256::digest(b"hello").into();
        let v = ver(Fake {
            owner: None,
            ok: None,
        });
        assert_eq!(check(&v, &p, &[(p.clone(), good)]), Verification::Pinned);
        let v = ver(Fake {
            owner: None,
            ok: None,
        });
        assert_eq!(
            check(&v, &p, &[(p.clone(), [0; 32])]),
            Verification::Modified
        );
    }

    #[test]
    fn rpm_owner_outcomes() {
        let p = Path::new("/tmp/x");
        let r = |code: Option<i32>, out: &[u8]| classify_owner(p, Some((code, out.to_vec())));
        assert_eq!(
            r(Some(0), b"coreutils-single\nother\n"),
            Owner::Owned("coreutils-single".into())
        );
        assert_eq!(
            r(Some(1), b"file /tmp/x is not owned by any package\n"),
            Owner::NotOwned
        );
        // Exit 1 for any other reason: a missing file, a broken database.
        assert_eq!(
            r(Some(1), b"error: file /tmp/x: No such file or directory\n"),
            Owner::Indeterminate
        );
        // Another path's "not owned" line doesn't count for this one.
        assert_eq!(
            r(Some(1), b"file /tmp/xy is not owned by any package\n"),
            Owner::Indeterminate
        );
        assert_eq!(r(Some(0), b"\n"), Owner::Indeterminate);
        assert_eq!(r(Some(2), b""), Owner::Indeterminate);
        assert_eq!(r(None, b""), Owner::Indeterminate, "killed by a signal");
        assert_eq!(
            classify_owner(p, None),
            Owner::Indeterminate,
            "timeout or spawn failure"
        );
    }

    struct Owners(Owner);
    impl RpmDb for Owners {
        fn owner(&self, _: &Path) -> Owner {
            self.0.clone()
        }
        fn verify(&self, _: &Path, _: &File, _: &Metadata) -> Option<bool> {
            Some(true)
        }
    }

    #[test]
    fn indeterminate_owner_is_unverified_and_not_cached() {
        let t = Tmp::new("ind-owner", b"x");
        let ind = ver(Owners(Owner::Indeterminate));
        assert_eq!(check(&ind, &t.0, &[]), Verification::Unverified);
        assert!(ind.cache.lock().unwrap().is_empty());
        // Not owned is a real answer, so it is cached.
        let not = ver(Owners(Owner::NotOwned));
        assert_eq!(check(&not, &t.0, &[]), Verification::Unverified);
        assert_eq!(not.cache.lock().unwrap().len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_fifo_at_a_trusted_path_does_not_block() {
        let p = std::env::temp_dir().join(format!("aegis-fifo-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = mpsc::channel();
        let q = p.clone();
        std::thread::spawn(move || {
            let ver = ver(Fake {
                owner: Some("bash"),
                ok: Some(true),
            });
            let pin = [(q.clone(), [0u8; 32])];
            let host = ver.verify_host(&q, &pin);
            let exec = ver.verify(&q, ino(&q), &pin);
            let _ = tx.send((host, exec));
        });
        let got = rx.recv_timeout(Duration::from_secs(5));
        let _ = std::fs::remove_file(&p);
        let (host, exec) = got.expect("verifying a FIFO blocked");
        assert!(host.is_none());
        assert_eq!(exec, Verification::Unverified);
    }

    #[test]
    fn a_symlink_at_a_trusted_path_is_unverified() {
        let t = Tmp::new("link-target", b"x");
        let l = std::env::temp_dir().join(format!("aegis-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&l);
        std::os::unix::fs::symlink(&t.0, &l).unwrap();
        let ver = ver(Fake {
            owner: Some("bash"),
            ok: Some(true),
        });
        let got = ver.verify(&l, ino(&t.0), &[]);
        let _ = std::fs::remove_file(&l);
        assert_eq!(got, Verification::Unverified);
    }

    #[test]
    fn indeterminate_verify_is_unverified_and_not_cached() {
        let t = Tmp::new("ind", b"x");
        let p = t.0.clone();
        let ver = ver(Fake {
            owner: Some("bash"),
            ok: None,
        });
        assert_eq!(check(&ver, &p, &[]), Verification::Unverified);
        assert!(ver.cache.lock().unwrap().is_empty());
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
        let t = Tmp::new("rpmfail", b"x");
        let f = File::open(&t.0).unwrap();
        let md = f.metadata().unwrap();
        assert_eq!(Rpm.verify(&t.0, &f, &md), None);
    }

    /// Swaps the path for a different file during owner(), then judges by
    /// reading the handle it is given. The verdict must describe the file
    /// that was opened, not whatever the path points at now.
    struct Swap {
        path: PathBuf,
        seen_ino: std::sync::Mutex<Option<u64>>,
    }
    impl RpmDb for Swap {
        fn owner(&self, _: &Path) -> Owner {
            let genuine = self.path.with_extension("genuine");
            std::fs::write(&genuine, b"genuine").unwrap();
            std::fs::rename(&genuine, &self.path).unwrap();
            Owner::Owned("bash".into())
        }
        fn verify(&self, _: &Path, mut f: &File, md: &Metadata) -> Option<bool> {
            *self.seen_ino.lock().unwrap() = Some(md.ino());
            let mut body = String::new();
            f.read_to_string(&mut body).unwrap();
            Some(body == "genuine")
        }
    }

    #[test]
    fn cache_key_and_hash_come_from_the_same_handle() {
        let t = Tmp::new("swap", b"evil");
        let evil_ino = std::fs::metadata(&t.0).unwrap().ino();
        let ver = ver(Swap {
            path: t.0.clone(),
            seen_ino: Default::default(),
        });
        assert_eq!(check(&ver, &t.0, &[]), Verification::Modified);
        assert_eq!(*ver.db.seen_ino.lock().unwrap(), Some(evil_ino));
        // cached under the opened (evil) file's identity, not the swapped-in one
        let cache = ver.cache.lock().unwrap();
        assert!(cache.keys().all(|k| k.1 == evil_ino));
        assert_eq!(cache.len(), 1);
    }
}
