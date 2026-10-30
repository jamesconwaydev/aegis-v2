// SPDX-License-Identifier: MIT OR Apache-2.0
//! Filing the honeypot's finished sessions into their incidents.
//!
//! The spool belongs to the honeypot user, and a compromised honeypot
//! can change anything in it at any moment, so everything there is
//! hostile. aegisd runs as root and must not be steered by it: it walks
//! the tree only through directory fds opened without following links,
//! checks each fd it opens (never a path), copies what it keeps into new
//! root-owned files and never renames anything the honeypot made. A name
//! from the spool is used only once it has parsed into an address, a
//! session id or a SHA-256.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime};

use aegis_proto::honeypot::{Session, PCAP_FIXED};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The honeypot unit's `StateDirectory`, plus `spool`.
pub const SPOOL: &str = "/var/lib/aegis-honeypot/spool";
/// The most `session.json` may be (the honeypot keeps it under this).
pub const MAX_JSON: u64 = 64 * 1024;
/// The most one payload may be: the honeypot holds no more in memory.
const MAX_PAYLOAD: u64 = 256 * 1024;
const MAX_PAYLOADS: usize = 256;
/// Names read from one directory per tick; the rest wait for the next.
const MAX_NAMES: usize = 1024;
/// Sessions handled, bytes copied and entries deleted per tick, so a
/// flood can't hold up the enforcer thread this runs on.
const MAX_SESSIONS: usize = 64;
const MAX_BYTES: u64 = 64 << 20;
const MAX_UNLINKS: usize = 4096;
/// Entries looked at per tick. The honeypot keeps at most 512 sessions
/// open, so a tick sees every live one.
const MAX_VISITS: usize = 8192;
/// How deep a junk tree is deleted. The honeypot never nests deeper
/// than a session's files; anything deeper only costs its own disk.
const MAX_DEPTH: u32 = 4;
/// Longest text from a session put in the timeline or telemetry.
const MAX_TEXT: usize = 255;
/// Sessions filed into one incident; past it they are deleted and
/// counted as rejected, so a flood can't bury what came after it from
/// the incident's readers, which read this many.
pub const MAX_FILED: usize = 4096;
/// 9999-12-31T23:59:59.999Z: no later time is a real one, and later
/// ones overflow nanoseconds.
pub const MAX_MS: u64 = 253_402_300_799_999;

/// Counted for the metrics, as sessions.
#[derive(Default)]
pub struct Counts {
    pub filed: AtomicU64,
    pub unmatched: AtomicU64,
    pub rejected: AtomicU64,
}

#[derive(Clone, Copy)]
pub struct Limits {
    /// `honeypot.max_session_bytes`.
    pub max_session_bytes: u64,
    /// An unfinished session dir older than this was left by a honeypot
    /// that died: it can no longer be live.
    pub stale: Duration,
    /// `MAX_FILED`, but for the tests.
    pub max_filed: usize,
}

/// What one sweep did.
#[derive(Debug, Default)]
pub struct Swept {
    /// (incident id, session) for each session filed.
    pub filed: Vec<(String, Session)>,
    pub unmatched: u64,
    pub rejected: u64,
    /// The first rejection, for the log.
    pub why: Option<String>,
    /// Unfinished session dirs deleted.
    pub stale: u64,
    /// Incidents that refused a session for being full, once each.
    pub capped: Vec<String>,
    /// An error on the incident side that stopped the walk early.
    pub io: Option<io::Error>,
}

/// Where the sessions on an address go: the incident's id, its
/// directory, and when its observation of the address opened (Unix ms).
pub type Find<'a> = &'a dyn Fn(Ipv4Addr) -> Option<(String, PathBuf, u64)>;

/// Why a session wasn't filed.
enum Skip {
    Unmatched,
    /// Filed on an earlier tick, whose delete from the spool failed.
    Filed,
    /// The spool's fault: the session is deleted.
    Bad(String),
    /// Ours (the incident side): the session stays for the next tick.
    Io(io::Error),
}

impl From<io::Error> for Skip {
    fn from(e: io::Error) -> Self {
        Skip::Io(e)
    }
}

fn bad<T>(why: impl std::fmt::Display) -> Result<T, Skip> {
    Err(Skip::Bad(why.to_string()))
}

/// `<unix-ms>-<8 hex>`, as the honeypot names sessions.
pub fn session_id(s: &str) -> bool {
    let Some((ms, r)) = s.split_once('-') else {
        return false;
    };
    (1..=20).contains(&ms.len())
        && ms.bytes().all(|b| b.is_ascii_digit())
        && r.len() == 8
        && r.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The milliseconds a session id starts with.
pub fn id_ms(id: &str) -> Option<u64> {
    id.split_once('-')?.0.parse().ok()
}

fn sha_name(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn incident_addr(a: Ipv4Addr) -> bool {
    a.octets()[..2] == [127, 77]
}

/// An address directory's name, only in its canonical form.
fn addr_name(n: &CStr) -> Option<Ipv4Addr> {
    let s = n.to_str().ok()?;
    let a: Ipv4Addr = s.parse().ok()?;
    (incident_addr(a) && a.to_string() == s).then_some(a)
}

/// `session.json` through its cap and serde, then checked for what
/// filing relies on. The reason never quotes the input.
pub fn parse(json: &[u8]) -> Result<Session, String> {
    if json.len() as u64 > MAX_JSON {
        return Err("session.json is over 64 KiB".into());
    }
    let s: Session = serde_json::from_slice(json).map_err(|e| {
        format!(
            "session.json does not parse (line {}, column {})",
            e.line(),
            e.column()
        )
    })?;
    if !session_id(&s.id) || !incident_addr(s.addr) {
        return Err("session.json has a bad id or address".into());
    }
    // The honeypot names a session by the ms it started; readers sort
    // by that name, so it must not lie.
    if id_ms(&s.id) != Some(s.started_ms) || s.ended_ms < s.started_ms || s.ended_ms > MAX_MS {
        return Err("session.json has impossible times".into());
    }
    let mut p: Vec<&str> = s.payloads.iter().map(String::as_str).collect();
    p.sort_unstable();
    p.dedup();
    if p.len() != s.payloads.len() || p.len() > MAX_PAYLOADS || !p.iter().all(|h| sha_name(h)) {
        return Err("session.json lists bad payload names".into());
    }
    Ok(s)
}

/// Printable and short: what a session says can't reach a terminal raw.
fn text(s: &str) -> String {
    aegis_proto::clean(s).chars().take(MAX_TEXT).collect()
}

/// The timeline's `honeypot_session`. Never payload bytes, credentials,
/// commands, bodies or headers: those stay in the incident's files.
pub fn event(s: &Session) -> Value {
    json!({
        "session": s.id,
        "protocol": s.protocol,
        "dst": s.dst.to_string(),
        "dns_name": s.dns_name.as_deref().map(text),
        "bytes_in": s.bytes_in,
        "bytes_out": s.bytes_out,
        "payloads": s.payloads.len(),
        "truncated": s.truncated,
    })
}

/// The same, as one telemetry reason.
pub fn reason(s: &Session) -> String {
    let proto = serde_json::to_value(s.protocol)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    let name = s
        .dns_name
        .as_deref()
        .map(|n| format!(" ({})", text(n)))
        .unwrap_or_default();
    format!(
        "honeypot_session {}: {proto} to {}{name}, {} bytes in, {} bytes out, {} payloads{}",
        s.id,
        s.dst,
        s.bytes_in,
        s.bytes_out,
        s.payloads.len(),
        if s.truncated { ", truncated" } else { "" }
    )
}

fn cstr(s: &str) -> CString {
    // Only validated names get here, and none holds a NUL.
    CString::new(s).unwrap_or_default()
}

fn openat(dir: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: a valid dirfd and NUL-terminated name; the fd returned is
    // ours alone.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// A directory, never through a link.
fn open_dir(dir: &File, name: &CStr) -> io::Result<File> {
    openat(
        dir,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
}

fn unlinkat(dir: &File, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: a valid dirfd and NUL-terminated name.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Up to `MAX_NAMES` entries of `dir`, without `.` and `..`.
fn names(dir: &File) -> io::Result<Vec<CString>> {
    // fdopendir takes the fd it's given: hand it a duplicate.
    // SAFETY: fcntl and the dirent calls get valid fds and DIR pointers,
    // and each name is copied out before the next readdir.
    unsafe {
        let fd = libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let d = libc::fdopendir(fd);
        if d.is_null() {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        // The duplicate shares the offset an earlier listing moved.
        libc::rewinddir(d);
        let mut out = Vec::new();
        while out.len() < MAX_NAMES {
            let ent = libc::readdir(d);
            if ent.is_null() {
                break;
            }
            let n = CStr::from_ptr((*ent).d_name.as_ptr());
            if n.to_bytes() != b"." && n.to_bytes() != b".." {
                out.push(n.to_owned());
            }
        }
        libc::closedir(d);
        // Oldest session first: ids start with their time.
        out.sort_unstable();
        Ok(out)
    }
}

/// Says which side of the walk an error came from.
fn tag(what: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// Removes what a crash mid-copy left in an incident's `honeypot/`:
/// the hidden directories filing copies into before the rename.
pub fn tidy(inc_dir: &Path) {
    let Ok(rd) = fs::read_dir(inc_dir.join("honeypot")) else {
        return;
    };
    for e in rd.flatten() {
        if e.file_name().as_encoded_bytes().starts_with(b".") {
            let _ = fs::remove_dir_all(e.path());
        }
    }
}

/// A new file only root can read, for the incident.
fn create(p: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(p)
}

fn private_dir(p: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(p) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

/// Copies at most `max` bytes of `src` into a new file at `to`; its
/// size and SHA-256. A source that can't be read, or holds more, is
/// the spool's fault; a failed write is ours.
fn copy(src: &mut File, to: &Path, max: u64) -> Result<(u64, String), Skip> {
    let mut out = create(to)?;
    let mut h = Sha256::new();
    let mut n = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let k = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return bad(format!("reading: {e}")),
        };
        n += k as u64;
        if n > max {
            return bad("a file grew past its cap");
        }
        h.update(&buf[..k]);
        out.write_all(&buf[..k])?;
    }
    let hex = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Ok((n, hex))
}

/// Sweeps `spool` once: files each finished session `find` maps to an
/// incident (its id and directory), deletes the rest and any junk, and
/// deletes unfinished sessions older than `lim.stale`. A missing spool
/// is nothing to do. One owned by root is refused: its owner is taken
/// to be the honeypot user, and root's files are never fair game.
pub fn sweep(spool: &Path, lim: Limits, find: Find) -> io::Result<Swept> {
    let root = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(spool)
    {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Swept::default()),
        r => r?,
    };
    let uid = root.metadata()?.uid();
    if uid == 0 {
        return Err(io::Error::other(
            "owned by root, not the honeypot user; not touched",
        ));
    }
    let mut w = Walk {
        uid,
        lim,
        now: SystemTime::now(),
        left: MAX_UNLINKS,
        visits: 0,
        sessions: 0,
        bytes: 0,
        filed_in: HashMap::new(),
        out: Swept::default(),
    };
    for n in names(&root)? {
        if w.busy() {
            break;
        }
        match addr_name(&n) {
            Some(a) => {
                // What was filed before it still counts.
                if let Err(e) = w.addr(&root, &n, a, find) {
                    w.out.io = Some(e);
                    break;
                }
            }
            None => {
                w.remove(&root, &n, 0);
            }
        }
    }
    Ok(w.out)
}

struct Walk {
    uid: u32,
    lim: Limits,
    now: SystemTime,
    /// Unlinks left this tick.
    left: usize,
    visits: usize,
    sessions: usize,
    bytes: u64,
    /// Sessions in each incident's `honeypot/`, counted once a tick.
    filed_in: HashMap<PathBuf, usize>,
    out: Swept,
}

impl Walk {
    /// Counts one entry looked at; true once the tick has done enough.
    fn busy(&mut self) -> bool {
        self.visits += 1;
        // Room to delete a whole session after filing it.
        // One more session may copy up to its cap; the first always may.
        let cap = self.lim.max_session_bytes.saturating_add(PCAP_FIXED);
        self.visits > MAX_VISITS
            || self.sessions >= MAX_SESSIONS
            || (self.bytes > 0 && self.bytes.saturating_add(cap) > MAX_BYTES)
            || self.left < MAX_PAYLOADS + 8
    }

    /// `name` in `dir` as a directory the honeypot user owns, or None.
    fn dir(&self, dir: &File, name: &CStr) -> Option<File> {
        let d = open_dir(dir, name).ok()?;
        (d.metadata().ok()?.uid() == self.uid).then_some(d)
    }

    /// Deletes `name` in `dir`: itself if it isn't a directory (a link
    /// is removed, never followed), else its tree, if the honeypot user
    /// owns each directory in it. True once it is gone.
    fn remove(&mut self, dir: &File, name: &CStr, depth: u32) -> bool {
        if self.left == 0 {
            return false;
        }
        self.left -= 1;
        if unlinkat(dir, name, 0).is_ok() {
            return true;
        }
        if depth >= MAX_DEPTH {
            return false;
        }
        let Some(d) = self.dir(dir, name) else {
            return false;
        };
        for n in names(&d).unwrap_or_default() {
            self.remove(&d, &n, depth + 1);
        }
        unlinkat(dir, name, libc::AT_REMOVEDIR).is_ok()
    }

    /// `spool/<a>/`: finished sessions in `done/`, unfinished ones
    /// beside it.
    fn addr(&mut self, root: &File, name: &CStr, a: Ipv4Addr, find: Find) -> io::Result<()> {
        let Some(d) = self.dir(root, name) else {
            self.remove(root, name, 0);
            return Ok(());
        };
        for n in names(&d).map_err(|e| tag("listing the spool", e))? {
            if self.busy() {
                break;
            }
            if n.as_bytes() == b"done" {
                let Some(done) = self.dir(&d, &n) else {
                    self.remove(&d, &n, 0);
                    continue;
                };
                for s in names(&done).map_err(|e| tag("listing the spool", e))? {
                    if self.busy() {
                        break;
                    }
                    match s.to_str().ok().filter(|s| session_id(s)) {
                        Some(id) => self.session(&done, &s, id, a, find)?,
                        None => {
                            self.remove(&done, &s, 0);
                        }
                    }
                }
            } else if n.to_str().is_ok_and(session_id) {
                self.stale(&d, &n);
            } else {
                self.remove(&d, &n, 0);
            }
        }
        Ok(())
    }

    /// An unfinished session: deleted once it is too old to be live.
    fn stale(&mut self, dir: &File, name: &CStr) {
        let Some(d) = self.dir(dir, name) else {
            self.remove(dir, name, 0);
            return;
        };
        let old = d.metadata().and_then(|m| m.modified()).is_ok_and(|t| {
            self.now
                .duration_since(t)
                .is_ok_and(|age| age >= self.lim.stale)
        });
        if old {
            drop(d);
            self.remove(dir, name, 0);
            self.out.stale += 1;
        }
    }

    fn session(
        &mut self,
        done: &File,
        name: &CStr,
        id: &str,
        a: Ipv4Addr,
        find: Find,
    ) -> io::Result<()> {
        self.sessions += 1;
        let filed = match self.file(done, name, id, a, find) {
            Ok(filed) => {
                self.out.filed.push(filed);
                true
            }
            Err(Skip::Filed) => false,
            Err(Skip::Unmatched) => {
                self.out.unmatched += 1;
                false
            }
            Err(Skip::Bad(why)) => {
                self.out.rejected += 1;
                self.out.why.get_or_insert(format!("{a}/done/{id}: {why}"));
                false
            }
            // Left in place for the next tick; the sweep stops here.
            Err(Skip::Io(e)) => return Err(tag("filing into the incident", e)),
        };
        // Said once, when filed: later ticks find it filed and try again.
        if !self.remove(done, name, 0) && filed {
            eprintln!(
                "aegisd: honeypot spool: {a}/done/{id} filed, but not deleted from the spool"
            );
        }
        Ok(())
    }

    /// A regular file in `dir` the honeypot user owns, with one link and
    /// at most `max` bytes.
    fn open_file(&self, dir: &File, name: &str, max: u64) -> Result<(File, u64), Skip> {
        // O_NONBLOCK: a FIFO must not hang the open.
        let f = openat(
            dir,
            &cstr(name),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY,
        )
        .or_else(|e| bad(format!("{name}: {e}")))?;
        let m = f.metadata().or_else(|e| bad(format!("{name}: {e}")))?;
        if !m.file_type().is_file() || m.uid() != self.uid || m.nlink() != 1 {
            return bad(format!(
                "{name} is not a regular file of the honeypot's with one link"
            ));
        }
        if m.len() > max {
            return bad(format!("{name} is over its cap"));
        }
        Ok((f, m.len()))
    }

    /// Copies one finished session into its incident: `session.json`
    /// and `stream.pcap` into `honeypot/<id>/`, each payload into
    /// `payloads/<sha256>` once its contents match the name. All of it
    /// is copied and checked in a hidden directory first, so a session
    /// is filed whole or not at all.
    fn file(
        &mut self,
        done: &File,
        name: &CStr,
        id: &str,
        a: Ipv4Addr,
        find: Find,
    ) -> Result<(String, Session), Skip> {
        let (inc, inc_dir, opened_ms) = find(a).ok_or(Skip::Unmatched)?;
        let d = match open_dir(done, name) {
            Ok(d) if d.metadata().is_ok_and(|m| m.uid() == self.uid) => d,
            Ok(_) => return bad("not the honeypot's directory"),
            Err(e) => return bad(e),
        };
        let (mut j, _) = self.open_file(&d, "session.json", MAX_JSON)?;
        let mut json = Vec::new();
        (&mut j)
            .take(MAX_JSON + 1)
            .read_to_end(&mut json)
            .or_else(|e| bad(format!("session.json: {e}")))?;
        let s = parse(&json).or_else(bad)?;
        if s.id != id || s.addr != a {
            return bad("session.json is for another session");
        }
        // From before this incident had the address: not its session.
        // The open is recorded in whole seconds, once the holds are
        // open: a first session can start a moment before it.
        if s.started_ms < opened_ms.saturating_sub(5000) {
            return bad("started before the incident's observation opened");
        }
        let cap = self.lim.max_session_bytes.saturating_add(PCAP_FIXED);
        let hp = inc_dir.join("honeypot");
        let dest = hp.join(id);
        if dest.exists() {
            return Err(Skip::Filed);
        }
        let held = *self.filed_in.entry(hp.clone()).or_insert_with(|| {
            fs::read_dir(&hp).map_or(0, |r| {
                r.flatten()
                    .filter(|e| e.file_name().to_str().is_some_and(session_id))
                    .count()
            })
        });
        if held >= self.lim.max_filed {
            if !self.out.capped.contains(&inc) {
                self.out.capped.push(inc.clone());
            }
            return bad(format!(
                "the incident already holds {} sessions",
                self.lim.max_filed
            ));
        }
        private_dir(&hp)?;
        let tmp = hp.join(format!(".{id}"));
        // Left by a crash mid-copy.
        let _ = fs::remove_dir_all(&tmp);
        DirBuilder::new().mode(0o700).create(&tmp)?;
        let r = (|| -> Result<(), Skip> {
            create(&tmp.join("session.json"))?.write_all(&json)?;
            let (mut pcap, _) = self.open_file(&d, "stream.pcap", cap)?;
            let n = copy(&mut pcap, &tmp.join("stream.pcap"), cap)?.0;
            self.bytes += n;
            let mut left = cap - n;
            for h in &s.payloads {
                let max = left.min(MAX_PAYLOAD);
                let (mut f, _) = self.open_file(&d, h, max)?;
                let (n, sum) = copy(&mut f, &tmp.join(h), max)?;
                self.bytes += n;
                if sum != *h {
                    return bad("a payload does not match its name");
                }
                left -= n;
            }
            Ok(())
        })();
        let r = r.and_then(|()| -> Result<(), Skip> {
            if !s.payloads.is_empty() {
                let p = inc_dir.join("payloads");
                private_dir(&p)?;
                // The same name is the same bytes, checked: renaming
                // over an earlier copy still leaves one.
                for h in &s.payloads {
                    fs::rename(tmp.join(h), p.join(h))?;
                }
            }
            Ok(fs::rename(&tmp, &dest)?)
        });
        if r.is_err() {
            let _ = fs::remove_dir_all(&tmp);
        } else {
            self.filed_in.insert(hp, held + 1);
        }
        r.map(|()| (inc, s))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::{lchown, symlink, PermissionsExt};

    /// The honeypot user, when the tests run as root and can chown.
    const HP: u32 = 4242;
    const ADDR: &str = "127.77.0.1";
    pub(crate) const ID: &str = "4102444800000-0badf00d";
    const INC: &str = "AEG-20261029-120000-0123456789abcdef";

    fn root() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    /// Gives `p` to the stand-in honeypot user, as root; else it is
    /// already the (non-root) tester's.
    pub(crate) fn own(p: &Path) {
        if root() {
            lchown(p, Some(HP), Some(HP)).unwrap();
        }
    }

    fn sha(b: &[u8]) -> String {
        Sha256::digest(b)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    struct T {
        base: PathBuf,
    }
    impl Drop for T {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
    impl T {
        fn new(name: &str) -> T {
            let base =
                std::env::temp_dir().join(format!("aegis-spool-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(base.join("spool")).unwrap();
            fs::create_dir_all(base.join("inc")).unwrap();
            fs::create_dir_all(base.join("outside")).unwrap();
            own(&base.join("spool"));
            T { base }
        }
        fn spool(&self) -> PathBuf {
            self.base.join("spool")
        }
        fn inc(&self) -> PathBuf {
            self.base.join("inc")
        }
        fn outside(&self) -> PathBuf {
            self.base.join("outside")
        }
        fn mkdir(&self, rel: &str) -> PathBuf {
            let mut p = self.spool();
            for c in rel.split('/') {
                p.push(c);
                if !p.exists() {
                    fs::create_dir(&p).unwrap();
                    own(&p);
                }
            }
            p
        }
        fn session(&self, addr: &str, id: &str, payloads: &[&[u8]]) -> PathBuf {
            fake(&self.spool(), addr, id, payloads)
        }
        fn sweep(&self) -> io::Result<Swept> {
            let inc = self.inc();
            sweep(&self.spool(), LIM, &|a: Ipv4Addr| {
                (a.to_string() == ADDR).then(|| (INC.to_string(), inc.clone(), 0))
            })
        }
        /// `sweep`, failing instead of hanging if an open blocks.
        fn sweep_within(&self, secs: u64) -> io::Result<Swept> {
            let (spool, inc) = (self.spool(), self.inc());
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let r = sweep(&spool, LIM, &|a: Ipv4Addr| {
                    (a.to_string() == ADDR).then(|| (INC.to_string(), inc.clone(), 0))
                });
                let _ = tx.send(r);
            });
            rx.recv_timeout(Duration::from_secs(secs))
                .expect("the sweep hung")
        }
    }

    fn fifo(p: &Path) {
        let c = CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        own(p);
    }

    const LIM: Limits = Limits {
        max_session_bytes: 4096,
        stale: Duration::from_secs(660),
        max_filed: MAX_FILED,
    };

    /// A finished session at `<spool>/<addr>/done/<id>` with
    /// `payloads`, as the honeypot leaves one.
    pub(crate) fn fake(spool: &Path, addr: &str, id: &str, payloads: &[&[u8]]) -> PathBuf {
        let mut d = spool.to_path_buf();
        for c in [addr, "done", id] {
            d.push(c);
            if !d.exists() {
                fs::create_dir(&d).unwrap();
                own(&d);
            }
        }
        let hashes: Vec<String> = payloads.iter().map(|p| sha(p)).collect();
        for (h, p) in hashes.iter().zip(payloads) {
            write(&d.join(h), p);
        }
        write(&d.join("stream.pcap"), b"pcap");
        write(&d.join("session.json"), &json_for(addr, id, &hashes));
        d
    }

    fn write(p: &Path, b: &[u8]) {
        fs::write(p, b).unwrap();
        own(p);
    }

    /// The ms an id starts with, as the honeypot's `started_ms`.
    fn ms(id: &str) -> u64 {
        id.split_once('-')
            .map_or(0, |(m, _)| m.parse().unwrap_or(0))
    }

    fn json_for(addr: &str, id: &str, payloads: &[String]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": id, "protocol": "http", "addr": addr,
            "src": "10.0.0.2:40000", "dst": "1.2.3.4:80",
            "started_ms": ms(id), "ended_ms": ms(id) + 5, "bytes_in": 3, "bytes_out": 4,
            "truncated": false, "timed_out": false, "payloads": payloads,
            "dns_name": "c2.example\u{1b}[31m", "queries": [], "sni": null, "ja4": null,
            "requests": [], "credentials": [{"user": "root", "password": "hunter2",
            "key": null}], "commands": ["rm -rf /"], "uploads": [], "helo": null,
            "mails": [],
        }))
        .unwrap()
    }

    fn filed(t: &T, id: &str) -> PathBuf {
        t.inc().join("honeypot").join(id)
    }

    #[test]
    fn a_session_is_copied_into_its_incident_and_deleted() {
        let t = T::new("ok");
        let src = t.session(ADDR, ID, &[b"payload one"]);
        let r = t.sweep().unwrap();
        assert_eq!((r.filed.len(), r.rejected, r.unmatched), (1, 0, 0), "{r:?}");
        assert_eq!(r.filed[0].0, INC);
        assert!(!src.exists());
        let d = filed(&t, ID);
        assert_eq!(fs::read(d.join("stream.pcap")).unwrap(), b"pcap");
        assert_eq!(
            parse(&fs::read(d.join("session.json")).unwrap())
                .unwrap()
                .id,
            ID
        );
        let p = t.inc().join("payloads").join(sha(b"payload one"));
        assert_eq!(fs::read(&p).unwrap(), b"payload one");
        let m = fs::metadata(&p).unwrap();
        assert_eq!(
            (m.permissions().mode() & 0o777, m.uid()),
            (0o400, unsafe { libc::geteuid() })
        );
        assert_eq!(
            fs::metadata(d.join("session.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        // Nothing half-made is left beside it.
        let names: Vec<_> = fs::read_dir(t.inc().join("honeypot"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names, [ID]);
    }

    #[test]
    fn filing_rejects_hostile_spool() {
        type Setup = fn(&T, &Path);
        let cases: &[(&str, Setup)] = &[
            ("session dir is a symlink", |t, d| {
                fs::rename(d, t.outside().join("s")).unwrap();
                symlink(t.outside().join("s"), d).unwrap();
            }),
            ("session.json is a symlink", |t, d| {
                fs::rename(d.join("session.json"), t.outside().join("j")).unwrap();
                symlink(t.outside().join("j"), d.join("session.json")).unwrap();
            }),
            ("stream.pcap is a symlink", |t, d| {
                write(&t.outside().join("p"), b"secret");
                fs::remove_file(d.join("stream.pcap")).unwrap();
                symlink(t.outside().join("p"), d.join("stream.pcap")).unwrap();
            }),
            ("payload is a symlink", |t, d| {
                let h = d.join(sha(b"x"));
                fs::rename(&h, t.outside().join("x")).unwrap();
                symlink(t.outside().join("x"), &h).unwrap();
            }),
            ("session.json is hardlinked", |t, d| {
                fs::hard_link(d.join("session.json"), t.outside().join("j")).unwrap();
            }),
            ("stream.pcap is a FIFO", |_, d| {
                fs::remove_file(d.join("stream.pcap")).unwrap();
                let p = CString::new(d.join("stream.pcap").as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(p.as_ptr(), 0o600) }, 0);
                own(&d.join("stream.pcap"));
            }),
            ("session.json is a directory", |_, d| {
                fs::remove_file(d.join("session.json")).unwrap();
                fs::create_dir(d.join("session.json")).unwrap();
                own(&d.join("session.json"));
            }),
            ("session.json is oversize", |_, d| {
                let mut j = fs::read(d.join("session.json")).unwrap();
                j.resize(MAX_JSON as usize + 1, b' ');
                write(&d.join("session.json"), &j);
            }),
            ("session.json is bad JSON", |_, d| {
                write(&d.join("session.json"), b"{\"id\": ");
            }),
            ("session.json has an unknown field", |_, d| {
                let mut v: Value =
                    serde_json::from_slice(&fs::read(d.join("session.json")).unwrap()).unwrap();
                v["extra"] = json!(1);
                write(&d.join("session.json"), &serde_json::to_vec(&v).unwrap());
            }),
            ("session.json names another session", |_, d| {
                write(
                    &d.join("session.json"),
                    &json_for(ADDR, "4102444800001-0badf00d", &[sha(b"x")]),
                );
            }),
            ("session.json names another address", |_, d| {
                write(
                    &d.join("session.json"),
                    &json_for("127.77.0.2", ID, &[sha(b"x")]),
                );
            }),
            ("a payload name is a path", |_, d| {
                write(
                    &d.join("session.json"),
                    &json_for(ADDR, ID, &["../../../etc/passwd".into()]),
                );
            }),
            ("a payload is listed twice", |_, d| {
                write(
                    &d.join("session.json"),
                    &json_for(ADDR, ID, &[sha(b"x"), sha(b"x")]),
                );
            }),
            ("a payload doesn't match its hash", |_, d| {
                write(&d.join(sha(b"x")), b"y");
            }),
            ("a payload is a FIFO", |_, d| {
                fs::remove_file(d.join(sha(b"x"))).unwrap();
                fifo(&d.join(sha(b"x")));
            }),
            ("a payload is missing", |_, d| {
                fs::remove_file(d.join(sha(b"x"))).unwrap();
            }),
            ("stream.pcap is over the cap", |_, d| {
                write(
                    &d.join("stream.pcap"),
                    &vec![0; (LIM.max_session_bytes + PCAP_FIXED + 1) as usize],
                );
            }),
            ("the files together are over the cap", |_, d| {
                let cap = LIM.max_session_bytes + PCAP_FIXED;
                write(&d.join("stream.pcap"), &vec![0; cap as usize]);
            }),
        ];
        for (what, setup) in cases {
            let t = T::new("hostile");
            let d = t.session(ADDR, ID, &[b"x"]);
            setup(&t, &d);
            let outside: Vec<_> = fs::read_dir(t.outside())
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .collect();
            // Under a timeout: an open that blocks on a FIFO fails, not hangs.
            let r = t.sweep_within(10).unwrap();
            assert_eq!((r.filed.len(), r.rejected), (0, 1), "{what}: {r:?}");
            assert!(
                fs::symlink_metadata(&d).is_err(),
                "{what}: left in the spool"
            );
            assert!(!filed(&t, ID).exists(), "{what}: filed");
            assert!(!t.inc().join("payloads").exists(), "{what}: payload filed");
            // A rejected session leaves no hidden copy behind.
            let left = fs::read_dir(t.inc().join("honeypot")).map_or(0, |r| r.count());
            assert_eq!(left, 0, "{what}");
            for p in outside {
                assert!(
                    fs::symlink_metadata(&p).is_ok(),
                    "{what}: {} deleted",
                    p.display()
                );
            }
        }
    }

    #[test]
    fn a_session_owned_by_someone_else_is_refused() {
        if !root() {
            return eprintln!("skipped: needs root to chown");
        }
        for f in ["session.json", "stream.pcap", &sha(b"x"), ""] {
            let t = T::new("owner");
            let d = t.session(ADDR, ID, &[b"x"]);
            lchown(d.join(f), Some(HP + 1), None).unwrap();
            let r = t.sweep().unwrap();
            assert_eq!((r.filed.len(), r.rejected), (0, 1), "{f}: {r:?}");
        }
    }

    #[test]
    fn junk_and_links_in_the_tree_are_removed_not_followed() {
        let t = T::new("junk");
        write(&t.outside().join("keep"), b"secret");
        fs::create_dir(t.outside().join("dir")).unwrap();
        write(&t.outside().join("dir/keep"), b"secret");
        // A link as an address dir, as done/ and as a session dir.
        symlink(t.outside().join("dir"), t.spool().join("127.77.0.9")).unwrap();
        t.mkdir("127.77.0.1");
        symlink(t.outside().join("dir"), t.spool().join("127.77.0.1/done")).unwrap();
        t.mkdir("127.77.0.2/done");
        symlink(
            t.outside().join("dir"),
            t.spool().join("127.77.0.2/done").join(ID),
        )
        .unwrap();
        // Names that aren't an incident address, a session id or done/.
        for junk in [
            "10.0.0.1",
            "127.77.0.01",
            "127.77.0.3/done/x",
            "127.77.0.3/abc",
            "notes",
        ] {
            t.mkdir(junk);
        }
        write(&t.spool().join("127.77.0.3/done/x/f"), b"");
        let r = t.sweep().unwrap();
        assert_eq!(r.filed.len(), 0);
        let mut left: Vec<String> = Vec::new();
        for e in walk(&t.spool()) {
            left.push(e.strip_prefix(t.spool()).unwrap().display().to_string());
        }
        left.sort();
        assert_eq!(
            left,
            [
                "127.77.0.1",
                "127.77.0.2",
                "127.77.0.2/done",
                "127.77.0.3",
                "127.77.0.3/done"
            ]
        );
        assert_eq!(fs::read(t.outside().join("keep")).unwrap(), b"secret");
        assert_eq!(fs::read(t.outside().join("dir/keep")).unwrap(), b"secret");
    }

    fn walk(p: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in fs::read_dir(p).unwrap().flatten() {
            out.push(e.path());
            if e.file_type().unwrap().is_dir() {
                out.extend(walk(&e.path()));
            }
        }
        out
    }

    #[test]
    fn a_spool_owned_by_root_is_not_touched() {
        if !root() {
            return eprintln!("skipped: needs root");
        }
        let t = T::new("rootowned");
        let d = t.session(ADDR, ID, &[]);
        lchown(t.spool(), Some(0), Some(0)).unwrap();
        assert!(t.sweep().is_err());
        assert!(d.join("session.json").exists());
    }

    #[test]
    fn a_spool_that_is_a_link_is_not_followed() {
        let t = T::new("rootlink");
        let real = t.base.join("real");
        fs::rename(t.spool(), &real).unwrap();
        symlink(&real, t.spool()).unwrap();
        let s = real.join(ADDR);
        fs::create_dir(&s).unwrap();
        assert!(t.sweep().is_err());
        assert!(s.exists());
    }

    #[test]
    fn a_missing_spool_is_nothing_to_do() {
        let t = T::new("missing");
        fs::remove_dir(t.spool()).unwrap();
        let r = t.sweep().unwrap();
        assert_eq!((r.filed.len(), r.rejected, r.unmatched), (0, 0, 0));
    }

    #[test]
    fn an_unmatched_session_is_deleted_unread() {
        let t = T::new("unmatched");
        let d = t.session("127.77.0.2", ID, &[]);
        let r = t.sweep().unwrap();
        assert_eq!((r.filed.len(), r.unmatched), (0, 1));
        assert!(!d.exists());
    }

    #[test]
    fn a_payload_two_sessions_share_is_kept_once() {
        let t = T::new("dedup");
        let other = "4102444800001-0badf00d";
        t.session(ADDR, ID, &[b"same", b"one"]);
        t.session(ADDR, other, &[b"same"]);
        let r = t.sweep().unwrap();
        assert_eq!(r.filed.len(), 2, "{r:?}");
        let mut p: Vec<_> = fs::read_dir(t.inc().join("payloads"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        p.sort();
        let mut want = [sha(b"same"), sha(b"one")];
        want.sort();
        assert_eq!(
            p,
            want.iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        );
        assert!(filed(&t, ID).exists() && filed(&t, other).exists());
    }

    #[test]
    fn a_session_already_filed_is_deleted_quietly() {
        let t = T::new("twice");
        t.session(ADDR, ID, &[]);
        assert_eq!(t.sweep().unwrap().filed.len(), 1);
        // As after a spool delete that failed once it was filed.
        let d = t.session(ADDR, ID, &[]);
        let r = t.sweep().unwrap();
        assert_eq!((r.filed.len(), r.rejected, r.unmatched), (0, 0, 0), "{r:?}");
        assert!(!d.exists());
    }

    #[test]
    fn a_session_started_before_its_observation_is_refused() {
        let t = T::new("early");
        let d = t.session(ADDR, ID, &[]);
        let inc = t.inc();
        let r = sweep(&t.spool(), LIM, &|_| {
            Some((INC.to_string(), inc.clone(), ms(ID) + 60_000))
        })
        .unwrap();
        assert_eq!((r.filed.len(), r.rejected), (0, 1), "{r:?}");
        assert!(!d.exists());
    }

    #[test]
    fn a_session_just_before_the_recorded_open_is_filed() {
        let t = T::new("justbefore");
        t.session(ADDR, ID, &[]);
        let inc = t.inc();
        // The open is recorded after the holds open, in whole seconds.
        let r = sweep(&t.spool(), LIM, &|_| {
            Some((INC.to_string(), inc.clone(), ms(ID) + 1000))
        })
        .unwrap();
        assert_eq!(r.filed.len(), 1, "{r:?}");
    }

    #[test]
    fn an_incident_side_error_stops_the_tick_but_keeps_what_was_filed() {
        let t = T::new("ioerr");
        let first = "4102444800000-00000001";
        let second = "4102444800000-00000002";
        t.session(ADDR, first, &[]);
        let d = t.session(ADDR, second, &[b"x"]);
        // payloads/ can't be made: the second session can't be filed.
        fs::write(t.inc().join("payloads"), b"").unwrap();
        let r = t.sweep().unwrap();
        assert_eq!(r.filed.len(), 1, "{r:?}");
        assert_eq!(r.filed[0].1.id, first);
        assert!(r.io.is_some());
        // Left for the next tick, and nothing half-made beside it.
        assert!(d.join("session.json").exists());
        let names: Vec<_> = fs::read_dir(t.inc().join("honeypot"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names, [first]);
    }

    #[test]
    fn a_tick_copies_a_bounded_number_of_bytes() {
        let t = T::new("bytes");
        let lim = Limits {
            max_session_bytes: MAX_BYTES - (1 << 20),
            ..LIM
        };
        for i in 1..=2 {
            let d = t.session(ADDR, &format!("4102444800000-0000000{i}"), &[]);
            write(&d.join("stream.pcap"), &vec![0; 1 << 20]);
        }
        let inc = t.inc();
        let find = |_| Some((INC.to_string(), inc.clone(), 0));
        // After one 1 MiB session another full one would pass the bound.
        assert_eq!(sweep(&t.spool(), lim, &find).unwrap().filed.len(), 1);
        assert_eq!(sweep(&t.spool(), lim, &find).unwrap().filed.len(), 1);
    }

    #[test]
    fn a_tick_deletes_a_bounded_number_of_entries() {
        let t = T::new("unlinks");
        for j in 0..5 {
            let d = t.mkdir(&format!("junk{j}"));
            for i in 0..1000 {
                write(&d.join(i.to_string()), b"");
            }
        }
        t.sweep().unwrap();
        assert!(fs::read_dir(t.spool()).unwrap().count() > 0);
        t.sweep().unwrap();
        assert_eq!(fs::read_dir(t.spool()).unwrap().count(), 0);
    }

    #[test]
    fn junk_is_deleted_only_so_deep() {
        let t = T::new("depth");
        t.mkdir("shallow/a/b/c");
        let deep = t.mkdir("deep/a/b/c/d");
        t.sweep().unwrap();
        assert!(!t.spool().join("shallow").exists());
        assert!(deep.exists());
    }

    #[test]
    fn only_old_unfinished_sessions_are_swept() {
        let t = T::new("stale");
        let old = t.mkdir(&format!("{ADDR}/4102444800000-00000001"));
        write(&old.join("stream.pcap"), b"x");
        let young = t.mkdir(&format!("{ADDR}/4102444800000-00000002"));
        write(&young.join("stream.pcap"), b"x");
        let past = SystemTime::now() - LIM.stale - Duration::from_secs(1);
        File::open(&old).unwrap().set_modified(past).unwrap();
        let r = t.sweep().unwrap();
        assert_eq!(r.stale, 1);
        assert!(!old.exists());
        assert!(young.join("stream.pcap").exists());
    }

    #[test]
    fn a_flood_is_handled_a_tick_at_a_time() {
        let t = T::new("flood");
        for i in 0..MAX_SESSIONS + 5 {
            t.session("127.77.0.2", &format!("4102444800000-{i:08x}"), &[]);
        }
        assert_eq!(t.sweep().unwrap().unmatched, MAX_SESSIONS as u64);
        assert_eq!(t.sweep().unwrap().unmatched, 5);
    }

    #[test]
    fn a_tick_looks_at_a_bounded_number_of_entries() {
        let t = T::new("visits");
        // 10 addresses, each with 1000 live sessions and a finished one:
        // more entries than one tick looks at.
        for a in 1..=10 {
            let addr = format!("127.77.1.{a}");
            for i in 0..1000 {
                t.mkdir(&format!("{addr}/4102444800000-{i:08x}"));
            }
            t.session(&addr, ID, &[]);
        }
        let n = t.sweep().unwrap().unmatched;
        assert!((1..10).contains(&n), "{n}");
    }

    #[test]
    fn the_event_carries_no_secrets_and_no_raw_control_bytes() {
        let s = parse(&json_for(ADDR, ID, &[])).unwrap();
        let e = event(&s).to_string();
        let r = reason(&s);
        for text in [&e, &r] {
            assert!(
                !text.contains("hunter2") && !text.contains("rm -rf"),
                "{text}"
            );
            assert!(!text.contains('\u{1b}'), "{text}");
        }
        assert_eq!(event(&s)["protocol"], "http");
        assert!(
            r.starts_with(&format!(
                "honeypot_session {ID}: http to 1.2.3.4:80 (c2.example\\x1b[31m)"
            )),
            "{r}"
        );
        let long = Session {
            dns_name: Some("a".repeat(5000)),
            ..s
        };
        assert!(reason(&long).len() < 400);
    }

    #[test]
    fn parse_refuses_impossible_times_and_a_start_that_is_not_the_ids() {
        let ok: Value = serde_json::from_slice(&json_for(ADDR, ID, &[])).unwrap();
        assert!(parse(&serde_json::to_vec(&ok).unwrap()).is_ok());
        let year_10000 = 253_402_300_800_000u64;
        let other = format!("{year_10000}-0badf00d");
        for (k, v) in [
            ("started_ms", json!(ms(ID) + 1)),
            ("ended_ms", json!(ms(ID) - 1)),
            ("ended_ms", json!(year_10000)),
            ("ended_ms", json!(u64::MAX)),
        ] {
            let mut j = ok.clone();
            j[k] = v;
            let e = parse(&serde_json::to_vec(&j).unwrap()).unwrap_err();
            assert!(e.contains("time"), "{k}: {e}");
        }
        let mut j = ok.clone();
        j["id"] = other.clone().into();
        j["started_ms"] = year_10000.into();
        j["ended_ms"] = year_10000.into();
        assert!(parse(&serde_json::to_vec(&j).unwrap()).is_err());
    }

    #[test]
    fn filing_stops_at_the_incident_cap() {
        let t = T::new("cap");
        let ids = [
            "4102444800000-00000001",
            "4102444800000-00000002",
            "4102444800000-00000003",
        ];
        for id in ids {
            t.session(ADDR, id, &[]);
        }
        let inc = t.inc();
        let lim = Limits {
            max_filed: 2,
            ..LIM
        };
        let r = sweep(&t.spool(), lim, &|_| {
            Some((INC.to_string(), inc.clone(), 0))
        })
        .unwrap();
        assert_eq!((r.filed.len(), r.rejected), (2, 1), "{r:?}");
        assert!(r.why.unwrap().contains("holds 2 sessions"));
        assert_eq!(r.capped, [INC]);
        assert!(!filed(&t, ids[2]).exists());
        assert!(fs::read_dir(t.spool().join(ADDR).join("done"))
            .unwrap()
            .next()
            .is_none());
        // A later tick counts what is already filed.
        t.session(ADDR, "4102444800000-00000004", &[]);
        let r = sweep(&t.spool(), lim, &|_| {
            Some((INC.to_string(), inc.clone(), 0))
        })
        .unwrap();
        assert_eq!((r.filed.len(), r.rejected), (0, 1), "{r:?}");
    }

    #[test]
    fn names_are_checked_exactly() {
        assert!(session_id(ID));
        for bad in [
            "",
            "1-",
            "-0badf00d",
            "4102444800000-0BADF00D",
            "4102444800000-0badf00",
            "a-0badf00d",
            "1/2-0badf00d",
        ] {
            assert!(!session_id(bad), "{bad}");
        }
        assert_eq!(addr_name(c"127.77.1.2"), Some(Ipv4Addr::new(127, 77, 1, 2)));
        for bad in [c"127.78.0.1", c"127.77.0.01", c"127.77.0", c" 127.77.0.1"] {
            assert_eq!(addr_name(bad), None);
        }
    }
}
