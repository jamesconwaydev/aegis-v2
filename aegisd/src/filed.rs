// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reading back the honeypot sessions filing put in an incident, for
//! `incidents show`, `incidents pcap` and `incidents stix`.
//!
//! The files are root's, written by aegisd, but what is in them came
//! from the honeypot. So each is opened without following links, read
//! through a cap and checked again, the same as on the way in.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, RandomState};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use aegis_proto::honeypot::{Session, ShowHoneypot, ShowLine, MAX_SHOWN};
use serde_json::Value;

use crate::spool::{self, MAX_JSON};

/// Sessions read for one request, oldest first: all filing keeps.
pub const MAX_READ: usize = spool::MAX_FILED;
/// The most `incidents pcap` sends.
pub const MAX_PCAP: u64 = 256 << 20;
/// Records indexed for one pcap, so the index stays near 24 MiB.
const MAX_RECORDS: usize = 1 << 20;
/// Longest value `incidents show` sends; commands run to 1 KiB.
const MAX_VALUE: usize = 256;
/// Distinct lines one protocol remembers, to show each once. Past it,
/// lines are counted without that check.
const MAX_SEEN: usize = 1 << 16;
/// Damaged pcaps named one by one; the rest are counted.
const MAX_NAMED: usize = 8;
/// Session pcaps the merge keeps open at once.
const OPEN_FILES: usize = 8;
/// What the honeypot writes: classic pcap, little-endian, microsecond
/// times, version 2.4, snaplen 65535, LINKTYPE_RAW.
const HEADER: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0, 0, 0,
];
/// IPv4's largest packet.
const MAX_PACKET: u32 = 65535;

/// A file, never through a link, and only a regular one.
fn open(p: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(p)?;
    if !f.metadata()?.file_type().is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a file"));
    }
    Ok(f)
}

/// The ids of the sessions filed in `inc_dir`, oldest first by the time
/// in their names, at most `max`; and how many there are in all.
/// Hidden half-filed copies and anything not named like a session are
/// skipped.
fn ids(inc_dir: &Path, max: usize) -> (Vec<String>, usize) {
    let Ok(rd) = fs::read_dir(inc_dir.join("honeypot")) else {
        return (Vec::new(), 0);
    };
    let mut v: Vec<(u64, String)> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| spool::session_id(n))
        .filter_map(|n| Some((spool::id_ms(&n)?, n)))
        .collect();
    let total = v.len();
    v.sort_unstable();
    v.truncate(max);
    (v.into_iter().map(|(_, n)| n).collect(), total)
}

/// Hands each filed session that reads and parses to `f`, oldest first,
/// one at a time, and keeps none: a caller holds the one it is given
/// and whatever it folds it into, so memory is one session at a time
/// however many there are. Stops when `f` says so or after `MAX_READ`
/// sessions. Returns how many sessions `f` never got, unreadable ones
/// included.
pub fn each(inc_dir: &Path, f: impl FnMut(Session) -> bool) -> usize {
    each_capped(inc_dir, MAX_READ, f)
}

fn each_capped(inc_dir: &Path, max: usize, mut f: impl FnMut(Session) -> bool) -> usize {
    let (ids, total) = ids(inc_dir, max);
    let hp = inc_dir.join("honeypot");
    let mut given = 0;
    let mut json = Vec::new();
    for id in ids {
        json.clear();
        let read = open(&hp.join(&id).join("session.json"))
            .and_then(|j| j.take(MAX_JSON + 1).read_to_end(&mut json));
        // spool::parse also checks the start against the id's time.
        let Some(s) = read
            .ok()
            .and_then(|_| spool::parse(&json).ok())
            .filter(|s| s.id == id)
        else {
            continue;
        };
        given += 1;
        if !f(s) {
            break;
        }
    }
    total - given
}

/// Printable and short, for old aegisctls that print what they're sent.
fn shown(s: &str) -> String {
    aegis_proto::clean(s).chars().take(MAX_VALUE).collect()
}

/// The kinds of line, most telling first: when a protocol has more
/// than `MAX_SHOWN`, each kind gets a turn in this order, so a flood of
/// one kind can't hide the logins and payloads.
const KINDS: [&str; 13] = [
    "login", "payload", "command", "request", "upload", "mail", "query", "name", "sni", "ja4",
    "helo", "dst", "header",
];

/// What `incidents show` lists for one session.
fn lines(s: &Session) -> Vec<(&'static str, String)> {
    let mut v = vec![("dst", s.dst.to_string())];
    v.extend(s.dns_name.iter().map(|n| ("name", n.clone())));
    v.extend(s.queries.iter().map(|q| {
        let a = q.answer.map(|a| format!(" -> {a}")).unwrap_or_default();
        ("query", format!("{} {}{a}", q.qtype, q.name))
    }));
    v.extend(s.sni.iter().map(|n| ("sni", n.clone())));
    v.extend(s.ja4.iter().map(|n| ("ja4", n.clone())));
    v.extend(s.helo.iter().map(|n| ("helo", n.clone())));
    v.extend(s.credentials.iter().map(|c| {
        let secret = match (&c.password, &c.key) {
            (Some(p), _) => format!(" / {p}"),
            (None, Some(k)) => format!(" key {k}"),
            (None, None) => String::new(),
        };
        ("login", format!("{}{secret}", c.user))
    }));
    v.extend(s.commands.iter().map(|c| ("command", c.clone())));
    for r in &s.requests {
        v.push(("request", format!("{} {}", r.method, r.path)));
        v.extend(r.headers.iter().map(|h| ("header", h.clone())));
    }
    v.extend(s.uploads.iter().map(|u| ("upload", u.name.clone())));
    v.extend(
        s.mails
            .iter()
            .map(|m| ("mail", format!("from <{}> to {}", m.from, m.to.join(", ")))),
    );
    v.extend(s.payloads.iter().map(|h| ("payload", h.clone())));
    v
}

#[derive(Default)]
struct Group {
    sessions: u64,
    /// Up to `MAX_SHOWN` lines of each of `KINDS`, first seen first.
    by_kind: [Vec<String>; KINDS.len()],
    distinct: u64,
    seen: HashSet<u64>,
}

/// The `honeypot` part of `incidents show`, built a session at a time.
#[derive(Default)]
pub struct Show {
    hasher: RandomState,
    by: BTreeMap<String, Group>,
}

impl Show {
    pub fn add(&mut self, s: &Session) {
        let proto = serde_json::to_value(s.protocol)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let g = self.by.entry(proto).or_default();
        g.sessions += 1;
        for (kind, value) in lines(s) {
            let k = KINDS.iter().position(|&n| n == kind).unwrap_or(0);
            // Hashes, not the lines: what's past the cap isn't kept.
            let h = self.hasher.hash_one((kind, &value));
            if g.seen.contains(&h) {
                continue;
            }
            if g.seen.len() < MAX_SEEN {
                g.seen.insert(h);
            }
            g.distinct += 1;
            if g.by_kind[k].len() < MAX_SHOWN {
                g.by_kind[k].push(shown(&value));
            }
        }
    }

    /// Each protocol's lines, at most `MAX_SHOWN`: one of each kind in
    /// `KINDS` order, then a second of each, and so on; listed by kind.
    pub fn finish(self) -> Vec<ShowHoneypot> {
        self.by
            .into_iter()
            .map(|(protocol, g)| {
                let mut take = [0usize; KINDS.len()];
                let mut n = 0;
                'fill: for round in 0..MAX_SHOWN {
                    let mut any = false;
                    for (k, v) in g.by_kind.iter().enumerate() {
                        if round < v.len() {
                            take[k] += 1;
                            n += 1;
                            any = true;
                            if n == MAX_SHOWN {
                                break 'fill;
                            }
                        }
                    }
                    if !any {
                        break;
                    }
                }
                let lines = g
                    .by_kind
                    .into_iter()
                    .zip(take)
                    .enumerate()
                    .flat_map(|(k, (v, t))| {
                        v.into_iter().take(t).map(move |value| ShowLine {
                            kind: KINDS[k].into(),
                            value,
                        })
                    })
                    .collect();
                ShowHoneypot {
                    protocol,
                    sessions: g.sessions,
                    lines,
                    more: g.distinct - n as u64,
                }
            })
            .collect()
    }
}

/// Adds the `honeypot` part to an incident's JSON when it has filed
/// sessions, and `honeypot_unread` when some couldn't be read. One
/// without (every drop-mode incident) is left as it was.
pub fn add_show(v: &mut Value, inc_dir: &Path) {
    let mut show = Show::default();
    let unread = each(inc_dir, |s| {
        show.add(&s);
        true
    });
    let groups = show.finish();
    let Some(m) = v.as_object_mut() else {
        return;
    };
    if !groups.is_empty() {
        m.insert(
            "honeypot".into(),
            serde_json::to_value(groups).unwrap_or_default(),
        );
    }
    if unread > 0 {
        m.insert("honeypot_unread".into(), unread.into());
    }
}

/// Where one pcap record is: its time in microseconds, the session it
/// belongs to, and its bytes in that session's file, header included.
#[derive(Clone, Copy, Debug)]
pub struct Rec {
    ts: u64,
    file: u32,
    off: u64,
    len: u32,
}

/// Reads up to `buf.len()` bytes, fewer only at the end of `r`.
fn fill(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Checks a record header: a real time, and a packet no bigger than
/// IPv4 allows and no bigger than the one it was cut from.
fn record(h: &[u8; 16]) -> Option<(u64, u32)> {
    let (sec, usec, incl, orig) = (le(h, 0), le(h, 4), le(h, 8), le(h, 12));
    (usec < 1_000_000 && incl <= MAX_PACKET && orig >= incl)
        .then_some((u64::from(sec) * 1_000_000 + u64::from(usec), incl))
}

/// Indexes one session's `stream.pcap` (session number `file`) into
/// `out`, at most `max` records. Only what the honeypot writes is
/// accepted: its exact file header, then whole records that pass
/// `record`. Returns the bytes after the file header.
pub fn index(mut r: impl Read, file: u32, max: usize, out: &mut Vec<Rec>) -> Result<u64, String> {
    let mut h = [0u8; 24];
    if fill(&mut r, &mut h).map_err(|e| e.to_string())? != 24 || h != HEADER {
        return Err("is not a pcap the honeypot wrote".into());
    }
    let mut off = 24u64;
    loop {
        let mut rh = [0u8; 16];
        match fill(&mut r, &mut rh).map_err(|e| e.to_string())? {
            0 => return Ok(off - 24),
            16 => {}
            _ => return Err(format!("has a truncated record at byte {off}")),
        }
        let (ts, incl) = record(&rh).ok_or_else(|| format!("has a bad record at byte {off}"))?;
        let got = io::copy(&mut (&mut r).take(u64::from(incl)), &mut io::sink())
            .map_err(|e| e.to_string())?;
        if got != u64::from(incl) {
            return Err(format!("has a truncated record at byte {off}"));
        }
        if out.len() >= max {
            return Err("has too many records".into());
        }
        out.push(Rec {
            ts,
            file,
            off,
            len: 16 + incl,
        });
        off += u64::from(16 + incl);
    }
}

/// Every session's packets as one pcap: one file header, then each
/// record in time order. Read from the files as it goes, so only the
/// index is held in memory.
pub struct Merge {
    files: Vec<PathBuf>,
    recs: Vec<Rec>,
    next: usize,
    started: bool,
    /// Up to `OPEN_FILES` of `files`: (index, file, offset), oldest
    /// opened first.
    open: Vec<(u32, File, u64)>,
    buf: Vec<u8>,
    pos: usize,
    /// What reading it yields, in all.
    pub bytes: u64,
    pub sessions: u64,
    /// Sessions not in it: damaged, over the caps, or never read.
    pub left_out: u64,
    /// Why, one reason a line.
    pub notes: Vec<String>,
}

/// The merged pcap of the incident at `inc_dir`. Sessions go in oldest
/// first until the next would take it past `MAX_PCAP` or the record
/// cap; from there on the rest are left out. A session whose pcap is
/// missing or fails `index` is left out and named.
pub fn pcap(inc_dir: &Path) -> Result<Merge, String> {
    pcap_capped(inc_dir, MAX_PCAP, MAX_RECORDS, MAX_READ)
}

fn pcap_capped(
    inc_dir: &Path,
    max_bytes: u64,
    max_recs: usize,
    max_read: usize,
) -> Result<Merge, String> {
    let (ids, total) = ids(inc_dir, max_read);
    let mut m = Merge {
        files: Vec::new(),
        recs: Vec::new(),
        next: 0,
        started: false,
        open: Vec::new(),
        buf: Vec::new(),
        pos: 0,
        bytes: 24,
        sessions: 0,
        left_out: 0,
        notes: Vec::new(),
    };
    let (mut damaged, mut over) = (0usize, 0u64);
    let mut one = Vec::new();
    for id in &ids {
        let p = inc_dir.join("honeypot").join(id).join("stream.pcap");
        // Once one is over, the rest are counted, not read: reading up
        // to 4096 of them first would outlast the client's wait.
        if over > 0 {
            over += 1;
            continue;
        }
        one.clear();
        let indexed = open(&p).map_err(|e| format!(": {e}")).and_then(|f| {
            // Its size says it won't fit before its records are read.
            let size = f.metadata().map_or(0, |m| m.len()).saturating_sub(24);
            if m.bytes + size > max_bytes {
                return Ok(None);
            }
            index(BufReader::new(f), m.files.len() as u32, max_recs, &mut one)
                .map(Some)
                .map_err(|e| format!(" {e}"))
        });
        let n = match indexed {
            Ok(Some(n)) => n,
            Ok(None) => {
                over += 1;
                continue;
            }
            Err(e) => {
                damaged += 1;
                if damaged <= MAX_NAMED {
                    m.notes.push(format!("session {id}: stream.pcap{e}"));
                }
                continue;
            }
        };
        if m.bytes + n > max_bytes || m.recs.len() + one.len() > max_recs {
            over += 1;
            continue;
        }
        m.bytes += n;
        m.sessions += 1;
        m.files.push(p);
        m.recs.extend_from_slice(&one);
    }
    let unread = (total - ids.len()) as u64;
    if damaged > MAX_NAMED {
        m.notes
            .push(format!("{} more damaged sessions", damaged - MAX_NAMED));
    }
    if over > 0 {
        m.notes.push(format!(
            "{over} newer sessions past the {} MiB or {max_recs}-record cap",
            max_bytes >> 20
        ));
    }
    if unread > 0 {
        m.notes
            .push(format!("{unread} sessions past the {max_read} read"));
    }
    m.left_out = damaged as u64 + over + unread;
    if m.sessions == 0 {
        let why = if m.notes.is_empty() {
            "no honeypot sessions were filed into this incident".to_string()
        } else {
            m.notes.join("; ")
        };
        return Err(format!("nothing to export: {why}"));
    }
    // (file, off) is unique, so the order is the same every time.
    m.recs.sort_unstable_by_key(|r| (r.ts, r.file, r.off));
    Ok(m)
}

impl Merge {
    /// The next record's bytes, checked again: the file must still say
    /// what it said when indexed.
    fn load(&mut self) -> io::Result<bool> {
        let Some(&r) = self.recs.get(self.next) else {
            return Ok(false);
        };
        self.next += 1;
        let i = match self.open.iter().position(|o| o.0 == r.file) {
            Some(i) => i,
            None => {
                if self.open.len() == OPEN_FILES {
                    self.open.remove(0);
                }
                self.open
                    .push((r.file, open(&self.files[r.file as usize])?, 0));
                self.open.len() - 1
            }
        };
        let (_, f, at) = &mut self.open[i];
        if *at != r.off {
            f.seek(SeekFrom::Start(r.off))?;
        }
        self.buf.resize(r.len as usize, 0);
        f.read_exact(&mut self.buf)?;
        *at = r.off + u64::from(r.len);
        let h: &[u8; 16] = self.buf[..16].try_into().unwrap_or(&[0; 16]);
        if record(h).map(|(ts, incl)| (ts, 16 + incl)) != Some((r.ts, r.len)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a session's pcap changed while it was read",
            ));
        }
        self.pos = 0;
        Ok(true)
    }
}

impl Read for Merge {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.buf.len() {
            if !self.started {
                self.started = true;
                self.buf = HEADER.to_vec();
                self.pos = 0;
            } else if !self.load()? {
                return Ok(0);
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aegis_proto::honeypot::{Credential, DnsQuery, HttpRequest, Protocol};
    use std::net::Ipv4Addr;

    pub(crate) struct Dir(pub PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    pub(crate) fn dir(name: &str) -> Dir {
        let d = std::env::temp_dir().join(format!("aegis-filed-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        Dir(d)
    }

    pub(crate) fn session(id: &str, protocol: Protocol) -> Session {
        Session {
            id: id.into(),
            protocol,
            addr: Ipv4Addr::new(127, 77, 0, 1),
            src: "10.0.0.2:40000".parse().unwrap(),
            dst: "1.2.3.4:80".parse().unwrap(),
            started_ms: spool::id_ms(id).unwrap_or(0),
            ended_ms: spool::id_ms(id).unwrap_or(0) + 1500,
            bytes_in: 10,
            bytes_out: 20,
            truncated: false,
            timed_out: false,
            payloads: vec![],
            dns_name: None,
            queries: vec![],
            sni: None,
            ja4: None,
            requests: vec![],
            credentials: vec![],
            commands: vec![],
            uploads: vec![],
            helo: None,
            mails: vec![],
        }
    }

    /// One pcap record: `incl` bytes of 0x45, at `sec`.`usec`.
    pub(crate) fn rec(sec: u32, usec: u32, incl: u32) -> Vec<u8> {
        let mut v = Vec::new();
        for w in [sec, usec, incl, incl] {
            v.extend(w.to_le_bytes());
        }
        v.resize(16 + incl as usize, 0x45);
        v
    }

    pub(crate) fn pcap_of(recs: &[Vec<u8>]) -> Vec<u8> {
        let mut v = HEADER.to_vec();
        recs.iter().for_each(|r| v.extend(r));
        v
    }

    /// Files `s` (and `pcap`, if any) into `inc` as filing does.
    pub(crate) fn file(inc: &Path, s: &Session, pcap: Option<&[u8]>) {
        let d = inc.join("honeypot").join(&s.id);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("session.json"), serde_json::to_vec(s).unwrap()).unwrap();
        if let Some(p) = pcap {
            fs::write(d.join("stream.pcap"), p).unwrap();
        }
    }

    const A: &str = "1793275200000-0000000a";
    const B: &str = "1793275201000-0000000b";
    const C: &str = "1793275202000-0000000c";

    fn read(d: &Path) -> (Vec<String>, usize) {
        let mut got = Vec::new();
        let unread = each(d, |s| {
            got.push(s.id);
            true
        });
        (got, unread)
    }

    fn show(ss: &[Session]) -> Vec<ShowHoneypot> {
        let mut s = Show::default();
        ss.iter().for_each(|x| s.add(x));
        s.finish()
    }

    #[test]
    fn sessions_are_read_oldest_first_and_junk_is_skipped() {
        let d = dir("read");
        file(&d.0, &session(B, Protocol::Http), None);
        file(&d.0, &session(A, Protocol::Ssh), None);
        // A half-filed copy and junk: not sessions, not counted.
        file(
            &d.0,
            &session(".1793275200000-0000000c", Protocol::Raw),
            None,
        );
        fs::create_dir_all(d.0.join("honeypot/junk")).unwrap();
        // A session.json that doesn't parse, and a link: counted unread.
        fs::create_dir_all(d.0.join("honeypot").join(C)).unwrap();
        fs::write(d.0.join("honeypot").join(C).join("session.json"), b"{").unwrap();
        let other = "1793275203000-0000000d";
        fs::create_dir_all(d.0.join("honeypot").join(other)).unwrap();
        std::os::unix::fs::symlink(
            d.0.join("honeypot").join(A).join("session.json"),
            d.0.join("honeypot").join(other).join("session.json"),
        )
        .unwrap();
        assert_eq!(read(&d.0), (vec![A.to_string(), B.to_string()], 2));
    }

    #[test]
    fn sessions_sort_by_their_time_not_their_name() {
        let d = dir("order");
        // As strings, "10..." sorts before "9...".
        let (late, early) = ("10000000000000-0000000a", "9000000000000-0000000b");
        file(&d.0, &session(late, Protocol::Raw), None);
        file(&d.0, &session(early, Protocol::Raw), None);
        assert_eq!(read(&d.0).0, [early, late]);
        assert_eq!(ids(&d.0, 1), (vec![early.to_string()], 2));
    }

    #[test]
    fn a_session_whose_start_is_not_its_ids_is_not_read() {
        let d = dir("liar");
        let mut s = session(A, Protocol::Raw);
        s.started_ms += 1;
        s.ended_ms += 1;
        file(&d.0, &s, None);
        file(&d.0, &session(B, Protocol::Raw), None);
        assert_eq!(read(&d.0), (vec![B.to_string()], 1));
    }

    #[test]
    fn reading_stops_at_the_session_and_byte_caps_and_counts_the_rest() {
        let d = dir("caps");
        for id in [A, B, C] {
            file(&d.0, &session(id, Protocol::Raw), None);
        }
        let mut got = 0;
        assert_eq!(
            each_capped(&d.0, 2, |_| {
                got += 1;
                true
            }),
            1
        );
        assert_eq!(got, 2);
    }

    #[test]
    fn fat_sessions_do_not_hide_later_ones() {
        let d = dir("fat");
        for i in 0..600u32 {
            let mut s = session(&format!("17932752{i:05}-0000000a"), Protocol::Ssh);
            s.commands = (0..60).map(|j| format!("{j:0>1000}")).collect();
            file(&d.0, &s, None);
        }
        let len = fs::metadata(d.0.join("honeypot/1793275200000-0000000a/session.json"))
            .unwrap()
            .len();
        assert!(len > 60_000 && len <= MAX_JSON, "{len}");
        let mut got = 0;
        assert_eq!(
            each(&d.0, |_| {
                got += 1;
                true
            }),
            0
        );
        assert_eq!(got, 600);
    }

    #[test]
    fn show_groups_by_protocol_once_each_and_caps_the_lines() {
        let mut h1 = session(A, Protocol::Http);
        h1.requests = vec![HttpRequest {
            method: "GET".into(),
            path: "/a".into(),
            headers: vec!["Host: c2.example".into()],
            body: None,
        }];
        let mut h2 = session(B, Protocol::Http);
        h2.requests = h1.requests.clone();
        let mut ssh = session(C, Protocol::Ssh);
        ssh.credentials = vec![Credential {
            user: "root".into(),
            password: Some("123456".into()),
            key: None,
        }];
        ssh.commands = (0..30).map(|i| format!("echo {i}")).collect();
        ssh.commands.push("x".repeat(1000));
        let g = show(&[h1, h2, ssh]);
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].protocol.as_str(), g[0].sessions), ("http", 2));
        let http: Vec<_> = g[0]
            .lines
            .iter()
            .map(|l| (l.kind.as_str(), l.value.as_str()))
            .collect();
        assert_eq!(
            http,
            [
                ("request", "GET /a"),
                ("dst", "1.2.3.4:80"),
                ("header", "Host: c2.example")
            ]
        );
        assert_eq!(
            (g[1].protocol.as_str(), g[1].lines.len()),
            ("ssh", MAX_SHOWN)
        );
        let kinds: Vec<_> = g[1].lines.iter().map(|l| l.kind.as_str()).collect();
        assert_eq!(kinds[0], "login");
        assert_eq!(kinds.last(), Some(&"dst"));
        assert_eq!(g[1].lines[0].value, "root / 123456");
        // dst + login + 31 commands, 20 shown.
        assert_eq!(g[1].more, 33 - MAX_SHOWN as u64);
    }

    #[test]
    fn a_chatty_session_cannot_hide_logins_or_payloads() {
        let mut s = session(A, Protocol::Http);
        s.requests = (0..40)
            .map(|i| HttpRequest {
                method: "GET".into(),
                path: format!("/{i}"),
                headers: (0..50).map(|j| format!("X-{i}: {j}")).collect(),
                body: None,
            })
            .collect();
        let mut later = session(B, Protocol::Http);
        later.credentials = vec![Credential {
            user: "admin".into(),
            password: Some("admin".into()),
            key: None,
        }];
        later.payloads = vec!["ab".repeat(32)];
        let g = show(&[s, later]);
        let kinds: Vec<_> = g[0].lines.iter().map(|l| l.kind.as_str()).collect();
        assert_eq!(&kinds[..2], ["login", "payload"]);
        assert!(kinds.contains(&"header") && kinds.contains(&"dst"));
    }

    #[test]
    fn show_lists_every_kind_cleans_and_clips_values() {
        let mut s = session(A, Protocol::Dns);
        s.dns_name = Some("c2.example\u{9b}31m".into());
        s.queries = vec![DnsQuery {
            name: "c2.example".into(),
            qtype: "A".into(),
            answer: Some(Ipv4Addr::new(198, 18, 0, 1)),
        }];
        s.commands = vec!["y".repeat(1000)];
        let g = show(&[s]);
        let kinds: Vec<_> = g[0].lines.iter().map(|l| l.kind.as_str()).collect();
        assert_eq!(kinds, ["command", "query", "name", "dst"]);
        assert_eq!(g[0].lines[1].value, "A c2.example -> 198.18.0.1");
        // An older aegisctl prints this as it comes.
        assert_eq!(g[0].lines[2].value, "c2.example\\x9b31m");
        assert_eq!(g[0].lines[0].value.len(), MAX_VALUE);
    }

    #[test]
    fn an_incident_without_sessions_is_shown_as_before() {
        let d = dir("noshow");
        let mut v = serde_json::json!({"id": "x"});
        add_show(&mut v, &d.0);
        assert_eq!(v, serde_json::json!({"id": "x"}));
        file(&d.0, &session(A, Protocol::Raw), None);
        add_show(&mut v, &d.0);
        assert_eq!(v["honeypot"][0]["protocol"], "raw");
        assert!(v.get("honeypot_unread").is_none());
        fs::create_dir_all(d.0.join("honeypot").join(B)).unwrap();
        add_show(&mut v, &d.0);
        assert_eq!(v["honeypot_unread"], 1);
    }

    fn read_all(m: &mut Merge) -> Vec<u8> {
        let mut out = Vec::new();
        // Small reads, so records cross read boundaries.
        let mut b = [0u8; 7];
        loop {
            let n = m.read(&mut b).unwrap();
            if n == 0 {
                return out;
            }
            out.extend_from_slice(&b[..n]);
        }
    }

    #[test]
    fn pcap_merge_keeps_one_header_and_puts_records_in_time_order() {
        let d = dir("merge");
        let a = [rec(10, 5, 40), rec(12, 0, 60), rec(14, 0, 20)];
        let b = [rec(10, 6, 30), rec(13, 0, 50)];
        file(&d.0, &session(A, Protocol::Http), Some(&pcap_of(&a)));
        file(&d.0, &session(B, Protocol::Ssh), Some(&pcap_of(&b)));
        let mut m = pcap(&d.0).unwrap();
        assert_eq!((m.sessions, m.left_out), (2, 0));
        let out = read_all(&mut m);
        let want = [&a[0], &b[0], &a[1], &b[1], &a[2]];
        let mut exp = HEADER.to_vec();
        want.iter().for_each(|r| exp.extend(*r));
        assert_eq!(out, exp);
        assert_eq!(m.bytes, out.len() as u64);
    }

    #[test]
    fn pcap_merge_interleaves_more_sessions_than_it_keeps_open() {
        let d = dir("many");
        let n = OPEN_FILES as u32 + 4;
        let mut want = Vec::new();
        for i in 0..n {
            let id = format!("17932752{i:05}-0000000a");
            // Session i has records at i, i + n, i + 2n: round robin.
            let recs: Vec<_> = (0..3).map(|k| rec(i + k * n, 0, 20 + i)).collect();
            file(&d.0, &session(&id, Protocol::Raw), Some(&pcap_of(&recs)));
            want.push(recs);
        }
        let mut exp = HEADER.to_vec();
        for k in 0..3 {
            want.iter().for_each(|r| exp.extend(&r[k]));
        }
        let mut m = pcap(&d.0).unwrap();
        assert_eq!(read_all(&mut m), exp);
        assert!(m.open.len() <= OPEN_FILES);
    }

    #[test]
    fn sessions_past_the_cap_are_counted_without_being_read() {
        let d = dir("skip");
        file(
            &d.0,
            &session(A, Protocol::Raw),
            Some(&pcap_of(&[rec(1, 0, 84)])),
        );
        // Its size alone is over the cap: not indexed, so not "damaged".
        let mut big = b"not a pcap".to_vec();
        big.resize(1000, 0);
        file(&d.0, &session(B, Protocol::Raw), Some(&big));
        // After the cap trips nothing is opened: this would be damaged.
        file(&d.0, &session(C, Protocol::Raw), Some(b"junk"));
        let m = pcap_capped(&d.0, 24 + 100 + 500, MAX_RECORDS, MAX_READ).unwrap();
        assert_eq!((m.sessions, m.left_out), (1, 2));
        assert_eq!(m.notes.len(), 1, "{:?}", m.notes);
        assert!(
            m.notes[0].starts_with("2 newer sessions past"),
            "{:?}",
            m.notes
        );
    }

    #[test]
    fn a_damaged_session_pcap_is_left_out_and_named() {
        let d = dir("trunc");
        let mut p = pcap_of(&[rec(10, 0, 40)]);
        p.truncate(p.len() - 1);
        file(&d.0, &session(A, Protocol::Http), Some(&p));
        let mut p = pcap_of(&[]);
        p[20] = 1; // LINKTYPE_ETHERNET
        file(&d.0, &session(B, Protocol::Http), Some(&p));
        // No pcap at all.
        file(&d.0, &session(C, Protocol::Dns), None);
        let e = pcap(&d.0).err().unwrap();
        assert!(e.starts_with("nothing to export: "), "{e}");
        assert!(e.contains(&format!(
            "session {A}: stream.pcap has a truncated record at byte 24"
        )));
        assert!(e.contains(&format!(
            "session {B}: stream.pcap is not a pcap the honeypot wrote"
        )));
        assert!(
            e.contains(&format!("session {C}: stream.pcap: No such file")),
            "{e}"
        );
        let good = "1793275203000-0000000d";
        file(
            &d.0,
            &session(good, Protocol::Raw),
            Some(&pcap_of(&[rec(1, 0, 8)])),
        );
        let m = pcap(&d.0).unwrap();
        assert_eq!((m.sessions, m.left_out, m.notes.len()), (1, 3, 3));
    }

    #[test]
    fn index_refuses_bad_records() {
        let mut v = Vec::new();
        for bad in [
            pcap_of(&[rec(1, 1_000_000, 4)]),
            pcap_of(&[rec(1, 0, MAX_PACKET + 1)]),
            {
                let mut p = pcap_of(&[rec(1, 0, 8)]);
                p[24 + 12] = 4; // orig_len under incl_len
                p
            },
            pcap_of(&[rec(1, 0, 8)])[..30].to_vec(),
            HEADER[..10].to_vec(),
        ] {
            assert!(index(&bad[..], 0, 10, &mut v).is_err());
        }
        let ok = pcap_of(&[rec(1, 0, 8), rec(2, 0, 8)]);
        assert_eq!(index(&ok[..], 0, 10, &mut v), Ok(48));
        assert!(index(&ok[..], 0, 3, &mut v).is_err());
    }

    #[test]
    fn pcap_leaves_out_the_newest_sessions_over_the_caps_and_says_why() {
        let d = dir("cap");
        for id in [A, B, C] {
            file(
                &d.0,
                &session(id, Protocol::Raw),
                Some(&pcap_of(&[rec(1, 0, 84)])),
            );
        }
        let m = pcap_capped(&d.0, 24 + 2 * 100, MAX_RECORDS, MAX_READ).unwrap();
        assert_eq!((m.sessions, m.left_out, m.bytes), (2, 1, 224));
        assert_eq!(
            m.notes,
            ["1 newer sessions past the 0 MiB or 1048576-record cap"]
        );
        let m = pcap_capped(&d.0, MAX_PCAP, 1, MAX_READ).unwrap();
        assert_eq!((m.sessions, m.left_out), (1, 2));
        let m = pcap_capped(&d.0, MAX_PCAP, MAX_RECORDS, 2).unwrap();
        assert_eq!((m.sessions, m.left_out), (2, 1));
        assert_eq!(m.notes, ["1 sessions past the 2 read"]);
        // Over the cap from the first session: nothing to send.
        let e = pcap_capped(&d.0, 100, MAX_RECORDS, MAX_READ).err().unwrap();
        assert!(
            e.starts_with("nothing to export: 3 newer sessions past"),
            "{e}"
        );
    }

    #[test]
    fn pcap_with_no_sessions_is_nothing_to_export() {
        let d = dir("none");
        let e = pcap(&d.0).err().unwrap();
        assert_eq!(
            e,
            "nothing to export: no honeypot sessions were filed into this incident"
        );
    }

    #[test]
    fn pcap_merge_notices_a_file_changed_after_indexing() {
        let d = dir("changed");
        let p = pcap_of(&[rec(10, 0, 40)]);
        file(&d.0, &session(A, Protocol::Http), Some(&p));
        let mut m = pcap(&d.0).unwrap();
        let f = d.0.join("honeypot").join(A).join("stream.pcap");
        fs::write(&f, pcap_of(&[rec(11, 0, 40)])).unwrap();
        let mut out = Vec::new();
        assert!(m.read_to_end(&mut out).is_err());
    }
}
