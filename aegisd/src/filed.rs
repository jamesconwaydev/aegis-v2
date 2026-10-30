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

/// Sessions read for one request, oldest first.
pub const MAX_READ: usize = 4096;
/// The most `incidents pcap` sends.
pub const MAX_PCAP: u64 = 256 << 20;
/// Records indexed for one pcap, so the index stays near 24 MiB.
const MAX_RECORDS: usize = 1 << 20;
/// Longest value `incidents show` sends; commands run to 1 KiB.
const MAX_VALUE: usize = 256;
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

/// The ids of the sessions filed in `inc_dir`, oldest first, at most
/// `MAX_READ`. Hidden half-filed copies and anything not named like a
/// session are skipped.
pub fn ids(inc_dir: &Path) -> Vec<String> {
    let Ok(rd) = fs::read_dir(inc_dir.join("honeypot")) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| spool::session_id(n))
        .collect();
    v.sort_unstable();
    v.truncate(MAX_READ);
    v
}

/// Every filed session that still reads and parses, oldest first.
pub fn sessions(inc_dir: &Path) -> Vec<Session> {
    let hp = inc_dir.join("honeypot");
    ids(inc_dir)
        .into_iter()
        .filter_map(|id| {
            let mut json = Vec::new();
            open(&hp.join(&id).join("session.json"))
                .ok()?
                .take(MAX_JSON + 1)
                .read_to_end(&mut json)
                .ok()?;
            spool::parse(&json).ok().filter(|s| s.id == id)
        })
        .collect()
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_VALUE).collect()
}

/// What `incidents show` lists for one session, in order.
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

/// The `honeypot` part of `incidents show`: sessions by protocol, each
/// protocol's lines once, at most `MAX_SHOWN` of them, the rest counted.
pub fn show(sessions: &[Session]) -> Vec<ShowHoneypot> {
    let hasher = RandomState::new();
    let mut by: BTreeMap<String, (ShowHoneypot, HashSet<u64>)> = BTreeMap::new();
    for s in sessions {
        let proto = serde_json::to_value(s.protocol)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let (g, seen) = by.entry(proto.clone()).or_insert_with(|| {
            let g = ShowHoneypot {
                protocol: proto,
                sessions: 0,
                lines: Vec::new(),
                more: 0,
            };
            (g, HashSet::new())
        });
        g.sessions += 1;
        for (kind, value) in lines(s) {
            // Hashes, not the lines: what's past the cap isn't kept.
            if !seen.insert(hasher.hash_one((kind, &value))) {
                continue;
            }
            if g.lines.len() < MAX_SHOWN {
                g.lines.push(ShowLine {
                    kind: kind.into(),
                    value: clip(&value),
                });
            } else {
                g.more += 1;
            }
        }
    }
    by.into_values().map(|(g, _)| g).collect()
}

/// Adds the `honeypot` part to an incident's JSON when it has filed
/// sessions. One without (every drop-mode incident) is left as it was.
pub fn add_show(v: &mut Value, inc_dir: &Path) {
    let s = sessions(inc_dir);
    if s.is_empty() {
        return;
    }
    if let (Some(m), Ok(h)) = (v.as_object_mut(), serde_json::to_value(show(&s))) {
        m.insert("honeypot".into(), h);
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
    cur: Option<(u32, File, u64)>,
    buf: Vec<u8>,
    pos: usize,
    /// What reading it yields, in all.
    pub bytes: u64,
    pub sessions: u64,
    /// Sessions over the cap, newest first.
    pub left_out: u64,
}

/// The merged pcap of the incident at `inc_dir`. Sessions go in oldest
/// first until the next would take it past `MAX_PCAP`. A session file
/// that fails `index` fails the whole export, naming it.
pub fn pcap(inc_dir: &Path) -> Result<Merge, String> {
    pcap_capped(inc_dir, MAX_PCAP, MAX_RECORDS)
}

fn pcap_capped(inc_dir: &Path, max_bytes: u64, max_recs: usize) -> Result<Merge, String> {
    let ids = ids(inc_dir);
    let mut m = Merge {
        files: Vec::new(),
        recs: Vec::new(),
        next: 0,
        started: false,
        cur: None,
        buf: Vec::new(),
        pos: 0,
        bytes: 24,
        sessions: 0,
        left_out: 0,
    };
    let mut one = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let p = inc_dir.join("honeypot").join(id).join("stream.pcap");
        let f = match open(&p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            r => r.map_err(|e| format!("session {id}: stream.pcap: {e}"))?,
        };
        one.clear();
        let n = index(BufReader::new(f), m.files.len() as u32, max_recs, &mut one)
            .map_err(|e| format!("session {id}: stream.pcap {e}"))?;
        if m.bytes + n > max_bytes || m.recs.len() + one.len() > max_recs {
            m.left_out = (ids.len() - i) as u64;
            break;
        }
        m.bytes += n;
        m.sessions += 1;
        m.files.push(p);
        m.recs.extend_from_slice(&one);
    }
    if m.sessions == 0 && m.left_out == 0 {
        return Err("nothing to export: no honeypot sessions were filed into this incident".into());
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
        if self.cur.as_ref().is_none_or(|c| c.0 != r.file) {
            self.cur = Some((r.file, open(&self.files[r.file as usize])?, 0));
        }
        let Some((_, f, at)) = self.cur.as_mut() else {
            return Ok(false);
        };
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
            started_ms: 1_793_275_260_000,
            ended_ms: 1_793_275_261_500,
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

    const A: &str = "1761739200000-0000000a";
    const B: &str = "1761739201000-0000000b";
    const C: &str = "1761739202000-0000000c";

    #[test]
    fn sessions_are_read_oldest_first_and_junk_is_skipped() {
        let d = dir("read");
        file(&d.0, &session(B, Protocol::Http), None);
        file(&d.0, &session(A, Protocol::Ssh), None);
        // A half-filed copy, junk, a session.json that doesn't parse,
        // one for another session, and a link.
        file(
            &d.0,
            &session(".1761739200000-0000000c", Protocol::Raw),
            None,
        );
        fs::create_dir_all(d.0.join("honeypot/junk")).unwrap();
        fs::create_dir_all(d.0.join("honeypot").join(C)).unwrap();
        fs::write(d.0.join("honeypot").join(C).join("session.json"), b"{").unwrap();
        file(&d.0, &session(A, Protocol::Ssh), None);
        let other = "1761739203000-0000000d";
        fs::create_dir_all(d.0.join("honeypot").join(other)).unwrap();
        std::os::unix::fs::symlink(
            d.0.join("honeypot").join(A).join("session.json"),
            d.0.join("honeypot").join(other).join("session.json"),
        )
        .unwrap();
        let got: Vec<String> = sessions(&d.0).into_iter().map(|s| s.id).collect();
        assert_eq!(got, [A, B]);
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
                ("dst", "1.2.3.4:80"),
                ("request", "GET /a"),
                ("header", "Host: c2.example")
            ]
        );
        assert_eq!(
            (g[1].protocol.as_str(), g[1].lines.len()),
            ("ssh", MAX_SHOWN)
        );
        assert_eq!(g[1].lines[1].value, "root / 123456");
        // dst + login + 31 commands, 20 shown.
        assert_eq!(g[1].more, 33 - MAX_SHOWN as u64);
    }

    #[test]
    fn show_lists_every_kind_and_clips_long_values() {
        let mut s = session(A, Protocol::Dns);
        s.dns_name = Some("c2.example".into());
        s.queries = vec![DnsQuery {
            name: "c2.example".into(),
            qtype: "A".into(),
            answer: Some(Ipv4Addr::new(198, 18, 0, 1)),
        }];
        s.commands = vec!["y".repeat(1000)];
        let g = show(&[s]);
        let kinds: Vec<_> = g[0].lines.iter().map(|l| l.kind.as_str()).collect();
        assert_eq!(kinds, ["dst", "name", "query", "command"]);
        assert_eq!(g[0].lines[2].value, "A c2.example -> 198.18.0.1");
        assert_eq!(g[0].lines[3].value.len(), MAX_VALUE);
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
        // No pcap at all: skipped, not an error.
        file(&d.0, &session(C, Protocol::Dns), None);
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
    fn pcap_merge_refuses_a_truncated_or_foreign_session() {
        let d = dir("trunc");
        let mut p = pcap_of(&[rec(10, 0, 40)]);
        p.truncate(p.len() - 1);
        file(&d.0, &session(A, Protocol::Http), Some(&p));
        let e = pcap(&d.0).err().unwrap();
        assert!(
            e.contains(A) && e.contains("truncated record at byte 24"),
            "{e}"
        );
        let mut p = pcap_of(&[]);
        p[20] = 1; // LINKTYPE_ETHERNET
        file(&d.0, &session(A, Protocol::Http), Some(&p));
        assert!(pcap(&d.0)
            .err()
            .unwrap()
            .contains("not a pcap the honeypot wrote"));
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
    fn pcap_leaves_out_the_newest_sessions_over_the_cap() {
        let d = dir("cap");
        for id in [A, B, C] {
            file(
                &d.0,
                &session(id, Protocol::Raw),
                Some(&pcap_of(&[rec(1, 0, 84)])),
            );
        }
        let m = pcap_capped(&d.0, 24 + 2 * 100, MAX_RECORDS).unwrap();
        assert_eq!((m.sessions, m.left_out, m.bytes), (2, 1, 224));
        let m = pcap_capped(&d.0, MAX_PCAP, 1).unwrap();
        assert_eq!((m.sessions, m.left_out), (1, 2));
    }

    #[test]
    fn pcap_with_no_sessions_is_nothing_to_export() {
        let d = dir("none");
        let e = pcap(&d.0).err().unwrap();
        assert!(e.starts_with("nothing to export"), "{e}");
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
