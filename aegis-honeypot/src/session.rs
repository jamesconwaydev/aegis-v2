// SPDX-License-Identifier: MIT OR Apache-2.0
//! One session's spool directory and the caps on it. Everything is
//! written under `spool/<addr>/<id>/` and the directory moves to
//! `spool/<addr>/done/<id>` in one rename on close, so aegisd never sees
//! a session half-written.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_proto::honeypot::{self, Protocol};
use sha2::{Digest, Sha256};

use crate::pcap::{Pcap, SEGMENT, SEGMENT_COST};

/// Sessions open at once from one incident address, and in all (§4.3).
const PER_ADDR: usize = 64;
const TOTAL: usize = 512;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// `<unix-ms>-<8 hex random>`: sorts by time, and two sessions in the
/// same millisecond still differ.
fn session_id() -> String {
    let mut r = [0u8; 4];
    // getrandom(2) never fails short for 4 bytes once the pool is up; a
    // zero suffix only costs uniqueness within one millisecond.
    unsafe { libc::getrandom(r.as_mut_ptr().cast(), r.len(), 0) };
    format!("{}-{:08x}", now_ms(), u32::from_ne_bytes(r))
}

/// A new file the honeypot user can write and aegisd's group can read.
fn create(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(path)
}

/// Payload files one session may keep. With the hashes in
/// `session.json`, 256 of them stay well under aegisd's 64 KiB read.
const MAX_PAYLOADS: usize = 256;

/// The least free space (bytes, inodes) a spool must keep for a new
/// session to open. Most hosts keep /var/lib on the root filesystem.
#[derive(Clone, Copy)]
pub struct Floor {
    pub bytes: u64,
    pub inodes: u64,
}

pub const FLOOR: Floor = Floor {
    bytes: 1 << 30,
    inodes: 10_000,
};

pub struct Session {
    pub rec: honeypot::Session,
    dir: PathBuf,
    done: PathBuf,
    pcap: Pcap,
    cap: u64,
    /// Charged against `cap`: pcap data segments, and payloads. The pcap
    /// header, handshake and close are the same in every session and
    /// aren't charged.
    used: u64,
}

/// Whether the filesystem holding `dir` has more free than `floor`.
fn above(dir: &Path, floor: Floor) -> io::Result<bool> {
    let (bytes, inodes) = free(dir)?;
    Ok(bytes >= floor.bytes && inodes.is_none_or(|n| n >= floor.inodes))
}

/// Free bytes and inodes for an unprivileged writer on `dir`'s
/// filesystem. No inode count where the filesystem has no inode table
/// (btrfs reports zero files).
pub fn free(dir: &Path) -> io::Result<(u64, Option<u64>)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    // SAFETY: a zeroed statvfs is valid, and statvfs(3) only fills it.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes = st.f_bavail.saturating_mul(st.f_frsize);
    Ok((bytes, (st.f_files != 0).then_some(st.f_favail)))
}

impl Session {
    /// Creates `spool/<addr>/<id>/` and starts its pcap with the
    /// handshake. `cap` bounds what the session leaves on disk, give or
    /// take the fixed pcap header, handshake and close. `spool` must
    /// exist. None when the spool is below `floor`: the honeypot
    /// would rather miss a session than fill the host's disk.
    pub fn open(
        spool: &Path,
        cap: u64,
        floor: Floor,
        protocol: Protocol,
        addr: Ipv4Addr,
        src: SocketAddrV4,
        dst: SocketAddrV4,
    ) -> io::Result<Option<Self>> {
        // Before any mkdir, so a refused session leaves nothing behind.
        if !above(spool, floor)? {
            return Ok(None);
        }
        let base = spool.join(addr.to_string());
        DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(base.join("done"))?;
        let id = session_id();
        let dir = base.join(&id);
        DirBuilder::new().mode(0o750).create(&dir)?;
        let mut pcap = Pcap::new(create(&dir.join("stream.pcap"))?, src, dst)?;
        pcap.syn()?;
        Ok(Some(Self {
            done: base.join("done").join(&id),
            rec: honeypot::Session {
                id,
                protocol,
                addr,
                src,
                dst,
                started_ms: now_ms(),
                ended_ms: 0,
                bytes_in: 0,
                bytes_out: 0,
                truncated: false,
                timed_out: false,
                payloads: Vec::new(),
            },
            dir,
            pcap,
            cap,
            used: 0,
        }))
    }

    /// Records bytes one side sent, up to the cap. False once the cap
    /// is reached: the session has said all it will be allowed to, and
    /// is flagged `truncated`, since the handler closes it there.
    pub fn record(&mut self, from_client: bool, data: &[u8]) -> io::Result<bool> {
        // Each segment costs its headers too, or a client sending one
        // byte at a time would write 57 bytes to disk per byte kept.
        for c in data.chunks(SEGMENT) {
            let fits = (self.cap - self.used).saturating_sub(SEGMENT_COST);
            let keep = &c[..c.len().min(usize::try_from(fits).unwrap_or(usize::MAX))];
            if !keep.is_empty() {
                self.pcap.data(from_client, keep)?;
                let n = keep.len() as u64;
                self.used += n + SEGMENT_COST;
                if from_client {
                    self.rec.bytes_in += n;
                } else {
                    self.rec.bytes_out += n;
                }
            }
            if keep.len() < c.len() {
                self.rec.truncated = true;
                return Ok(false);
            }
        }
        let more = self.cap - self.used > SEGMENT_COST;
        self.rec.truncated |= !more;
        Ok(more)
    }

    /// Keeps `data` as a payload file named by its SHA-256, once, and
    /// charges it to the cap. None, and `truncated`, when it doesn't fit
    /// or the session already holds `MAX_PAYLOADS`. Protocol handlers
    /// store bodies, mail and uploads this way.
    #[allow(dead_code)]
    pub fn payload(&mut self, data: &[u8]) -> io::Result<Option<String>> {
        let d: [u8; 32] = Sha256::digest(data).into();
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        if self.rec.payloads.contains(&hex) {
            return Ok(Some(hex));
        }
        let len = data.len() as u64;
        if self.rec.payloads.len() >= MAX_PAYLOADS || len > self.cap - self.used {
            self.rec.truncated = true;
            return Ok(None);
        }
        create(&self.dir.join(&hex))?.write_all(data)?;
        self.used += len;
        self.rec.payloads.push(hex.clone());
        Ok(Some(hex))
    }

    /// Ends the pcap, writes `session.json` and moves the directory to
    /// `done/`. Returns where it landed.
    pub fn close(mut self) -> io::Result<PathBuf> {
        self.pcap.fin()?;
        self.rec.ended_ms = now_ms();
        let json = serde_json::to_vec_pretty(&self.rec).map_err(io::Error::other)?;
        create(&self.dir.join("session.json"))?.write_all(&json)?;
        std::fs::rename(&self.dir, &self.done)?;
        Ok(self.done)
    }
}

/// Counts open sessions against the caps. Single-threaded: every
/// session runs on the one runtime thread.
#[derive(Clone, Default)]
pub struct Slots(Rc<RefCell<(usize, HashMap<Ipv4Addr, usize>)>>);

/// One open session's place; dropping it frees the place.
pub struct Slot {
    slots: Slots,
    addr: Ipv4Addr,
}

impl Slots {
    /// Sessions open now, from every address.
    pub fn open(&self) -> usize {
        self.0.borrow().0
    }

    /// A place for one more session from `addr`, or None at either cap.
    pub fn take(&self, addr: Ipv4Addr) -> Option<Slot> {
        let mut g = self.0.borrow_mut();
        let (total, per) = &mut *g;
        let n = per.entry(addr).or_default();
        if *total >= TOTAL || *n >= PER_ADDR {
            if *n == 0 {
                per.remove(&addr);
            }
            return None;
        }
        *n += 1;
        *total += 1;
        Some(Slot {
            slots: self.clone(),
            addr,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut g = self.slots.0.borrow_mut();
        let (total, per) = &mut *g;
        *total -= 1;
        if let Some(n) = per.get_mut(&self.addr) {
            *n -= 1;
            if *n == 0 {
                per.remove(&self.addr);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// An empty spool root, as main creates it at start.
    pub fn spool(name: &str) -> PathBuf {
        let r = std::env::temp_dir().join(format!("aegis-spool-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        DirBuilder::new().mode(0o750).create(&r).unwrap();
        r
    }

    pub const NO_FLOOR: Floor = Floor {
        bytes: 0,
        inodes: 0,
    };

    fn try_open(spool: &Path, cap: u64, floor: Floor) -> Option<Session> {
        Session::open(
            spool,
            cap,
            floor,
            Protocol::Raw,
            Ipv4Addr::new(127, 77, 0, 5),
            "10.0.0.2:40000".parse().unwrap(),
            "1.2.3.4:6667".parse().unwrap(),
        )
        .unwrap()
    }

    fn open(spool: &Path, cap: u64) -> Session {
        try_open(spool, cap, NO_FLOOR).unwrap()
    }

    /// The cap for `data` bytes in `segments` segments.
    fn cap(data: u64, segments: u64) -> u64 {
        data + segments * SEGMENT_COST
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn ids_sort_by_time_and_differ() {
        let (a, b) = (session_id(), session_id());
        assert_ne!(a, b);
        let (ms, rand) = a.split_once('-').unwrap();
        assert!(ms.parse::<u64>().unwrap().abs_diff(now_ms()) < 60_000);
        assert_eq!(rand.len(), 8);
        assert!(rand
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn a_session_appears_in_done_only_whole() {
        let sp = spool("rename");
        let mut s = open(&sp, 1000);
        let addr = sp.join("127.77.0.5");
        let live = addr.join(&s.rec.id);
        assert!(live.join("stream.pcap").is_file());
        // While it runs, done/ is there for aegisd but holds nothing.
        assert_eq!(std::fs::read_dir(addr.join("done")).unwrap().count(), 0);
        assert!(s.record(true, b"hi").unwrap());
        let id = s.rec.id.clone();
        let done = s.close().unwrap();

        assert_eq!(done, addr.join("done").join(&id));
        assert!(!live.exists());
        let mut names: Vec<String> = std::fs::read_dir(&done)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["session.json", "stream.pcap"]);
        for d in [&sp, &addr, &addr.join("done"), &done] {
            assert_eq!(mode(d), 0o750, "{}", d.display());
        }
        for n in &names {
            assert_eq!(mode(&done.join(n)), 0o640, "{n}");
        }
        let rec: honeypot::Session =
            serde_json::from_slice(&std::fs::read(done.join("session.json")).unwrap()).unwrap();
        assert_eq!(rec.id, id);
        assert_eq!((rec.bytes_in, rec.bytes_out, rec.truncated), (2, 0, false));
        assert!(rec.started_ms <= rec.ended_ms);
        let pkts = crate::pcap::tests::read(&std::fs::read(done.join("stream.pcap")).unwrap());
        assert_eq!(pkts.len(), 3 + 1 + 3);
        assert_eq!(pkts[3].data, b"hi");
        assert_eq!(pkts[3].dst, rec.dst);
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[test]
    fn byte_cap_truncates_and_flags() {
        let sp = spool("cap");
        let mut s = open(&sp, cap(10, 3));
        assert!(s.record(true, b"12345").unwrap());
        assert!(s.record(false, b"abc").unwrap());
        // Two bytes of room left: kept, and the session is told to stop.
        assert!(!s.record(true, b"6789").unwrap());
        assert!(!s.record(false, b"more").unwrap());
        assert!(s.rec.truncated);
        assert_eq!((s.rec.bytes_in, s.rec.bytes_out), (7, 3));
        let done = s.close().unwrap();
        let pkts = crate::pcap::tests::read(&std::fs::read(done.join("stream.pcap")).unwrap());
        let kept: Vec<u8> = pkts.iter().flat_map(|p| p.data.clone()).collect();
        assert_eq!(kept, b"12345abc67");
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[test]
    fn filling_the_cap_exactly_still_flags_the_cut() {
        let sp = spool("exact");
        let mut s = open(&sp, cap(4, 1));
        assert!(!s.record(true, b"1234").unwrap());
        assert_eq!(s.rec.bytes_in, 4);
        assert!(s.rec.truncated);
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[test]
    fn payloads_are_named_by_hash_and_kept_once() {
        let sp = spool("payload");
        let mut s = open(&sp, 100);
        let h = s.payload(b"abc").unwrap().unwrap();
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(s.payload(b"abc").unwrap().unwrap(), h);
        assert_eq!(s.rec.payloads, std::slice::from_ref(&h));
        // Charged once: 97 bytes of room are left.
        assert!(s.payload(&[0; 98]).unwrap().is_none());
        assert!(s.rec.truncated);
        assert!(s.payload(&[0; 97]).unwrap().is_some());
        let done = s.close().unwrap();
        assert_eq!(std::fs::read(done.join(&h)).unwrap(), b"abc");
        assert_eq!(mode(&done.join(&h)), 0o640);
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[test]
    fn a_one_byte_flood_stays_within_the_cap_on_disk() {
        let sp = spool("flood");
        let max = 10_000;
        let mut s = open(&sp, max);
        let mut sent = 0;
        while s.record(sent % 2 == 0, b"x").unwrap() {
            sent += 1;
            assert!(sent < max, "the cap never closed the session");
        }
        assert!(s.rec.truncated);
        // One more byte does not fit, and is not written.
        let kept = s.rec.bytes_in + s.rec.bytes_out;
        assert!(!s.record(true, b"x").unwrap());
        assert_eq!(s.rec.bytes_in + s.rec.bytes_out, kept);
        let done = s.close().unwrap();
        let size = std::fs::metadata(done.join("stream.pcap")).unwrap().len();
        assert!(size <= max + crate::pcap::FIXED_COST, "{size}");
        assert!(size > max - 2 * SEGMENT_COST, "{size}");
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[test]
    fn payloads_stop_at_their_count_limit() {
        let sp = spool("many");
        let mut s = open(&sp, 1 << 20);
        for i in 0..MAX_PAYLOADS as u32 {
            assert!(s.payload(&i.to_be_bytes()).unwrap().is_some());
        }
        assert!(!s.rec.truncated);
        assert!(s.payload(b"one too many").unwrap().is_none());
        assert!(s.rec.truncated);
        let done = s.close().unwrap();
        // 64 KiB is what aegisd will read of session.json.
        let json = std::fs::metadata(done.join("session.json")).unwrap().len();
        assert!(json < 64 * 1024, "{json}");
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[test]
    fn a_spool_below_its_floor_opens_no_session() {
        let sp = spool("floor");
        for floor in [
            Floor {
                bytes: u64::MAX,
                inodes: 0,
            },
            Floor {
                bytes: 0,
                inodes: u64::MAX,
            },
        ] {
            assert!(try_open(&sp, 100, floor).is_none());
        }
        assert_eq!(
            std::fs::read_dir(&sp).unwrap().count(),
            0,
            "left a directory"
        );
        assert!(try_open(&sp, 100, NO_FLOOR).is_some());
        std::fs::remove_dir_all(sp).unwrap();
    }

    #[test]
    fn slots_cap_per_address_and_in_all() {
        let s = Slots::default();
        let a = Ipv4Addr::new(127, 77, 0, 1);
        let mut held: Vec<Slot> = (0..PER_ADDR).map(|_| s.take(a).unwrap()).collect();
        assert!(s.take(a).is_none());
        // Another address is unaffected, and a freed place is reusable.
        let b = Ipv4Addr::new(127, 77, 0, 2);
        assert!(s.take(b).is_some());
        held.pop();
        held.push(s.take(a).unwrap());
        assert!(s.take(a).is_none());

        for i in 0..(TOTAL - PER_ADDR) {
            let other = Ipv4Addr::from(0x7f4d_1000 + i as u32 / 8);
            held.push(s.take(other).unwrap());
        }
        assert!(s.take(b).is_none());
        drop(held);
        assert_eq!(s.0.borrow().0, 0);
        assert!(s.0.borrow().1.is_empty());
    }
}
