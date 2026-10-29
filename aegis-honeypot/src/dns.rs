// SPDX-License-Identifier: MIT OR Apache-2.0
//! DNS for a tree under observation: every A question gets an address
//! of its own from 198.18.0.0/15, the same one each time it asks, so a
//! later connection to that address can be labelled with the name.
//! Every byte here comes from the tree.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use aegis_proto::honeypot::DnsQuery;

/// The first address handed out; 198.18.0.0 itself would look like a
/// network address to a careful client.
const BASE: u32 = u32::from_be_bytes([198, 18, 0, 1]);
/// Names remembered per incident address, and in all. A tree that asks
/// for more is generating names; past the total, the table of the
/// incident address that has been quiet longest goes.
const PER_INCIDENT: usize = 1024;
const TOTAL: usize = 16 * 1024;
/// The answer for every name past the per-address bound: still an address, so the
/// tree carries on, but one no connection is ever labelled from.
pub const OVERFLOW: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 255);
/// Short, so a client that outlives a honeypot restart asks again.
const TTL: u32 = 60;

/// The names each incident address has asked for, and the address each
/// was given: `BASE + index`, in the order they were first asked.
#[derive(Default)]
pub struct Names {
    tables: HashMap<Ipv4Addr, Table>,
    total: usize,
}

struct Table {
    names: HashMap<String, u32>,
    /// When its incident address last asked anything.
    last: Instant,
}

impl Names {
    /// The address for `name` asked from `incident` at `now`: the one it
    /// got before, or the next free one.
    pub fn address(&mut self, incident: Ipv4Addr, name: &str, now: Instant) -> Ipv4Addr {
        if let Some(t) = self.tables.get_mut(&incident) {
            t.last = now;
            if let Some(&i) = t.names.get(name) {
                return Ipv4Addr::from(BASE + i);
            }
            if t.names.len() >= PER_INCIDENT {
                return OVERFLOW;
            }
        }
        if self.total >= TOTAL {
            // Whole tables only: an index is its table's size when given,
            // so dropping single names would hand an address out twice.
            let quietest = self
                .tables
                .iter()
                .filter(|(a, _)| **a != incident)
                .min_by_key(|(_, t)| t.last)
                .map(|(a, _)| *a);
            let Some(gone) = quietest.and_then(|a| self.tables.remove(&a)) else {
                return OVERFLOW;
            };
            self.total -= gone.names.len();
        }
        let t = self.tables.entry(incident).or_insert_with(|| Table {
            names: HashMap::new(),
            last: now,
        });
        let i = t.names.len() as u32;
        t.names.insert(name.to_owned(), i);
        self.total += 1;
        Ipv4Addr::from(BASE + i)
    }

    /// The name `incident` was given `ip` for, if it was.
    /// Marks `incident` active at `now`, whatever it asked.
    pub fn touch(&mut self, incident: Ipv4Addr, now: Instant) {
        if let Some(t) = self.tables.get_mut(&incident) {
            t.last = now;
        }
    }

    /// `name_of` for a connection at `now`, which counts as activity.
    pub fn label(&mut self, incident: Ipv4Addr, ip: Ipv4Addr, now: Instant) -> Option<String> {
        self.touch(incident, now);
        self.name_of(incident, ip).map(str::to_owned)
    }

    pub fn name_of(&self, incident: Ipv4Addr, ip: Ipv4Addr) -> Option<&str> {
        let i = u32::from(ip).checked_sub(BASE)?;
        // Once per connection, over at most PER_INCIDENT entries.
        self.tables
            .get(&incident)?
            .names
            .iter()
            .find_map(|(n, &j)| (j == i).then_some(n.as_str()))
    }
}

/// The reply to one message from `incident`, and the question it asked
/// when it parsed. None for a message that gets no reply at all.
pub fn answer(
    msg: &[u8],
    names: &mut Names,
    incident: Ipv4Addr,
    now: Instant,
) -> Option<(Vec<u8>, Option<DnsQuery>)> {
    let id = msg.get(..2)?;
    let Some(h) = msg.get(..12) else {
        return Some((error(id, 0, FORMERR), None));
    };
    if h[2] & QR != 0 {
        return None;
    }
    if h[2] & OPCODE != 0 {
        return Some((error(id, h[2] & (OPCODE | RD), h[3] & CD | NOTIMP), None));
    }
    // Only the one question is read: no count sizes anything, and what
    // follows the question (EDNS, say) changes nothing here.
    let Some((name, end)) = (h[4..6] == [0, 1]).then(|| question(msg)).flatten() else {
        return Some((error(id, 0, FORMERR), None));
    };
    let (qtype, class) = (be(&msg[end..]), be(&msg[end + 2..]));
    let key = key(&name);
    // Any question is activity, or a busy tree that never asks for an A
    // record would lose the names it still connects to.
    names.touch(incident, now);
    let given = (qtype == 1 && class == 1).then(|| names.address(incident, &key, now));
    let mut r = Vec::with_capacity(12 + name.len() + 4 + 16);
    r.extend(id);
    // A plausible resolver says it recursed.
    r.extend([QR | h[2] & RD, RA | h[3] & CD]);
    r.extend([0, 1, 0, u8::from(given.is_some()), 0, 0, 0, 0]);
    r.extend(&name);
    r.extend(&msg[end..end + 4]);
    if let Some(ip) = given {
        // Owned by the question's name, at offset 12.
        r.extend([0xc0, 12, 0, 1, 0, 1]);
        r.extend(TTL.to_be_bytes());
        r.extend([0, 4]);
        r.extend(ip.octets());
    }
    let qtype = mnemonic(qtype).map_or_else(|| format!("TYPE{qtype}"), str::to_owned);
    let asked = DnsQuery {
        name: key,
        qtype,
        answer: given,
    };
    Some((r, Some(asked)))
}

const QR: u8 = 0x80;
const OPCODE: u8 = 0x78;
const RD: u8 = 0x01;
const RA: u8 = 0x80;
const CD: u8 = 0x10;
const FORMERR: u8 = 1;
const NOTIMP: u8 = 4;

fn be(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// A reply that's only a header.
fn error(id: &[u8], flags: u8, code: u8) -> Vec<u8> {
    let mut r = id.to_vec();
    r.extend([QR | flags, code, 0, 0, 0, 0, 0, 0, 0, 0]);
    r
}

/// The question's name, uncompressed and in its own case, and where its
/// type and class start. None unless every label is at most 63 bytes,
/// the name at most 255, and each pointer goes back before the last
/// place one led: the jumps only ever go down, so they can't loop.
pub fn question(msg: &[u8]) -> Option<(Vec<u8>, usize)> {
    let (mut at, mut floor, mut end) = (12, 12, None);
    let mut name = Vec::new();
    loop {
        let len = *msg.get(at)?;
        match len {
            0 => break,
            1..=63 => {
                let next = at + 1 + usize::from(len);
                name.extend(msg.get(at..next)?);
                at = next;
            }
            0xc0..=0xff => {
                let to = usize::from(len & 0x3f) << 8 | usize::from(*msg.get(at + 1)?);
                if to >= floor {
                    return None;
                }
                end.get_or_insert(at + 2);
                (at, floor) = (to, to);
            }
            _ => return None,
        }
        // 255 with the root label still to come.
        if name.len() > 254 {
            return None;
        }
    }
    name.push(0);
    let end = end.unwrap_or(at + 1);
    msg.get(end..end + 4)?;
    Some((name, end))
}

/// How a name is remembered and recorded: lower case, since DNS ignores
/// case and clients randomise it; dotted, with `.`, `\` and anything
/// unprintable escaped as in a zone file.
fn key(wire: &[u8]) -> String {
    let mut s = String::new();
    let mut at = 0;
    while wire[at] != 0 {
        let next = at + 1 + usize::from(wire[at]);
        if at > 0 {
            s.push('.');
        }
        for &b in &wire[at + 1..next] {
            match b.to_ascii_lowercase() {
                c @ (b'.' | b'\\') => s.extend(['\\', char::from(c)]),
                c if c.is_ascii_graphic() => s.push(char::from(c)),
                c => s.push_str(&format!("\\{c:03}")),
            }
        }
        at = next;
    }
    if s.is_empty() {
        s.push('.');
    }
    s
}

fn mnemonic(t: u16) -> Option<&'static str> {
    Some(match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        _ => return None,
    })
}

/// Builds queries and reads replies the way a client would, without the
/// code under test.
#[cfg(test)]
pub(crate) mod wire {
    use std::net::Ipv4Addr;

    pub const A: u16 = 1;
    pub const AAAA: u16 = 28;

    /// A query for `name` (dotted, the final dot optional), class IN,
    /// with RD set.
    pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend([0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        m.extend(question(name, qtype));
        m
    }

    pub fn question(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        for l in name.split('.').filter(|l| !l.is_empty()) {
            q.push(l.len() as u8);
            q.extend(l.as_bytes());
        }
        q.push(0);
        q.extend(qtype.to_be_bytes());
        q.extend([0, 1]);
        q
    }

    pub struct Reply {
        pub id: u16,
        pub flags: [u8; 2],
        /// The question section as sent back.
        pub question: Vec<u8>,
        pub a: Vec<Ipv4Addr>,
        pub ttls: Vec<u32>,
    }

    impl Reply {
        pub fn rcode(&self) -> u8 {
            self.flags[1] & 0x0f
        }
    }

    /// Reads a reply, checking its shape on the way: a response, at
    /// most one plain question, A records only, nothing after them.
    pub fn read(r: &[u8]) -> Reply {
        assert!((12..=512).contains(&r.len()), "{}", r.len());
        assert_ne!(r[2] & 0x80, 0, "not a response");
        let count = |i: usize| u16::from_be_bytes([r[i], r[i + 1]]);
        assert_eq!((count(8), count(10)), (0, 0));
        let mut p = 12;
        if count(4) == 1 {
            while r[p] != 0 {
                assert!(r[p] <= 63, "label {}", r[p]);
                p += 1 + usize::from(r[p]);
            }
            p += 5;
        } else {
            assert_eq!(count(4), 0);
        }
        let question = r[12..p].to_vec();
        let (mut a, mut ttls) = (Vec::new(), Vec::new());
        for _ in 0..count(6) {
            // Owner name: a pointer to the question's name.
            assert_eq!(r[p..p + 6], [0xc0, 12, 0, 1, 0, 1]);
            ttls.push(u32::from_be_bytes(r[p + 6..p + 10].try_into().unwrap()));
            assert_eq!(r[p + 10..p + 12], [0, 4]);
            a.push(Ipv4Addr::new(r[p + 12], r[p + 13], r[p + 14], r[p + 15]));
            p += 16;
        }
        assert_eq!(p, r.len(), "trailing bytes");
        Reply {
            id: count(0),
            flags: [r[2], r[3]],
            question,
            a,
            ttls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wire::{query, question, read, Reply, A, AAAA};
    use super::*;

    const INCIDENT: Ipv4Addr = Ipv4Addr::new(127, 77, 0, 1);

    fn ask(names: &mut Names, msg: &[u8]) -> (Reply, Option<DnsQuery>) {
        let (reply, q) = answer(msg, names, INCIDENT, Instant::now()).expect("a reply");
        (read(&reply), q)
    }

    /// A header with `qd` questions and these flags, then `rest`.
    fn raw(id: u16, flags: [u8; 2], qd: u16, rest: &[u8]) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend(flags);
        m.extend(qd.to_be_bytes());
        m.extend([0; 6]);
        m.extend(rest);
        m
    }

    #[test]
    fn the_same_name_gets_the_same_address() {
        let mut n = Names::default();
        let (r1, q1) = ask(&mut n, &query(7, "c2.example.", A));
        // Case differs (0x20 randomisation); the name doesn't.
        let q2 = query(8, "C2.Example.", A);
        let (r2, _) = ask(&mut n, &q2);
        assert_eq!(r1.a, [Ipv4Addr::new(198, 18, 0, 1)]);
        assert_eq!(r1.a, r2.a);
        assert_eq!((r1.id, r2.id), (7, 8));
        assert_eq!(r1.rcode(), 0);
        // RD echoed, RA set, AA clear.
        assert_eq!(r1.flags[0] & 0x05, 0x01);
        assert_ne!(r1.flags[1] & 0x80, 0);
        // The question goes back as asked, case and all.
        assert_eq!(r2.question, q2[12..]);
        assert_eq!(r1.ttls, [TTL]);
        assert_eq!(
            q1,
            Some(DnsQuery {
                name: "c2.example".into(),
                qtype: "A".into(),
                answer: Some(Ipv4Addr::new(198, 18, 0, 1)),
            })
        );
    }

    #[test]
    fn two_names_differ_and_each_is_remembered() {
        let mut n = Names::default();
        let (x, _) = ask(&mut n, &query(1, "a.example.", A));
        let (y, _) = ask(&mut n, &query(2, "b.example.", A));
        assert_ne!(x.a, y.a);
        assert_eq!(y.a, [Ipv4Addr::new(198, 18, 0, 2)]);
        assert_eq!(n.name_of(INCIDENT, x.a[0]), Some("a.example"));
        assert_eq!(n.name_of(INCIDENT, y.a[0]), Some("b.example"));
        // Only for the incident that asked, and only for given addresses.
        assert_eq!(n.name_of(Ipv4Addr::new(127, 77, 0, 2), x.a[0]), None);
        assert_eq!(n.name_of(INCIDENT, Ipv4Addr::new(198, 18, 0, 3)), None);
        assert_eq!(n.name_of(INCIDENT, Ipv4Addr::new(1, 1, 1, 1)), None);
    }

    #[test]
    fn each_incident_counts_from_the_start() {
        let mut n = Names::default();
        n.address(INCIDENT, "a", Instant::now());
        let other = Ipv4Addr::new(127, 77, 0, 2);
        assert_eq!(
            n.address(other, "b", Instant::now()),
            Ipv4Addr::new(198, 18, 0, 1)
        );
        assert_eq!(n.name_of(other, Ipv4Addr::new(198, 18, 0, 1)), Some("b"));
        assert_eq!(n.name_of(INCIDENT, Ipv4Addr::new(198, 18, 0, 1)), Some("a"));
    }

    #[test]
    fn past_the_bounds_every_name_gets_the_overflow_address() {
        let mut n = Names::default();
        for i in 0..PER_INCIDENT {
            assert_ne!(
                n.address(INCIDENT, &i.to_string(), Instant::now()),
                OVERFLOW
            );
        }
        assert_eq!(n.address(INCIDENT, "one more", Instant::now()), OVERFLOW);
        // Known names keep theirs; the overflow is never a label.
        assert_eq!(
            n.address(INCIDENT, "0", Instant::now()),
            Ipv4Addr::new(198, 18, 0, 1)
        );
        assert_eq!(n.name_of(INCIDENT, OVERFLOW), None);
    }

    #[test]
    fn past_the_total_the_quietest_incident_loses_its_table() {
        let mut n = Names::default();
        let t0 = Instant::now();
        let at = |s: u64| t0 + std::time::Duration::from_secs(s);
        let inc = |i: u32| Ipv4Addr::from(u32::from(INCIDENT) + i);
        let first = Ipv4Addr::new(198, 18, 0, 1);
        let tables = (TOTAL / PER_INCIDENT) as u32;
        for i in 0..tables {
            for j in 0..PER_INCIDENT {
                n.address(inc(i), &j.to_string(), at(i.into()));
            }
        }
        assert_eq!(n.total, TOTAL);
        // The oldest asks again, even a name it knows: now incident 1 has
        // been quiet longest.
        n.address(inc(0), "0", at(100));
        let fresh = Ipv4Addr::new(127, 77, 255, 1);
        assert_eq!(n.address(fresh, "x", at(101)), first);
        assert_eq!(n.name_of(fresh, first), Some("x"));
        assert_eq!(n.name_of(inc(1), first), None, "incident 1 kept its table");
        assert_eq!(n.name_of(inc(0), first), Some("0"));
        assert_eq!(n.name_of(inc(2), first), Some("0"));
        assert_eq!(n.total, TOTAL - PER_INCIDENT + 1);
        // Whole tables go, so the evicted address starts again at the
        // first address when it comes back.
        assert_eq!(n.address(inc(1), "new", at(102)), first);
    }

    #[test]
    fn asking_anything_or_connecting_keeps_a_table() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + std::time::Duration::from_secs(s);
        let inc = |i: u32| Ipv4Addr::from(u32::from(INCIDENT) + i);
        let first = Ipv4Addr::new(198, 18, 0, 1);
        for how in ["AAAA", "CH", "connect"] {
            let mut n = Names::default();
            for i in 0..(TOTAL / PER_INCIDENT) as u32 {
                for j in 0..PER_INCIDENT {
                    n.address(inc(i), &j.to_string(), at(i.into()));
                }
            }
            // Incident 0 is the oldest by A questions, but busy since.
            match how {
                "AAAA" => {
                    answer(&query(1, "x.", AAAA), &mut n, inc(0), at(100));
                }
                "CH" => {
                    let mut q = query(1, "version.bind.", A);
                    *q.last_mut().unwrap() = 3;
                    answer(&q, &mut n, inc(0), at(100));
                }
                _ => assert_eq!(n.label(inc(0), first, at(100)).as_deref(), Some("0")),
            }
            n.address(Ipv4Addr::new(127, 77, 255, 1), "x", at(101));
            assert_eq!(
                n.name_of(inc(0), first),
                Some("0"),
                "{how}: evicted while busy"
            );
            assert_eq!(n.name_of(inc(1), first), None, "{how}");
        }
    }

    #[test]
    fn aaaa_and_other_types_get_an_empty_noerror() {
        let mut n = Names::default();
        for (t, name) in [
            (AAAA, "AAAA"),
            (15, "MX"),
            (16, "TXT"),
            (65280, "TYPE65280"),
        ] {
            let msg = query(3, "c2.example.", t);
            let (r, q) = ask(&mut n, &msg);
            assert_eq!(r.rcode(), 0);
            assert!(r.a.is_empty(), "{t}");
            assert_eq!(r.question, msg[12..]);
            let q = q.unwrap();
            assert_eq!((q.qtype.as_str(), q.answer), (name, None));
        }
        // Nothing was handed out, so nothing can be labelled.
        assert_eq!(n.total, 0);
    }

    #[test]
    fn a_question_outside_class_in_gets_no_address() {
        let mut n = Names::default();
        let mut m = query(4, "version.bind.", A);
        // Class CH.
        *m.last_mut().unwrap() = 3;
        let (r, _) = ask(&mut n, &m);
        assert!(r.a.is_empty());
        assert_eq!(n.total, 0);
    }

    #[test]
    fn malformed_gets_formerr_with_the_id() {
        let mut n = Names::default();
        let good = query(0x1234, "c2.example.", A);
        let two = raw(
            0x1234,
            [1, 0],
            2,
            &[question("a.", A), question("b.", A)].concat(),
        );
        for bad in [
            good[..5].to_vec(),
            good[..good.len() - 1].to_vec(),
            two,
            raw(0x1234, [1, 0], 0, &[]),
            // A compression pointer to itself.
            [&good[..12], &[0xc0, 12, 0, 1, 0, 1][..]].concat(),
        ] {
            let (r, q) = ask(&mut n, &bad);
            assert_eq!(r.id, 0x1234, "{bad:?}");
            assert_eq!(r.rcode(), 1, "{bad:?}");
            assert!(r.a.is_empty() && q.is_none());
        }
        assert_eq!(n.total, 0);
    }

    #[test]
    fn labels_names_and_pointers_are_held_to_their_limits() {
        let mut n = Names::default();
        // Each would be a whole question but for the one thing wrong.
        let end = [0, 0, 1, 0, 1];
        let label = |len: u8| [&[len][..], &vec![b'x'; usize::from(len & 0x3f | len)]].concat();
        let long: Vec<u8> = (0..4).flat_map(|_| label(63)).collect();
        for (why, q) in [
            ("label type 01", [label(0x40), end.to_vec()].concat()),
            ("label type 10", [label(0x80), end.to_vec()].concat()),
            ("256 bytes and the end", [long, end.to_vec()].concat()),
            // Offset 20 holds the name "x".
            (
                "a pointer forward",
                vec![0xc0, 20, 0, 1, 0, 1, 0, 0, 1, b'x', 0],
            ),
        ] {
            let (r, asked) = ask(&mut n, &raw(0x4242, [1, 0], 1, &q));
            assert_eq!((r.id, r.rcode()), (0x4242, 1), "{why}");
            assert!(asked.is_none(), "{why}");
        }
        // 255 bytes exactly is a name.
        let most: Vec<u8> = (0..3).flat_map(|_| label(63)).chain(label(61)).collect();
        let (r, _) = ask(&mut n, &raw(1, [1, 0], 1, &[&most[..], &end[..]].concat()));
        assert_eq!(r.rcode(), 0);
    }

    #[test]
    fn a_backward_pointer_is_followed_and_echoed_whole() {
        let mut n = Names::default();
        // The id reads as the label "a" and the flags byte ends it, so a
        // pointer to offset 0 names "a".
        let msg = raw(0x0161, [0, 0], 1, &[0xc0, 0, 0, 1, 0, 1]);
        let (r, q) = ask(&mut n, &msg);
        assert_eq!(r.rcode(), 0);
        assert_eq!(r.question, question("a", A));
        assert_eq!(q.unwrap().name, "a");
    }

    #[test]
    fn what_cannot_be_answered_gets_nothing() {
        let mut n = Names::default();
        // No id to answer with.
        assert_eq!(answer(&[], &mut n, INCIDENT, Instant::now()), None);
        assert_eq!(answer(&[1], &mut n, INCIDENT, Instant::now()), None);
        // A response: answering it could set two servers talking forever.
        let mut r = query(9, "a.", A);
        r[2] |= 0x80;
        assert_eq!(answer(&r, &mut n, INCIDENT, Instant::now()), None);
    }

    #[test]
    fn other_opcodes_are_not_implemented() {
        let mut n = Names::default();
        // NOTIFY (4), with RD and CD set.
        let msg = raw(5, [4 << 3 | 1, 0x10], 1, &question("a.", 6));
        let (r, q) = ask(&mut n, &msg);
        assert_eq!(r.rcode(), 4);
        assert_eq!(r.flags[0] & 0x79, 4 << 3 | 1);
        assert_eq!(r.flags[1] & 0x10, 0x10);
        assert!(q.is_none());
    }

    #[test]
    fn edns_and_trailing_records_are_ignored_not_parsed() {
        let mut n = Names::default();
        let mut msg = query(6, "c2.example.", A);
        // Claims 65535 answers it doesn't have: those are never read, so
        // the claim allocates nothing.
        msg[6..8].copy_from_slice(&[0xff, 0xff]);
        let (r, _) = ask(&mut n, &msg);
        assert_eq!(r.a, [Ipv4Addr::new(198, 18, 0, 1)]);
    }

    #[test]
    fn the_longest_name_still_fits_a_plain_udp_reply() {
        let mut n = Names::default();
        // 255 bytes on the wire, every byte escaped when written out.
        let name: Vec<u8> = [63, 63, 63, 61]
            .into_iter()
            .flat_map(|l| [&[l][..], &vec![0xff; usize::from(l)]].concat())
            .chain([0, 0, 1, 0, 1])
            .collect();
        let (r, q) = ask(&mut n, &raw(1, [1, 0], 1, &name));
        assert_eq!(r.a.len(), 1);
        assert_eq!(q.unwrap().name.len(), 250 * 4 + 3);
    }
}
