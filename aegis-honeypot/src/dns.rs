// SPDX-License-Identifier: MIT OR Apache-2.0
//! DNS for a tree under observation: every A question gets an address
//! of its own from 198.18.0.0/15, the same one each time it asks, so a
//! later connection to that address can be labelled with the name.
//! Every byte here comes from the tree.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use aegis_proto::honeypot::DnsQuery;
use hickory_proto::op::{Header, Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

/// The first address handed out; 198.18.0.0 itself would look like a
/// network address to a careful client.
const BASE: u32 = u32::from_be_bytes([198, 18, 0, 1]);
/// Names remembered per incident address, and in all. A tree that asks
/// for more is generating names, and each one costs memory for good.
const PER_INCIDENT: usize = 1024;
const TOTAL: usize = 16 * 1024;
/// The answer for every name past those bounds: still an address, so the
/// tree carries on, but one no connection is ever labelled from.
pub const OVERFLOW: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 255);
/// Short, so a client that outlives a honeypot restart asks again.
const TTL: u32 = 60;

/// The names each incident address has asked for, and the address each
/// was given: `BASE + index`, in the order they were first asked.
#[derive(Default)]
pub struct Names {
    tables: HashMap<Ipv4Addr, HashMap<String, u32>>,
    total: usize,
}

impl Names {
    /// The address for `name` asked from `incident`: the one it got
    /// before, or the next free one.
    pub fn address(&mut self, incident: Ipv4Addr, name: &str) -> Ipv4Addr {
        if let Some(&i) = self.tables.get(&incident).and_then(|t| t.get(name)) {
            return Ipv4Addr::from(BASE + i);
        }
        // Checked before the entry, so a refused name leaves no table.
        let full = self.tables.get(&incident).map_or(0, HashMap::len) >= PER_INCIDENT;
        if full || self.total >= TOTAL {
            return OVERFLOW;
        }
        let t = self.tables.entry(incident).or_default();
        let i = t.len() as u32;
        t.insert(name.to_owned(), i);
        self.total += 1;
        Ipv4Addr::from(BASE + i)
    }

    /// The name `incident` was given `ip` for, if it was.
    pub fn name_of(&self, incident: Ipv4Addr, ip: Ipv4Addr) -> Option<&str> {
        let i = u32::from(ip).checked_sub(BASE)?;
        // Once per connection, over at most PER_INCIDENT entries.
        self.tables
            .get(&incident)?
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
) -> Option<(Vec<u8>, Option<DnsQuery>)> {
    let id = u16::from_be_bytes([*msg.first()?, *msg.get(1)?]);
    let formerr = || {
        error(
            Metadata::new(id, MessageType::Response, OpCode::Query),
            ResponseCode::FormErr,
        )
    };
    let mut d = BinDecoder::new(msg);
    let Ok(Header { metadata, counts }) = Header::read(&mut d) else {
        return Some((formerr()?, None));
    };
    if metadata.message_type == MessageType::Response {
        return None;
    }
    let mut reply = Metadata::response_from_request(&metadata);
    if metadata.op_code != OpCode::Query {
        return Some((error(reply, ResponseCode::NotImp)?, None));
    }
    // Only the one question is read. Message::read would size a Vec from
    // each count the client claims, and what follows the question (EDNS,
    // say) changes nothing here.
    let q = match Query::read(&mut d) {
        Ok(q) if counts.queries == 1 => q,
        _ => return Some((formerr()?, None)),
    };
    let name = key(q.name());
    let given = (q.query_class() == DNSClass::IN && q.query_type() == RecordType::A)
        .then(|| names.address(incident, &name));
    // A plausible resolver says it recursed.
    reply.recursion_available = true;
    let mut m = Message::new(id, MessageType::Response, OpCode::Query);
    m.metadata = reply;
    if let Some(ip) = given {
        m.add_answer(Record::from_rdata(q.name().clone(), TTL, RData::A(A(ip))));
    }
    let qtype = match q.query_type() {
        RecordType::Unknown(n) => format!("TYPE{n}"),
        t => t.to_string(),
    };
    m.add_query(q);
    let asked = DnsQuery {
        name,
        qtype,
        answer: given,
    };
    Some((m.to_vec().ok()?, Some(asked)))
}

/// A reply that's only a header with `code`.
fn error(mut m: Metadata, code: ResponseCode) -> Option<Vec<u8>> {
    m.response_code = code;
    let mut r = Message::new(m.id, MessageType::Response, m.op_code);
    r.metadata = m;
    r.to_vec().ok()
}

/// How a name is remembered and recorded: DNS names ignore case, and
/// clients randomise it.
fn key(n: &Name) -> String {
    let s = n.to_lowercase().to_ascii();
    match s.strip_suffix('.') {
        Some(t) if !t.is_empty() => t.to_owned(),
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INCIDENT: Ipv4Addr = Ipv4Addr::new(127, 77, 0, 1);

    fn query(id: u16, name: &str, t: RecordType) -> Vec<u8> {
        let mut m = Message::new(id, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
        m.to_vec().unwrap()
    }

    fn ask(names: &mut Names, msg: &[u8]) -> (Message, Option<DnsQuery>) {
        let (reply, q) = answer(msg, names, INCIDENT).expect("a reply");
        assert!(reply.len() <= 512, "{}", reply.len());
        (Message::from_vec(&reply).unwrap(), q)
    }

    fn a(m: &Message) -> Vec<Ipv4Addr> {
        m.answers
            .iter()
            .map(|r| match &r.data {
                RData::A(a) => a.0,
                d => panic!("{d:?}"),
            })
            .collect()
    }

    #[test]
    fn the_same_name_gets_the_same_address() {
        let mut n = Names::default();
        let (m1, q1) = ask(&mut n, &query(7, "c2.example.", RecordType::A));
        // Case differs (0x20 randomisation); the name doesn't.
        let (m2, _) = ask(&mut n, &query(8, "C2.Example.", RecordType::A));
        assert_eq!(a(&m1), [Ipv4Addr::new(198, 18, 0, 1)]);
        assert_eq!(a(&m1), a(&m2));
        assert_eq!(m1.metadata.id, 7);
        assert_eq!(m2.metadata.id, 8);
        assert_eq!(m1.metadata.message_type, MessageType::Response);
        assert_eq!(m1.metadata.response_code, ResponseCode::NoError);
        assert!(m1.metadata.recursion_desired && m1.metadata.recursion_available);
        // The question goes back as asked, case and all.
        assert_eq!(m2.queries[0].name().to_ascii(), "C2.Example.");
        assert_eq!(m2.answers[0].name.to_ascii(), "C2.Example.");
        assert_eq!(m1.answers[0].ttl, TTL);
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
        let (x, _) = ask(&mut n, &query(1, "a.example.", RecordType::A));
        let (y, _) = ask(&mut n, &query(2, "b.example.", RecordType::A));
        assert_ne!(a(&x), a(&y));
        assert_eq!(a(&y), [Ipv4Addr::new(198, 18, 0, 2)]);
        assert_eq!(n.name_of(INCIDENT, a(&x)[0]), Some("a.example"));
        assert_eq!(n.name_of(INCIDENT, a(&y)[0]), Some("b.example"));
        // Only for the incident that asked, and only for given addresses.
        assert_eq!(n.name_of(Ipv4Addr::new(127, 77, 0, 2), a(&x)[0]), None);
        assert_eq!(n.name_of(INCIDENT, Ipv4Addr::new(198, 18, 0, 3)), None);
        assert_eq!(n.name_of(INCIDENT, Ipv4Addr::new(1, 1, 1, 1)), None);
    }

    #[test]
    fn each_incident_counts_from_the_start() {
        let mut n = Names::default();
        n.address(INCIDENT, "a");
        let other = Ipv4Addr::new(127, 77, 0, 2);
        assert_eq!(n.address(other, "b"), Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(n.name_of(other, Ipv4Addr::new(198, 18, 0, 1)), Some("b"));
        assert_eq!(n.name_of(INCIDENT, Ipv4Addr::new(198, 18, 0, 1)), Some("a"));
    }

    #[test]
    fn past_the_bounds_every_name_gets_the_overflow_address() {
        let mut n = Names::default();
        for i in 0..PER_INCIDENT {
            assert_ne!(n.address(INCIDENT, &i.to_string()), OVERFLOW);
        }
        assert_eq!(n.address(INCIDENT, "one more"), OVERFLOW);
        // Known names keep theirs; the overflow is never a label.
        assert_eq!(n.address(INCIDENT, "0"), Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(n.name_of(INCIDENT, OVERFLOW), None);
        // The total bounds every incident together.
        let mut i = 1u32;
        while n.total < TOTAL {
            let inc = Ipv4Addr::from(u32::from(INCIDENT) + i);
            for j in 0..PER_INCIDENT.min(TOTAL - n.total) {
                n.address(inc, &j.to_string());
            }
            i += 1;
        }
        let fresh = Ipv4Addr::new(127, 77, 255, 1);
        assert_eq!(n.address(fresh, "x"), OVERFLOW);
        assert!(!n.tables.contains_key(&fresh), "an empty table was kept");
    }

    #[test]
    fn aaaa_and_other_types_get_an_empty_noerror() {
        let mut n = Names::default();
        for (t, name) in [
            (RecordType::AAAA, "AAAA"),
            (RecordType::MX, "MX"),
            (RecordType::TXT, "TXT"),
            (RecordType::Unknown(65280), "TYPE65280"),
        ] {
            let (m, q) = ask(&mut n, &query(3, "c2.example.", t));
            assert_eq!(m.metadata.response_code, ResponseCode::NoError);
            assert!(m.answers.is_empty(), "{t}");
            assert_eq!(m.queries.len(), 1);
            let q = q.unwrap();
            assert_eq!((q.qtype.as_str(), q.answer), (name, None));
        }
        // Nothing was handed out, so nothing can be labelled.
        assert_eq!(n.total, 0);
    }

    #[test]
    fn a_question_outside_class_in_gets_no_address() {
        let mut n = Names::default();
        let mut m = Message::new(4, MessageType::Query, OpCode::Query);
        let mut q = Query::query(Name::from_ascii("version.bind.").unwrap(), RecordType::A);
        q.set_query_class(DNSClass::CH);
        m.add_query(q);
        let (r, _) = ask(&mut n, &m.to_vec().unwrap());
        assert!(r.answers.is_empty());
        assert_eq!(n.total, 0);
    }

    #[test]
    fn malformed_gets_formerr_with_the_id() {
        let mut n = Names::default();
        let good = query(0x1234, "c2.example.", RecordType::A);
        let mut two = Message::new(0x1234, MessageType::Query, OpCode::Query);
        two.add_query(Query::query(Name::from_ascii("a.").unwrap(), RecordType::A));
        two.add_query(Query::query(Name::from_ascii("b.").unwrap(), RecordType::A));
        let none = Message::new(0x1234, MessageType::Query, OpCode::Query);
        for bad in [
            good[..5].to_vec(),
            good[..good.len() - 1].to_vec(),
            two.to_vec().unwrap(),
            none.to_vec().unwrap(),
            // A compression pointer to itself.
            [&good[..12], &[0xc0, 12, 0, 1, 0, 1][..]].concat(),
        ] {
            let (m, q) = ask(&mut n, &bad);
            assert_eq!(m.metadata.id, 0x1234, "{bad:?}");
            assert_eq!(m.metadata.response_code, ResponseCode::FormErr, "{bad:?}");
            assert!(m.answers.is_empty() && q.is_none());
        }
        assert_eq!(n.total, 0);
    }

    #[test]
    fn what_cannot_be_answered_gets_nothing() {
        let mut n = Names::default();
        // No id to answer with.
        assert_eq!(answer(&[], &mut n, INCIDENT), None);
        assert_eq!(answer(&[1], &mut n, INCIDENT), None);
        // A response: answering it could set two servers talking forever.
        let mut r = Message::new(9, MessageType::Response, OpCode::Query);
        r.add_query(Query::query(Name::from_ascii("a.").unwrap(), RecordType::A));
        assert_eq!(answer(&r.to_vec().unwrap(), &mut n, INCIDENT), None);
    }

    #[test]
    fn other_opcodes_are_not_implemented() {
        let mut n = Names::default();
        let mut m = Message::new(5, MessageType::Query, OpCode::Notify);
        m.add_query(Query::query(
            Name::from_ascii("a.").unwrap(),
            RecordType::SOA,
        ));
        let (r, q) = ask(&mut n, &m.to_vec().unwrap());
        assert_eq!(r.metadata.response_code, ResponseCode::NotImp);
        assert_eq!(r.metadata.op_code, OpCode::Notify);
        assert!(q.is_none());
    }

    #[test]
    fn edns_and_trailing_records_are_ignored_not_parsed() {
        let mut n = Names::default();
        let mut msg = query(6, "c2.example.", RecordType::A);
        // Claims 65535 answers it doesn't have: those are never read, so
        // the claim allocates nothing.
        msg[6..8].copy_from_slice(&[0xff, 0xff]);
        let (m, _) = ask(&mut n, &msg);
        assert_eq!(a(&m), [Ipv4Addr::new(198, 18, 0, 1)]);
    }

    #[test]
    fn the_longest_name_still_fits_a_plain_udp_reply() {
        let mut n = Names::default();
        // 255 bytes on the wire, every byte escaped when written out.
        let labels: Vec<Vec<u8>> = vec![
            vec![0xff; 63],
            vec![0xff; 63],
            vec![0xff; 63],
            vec![0xff; 61],
        ];
        let name = Name::from_labels(labels).unwrap();
        let mut m = Message::new(1, MessageType::Query, OpCode::Query);
        m.add_query(Query::query(name, RecordType::A));
        let (r, q) = ask(&mut n, &m.to_vec().unwrap());
        assert_eq!(r.answers.len(), 1);
        assert_eq!(q.unwrap().name.len(), 250 * 4 + 3);
    }
}
