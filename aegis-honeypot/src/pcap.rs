// SPDX-License-Identifier: MIT OR Apache-2.0
//! `stream.pcap`: what a session said, rebuilt as packets between the
//! client and where it meant to connect, so Wireshark and Zeek read it
//! like a capture. Classic pcap, LINKTYPE_RAW, real timestamps; the
//! segments are synthetic but their checksums are right, or tools flag
//! every packet.

use std::fs::File;
use std::io::{self, Write};
use std::net::SocketAddrV4;
use std::time::{SystemTime, UNIX_EPOCH};

const LINKTYPE_RAW: u32 = 101;
const TCP: u8 = 6;
const UDP: u8 = 17;
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;
/// Under a 1500-byte MTU, so a segment looks like one off the wire.
pub const SEGMENT: usize = 1400;
/// What one TCP segment adds on disk to its data: pcap record header,
/// IPv4 and TCP headers.
pub const SEGMENT_COST: u64 = 16 + 20 + 20;
/// What one UDP datagram adds on disk to its data: pcap record header,
/// IPv4 and UDP headers.
pub const DATAGRAM_COST: u64 = 16 + 20 + 8;
/// The most one IPv4 UDP datagram can carry; `datagram` cuts there.
pub const MAX_DATAGRAM: usize = 65535 - 28;
/// The file header, the handshake and the close: the same in every
/// session, and not charged to its cap.
pub const FIXED_COST: u64 = 24 + 6 * SEGMENT_COST;

pub struct Pcap {
    f: File,
    cli: SocketAddrV4,
    srv: SocketAddrV4,
    cseq: u32,
    sseq: u32,
    ip_id: u16,
}

impl Pcap {
    /// Writes the file header to `f`. Packets run between `cli` and `srv`.
    pub fn new(mut f: File, cli: SocketAddrV4, srv: SocketAddrV4) -> io::Result<Self> {
        let mut h = Vec::with_capacity(24);
        // Version 2.4 is two u16s, which this one LE word lays out.
        for w in [0xa1b2_c3d4u32, 0x0004_0002, 0, 0, 65535, LINKTYPE_RAW] {
            h.extend(w.to_le_bytes());
        }
        f.write_all(&h)?;
        Ok(Self {
            f,
            cli,
            srv,
            cseq: 0x1000_0000,
            sseq: 0x2000_0000,
            ip_id: 1,
        })
    }

    /// The three-way handshake.
    pub fn syn(&mut self) -> io::Result<()> {
        self.segment(true, SYN, &[])?;
        self.segment(false, SYN | ACK, &[])?;
        self.segment(true, ACK, &[])
    }

    /// `data` as TCP segments of at most 1400 bytes.
    pub fn data(&mut self, from_client: bool, data: &[u8]) -> io::Result<()> {
        data.chunks(SEGMENT)
            .try_for_each(|c| self.segment(from_client, PSH | ACK, c))
    }

    /// Both FINs and the last ACK.
    pub fn fin(&mut self) -> io::Result<()> {
        self.segment(true, FIN | ACK, &[])?;
        self.segment(false, FIN | ACK, &[])?;
        self.segment(true, ACK, &[])
    }

    /// One UDP datagram; DNS over UDP records through this.
    pub fn datagram(&mut self, from_client: bool, data: &[u8]) -> io::Result<()> {
        // What fits in one IPv4 packet; DNS never comes close.
        let data = &data[..data.len().min(MAX_DATAGRAM)];
        let (src, dst) = self.ends(from_client);
        let mut l4 = Vec::with_capacity(8 + data.len());
        l4.extend(src.port().to_be_bytes());
        l4.extend(dst.port().to_be_bytes());
        l4.extend((8 + data.len() as u16).to_be_bytes());
        l4.extend([0, 0]);
        l4.extend(data);
        self.packet(from_client, UDP, l4, 6)
    }

    fn ends(&self, from_client: bool) -> (SocketAddrV4, SocketAddrV4) {
        if from_client {
            (self.cli, self.srv)
        } else {
            (self.srv, self.cli)
        }
    }

    fn segment(&mut self, from_client: bool, flags: u8, data: &[u8]) -> io::Result<()> {
        let (src, dst) = self.ends(from_client);
        let (seq, ack) = if from_client {
            (self.cseq, self.sseq)
        } else {
            (self.sseq, self.cseq)
        };
        let ack = if flags & ACK != 0 { ack } else { 0 };
        let mut l4 = Vec::with_capacity(20 + data.len());
        l4.extend(src.port().to_be_bytes());
        l4.extend(dst.port().to_be_bytes());
        l4.extend(seq.to_be_bytes());
        l4.extend(ack.to_be_bytes());
        l4.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        l4.extend(data);
        self.packet(from_client, TCP, l4, 16)?;
        // SYN and FIN each take a sequence number of their own.
        let adv = data.len() as u32 + u32::from(flags & (SYN | FIN) != 0);
        let next = if from_client {
            &mut self.cseq
        } else {
            &mut self.sseq
        };
        *next = next.wrapping_add(adv);
        Ok(())
    }

    /// Wraps `l4` in an IPv4 header, fills in both checksums (the L4 one
    /// at `csum_at`) and writes the record.
    fn packet(
        &mut self,
        from_client: bool,
        proto: u8,
        mut l4: Vec<u8>,
        csum_at: usize,
    ) -> io::Result<()> {
        let (src, dst) = self.ends(from_client);
        let (s, d) = (src.ip().octets(), dst.ip().octets());
        let pseudo = sum(sum(sum(0, &s), &d), &[0, proto]) + l4.len() as u32;
        let mut c = fold(sum(pseudo, &l4));
        // An all-zero UDP checksum means "none"; the RFC sends it as ones.
        if proto == UDP && c == 0 {
            c = 0xffff;
        }
        l4[csum_at..csum_at + 2].copy_from_slice(&c.to_be_bytes());

        let len = (20 + l4.len()) as u16;
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&len.to_be_bytes());
        ip[4..6].copy_from_slice(&self.ip_id.to_be_bytes());
        ip[6] = 0x40; // don't fragment
        ip[8] = 64;
        ip[9] = proto;
        ip[12..16].copy_from_slice(&s);
        ip[16..20].copy_from_slice(&d);
        let c = fold(sum(0, &ip));
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        self.ip_id = self.ip_id.wrapping_add(1);

        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut rec = Vec::with_capacity(16 + usize::from(len));
        for w in [
            t.as_secs() as u32,
            t.subsec_micros(),
            len.into(),
            len.into(),
        ] {
            rec.extend(w.to_le_bytes());
        }
        rec.extend(ip);
        rec.extend(l4);
        self.f.write_all(&rec)
    }
}

/// Adds `b` to a one's-complement sum as big-endian 16-bit words.
fn sum(acc: u32, b: &[u8]) -> u32 {
    b.chunks(2).fold(acc, |a, c| {
        a + u32::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
    })
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sum(b: &[u8]) -> u32 {
        b.chunks(2)
            .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
            .sum()
    }

    fn ok(mut s: u32) -> bool {
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        s == 0xffff
    }

    /// One packet as read back: (src, dst, proto, tcp flags, seq, ack, data).
    #[derive(Debug)]
    pub struct Pkt {
        pub src: SocketAddrV4,
        pub dst: SocketAddrV4,
        pub proto: u8,
        pub flags: u8,
        pub seq: u32,
        pub ack: u32,
        pub data: Vec<u8>,
    }

    /// A minimal reader that checks every header and checksum on the way.
    pub fn read(b: &[u8]) -> Vec<Pkt> {
        assert_eq!(&b[..4], &0xa1b2c3d4u32.to_le_bytes());
        assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 101);
        let mut out = Vec::new();
        let mut p = &b[24..];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        while !p.is_empty() {
            let ts = u64::from(u32::from_le_bytes(p[..4].try_into().unwrap()));
            assert!(ts.abs_diff(now) < 60, "timestamp {ts} is not now");
            let usec = u32::from_le_bytes(p[4..8].try_into().unwrap());
            assert!(usec < 1_000_000);
            let incl = u32::from_le_bytes(p[8..12].try_into().unwrap()) as usize;
            let orig = u32::from_le_bytes(p[12..16].try_into().unwrap()) as usize;
            assert_eq!(incl, orig);
            let ip = &p[16..16 + incl];
            p = &p[16 + incl..];
            assert_eq!(ip[0], 0x45);
            assert_eq!(usize::from(u16::from_be_bytes([ip[2], ip[3]])), ip.len());
            assert!(ok(sum(&ip[..20])), "IPv4 header checksum");
            let (src, dst) = (
                Ipv4Addr::from(<[u8; 4]>::try_from(&ip[12..16]).unwrap()),
                Ipv4Addr::from(<[u8; 4]>::try_from(&ip[16..20]).unwrap()),
            );
            let l4 = &ip[20..];
            let pseudo = sum(&ip[12..20]) + u32::from(ip[9]) + l4.len() as u32;
            assert!(ok(pseudo + sum(l4)), "L4 checksum");
            let port = |i: usize| u16::from_be_bytes([l4[i], l4[i + 1]]);
            let word = |i: usize| u32::from_be_bytes(l4[i..i + 4].try_into().unwrap());
            let (flags, seq, ack, data) = match ip[9] {
                TCP => {
                    assert_eq!(l4[12], 0x50);
                    (l4[13], word(4), word(8), l4[20..].to_vec())
                }
                UDP => {
                    assert_eq!(usize::from(port(4)), l4.len());
                    (0, 0, 0, l4[8..].to_vec())
                }
                p => panic!("protocol {p}"),
            };
            out.push(Pkt {
                src: SocketAddrV4::new(src, port(0)),
                dst: SocketAddrV4::new(dst, port(2)),
                proto: ip[9],
                flags,
                seq,
                ack,
                data,
            });
        }
        out
    }

    fn file(name: &str) -> (std::path::PathBuf, File) {
        let p = std::env::temp_dir().join(format!("aegis-pcap-{}-{name}", std::process::id()));
        (p.clone(), File::create(&p).unwrap())
    }

    const CLI: &str = "10.0.0.2:40000";
    const SRV: &str = "1.2.3.4:6667";

    #[test]
    fn tcp_reads_back_as_one_clean_conversation() {
        let (path, f) = file("tcp");
        let (cli, srv) = (CLI.parse().unwrap(), SRV.parse().unwrap());
        let mut w = Pcap::new(f, cli, srv).unwrap();
        w.syn().unwrap();
        let up: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        w.data(true, &up).unwrap();
        w.data(false, b"hello").unwrap();
        // Odd length, so the checksum pads.
        w.data(true, b"abc").unwrap();
        w.fin().unwrap();
        drop(w);

        let pkts = read(&std::fs::read(&path).unwrap());
        let flags: Vec<u8> = pkts.iter().map(|p| p.flags).collect();
        let pa = PSH | ACK;
        assert_eq!(
            flags,
            [
                SYN,
                SYN | ACK,
                ACK,
                pa,
                pa,
                pa,
                pa,
                pa,
                FIN | ACK,
                FIN | ACK,
                ACK
            ]
        );
        let sizes: Vec<usize> = pkts.iter().map(|p| p.data.len()).collect();
        assert_eq!(sizes, [0, 0, 0, 1400, 1400, 200, 5, 3, 0, 0, 0]);
        for p in &pkts {
            assert_eq!(p.proto, TCP);
            let from_cli = p.src == cli;
            assert_eq!(if from_cli { p.dst } else { p.src }, srv);
        }
        // Each side's seq follows what it sent; each ack is what the
        // other side has sent so far.
        let (mut c, mut s) = (pkts[0].seq, pkts[1].seq);
        let (mut got_up, mut got_down) = (Vec::<u8>::new(), Vec::<u8>::new());
        for p in &pkts {
            let from_cli = p.src == cli;
            let (me, other) = if from_cli { (&mut c, s) } else { (&mut s, c) };
            assert_eq!(p.seq, *me, "{p:?}");
            if p.flags & ACK != 0 {
                assert_eq!(p.ack, other, "{p:?}");
            }
            let adv = p.data.len() as u32 + u32::from(p.flags & (SYN | FIN) != 0);
            *me = me.wrapping_add(adv);
            if from_cli { &mut got_up } else { &mut got_down }.extend(&p.data);
        }
        assert_eq!(got_up, [&up[..], b"abc"].concat());
        assert_eq!(got_down, b"hello");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn udp_datagrams_read_back_with_their_addresses() {
        let (path, f) = file("udp");
        let (cli, srv) = (CLI.parse().unwrap(), "8.8.8.8:53".parse().unwrap());
        let mut w = Pcap::new(f, cli, srv).unwrap();
        w.datagram(true, b"query").unwrap();
        w.datagram(false, b"answer!").unwrap();
        drop(w);
        let pkts = read(&std::fs::read(&path).unwrap());
        assert_eq!(pkts.len(), 2);
        assert_eq!((pkts[0].src, pkts[0].dst, pkts[0].proto), (cli, srv, UDP));
        assert_eq!((pkts[1].src, pkts[1].dst), (srv, cli));
        assert_eq!(pkts[0].data, b"query");
        assert_eq!(pkts[1].data, b"answer!");
        std::fs::remove_file(path).unwrap();
    }
}
