// SPDX-License-Identifier: MIT OR Apache-2.0
//! A TLS client's ClientHello, read by hand: JA4 needs the extensions
//! as sent, GREASE and all, and rustls doesn't hand those out. Every
//! byte is the client's, so every length is checked against what's
//! there before it's believed.

use sha2::{Digest, Sha256};

/// The most of the client's opening the honeypot holds while it waits
/// for a whole ClientHello. Real ones, post-quantum key shares
/// included, are a few KiB.
pub const MAX: usize = 32 * 1024;

pub enum Parsed {
    /// Not all there yet.
    More,
    /// Not a ClientHello, or not one this reads.
    Bad,
    Hello(Hello),
}

#[derive(Debug, PartialEq)]
pub struct Hello {
    pub sni: Option<String>,
    /// The name was longer than `MAX_SNI` and is cut there.
    pub cut: bool,
    pub ja4: String,
}

/// The most of a server name kept: as long as a DNS name can be.
pub const MAX_SNI: usize = 255;

/// Printable text from client bytes, for the record: invalid UTF-8 and
/// control characters become U+FFFD, so nothing can forge a line break
/// in a log or a terminal later.
pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// The ClientHello at the start of `records`, the client's first bytes.
pub fn parse(records: &[u8]) -> Parsed {
    let mut msg = Vec::new();
    let mut r = records;
    loop {
        // A handshake message may be split over records (RFC 8446 5.1).
        if let Some(head) = msg.get(..4) {
            if head[0] != 1 {
                return Parsed::Bad;
            }
            let len = 4 + u32::from_be_bytes([0, head[1], head[2], head[3]]) as usize;
            if let Some(m) = msg.get(..len) {
                return hello(m).map_or(Parsed::Bad, Parsed::Hello);
            }
        }
        let Some(&[kind, major, _, hi, lo]) = r.get(..5) else {
            return Parsed::More;
        };
        if kind != 22 || major != 3 {
            return Parsed::Bad;
        }
        let end = 5 + usize::from(u16::from_be_bytes([hi, lo]));
        let Some(body) = r.get(5..end) else {
            return Parsed::More;
        };
        msg.extend_from_slice(body);
        r = &r[end..];
    }
}

/// Reads client bytes front to back; None past their end.
struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn vec8(&mut self) -> Option<R<'a>> {
        let n = self.take(1)?[0];
        self.take(n.into()).map(R)
    }
    fn vec16(&mut self) -> Option<R<'a>> {
        let n = self.u16()?;
        self.take(n.into()).map(R)
    }
    fn u16s(mut self) -> Option<Vec<u16>> {
        let mut v = Vec::new();
        while !self.0.is_empty() {
            v.push(self.u16()?);
        }
        Some(v)
    }
}

/// RFC 8701: 0x0a0a, 0x1a1a, ... 0xfafa, sent to keep servers honest.
fn grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// The first 12 hex digits of SHA-256, as JA4 hashes its lists.
fn hash12(list: &str) -> String {
    hex(&Sha256::digest(list)[..6])
}

fn list(v: &[u16]) -> String {
    let v: Vec<String> = v.iter().map(|x| format!("{x:04x}")).collect();
    v.join(",")
}

/// JA4's two ALPN characters, from the first protocol offered.
fn alpn(v: Option<&[u8]>) -> String {
    let Some((&f, &l)) = v.and_then(|v| v.first().zip(v.last())) else {
        return "00".into();
    };
    // Exactly as FoxIO's code (`first_last` in rust/ja4/src/tls.rs),
    // which ja4db's fingerprints come from: ASCII as it is, a 9 for
    // anything else. Neither their Rust nor Python has the spec text's
    // hex rule.
    let end = |b: u8| if b.is_ascii() { b as char } else { '9' };
    format!("{}{}", end(f), end(l))
}

/// A whole ClientHello handshake message (RFC 8446 4.1.2), to JA4 as
/// FoxIO specifies it (technical_details/JA4.md).
fn hello(msg: &[u8]) -> Option<Hello> {
    let mut r = R(msg);
    r.take(4)?;
    let legacy = r.u16()?;
    r.take(32)?;
    r.vec8()?;
    let ciphers = r.vec16()?.u16s()?;
    r.vec8()?;
    let (mut exts, mut name, mut proto, mut versions, mut sigs) =
        (Vec::new(), None, None, Vec::new(), Vec::new());
    // Hellos from before extensions end here.
    if !r.0.is_empty() {
        let mut e = r.vec16()?;
        while !e.0.is_empty() {
            let t = e.u16()?;
            let mut d = e.vec16()?;
            exts.push(t);
            // A broken body costs only its own detail: the type still
            // counts, so a client can't shed its fingerprint this way.
            let _: Option<()> = (|| {
                match t {
                    0x0000 => {
                        let mut names = d.vec16()?;
                        if names.take(1)? == [0] {
                            name = Some(names.vec16()?.0);
                        }
                    }
                    0x0010 => proto = d.vec16()?.vec8().map(|p| p.0),
                    0x000d => sigs = d.vec16()?.u16s()?,
                    0x002b => versions = d.vec8()?.u16s()?,
                    _ => {}
                }
                Some(())
            })();
        }
    }
    let keep = |v: Vec<u16>| -> Vec<u16> { v.into_iter().filter(|&x| !grease(x)).collect() };
    let (mut ciphers, mut exts, sigs) = (keep(ciphers), keep(exts), keep(sigs));
    let version = match keep(versions).into_iter().max().unwrap_or(legacy) {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    };
    let a = format!(
        "t{version}{}{:02}{:02}{}",
        if exts.contains(&0) { 'd' } else { 'i' },
        ciphers.len().min(99),
        exts.len().min(99),
        alpn(proto),
    );
    ciphers.sort_unstable();
    exts.retain(|&x| x != 0x0000 && x != 0x0010);
    exts.sort_unstable();
    let zeros = || "000000000000".to_string();
    let b = if ciphers.is_empty() {
        zeros()
    } else {
        hash12(&list(&ciphers))
    };
    let c = match (exts.is_empty(), sigs.is_empty()) {
        (true, _) => zeros(),
        (false, true) => hash12(&list(&exts)),
        (false, false) => hash12(&format!("{}_{}", list(&exts), list(&sigs))),
    };
    Some(Hello {
        sni: name.map(|n| text(&n[..n.len().min(MAX_SNI)])),
        cut: name.is_some_and(|n| n.len() > MAX_SNI),
        ja4: format!("{a}_{b}_{c}"),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hello(records: &[u8]) -> Hello {
        match parse(records) {
            Parsed::Hello(h) => h,
            Parsed::More => panic!("wants more"),
            Parsed::Bad => panic!("bad"),
        }
    }

    /// FoxIO's own captures and the JA4 their reference implementation
    /// gives for each: https://github.com/FoxIO-LLC/ja4, `pcap/<name>`
    /// and `rust/ja4/src/snapshots/ja4__insta@<name>.snap`. The files
    /// here are the client's ClientHello records cut from those
    /// captures, byte for byte.
    #[test]
    fn foxio_captures_give_foxio_fingerprints() {
        for (bytes, sni, ja4) in [
            (
                &include_bytes!("testdata/ja4/tls12.bin")[..],
                "contile.services.mozilla.com",
                "t13d1715h2_5b57614c22b0_3d5424432f57",
            ),
            (
                include_bytes!("testdata/ja4/tls-alpn-h2.bin"),
                "www.cloudflare.com",
                "t12d4605h2_85626a9a5f7f_aaf95bb78ec9",
            ),
            // The first ALPN is 0xba 0xad, which FoxIO's code makes "99".
            (
                include_bytes!("testdata/ja4/tls-non-ascii-alpn.bin"),
                "clientservices.googleapis.com",
                "t13d151699_8daaf6152771_e5627efa2ab1",
            ),
            // GREASE among the signature algorithms too.
            (
                include_bytes!("testdata/ja4/sigalg-grease.bin"),
                "optimizationguide-pa.googleapis.com",
                "t13d1517h2_8daaf6152771_cb7bf5808d99",
            ),
        ] {
            let h = hello(bytes);
            assert_eq!(h.sni.as_deref(), Some(sni));
            assert_eq!(h.ja4, ja4, "{sni}");
        }
    }

    /// The examples in FoxIO's JA4 spec, "ALPN Extension Value"
    /// (technical_details/JA4.md).
    #[test]
    fn alpn_goes_in_as_foxio_writes_it() {
        // `test_first_last` and `test_first_last_non_ascii` in FoxIO's
        // rust/ja4/src/tls.rs, with each U+FFFD there a byte that isn't
        // ASCII here; None there is "00" here.
        for (v, want) in [
            (&b""[..], "00"),
            (b"a", "aa"),
            (b"x", "xx"),
            (b"7", "77"),
            (b"ab", "ab"),
            (b"abc", "ac"),
            (&[0xff], "99"),
            (&[0xff, 0xff], "99"),
            (&[0xff, b'x', 0xff], "99"),
            (b"x\xff", "x9"),
            (b"\xffx", "9x"),
        ] {
            assert_eq!(alpn(Some(v)), want, "{v:?}");
        }
        assert_eq!(alpn(None), "00");
        // Their code has no hex path: ASCII goes in as it is, punctuation
        // included, where the spec text would write hex ("20", "21").
        for (v, want) in [
            (&b"h2"[..], "h2"),
            (b"http/1.1", "h1"),
            (b" ", "  "),
            (b" a", " a"),
            (b"a/", "a/"),
            (&[0x30, 0xab], "09"),
            (&[b' ', 0xab], " 9"),
        ] {
            assert_eq!(alpn(Some(v)), want, "{v:?}");
        }
    }

    /// `records`' one handshake message split across two records.
    fn split(records: &[u8], at: usize) -> Vec<u8> {
        let msg = &records[5..];
        let rec = |m: &[u8]| {
            let mut r = vec![22, 3, 1];
            r.extend((m.len() as u16).to_be_bytes());
            r.extend(m);
            r
        };
        [rec(&msg[..at]), rec(&msg[at..])].concat()
    }

    #[test]
    fn a_hello_over_several_records_is_put_back_together() {
        let one = include_bytes!("testdata/ja4/tls12.bin");
        for at in [1, 3, 4, 100, one.len() - 6] {
            assert_eq!(hello(&split(one, at)), hello(one), "{at}");
        }
    }

    #[test]
    fn a_hello_cut_short_wants_more_and_garbage_is_bad() {
        let one = include_bytes!("testdata/ja4/tls12.bin");
        for n in [0, 1, 5, 9, 100, one.len() - 1] {
            assert!(matches!(parse(&one[..n]), Parsed::More), "{n}");
        }
        // Not a handshake record, not a ClientHello, a lying length
        // inside, and an SSLv2 hello.
        let mut lying = one.to_vec();
        lying[5 + 4 + 2 + 32] = 0xff;
        for bad in [
            &b"GET / HTTP/1.1\r\n"[..],
            &[23, 3, 3, 0, 1, 0],
            &[22, 3, 1, 0, 4, 2, 0, 0, 0],
            &lying,
            &[0x80, 0x2e, 1, 3, 1],
        ] {
            assert!(matches!(parse(bad), Parsed::Bad), "{bad:?}");
        }
    }

    #[test]
    fn a_bare_hello_has_an_ip_fingerprint_and_zero_hashes() {
        let h = hello(&build(None));
        assert_eq!(h.sni, None);
        let b: String = Sha256::digest(b"002f")[..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(h.ja4, format!("t12i010000_{b}_000000000000"));
    }

    /// A TLS 1.2 hello with one cipher and these extensions (none at all
    /// for None), in one record.
    pub fn build(exts: Option<&[(u16, Vec<u8>)]>) -> Vec<u8> {
        let mut m = vec![1, 0, 0, 0, 3, 3];
        m.extend([0; 32]);
        m.extend([0, 0, 2, 0x00, 0x2f, 1, 0]);
        if let Some(exts) = exts {
            let mut e = Vec::new();
            for (t, d) in exts {
                e.extend(t.to_be_bytes());
                e.extend((d.len() as u16).to_be_bytes());
                e.extend(d);
            }
            m.extend((e.len() as u16).to_be_bytes());
            m.extend(e);
        }
        let len = (m.len() - 4) as u32;
        m[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        [&[22, 3, 1][..], &(m.len() as u16).to_be_bytes(), &m].concat()
    }

    pub fn sni(name: &[u8]) -> (u16, Vec<u8>) {
        let mut d = ((name.len() + 3) as u16).to_be_bytes().to_vec();
        d.push(0);
        d.extend((name.len() as u16).to_be_bytes());
        d.extend(name);
        (0, d)
    }

    #[test]
    fn a_long_server_name_is_cut_and_says_so() {
        let h = hello(&build(Some(&[sni(&[0xff; 30_000])])));
        assert!(h.cut);
        assert_eq!(h.sni.unwrap(), "\u{fffd}".repeat(MAX_SNI));
        assert!(h.ja4.starts_with("t12d0101"), "{}", h.ja4);
        let h = hello(&build(Some(&[sni(&[b'a'; MAX_SNI])])));
        assert!(!h.cut);
        assert_eq!(h.sni.unwrap().len(), MAX_SNI);
    }

    #[test]
    fn a_broken_extension_loses_only_its_own_detail() {
        let (_, good) = sni(b"c2.example");
        let whole = hello(&build(Some(&[(0, good.clone()), (0x0d, vec![0, 2, 4, 3])])));
        let broken = [
            // An empty SNI, an odd-length supported_versions, and a
            // signature algorithm list with a byte too many.
            (0, vec![]),
            (0x2b, vec![3, 3, 4, 3]),
            (0x0d, vec![0, 3, 4, 3, 1]),
        ];
        let h = hello(&build(Some(&broken)));
        assert_eq!(h.sni, None);
        // Still a domain, three extensions, and the legacy version.
        assert!(h.ja4.starts_with("t12d010300_"), "{}", h.ja4);
        assert!(whole.ja4.starts_with("t12d010200_"), "{}", whole.ja4);
    }

    #[test]
    fn text_keeps_nothing_that_could_forge_a_line() {
        assert_eq!(text(b"c2.example"), "c2.example");
        assert_eq!(
            text(b"a\r\nb\x1b[2J\xff"),
            "a\u{fffd}\u{fffd}b\u{fffd}[2J\u{fffd}"
        );
    }
}
