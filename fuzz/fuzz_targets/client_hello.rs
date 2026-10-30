// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's TLS: a client's first bytes into the ClientHello
//! parser and JA4.
#![no_main]

use aegis_honeypot::hello::{parse, Parsed};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Parsed::Hello(h) = parse(data) {
        // Always the same shape: t, version, d/i and two counts, two
        // ALPN characters (any ASCII, as FoxIO's code writes them, even
        // an underscore), then two 12-digit hashes.
        let j = h.ja4.as_bytes();
        assert_eq!(j.len(), 36, "{}", h.ja4);
        assert!(j[..8].iter().all(u8::is_ascii_alphanumeric), "{}", h.ja4);
        assert!(j[8..10].iter().all(u8::is_ascii), "{}", h.ja4);
        assert_eq!((j[10], j[23]), (b'_', b'_'), "{}", h.ja4);
        for p in [&j[11..23], &j[24..]] {
            assert!(p.iter().all(u8::is_ascii_hexdigit), "{}", h.ja4);
        }
        if let Some(sni) = h.sni {
            assert!(!sni.chars().any(char::is_control), "{sni:?}");
        }
    }
});
