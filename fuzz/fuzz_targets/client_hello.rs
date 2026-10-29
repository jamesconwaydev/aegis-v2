// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's TLS: a client's first bytes into the ClientHello
//! parser and JA4.
#![no_main]

use aegis_honeypot::hello::{parse, Parsed};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Parsed::Hello(h) = parse(data) {
        // Always the same shape: t, version, d/i, two counts, ALPN, then
        // two 12-digit hashes.
        let parts: Vec<&str> = h.ja4.split('_').collect();
        assert_eq!(parts.len(), 3, "{}", h.ja4);
        assert_eq!(parts[0].len(), 10, "{}", h.ja4);
        assert!(parts[0].bytes().all(|b| b.is_ascii_alphanumeric()), "{}", h.ja4);
        for p in &parts[1..] {
            assert_eq!(p.len(), 12, "{}", h.ja4);
            assert!(p.bytes().all(|b| b.is_ascii_hexdigit()), "{}", h.ja4);
        }
        if let Some(sni) = h.sni {
            assert!(!sni.chars().any(char::is_control), "{sni:?}");
        }
    }
});
