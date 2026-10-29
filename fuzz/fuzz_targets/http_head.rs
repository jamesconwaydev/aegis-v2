// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's HTTP: a client's bytes into the head parser, and each
//! line of them into the chunk-size parser.
#![no_main]

use aegis_honeypot::http::{chunk_size, head, image, Parsed, MAX_HEAD, MAX_HEADERS};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let whole = head(data, 0);
    // Read in two pieces, as a client's bytes arrive, the answer is the
    // same.
    // Anywhere in the head, not just the first 256 bytes.
    let cut = match data {
        [a, b, ..] => usize::from(u16::from_le_bytes([*a, *b])) % (data.len() + 1),
        _ => data.len() / 2,
    };
    if head(&data[..cut], 0) == Parsed::More {
        assert_eq!(head(data, cut.saturating_sub(3)), whole);
    }
    match whole {
        Parsed::Done(h) => {
            assert!(h.len <= data.len().min(MAX_HEAD));
            let r = &h.request;
            assert!(r.headers.len() <= MAX_HEADERS);
            assert!(!r.method.is_empty() && !r.path.is_empty());
            for s in [&r.method, &r.path].into_iter().chain(&r.headers) {
                assert!(!s.chars().any(char::is_control), "{s:?}");
            }
            let _ = image(&r.path);
        }
        Parsed::More => assert!(data.len() < MAX_HEAD),
        Parsed::Bad => {}
    }
    for line in data.split(|&c| c == b'\n') {
        if let Some(n) = chunk_size(line) {
            // Read back exactly as written, extensions aside.
            let hex = line.split(|&c| c == b';').next().unwrap().trim_ascii();
            assert_eq!(u64::from_str_radix(std::str::from_utf8(hex).unwrap(), 16), Ok(n));
        }
    }
});
