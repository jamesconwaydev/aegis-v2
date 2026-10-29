// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's peek: the first bytes a client sends on a port with
//! no protocol of its own choose its handler.
#![no_main]

use aegis_honeypot::dispatch::{by_bytes, by_port, PEEK};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let port = u16::from_be_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ]);
    by_port(port);
    let first = data.get(2..).unwrap_or_default();
    // PEEK has to cover the longest signature, or a client that sends
    // more than the peek reads would be answered as something else.
    assert_eq!(by_bytes(&first[..first.len().min(PEEK)]), by_bytes(first));
});
