// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's DNS: a message from a tree under observation, over
//! UDP or TCP, into the parser and the reply builder.
#![no_main]

use std::net::Ipv4Addr;
use std::time::Instant;

use aegis_honeypot::dns::{answer, question, Names};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut names = Names::default();
    let incident = Ipv4Addr::new(127, 77, 0, 1);
    let now = Instant::now();
    let first = answer(data, &mut names, incident, now);
    if let Some((reply, _)) = &first {
        // One question and at most one A record: always a plain UDP
        // reply, and always to the id that was asked.
        assert!(reply.len() <= 512, "{}", reply.len());
        assert_eq!(reply[..2], data[..2]);
        // An answer carries the one question it was asked, the same name
        // byte for byte, readable by the same rules it was read by.
        if reply[3] & 0x0f == 0 {
            assert_eq!(reply[4..6], [0, 1]);
            let asked = question(data).map(|(n, _)| n);
            assert!(asked.is_some());
            assert_eq!(question(reply).map(|(n, _)| n), asked);
        }
    }
    // Asked again, told the same.
    assert_eq!(first, answer(data, &mut names, incident, now));
});
