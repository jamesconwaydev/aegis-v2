// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's DNS: a message from a tree under observation, over
//! UDP or TCP, into the parser and the reply builder.
#![no_main]

use std::net::Ipv4Addr;

use aegis_honeypot::dns::{answer, Names};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut names = Names::default();
    let incident = Ipv4Addr::new(127, 77, 0, 1);
    let first = answer(data, &mut names, incident);
    if let Some((reply, _)) = &first {
        // One question and at most one A record: always a plain UDP
        // reply, and always to the id that was asked.
        assert!(reply.len() <= 512, "{}", reply.len());
        assert_eq!(reply[..2], data[..2]);
    }
    // Asked again, told the same.
    assert_eq!(first, answer(data, &mut names, incident));
});
