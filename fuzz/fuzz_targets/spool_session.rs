// SPDX-License-Identifier: MIT OR Apache-2.0
//! A `session.json` as aegisd finds it in the honeypot's spool: written
//! by a user a compromised honeypot controls, so any bytes at all.
#![no_main]

use aegisd::spool::{event, parse, reason, MAX_JSON};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = parse(data) {
        assert!(data.len() as u64 <= MAX_JSON);
        // What a filed session puts on the timeline and in telemetry.
        let e = event(&s).to_string();
        let r = reason(&s);
        assert!(!r.chars().any(char::is_control), "{r:?}");
        assert!(r.len() < 2048 && e.len() < 4096);
    }
});
