// SPDX-License-Identifier: MIT OR Apache-2.0
//! A filed `stream.pcap` as `incidents pcap` indexes it before merging:
//! root's file now, but the honeypot wrote every byte, so any bytes.
#![no_main]

use aegisd::filed::index;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut recs = Vec::new();
    if let Ok(n) = index(data, 0, 1 << 16, &mut recs) {
        // Accepted only whole: every byte is the header or a record.
        assert_eq!(24 + n, data.len() as u64);
        assert!(recs.len() <= 1 << 16);
    }
});
