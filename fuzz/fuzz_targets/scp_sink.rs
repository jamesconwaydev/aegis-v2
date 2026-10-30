// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's scp sink: a client's bytes, whole and in two pieces.
#![no_main]

use aegis_honeypot::upload::{Event, Scp, MAX_LINE};
use libfuzzer_sys::fuzz_target;

/// Replies, the result, and each file as (name, bytes at their offsets,
/// ended).
type Seen = (Vec<u8>, bool, Vec<(Vec<u8>, Vec<u8>, bool)>);

fn feed(pieces: &[&[u8]]) -> Seen {
    let (mut p, mut out, mut files) = (Scp::default(), Vec::new(), Vec::new());
    let mut ok = true;
    for piece in pieces {
        let r = p.feed(piece, &mut out, &mut |e| match e {
            Event::Start(n) => {
                assert!(!n.is_empty() && n.len() < MAX_LINE);
                files.push((n.to_vec(), Vec::new(), false));
            }
            Event::Data(at, d) => {
                let f: &mut (Vec<u8>, Vec<u8>, bool) = files.last_mut().expect("data before a file");
                assert!(!f.2, "data after the end");
                assert_eq!(at, f.1.len() as u64);
                f.1.extend_from_slice(d);
            }
            Event::End => files.last_mut().expect("end before a file").2 = true,
        });
        if r.is_err() {
            ok = false;
            break;
        }
    }
    (out, ok, files)
}

fuzz_target!(|data: &[u8]| {
    let whole = feed(&[data]);
    assert!(whole.0.iter().all(|&b| b == 0));
    let data_in: usize = whole.2.iter().map(|f| f.1.len()).sum();
    assert!(data_in <= data.len());
    // However the bytes arrive, the same files and replies.
    let cut = data.first().map_or(0, |&b| usize::from(b)) % (data.len() + 1);
    assert_eq!(feed(&[&data[..cut], &data[cut..]]), whole);
});
