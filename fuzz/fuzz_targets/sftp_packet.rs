// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's SFTP: a client's bytes, whole and in two pieces.
#![no_main]

use aegis_honeypot::upload::{Event, Sftp, MAX_REPLY};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, PartialEq)]
enum Ev {
    Start(Vec<u8>),
    Data(u64, Vec<u8>),
    End,
}

fn feed(pieces: &[&[u8]]) -> (Vec<u8>, bool, Vec<Ev>) {
    let (mut p, mut out, mut evs) = (Sftp::default(), Vec::new(), Vec::new());
    let mut ok = true;
    for piece in pieces {
        let r = p.feed(piece, &mut out, &mut |e| {
            evs.push(match e {
                Event::Start(n, size) => {
                    assert_eq!(size, None);
                    Ev::Start(n.to_vec())
                }
                Event::Data(at, d) => Ev::Data(at, d.to_vec()),
                Event::End => Ev::End,
            })
        });
        if r.is_err() {
            ok = false;
            break;
        }
    }
    (out, ok, evs)
}

fuzz_target!(|data: &[u8]| {
    let whole = feed(&[data]);
    // One read's replies stop at the cap, give or take the last one,
    // which at most echoes a 4 KiB path twice.
    assert!(whole.0.len() <= MAX_REPLY + 9 * 1024, "{}", whole.0.len());
    // Replies are whole packets.
    let mut out = &whole.0[..];
    while let Some(len) = out.get(..4) {
        let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
        assert!((5..=9 * 1024).contains(&len), "{len}");
        out = &out[4 + len..];
    }
    assert!(out.is_empty());
    // Files open and close in turn.
    let mut open = false;
    for e in &whole.2 {
        match e {
            Ev::Start(_) => assert!(!std::mem::replace(&mut open, true)),
            Ev::Data(..) => assert!(open),
            Ev::End => assert!(std::mem::replace(&mut open, false)),
        }
    }
    let cut = data.first().map_or(0, |&b| usize::from(b)) % (data.len() + 1);
    let split = feed(&[&data[..cut], &data[cut..]]);
    // A packet that's refused may leave the others answered or not, as
    // they fell; otherwise the same.
    if whole.1 && split.1 {
        assert_eq!(split, whole);
    }
});
