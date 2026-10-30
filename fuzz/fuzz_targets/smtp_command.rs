// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's SMTP: each line of a client's bytes into the command,
//! base64 and AUTH PLAIN parsers, and all of them into the end-of-message
//! finder, whole and in two.
#![no_main]

use aegis_honeypot::smtp::{base64, command, plain, Cmd, Dot, MAX_LINE};
use libfuzzer_sys::fuzz_target;

/// What a message keeps of `parts` fed in turn, and where it ended.
fn read(parts: &[&[u8]]) -> (Vec<u8>, Option<usize>) {
    let mut d = Dot::default();
    let (mut kept, mut at) = (Vec::new(), 0);
    for p in parts {
        if let Some(n) = d.feed(p, &mut |b| kept.extend_from_slice(b)) {
            return (kept, Some(at + n));
        }
        at += p.len();
    }
    (kept, None)
}

fuzz_target!(|data: &[u8]| {
    for line in data.split(|&c| c == b'\n') {
        let line = &line[..line.len().min(MAX_LINE)];
        match command(line) {
            Cmd::Rcpt(Some(a)) => assert!(!a.is_empty() && a.len() < line.len()),
            Cmd::Helo(a) | Cmd::Ehlo(a) | Cmd::Mail(Some(a)) | Cmd::Auth(a, _) => {
                assert!(a.len() < line.len())
            }
            _ => {}
        }
        if let Some(d) = base64(line) {
            assert_eq!(d.len(), line.len() / 4 * 3 - line.iter().filter(|&&c| c == b'=').count());
            if let Some((u, p)) = plain(&d) {
                assert!(!u.contains(&0) && !p.contains(&0));
            }
        }
    }
    let (kept, end) = read(&[data]);
    // Never more kept than read, and a dot gone from every stuffed line.
    assert!(kept.len() <= end.unwrap_or(data.len()));
    let cut = match data {
        [a, b, ..] => usize::from(u16::from_le_bytes([*a, *b])) % (data.len() + 1),
        _ => data.len() / 2,
    };
    let (a, b) = data.split_at(cut);
    assert_eq!(read(&[a, b]), (kept, end));
});
