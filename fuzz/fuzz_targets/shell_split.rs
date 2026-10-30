// SPDX-License-Identifier: MIT OR Apache-2.0
//! The honeypot's fake shell: a typed line into the splitter, then run.
#![no_main]

use aegis_honeypot::shell::{run, split, Host, MAX_OUT};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let line = String::from_utf8_lossy(data);
    let cmds = split(&line);
    // Every command is a trimmed, non-empty piece of the line, and each
    // takes at least a byte and a separator.
    for (c, _) in &cmds {
        assert!(!c.is_empty() && c.trim() == *c, "{c:?}");
        assert!(line.contains(c));
    }
    assert!(cmds.len() <= line.len() / 2 + 1);
    let host = Host {
        name: "web1".into(),
        release: "6.12.0".into(),
        version: "#1 SMP".into(),
        arch: "x86_64".into(),
    };
    let mut seen = Vec::new();
    let r = run(&line, &host, |c| seen.push(c.to_string()));
    assert!(r.out.len() <= MAX_OUT);
    // Run sees the same commands, stopping early only at an exit.
    let want: Vec<&str> = cmds.iter().map(|(c, _)| *c).collect();
    assert!(want.starts_with(&seen.iter().map(String::as_str).collect::<Vec<_>>()));
    assert!(r.exit || seen.len() == want.len());
});
