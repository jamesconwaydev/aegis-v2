// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `/proc/<pid>` readers. A watched process can shape what these
//! files say: its comm sits inside `stat`, and it writes its own
//! environment.
#![no_main]

use aegisd::enforce::systemd::in_unit;
use aegisd::pipeline::parse_stat;
use aegisd::proctable::env_taint;
use aegisd::scoring::is_service_cgroup;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    env_taint(Some(data));
    let text = String::from_utf8_lossy(data);
    // Any tick rate the kernel could report; sysconf is never below 1.
    let hz = u64::from(data.first().copied().unwrap_or(100).max(1));
    parse_stat(&text, hz);
    is_service_cgroup(&text);
    in_unit(&text, "aegis-quarantine-AEG-x.scope");
});
