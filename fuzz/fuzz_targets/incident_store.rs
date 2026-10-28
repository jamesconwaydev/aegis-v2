// SPDX-License-Identifier: MIT OR Apache-2.0
//! An incident directory as aegisd finds it on start: `incident.json`
//! and `timeline.jsonl`, which a full disk, a crash mid-write or a root
//! user with an editor can leave in any state.
#![no_main]

use std::fs;
use std::sync::LazyLock;

use aegisd::incident::{IncidentId, IncidentStore};
use libfuzzer_sys::fuzz_target;

const ID: &str = "AEG-20261028-120000-0123456789abcdef";

static DIR: LazyLock<std::path::PathBuf> = LazyLock::new(|| {
    let d = std::env::temp_dir().join(format!("aegis-fuzz-incident-{}", std::process::id()));
    fs::create_dir_all(d.join(ID)).unwrap();
    d
});

fuzz_target!(|data: &[u8]| {
    // JSON can't hold a raw NUL: one splits incident.json from the
    // timeline.
    let (inc, timeline) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &b""[..]),
    };
    fs::write(DIR.join(ID).join("incident.json"), inc).unwrap();
    fs::write(DIR.join(ID).join("timeline.jsonl"), timeline).unwrap();
    // now 0 keeps every incident in the load window; the boot id matches
    // the seeds so the process index is built too.
    let store = IncidentStore::open_at(&DIR, Some("boot".into()), 0).unwrap();
    store.list();
    store.memberships();
    let id = IncidentId(ID.into());
    store.get(&id);
    store.timeline(&id);
});
