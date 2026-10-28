// SPDX-License-Identifier: MIT OR Apache-2.0
//! `/etc/aegis-v2/config.toml` and one allowlist drop-in, loaded the way
//! aegisd loads them at start and on reload: parse, validators, spans.
#![no_main]

use std::fs;
use std::sync::LazyLock;

use aegisd::config::Config;
use libfuzzer_sys::fuzz_target;

static DIR: LazyLock<std::path::PathBuf> = LazyLock::new(|| {
    let d = aegis_fuzz::scratch_dir("config");
    fs::create_dir_all(d.join("allowlist.d")).unwrap();
    d
});

fuzz_target!(|data: &[u8]| {
    // TOML can't hold a NUL, so one splits the main file from the drop-in.
    let (main, dropin) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], Some(&data[i + 1..])),
        None => (data, None),
    };
    let main_path = DIR.join("config.toml");
    let dropin_path = DIR.join("allowlist.d/50-fuzz.toml");
    fs::write(&main_path, main).unwrap();
    match dropin {
        Some(d) => fs::write(&dropin_path, d).unwrap(),
        None => {
            let _ = fs::remove_file(&dropin_path);
        }
    }
    if let Err(e) = Config::load_checked(&main_path, &DIR.join("allowlist.d")) {
        // The error names a line and column; building it walks the text.
        e.to_string();
    }
});
