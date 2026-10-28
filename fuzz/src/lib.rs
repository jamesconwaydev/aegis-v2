// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the targets share.

use std::fs;
use std::path::{Path, PathBuf};

/// A scratch directory for this process, `<tmp>/aegis-fuzz-<name>-<pid>`.
/// libFuzzer exits without running destructors, so instead of cleaning
/// up after itself this removes what earlier runs left: every
/// `aegis-fuzz-<name>-<pid>` whose process is gone.
pub fn scratch_dir(name: &str) -> PathBuf {
    let tmp = std::env::temp_dir();
    let prefix = format!("aegis-fuzz-{name}-");
    for e in fs::read_dir(&tmp).into_iter().flatten().flatten() {
        let n = e.file_name();
        let pid = n.to_str().and_then(|n| n.strip_prefix(&prefix));
        if pid.is_some_and(|p| !Path::new("/proc").join(p).exists()) {
            let _ = fs::remove_dir_all(e.path());
        }
    }
    let d = tmp.join(format!("{prefix}{}", std::process::id()));
    fs::create_dir_all(&d).unwrap();
    d
}
