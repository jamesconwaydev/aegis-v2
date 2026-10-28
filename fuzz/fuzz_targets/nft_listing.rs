// SPDX-License-Identifier: MIT OR Apache-2.0
//! What `nft` prints back: the rule handle from `--echo`, and the
//! handles in `nft -a list chain`. The cgroup paths in a listing come
//! from scope names, and anything nft prints is parsed.
#![no_main]

use aegisd::enforce::nft::Nft;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // Before the first NUL, the listing; after it, the cgroup path.
    let (listing, path) = text.split_once('\0').unwrap_or((&text, "a/b.scope"));
    Nft::echoed_handle(listing);
    Nft::unresolved(listing);
    Nft::handles(listing, path);
});
