#!/bin/bash -eu
# Builds every target in fuzz/ with the sanitizer flags the image sets,
# and hands each one its seeds.

# The image's own nightly is older than the workspace's rust-version.
# Use the one fuzz/rust-toolchain.toml pins instead, so CI and local
# fuzzing build with the same compiler.
unset RUSTUP_TOOLCHAIN
cd fuzz
rustup toolchain install

# The same dependency versions the release builds with: cargo keeps
# everything in the root lock and adds only what the fuzz crate needs.
cp ../Cargo.lock .

# aegis-ebpf's build script only checks that bpf-linker is on PATH. A
# fuzz build never compiles the probes (aegisd/build.rs skips them under
# --cfg fuzzing), so any file of that name will do.
ln -sf /bin/true /usr/local/bin/bpf-linker

cargo fuzz build -O --debug-assertions
bins=target/x86_64-unknown-linux-gnu/release
for t in $(cargo fuzz list); do
    cp "$bins/$t" "$OUT/"
    (cd "seeds/$t" && zip -q "$OUT/${t}_seed_corpus.zip" ./*)
done
