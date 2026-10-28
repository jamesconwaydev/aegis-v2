#!/bin/bash -eu
# Builds every target in fuzz/ with the image's nightly and sanitizer
# flags, and hands each one its seeds.
#
# aegis-ebpf's build script only checks that bpf-linker is on PATH. A
# fuzz build never compiles the probes (aegisd/build.rs skips them under
# --cfg fuzzing), so any file of that name will do.
ln -sf /bin/true /usr/local/bin/bpf-linker

cd fuzz
cargo fuzz build -O --debug-assertions
bins=target/x86_64-unknown-linux-gnu/release
for t in $(cargo fuzz list); do
    cp "$bins/$t" "$OUT/"
    (cd "seeds/$t" && zip -q "$OUT/${t}_seed_corpus.zip" ./*)
done
