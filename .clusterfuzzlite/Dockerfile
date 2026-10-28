# ClusterFuzzLite builds the fuzz targets in this image. Pinned by digest:
# the v1 tag of 2026-10-12.
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f

# The image's own nightly (2025-09-05) is older than the workspace's
# rust-version, so swap in the one fuzz/rust-toolchain.toml pins.
ENV RUSTUP_TOOLCHAIN=nightly-2026-10-19
RUN rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal --component rust-src

COPY . $SRC/aegis-v2
WORKDIR $SRC/aegis-v2
COPY .clusterfuzzlite/build.sh $SRC/
