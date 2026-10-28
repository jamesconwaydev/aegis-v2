# ClusterFuzzLite builds the fuzz targets in this image. Pinned by digest:
# the v1 tag of 2026-10-12.
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f
COPY . $SRC/aegis-v2
WORKDIR $SRC/aegis-v2
COPY .clusterfuzzlite/build.sh $SRC/
