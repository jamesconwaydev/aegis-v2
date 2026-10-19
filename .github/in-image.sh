#!/bin/sh
# Runs a command in the x86_64 build image, with the checkout at /src and
# the runner's cargo registry and target dir mounted so rust-cache can
# keep them. The container runs as root, so it hands target/ and the
# registry back to the runner user before exiting. The chown runs
# whether the command passed or failed, and the script exits with the
# command's status, not chown's, so a failing check still fails the step.
set -eu
mkdir -p "$HOME/.cargo/registry" "$HOME/.cargo/git" target
exec docker run --rm -v "$PWD:/src" -w /src \
    -v "$HOME/.cargo/registry:/usr/local/cargo/registry" \
    -v "$HOME/.cargo/git:/usr/local/cargo/git" \
    aegis-build:rocky10-x86_64 \
    sh -c "$1"'
s=$?
chown -R '"$(id -u):$(id -g)"' /src/target /usr/local/cargo/registry /usr/local/cargo/git
exit $s'
