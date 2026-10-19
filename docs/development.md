# Development

Aegis ships to Rocky Linux 10, so that's where it gets compiled. You don't need
a Rocky box for it, though. Every build runs inside a Rocky 10 container, and
your machine only has to supply two things: Rust (through
[rustup](https://rustup.rs)) and either podman or docker.

## Building

```sh
cargo xtask build --release                 # your machine's architecture
cargo xtask build --arch x86_64 --release   # the other one
```

The binaries land in `dist/<arch>/aegisd` and `dist/<arch>/aegisctl`. Drop
`--release` for a debug build.

The first run builds the image, which takes a few minutes. After that a clean
build is about 15 seconds on aarch64 and a minute on emulated x86_64. When you
want a fresh image, say because you bumped a pinned version in the
Containerfile, rebuild it:

```sh
cargo xtask container --arch aarch64
```

## Choosing podman or docker

xtask uses podman if it can find it, then docker. The one exception is
building the other architecture on a Mac, covered below. To pick one yourself:

```sh
export AEGIS_CONTAINER_ENGINE=docker
```

On macOS, check the podman machine's memory before anything else. It starts at
2 GiB, and a Rust build runs out long before that's enough. Give it 8:

```sh
podman machine stop
podman machine set --memory 8192 --cpus 8
podman machine start
```

## x86_64 on Apple Silicon

x86_64 builds run the x86_64 image under emulation (`--platform linux/amd64`).
Cross-compiling would be faster, but it needs an x86_64 glibc and gcc sysroot
in the image and a linker setup to match. Emulation needs none of that.

There's one catch. Podman's machine emulates with qemu, and rustc segfaults
under it (`qemu: uncaught target signal 11`). Docker Desktop runs x86_64
through Rosetta instead, and rustc is fine there.

So on a Mac, xtask picks docker first whenever `--arch` isn't your own
architecture. Force podman with `AEGIS_CONTAINER_ENGINE` and it warns you
before the crash.

On an x86_64 Linux host it's the other way round: x86_64 builds natively, and
aarch64 is the emulated one.

## What's in the image

`build/Containerfile` starts from Rocky 10.2, pinned by digest, and adds:

- gcc, clang and llvm, plus the RPM tooling (`rpm-build`,
  `selinux-policy-devel`, `systemd-rpm-macros`)
- Rust 1.99.1 with `rust-src`, clippy and rustfmt, for userspace
- Rust `nightly-2026-10-19` with `rust-src`, for the eBPF crate
- `bpf-linker` v0.12.0 from upstream's release binaries, checked against
  a sha256 committed in the Containerfile

Everything is pinned, so the image you build next month matches today's.
Moving a version is a deliberate edit:

- **Stable:** change `RUST_STABLE` and `rust-toolchain.toml` together.
- **Nightly:** change `AEGIS_EBPF_TOOLCHAIN`. `aegisd/build.rs` reads it and
  hands it to aya-build, and the build fails if it's unset.
- **bpf-linker:** change `BPF_LINKER` and both hashes. The release page lists
  each asset's sha256.

The nightly and bpf-linker have to agree on LLVM, so bump them together and
build both architectures before you push.

That last one comes as a binary because building it from source needs a system
LLVM matching the one inside rustc nightly, and Rocky doesn't ship it. The
release binary bundles the right LLVM.

## How the eBPF crate gets built

You never build `aegis-ebpf` directly. `aegisd/build.rs` hands it to
[`aya-build`](https://crates.io/crates/aya-build), which runs nightly cargo
with `-Z build-std=core` for the BPF target and leaves the object in
`OUT_DIR`. This is the wiring from
[aya-template](https://github.com/aya-rs/aya-template), with the crates
renamed.

It also means `cargo build` on a Mac fails in `aegisd`'s build script: there's
no `bpf-linker`, and nothing to load the result into anyway. Formatting works
on the host. Run clippy and the tests in the container:

```sh
podman run --rm -v "$PWD:/src:z" -w /src \
  -v aegis-cargo-aarch64:/usr/local/cargo/registry \
  -v aegis-target-aarch64:/target -e CARGO_TARGET_DIR=/target \
  aegis-build:rocky10-aarch64 \
  sh -c 'cargo clippy --all-targets -- -D warnings && cargo test'
```

## Running it on aarch64

aegisd only does anything on a kernel with BTF and the BPF LSM switched
on, and your Mac has neither. For aarch64 there's a Rocky 10 VM under
[Lima](https://lima-vm.io):

```sh
brew install lima
limactl create --name aegis-rocky10 --cpus 2 --memory 4 template:rocky-10
limactl start aegis-rocky10
```

Check the BPF LSM is active before you trust a result. `bpf` has to be in
the list:

```sh
limactl shell aegis-rocky10 cat /sys/kernel/security/lsm
```

Then build, copy the binary in, and run it as root:

```sh
cargo xtask build --release
limactl copy dist/aarch64/aegisd aegis-rocky10:/tmp/aegisd
limactl shell aegis-rocky10 sudo /tmp/aegisd --dump-events
```

`--dump-events` is a hidden debug flag. It prints every probe event as a
JSON line until you press Ctrl-C, then reports how many the ring buffer
dropped.

One difference from a real Rocky box: Lima's image boots with SELinux
permissive, so a policy denial won't show up here. Test anything
SELinux-sensitive on an enforcing x86_64 host as well.

`limactl stop aegis-rocky10` when you're done; `limactl delete` throws
it away.

## How the probes find kernel fields

The eBPF crate reads a handful of kernel struct fields, such as
`task_struct.real_parent` and `linux_binprm.file`. Their offsets move
between kernel builds and between architectures, and Rust has no CO-RE
to relocate them. So nothing is baked in: at startup aegisd reads the
offsets from `/sys/kernel/btf/vmlinux` and patches them into the
object's `OFFSETS` global before loading it. Adding a field means adding
it to `KernelOffsets` in `aegis-common` and looking it up in
`aegisd/src/ebpf.rs`.

## Caches

Two named volumes per architecture keep rebuilds quick:

- `aegis-cargo-<arch>` holds the crate registry
- `aegis-target-<arch>` holds the target directory

The target directory sits in a volume rather than in `./target` because a bind
mount through the macOS VM is slow, and it would mix Linux artifacts with your
host's. If a build gets into a strange state, delete both and start over:

```sh
podman volume rm aegis-cargo-aarch64 aegis-target-aarch64
```

## Minimum Rust version

The workspace pins `rust-version = "1.98"`, because `aya-build` 0.2.1 won't
build on anything older. Raise it when a dependency does.

## Who owns dist/

The container runs as root. With podman, or Docker Desktop on a Mac, that root
maps back to you and `dist/` is yours. Rootful docker on Linux maps nothing, so
`dist/<arch>/` comes out owned by root. Use podman there, or take it back
after a build:

```sh
sudo chown -R "$(id -u):$(id -g)" dist
```
