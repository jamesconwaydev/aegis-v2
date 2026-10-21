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
build is about 15 seconds on aarch64 and a minute on emulated x86_64.

You don't have to remember to rebuild the image when the Containerfile
changes. Each image carries a hash of the Containerfile it was built from,
and xtask rebuilds when that no longer matches. To force a fresh one anyway:

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

## Packaging

```sh
cargo xtask rpm --arch x86_64
```

That's a release build, then rpmbuild, both in the container. You get
two RPMs in `dist/rpm/`: `aegis-v2-0.1.1-1.el10.x86_64.rpm` and the
noarch `aegis-v2-selinux-0.1.1-1.el10.noarch.rpm`. The spec is
`packaging/aegis-v2.spec`, the unit is `packaging/aegisd.service`, and
the policy module lives in `selinux/`.

Every crate compiled into the binaries ships its licence text in
`/usr/share/licenses/aegis-v2/THIRD-PARTY-LICENSES`. cargo-about writes
that file during the build, from `packaging/about.toml`. The spec's
`License:` tag lists the same licences by hand, so when `Cargo.lock`
brings in a new one, update the tag; the comment above it has the
command that lists them.

Test a policy change on an enforcing x86_64 host, not under Lima. Install
both RPMs, start the daemon, put it through its paces, then look for
denials:

```sh
dnf install ./*.rpm
systemctl enable --now aegisd
ps -eZ | grep aegisd            # should say aegisd_t
ausearch -m AVC -ts recent      # should say <no matches>
```

`semodule -DB` turns off the policy's dontaudit rules while you hunt
for a denial that's hiding; `semodule -B` turns them back on. Never
commit a `permissive aegisd_t;` line.

## End-to-end tests

`cargo xtask e2e` checks the whole thing on a real Rocky 10 host. It
builds the RPMs and the `aegis-sim` attack simulator for the host's
architecture (on your machine, never on the host), installs them over
SSH, runs every scenario in `tests/e2e/scenarios.toml`, and checks what
aegisd recorded.

```sh
cargo xtask e2e --host root@203.0.113.10 --key ~/.ssh/test-host
```

For the Lima VM, export its SSH config and run as the login user with
sudo:

```sh
limactl show-ssh --format=config aegis-rocky10 > lima.ssh
cargo xtask e2e --host lima-aegis-rocky10 --ssh-config lima.ssh --sudo
```

Use a disposable host, and mark it as one first:

```sh
ssh root@203.0.113.10 touch /etc/aegis-e2e-host
```

The harness refuses a host without `/etc/aegis-e2e-host` unless you pass
`--yes-wipe`, because it reinstalls aegis-v2, deletes
`/var/lib/aegis-v2` between scenarios, installs `gdb`, `podman`,
`python3-pip` and `strace` if they're missing, and turns SELinux
enforcing for the run. Afterwards
it removes the packages it added, the aegis RPMs and
`/var/lib/aegis-v2`, and puts SELinux back how it found it. `--keep`
leaves everything installed.

Each scenario runs over a fresh SSH connection, with the incident store
cleared first. It passes when:

- its command exits 0,
- `aegisctl incidents list --json` shows exactly what `expect` says:
  `none`, or one incident with `would_throttle` or `would_quarantine`,
- no SELinux denial mentioning aegis was logged (an `ausearch` failure
  other than `<no matches>` fails the check), and
- `/etc` hashes the same before and after, since v0.1 must never change
  the host.

"No incident" has to hold for 8 seconds, past aegisd's 6-second hold on
signals, and an expected incident has 15 seconds to appear.

There are twelve scenarios: five attack simulations (`tmp-dropper`,
`memfd-exec`, `ptrace-daemon`, `port-scan`, `chain`), five benign
workloads that must not trip anything (`dnf-install`, `gdb-attach`,
`pip-download`, `podman-run`, `ssh-login`), and a pair for the
injection check. `preload-memfd` pins `aegis-sim`, lists it as a memfd
caller, and runs it with `LD_PRELOAD`, which must still quarantine;
`pinned-memfd` does the same without the preload, which must not.

Adding a scenario means adding a `[[scenario]]` with a `name`, a shell
`run` command and an `expect`.
`aegis-sim --help` lists the simulators.

## Licences and CI

`deny.toml` says which licences a dependency may carry, and the list is
permissive only. A new crate under anything else fails `cargo deny
check` until someone reads its licence and adds it, to `deny.toml` and
to `packaging/about.toml` alike. `aegis-ebpf` is the one GPL-2.0-only
exception: it runs in the kernel, and no userspace binary links it.

Every pull request runs seven checks, and main won't take a merge
until all of them pass: `fmt`, `clippy`, `test`, `deny`, `ebpf-build`,
`rpm` and `docs`. A change that only touches `docs/` or Markdown skips
the Rust jobs, and a skipped job counts as passing. If the step that
decides breaks, every job runs. Pushing again
cancels the run it replaces, and every job has a timeout, so nothing
runs on after it's useful.

Pushing a `v*.*.*` tag builds the x86_64 and aarch64 RPMs and publishes
a GitHub release with a `SHA256SUMS` file. The notes come from that
version's section of `CHANGELOG.md`, so write it before you tag. With
no section, the release fails before anything builds. The tag has to
match the version in `Cargo.toml` and point at a commit on main. The
RPM takes its version from `Cargo.toml` too, so bumping a release means
`Cargo.toml`, a new `%changelog` entry in the spec, and the CHANGELOG
section.

To try all of that without publishing, run the Release workflow by hand
from the Actions tab (or `gh workflow run release.yml`). It runs every
check and builds both RPMs, and stops short of the release.

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
