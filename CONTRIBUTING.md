# Contributing to Aegis

Thanks for wanting to help. This page covers what we need from a pull request
and how to get one merged without a long back-and-forth.

## Building

Aegis builds inside a Rocky Linux 10 container, so everyone compiles against
the same toolchain and kernel headers as the people running it. The wrapper for
that is `cargo xtask`, and it isn't in the repo yet. It arrives in a later PR.
The planned entry points are:

- `cargo xtask build` to build everything in the container
- `cargo xtask rpm` to produce the RPM
- `cargo xtask e2e` to run the end-to-end tests

Until they land there's nothing to build, so there's nothing to get wrong. This
page will be updated when they do.

## Pull requests

`main` is protected. Nothing is pushed to it directly; every change goes
through a pull request and is squash-merged, so the PR title becomes the commit
message on `main`.

1. Fork the repo (or branch, if you have access) and make your change.
2. Open a pull request and fill in the template.
3. Wait for review. We'll answer as soon as we can.

Keep PRs small and about one thing. A reviewer can say yes to a 100-line change
this afternoon; a 1,500-line one sits.

## Commit messages and PR titles

We use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
`fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, with an optional scope
such as `fix(ebpf):`. Keep the subject to 72 characters, say what was wrong or
what is new rather than "update stuff", and wrap the body at 72.

## Before you push

Run these. CI runs them too, and they're quicker on your machine.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

New behaviour needs a test. A bug fix needs one that fails without the fix.
If you changed something a user would notice, add a line to `CHANGELOG.md`
under `[Unreleased]`.

Say in the PR how you tested on Rocky 10: container, VM or bare metal, and
which kernel. eBPF code in particular can behave differently between kernels.

## Licensing and headers

Userspace code is licensed `MIT OR Apache-2.0`. The future `aegis-ebpf` crate is
`GPL-2.0-only`, because the kernel requires it for eBPF programs. By
contributing, you agree your work is licensed under the terms of the part of
the project you changed. There's no DCO sign-off and no CLA.

Every `.rs` file starts with an SPDX header. For userspace:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
```

and for `aegis-ebpf`:

```rust
// SPDX-License-Identifier: GPL-2.0-only
```

## Reporting false positives

If Aegis quarantined something legitimate, we want to know. It's the most
useful bug report you can send. Open an issue with the **False positive**
form and include your Rocky and kernel versions, the Aegis version and mode, the
`aegisctl preflight` output and the incident JSON. Scrub anything sensitive
from the JSON first. The form lists everything we ask for.

A missed detection goes in the **Detection report** form instead.

## Security problems

Don't file those as issues. See [SECURITY.md](SECURITY.md) for private
reporting.

## Conduct

Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
