# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Relicensed: userspace code is `MIT OR Apache-2.0`, and the future
  `aegis-ebpf` crate is `GPL-2.0-only`.

### Added

- Cargo workspace (`aegis-common`, `aegis-ebpf`, `aegisd`, `aegisctl`) and
  a Rocky Linux 10 build container driven by `cargo xtask build`.
- eBPF probes for exec, fork, exit, ptrace attach, memfd_create and
  outbound TCP connects, streamed to aegisd over a ring buffer. A hidden
  `aegisd --dump-events` flag prints them as JSON lines.
- A risk score for every process, halving every 30 seconds of quiet. A
  run from a temp directory, a memfd, a ptrace attach to a system daemon
  or a burst of outbound connects each adds to it. When dnf, gdb or nmap
  does what they're for, and the binary verifies, it adds nothing.
  Nothing acts on the score yet.
- Contributor scaffolding: issue forms, pull request template, security
  policy, code of conduct and contributing guide.
