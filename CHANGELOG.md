# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-21

Two fixes the new lab demo caught in the evidence v0.1.0 writes.

### Fixed

- A process that joined an incident at an exec was listed under the
  binary it was before the exec. The lab's copy of strace showed up as
  `/usr/bin/timeout`. Members are now recorded as the image they run;
  the evidence already named the right file.
- Evidence recorded each signal as a Rust debug string, such as
  `PtraceSystemDaemon { target: ProcKey { tgid: 1641528, start_time_ns: … } }`.
  The `signal` field now holds the signal's weight key (`tmp_exec`,
  `memfd_create`, `memfd_exec`, `ptrace_system_daemon`, `egress_scan`),
  and the attached pid or the scan's target count moves into the
  reason. Anything that parses `incident.json` or `timeline.jsonl`
  should expect the new names; incidents already on disk keep the old
  ones.

## [0.1.0] - 2026-10-19

The first release, and it watches without touching. Install it, run it in
audit mode for a few days, and read what it would have done. Nothing on
the host is stopped, moved or rewritten yet; that starts in v0.2.0.

### Added

- eBPF probes for every committed exec, fork and exit, successful ptrace
  attaches, memfd_create and outbound TCP connects. The exec probe reports
  the file the kernel actually ran, so a script in `/tmp` shows up as the
  script, not as `/bin/sh`, and a memfd or tmpfs binary is flagged however
  it was reached.
- A risk score for every process that halves after 30 seconds of quiet.
  Running from a temp directory adds 25, creating a memfd 20, running one
  65, attaching to a system daemon 45, and a burst of outbound connects 40.
  Repeats of the same kind don't stack. Cross 50 and you get a
  `would_throttle` incident; cross 80 and it's `would_quarantine`.
- Incidents that follow the attack, not the PID. Once one process crosses
  the line, its children join the same incident, and the incident is
  judged on everything they did between them.
- Allowlists that can't be satisfied by a name. dnf, gdb, nmap, runc and
  friends are forgiven only when the binary is owned by an installed
  package, matches the package's SHA-256, and is the same inode the kernel
  executed. A process loaded with `LD_PRELOAD`, `LD_AUDIT` or
  `LD_LIBRARY_PATH`, or one that has been ptrace-attached, gets no
  forgiveness at all.
- Incidents on disk under `/var/lib/aegis-v2/incidents`, written
  atomically, with a timeline of each decision and every process involved.
- Telemetry to journald, a JSON-lines file and OTLP logs over http or
  https with auth headers. A slow collector costs you records, never
  detection.
- `aegisctl status`, `preflight` and `incidents list | show | timeline`,
  all with `--json`. Text pulled from an incident is escaped before it
  reaches your terminal.
- RPMs for x86_64 and aarch64: a hardened systemd unit with five
  capabilities, and an SELinux module that confines aegisd to its own
  `aegisd_t` domain. It runs in enforcing mode with no denials across the
  end-to-end suite. OTLP needs `setsebool -P aegisd_can_network_connect 1`.
- `cargo xtask e2e`, which installs the RPMs on a disposable test host and
  runs twelve attack and everyday-admin scenarios, including a container
  start and an ssh login that must stay quiet.
- CI on every pull request, a licence and advisory audit, and a tag-driven
  release that builds both architectures and publishes checksums.
- A README and a full set of docs, including a threat model that says
  plainly what v0.1.0 can and can't see.

### Known limits

- Audit mode only. `mode = "enforce"` is refused at startup.
- The injection checks are best effort: a library can scrub its own
  environment, and a tracer that attaches before exec isn't seen. Capture
  in the kernel is planned for v0.2.0.
- UDP, and scans spread one connection per process, aren't detected.
- Binaries on btrfs subvolumes, overlay roots and inside containers stay
  unverified, so their allowlist entries don't apply.

The [threat model](docs/threat-model.md) has the full list.

[Unreleased]: https://github.com/jamesconwaydev/aegis-v2/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jamesconwaydev/aegis-v2/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jamesconwaydev/aegis-v2/releases/tag/v0.1.0
