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
- aegisd now runs as a daemon. Every probe event is scored, and a process
  that crosses the throttle line gets an incident on disk and a record in
  journald, plus JSON lines or OTLP if you've turned those on. Root can
  ask how it's doing over `/run/aegis-v2/aegisd.sock`: events seen,
  events the ring buffer lost, telemetry dropped, incidents open. It's
  still audit only, so nothing is stopped yet. SIGHUP reloads the config,
  and a bad file leaves the running one in place.
- systemd and cockpit-tls can create memfds without scoring. On Rocky 10,
  systemd makes one for every unit it starts, and that alone pushed pid 1
  past the quarantine threshold seconds after startup.
- RPMs. `cargo xtask rpm` builds `aegis-v2` and a noarch
  `aegis-v2-selinux`, and `dnf install ./*.rpm` gives you a systemd unit
  and a daemon confined to its own SELinux domain, `aegisd_t`. It runs in
  enforcing mode without a single denial in the audit log. The unit
  keeps six capabilities out of root's forty-one and sees the filesystem
  read-only, apart from its state, socket and log directories.
- OTLP export now needs one more step on an SELinux host:
  `setsebool -P aegisd_can_network_connect 1`. Until you run it, aegisd
  can't open a socket to anything.
- Contributor scaffolding: issue forms, pull request template, security
  policy, code of conduct and contributing guide.
