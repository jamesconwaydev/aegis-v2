<!-- markdownlint-disable-next-line MD041 -->
![Aegis v2: eBPF runtime threat detection for Rocky Linux 10](assets/header.svg)

[![CI][ci-badge]][ci]
[![Release][release-badge]][releases]
[![License: MIT OR Apache-2.0][license-badge]](#license)
[![Rocky Linux 10][rocky-badge]](docs/installation.md)
[![Rust 1.98+][msrv-badge]](docs/development.md#minimum-rust-version)
[![OpenSSF Scorecard][scorecard-badge]][scorecard]
[![Discussions][discussions-badge]][discussions]

[ci-badge]: https://img.shields.io/github/actions/workflow/status/jamesconwaydev/aegis-v2/ci.yml?branch=main&label=CI
[ci]: https://github.com/jamesconwaydev/aegis-v2/actions/workflows/ci.yml
[release-badge]: https://img.shields.io/github/v/release/jamesconwaydev/aegis-v2?include_prereleases&sort=semver
[releases]: https://github.com/jamesconwaydev/aegis-v2/releases
[license-badge]: https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue
[rocky-badge]: https://img.shields.io/badge/Rocky%20Linux-10-10b981
[msrv-badge]: https://img.shields.io/badge/rust-1.98%2B-orange
[scorecard-badge]: https://api.scorecard.dev/projects/github.com/jamesconwaydev/aegis-v2/badge
[scorecard]: https://scorecard.dev/viewer/?uri=github.com/jamesconwaydev/aegis-v2
[discussions-badge]: https://img.shields.io/github/discussions/jamesconwaydev/aegis-v2
[discussions]: https://github.com/jamesconwaydev/aegis-v2/discussions

# Aegis v2

Something on your server just ran a binary out of `/tmp`, then started
knocking on every port in the subnet. Most tools will tell you that
happened, one line each, in a log you read on Monday. Aegis watches the
whole process tree from the kernel, adds those signals up into one score,
and hands you a single incident with the evidence attached.

![Aegis v2 running its lab on a Rocky Linux 10 test VM: a copy of bash in /tmp scans loopback, its child attaches strace to a throwaway service, and one incident climbs from 65 to 110.](assets/lab.gif)

That's a real run of [`examples/lab/run.sh`](examples/lab) on a Rocky
Linux 10.2 test VM. It uses nothing but copies of the host's own bash
and strace, never leaves the host, and cleans up after itself. Run it on
a throwaway VM and you'll get the same incident. Run it with
`MODE=enforce` against an aegisd in enforce mode and you'll also watch
the tree get frozen and cut off, then killed when the script exits.

## What v0.2 does today

Out of the box, nothing changes: v0.2 starts in audit mode, where it
scores, records and reports and leaves every process alone. Give it a
few days of that. When the incidents it writes are ones you'd act on,
set `mode = "enforce"` and it starts acting on them itself.

Here's what you get in either mode:

- **Kernel probes** for every committed exec (the real path, not
  `argv[0]`), fork, exit, successful `ptrace` attach, `memfd_create`,
  and outbound TCP connects with their outcome. The environment of each
  new program is read in the kernel at exec, before any of its code
  runs, so a preloaded library can't hide from the check.
- **A risk score per process** that halves every 30 seconds of quiet.
  An exec from `/tmp` adds 25, a memfd exec adds 65, an attach to a
  system daemon adds 45, a burst of outbound connects adds 40.
- **Allowlists that can't be fooled by a name.** `dnf`, `gdb` or
  `podman` only get a pass when the binary on disk is RPM-owned and
  unmodified, or matches a SHA-256 you pinned, and the process shows no
  sign of `LD_PRELOAD` or an attached debugger.
- **Incidents, not alerts.** A process whose score reaches 50 opens an
  incident at the throttle tier, and its children's signals count
  towards the same one. At 80 it reaches the quarantine tier. Each
  incident is a directory under `/var/lib/aegis-v2/incidents`.
- **Telemetry** to journald, a JSON-lines file, OTLP logs and metrics,
  and webhooks (JSON or Slack) the moment an incident reaches a tier.
- **`aegisctl`** for `status`, `preflight` and `incidents
  list|show|timeline|release|kill`, with `--json` on all of them.
- **RPMs** for x86_64 and aarch64, a hardened systemd unit, and an
  SELinux module that confines aegisd to its own domain.

And in enforce mode, the tiers turn into actions:

- **Throttle** moves the tree into its own scope under
  `aegis-throttle.slice`, at 25% of one CPU and a 256 MiB soft memory
  limit by default. It keeps running, slowly, and its score can still
  climb.
- **Quarantine** holds every process in the kernel first: thirteen BPF
  LSM programs refuse it fork, connect, send, mount, `bpf()`, module
  loading, ptrace, writes through any file descriptor, new user
  namespaces and any signal to aegisd. Then systemd moves the tree into
  its own scope under `aegis-quarantine.slice` and freezes it, and an
  nftables rule drops its traffic.
- **Nothing is killed for you.** A frozen tree waits for you to look.
  `aegisctl incidents release <id>` thaws it and gives its network
  back; `aegisctl incidents kill <id>` ends it.

Enforce mode needs the BPF LSM and `nft`, and aegisd refuses to start in
it without them.

### Today versus planned

|                                            | v0.2 (today) | Planned |
| ------------------------------------------ | ------------ | ------- |
| Kernel probes, scores, incidents           | yes          |         |
| Verified-binary allowlists                 | yes          |         |
| Environment read in the kernel at exec     | yes          |         |
| journald, JSON-lines, OTLP logs, metrics   | yes          |         |
| Webhooks                                   | yes          |         |
| Throttle a process tree                    | enforce mode |         |
| Hold, freeze and cut off a tree            | enforce mode |         |
| Release or kill it with `aegisctl`         | yes          |         |
| Answer its traffic with a honeypot         | no           | v0.3.0  |
| Packet captures, STIX                      | no           | v0.3.0  |
| A box with its own disk overlay, migration | no           | v0.4.0  |

The [roadmap](docs/roadmap.md) has the detail on what's next.

## What it can and can't catch

It's built to catch the moves an intruder makes after getting a foothold:
running a dropped payload from `/tmp`, `/var/tmp` or `/dev/shm`, running
code that only exists in memory, attaching a debugger to pid 1 or a
system service, and scanning outward over TCP.

It won't reliably catch, in v0.2:

- **Root who knows it's there.** Root can stop aegisd, unload its probes
  or edit its config. Ship telemetry off the host so the record
  survives.
- **Loader tricks on processes older than aegisd.** A program started
  after aegisd has its environment read in the kernel at exec. One that
  was already running gets the old `/proc` read, and a library loaded
  long ago may have scrubbed its `LD_PRELOAD` by then. A tracer that
  attaches before the exec isn't seen either.
- **Scripts run as `sh /tmp/x`.** The kernel ran the shell, so that's
  what Aegis sees. A script with a `#!` line run directly is caught.
- **UDP, and scans spread across many processes.** Only TCP connects
  are counted, per process.
- **Allowlisting inside containers.** Container binaries never verify
  against the host's files, so allowlists don't apply to them.

Enforce mode has edges of its own. The hold lands a few milliseconds
after the score crosses the line, and anything the tree wrote before
then is on disk. A restart of aegisd lifts the holds, though the freeze
and the network rule stay. The [threat model](docs/threat-model.md) has
every known gap and why.

### What it needs, and what it can touch

aegisd runs as root under systemd, but with six capabilities rather
than all of them: `CAP_BPF` and `CAP_PERFMON` to load and attach the probes,
`CAP_SYS_ADMIN` for the BPF LSM programs, `CAP_SYS_PTRACE` to read other
processes' `/proc` entries, `CAP_DAC_READ_SEARCH` to hash any
executable, and `CAP_NET_ADMIN` so `nft` can block a quarantined tree's
traffic in enforce mode. The filesystem is read-only to it apart from
`/var/lib/aegis-v2` and `/run/aegis-v2`, it can't gain privileges, and
SELinux confines it to its own `aegisd_t` domain. Its control socket
answers root only.

That protects the host from a compromised aegisd. It doesn't protect
aegisd from root, though no debugger can attach to it, root's included.
In audit mode nothing it does changes the host. In enforce mode, what it
changes is what it creates: transient scopes under `aegis.slice` and an
nftables table called `inet aegis`. Either way, the end-to-end tests
check that `/etc` is byte-for-byte unchanged.
[Installation](docs/installation.md#the-systemd-unit) has the
full unit.

## What one incident looks like

The lab's run above, as Aegis recorded it. Times are milliseconds from
the first signal; scores are the incident's.

```text
process tree
  1653422  /tmp/aegis-lab.9mGtdQ/bash      unverified   root, opened the incident
  └─ 1653425  /tmp/aegis-lab.9mGtdQ/strace unverified   joined at its exec

  ms   pid      signal                     adds  score  verdict
   0   1653422  tmp_exec                    25     25   below 50, not recorded
  14   1653422  egress_scan (10 targets)    40     65   would_throttle, opens
  22   1653425  tmp_exec                    25     65   would_throttle, joins
  34   1653425  ptrace_system_daemon        45    110   would_quarantine

/var/lib/aegis-v2/incidents/AEG-20261021-233357-76d2c9b5faf63e86/
├── incident.json     the summary: tree, 4 pieces of evidence, peak 110
└── timeline.jsonl    one line per decision that changed something
```

The child's own `tmp_exec` doesn't raise the incident score: each kind
counts once, at its strongest, across the tree. The two files are in
[`examples/lab`](examples/lab), unedited, and
[incidents](docs/incidents.md) documents every field. That run was in
audit mode, so nothing was throttled or quarantined. In enforce mode the
same chain is throttled at 65 and quarantined at 110, and the verdicts
read `throttled` and `quarantined`.

## How the score adds up

| Signal                                | Adds | Weight key             |
| ------------------------------------- | ---- | ---------------------- |
| Exec from `/tmp`, `/var/tmp`, tmpfs   | 25   | `tmp_exec`             |
| `memfd_create`                        | 20   | `memfd_create`         |
| Exec of a memfd                       | 65   | `memfd_exec`           |
| ptrace attach to pid 1 or a service   | 45   | `ptrace_system_daemon` |
| 20 targets or 10 failed connects, 2 s | 40   | `egress_scan`          |

| Score     | Audit mode         | Enforce mode     |
| --------- | ------------------ | ---------------- |
| below 50  | debug log only     | debug log only   |
| 50 to 79  | `would_throttle`   | `throttled`      |
| 80 and up | `would_quarantine` | `quarantined`    |

Each signal kind counts once per process, so ten `memfd_create` calls
are worth 20, not 200. Every component halves after 30 seconds of quiet:
a 45-point attach is worth 22.5 half a minute later, and about 6 after
90 seconds. Once a tree is in an incident, it's judged on the strongest
of each kind across all its members, which is how the lab's scan in one
process and attach in another add up to 110. Weights, thresholds and the
half-life are all in the config. [Scoring](docs/scoring.md) covers the
rest, and how to baseline a host before you trust any of it.

## How it fits together

```mermaid
flowchart LR
    K["Kernel<br/>eBPF probes"] -->|ring buffer| D["aegisd"]
    D --> P["Process table<br/>+ verification"]
    P --> S["Scoring<br/>decay, allowlists"]
    S -->|"score ≥ 50"| I["Incident store<br/>/var/lib/aegis-v2"]
    S -->|"score ≥ 50"| T["journald · JSONL · OTLP · webhooks"]
    S -->|"enforce mode"| E["Enforcer<br/>holds · systemd · nft"]
    C["aegisctl"] <-->|"/run/aegis-v2/aegisd.sock"| D
```

[Architecture](docs/architecture.md) walks through each box.

## Quickstart

Grab both RPMs for your architecture from the
[releases page][releases], then on a Rocky Linux 10 host, as root:

```sh
dnf install ./aegis-v2-*.x86_64.rpm ./aegis-v2-selinux-*.noarch.rpm
aegisctl preflight
systemctl enable --now aegisd
# leave it in audit mode for 48 to 72 hours of normal work
aegisctl incidents list
```

Every incident you see after those few days is either something worth a
look or a false positive you can allowlist. [Scoring](docs/scoring.md)
covers the baselining, and [installation](docs/installation.md) covers
aarch64 and what `preflight` wants from your kernel. Once the list is
quiet, set `mode = "enforce"` in `/etc/aegis-v2/config.toml` and run
`systemctl reload aegisd`; [configuration](docs/configuration.md#general)
has what that turns on.

## Compatibility

| Distribution                | Kernel | Arch    | Tested                    |
| --------------------------- | ------ | ------- | ------------------------- |
| Rocky Linux 10.2            | 6.12   | x86_64  | end to end                |
| Rocky Linux 10.2            | 6.12   | aarch64 | end to end                |
| Other EL10 (Alma, RHEL)     | 6.12+  | either  | not yet; reports welcome  |
| EL9 or older, other distros |        |         | not supported             |

It needs kernel BTF, cgroup v2 and the BPF LSM, which Rocky 10.2 enables
by default. `aegisctl preflight` checks each one and tells you the fix.

## Documentation

| Page                                       | What it covers                  |
| ------------------------------------------ | ------------------------------- |
| [Overview](docs/overview.md)               | Concepts and vocabulary         |
| [Architecture](docs/architecture.md)       | Probes, pipeline, data flow     |
| [Installation](docs/installation.md)       | RPMs, first start, uninstall    |
| [Preflight](docs/preflight.md)             | Every host check and its fix    |
| [Configuration](docs/configuration.md)     | Every setting and its default   |
| [Scoring](docs/scoring.md)                 | Weights, decay, tuning          |
| [Incidents](docs/incidents.md)             | On-disk format and reading them |
| [Telemetry](docs/telemetry.md)             | journald, JSONL, OTLP           |
| [aegisctl](docs/aegisctl.md)               | Command reference               |
| [SELinux](docs/selinux.md)                 | The `aegisd_t` policy           |
| [Threat model](docs/threat-model.md)       | What it catches, what it can't  |
| [Troubleshooting](docs/troubleshooting.md) | Common problems                 |
| [FAQ](docs/faq.md)                         | Short answers                   |
| [Development](docs/development.md)         | Building and testing            |
| [Releasing](docs/releasing.md)             | Cutting a release               |
| [Roadmap](docs/roadmap.md)                 | What's planned, by version      |

## Contributing

Bug reports, false positives and pull requests are all welcome.
[CONTRIBUTING.md](CONTRIBUTING.md) has the details, and security problems
go through [SECURITY.md](SECURITY.md), not the issue tracker.

## License

The userspace code (`aegisd`, `aegisctl` and the libraries they use) is
dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option. The eBPF programs in `aegis-ebpf` are
[GPL-2.0-only](LICENSE-GPL-2.0), because the kernel requires it.
