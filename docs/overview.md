# Overview

Aegis v2 is a runtime threat detection daemon for Rocky Linux 10. It
watches processes from the kernel with eBPF, scores how risky each one's
behaviour looks, and records an incident when a score crosses a
threshold. This page explains the ideas the other pages rely on.

## The problem it addresses

A single suspicious event rarely means much. Package managers run
scripts from `/tmp`. Container runtimes execute themselves out of memory.
Administrators attach debuggers to daemons. Alerting on each event alone
buries you in noise, so most of them end up ignored.

An attack is usually a chain of those events: a payload dropped into a
temp directory, a scan of the local network, an attach to a running
service. Aegis adds the links of a chain together, per process and
across a process tree, and only speaks up when the total is high.

## What v0.1 is

v0.1.0 runs in **audit mode** only. It computes every decision, records
it, and acts on none of them. The verdicts it records are
`would_throttle` and `would_quarantine`: what a later release in
enforce mode would do. Enforcement, quarantine and the honeypot are on
the [roadmap](roadmap.md).

## Concepts

### Signals

A signal is one kind of risky behaviour that the probes can observe.
v0.1 has five:

| Signal                     | Raised when a process...                     |
| -------------------------- | -------------------------------------------- |
| exec from a temp directory | runs a file from tmpfs, `/tmp` or `/var/tmp` |
| `memfd_create`             | calls `memfd_create`                         |
| exec of a memfd            | runs a file that only exists in memory       |
| ptrace of a system daemon  | attaches to pid 1 or a systemd service       |
| egress scan                | makes many outbound TCP connects in 2 s      |

[Scoring](scoring.md) has the exact rules and weights.

### Score

Each process has a score: the sum of its signals' weights, each decaying
with a 30-second half-life. A child process starts with a copy of its
parent's score. Repeating a signal tops it back up to full weight rather
than adding to it, so a busy daemon that calls `memfd_create` a thousand
times scores the same 20 as one that calls it once.

### Thresholds and tiers

Two thresholds split scores into three tiers:

| Score        | Tier       | Recorded verdict   |
| ------------ | ---------- | ------------------ |
| below 50     | log        | nothing            |
| 50 up to 80  | throttle   | `would_throttle`   |
| 80 and above | quarantine | `would_quarantine` |

Both thresholds are configurable.

### Incidents

When a process reaches the throttle tier, Aegis opens an incident for
it. From then on, its descendants' signals join that incident, and the
incident has its own score: for each kind of signal, the strongest
member's current contribution, summed. That's how a scan in one process
and a ptrace in its child add up to one quarantine-worthy incident. See
[incidents](incidents.md).

### Verified executables

Allowlists forgive signals for known tools, such as `dnf` running
scripts from `/tmp`. Aegis never trusts a process name for that, since a
process picks its own. An allowlist entry is an absolute path, and it
applies only when the file the process actually executed is that path
on the host and is either:

- owned by an RPM package and unchanged (size, mode and SHA-256 match
  the RPM database), or
- pinned by an administrator to a SHA-256 in the config.

Anything else is *unverified* and gets no allowlist credit. aegisd
only checks files that an allowlist entry or a pin names, so every
other executable shows as unverified too; for those, a verdict wouldn't
change the score.

Even a verified binary loses its allowlist credit when something else
may be running inside it: `LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_PATH`
in its environment, an environment aegisd can't read, or a successful
ptrace attach to it. See
[scoring](scoring.md#when-an-allowlist-is-withheld).

## Where to go next

- [Install it](installation.md).
- Learn [how the score works](scoring.md) before tuning anything.
- Read the [threat model](threat-model.md) to see what Aegis can and
  can't see.
