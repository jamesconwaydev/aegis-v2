# Threat model

This page says what Aegis v0.1 is for, what it can see, and where it is
blind. Read it before you rely on it.

## What it's for

Aegis v0.1 detects common post-exploitation behaviour on a Rocky Linux
10 host and records it as incidents:

- running a dropped payload from a temp directory
- running code that only exists in memory (`memfd_create` and exec)
- attaching a debugger to pid 1 or a system service
- scanning the network outward

It's a detector in audit mode. It doesn't stop, slow, isolate or kill
anything, and nothing it does changes the host. The e2e tests check
that `/etc` is byte-for-byte unchanged across every scenario.

## What it trusts

- **The kernel.** Events come from eBPF programs in the kernel. A kernel
  compromise defeats Aegis.
- **The RPM database and pins.** A binary counts as verified if its
  content matches the RPM database or an admin's SHA-256 pin. Someone
  who can rewrite the RPM database as root can make a binary verify.
- **Root's config.** `/etc/aegis-v2` is root-only. Whoever can edit it
  can allowlist anything.

## What it never trusts

- **Process names.** `comm` and `argv[0]` are recorded but never used to
  decide anything. Allowlists take absolute paths, and a path only
  counts when the file the kernel executed is that path on the host and
  verifies.
- **A lookalike in a chroot or container.** A process that runs its own
  `/usr/bin/dnf` inside a chroot doesn't get the host's verdict: aegisd
  checks the executed inode against the host's file.
- **Text from processes.** Paths and names may contain anything.
  Incidents store exact bytes in base64 beside a lossy UTF-8 copy,
  journald fields use the binary-safe encoding, and `aegisctl` escapes
  control characters before printing.

## Self-protection

aegisd runs confined: five capabilities, a read-only filesystem apart
from its own directories, and its own SELinux domain. The control socket
answers root only.

That protects the host from a compromised aegisd. It doesn't protect
aegisd from root.

## Known limitations

These are known, and some are planned to change. None of them is a
secret.

### A root attacker can stop it

An attacker with root who hasn't been caught yet can stop aegisd,
unload its probes, or edit its config. Aegis isn't a rootkit defence.
Ship its telemetry off the host (OTLP, or journald forwarding) so the
record of what happened before it stopped survives.

### Scripts run through a shell aren't execs

`sh /tmp/x`, or a shebang-less script that `execvp` hands to `/bin/sh`
when the kernel refuses it (`ENOEXEC`), isn't an exec of `/tmp/x`. The
kernel executed the shell, which then read the file. Aegis sees the
shell, not the script, and scores no temp-directory exec. A script with
a `#!` line run directly is caught.

### Only TCP connects count towards scans

The egress scan signal comes from TCP state changes. UDP traffic,
including UDP scans, isn't observed in v0.1.

### btrfs subvolumes and overlayfs stay unverified

Verification compares the device and inode the kernel executed with the
file at the same path on the host. On btrfs subvolumes and overlayfs
the device numbers don't match, so binaries there are always
`unverified`, and allowlists never apply to them. Rocky's default
filesystem, XFS, isn't affected.

### Containers

Every binary is verified against the file at the same path under the
host's root (pid 1's). A process inside a container runs a file from
the container's image, which is a different file, so it's always
`unverified` and allowlists don't apply to it. The container runtimes
themselves (`podman`, `crun`, `runc`) run from the host and verify
normally.

The `ptrace` target pid is looked up in the host's pid namespace. A
tracer inside a container names a pid in its own namespace, so Aegis
may judge the wrong process, or none, as the target.

### Hosts that suspend

aegisd sweeps its process table every 60 seconds, matching each entry's
start time against `/proc`. On a host that suspends and resumes,
processes that were alive across the suspend can fail that match and
lose their accumulated score. Servers rarely suspend.

### Scores just under a threshold

Scores decay continuously, including in the moment between two
signals. Weights that add up exactly to a threshold land just under it.
See [scoring](scoring.md#tuning-notes).

### Lost events

Under a heavy burst, such as thousands of execs a second, the 4 MiB
ring buffer can fill. Events that don't fit are counted, not queued, and
show in `aegisctl status` as `dropped events`. A signal in a dropped
event is missed.

### Verification is held for 2 seconds

A signal waiting on its binary's verification is held for up to
2 seconds. An `rpm` query slower than that scores the signal as
`unverified`, which errs towards scoring, never towards forgiving.

### Paths are capped at 256 bytes

Longer paths are truncated in events and incidents. A truncated path is
never verified, and a path too long to render at all scores as a
temp-directory exec.

### OTLP

OTLP endpoints that carry credentials in the URL are rejected; put them
in `[telemetry.otlp.headers]`. Failed exports aren't retried.

### The JSONL file doesn't rotate

Use logrotate with `copytruncate`. See
[telemetry](telemetry.md#json-lines).

## Reporting a bypass

A way to evade detection, forge a verified binary, or tamper with
incidents is a security issue. Report it privately, as
[SECURITY.md](../SECURITY.md) describes, not as a public issue.
