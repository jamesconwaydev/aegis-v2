# Threat model

Read this before you rely on Aegis v0.1.

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
- **A verified binary that may be running foreign code.** A process
  started with `LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_PATH`, one whose
  environment can't be read, and one a host-side debugger attached to
  get no allowlist credit, however well their binary verifies. These
  checks are best effort; see
  [below](#the-injection-checks-are-best-effort).
- **Text from processes.** Paths and names may contain anything.
  Incidents store exact bytes in base64 beside a lossy UTF-8 copy,
  journald fields use the binary-safe encoding, and the journald
  message and `aegisctl` escape control, line-separator and
  bidirectional characters before they're shown.

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

### The injection checks are best effort

Allowlist credit is withheld from a process that shows `LD_PRELOAD`,
`LD_AUDIT` or `LD_LIBRARY_PATH`, or that a debugger attached to. In
v0.1 those checks can be beaten:

- aegisd reads the environment from `/proc/<pid>/environ` a few
  milliseconds after the exec. That's the process's own memory, and a
  preloaded library can scrub its `LD_PRELOAD` entry before aegisd reads
  it.
- A process can exec onward with a clean environment, and the next
  image starts out trusted.
- A ptrace attach is only seen when another process attaches to the
  target. `PTRACE_TRACEME`, or a seize set up before the exec, isn't
  seen.
- A process can re-exec the same file without the loader variable in
  the moment before aegisd reads its environment, and the read then
  sees the clean one.

They stop careless injection and inherited environments, not an
attacker who knows about them. Capturing the environment in the kernel
at exec is planned for v0.2.0.

### Environment reads can get stuck

A read of `/proc/<pid>/environ` can block for good, for example when a
process's memory is backed by a hung FUSE filesystem. aegisd runs at
most 16 reads at once. Once 16 are stuck, every later read is refused,
and every allowlisted process counts as untrusted until aegisd
restarts. That causes false positives, not missed detections.

### A broken RPM database sticks

If the RPM database is broken when aegisd checks a binary, rpm can
answer "not owned", and aegisd caches that. Allowlisted binaries stay
`unverified`, and lose their allowlist credit, until a reload
(`systemctl reload aegisd`) or a restart empties the cache.

### Some scans aren't detected

The egress scan signal counts connects per process. A scan spread
across many processes, one connection each, never crosses the
threshold in any of them. It also comes from TCP state changes only, so
UDP traffic, UDP scans included, isn't observed in v0.1.

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

### Signals are held for up to 6 seconds

A signal waiting on its binary's verification or its environment read
is held for up to 6 seconds. Anything still unknown then scores as
`unverified` or untrusted, which errs towards scoring, never towards
forgiving. On a busy host, an allowlisted process that exits before its
environment is read loses its allowlist credit the same way.

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
