# FAQ

## Does Aegis block anything?

Not in v0.1. It runs in audit mode only and changes nothing on the
host. Its verdicts, `would_throttle` and `would_quarantine`, say what a
later release would do. Enforce mode is planned for v0.2.0; see the
[roadmap](roadmap.md).

## Then why run it now?

To learn what normal looks like on your hosts before anything acts on
it. A few days in audit mode turns up the tools that need allowlisting,
so that when enforcement arrives, it doesn't fire on your own backup
job. It's also a working detector: an incident is worth reading
whether or not anything was stopped.

## How is it different from Falco or Tracee?

Those emit an alert per rule match. Aegis adds signals up per process
and across a process tree, with decay, so a single odd event stays
quiet and a chain of them becomes one incident with all its evidence.
Its allowlists also require the binary to verify against the RPM
database or a pin, never a name. v0.1 has five signals; Falco and Tracee
ship far larger rule sets.

## Which distributions does it support?

Rocky Linux 10, x86_64 and aarch64. Other EL10 rebuilds with a 6.12
kernel, BTF and the BPF LSM should work, but aren't tested. It needs the
BPF LSM, cgroup v2 and kernel 6.12 or newer; `aegisctl preflight` checks
all of these.

## Does it work in containers?

aegisd runs on the host and sees processes inside containers too, since
the probes are in the kernel. Binaries inside containers never verify,
so allowlists don't apply to them. See the
[threat model](threat-model.md#containers).

## How much does it cost to run?

Overhead hasn't been measured for v0.1, so there are no numbers to
quote yet. Measuring it is on the roadmap for v1.0.0. aegisd does its
own work in one event loop, with up to four threads verifying binaries,
up to 16 reading process environments, one writing incidents, and one
sending OTLP batches when that sink is on.

## Will an update to a package cause false positives?

It shouldn't. After an update, the new binary is a new file, so aegisd
verifies it again against the updated RPM database. A pinned binary is
different: if you replace it, update the pin, or it verifies as
`modified`.

## Where's the web UI?

There isn't one. Use `aegisctl`, journald, or ship OTLP logs to the
tools you already have.

## Can I change the weights?

Yes, under `[scoring.weights]` in the config, and reload. Prefer an
allowlist when you're trying to silence one tool; a weight change
affects every process. See [scoring](scoring.md#baselining-a-host).

## How do I validate a config change before applying it?

```sh
aegisd --check-config
```

It exits 0 if the config and drop-ins are valid, or 78 with the file,
line and column of the problem.

## Does it send anything anywhere?

Only what you configure. journald is always on and local. The JSONL
file and OTLP export are off until you turn them on, and SELinux blocks
network access until you enable `aegisd_can_network_connect`. aegisd
never contacts anything else.

## Why does the package require `criu` and `nftables`?

Later releases use them: `nftables` for egress control in v0.2.0, and
`criu` for live migration in v0.4.0. v0.1 uses neither.

## Why is the eBPF code GPL?

The kernel only lets GPL-compatible eBPF programs use many of its
helpers. The eBPF crate is `GPL-2.0-only`; everything in userspace is
`MIT OR Apache-2.0`.
