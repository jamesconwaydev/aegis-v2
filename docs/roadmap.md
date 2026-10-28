# Roadmap

Everything below the current release is **planned**. None of it ships
today, and plans can change. For what the current release does, see the
[overview](overview.md), and for a one-table summary, the
[README](../README.md#today-versus-planned).

Each release goes through the same path: pull requests with green CI,
end-to-end tests on a real Rocky 10 host, then a tagged pre-release with
RPMs.

## v0.1: audit mode (shipped)

v0.1.0 and v0.1.1 watched and recorded, and changed nothing: eBPF
probes for exec, fork, exit, ptrace, `memfd_create` and outbound TCP
connects; decaying risk scores with verified-binary allowlists;
incidents on disk; journald, JSON-lines and OTLP log telemetry;
`aegisctl status`, `preflight` and `incidents`; RPMs for x86_64 and
aarch64 with a systemd unit and SELinux module.

## v0.2: enforcement (current)

v0.2.0 is the current release, and the first that acts. Audit mode is
still the default. Enforce mode is something you set in the config
after you've baselined the host, and aegisd refuses it unless the BPF
LSM is enabled and `nft` is installed. The
[changelog](../CHANGELOG.md) has the full list; in short:

- **The same scores decide.** The thresholds you tuned in audit mode
  are the ones that act: `would_throttle` becomes `throttled`, and
  `would_quarantine` becomes `quarantined`.
- **Throttle slows, it doesn't stop.** The tree moves into its own
  scope under `aegis-throttle.slice`, with the CPU and memory limits in
  `[throttle]`.
- **Quarantine holds, freezes and cuts off.** BPF LSM programs refuse a
  held process fork, connect, send, mount, `bpf()`, module loading,
  ptrace, writes and new user namespaces. systemd moves the tree into
  its own scope under `aegis-quarantine.slice` and freezes it, and
  nftables drops its traffic.
- **Nothing is killed for you.** `aegisctl incidents release` and
  `kill` are yours to run.
- **Every action is evidence.** Each step goes into the incident's
  `actions`, failures go out through telemetry, and webhooks tell you
  when an incident reaches a tier.
- **OTLP metrics** sit beside the logs, and the environment checks
  read the environment in the kernel at exec.

What v0.2 doesn't do: answer the quarantined tree's traffic, or give it
a filesystem of its own. Until those land, quarantine means held, frozen
and cut off, and whatever it wrote before the hold is on disk.

## v0.3.0: the honeypot (planned)

- A separate, unprivileged honeypot service that answers a quarantined
  process's network traffic: DNS, SSH, HTTP and HTTPS, SMTP, and a
  catch-all for other ports.
- nftables redirection (DNAT) that sends the quarantined tree's
  traffic to the honeypot instead of dropping it.
- Packet captures and a store for captured payloads.
- STIX 2.1 output of the indicators an incident collects.

## v0.4.0: live migration (planned)

- **CRIU live migration** of a flagged process tree into a box: a
  disk-backed overlay filesystem and its own network namespace, so its
  writes never reach the real disk.
- **Containers quarantined in place.**
- **Release & Merge:** discard a boxed process, or, for a false
  positive, review its file changes and merge them back to the host.
- **`aegisctl top`:** a live view of scores and incidents.
- **Retention** for incident data.

## v1.0.0 (planned)

- A hardened SELinux policy.
- Complete documentation.
- Measured performance numbers, published.
- A security review of the whole codebase.

## Have an idea?

Open a feature request on GitHub. Say what you're trying to catch or
stop, and what you'd expect Aegis to do.
