# Roadmap

Everything below the current release is **planned**. None of it ships
today, and plans can change. For what the current release does, see the
[overview](overview.md), and for a one-table summary, the
[README](../README.md#today-versus-planned).

Each release goes through the same path: pull requests with green CI,
end-to-end tests on a real Rocky 10 host, then a tagged pre-release with
RPMs.

## v0.1: audit mode (current)

v0.1.1 is the current release. It fixes two problems in the evidence
v0.1.0 recorded; see the [changelog](../CHANGELOG.md).

What ships: eBPF probes for exec, fork, exit, ptrace, `memfd_create`
and outbound TCP connects; decaying risk scores with verified-binary
allowlists; incidents on disk; journald, JSON-lines and OTLP log
telemetry; `aegisctl status`, `preflight` and `incidents`; RPMs for
x86_64 and aarch64 with a systemd unit and SELinux module.

## v0.2.0: enforcement (planned)

v0.1 only records what it would do. v0.2.0 is where it starts doing it,
and only on hosts where you ask it to.

### How it's meant to work

- **You turn it on.** `mode = "audit"` stays the default. Enforce mode is
  something you set in the config after you've baselined the host, and
  aegisd refuses it on a host where the BPF LSM isn't enabled, because
  the hooks that keep a quarantined process in place depend on it.
  v0.1 refuses enforce mode outright.
- **The same scores decide.** The thresholds you tuned in audit mode
  are the ones that act. An incident that would have said
  `would_throttle` throttles; one that would have said
  `would_quarantine` is quarantined.
- **Throttle slows, it doesn't stop.** The process tree moves into
  `aegis-throttle.slice` with CPU and memory limits from the config. It
  keeps running and its score can still climb.
- **Quarantine contains.** The tree moves into its own transient scope
  under `aegis-quarantine.slice`, its traffic is dropped by nftables,
  and BPF LSM hooks keyed to that cgroup refuse the usual ways out:
  mounts, namespace changes, module loading, `bpf()`, and writes where it
  shouldn't write.
- **Nothing is killed for you.** Quarantine holds a process; deciding
  what happens to it next is yours.
- **Every action is evidence.** What was done, to which process, and
  when goes into the incident and out through telemetry, and webhooks
  tell you as it happens.

What v0.2.0 won't do yet: answer the quarantined tree's traffic (the
honeypot, v0.3.0), or move it into a box with its own filesystem
(v0.4.0). Until then, quarantine means held, cut off and watched.

### What's in it

- **Enforce mode**, an explicit opt-in. Audit stays the default.
- **Throttle tier:** move a process tree into `aegis-throttle.slice`
  with CPU and memory limits.
- **Quarantine via cgroups:** a transient scope per incident under
  `aegis-quarantine.slice`, created through systemd.
- **Egress control with nftables:** drop a quarantined tree's traffic,
  with redirection plumbing for the honeypot.
- **BPF LSM hooks** that stop a quarantined process from escaping
  (mounts, namespaces, module loading, `bpf()`) and from writing where it
  shouldn't.
- **Webhooks** for throttle and quarantine events.
- **OTLP metrics**, alongside the OTLP logs v0.1 already sends.
- **In-kernel environment capture** at exec, replacing v0.1's
  best-effort `/proc/<pid>/environ` read for the injection checks.

## v0.3.0: the honeypot (planned)

- A separate, unprivileged honeypot service that answers a quarantined
  process's network traffic: DNS, SSH, HTTP and HTTPS, SMTP, and a
  catch-all for other ports.
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
