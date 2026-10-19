# Roadmap

Everything on this page is **planned**. None of it ships in v0.1.0,
and plans can change. For what v0.1.0 does today, see the
[overview](overview.md).

Each release goes through the same path: pull requests with green CI,
end-to-end tests on a real Rocky 10 host, then a tagged pre-release with
RPMs.

## v0.1.0: audit mode (current)

What ships: eBPF probes for exec, fork, exit, ptrace, `memfd_create`
and outbound TCP connects; decaying risk scores with verified-binary
allowlists; incidents on disk; journald, JSON-lines and OTLP log
telemetry; `aegisctl status`, `preflight` and `incidents`; RPMs for
x86_64 and aarch64 with a systemd unit and SELinux module.

## v0.2.0: enforcement (planned)

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
