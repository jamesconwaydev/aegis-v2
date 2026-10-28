# Aegis v2 documentation

These pages describe v0.2 (currently v0.2.3). Where a page mentions
something later releases will add, it says so and links to the
[roadmap](roadmap.md).

## Getting started

- [Overview](overview.md): what Aegis is, and the words the rest of the
  docs use.
- [Installation](installation.md): install the RPMs, start the daemon,
  remove it again.
- [Preflight](preflight.md): every host check `aegisctl preflight` runs,
  and how to fix each one.

## Running it

- [Configuration](configuration.md): every setting in
  `/etc/aegis-v2/config.toml` and the allowlist drop-ins.
- [Scoring](scoring.md): the weights, decay, thresholds, and how to
  baseline a host in audit mode.
- [Incidents](incidents.md): what an incident is, where it lives, and
  how to read one.
- [Telemetry](telemetry.md): the journald, JSON-lines and OTLP outputs,
  field by field.
- [aegisctl](aegisctl.md): every command, flag and exit code.
- [SELinux](selinux.md): the `aegisd_t` domain and its one boolean.

## Knowing its limits

- [Threat model](threat-model.md): what Aegis sees, what it can't, and
  the known gaps.
- [Troubleshooting](troubleshooting.md): symptoms and fixes.
- [FAQ](faq.md): short answers to common questions.

## Working on Aegis

- [Architecture](architecture.md): the crates, probes and pipeline.
- [Development](development.md): building, testing, the e2e harness.
- [Releasing](releasing.md): versioning and cutting a release.
- [Roadmap](roadmap.md): what's planned for v0.2.0 and later.
