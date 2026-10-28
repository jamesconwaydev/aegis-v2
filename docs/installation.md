# Installation

Installing Aegis v0.2 from the release RPMs and starting it takes
about five minutes.

## Requirements

- Rocky Linux 10 (or another EL10 build) on x86_64 or aarch64
- Kernel 6.12 or newer with BTF, which Rocky 10 ships
- The BPF LSM enabled; Rocky 10.2 enables it by default
- cgroup v2
- Root

`aegisctl preflight` checks all of this. [Preflight](preflight.md) has
each check and its fix.

## Install the RPMs

Each release on the [releases page][releases] carries three RPMs and a
`SHA256SUMS` file:

| File                                           | Contents               |
| ---------------------------------------------- | ---------------------- |
| `aegis-v2-<version>-1.el10.x86_64.rpm`         | aegisd, aegisctl, unit |
| `aegis-v2-<version>-1.el10.aarch64.rpm`        | the same, for aarch64  |
| `aegis-v2-selinux-<version>-1.el10.noarch.rpm` | the SELinux module     |

[releases]: https://github.com/jamesconwaydev/aegis-v2/releases

Download the one for your architecture and the SELinux module, check
them, and install both:

```sh
sha256sum --ignore-missing -c SHA256SUMS
dnf install ./aegis-v2-0.2.0-1.el10.x86_64.rpm \
    ./aegis-v2-selinux-0.2.0-1.el10.noarch.rpm
```

From v0.2.0, each release also carries a signature over `SHA256SUMS`,
build provenance for every file, and an SBOM of the Rust dependencies in
SPDX and CycloneDX. If you want proof the RPMs came from this
repository's Release workflow, and not just that they downloaded intact,
check both before you install:

```sh
id='^https://github\.com/jamesconwaydev/aegis-v2/\.github/workflows/release\.yml@refs/tags/v'
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
    --certificate-identity-regexp "$id" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify aegis-v2-0.2.0-1.el10.x86_64.rpm \
    --repo jamesconwaydev/aegis-v2
```

`dnf` pulls in `nftables` and `criu`, which the package requires.
Enforce mode uses `nftables`; `criu` waits for live migration in
v0.4.0 (see the [roadmap](roadmap.md)).
When `selinux-policy-targeted` is installed, as it is on every stock
Rocky host, `aegis-v2` requires the matching `aegis-v2-selinux`, so
install the two together.

The package's post-install step runs `aegisctl preflight` and prints the
result. It never changes your boot configuration. If a check fails, fix
it before you start the daemon.

## What the package installs

| Path                                        | Purpose                   |
| ------------------------------------------- | ------------------------- |
| `/usr/sbin/aegisd`                          | the daemon                |
| `/usr/bin/aegisctl`                         | the CLI                   |
| `/usr/lib/systemd/system/aegisd.service`    | the systemd unit          |
| `/etc/aegis-v2/config.toml`                 | main config, mode 0600    |
| `/etc/aegis-v2/allowlist.d/00-default.toml` | default allowlist         |
| `/var/lib/aegis-v2/`                        | incident store, mode 0700 |
| `/var/log/aegis-v2/`                        | optional JSONL log, 0700  |
| `/usr/share/licenses/aegis-v2/`             | licence texts             |

Both files under `/etc/aegis-v2` are marked `%config(noreplace)`, so an
upgrade keeps your edits.

## Start the daemon

```sh
systemctl enable --now aegisd
aegisctl status
```

`status` shows `mode audit`, lists nine probes, and has an `events`
counter that climbs. If it says aegisd isn't running, see
[troubleshooting](troubleshooting.md#aegisd-wont-start).

## Baseline in audit mode

Leave it alone for 48 to 72 hours of normal work: deploys, backups,
cron jobs, whatever the host usually does. Then:

```sh
aegisctl incidents list
```

Each incident is either worth investigating or a false positive.
[Scoring](scoring.md#baselining-a-host) explains how to tell, and how to
allowlist the second kind.

## The systemd unit

The unit runs aegisd as root with only six capabilities:

| Capability            | Why                                             |
| --------------------- | ----------------------------------------------- |
| `CAP_BPF`             | load the probes                                 |
| `CAP_PERFMON`         | open the tracepoints                            |
| `CAP_SYS_ADMIN`       | attach the BPF LSM programs                     |
| `CAP_SYS_PTRACE`      | read `/proc/<pid>/exe` and pid 1's root         |
| `CAP_DAC_READ_SEARCH` | open and hash any executable, whatever its mode |
| `CAP_NET_ADMIN`       | enforce mode: let `nft` add the egress block    |

In enforce mode aegisd asks systemd, over D-Bus, to move, freeze, thaw
and kill a process tree, so it never writes to the cgroup tree itself
and `ProtectControlGroups=yes` stays on. `nft` talks to the kernel over
netlink, which is why `AF_NETLINK` is among the allowed socket families.

It also sets `NoNewPrivileges=yes` and `ProtectSystem=strict`, so the
filesystem is read-only to aegisd apart from `/var/lib/aegis-v2`,
`/run/aegis-v2` and `/var/log/aegis-v2`. `Type=notify` means `systemctl
start` returns once the probes are attached and the socket is listening.

A config error exits with status 78, and the unit won't restart on that
status, since restarting can't fix a bad file. Any other failure
restarts after 5 seconds, including the probe event stream ending
unexpectedly, which makes aegisd exit non-zero.

## Upgrade

Install the newer RPMs the same way. The package restarts aegisd after
an upgrade, and the SELinux package relabels anything its file contexts
changed.

## Uninstall

```sh
systemctl disable --now aegisd
dnf remove aegis-v2 aegis-v2-selinux
rm -rf /var/lib/aegis-v2 /var/log/aegis-v2   # only if you want the incidents gone
```

`dnf remove` leaves incidents and logs in place, because aegisd created
them at run time and the RPM doesn't own them.

## Where to go next

- [Configuration](configuration.md) for every setting.
- [Telemetry](telemetry.md) to ship incidents to journald, a file or an
  OTLP collector.
