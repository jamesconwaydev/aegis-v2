# Configuration

aegisd reads one main file and a directory of allowlist drop-ins:

- `/etc/aegis-v2/config.toml`: everything
- `/etc/aegis-v2/allowlist.d/*.toml`: allowlist rules only

Every setting has a built-in default, and the shipped `config.toml`
spells each one out, so an empty file behaves exactly like the shipped
one. Change what you need and leave the rest.

## Applying changes

Check a file before you load it:

```sh
aegisd --check-config
```

That loads the config and drop-ins, prints any warnings, and exits 0 if
they're valid or 78 with the error if not. It never starts the daemon.

Then reload:

```sh
systemctl reload aegisd
```

A reload that fails is logged, and the running config stays. What a
reload applies:

| Setting                                            | On reload    |
| -------------------------------------------------- | ------------ |
| `[general]` thresholds                             | applied      |
| `[scoring]`, `[scoring.weights]`, `[scoring.scan]` | applied      |
| `[allowlist]` and every drop-in, pins included     | applied      |
| `[telemetry]`, `[incidents]`                       | next restart |

Scores already built up carry over a reload, and decay at the new
half-life from then on. A reload empties the verification cache, so
every allowlisted and pinned path is checked again, and every process
running a pinned binary is verified again.

## Errors

The file is strict. An unknown key, a wrong type or an out-of-range value
is an error, reported with the file, line and column (wrapped here to
fit the page):

```text
/etc/aegis-v2/config.toml:2:8: enforce mode needs nftables (dnf
install nftables)
```

An invalid file at startup stops aegisd with exit status 78, and the
unit doesn't retry. Fix the file and start it again.

## `[general]`

| Key                          | Type    | Default   |
| ---------------------------- | ------- | --------- |
| `mode`                       | string  | `"audit"` |
| `score_threshold_throttle`   | integer | `50`      |
| `score_threshold_quarantine` | integer | `80`      |

- `mode`: `"audit"` scores and records what Aegis would do. From v0.2.0,
  `"enforce"` also does it. aegisd refuses `"enforce"` unless the BPF
  LSM is on (`bpf` in `/sys/kernel/security/lsm`; see
  [preflight](preflight.md#bpf-lsm)) and `/usr/sbin/nft` exists. The
  error points at the `mode` line, as above. A reload that fails this
  check keeps the old configuration.

- `score_threshold_throttle`: A score at or above this records
  `would_throttle`. Must be lower than `score_threshold_quarantine`.

- `score_threshold_quarantine`: A score at or above this records
  `would_quarantine`.

## `[scoring]`

| Key              | Type  | Default | Rule |
| ---------------- | ----- | ------- | ---- |
| `half_life_secs` | float | `30.0`  | > 0  |

- `half_life_secs`: How long a signal's contribution takes to halve when
  nothing new happens.

## `[scoring.weights]`

Every weight is a float, 0 or more. Setting one to 0 turns that signal
off.

| Key                    | Default | Signal                     |
| ---------------------- | ------- | -------------------------- |
| `tmp_exec`             | `25.0`  | exec from a temp directory |
| `memfd_create`         | `20.0`  | a call to `memfd_create`   |
| `memfd_exec`           | `65.0`  | exec of a memfd            |
| `ptrace_system_daemon` | `45.0`  | ptrace attach to a daemon  |
| `egress_scan`          | `40.0`  | an outbound connect burst  |

[Scoring](scoring.md) defines each signal.

## `[scoring.scan]`

What counts as an egress scan: either count reached inside the window.

| Key                | Type    | Default | Rule |
| ------------------ | ------- | ------- | ---- |
| `window_secs`      | float   | `2.0`   | > 0  |
| `distinct_targets` | integer | `20`    | ≥ 1  |
| `failed_connects`  | integer | `10`    | ≥ 1  |

- `window_secs`: The sliding window, per process.

- `distinct_targets`: Distinct (address, port) pairs connected to inside
  the window.

- `failed_connects`: Outbound connects that failed inside the window:
  refused, timed out, reset, or any other socket error.

## `[allowlist]`

Every list defaults to empty in the code. The package fills them in
`allowlist.d/00-default.toml`; see [the default allowlist](#the-default-allowlist).

Paths must be absolute. A bare name such as `"dnf"` is an error, since a
process can call itself anything. An entry only counts for a binary that
verifies: RPM-owned and unchanged, or matching a pin. Name the real
file: a symlink, FIFO or device at a listed path never verifies.

The paths on these lists and in `pinned` are also the only executables
aegisd verifies at all. Every other binary shows as `unverified` in
incidents, which changes nothing about its score.

Even a verified binary gets no credit when the process was started with
`LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_PATH`, when its environment
can't be read, or after a debugger attached to it. See
[scoring](scoring.md#when-an-allowlist-is-withheld).

| Key                                 | Forgives                     |
| ----------------------------------- | ---------------------------- |
| `excluded_parent_processes` (paths) | `tmp_exec`                   |
| `memfd_callers` (paths)             | `memfd_create`, `memfd_exec` |
| `ptrace_tracers` (paths)            | `ptrace_system_daemon`       |
| `scan_binaries` (paths)             | `egress_scan`                |
| `excluded_selinux_domains` (types)  | `tmp_exec`, `memfd_create`   |
| `pinned` (path = SHA-256)           | nothing on its own           |

- `excluded_parent_processes`: A temp-directory exec is forgiven when the
  parent of the process doing the exec is on this list. Only the immediate
  parent counts.

- `memfd_callers`: Forgives `memfd_create` from a listed binary, and an
  exec of a memfd by a listed binary. `runc` and `crun` need both: they
  copy themselves into a memfd and run that on every container start.

- `ptrace_tracers`: Forgives a listed debugger attaching to a system daemon.

- `scan_binaries`: Forgives an egress scan from a listed binary, but only
  when it runs as root (uid 0) and has a controlling terminal: someone is
  at the keyboard.

- `excluded_selinux_domains`: SELinux types, such as `"rpm_t"`. A process
  running in one is forgiven `tmp_exec` and `memfd_create`. `unconfined_t`
  is ignored even if listed, and listing it prints a warning: every root
  shell runs in it.

- `pinned`: Trust a binary that isn't in the RPM database. The key is its
  absolute path, the value its SHA-256 as exactly 64 hex characters. A
  pinned binary whose hash doesn't match verifies as `modified`. A pin is
  checked before the RPM database, so pinning an RPM-owned path replaces
  the RPM check for it. Pinning makes a binary verify; it still needs to
  be on one of the lists above to be forgiven anything.

```toml
[allowlist]
scan_binaries = ["/opt/tools/scanner"]

[allowlist.pinned]
"/opt/tools/scanner" = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

## Drop-ins

Files in `/etc/aegis-v2/allowlist.d/` ending in `.toml` are read after
the main file, in lexical order. Files starting with a dot are skipped.
A drop-in may contain only an `[allowlist]` table.

Lists in drop-ins add to the main file's lists. A pin for a path that's
already pinned replaces the earlier pin, so a later file can re-pin a
binary.

Put your own rules in a file that sorts after the shipped one, such as
`50-site.toml`, so a package upgrade never touches them.

## The default allowlist

`allowlist.d/00-default.toml`, as shipped:

- `excluded_parent_processes`: `/usr/bin/ansible-playbook`,
  `/usr/bin/dnf`, `/usr/bin/rpm`, `/usr/bin/podman`, `/usr/bin/cargo`,
  `/usr/bin/pip3`
- `memfd_callers`: `/usr/bin/podman`, `/usr/bin/pipewire`,
  `/usr/bin/gnome-shell`, `/usr/bin/runc`, `/usr/bin/crun`,
  `/usr/lib/systemd/systemd`, `/usr/libexec/cockpit-tls`
- `ptrace_tracers`: `/usr/bin/gdb`, `/usr/bin/strace`, `/usr/bin/perf`
- `scan_binaries`: `/usr/bin/nmap`
- `excluded_selinux_domains`: empty, on purpose

systemd and cockpit-tls are there because systemd 255 and later hands
each unit's settings to `systemd-executor` in a memfd, and cockpit-tls
creates memfds as it serves. Without them, pid 1 alone would score on
every unit start.

## `[quarantine]`

| Key                   | Type    | Default | Rule |
| --------------------- | ------- | ------- | ---- |
| `overlay_max_size_mb` | integer | `512`   | ≥ 1  |
| `auto_expire_seconds` | integer | `3600`  | ≥ 1  |

Both are validated and otherwise unused in v0.1. They're reserved for
the quarantine box planned for later releases (see the
[roadmap](roadmap.md)).

## `[incidents]`

| Key   | Type | Default                         |
| ----- | ---- | ------------------------------- |
| `dir` | path | `"/var/lib/aegis-v2/incidents"` |

- `dir`: Where incidents are written. The systemd unit only lets aegisd write
  under `/var/lib/aegis-v2`, and so does the SELinux policy, so keep it
  there.

## `[telemetry]`

journald is always on and has no setting. The other two sinks are off
until you add them.

| Key     | Type  | Default |
| ------- | ----- | ------- |
| `jsonl` | path  | unset   |
| `otlp`  | table | unset   |

- `jsonl`: Append one JSON line per record to this file, created with mode 0600.
  It has to live under `/var/log/aegis-v2`: the unit makes the rest of
  the filesystem read-only, and the SELinux policy agrees.

### `[telemetry.otlp]`

| Key            | Type    | Default    |
| -------------- | ------- | ---------- |
| `endpoint`     | string  | (required) |
| `headers`      | table   | empty      |
| `timeout_secs` | integer | `5`        |

- `endpoint`: Base URL of an OTLP/HTTP collector, `http://` or `https://`.
  Records go to `<endpoint>/v1/logs`, unless the endpoint already ends in
  `/v1/logs`. A URL with credentials (`user:pass@host`) is rejected; use
  `headers`.

- `headers`: Extra HTTP headers on every request, typically for a token.
  Names must be valid HTTP tokens and values can't hold control
  characters. Values are never logged.

- `timeout_secs`: Per-request timeout, at least 1.

```toml
[telemetry]
jsonl = "/var/log/aegis-v2/events.jsonl"

[telemetry.otlp]
endpoint = "https://otel.example.com:4318"
timeout_secs = 5

[telemetry.otlp.headers]
Authorization = "Bearer <token>"
```

OTLP needs one more step on an SELinux host; see
[telemetry](telemetry.md#otlp).

The config file is mode 0600 in a 0750 directory, root only, because it
may hold that token.

## Command-line flags

The unit runs `aegisd` with no flags. These exist for testing and
`--check-config`:

- `--config <path>`: the main file. Default `/etc/aegis-v2/config.toml`.
- `--allowlist-dir <dir>`: the drop-in directory. Default: `allowlist.d`
  beside `--config`.
- `--socket <path>`: the control socket. Default
  `/run/aegis-v2/aegisd.sock`.
- `--check-config`: load and check the configuration, print any
  warnings, and exit.
- `--debug`: log every scoring decision to stderr, which the unit sends
  to journald.
- `--version`, `--help`.
