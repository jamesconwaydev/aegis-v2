# Incidents

An incident is aegisd's record of one process tree that reached the
throttle tier: who was involved, what they did, and how high the score
went.

## How an incident forms

1. A process's own score reaches `score_threshold_throttle` (50). aegisd
   opens an incident with that process as its root.
2. Later decisions about that process, or about any process with an
   ancestor that is already a member, go to the same incident. When
   several ancestors are members, the nearest one decides.
3. A decision at throttle or above is recorded, appended to the
   timeline and sent to telemetry, only when it adds something: the
   incident's tier rose, this process showed this signal kind for the
   first time, or 60 seconds have passed since the incident last
   recorded anything. Repeats are counted in `aegisctl status` as
   `incident repeats not recorded`, and nothing else. When a member
   exits, the signal kinds it showed are forgotten.
4. The verdict only moves up, in this order: `would_throttle`,
   `throttled`, `would_quarantine`, `quarantined`. Once an incident has
   reached one, it never goes back.

The rules for the incident score are in
[scoring](scoring.md#incidents-and-process-trees).

Incidents never close in v0.1. Every incident counts as open, and
`aegisctl status` reports how many are loaded as `open incidents`.

## Where they live

```text
/var/lib/aegis-v2/incidents/
└── AEG-20261019-093000-0123456789abcdef/
    ├── incident.json     the summary, rewritten on every record
    └── timeline.jsonl    one line per record, append-only
```

The directory is set by `[incidents] dir`. Directories are mode 0700
and files 0600, owned by root. `incident.json` is written to a temporary
file, synced, renamed into place, and the directory synced, so a crash
never leaves a half-written summary.

### Incident ids

`AEG-<date>-<time>-<16 hex digits>`: the date and time in UTC when the
incident opened, then 64 random bits in lowercase hex. For example,
`AEG-20261019-093000-0123456789abcdef` opened at 09:30:00 UTC on
19 October 2026. aegisd and `aegisctl` accept only that exact shape,
and `aegisctl` turns anything else away before asking the daemon.

### What aegisd loads at startup

At startup aegisd reads every incident updated in the last 30 days.
Those from the current boot (same `boot_id`) keep their memberships, so
a process already in an incident stays in it across a daemon restart.

`aegisctl incidents list` shows only those loaded incidents. Older ones
stay on disk, and `aegisctl incidents show <id>` still finds them by id.

v0.1 never deletes an incident. Remove old directories yourself when you
no longer need them.

## `incident.json`

```json
{
  "id": "AEG-20261019-093000-0123456789abcdef",
  "created": "2026-10-19T09:30:00Z",
  "updated": "2026-10-19T09:30:02Z",
  "updated_ns": 1792402202000000000,
  "boot_id": "6f1c0d2e-…",
  "mode": "audit",
  "verdict": "would_quarantine",
  "max_score": 85.0,
  "score": 85.0,
  "root": { "tgid": 4242, "…": "…" },
  "process_tree": [ { "tgid": 4242, "…": "…" } ],
  "evidence": [ { "signal": "MemfdExec", "…": "…" } ],
  "evidence_truncated": false,
  "process_tree_truncated": false,
  "timeline_lines": 1,
  "actions": []
}
```

| Field                    | Meaning                                     |
| ------------------------ | ------------------------------------------- |
| `id`                     | the incident id, same as the directory name |
| `created`, `updated`     | UTC, RFC 3339, to the second                |
| `updated_ns`             | `updated` in Unix nanoseconds               |
| `boot_id`                | the boot the process ids belong to          |
| `mode`                   | `audit` in v0.1                             |
| `verdict`                | see [Verdicts](#verdicts)                   |
| `max_score`              | the highest score recorded                  |
| `score`                  | the score at the last update                |
| `root`                   | the process that opened the incident        |
| `process_tree`           | the members, root first, up to 4096         |
| `process_tree_truncated` | `true` once the 4096 cap kept a member out  |
| `evidence`               | every distinct piece of evidence, up to 256 |
| `evidence_truncated`     | `true` once the 256 cap dropped something   |
| `timeline_lines`         | lines in `timeline.jsonl`, marker included  |
| `actions`                | what enforce mode did, see below            |

### Verdicts

`would_throttle` and `would_quarantine` are predictions: audit mode
records what the tier called for and touches nothing. From v0.2.0,
enforce mode can also write `throttled` and `quarantined`, and only
after the action succeeded. If it failed, the verdict stays at
`would_*` and the failure is in `actions`. A verdict never moves down.

### Action entries

From v0.2.0, each thing enforce mode does to an incident's processes is
appended to `actions`, oldest first. The list is empty in audit mode,
and in incidents written before v0.2.0. Releasing or killing an
incident reads the unit names and nft handles from here, so they
survive a restart.

| Field        | Meaning                                              |
| ------------ | ---------------------------------------------------- |
| `kind`       | what was done, see below                             |
| `ok`         | `true` if it worked                                  |
| `unit`       | the systemd unit involved, if any                    |
| `nft_handle` | the nftables rule handle involved, if any            |
| `pids`       | the process ids it applied to                        |
| `error`      | why it failed, when `ok` is `false`                  |
| `ts`         | when it happened, UTC, RFC 3339                      |

`kind` is one of:

| Value         | Meaning                                     |
| ------------- | ------------------------------------------- |
| `hold`        | resource limits put on the processes        |
| `scope`       | the processes moved into their own scope    |
| `freeze`      | the processes frozen                        |
| `nft_drop`    | an nftables rule dropping their traffic     |
| `thaw`        | frozen processes resumed                    |
| `unhold`      | resource limits removed                     |
| `nft_remove`  | the nftables rule deleted                   |
| `kill`        | the processes killed                        |
| `lift_limits` | every limit lifted                          |

### Process entries

`root` and each `process_tree` entry:

| Field            | Meaning                                            |
| ---------------- | -------------------------------------------------- |
| `tgid`           | process id                                         |
| `start_time_ns`  | start time, nanoseconds since boot (monotonic)     |
| `exe`            | executable path, as UTF-8 (invalid bytes replaced) |
| `exe_b64`        | the exact path bytes, base64                       |
| `comm`           | the process's own name for itself; never trusted   |
| `uid`            | user id                                            |
| `selinux_domain` | full SELinux context, if known                     |
| `verification`   | see below                                          |

Each entry is the process as it was when it joined. A process that
joins at an exec is recorded as the image the exec started, not the one
that did the exec.

`verification` is one of:

| Value                 | Meaning                                      |
| --------------------- | -------------------------------------------- |
| `rpm_owned:<package>` | owned by that package and unchanged          |
| `pinned`              | matches the SHA-256 pinned in the config     |
| `modified`            | RPM-owned or pinned, but the content differs |
| `unverified`          | anything else; see below                     |

`unverified` covers a binary no allowlist entry or pin names (aegisd
never checks those), one rpm doesn't own, one rpm couldn't answer for,
a symlink, FIFO or device at the path, and a file other than the one the
kernel executed. It's also what a process shows while its check is
still running.

Members past the 4096 cap still join the incident while aegisd runs,
but they aren't listed, so after a restart aegisd doesn't know they
belong to it.

A path can hold any byte, including newlines and terminal escapes. Use
`exe_b64` when you need the exact bytes. `aegisctl` escapes control and
bidirectional characters before printing either.

### Evidence entries

| Field      | Meaning                                              |
| ---------- | ---------------------------------------------------- |
| `signal`   | which signal, see below                              |
| `base`     | the signal's weight                                  |
| `modifier` | minus the weight if an allowlist forgave it, else 0  |
| `reason`   | a readable explanation                               |
| `ts_ns`    | when it happened, nanoseconds since boot (monotonic) |

`signal` is one of `tmp_exec`, `memfd_create`, `memfd_exec`,
`ptrace_system_daemon` or `egress_scan`, the same names as the weights
in `[scoring.weights]`. Incidents written by v0.1.0 used Rust-style
names instead, such as `TmpExec`.

`reason` reads like `exec of a memfd (/memfd:x (deleted))`,
`memfd_create; caller is allowlisted`, or
`memfd_create; allowlist withheld: LD_PRELOAD, LD_AUDIT or
LD_LIBRARY_PATH is set`. In brackets at
the end:

- for the two exec signals, the file that was executed;
- for `ptrace_system_daemon`, the pid that was attached to;
- for `egress_scan`, how many distinct (address, port) pairs the
  process had connected to when the scan was flagged.

`ts_ns` counts from boot, so it only converts to a wall-clock time
within the same boot. `aegisctl incidents show` does that conversion
when `boot_id` matches the running boot, and otherwise prints
`boot+<seconds>s`.

## `timeline.jsonl`

One JSON object per line, one line per recorded decision:

```json
{"evidence":[…],"score":85.0,"start_time_ns":81234567890,"tgid":4242,"tier":"quarantine","ts":"2026-10-19T09:30:02Z","verdict":"would_quarantine"}
```

| Field           | Meaning                                    |
| --------------- | ------------------------------------------ |
| `ts`            | when it was recorded, UTC                  |
| `tgid`          | the process the decision was about         |
| `start_time_ns` | that process's start time                  |
| `tier`          | `throttle` or `quarantine`                 |
| `verdict`       | the incident's verdict after this line     |
| `score`         | the decision's score                       |
| `evidence`      | the one evidence entry this decision added |

A line for actions has `ts`, `actions` (the entries added) and
`verdict`, and no `tgid` or `evidence`.

Earlier evidence is on earlier lines. A timeline stops at 10,000 lines.
One marker line follows (shown wrapped here), and then nothing more is
appended, though `incident.json` keeps updating:

```json
{"note": "timeline truncated at 10000 lines", "truncated": true,
 "ts": "2026-10-19T11:02:41Z"}
```

`aegisctl incidents timeline` prints the marker as a row.

## Reading incidents

```sh
aegisctl incidents list
aegisctl incidents show AEG-20261019-093000-0123456789abcdef
aegisctl incidents timeline AEG-20261019-093000-0123456789abcdef
```

Add `--json` to any of them for the raw data. See
[aegisctl](aegisctl.md) for the output of each.

## When writes fail

Incident writes happen on their own thread, so a slow disk never holds
up scoring. If the thread's 256-entry queue fills, the decision is
dropped and counted as `incidents dropped` in `aegisctl status`, and its
telemetry isn't sent either. Nothing counts as said, so the next
decision in that incident is recorded and sent in its place. A write
that fails on disk is logged and counted as `incident write errors`;
its telemetry has already gone out.
