# aegisctl

`aegisctl` asks a running aegisd what it has seen, and checks whether a
host can run aegisd at all. Every command except `preflight` talks to
the daemon over its control socket, which only root can use.

```text
aegisctl [--socket <path>] [--json] <command>
```

## Global flags

- `--socket <path>`: the control socket. Default
  `/run/aegis-v2/aegisd.sock`.
- `--json`: print JSON instead of a table.
- `--help`, `--version`.

`--json` works on every command and can go before or after it.

## Exit codes

| Code | Meaning                                             |
| ---- | --------------------------------------------------- |
| 0    | success                                             |
| 1    | an error (printed to stderr), or a preflight `FAIL` |
| 2    | preflight only: warnings, no failures               |

## `status`

```sh
aegisctl status
```

Shows the daemon's version, mode and health counters, then its probes.

```text
version                                0.1.0
mode                                   audit
uptime                                 2h 14m
events                                 1843920
dropped events                         0
open incidents                         1
incident write errors                  0
incidents dropped                      0
verifications skipped                  0
defer queue overflows                  0
incident repeats not recorded          0
telemetry dropped: journald            0
telemetry dropped: otlp queue full     0
telemetry dropped: otlp export failed  0
telemetry dropped: otlp disconnected   0

probes
  aegis_exec_check   lsm/bprm_check_security
  aegis_exec         lsm/bprm_committed_creds
  ...
```

What each row means, with its key in `--json` output:

- **version** (`version`), **mode** (`mode`), **uptime** (`uptime_s`).
- **events** (`events_total`): probe events processed.
- **dropped events** (`dropped_events`): events the kernel ring buffer
  had no room for.
- **open incidents** (`incidents_open`): incidents loaded. All of them
  are open in v0.1.
- **incident write errors** (`incident_errors`): incident writes that
  failed.
- **incidents dropped** (`incident_dropped`): decisions lost to a full
  incident writer queue.
- **verifications skipped** (`verify_skipped`): execs left unverified
  because 1,024 verifications were already in flight.
- **defer queue overflows** (`deferred_overflow`): signals scored
  without waiting for verification, because the process already had 64
  waiting or 8,192 were waiting in all.
- **incident repeats not recorded** (`incident_suppressed`): decisions
  inside an open incident that weren't recorded or sent to telemetry,
  because they added nothing new. This one grows in normal use.
- **telemetry dropped: ...** (`telemetry_dropped`): records each sink
  lost.
- **probes** (`probes`): each probe's name and hook.

Every counter counts from when aegisd started. Apart from `events` and
`incident repeats not recorded`, anything other than 0 means some events
or records were lost; see
[troubleshooting](troubleshooting.md#counters-in-aegisctl-status).

## `preflight`

```sh
aegisctl preflight
```

Checks the host, with or without aegisd installed. The checks, their
fixes and the exit codes are in [preflight](preflight.md). Output is in
colour on a terminal, unless `NO_COLOR` is set.

## `incidents list`

```sh
aegisctl incidents list
```

<!-- markdownlint-disable MD013 -->
```text
ID                                    VERDICT           SCORE  ROOT PID  CREATED               UPDATED
AEG-20261019-093000-0123456789abcdef  would_quarantine  85.0   4242      2026-10-19T09:30:00Z  2026-10-19T09:30:02Z
```
<!-- markdownlint-enable MD013 -->

`SCORE` is the highest score the incident reached. The list holds
incidents updated in the last 30 days; older ones are still on disk.
With nothing to show it prints `No incidents.`

## Incident ids

`show` and `timeline` take an id in the exact form
`AEG-YYYYMMDD-HHMMSS-` plus 16 lowercase hex digits. Anything else is
refused before the daemon is asked:

```text
aegisctl: AEG-1 is not an incident id (AEG-YYYYMMDD-HHMMSS- and 16 hex digits)
```

## `incidents show <id>`

```sh
aegisctl incidents show AEG-20261019-093000-0123456789abcdef
```

Prints the summary, the member processes, and the evidence:

<!-- markdownlint-disable MD013 -->
```text
id            AEG-20261019-093000-0123456789abcdef
verdict       would_quarantine
mode          audit
score         85.0 (peak 85.0)
created       2026-10-19T09:30:00Z
updated       2026-10-19T09:30:02Z
root process  pid 4242  /usr/local/bin/aegis-sim (aegis-sim) uid 0  unverified

members (1)
  4242  /usr/local/bin/aegis-sim  unverified

evidence (2)
  TIME                  SIGNAL       BASE  MOD   REASON
  2026-10-19T09:30:02Z  MemfdCreate  20.0  0.00  memfd_create
  2026-10-19T09:30:02Z  MemfdExec    65.0  0.00  exec of a memfd (/memfd:aegis-sim (deleted))
```
<!-- markdownlint-enable MD013 -->

Evidence times are converted from boot-relative timestamps. For an
incident from an earlier boot they print as `boot+<seconds>s (previous
boot)`.

With `--json`, you get `incident.json` exactly; see
[incidents](incidents.md#incidentjson). `show` finds an incident by id
even when it's too old for `list`.

## `incidents timeline <id>`

```sh
aegisctl incidents timeline AEG-20261019-093000-0123456789abcdef
```

One line per recorded decision: time, process, the signal this decision
added, score, and tier.

```text
2026-10-19T09:30:02Z  aegis-sim (4242)  MemfdExec  85.0  quarantine
```

A timeline that reached its 10,000-line cap ends with a row saying
`timeline truncated at 10000 lines`.

With `--json`, you get the lines of `timeline.jsonl` as a JSON array;
see [incidents](incidents.md#timelinejsonl).

## Text from processes

Paths and process names come from whatever ran, and an attacker
controls both. Before printing them, `aegisctl` turns control
characters and bidirectional or zero-width marks into visible escapes
such as `\x1b` or `\u{202e}`, so a crafted name can't rewrite your
terminal. `--json` output is standard JSON escaping.

## Errors

Errors go to stderr, prefixed with `aegisctl:`, with exit code 1.

- `aegisd is not running (no socket at ...)`: the daemon isn't up.
- `aegisctl must run as root`: the socket refused your user.
- `aegisd: no such incident`: no incident has that id.
- `no reply from aegisd within 30 s`: the daemon is stuck or
  overloaded.

Replies over 16 MiB are refused rather than read.

## The protocol

For scripts that want to skip `aegisctl`: connect to the socket as
root, write one JSON request per line, read one JSON response per line.
Requests are `"Status"`, `"IncidentsList"`,
`{"IncidentShow":{"id":"<id>"}}` and
`{"IncidentTimeline":{"id":"<id>"}}`. An error comes back as
`{"error":"<message>"}`.

```sh
echo '"Status"' | socat - UNIX-CONNECT:/run/aegis-v2/aegisd.sock
```

The protocol may change before 1.0; `aegisctl --json` is the more
stable interface.
