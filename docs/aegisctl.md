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

| Code | Meaning                                              |
| ---- | ---------------------------------------------------- |
| 0    | success                                              |
| 1    | an error (printed to stderr), or a preflight `FAIL`  |
| 2    | preflight only: warnings, no failures                |

A refused `incidents release` or `incidents kill` is an error too.

## `status`

```sh
aegisctl status
```

Shows the daemon's version, mode and health counters, then its probes.

```text
version                                0.2.3
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
telemetry dropped: webhook queue full  0
telemetry dropped: webhook failed      0

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
- **open incidents** (`incidents_open`): incidents loaded. Incidents
  don't close yet, so that's all of them.
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
- **enforce jobs dropped** (`enforce_dropped`): enforcer jobs dropped
  without running: lost to a full queue, or still queued when a reload
  switched to audit mode. That includes the jobs for children a tree
  forks after it's enforced, which can only take half the queue, so a
  forking tree can't crowd out a new throttle or quarantine. A dropped
  throttle or quarantine is also logged and sent to telemetry as
  `enforcement failed: queue full, nothing was done`; dropped child
  jobs are logged once per burst.
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
ID                                    VERDICT           STATE     SCORE  ROOT PID  CREATED               UPDATED
AEG-20261019-093000-0123456789abcdef  would_quarantine  -         85.0   4242      2026-10-19T09:30:00Z  2026-10-19T09:30:02Z
AEG-20261020-141500-fedcba9876543210  quarantined       released  92.5   5150      2026-10-20T14:15:00Z  2026-10-20T14:31:40Z
```
<!-- markdownlint-enable MD013 -->

`VERDICT` is history: what aegisd decided, and it never goes back down.
`STATE` (from v0.2.1) is what's in place right now:

| `STATE`       | What it means                                              |
| ------------- | ---------------------------------------------------------- |
| `throttled`   | the tree runs in its CPU- and memory-limited scope         |
| `quarantined` | the tree is in its quarantine scope, frozen                |
| `held`        | kernel holds only: the move or the freeze failed           |
| `released`    | you ended it with `incidents release`                      |
| `killed`      | you ended it with `incidents kill`                         |
| `expired`     | it's from an earlier boot, so nothing of it is left        |
| `-`           | nothing was ever enforced, as in every audit-mode incident |

The second row above, then, was quarantined and later let go. One
catch with `held`: the holds live in aegisd, so an aegisd restart lifts
them and the tree runs free, while the list still says `held`. Release
or kill it before you restart. `--json` carries the same value as
`state`, or `null` for `-`.

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

In enforce mode, each batch of actions gets a row too: `enforcement`,
the steps in order (a failed one marked `(failed)`), `-` where the score
goes, and the verdict after them.

```text
2026-10-19T09:30:03Z  enforcement  hold, scope, freeze, nft drop  -  quarantined
```

A timeline that reached its 10,000-line cap ends with a row saying
`timeline truncated at 10000 lines`.

With `--json`, you get the lines of `timeline.jsonl` as a JSON array;
see [incidents](incidents.md#timelinejsonl).

## `incidents release <id>`

From v0.2.0.

```sh
aegisctl incidents release AEG-20261019-093000-0123456789abcdef
```

Undoes what enforce mode did to an incident. A quarantined tree loses
its kernel holds while it's still frozen, then is thawed and gets its
network back; a throttled one loses its CPU and memory limits. The tree
stays in its scope, so a released quarantine's accounting remains under
`aegis-quarantine.slice`.

```text
released AEG-20261019-093000-0123456789abcdef: thawed, network restored
```

A throttle prints `released <id>: limits lifted` instead. It works from
the actions recorded on the incident, so it still works after a daemon
restart, and after you've switched `mode` back to `"audit"`.

After a reboot there's nothing left to release: the scope, the freeze
and the nftables rule went with the old boot. Release of an incident
from an earlier boot runs nothing, records it as ended, and answers
`<id> is from an earlier boot; nothing of it is left on this host`.

It refuses, with exit code 1, an incident that was never enforced
(`<id> was never enforced`) and one already released
(`<id> is already released`).

With `--json`, you get `{"done": "<the line above>"}`.

## `incidents kill <id>`

From v0.2.0.

```sh
aegisctl incidents kill AEG-20261019-093000-0123456789abcdef
```

Sends SIGKILL to a quarantined tree, frozen or not, and removes its
network rule. It prints `killed <id>`.

A throttled incident has nothing to kill: aegisctl says
`<id> was only throttled; release it instead`. Kill also refuses an
incident that was never enforced or was already released or killed.
Every refusal exits 1. Like release, kill of an incident from an
earlier boot runs nothing and records it as ended.

With `--json`, you get `{"done": "killed <id>"}`.

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
- `aegisd: enforcer busy, try again`: release and kill (from v0.2.0)
  found the enforcer's queue full.
- ``aegisd: still queued; check `aegisctl incidents show <id>` shortly``:
  the enforcer was still busy after 25 s. Your request isn't lost. It
  runs when the enforcer gets to it, so don't send it again.
  (Before v0.2.1 this said `timed out waiting for the enforcer`.)

Replies over 16 MiB are refused rather than read.

## The protocol

For scripts that want to skip `aegisctl`: connect to the socket as
root, write one JSON request per line, read one JSON response per line.
Requests are `"Status"`, `"IncidentsList"`,
`{"IncidentShow":{"id":"<id>"}}` and
`{"IncidentTimeline":{"id":"<id>"}}`, and from v0.2.0
`{"IncidentRelease":{"id":"<id>"}}` and `{"IncidentKill":{"id":"<id>"}}`,
which answer `{"Done":"<message>"}`. An error comes back as
`{"error":"<message>"}`.

```sh
echo '"Status"' | socat - UNIX-CONNECT:/run/aegis-v2/aegisd.sock
```

The protocol may change before 1.0; `aegisctl --json` is the more
stable interface.
