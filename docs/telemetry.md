# Telemetry

Every recorded incident decision produces one telemetry record, sent to
up to three sinks. That's the first decision at the throttle tier or
above, and after it, only the ones that add something: the incident's
tier rose, a process showed a signal kind for the first time, or 60
seconds have passed since the incident last recorded. Repeats and
decisions below the throttle tier produce none.

| Sink       | On by default | Configured in        |
| ---------- | ------------- | -------------------- |
| journald   | always        | nothing to configure |
| JSON lines | no            | `[telemetry] jsonl`  |
| OTLP logs  | no            | `[telemetry.otlp]`   |

Every sink is best effort. A sink that fails logs the problem and counts
what it lost; it never slows down or stops scoring. `aegisctl status`
shows the counts as `telemetry dropped: ...`.

Telemetry settings are read at startup. After changing them, run
`systemctl restart aegisd`; a reload says the change waits for a
restart.

## The record

Every sink carries these facts:

| Fact       | Meaning                                              |
| ---------- | ---------------------------------------------------- |
| incident   | the incident id                                      |
| verdict    | `would_throttle` or `would_quarantine`               |
| tier       | `throttle` or `quarantine`                           |
| score      | the decision's score                                 |
| mode       | `audit`                                              |
| tgid       | the process the decision was about                   |
| comm       | its self-reported name                               |
| path       | its executable, as UTF-8 with invalid bytes replaced |
| path_b64   | the exact executable path bytes, base64              |
| target     | for an exec signal, the file it started, UTF-8       |
| target_b64 | the exact target path bytes, base64                  |
| reasons    | the process's evidence reasons, oldest first         |

For an exec, `path` is the binary that did the exec and `target` is the
file it ran. Other signals have no target.

## journald

Records go to the journal directly over its native socket, as
structured entries:

| Field               | Value                                      |
| ------------------- | ------------------------------------------ |
| `MESSAGE`           | a one-line summary, below                  |
| `PRIORITY`          | 4 for throttle, 2 for quarantine           |
| `SYSLOG_IDENTIFIER` | `aegisd`                                   |
| `AEGIS_INCIDENT`    | the incident id                            |
| `AEGIS_SCORE`       | the score, one decimal place               |
| `AEGIS_TIER`        | `throttle` or `quarantine`                 |
| `AEGIS_VERDICT`     | `would_throttle` or `would_quarantine`     |
| `AEGIS_MODE`        | `audit`                                    |
| `AEGIS_TGID`        | the process id                             |
| `AEGIS_COMM`        | the process name                           |
| `AEGIS_EXE`         | the executable path, UTF-8                 |
| `AEGIS_EXE_B64`     | the exact path bytes, base64               |
| `AEGIS_TARGET`      | the exec'd file, UTF-8 (exec signals only) |
| `AEGIS_TARGET_B64`  | its exact path bytes (exec signals only)   |
| `AEGIS_REASON`      | one field per evidence reason              |

journald keeps every value of a repeated field, so `AEGIS_REASON`
appears once per reason.

`MESSAGE` names the target when there is one, and escapes control,
line-separator and bidirectional characters in the name and paths the
way `aegisctl` prints them, so a hostile path can't break the line. The
exact bytes are in the `*_B64` fields. It reads like this, on one line:

<!-- markdownlint-disable MD013 -->
```text
aegis would_quarantine incident AEG-20261019-093000-0123456789abcdef score 85.0 tgid 4242 comm aegis-sim exe /usr/local/bin/aegis-sim target /memfd:aegis-sim (deleted)
```
<!-- markdownlint-enable MD013 -->

Some queries:

```sh
journalctl -t aegisd AEGIS_VERDICT=would_quarantine
journalctl -t aegisd AEGIS_INCIDENT=AEG-20261019-093000-0123456789abcdef -o json
journalctl -t aegisd -p crit --since today
```

Other field values that contain a newline are sent in journald's
binary-safe form, so a hostile path can't forge extra fields. aegisd's own log
messages (startup, reload, errors) go to the journal too, through the
unit's stderr, under the `aegisd.service` unit.

If journald restarts, aegisd reconnects, at most once a second.
Records lost meanwhile, or to a full socket buffer, count as
`telemetry dropped: journald`.

## JSON lines

```toml
[telemetry]
jsonl = "/var/log/aegis-v2/events.jsonl"
```

One JSON object per line, appended to a file aegisd creates with mode
0600:

```json
{"comm": "aegis-sim",
 "incident": "AEG-20261019-093000-0123456789abcdef",
 "mode": "audit", "path": "/usr/local/bin/aegis-sim",
 "path_b64": "L3Vzci9sb2NhbC9iaW4vYWVnaXMtc2lt",
 "reasons": ["memfd_create",
             "exec of a memfd (/memfd:aegis-sim (deleted))"],
 "score": 85.0, "target": "/memfd:aegis-sim (deleted)",
 "target_b64": "L21lbWZkOmFlZ2lzLXNpbSAoZGVsZXRlZCk=",
 "tgid": 4242, "tier": "quarantine", "ts": "2026-10-19T09:30:02Z",
 "verdict": "would_quarantine"}
```

That's one line in the file, wrapped here to fit the page.

`target` and `target_b64` are `null` for signals that aren't an exec.
`reasons` lists the process's evidence, oldest first, as in
[incidents](incidents.md#evidence-entries).

The file has to live under `/var/log/aegis-v2`. Anywhere else, the
systemd unit's read-only filesystem and the SELinux policy both stop
aegisd from opening it, and it logs `telemetry jsonl <path>: <error>` at
startup and carries on without the sink.

aegisd doesn't rotate the file. Use logrotate with `copytruncate`,
because aegisd keeps the file open:

```text
/var/log/aegis-v2/events.jsonl {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
```

Save that as `/etc/logrotate.d/aegis-v2`.

## OTLP

aegisd can send records as OpenTelemetry logs to any collector that
accepts OTLP over HTTP with JSON bodies.

```toml
[telemetry.otlp]
endpoint = "https://otel.example.com:4318"
timeout_secs = 5

[telemetry.otlp.headers]
Authorization = "Bearer <token>"
```

On an SELinux host, aegisd can't open a network socket until you allow
it:

```sh
setsebool -P aegisd_can_network_connect 1
systemctl restart aegisd
```

### What gets sent

Records go in batches by `POST` to `<endpoint>/v1/logs` (or to the
endpoint as given, if it already ends in `/v1/logs`), with
`Content-Type: application/json` and your headers. A batch is sent when
it holds 512 records or one second after its first record, whichever
comes first.

Resource attributes: `service.name` = `aegisd`, `service.version`, and
`host.name`. Each log record has:

| OTLP field       | Value                                                |
| ---------------- | ---------------------------------------------------- |
| `timeUnixNano`   | when the record was made                             |
| `severityNumber` | 13 (WARN) for throttle, 17 (ERROR) for quarantine    |
| `severityText`   | `WARN` or `ERROR`                                    |
| `body`           | the same one-line message as journald                |
| attributes       | `aegis.*`, one per fact in [the record](#the-record) |

The attributes are `aegis.incident`, `aegis.verdict`, `aegis.tier`,
`aegis.score`, `aegis.mode`, `aegis.tgid`, `aegis.comm`, `aegis.path`,
`aegis.path_b64` and `aegis.reasons`, plus `aegis.target` and
`aegis.target_b64` on exec signals. All are strings except
`aegis.reasons`, an array of strings.

### TLS

`https://` endpoints are verified against the system trust store. On
Rocky that's the bundle `update-ca-trust` manages, so a private CA you've
added there works.

### Failure handling

Records wait in a queue of 4,096. When it's full, new records are
dropped and counted as `otlp queue full`. A batch the collector doesn't
accept (a network error, a timeout, a non-2xx response) is dropped and
counted as `otlp export failed`; aegisd logs the first failure in a run
and stays quiet until an export succeeds again. There's no retry.

### Metrics

OTLP metrics aren't in v0.1; they're planned for v0.2.0 (see the
[roadmap](roadmap.md)). Until then, `aegisctl status --json` gives you
the counters to scrape.
