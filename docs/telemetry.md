# Telemetry

Every recorded incident decision produces one telemetry record, sent to
up to four sinks. That's the first decision at the throttle tier or
above, and after it, only the ones that add something: the incident's
tier rose, a process showed a signal kind for the first time, or 60
seconds have passed since the incident last recorded. Repeats and
decisions below the throttle tier produce none.

| Sink       | On by default | Configured in           |
| ---------- | ------------- | ----------------------- |
| journald   | always        | nothing to configure    |
| JSON lines | no            | `[telemetry] jsonl`     |
| OTLP       | no            | `[telemetry.otlp]`      |
| Webhooks   | no            | `[[telemetry.webhook]]` |

Webhooks are the odd one out: they hear about fewer records, not more.
See [Webhooks](#webhooks).

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
| verdict    | one of the four [verdicts](incidents.md#verdicts)    |
| tier       | `throttle` or `quarantine`                           |
| score      | the decision's score                                 |
| mode       | `audit` or `enforce`                                 |
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
| `AEGIS_VERDICT`     | the verdict, as in the record above        |
| `AEGIS_MODE`        | `audit` or `enforce`                       |
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

Every 60 seconds aegisd also sends its counters to
`<endpoint>/v1/metrics`, with the same headers and resource attributes.
They share the logs' queue, so a failed or dropped metrics POST is
counted in the same `otlp` drop counts, and metrics go out only when
`[telemetry.otlp]` is set. The first batch arrives 60 seconds after
start.

Sums are cumulative and monotonic, counting from daemon start. Gauges
are the value at that moment.

- `aegis.events` (sum): probe events processed.
- `aegis.events.dropped` (sum): events lost before aegisd read them.
- `aegis.enforce.actions` (sum): enforcement actions, with a `result`
  attribute of `ok` or `failed`.
- `aegis.telemetry.dropped` (sum): records lost across all sinks.
- `aegis.incidents.open` (gauge): incidents currently open.
- `aegis.incidents` (gauge): open incidents, with a `verdict` attribute
  such as `would_throttle`.
- `aegis.honeypot.sessions` (sum): honeypot sessions, with a `result`
  attribute: `filed` into their incident, `unmatched` (no incident had
  the address) or `rejected` (the spool entry failed a check). Both of
  the last two are deleted. It only appears once there's been one.

## Webhooks

Journald is for the log you read afterwards. A webhook is for the
moment an incident opens and nobody is reading anything. aegisd posts to
a URL you choose each time an incident's verdict rises, and whenever
enforcement fails. A busy incident whose verdict stays put sends
nothing more.

```toml
[[telemetry.webhook]]
url = "https://hooks.slack.com/services/<path>"
format = "slack"

[[telemetry.webhook]]
url = "https://alerts.example.com/aegis"
format = "json"
timeout_secs = 5

[telemetry.webhook.headers]
Authorization = "Bearer <token>"
```

Repeat `[[telemetry.webhook]]` for as many targets as you like; each has
its own queue and thread. `format` is `json` (the default) or `slack`.
`timeout_secs` defaults to 5. A URL can't carry `user:pass@`; put
credentials in `headers`. Header values and the URL stay out of
logs. The same SELinux boolean as OTLP applies
(`aegisd_can_network_connect`), and `https://` is checked against the
system trust store.

### When it sends

A webhook sends in audit mode and in enforce mode. Verdicts rank
`would_throttle`, `throttled`, `would_quarantine`, `quarantined`, and a
webhook sends the first record for an incident at each rank above the
last one it sent. In audit mode that's at most two: `would_throttle`
tells you what enforce mode would have done. In enforce mode the
prediction goes out first and the action follows once it worked, so a
quarantine typically sends `would_quarantine`, then `quarantined` with
a reason such as `enforcement done: members held, moved, frozen, egress
dropped`. A throttle's reads `enforcement done: moved into a CPU and
memory limited scope`.

It also sends every enforcement failure, whatever its rank, with a
reason starting `enforcement failed:` or `enforcement skipped:`. That
includes a throttle or quarantine dropped because the enforcer's queue
was full: `enforcement failed: queue full, nothing was done`.

It doesn't send a second record at a rank it has already reported. The
webhook remembers its last 4,096 incidents; past that it forgets them
all and an old incident that records again may notify again.

### Payloads

`json` posts one object per record:

```json
{
  "incident": "AEG-20261021-093000-0123456789abcdef",
  "verdict": "would_throttle",
  "score": 62.0,
  "mode": "audit",
  "tgid": 4242,
  "comm": "x",
  "exe": "/tmp/x",
  "reasons": ["exec from a temp directory (/tmp/x)"],
  "ts": "2026-10-21T09:30:00Z"
}
```

`slack` posts the same one-line message journald gets, as the only
field Slack needs. For an enforcement failure the reason follows it;
the verdict says when enforcement worked.

<!-- markdownlint-disable MD013 -->
```json
{
  "text": "aegis would_throttle incident AEG-20261021-093000-0123456789abcdef score 62.0 tgid 4242 comm x exe /tmp/x"
}
```
<!-- markdownlint-enable MD013 -->

### Retries and drops

Each webhook queues 256 bodies for one worker thread, so a slow endpoint
never slows scoring. A body gets up to three attempts, waiting 1 second
after the first failure and 2 seconds after the second. Any network
error, timeout or non-2xx answer is a failed attempt. While a body
retries, the ones behind it wait.

Two counters in `aegisctl status` show losses, summed over all your
webhooks:

- `telemetry dropped: webhook queue full`: the queue was full, so the
  new record was discarded.
- `telemetry dropped: webhook failed`: a body failed all three attempts
  and was discarded.

aegisd logs the first failure in a run, without the URL, and stays quiet
until a post succeeds again.
