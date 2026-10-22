# Troubleshooting

Start with these two commands. Most problems show up in one of them.

```sh
aegisctl preflight
journalctl -u aegisd -n 50
```

## aegisd won't start

### `systemctl status aegisd` shows exit status 78

The config is invalid. The journal has the file, line and column:

```sh
journalctl -u aegisd -n 5
aegisd --check-config
```

Fix the file, then `systemctl start aegisd`. The unit doesn't retry on
status 78, because the same file would fail the same way.

The most common cause in v0.1 is `mode = "enforce"`, which isn't
available yet. Set it back to `"audit"`.

### It fails while loading the probes

The journal shows something like `loading eBPF object`, `attaching ...`
or a missing program. Run `aegisctl preflight`:

- **`bpf-lsm` FAIL:** the BPF LSM isn't enabled, and the exec probes
  can't attach without it. Apply the `grubby` command the check prints
  and reboot. See [preflight](preflight.md#bpf-lsm).
- **`btf` FAIL:** the kernel has no BTF, so aegisd can't find the struct
  offsets it needs.
- **`kernel` FAIL:** the kernel is older than 6.12.

aegisd attaches all nine probes or none, and won't run with a partial
set.

### It keeps restarting with `probe event stream ended`

The kernel side stopped delivering events, and aegisd exited non-zero
so systemd would restart it. If it happens again, report it with the
journal around the restart and your kernel version.

### `another aegisd is running`

A second copy is running, often one started by hand for testing while
the service is also up. Stop one of them. The lock is
`/run/aegis-v2/aegisd.lock`, and it's released when its process exits;
don't delete it.

### `/run/aegis-v2 must be owned by uid 0 and not group or world writable`

Something changed the socket directory's ownership or mode. The unit
creates it as root, 0700. Remove the directory and start the service
again, so systemd recreates it.

## aegisctl can't reach the daemon

- `aegisd is not running (no socket at /run/aegis-v2/aegisd.sock)`:
  check `systemctl status aegisd`.
- `aegisctl must run as root`: the socket only answers root. Use `sudo`.
- `no reply from aegisd within 30 s`: the daemon is alive but not
  answering. Check the journal, and report it as a bug with the output.

## Nothing shows up in `incidents list`

That's normal on a quiet host: most activity scores below 50, and
below-threshold decisions aren't recorded. To see that probes are
working, check that `events` in `aegisctl status` is climbing.

To see every scoring decision, including the ones that stay below the
threshold, run aegisd with `--debug` for a while. One way:

```sh
systemctl stop aegisd
aegisd --debug     # Ctrl-C when done
systemctl start aegisd
```

Each decision prints a line such as:

<!-- markdownlint-disable MD013 -->
```text
aegisd: debug: tgid 4242 comm x score 25.0 tier Log: exec from a temp directory (/tmp/x)
```
<!-- markdownlint-enable MD013 -->

Also check `incidents list` only shows incidents updated in the last 30
days. `incidents show <id>` finds older ones on disk.

## Too many incidents

Work through them as [scoring](scoring.md#baselining-a-host) describes.
Look at each incident's evidence and member verification:

- **A tool you trust, marked `unverified`:** aegisd only checks binaries
  an allowlist entry or pin names, so this is expected for anything not
  listed yet. Add its path to the list for the signal that fired, and
  pin its SHA-256 too if no RPM package owns it.
- **A tool you trust, marked `modified`:** the file no longer matches
  its package or pin. Find out why before you allowlist anything: `rpm
  -V <package>` shows what changed.
- **Evidence that says `allowlist withheld:`:** see the next section.

### Allowlisted, but it still scores

- The binary must verify. Check the incident's `verification` for that
  process.
- The path must be exact and absolute. Allowlists match the resolved
  path the kernel executed, such as `/usr/bin/python3.12`, not the
  symlink you typed. A symlink at a listed or pinned path never
  verifies.
- Look for `allowlist withheld:` in the evidence reason. It means the
  binary verified but the process wasn't trusted:
  - `LD_PRELOAD, LD_AUDIT or LD_LIBRARY_PATH is set`: the process was
    started with one of those loader variables. On a host that
    sets `LD_LIBRARY_PATH` globally (in `/etc/environment` or a profile
    script, say), every allowlisted tool hits this. Remove the global
    setting, or expect these incidents.
  - `its environment could not be read`: the kernel couldn't read the
    environment at exec, it was longer than 32 KiB, or no answer came
    within 1 second. For a process that was already running when aegisd
    started, the answer is a read of `/proc/<pid>/environ`, often lost
    because the process exited first. If it happens for every one of
    those until a restart, see
    [stuck environment reads](#every-allowlisted-process-loses-its-allowlist).
  - `it was the target of a ptrace attach`: a debugger attached to it,
    or to its parent before the fork. The mark clears at the next exec.
- For `excluded_parent_processes`, only the immediate parent of the
  process doing the exec counts.
- For `scan_binaries`, the scanner must run as root and from a terminal.
- After a reload, check the journal for `configuration reloaded`. A
  failed reload keeps the old config and says why.

### Every allowlisted process loses its allowlist

If every allowlisted process that was running before aegisd started
shows `its environment could not be read` until aegisd restarts,
`/proc` environment reads are stuck. A read of a process
whose memory is backed by something that never answers, such as a hung
FUSE filesystem, can block for good, and after 16 of those every
further read is refused. That gives false positives, not missed
detections. `systemctl restart aegisd` clears it.

### An allowlisted RPM binary stays unverified

If the RPM database was broken or unreadable when aegisd checked a
binary, rpm can answer "not owned", and aegisd caches that. Fix the
database (`rpm --rebuilddb`), then `systemctl reload aegisd`, which
empties the cache.

### Binaries on btrfs or overlayfs never verify

On btrfs subvolumes and overlayfs, the device number the kernel reports
for an executed file doesn't match what `stat` reports, so aegisd can't
confirm it's the same file. Those binaries stay `unverified`, and
allowlists don't apply to them. There's no workaround in v0.1; XFS and
ext4 aren't affected. See the [threat model](threat-model.md).

### A process lost its score after the host resumed from suspend

On a host that suspends, the 60-second process sweep can drop processes
that were alive across the suspend, along with their scores. This is a
known limitation, and servers rarely suspend.

## Counters in `aegisctl status`

These should stay at 0. Each one that grows means something was lost.

- **dropped events:** the 4 MiB ring buffer was full. Expect it only
  in huge bursts of execs or connects.
- **incidents dropped:** the incident writer fell 256 decisions behind.
  Check disk latency on `/var/lib`.
- **incident write errors:** an incident write failed. The journal has
  the error; check disk space.
- **verifications skipped:** 1,024 verifications were already in
  flight. Check that `rpm -qf /usr/bin/bash` returns quickly.
- **defer queue overflows:** a process had 64 signals waiting on
  verification, or 8,192 were waiting in all. Report it, with the
  incident.
- **telemetry dropped: journald:** journald was away or its buffer was
  full. Check `systemctl status systemd-journald`.
- **telemetry dropped: otlp ...:** see
  [telemetry](telemetry.md#failure-handling).

`incident repeats not recorded` is different: it counts decisions inside
an open incident that added nothing new, and it grows in normal use.

## Telemetry

### The JSONL file is never created

The journal says `telemetry jsonl <path>: Permission denied` or
`Read-only file system`. The path has to be under `/var/log/aegis-v2`.
Telemetry changes also need `systemctl restart aegisd`, not a reload.

### The JSONL file grows forever

aegisd doesn't rotate it. Set up logrotate with `copytruncate`; see
[telemetry](telemetry.md#json-lines).

### OTLP records never arrive

1. Check the boolean: `getsebool aegisd_can_network_connect` must be
   `on`. Without it the journal shows a connection error and `ausearch
   -m AVC -ts recent` shows the denial.
2. Check the journal for `otlp export failing, dropping records:`,
   followed by the reason.
3. Check the endpoint. aegisd posts to `<endpoint>/v1/logs` with a JSON
   body, so the collector needs its OTLP/HTTP receiver enabled.
4. For `https://`, the collector's certificate must chain to a CA in the
   system trust store.
5. Restart after any telemetry change.

An endpoint with `user:pass@` in it is rejected at load; put credentials
in `[telemetry.otlp.headers]`.

## SELinux denials

```sh
ausearch -m AVC -ts recent | grep aegis
```

Any denial from `aegisd_t` is a bug; please report it with that output.
See [SELinux](selinux.md#hunting-a-denial).

## Still stuck

Open an issue with your Rocky and kernel versions, the Aegis version,
the `aegisctl preflight --json` and `aegisctl status --json` output, and
the relevant journal lines.
