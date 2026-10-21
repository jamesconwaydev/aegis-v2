# Scoring

Every process gets a risk score built from the signals it raises.

## Signals and weights

| Signal                     | Config key             | Default weight |
| -------------------------- | ---------------------- | -------------- |
| exec from a temp directory | `tmp_exec`             | 25             |
| `memfd_create`             | `memfd_create`         | 20             |
| exec of a memfd            | `memfd_exec`           | 65             |
| ptrace of a system daemon  | `ptrace_system_daemon` | 45             |
| egress scan                | `egress_scan`          | 40             |

The weights live in `[scoring.weights]`; see
[configuration](configuration.md#scoringweights).

### Exec from a temp directory

Raised when a process successfully executes a file that:

- sits on a tmpfs filesystem, such as `/dev/shm`, a tmpfs `/tmp`, or
  any bind mount of a tmpfs, or
- has a path starting with `/tmp/`, `/var/tmp/` or `/dev/shm/`, which
  catches a disk-backed `/tmp`, or
- has a path too long for the kernel to render at all. A path that can't
  be shown not to be in a temp directory scores as if it were.

The path is the file's real path, resolved in the kernel, not `argv[0]`.
For a script, it's the script, not its interpreter.

An exec of a memfd is also on tmpfs. It scores once, as an exec of a
memfd, not as both.

### `memfd_create`

Raised on every call to `memfd_create`, whether or not it succeeds.

### Exec of a memfd

Raised when a process executes a file whose path is `/memfd:<name>`: a
file created with `memfd_create` that has no name on any filesystem.
This is how fileless malware runs. The weight is 65 so that
`memfd_create` plus the exec (20 + 65 = 85) clears the quarantine
threshold with room to spare for the decay between the two calls.

### ptrace of a system daemon

Raised when a process attaches to a system daemon with `PTRACE_ATTACH`
or `PTRACE_SEIZE` and the kernel allows it. A refused attach, such as
one aimed at another user's process, doesn't score. A target is a
system daemon when it is pid 1, or when its cgroup (from
`/proc/<pid>/cgroup`) is directly a `system.slice/*.service` unit.

### Egress scan

aegisd keeps a sliding window per process (2 seconds by default) of its
outbound TCP connects. The signal fires when, inside the window, either:

- the process has connected to 20 or more distinct (address, port)
  pairs, or
- 10 or more of its connects have failed.

It fires once on crossing, then stays quiet until both counts drop back
below their thresholds. IPv4-mapped IPv6 addresses count as the IPv4
address. UDP isn't observed. The window and both counts are in
`[scoring.scan]`.

## How a score is built

Each process holds one component per signal kind. When a signal is
raised:

1. Its contribution is the weight, or 0 if an allowlist forgives it
   (see [allowlists](#allowlists)).
2. The component for that kind becomes the larger of its current,
   decayed value and the new contribution. Repeats don't stack: ten
   `memfd_create` calls score 20, not 200.
3. The process's score is the sum of its components, each decayed to
   now.

Decay is exponential. A component of value *c* set at time *t₀* is worth
*c* × 0.5^((*t* − *t₀*) / *half-life*) at time *t*. The default
half-life is 30 seconds, so 45 points of ptrace are worth 22.5 after
30 s and about 5.6 after 90 s.

When a process forks, the child starts with a copy of the parent's
components, still decaying from when the parent got them. A recycled pid
never inherits anything: processes are tracked by pid and start time.

## Tiers

| Score                | Tier       | Verdict            |
| -------------------- | ---------- | ------------------ |
| below 50             | log        | none               |
| 50 or more, below 80 | throttle   | `would_throttle`   |
| 80 or more           | quarantine | `would_quarantine` |

The thresholds are `score_threshold_throttle` and
`score_threshold_quarantine` in `[general]`. In v0.1 a verdict is only
recorded. Nothing is throttled or quarantined.

Log-tier decisions aren't written anywhere by default. Run aegisd with
`--debug` to see every one on stderr.

## Incidents and process trees

A process opens an incident when its own score, inherited components
included, reaches the throttle tier. From then on, a process that
scores belongs to that incident if it, or any of its ancestors, is
already a member. The nearest member ancestor decides which incident.

Once a process is in an incident, its tier is the higher of:

- its own score, and
- the incident score: for each signal kind, the strongest current
  component across all live members, summed.

That's what catches a chain split across processes. Say a program
started from `/tmp` (25) forks a helper, then scans the network (40).
At 65 it opens a `would_throttle` incident. The helper was forked
before the scan, so it carries only the 25. When the helper attaches
to `sshd` (45), its own score is 70, but the incident score is
25 + 40 + 45 = 110, and the incident becomes `would_quarantine`.

A tree in which no single process reaches the throttle tier opens no
incident. pid 1 and pid 2 (`kthreadd`) never open or join one, so an
incident is never rooted at init. [Incidents](incidents.md) covers what
gets recorded.

## Allowlists

An allowlist entry cancels a signal's whole weight: the evidence records
a modifier equal to minus the base, and the contribution is 0. The
signal still appears in the process's evidence.

- **Exec from a temp directory:** the parent of the process doing the
  exec is in `excluded_parent_processes`, or the process's SELinux type
  is in `excluded_selinux_domains`.
- **`memfd_create`:** the caller is in `memfd_callers`, or its SELinux
  type is in `excluded_selinux_domains`.
- **Exec of a memfd:** the binary doing the exec is in `memfd_callers`.
- **ptrace of a system daemon:** the tracer is in `ptrace_tracers`.
- **Egress scan:** the scanner is in `scan_binaries`, runs as uid 0, and
  has a controlling terminal.

A path on a list only counts when that binary verifies: RPM-owned and
unchanged, or matching a pin. Name the real file, not a symlink to it:
a symlink never verifies. See
[verified executables](overview.md#verified-executables).

For an exec, "the binary doing the exec" is the image before the exec,
not the file it starts. That's what lets `runc` run its own memfd copy
without letting anything else run one.

### When an allowlist is withheld

A verified binary can still be running someone else's code. So a
process gets no allowlist modifier at all, the SELinux-domain one
included, when:

- its environment at exec holds `LD_PRELOAD`, `LD_AUDIT` or
  `LD_LIBRARY_PATH`;
- its environment couldn't be read within 1 second (this fails closed);
  or
- a tracer in the host's pid namespace attached to it with ptrace and
  the attach succeeded. Its children inherit that at fork, and its next
  exec clears it.

For a temp-directory exec the parent's state counts too, since the
parent is what earns the modifier. Withholding doesn't change a
binary's verification, and the evidence says what was withheld and why:

```text
exec of a memfd; allowlist withheld: LD_PRELOAD is set (/memfd:aegis-sim (deleted))
```

For the two exec signals, the file that was run follows in brackets.

On a host that sets `LD_LIBRARY_PATH` globally, every allowlisted tool
loses its modifiers this way. Expect incidents from tools such as
`runc` or `dnf` there, and look for `allowlist withheld:` in their
evidence. These checks are best effort; the
[threat model](threat-model.md#the-injection-checks-are-best-effort)
explains how they can be beaten.

### Waiting for verification

Verification takes a moment (an `rpm` query and a hash), and so does
the environment read. A signal that needs either is held for up to
6 seconds, then scored with whatever is known by then: `unverified` if
no verdict came, tainted if no environment did. Up to 64 signals are
held per process and 8,192 in all; past either cap they score at once.

## Default examples

These come from the end-to-end scenarios in `tests/e2e/scenarios.toml`,
run against a real Rocky 10 host. "throttle" and "quarantine" mean
`would_throttle` and `would_quarantine`.

| Scenario        | What happened                       | Score | Verdict    |
| --------------- | ----------------------------------- | ----- | ---------- |
| `tmp-dropper`   | a payload dropped in `/tmp` and run | 25    | none       |
| `port-scan`     | an egress scan of loopback          | 40    | none       |
| `memfd-exec`    | `memfd_create`, then exec of it     | 85    | quarantine |
| `ptrace-daemon` | `/tmp` strace copy traces sshd      | 70    | throttle   |
| `chain`         | from `/tmp`: scan, then ptrace sshd | 110   | quarantine |
| `preload-memfd` | allowlisted memfd, `LD_PRELOAD` set | 85    | quarantine |
| `pinned-memfd`  | the same without `LD_PRELOAD`       | 0     | none       |
| benign          | dnf, gdb, pip, podman, ssh login    | < 50  | none       |

## Baselining a host

v0.1 changes nothing on the host, which makes it a safe place to find
out what's normal before enforcement exists.

1. Install and start aegisd, then leave it for 48 to 72 hours. Cover
   whatever the host does weekly if you can: backups, deploys, patching.
2. List what it recorded:

   ```sh
   aegisctl incidents list
   ```

3. For each incident, read the evidence:

   ```sh
   aegisctl incidents show AEG-20261019-093000-0123456789abcdef
   ```

   The `reason` column says what fired and why, for example
   `exec from a temp directory (/tmp/x)`. Each line under `members`
   ends with that process's verification. Only binaries an allowlist
   or pin names are ever checked, so everything else shows
   `unverified`.
4. Decide. If it's something you'd want to know about, leave it. If it's
   a legitimate tool, forgive it as narrowly as you can, in a drop-in
   such as `/etc/aegis-v2/allowlist.d/50-site.toml`:
   - An RPM-owned binary: add its path to the matching list.
   - A binary from outside the RPM database: add its path to the list
     and pin its SHA-256 (`sha256sum /path/to/binary`) under
     `[allowlist.pinned]`.
   - A confined service with its own SELinux type: add the type to
     `excluded_selinux_domains`. Never `unconfined_t`.
5. Check and reload:

   ```sh
   aegisd --check-config && systemctl reload aegisd
   ```

Change weights or thresholds only when an allowlist can't express the
fix, such as a host that legitimately scans all day. A lower weight
applies to every process on the host, not just the one you meant.

A binary that verifies as `modified` is worth a closer look before you
allowlist anything: it's an RPM-owned file that no longer matches its
package, or a pinned file whose hash changed.

## Tuning notes

- **Weights that sum exactly to a threshold land just under it.** Each
  component decays a little between two events. Set `memfd_create` to
  25, and a temp-directory exec followed by a `memfd_create` scores a
  hair under 50, not 50. Leave a margin, as `memfd_exec` does.
- `allowlist withheld:` in an allowlisted tool's evidence means the
  tool ran with a loader variable, an unreadable environment, or after
  a ptrace attach. Find out which before you change anything.
- A weight of 0 turns a signal off. Its evidence is still recorded if
  the process lands in an incident for another reason.
- A shorter half-life forgives slow, spread-out activity sooner; a
  longer one catches it but holds benign bursts against a process for
  longer.
