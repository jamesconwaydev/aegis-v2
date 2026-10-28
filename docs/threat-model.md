# Threat model

Read this before you rely on Aegis v0.2.

## What it's for

Aegis v0.2 detects common post-exploitation behaviour on a Rocky Linux
10 host and records it as incidents:

- running a dropped payload from a temp directory
- running code that only exists in memory (`memfd_create` and exec)
- attaching a debugger to pid 1 or a system service
- scanning the network outward

In audit mode, the default, that's all it does. Nothing it does changes
the host.

In enforce mode it also acts on the incident's process tree. At the
throttle tier it moves the tree into a scope with CPU and memory limits.
At the quarantine tier it holds the tree's processes in the kernel,
moves the tree into its own scope, freezes it and drops its traffic.
[Below](#children-of-a-caught-tree) is exactly which processes get
which. It never
kills anything unless you run `aegisctl incidents kill`. It never acts
on pid 1, on aegisd, or on any ancestor of the tree, so the shell or
service a payload came from is left alone.

The end-to-end tests check that `/etc` is byte-for-byte unchanged
across every scenario, enforce mode included.

## What it trusts

- **The kernel.** Events come from eBPF programs in the kernel. A kernel
  compromise defeats Aegis.
- **The RPM database and pins.** A binary counts as verified if its
  content matches the RPM database or an admin's SHA-256 pin. Someone
  who can rewrite the RPM database as root can make a binary verify.
- **Root's config.** `/etc/aegis-v2` is root-only. Whoever can edit it
  can allowlist anything.

## What it never trusts

- **Process names.** `comm` and `argv[0]` are recorded but never used to
  decide anything. Allowlists take absolute paths, and a path only
  counts when the file the kernel executed is that path on the host and
  verifies.
- **A lookalike in a chroot or container.** A process that runs its own
  `/usr/bin/dnf` inside a chroot doesn't get the host's verdict: aegisd
  checks the executed inode against the host's file.
- **A verified binary that may be running foreign code.** A process
  started with `LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_PATH`, one whose
  environment can't be read, and one a host-side debugger attached to
  get no allowlist credit, however well their binary verifies. These
  checks are best effort; see
  [below](#the-injection-checks-are-best-effort).
- **Text from processes.** Paths and names may contain anything.
  Incidents store exact bytes in base64 beside a lossy UTF-8 copy,
  journald fields use the binary-safe encoding, and the journald
  message and `aegisctl` escape control, line-separator and
  bidirectional characters before they're shown.

## Self-protection

aegisd runs confined: six capabilities, a read-only filesystem apart
from its own directories, and its own SELinux domain. The control socket
answers root only.

That protects the host from a compromised aegisd. It mostly doesn't
protect aegisd from root, with one exception in both modes and a second
in enforce mode:

- **No debugger gets in**, in either mode. While aegisd runs, the
  kernel refuses any other process, root included, an attach-level
  ptrace access to it:
  `strace -p`, `gdb -p`, reading or writing `/proc/<pid>/mem`, and
  `process_vm_readv` or `process_vm_writev` all fail with `EPERM`.
  Read-level access still works, so `ps`, `/proc/<pid>/status` and
  `/proc/<pid>/maps` do too.
- **A held process can't signal it**, in enforce mode, where processes
  get held. Only held processes are refused; root and systemd aren't.

Root can still stop, restart or kill aegisd, through systemd or a
signal, and that unloads every probe and hold program with it. Root can
also edit the config or remove the package. The guard stops someone
reading or steering a running aegisd from the inside, not someone
turning it off.

## Known limitations

These are known, and some are planned to change. None of them is a
secret.

### A root attacker can stop it

An attacker with root who hasn't been caught yet can stop aegisd,
unload its probes, or edit its config. Aegis isn't a rootkit defence.
Ship its telemetry off the host (OTLP, or journald forwarding) so the
record of what happened before it stopped survives.

### Scripts run through a shell aren't execs

`sh /tmp/x`, or a shebang-less script that `execvp` hands to `/bin/sh`
when the kernel refuses it (`ENOEXEC`), isn't an exec of `/tmp/x`. The
kernel executed the shell, which then read the file. Aegis sees the
shell, not the script, and scores no temp-directory exec. A script with
a `#!` line run directly is caught.

### The injection checks are best effort

Allowlist credit is withheld from a process that shows `LD_PRELOAD`,
`LD_AUDIT` or `LD_LIBRARY_PATH`, or that a debugger attached to. The
kernel reads the environment at every exec, when the new image is in
place but before any of its code has run. A preloaded library can't
scrub its own entry before that read, because it hasn't been loaded
yet. The checks can still be beaten:

- A process can exec onward with a clean environment, and the next
  image starts out trusted.
- Only the first 32 KiB of the environment is read. A longer one counts
  as unreadable, so it fails closed: the process gets no allowlist
  credit.
- Processes already running when aegisd starts never exec in front of
  it, so their environment is read from `/proc/<pid>/environ`, as v0.1
  read every process's. That read sees the process's memory as it is
  now, and a library already loaded could have scrubbed its
  `LD_PRELOAD` entry by then.
- A ptrace attach is only seen when another process attaches to the
  target. `PTRACE_TRACEME`, or a seize set up before the exec, isn't
  seen.

They stop careless injection and inherited environments. An attacker
who knows about them still has the gaps above.

### Environment reads can get stuck

This only touches processes that were running before aegisd started,
the ones whose environment comes from `/proc/<pid>/environ`. That read
can block for good, for example when a process's memory is backed by a
hung FUSE filesystem. aegisd runs at most 16 reads at once. Once 16 are
stuck, every later one is refused, and those processes count as
untrusted until aegisd restarts. That causes false positives, not
missed detections.

### A broken RPM database sticks

If the RPM database is broken when aegisd checks a binary, rpm can
answer "not owned", and aegisd caches that. Allowlisted binaries stay
`unverified`, and lose their allowlist credit, until a reload
(`systemctl reload aegisd`) or a restart empties the cache.

### Some scans aren't detected

The egress scan signal counts connects per process. A scan spread
across many processes, one connection each, never crosses the
threshold in any of them. It also comes from TCP state changes only, so
UDP traffic, UDP scans included, isn't observed.

### btrfs subvolumes and overlayfs stay unverified

Verification compares the device and inode the kernel executed with the
file at the same path on the host. On btrfs subvolumes and overlayfs
the device numbers don't match, so binaries there are always
`unverified`, and allowlists never apply to them. Rocky's default
filesystem, XFS, isn't affected.

### Containers

Every binary is verified against the file at the same path under the
host's root (pid 1's). A process inside a container runs a file from
the container's image, which is a different file, so it's always
`unverified` and allowlists don't apply to it. The container runtimes
themselves (`podman`, `crun`, `runc`) run from the host and verify
normally.

The `ptrace` target pid is looked up in the host's pid namespace. A
tracer inside a container names a pid in its own namespace, so Aegis
may judge the wrong process, or none, as the target.

### Hosts that suspend

aegisd sweeps its process table every 60 seconds, matching each entry's
start time against `/proc`. On a host that suspends and resumes,
processes that were alive across the suspend can fail that match and
lose their accumulated score. Servers rarely suspend.

### Scores just under a threshold

Scores decay continuously, including in the moment between two
signals. Weights that add up exactly to a threshold land just under it.
See [scoring](scoring.md#tuning-notes).

### Lost events

Under a heavy burst, such as thousands of execs a second, the 4 MiB
ring buffer can fill. Events that don't fit are counted, not queued, and
show in `aegisctl status` as `dropped events`. A signal in a dropped
event is missed.

### Signals are held for up to 6 seconds

A signal waiting on its binary's verification or its environment read
is held for up to 6 seconds. Anything still unknown then scores as
`unverified` or untrusted, which errs towards scoring, never towards
forgiving. On a busy host, an allowlisted process that exits before its
environment is read loses its allowlist credit the same way.

### Paths are capped at 256 bytes

Longer paths are truncated in events and incidents. A truncated path is
never verified, and a path too long to render at all scores as a
temp-directory exec.

### Enforce mode acts after the fact

The hold starts when aegisd writes the process into the kernel's hold
map, not at the moment the score crosses the line. Between the two,
the event travels to userspace, is scored, the incident is written to
disk, and the enforcer takes the job: usually a few milliseconds, in
which the tree can still fork, connect and write.

### Children of a caught tree

A tree can fork in that gap, and aegisd chases what it forks in three
ways:

- **Fork events.** For 30 seconds after a throttle or quarantine
  decision, every child a covered process forks gets a job of its own,
  unless its fork jobs fill their half of the enforcer's queue (128
  jobs), when the rest are dropped and counted. Under a quarantine
  it's held and attached to the frozen scope, where it stops. Under a
  throttle it joins the throttle scope.
- **A `/proc` walk.** When aegisd quarantines a tree, it also moves and
  freezes any child it finds in `/proc`, including children whose fork
  it never saw.
- **A second walk** after the freeze, which attaches anything new to
  the frozen scope.

A child is held (writes, connects and forks refused) only once aegisd
sees its fork event. If the event was lost (say, an attacker flooded
the ring buffer), that child is frozen and cut off from the network
like the rest of the tree. It isn't held, though, so for the few
milliseconds before the freeze it can still act. A process that child
forks before the move and then orphans, by exiting so the process is
reparented out of the tree, can stay outside the scope, whether or not
its own fork event arrives. So can anything past the walk's
1,024-process limit. Closing this needs a kernel-side change and is
planned.

A throttle never walks `/proc`, so it relies on fork jobs alone. The 30
seconds start at the decision, not the move. If aegisd's enforcer falls
more than 30 seconds behind, or a throttled tree's fork jobs are
dropped because they filled their half of the queue, the processes it
starts in that time may stay outside its limits. A quarantine isn't
affected: its walk runs when its job does.

### A failed move isn't retried

If aegisd can't move a tree into its quarantine scope, it doesn't try
again. The tree stays held but not frozen, and the incident stays
`would_quarantine` with the error recorded. Later processes that join
the tree are held the same way. A restart doesn't retry the move, and it
lifts the holds, so after one the tree runs free. Kill it yourself, or
release it.

### Writes before the hold reach the disk

Once held, a process can't write through any file descriptor. Whatever
it wrote before that is on disk, and a shared writable memory mapping
it already had isn't a write the hook sees, so data written through one
before the freeze lands too. There's no overlay to throw those writes
away yet; that's the box planned for v0.4.0.

### A restart lifts the holds

The hold map lives in the kernel only while aegisd's programs are
loaded. Restart aegisd and every hold is gone. The freeze and the
nftables rule stay, because systemd and nftables keep them, so a
quarantined tree is still frozen and cut off. `aegisctl incidents
release` and `kill` read the recorded actions and still work.

After a reboot there's nothing left to release: the scope, the freeze
and the nftables rule went with the old boot. Release or kill of an
incident from an earlier boot touches nothing on the host and records
it as ended.

### Reloading nftables opens a gap of about ten seconds

Reloading nftables (`systemctl reload nftables`, or any
`nft flush ruleset`) takes aegisd's `inet aegis` table with it, and
every quarantined tree's drop rule too. aegisd checks every 10 seconds
and puts back the table and each missing rule. So for up to 10 seconds
a quarantined tree has no drop rule, and up to 20 if a check found the
enforcer's queue full and was dropped. A check also waits its turn
behind whatever the enforcer is already doing. Through all of it the
tree stays frozen and held, so it can't use the network unless
something thaws it. Each rule put back is recorded on its incident as
an `nft_drop` that says why. This is a poll, not a watch on nftables.

In audit mode the check only puts back a rule that enforce mode added.
If a quarantine's own rule failed, enforce mode adds it late on a
check. Audit mode never does, because that would be a new action.

Release and kill no longer trust the handle they recorded, since a
reload lets nftables hand that number to someone else's rule. They look
the rule up by the tree's cgroup in the live table and delete that one
only. Kill looks before it sends SIGKILL, because once the scope
empties nftables shows the rule by a bare cgroup id, not the path.
Release of a scope that's already gone falls back to the recorded
handle, but only when that handle's rule shows such a bare id.

A reload can also land in the middle of one of these jobs, in the few
milliseconds between nft calls. If the check's add fails and the table
turns out to be gone, aegisd recreates it and adds the rule again
rather than reporting a failed enforcement. If a release or kill's
delete fails and the rule is no longer listed, that's recorded as "the
rule was already gone", because the network is back either way. A
failure with the rule still in place is still an error.

### Incident scopes are delegated

Both incident scopes, `aegis-incident-<id>.scope` and
`aegis-incident-<id>-q.scope`, are started with `Delegate=yes`.
systemd only lets a process join a running scope that way, and
newcomers join by that call, `AttachProcessesToUnit`. It changes less
than it sounds:

- The scope's cgroup stays root-owned. A process in it that isn't root
  can't create cgroups, change limits, thaw, or move itself out, any
  more than it could before.
- A process running as root inside a throttled or quarantined tree can
  create sub-cgroups under the scope, or leave it, as root always could;
  that sits under [a root attacker can stop it](#a-root-attacker-can-stop-it).
  Delegation only means systemd leaves those sub-cgroups alone.
- Limits, freezing and kill are hierarchical. CPU and memory limits
  bind the whole subtree, a frozen scope freezes every cgroup below it,
  and a kill reaches every process under it, sub-cgroups included.

### A frozen process looks frozen

Freezing is a cgroup state, and anything that inspects the process can
see it: `systemctl status`, the scope's `cgroup.events`, a process
listing that shows its cgroup. If an attacker has a second foothold
outside the tree, it can tell the first one was caught.

### A released process stays in the quarantine slice

`aegisctl incidents release` lifts the tree's holds, thaws it and
removes its nftables rule, but leaves it in its scope under
`aegis-quarantine.slice`. Its CPU and memory accounting stays there,
and the limits of the unit it came from no longer apply to it.

A throttled tree is the same, in `aegis-throttle.slice`, and releasing
a throttle doesn't move it back either. What that costs you is the
service's hold on its own workers. Say aegisd throttled an httpd
worker. That worker now lives in `aegis-incident-<id>.scope`, not in
`httpd.service`, so `systemctl restart httpd` stops every other worker
and leaves this one running. Stop the incident's scope to end it:

```sh
systemctl list-units 'aegis-incident-*'
systemctl stop aegis-incident-<id>.scope
```

A quarantined tree's scope ends in `-q.scope`.

### OTLP

OTLP endpoints that carry credentials in the URL are rejected; put them
in `[telemetry.otlp.headers]`. Failed exports aren't retried.

### The JSONL file doesn't rotate

Use logrotate with `copytruncate`. See
[telemetry](telemetry.md#json-lines).

## Reporting a bypass

A way to evade detection, forge a verified binary, or tamper with
incidents is a security issue. Report it privately, as
[SECURITY.md](../SECURITY.md) describes, not as a public issue.
