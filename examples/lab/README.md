# Lab: one incident, start to finish

`run.sh` stages a small attack chain on a test VM and shows how Aegis
turns it into one incident. Nothing in it is malware. The "payload" is a
copy of the host's own bash and strace, run from a temp directory, and
nothing leaves the host.

![The lab running on a Rocky Linux 10 test VM](../../assets/lab.gif)

## Run it

You need a VM you don't mind poking, not a production host. It should
run Rocky Linux 10 with Aegis installed and running in audit mode (see
[installation](../../docs/installation.md)), plus strace:

```console
# dnf install strace
# examples/lab/run.sh
```

It takes about 15 seconds. `PACE=0` drops the pauses between steps. The
script reads like a shell script because it is one, so read it first.
To watch enforce mode do it for real, see
[in enforce mode](#in-enforce-mode).

## What it does

1. Starts `sleep 300` as a throwaway service,
   `aegis-lab-target-<random>.service`. That puts it in `system.slice`,
   which is what makes Aegis treat it as a system daemon.
2. Copies `/usr/bin/bash` and `/usr/bin/strace` into a fresh
   `/tmp/aegis-lab.XXXXXX` directory.
3. Runs the bash copy. Exec from a temp directory: **25**.
4. That bash connects to 30 closed ports on `127.0.0.1`, in-process,
   without forking. Ten refused connects inside two seconds is an egress
   scan: **+40**, so the process is at 65, past the throttle line of 50.
   Aegis opens a `would_throttle` incident with the bash copy as root.
5. The bash copy starts the strace copy as a child (another exec from
   `/tmp`), which attaches to the sleep for two seconds and detaches. A
   ptrace attach to a system daemon: **+45**. The child is in the same
   incident, which is scored per signal kind across its members:
   25 + 40 + 45 = **110**, past the quarantine line of 80. The verdict
   becomes `would_quarantine`.
6. Prints `aegisctl incidents list`, `timeline` and `show` for the new
   incident, and the evidence directory.

On exit, including Ctrl-C, it stops the service and deletes the temp
directory. The incident stays in `/var/lib/aegis-v2/incidents/`.

In audit mode nothing is throttled or quarantined. The verdicts say what
enforce mode would do.

## In enforce mode

Put aegisd in enforce mode first (`mode = "enforce"` in
`/etc/aegis-v2/config.toml`, then `systemctl reload aegisd`), and tell
the script:

```console
# MODE=enforce examples/lab/run.sh
```

It refuses to run if aegisd's mode doesn't match `MODE`, so you can't
freeze something by accident. This time the scan at 65 throttles the
bash copy, and the attach at 110 quarantines the tree: the copies of
bash and strace, and the `timeout` between them, are held, moved into
`aegis-incident-<id>-q.scope`, frozen, and cut off by an nftables
rule. The incident's verdict reads `quarantined`. The script prints
the scope's `FreezerState`, the processes in it, and the `inet aegis`
table, then the incident as before.

The bash copy never prints its last line, because it's frozen before
it gets there. On exit the script runs `aegisctl incidents kill` on the
incident, so nothing is left frozen. Put the mode back to `"audit"`
when you're done.

## A captured run

[`incident.json`](incident.json) and [`timeline.jsonl`](timeline.jsonl)
came from one run on a Rocky Linux 10.2 test VM with Aegis v0.1.1, and
are unedited.

The timeline has three lines, one per decision that changed something:
the scan that opened the incident at 65, the child's exec from `/tmp`
that joined it, and the ptrace attach that took it to 110. The bash
copy's own exec, at 25, sits below the throttle line, so it's in the
evidence but never got a timeline line of its own.
