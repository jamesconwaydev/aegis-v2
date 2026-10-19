# SELinux

The `aegis-v2-selinux` package confines aegisd to its own SELinux
domain, `aegisd_t`, so that even a compromised daemon can only reach
what it needs. The policy is written to run with SELinux enforcing, and
the release is tested that way with no denials.

## What the package does

On install it loads the `aegis` policy module and relabels the paths in
its file contexts. On removal it unloads the module. A running aegisd
picks up the new domain at its next start; the package restarts it for
you if it's running.

Check it:

```sh
semodule -l | grep aegis              # aegis
ps -eZ | grep aegisd                  # ...:aegisd_t:...
getsebool aegisd_can_network_connect  # off
```

## Types

| Type              | Labels                                  |
| ----------------- | --------------------------------------- |
| `aegisd_t`        | the running daemon                      |
| `aegisd_exec_t`   | `/usr/sbin/aegisd`                      |
| `aegis_etc_t`     | `/etc/aegis-v2` and everything under it |
| `aegis_var_lib_t` | `/var/lib/aegis-v2` (incidents)         |
| `aegis_var_run_t` | `/run/aegis-v2` (socket and lock file)  |
| `aegis_log_t`     | `/var/log/aegis-v2` (the JSONL file)    |

Rocky 10 labels `/usr/sbin` as if it were `/usr/bin`, so the module also
labels `/usr/bin/aegisd`.

## What `aegisd_t` may do

- **Load and run the probes:** BPF maps and programs, perf events for
  the tracepoints, and the capabilities `bpf`, `perfmon` and `sys_admin`.
- **Read the kernel's BTF** from sysfs and tracepoint ids from tracefs.
- **Inspect every process:** `/proc/<pid>/stat`, `exe`, `cgroup`,
  `attr/current` and `root`, with `sys_ptrace` to read other users'
  entries.
- **Read and hash executables:** any non-security file, with
  `dac_read_search` to open files whatever their mode. Shadow files,
  keys and other security types stay out of reach.
- **Query the RPM database:** run `rpm` inside `aegisd_t` and read the
  database, read-only.
- **Read its config**, and manage its incidents, socket, lock file and
  log directory.
- **Log to journald** and notify systemd.

It can't open network sockets, apart from Unix ones, unless you turn on
the boolean below.

## The one boolean

`aegisd_can_network_connect`, off by default, lets aegisd make outbound
TCP connections to any port and resolve names over DNS. It also allows
reading the system's certificates. The OTLP sink needs it:

```sh
setsebool -P aegisd_can_network_connect 1
```

Leave it off if you don't use OTLP.

## Talking to aegisd from another domain

The module exports one interface, `aegis_stream_connect(domain)`, for a
policy that wants to let another confined domain use the control socket.
Root's usual `unconfined_t` shell needs nothing extra.

## Hunting a denial

```sh
ausearch -m AVC -ts recent | grep aegis
```

Some harmless denials are hidden with `dontaudit` rules: rpm trying to
open its database read-write before falling back to read-only, and its
SELinux plugin looking at the policy store. To see everything while you
investigate:

```sh
semodule -DB     # disable dontaudit rules
semodule -B      # turn them back on when you're done
```

Please report a real denial as a bug, with the `ausearch` output. Don't
work around it with `semanage permissive -a aegisd_t`: that removes the
confinement entirely.

## Without SELinux

aegisd runs fine with SELinux permissive or disabled, but it's no longer
confined. `aegisctl preflight` warns about that. The `aegis-v2` package
only requires `aegis-v2-selinux` when the targeted policy is installed.
