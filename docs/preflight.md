# Preflight

`aegisctl preflight` checks whether a host can run aegisd. It works
before the package is installed too, from a copied `aegisctl` binary, and
it never changes anything. The RPM runs it once after install.

```sh
aegisctl preflight
aegisctl preflight --json
```

Each check prints `PASS`, `WARN` or `FAIL`, a detail line, and on
anything but a pass, the fix. The exit code sums it up:

| Exit | Meaning                        |
| ---- | ------------------------------ |
| 0    | every check passed             |
| 1    | at least one check failed      |
| 2    | no failures, but some warnings |

With `--json`, the output is an array of objects with `check`, `status`
and `detail`, plus `fix` when the check didn't pass.

A `FAIL` means aegisd won't run, or the package won't work as shipped.
A `WARN` means it will run, with something missing.

## The checks

They run in this order.

### kernel

Reads `/proc/sys/kernel/osrelease` and wants 6.12 or newer.

- **On failure:** `FAIL`
- **Fix:** Boot a 6.12+ kernel (Rocky 10 ships one).

The probes are built and tested against 6.12, which is what Rocky 10
ships.

### cgroup2

Looks in `/proc/mounts` for `cgroup2` mounted at `/sys/fs/cgroup`.

- **On failure:** `FAIL`
- **Fix:** Remove `systemd.unified_cgroup_hierarchy=0` from the kernel
  command line and reboot.

### btf

Checks that `/sys/kernel/btf/vmlinux` exists. aegisd reads kernel struct
offsets from it at every start.

- **On failure:** `FAIL`
- **Fix:** Use a kernel built with `CONFIG_DEBUG_INFO_BTF=y` (Rocky's
  is).

### bpf-lsm

Reads `/sys/kernel/security/lsm` and looks for `bpf` in the list. The
exec probes are BPF LSM programs, so without it aegisd can't attach them
and won't start.

- **On failure:** `FAIL`
- **Fix:** add `bpf` to the end of the current list. The check prints
  the exact command, built from your list, for example:

  ```sh
  grubby --update-kernel=ALL \
    --args="lsm=lockdown,capability,yama,selinux,landlock,ima,evm,bpf"
  ```

  A reboot is needed. If the list couldn't be read, the fix tells you to
  run `cat /sys/kernel/security/lsm` first and append `,bpf` to what it
  prints. Don't set `lsm=bpf` on its own: that list replaces the whole
  set, and you'd lose SELinux.

Rocky 10.2 has `bpf` in the list by default. Aegis only ever prints this
command; it never edits your boot configuration.

### selinux

Reads `/sys/fs/selinux/enforce` and wants `1`.

- **On failure:** `WARN`
- **Fix:** `setenforce 1`, and set `SELINUX=enforcing` in
  `/etc/selinux/config`.

aegisd runs with SELinux permissive or off. The warning is there because
the policy module only confines it when SELinux is enforcing.

### nft

Looks for an `nft` executable on `PATH`.

- **On failure:** `FAIL`
- **Fix:** `dnf install nftables`

v0.1 doesn't call `nft`. The package requires `nftables` because egress
control is planned for v0.2.0, and the check matches that requirement.

### criu

Looks for a `criu` executable on `PATH`.

- **On failure:** `WARN` (`criu not found (needed from v0.4.0)`)
- **Fix:** `dnf install criu`

### aegisd

Tries to connect to the control socket, `/run/aegis-v2/aegisd.sock`, or
the path given with `--socket`. A permission error counts as a pass:
the socket only lets root in, so a refusal still means aegisd is there.

- **On failure:** `WARN`
- **Fix:** `systemctl enable --now aegisd` (after installing the
  package).

This one warns on a fresh install by design, since the daemon isn't
started yet.

## Example

On a stock Rocky 10.2 host, after installing but before starting aegisd:

```text
kernel   PASS  6.12.0-211.16.1.el10_2.0.1.x86_64 (6.12 or newer needed)
cgroup2  PASS  cgroup2 mounted at /sys/fs/cgroup
btf      PASS  /sys/kernel/btf/vmlinux present
bpf-lsm  PASS  bpf is in the LSM list (lockdown,capability,yama,selinux,bpf,landlock,ima,evm)
selinux  PASS  SELinux is enforcing
nft      PASS  nft found
criu     PASS  criu found
aegisd   WARN  aegisd is not running (no answer on /run/aegis-v2/aegisd.sock)
               fix: systemctl enable --now aegisd (after installing the package).
```

The exit code there is 2.
