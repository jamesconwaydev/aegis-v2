# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

**Upgrading from 0.2.0.** There's nothing to migrate. Incidents 0.2.0
recorded get their `STATE` the first time you list them. An incident
that was quarantined and lost its rule to an earlier reload gets the
rule back within about 10 seconds of the restart. One catch: the
"Stopping aegisd lets the enforcer finish first" fix below can't cover
the upgrade itself, because it's the 0.2.0 binary that shuts down. A
quarantine caught mid-flight by that restart may still go unrecorded.

### Fixed

- **An nftables reload no longer gives quarantined trees their network
  back.** In v0.2.0, `systemctl reload nftables` (or any ruleset flush)
  deleted the `inet aegis` table and every drop rule in it, and nothing
  put them back. Now aegisd checks every 10 seconds and re-adds the
  table and each missing rule, recording an `nft_drop` that says why.
  In audit mode it only restores rules enforce mode added. Release and
  kill also stop trusting the handle they recorded, which a reload
  could hand to another incident's rule: they look the rule up by the
  tree's cgroup and delete only that. Kill looks it up before the
  SIGKILL, while nftables can still name the cgroup. If the rule's
  already gone, release still succeeds and says so. (#53)
- **A quarantine on a busy host gets frozen, not just held.** busctl
  hands back as soon as systemd queues the scope's start job, so the
  freeze straight after it could find the scope not yet running. The
  tree then stayed held but unfrozen, at `would_quarantine`. Now a
  freeze that fails, on a scope the kernel says isn't frozen, gets one
  more try 200 ms later.
- **Stopping aegisd lets the enforcer finish first.** A `SIGTERM` that
  landed mid-quarantine (a `dnf upgrade` restart, say) could leave a
  tree moved or frozen with nothing written down, and the next release
  then said "never enforced". Shutdown now waits up to 5 seconds for the
  job in hand and anything still queued.
- **A drop rule whose first try failed gets added later.** In enforce
  mode, if the `nft` call that should have blocked a quarantined tree
  failed, nothing came back for it. Now the 10-second check adds it,
  and the record says `added late: the first attempt failed`.
- **nft runs from `/usr/bin/nft` when that's the only copy.** The
  config check already looked there; the enforcer didn't. Stock Rocky 10
  has both, so you'll only notice on a trimmed image.
- **The "queue full" alert names the incident's score and root
  process.** It used to arrive with a score of 0 and no process name.
- **An `attach` on the record means something moved.** When every
  newcomer was already in the quarantine scope, or had already exited,
  aegisd still wrote an `attach` with `ok: true` and their pids. Now it
  writes nothing.

### Changed

- **Actions in `incident.json` can carry a `detail` field,** and
  `incidents show` prints it. It says why an action happened, such as a
  rule re-added after a reload. If you parse the records: a removal
  that finds the rule already gone is now an ok `nft_remove` with no
  `nft_handle`, where it used to be an error.
- **`incidents list` has a `STATE` column.** The verdict is history, so
  a tree you'd released still showed `quarantined` and nothing said
  otherwise. `STATE` says what's in place now: `throttled`,
  `quarantined`, `held` (kernel holds only), `released`, `killed`,
  `expired`, or `-` when nothing was enforced. `--json` carries it as
  `state`. Scripts that read the table by column position will
  find `SCORE` and everything after it one column to the right.
- **A release or kill that outlasts the enforcer wait says it's still
  queued.** It used to say "timed out waiting for the enforcer", which
  sounded like a failure. The job always ran anyway, and running it a
  second time got you an "is already released" error. Worse, aegisctl's
  own 30-second deadline usually ran out first, so you saw "no reply
  from aegisd" instead. aegisd now waits 25 seconds, then tells you to
  check `aegisctl incidents show <id>` shortly.

## [0.2.0] - 2026-10-28

v0.1 watched and wrote things down. v0.2.0 is the first release that
acts. Audit mode is still the default and still changes nothing, so an
upgrade alone won't touch a single process. Set `mode = "enforce"` and
the tiers you've been reading about become real: a throttle-tier
incident is slowed down, and a quarantine-tier one is held in the
kernel, frozen and cut off from the network, where it waits until you
release it or kill it.

### Added

- **Enforce mode.** `mode = "enforce"` is no longer refused outright.
  aegisd now refuses it only when the BPF LSM is missing from
  `/sys/kernel/security/lsm` or `nft` isn't installed, and points at the
  `mode` line when it does. (#29, #30)
- **Throttle.** At the throttle tier the process tree moves into
  `aegis-incident-<id>.scope` under `aegis-throttle.slice`, limited by
  the new `[throttle]` settings: `cpu_quota_percent` (25% of one CPU)
  and `memory_high_mb` (256 MiB). It keeps running, and keeps being
  scored. (#29)
- **Quarantine.** At the quarantine tier the tree's members are held in
  the kernel, then moved into `aegis-incident-<id>-q.scope` under
  `aegis-quarantine.slice` with any children aegisd finds under them in
  `/proc`, frozen, and cut off by an nftables rule. A second walk after
  the freeze attaches anything new. For 30 seconds after the decision,
  each child the tree forks gets its own job: held and frozen under a
  quarantine, moved into the scope under a throttle. Pid 1, kthreadd,
  aegisd and the tree's ancestors are never touched. (#29)
- **Delegated incident scopes.** Both incident scopes are started with
  `Delegate=yes`, because systemd only lets a process join a running
  scope that way. Their cgroups stay root-owned, so a tree that isn't
  root gains nothing, and limits, freezing and kill still cover
  everything below the scope. The end-to-end suite now fails any
  enforce-mode scenario whose incident records a failed action.
- **The hold.** Thirteen BPF LSM programs refuse a held process fork and
  clone, connect, send, mount, `bpf()`, module loading, ptrace, writes
  through any file descriptor, new user namespaces, and any signal to
  aegisd. A process that isn't held costs one map lookup per hook.
  Separately, in audit mode too, no other process can ptrace aegisd,
  root included: `strace -p`, `gdb -p` and `/proc/<pid>/mem` get
  `EPERM`. Root can still stop it. (#26)
- **`aegisctl incidents release` and `kill`.** Release lifts a
  quarantined tree's holds while it's still frozen, thaws it and
  restores its network, or lifts a throttle's limits. Kill sends
  SIGKILL to a quarantined tree, frozen or not. Both work from the
  recorded actions, so they still work after a daemon restart and in
  audit mode. After a reboot there's nothing left to release: either
  one, on an incident from an earlier boot, touches nothing on the host
  and records it as ended. (#30)
- **Actions on the record.** Each incident now carries an `actions`
  list: what was done, to which pids, with the unit name or nft handle
  needed to undo it, and any error. Verdicts gain `throttled` and
  `quarantined`, which an incident only reaches once the action worked.
  Reaching one sends a record to telemetry with a reason starting
  `enforcement done:`. Incidents written by v0.1 still load. (#28)
- **Webhooks.** `[[telemetry.webhook]]` posts JSON or a Slack message
  each time an incident's verdict rises (`would_throttle`, `throttled`,
  `would_quarantine`, `quarantined`), and on every enforcement failure,
  including a job dropped because the enforcer's queue was full. They
  fire in audit mode too. (#33)
- **OTLP metrics.** Every 60 seconds aegisd sends its event, drop,
  enforcement and telemetry counters, and its open incidents by
  verdict, to `<endpoint>/v1/metrics`. (#34)
- **Signed releases.** Releases are published with a cosign signature
  over `SHA256SUMS`, build provenance attestations, and SPDX and
  CycloneDX SBOMs. [Installation](https://github.com/jamesconwaydev/aegis-v2/blob/v0.2.0/docs/installation.md#install-the-rpms)
  shows how to verify them. (#38)

### Changed

- **SELinux policy 0.2.0.** `aegisd_t` may now run `busctl`,
  `systemctl` and `nft`, talk to systemd over D-Bus, and hand `nft` to
  its own domain. Each rule fixes a denial seen on Rocky 10 while a
  throttle, a quarantine, a release and a kill ran. The unit gains
  `CAP_NET_ADMIN` and `AF_NETLINK` for `nft`, which makes six
  capabilities. (#31)
- **Dependencies.** `which` 8, `toml` 1.1 and `sha2` 0.11. (#24)

### Fixed

- **A preloaded library could scrub `LD_PRELOAD` before the check.**
  v0.1 read `/proc/<pid>/environ` a few milliseconds after each exec,
  and that's the process's own memory. The environment is now read in
  the kernel at exec, before any of the new image's code runs.
  Processes that were already running when aegisd started still get
  the `/proc` read. (#25)
- **Uninstalling left systemd holding on.** After `dnf remove`,
  `aegis.slice` stayed active and the removed unit stayed loaded. On
  erase the package now reloads systemd, and stops the aegis slices and
  deletes the `inet aegis` table when no incident scope is left. If any
  tree aegisd moved is still there, released ones included, it keeps
  all of that, warns you, and the
  [uninstall steps](https://github.com/jamesconwaydev/aegis-v2/blob/v0.2.0/docs/installation.md#uninstall)
  say how to end it.
- **The end-to-end SELinux check never looked.** Over ssh, `ausearch`
  read its stdin instead of the audit log and answered `<no matches>`
  every time, so the suite's "no denials" result for v0.1 proved
  nothing. It now reads the log and fails if it finds no events at all.
  The suite also gains eight enforce-mode scenarios, all run on Rocky
  10 with SELinux enforcing. (#49)

### Security

- **OTLP failures could log a credential.** The first failed export
  logged the HTTP client's error text, which can quote the request URL,
  and a URL can carry a token. aegisd now logs the status code or the
  kind of error instead, for OTLP and webhooks alike. (#33)

### Known limits

- The hold starts when aegisd writes the process into the kernel's
  map, not when the score crosses the line, so a few milliseconds of
  activity can land first.
- Writes made before the hold, including through a shared memory
  mapping, reach the disk. The overlay that would catch them arrives in
  v0.4.0.
- Holds don't survive an aegisd restart. The freeze and the network
  rule do.
- A child aegisd finds in `/proc` but never saw fork is frozen and cut
  off, not held, so it can act until the freeze. If the enforcer falls
  more than 30 seconds behind, children a throttled tree starts in that
  time can stay outside its limits.
- If the move into the quarantine scope fails, aegisd doesn't retry it.
  The tree stays held but not frozen, at `would_quarantine`. A restart
  doesn't retry the move either, and it lifts the holds, so after one
  the tree runs free until you kill or release it.
- `systemctl reload nftables`, or any full ruleset flush, deletes the
  `inet aegis` table and with it every quarantined tree's drop rule.
  They stay frozen. After that, rule handles can be reused
  within the boot, so release affected incidents one at a time. A fix
  that puts the table back is planned for v0.2.1.
- A frozen process looks frozen to anything that inspects it, and a
  released one stays under `aegis-quarantine.slice`.
- An environment longer than 32 KiB counts as unreadable, so the
  process gets no allowlist credit.
- The quarantined tree's traffic is dropped, not answered. The honeypot,
  and the nftables redirection that feeds it, are planned for v0.3.0.

The full list is in the
[threat model](https://github.com/jamesconwaydev/aegis-v2/blob/v0.2.0/docs/threat-model.md).

## [0.1.1] - 2026-10-21

Two fixes the new lab demo caught in the evidence v0.1.0 writes.

### Fixed

- A process that joined an incident at an exec was listed under the
  binary it was before the exec. The lab's copy of strace showed up as
  `/usr/bin/timeout`. Members are now recorded as the image they run;
  the evidence already named the right file.
- Evidence recorded each signal as a Rust debug string, such as
  `PtraceSystemDaemon { target: ProcKey { tgid: 1641528, start_time_ns: … } }`.
  The `signal` field now holds the signal's weight key (`tmp_exec`,
  `memfd_create`, `memfd_exec`, `ptrace_system_daemon`, `egress_scan`),
  and the attached pid or the scan's target count moves into the
  reason. Anything that parses `incident.json` or `timeline.jsonl`
  should expect the new names; incidents already on disk keep the old
  ones.

### Security

- OTLP export over https now uses rustls-webpki 0.103.16 and
  webpki-roots 1.0.10, for RUSTSEC-2026-0382 (certificate verification
  could accept distrusted intermediates) and RUSTSEC-2026-0381 (bundled
  roots trusted distrusted emSign intermediates).

## [0.1.0] - 2026-10-19

The first release, and it watches without touching. Install it, run it in
audit mode for a few days, and read what it would have done. Nothing on
the host is stopped, moved or rewritten yet; that starts in v0.2.0.

### Added

- eBPF probes for every committed exec, fork and exit, successful ptrace
  attaches, memfd_create and outbound TCP connects. The exec probe reports
  the file the kernel actually ran, so a script in `/tmp` shows up as the
  script, not as `/bin/sh`, and a memfd or tmpfs binary is flagged however
  it was reached.
- A risk score for every process that halves after 30 seconds of quiet.
  Running from a temp directory adds 25, creating a memfd 20, running one
  65, attaching to a system daemon 45, and a burst of outbound connects 40.
  Repeats of the same kind don't stack. Cross 50 and you get a
  `would_throttle` incident; cross 80 and it's `would_quarantine`.
- Incidents that follow the attack, not the PID. Once one process crosses
  the line, its children join the same incident, and the incident is
  judged on everything they did between them.
- Allowlists that can't be satisfied by a name. dnf, gdb, nmap, runc and
  friends are forgiven only when the binary is owned by an installed
  package, matches the package's SHA-256, and is the same inode the kernel
  executed. A process loaded with `LD_PRELOAD`, `LD_AUDIT` or
  `LD_LIBRARY_PATH`, or one that has been ptrace-attached, gets no
  forgiveness at all.
- Incidents on disk under `/var/lib/aegis-v2/incidents`, written
  atomically, with a timeline of each decision and every process involved.
- Telemetry to journald, a JSON-lines file and OTLP logs over http or
  https with auth headers. A slow collector costs you records, never
  detection.
- `aegisctl status`, `preflight` and `incidents list | show | timeline`,
  all with `--json`. Text pulled from an incident is escaped before it
  reaches your terminal.
- RPMs for x86_64 and aarch64: a hardened systemd unit with five
  capabilities, and an SELinux module that confines aegisd to its own
  `aegisd_t` domain. It runs in enforcing mode with no denials across the
  end-to-end suite. OTLP needs `setsebool -P aegisd_can_network_connect 1`.
- `cargo xtask e2e`, which installs the RPMs on a disposable test host and
  runs twelve attack and everyday-admin scenarios, including a container
  start and an ssh login that must stay quiet.
- CI on every pull request, a licence and advisory audit, and a tag-driven
  release that builds both architectures and publishes checksums.
- A README and a full set of docs, including a threat model that says
  plainly what v0.1.0 can and can't see.

### Known limits

- Audit mode only. `mode = "enforce"` is refused at startup.
- The injection checks are best effort: a library can scrub its own
  environment, and a tracer that attaches before exec isn't seen. Capture
  in the kernel is planned for v0.2.0.
- UDP, and scans spread one connection per process, aren't detected.
- Binaries on btrfs subvolumes, overlay roots and inside containers stay
  unverified, so their allowlist entries don't apply.

The [threat model](docs/threat-model.md) has the full list.

[Unreleased]: https://github.com/jamesconwaydev/aegis-v2/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesconwaydev/aegis-v2/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jamesconwaydev/aegis-v2/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jamesconwaydev/aegis-v2/releases/tag/v0.1.0
