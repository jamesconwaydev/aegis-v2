#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Stage one incident on a test box and show how Aegis builds it.
#
#   sudo examples/lab/run.sh              (PACE=0 to skip the pauses)
#   sudo MODE=enforce examples/lab/run.sh (aegisd in enforce mode)
#
# Needs root on a Rocky Linux 10 VM you don't mind poking, with aegisd
# running in MODE (audit unless you say otherwise) and strace
# installed. Nothing here is malware.
# The "payload" is a copy of the host's own bash, run from a temp
# directory. It knocks on 30 closed loopback ports, then a copy of
# strace attaches to a sleep the script started as a throwaway service,
# and detaches two seconds later. Nothing leaves the host, and nothing
# outside the script's own temp directory and unit is touched. On exit,
# even on Ctrl-C, it stops the unit and removes the temp directory. The
# incident stays in /var/lib/aegis-v2/incidents.
#
# With MODE=enforce, aegisd quarantines the tree: the copies of bash,
# timeout and strace are held, moved into their own scope, frozen and
# cut off. The script shows that, then kills the incident on exit.
set -euo pipefail

MODE=${MODE:-audit}
case $MODE in
audit) WANT=would_quarantine ;;
enforce) WANT=quarantined ;;
*)
	echo "run.sh: MODE is audit or enforce, not $MODE" >&2
	exit 1
	;;
esac
SUFFIX=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
TARGET=aegis-lab-target-$SUFFIX.service

say() {
	printf '\n\033[1;36m# %s\033[0m\n' "$*"
	sleep "${PACE:-1.5}"
}
die() {
	echo "run.sh: $*" >&2
	exit 1
}

[ "$(id -u)" = 0 ] || die "run me as root"
command -v strace >/dev/null || die "needs strace (dnf install strace)"
mode=$(aegisctl --json status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["mode"])') ||
	die "aegisd isn't running (systemctl enable --now aegisd)"
[ "$mode" = "$MODE" ] || die "aegisd is in $mode mode; run with MODE=$mode, or set mode = \"$MODE\" and reload"
[ "$MODE" = audit ] || command -v nft >/dev/null || die "needs nft (dnf install nftables)"

WORK=$(mktemp -d /tmp/aegis-lab.XXXXXX)
ID=
cleanup() {
	set +e
	# A quarantined tree stays frozen until someone ends it.
	[ "$MODE" = enforce ] && [ -n "$ID" ] && aegisctl incidents kill "$ID"
	# Whatever of the payload is still running, if we stopped early.
	pkill -KILL -f "^$WORK/"
	systemctl stop "$TARGET" 2>/dev/null
	systemctl reset-failed "$TARGET" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

# Incident ids, oldest first, so the new one is whatever wasn't there.
incident_ids() {
	aegisctl --json incidents list | python3 -c '
import json, sys
print("\n".join(sorted(i["id"] for i in json.load(sys.stdin))))
'
}
# Waits up to 20 s for an incident that wasn't there before to reach
# $WANT, and prints its id.
new_incident() {
	local id
	for _ in $(seq 40); do
		id=$(aegisctl --json incidents list | python3 -c '
import json, sys
before = set(sys.argv[1].split())
print(next((i["id"] for i in json.load(sys.stdin)
            if i["id"] not in before and i["verdict"] == sys.argv[2]), ""))
' "$before" "$WANT")
		[ -z "$id" ] || {
			echo "$id"
			return
		}
		sleep 0.5
	done
	return 1
}
before=$(incident_ids)

say "a stand-in for a system daemon: sleep, as $TARGET"
systemd-run --quiet --unit="$TARGET" sleep 300
PID=$(systemctl show -p MainPID --value "$TARGET")
echo "pid $PID in system.slice/$TARGET"

say "the 'payload': copies of bash and strace in $WORK"
cp /usr/bin/bash /usr/bin/strace "$WORK/"
ls -l "$WORK"

say "run it: exec from /tmp, scan 30 closed loopback ports, then attach to pid $PID"
# The scan runs in the copied bash itself: a redirection on a builtin
# connects without forking. The attach runs as its child, so both land
# in one process tree and one incident. It runs in the background: in
# enforce mode it's frozen part-way and never finishes on its own.
"$WORK/bash" -c '
for port in $(seq 47000 47029); do
	{ : <>"/dev/tcp/127.0.0.1/$port"; } 2>/dev/null || true
done
echo "scanned 30 ports"
timeout 2 "$1" -e trace=none -p "$2" 2>/dev/null
echo "attached to $2 for 2 s, then detached"
' lab "$WORK/strace" "$PID" &
PAYLOAD=$!

ID=$(new_incident) || die "no new $WANT incident; check journalctl -u aegisd"
if [ "$MODE" = audit ]; then
	wait "$PAYLOAD" || true
else
	SCOPE=aegis-incident-$ID-q.scope
	say "quarantined: the tree is frozen in $SCOPE"
	systemctl show -p FreezerState "$SCOPE"
	ps -o pid,args -p "$(paste -sd, "/sys/fs/cgroup/aegis.slice/aegis-quarantine.slice/$SCOPE/cgroup.procs")"

	say "and cut off from the network"
	nft list table inet aegis
fi

say "aegisctl incidents list"
aegisctl incidents list

say "aegisctl incidents timeline $ID"
aegisctl incidents timeline "$ID"

say "aegisctl incidents show $ID"
aegisctl incidents show "$ID"

say "the evidence on disk"
ls -l "/var/lib/aegis-v2/incidents/$ID"

if [ "$MODE" = enforce ]; then
	say "on exit: aegisctl incidents kill $ID"
fi
