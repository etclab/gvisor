#!/bin/bash
# Ticket 25, spike E2. Runs the UDP/TCP probe inside a runsc sandbox booted with
# S1's flag set (--network=none), with the sentry's debug log and strace on, so
# the SPIKE-E2 log lines in the sentry and the caller's errnos can be read side
# by side.
#
#   run-e2.sh <runsc-binary> <workdir> <probe-binary>
#
# Host-side only; no sudo, rootless. The bundle is a directory (ticket 24 E3's
# layout minus the workload-device step).
set -euo pipefail
RUNSC="${1:?runsc}"; WORK="${2:?workdir}"; PROBE="${3:?probe}"
FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"

rm -rf "$WORK/bundle" "$WORK/state" "$WORK/logs"
mkdir -p "$WORK/bundle/rootfs/proc" "$WORK/bundle/rootfs/etc" "$WORK/state" "$WORK/logs"
install -m 755 "$PROBE" "$WORK/bundle/rootfs/udpprobe"
cat > "$WORK/bundle/config.json" <<'JSON'
{
	"ociVersion": "1.0.0",
	"process": {
		"terminal": false,
		"user": {"uid": 0, "gid": 0},
		"args": ["/udpprobe"],
		"env": ["PATH=/", "TERM=xterm"],
		"cwd": "/",
		"capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": []},
		"rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}]
	},
	"root": {"path": "rootfs", "readonly": true},
	"hostname": "workload",
	"mounts": [{"destination": "/proc", "type": "proc", "source": "proc"}],
	"linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}]}
}
JSON
chmod -R a+rX "$WORK/bundle"

echo "runsc sha256: $(sha256sum "$RUNSC" | cut -d' ' -f1)"
echo "probe sha256: $(sha256sum "$PROBE" | cut -d' ' -f1)"
echo "\$ $RUNSC --root=$WORK/state $FLAGS --debug --debug-log=$WORK/logs/ --strace run --bundle $WORK/bundle e2"
set +e
"$RUNSC" --root="$WORK/state" $FLAGS --debug --debug-log="$WORK/logs/" --strace \
	run --bundle "$WORK/bundle" e2 </dev/null 2>&1
echo "RUNSC_EXIT=$?"
