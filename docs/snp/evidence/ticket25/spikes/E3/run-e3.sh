#!/bin/bash
# Ticket 25, spike E3. A FilePayload round trip over the sandbox's control
# socket, and then real I/O on the FD that came back.
#
#   run-e3.sh <runsc-binary> <workdir> <supervisor-binary>
#
# Starts a sandbox whose workload just sleeps, so the control socket stays up;
# then runs the host-side supervisor against that control socket. Everything the
# sentry does is in its debug log; everything the supervisor does is on stderr.
set -euo pipefail
RUNSC="${1:?runsc}"; WORK="${2:?workdir}"; SUP="${3:?supervisor}"
FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"
ID=e3

rm -rf "$WORK/bundle" "$WORK/state" "$WORK/logs"
mkdir -p "$WORK/bundle/rootfs/bin" "$WORK/bundle/rootfs/proc" "$WORK/state" "$WORK/logs"
install -m 755 /bin/busybox "$WORK/bundle/rootfs/bin/busybox"
ln -sf busybox "$WORK/bundle/rootfs/bin/sh"
ln -sf busybox "$WORK/bundle/rootfs/bin/sleep"
cat > "$WORK/bundle/config.json" <<'JSON'
{
	"ociVersion": "1.0.0",
	"process": {
		"terminal": false,
		"user": {"uid": 0, "gid": 0},
		"args": ["/bin/sh", "-c", "echo workload-up; sleep 100; echo workload-done"],
		"env": ["PATH=/bin", "TERM=xterm"],
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

echo "runsc sha256:      $(sha256sum "$RUNSC" | cut -d' ' -f1)"
echo "supervisor sha256: $(sha256sum "$SUP" | cut -d' ' -f1)"
echo "\$ $RUNSC --root=$WORK/state $FLAGS --debug --debug-log=$WORK/logs/ run --bundle $WORK/bundle $ID &"
"$RUNSC" --root="$WORK/state" $FLAGS --debug --debug-log="$WORK/logs/" \
	run --bundle "$WORK/bundle" "$ID" </dev/null > "$WORK/workload.txt" 2>&1 &
RUNPID=$!

SOCK="$WORK/state/runsc-$ID.sock"
for i in $(seq 1 60); do [ -S "$SOCK" ] && break; sleep 0.5; done
if [ ! -S "$SOCK" ]; then echo "NO CONTROL SOCKET at $SOCK"; ls -la "$WORK/state"; kill $RUNPID; exit 1; fi
echo "control socket: $SOCK"
ls -la "$SOCK"

echo "\$ $SUP -ctrl $SOCK -mode e3 -hold 90s"
set +e
"$SUP" -ctrl "$SOCK" -mode e3 -hold 90s 2>&1
echo "SUPERVISOR_EXIT=$?"
wait $RUNPID
echo "RUNSC_EXIT=$?"
echo "---- workload stdout ----"
cat "$WORK/workload.txt"
