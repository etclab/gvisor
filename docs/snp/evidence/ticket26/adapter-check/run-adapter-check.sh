#!/bin/bash
# Ticket 26's adapter check: a sandbox that honours a pushed policy, end to end,
# with a stand-in where tunneld would be.
#
#   run-adapter-check.sh <runsc> <workdir> <faketunneld> <seccheck-receiver> <workload.sh>
#
# One sandbox, one run, and everything the definition of done says must be true
# of it:
#
#   P0   both names, x = [/bin/busybox]      accepted; the digest comes back
#   P1   one name, the same x                accepted; the other name is gone
#   P2   both names again                    REFUSED, naming the component
#   X    an exec of /bin/probe               EACCES, with an exec_refused event
#   N    the dropped name                    NXDOMAIN, with an egress_refused event
#        and its old synthetic address       ENETUNREACH, with another
#   F    a ["ro","noexec"] bind mount        an exec on it is EACCES before any policy
#   v3   one `alive` a second carrying the digest, watched from the stand-in;
#        a watch on the OLD digest is lost as a MISMATCH the moment P1 lands;
#        a watch on a digest nothing enforces is lost as a mismatch too;
#        and killing the workload closes the client, which the last watch sees.
#
# There is no tunneld, no attestation and no peer in this: `faketunneld` serves
# attest/sandbox's local socket, pushes through Host.Apply and watches through
# Host.Watch. Nothing here is evidence about tunneld, and nothing in it spends
# money — no API key is passed into any bundle.
set -uo pipefail
RUNSC="${1:?runsc}"; WORK="${2:?workdir}"; FAKE="${3:?faketunneld}"
RECV="${4:?seccheck-receiver}"; WORKLOAD="${5:?workload.sh}"

FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"
KEEP="keep.peer-a:9000"
GONE="gone.peer-a:9001"
SHM="/dev/shm/t26-check-$$"
mkdir -p "$SHM"; chmod 700 "$SHM"
trap 'rm -rf "$SHM"' EXIT

echo "runsc sha256:          $(sha256sum "$RUNSC" | cut -d' ' -f1)"
echo "faketunneld sha256:    $(sha256sum "$FAKE" | cut -d' ' -f1)"
echo "receiver sha256:       $(sha256sum "$RECV" | cut -d' ' -f1)"
echo "workload sha256:       $(sha256sum "$WORKLOAD" | cut -d' ' -f1)"
echo "busybox sha256:        $(sha256sum /bin/busybox | cut -d' ' -f1)"
echo "date:                  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "ANTHROPIC_API_KEY is deliberately NOT passed into any bundle in this run."
echo

# ---- the rootfs ----
R="$WORK/rootfs"
rm -rf "$WORK"; mkdir -p "$R"/{bin,proc,tmp,etc,noexec}
install -m 755 /bin/busybox "$R/bin/busybox"
for a in sh wget uname head sleep echo cat touch; do ln -sf busybox "$R/bin/$a"; done
install -m 755 "$WORKLOAD" "$R/check-workload.sh"
# /bin/probe: the same busybox with a comment appended, so it is a different
# file at a different path and neither half of x matches it.
cp /bin/busybox "$R/bin/probe"
printf '\n# the adapter check: a different file, so a different sha256.\n' >> "$R/bin/probe"
chmod 755 "$R/bin/probe"
# The source of the ro,noexec bind mount is a directory holding the very
# busybox x permits by path, so what refuses an exec there is the mount.
NOEXEC="$WORK/noexec-src"; mkdir -p "$NOEXEC"
install -m 755 /bin/busybox "$NOEXEC/busybox"
printf '127.0.0.1\tlocalhost\n' > "$R/etc/hosts"
printf 'hosts: files dns\n'      > "$R/etc/nsswitch.conf"
printf 'nameserver 127.0.0.53\n' > "$R/etc/resolv.conf"
chmod -R a+rX "$R" "$NOEXEC"
echo "the rootfs:"
echo "  /bin/busybox      $(sha256sum "$R/bin/busybox" | cut -d' ' -f1)"
echo "  /bin/probe        $(sha256sum "$R/bin/probe" | cut -d' ' -f1)"
echo "  /noexec/busybox   $(sha256sum "$NOEXEC/busybox" | cut -d' ' -f1)  (bind-mounted ro,noexec)"
echo

# ---- the table: the two names, and nothing else ----
cat > "$WORK/table.json" <<TABLE
{"default_exit":"b","names":{"keep.peer-a":{"port":9000},"gone.peer-a":{"port":9001}}}
TABLE
# gone.peer-a sorts before keep.peer-a, so its synthetic address is 100.64.1.0.
GONEADDR=100.64.1.0

# ---- the three policies ----
cat > "$WORK/p0.json" <<P0
{"format":"policy","version":1,"n":[{"host":"keep.peer-a","ports":[9000]},{"host":"gone.peer-a","ports":[9001]}],"f":[{"path":"/noexec","modes":["r"]}],"x":[{"path":"/bin/busybox"}]}
P0
cat > "$WORK/p1.json" <<P1
{"format":"policy","version":1,"n":[{"host":"keep.peer-a","ports":[9000]}],"f":[{"path":"/noexec","modes":["r"]}],"x":[{"path":"/bin/busybox"}]}
P1
cat > "$WORK/p2.json" <<P2
{"format":"policy","version":1,"n":[{"host":"keep.peer-a","ports":[9000]},{"host":"gone.peer-a","ports":[9001]}],"f":[{"path":"/noexec","modes":["r"]}],"x":[{"path":"/bin/busybox"}]}
P2
echo "the policies:"
for f in p0 p1 p2; do
	printf '  %-3s %s\n      %s\n' "$f" "$(sha256sum "$WORK/$f.json" | cut -d' ' -f1)" "$(cat "$WORK/$f.json")"
done
echo

# ---- the trace session ----
EV="$SHM/check.events"
cat > "$WORK/pod-init.json" <<PODINIT
{
	"trace_session": {
		"name": "Default",
		"points": [
			{"name": "sentry/egress_refused", "context_fields": ["time", "container_id", "thread_id"]},
			{"name": "sentry/exec_refused", "context_fields": ["time", "container_id", "thread_id"]}
		],
		"sinks": [
			{"name": "remote", "config": {"endpoint": "$EV", "retries": 3}, "ignore_setup_error": true}
		]
	}
}
PODINIT

# ---- the bundle ----
B="$WORK/bundle"; mkdir -p "$B"
cat > "$B/config.json" <<JSON
{
	"ociVersion": "1.0.0",
	"process": {
		"terminal": false,
		"user": {"uid": 0, "gid": 0},
		"args": ["/bin/busybox", "sh", "/check-workload.sh"],
		"env": ["PATH=/bin", "HOME=/tmp", "KEEP=$KEEP", "GONE=$GONE", "GONEADDR=$GONEADDR"],
		"cwd": "/",
		"capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": []},
		"rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}]
	},
	"root": {"path": "$R", "readonly": true},
	"hostname": "workload",
	"mounts": [
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/noexec", "type": "bind", "source": "$NOEXEC", "options": ["ro", "noexec", "rbind"]}
	],
	"linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}]}
}
JSON

# ---- the stand-in and the receiver ----
"$RECV" "$EV" > "$WORK/events.txt" 2>&1 &
RECVPID=$!
for i in $(seq 1 100); do [ -S "$EV" ] && break; sleep 0.05; done

SOCK="$SHM/tunneld.sock"
CMD="$SHM/cmd"
mkfifo "$CMD"
"$FAKE" -socket "$SOCK" -peer b -allow "$KEEP,$GONE" -slow "" < "$CMD" > "$WORK/faketunneld.txt" 2>&1 &
FAKEPID=$!
exec 3>"$CMD"
for i in $(seq 1 200); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || { echo "the stand-in never bound $SOCK"; cat "$WORK/faketunneld.txt"; exit 1; }

# ---- the sandbox ----
STATE="$SHM/state"; mkdir -p "$STATE"
ID="t26-check-$$"
mkdir -p "$WORK/logs"
echo "\$ $RUNSC --root=$STATE $FLAGS --tunnel-socket=$SOCK --tunnel-table=$WORK/table.json --pod-init-config=$WORK/pod-init.json --debug --debug-log=$WORK/logs/ run --bundle $B $ID"
timeout 300 "$RUNSC" --root="$STATE" $FLAGS \
	--tunnel-socket="$SOCK" --tunnel-table="$WORK/table.json" \
	--pod-init-config="$WORK/pod-init.json" \
	--debug --debug-log="$WORK/logs/" \
	run --bundle "$B" "$ID" </dev/null > "$WORK/workload.txt" 2>&1 &
RUNPID=$!

ready=0
for i in $(seq 1 600); do
	if grep -q "Tunnel adapter installed" "$WORK"/logs/*boot* 2>/dev/null; then ready=1; break; fi
	sleep 0.1
done
echo "the adapter was installed: ready=$ready after $i tenths of a second"

echo "echo ---- P0: both names, x names /bin/busybox ----" >&3
echo "apply $WORK/p0.json" >&3

# Wait for the workload to have used both names before narrowing.
flowing=0
for i in $(seq 1 600); do
	if grep -q "READY" "$WORK/workload.txt" 2>/dev/null; then flowing=1; break; fi
	sleep 0.1
done
echo "the workload reached READY: flowing=$flowing after $i tenths of a second"

# Five seconds of alive at one a second before anything changes.
sleep 5
echo "echo ---- P1: one name, which must lose the P0 watch as a MISMATCH ----" >&3
echo "apply $WORK/p1.json" >&3
sleep 3
echo "echo ---- P2: both names again ----" >&3
echo "apply $WORK/p2.json" >&3
sleep 1
echo "echo ---- a watch on a digest nothing is enforcing ----" >&3
echo "watch 0000000000000000000000000000000000000000000000000000000000000000" >&3

# Long enough that the P1 watch has seen many pulses and not lost them.
sleep 8
echo "echo ---- killing the workload ----" >&3
echo "the workload is being killed at $(date -u +%H:%M:%S.%N)"
"$RUNSC" --root="$STATE" kill "$ID" KILL 2>&1 | sed 's/^/kill: /'
wait $RUNPID; echo "RUNSC_EXIT=$?"
sleep 2
echo "quit" >&3
exec 3>&-
wait $FAKEPID 2>/dev/null
sleep 0.5
kill $RECVPID 2>/dev/null; wait $RECVPID 2>/dev/null
rm -f "$CMD"

echo
echo "---- what the workload said ----"
cat "$WORK/workload.txt"
echo "---- what the stand-in said: the pushes, the watches and the losses ----"
cat "$WORK/faketunneld.txt"
echo "---- the sentry on the policy, the table and the exec sink ----"
grep -h "tunnel\|policy\|exec sink\|exec refused" "$WORK"/logs/*boot* 2>/dev/null
echo "---- what the helper said ----"
grep -h "Tunnel helper" "$WORK"/logs/*tunnel-helper* 2>/dev/null
echo "---- the points the receiver got ----"
cat "$WORK/events.txt"
echo
echo "===== the adapter check is complete ====="
