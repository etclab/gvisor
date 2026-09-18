#!/bin/bash
# Spike E1: narrowing under traffic.
#
#   run-e1.sh <runsc> <workdir> <faketunneld> <seccheck-receiver> <workload.sh>
#
# The question the ticket asks is whether a pushed policy can replace the
# sentry's table while a workload is running and a stream is carrying bytes —
# and, if it can, what it costs and what the workload sees. Two runs answer it:
#
#   narrow-other   the stream is on bulk.peer-a and the narrowing removes
#                  drop.peer-a, the OTHER name
#   narrow-self    the narrowing removes bulk.peer-a, the name the open stream
#                  is ON, which is the case where "live streams are untouched"
#                  is a claim about something rather than a tautology
#
# Each run pushes twelve policies. The first is the whole table, which is the
# push that fixes f and x; the second is the narrowing the workload watches for;
# and ten more drop one filler name each, so that the cost of a swap is measured
# over more than one sample. A thirteenth push tries to put a name back, which
# must be refused by name.
#
# There is no tunneld here. `faketunneld` serves attest/sandbox's local socket
# and pushes through Host.Apply, and behind each stream is its own exit; nothing
# in this run is evidence about tunneld, about attestation or about two peers.
set -uo pipefail
RUNSC="${1:?runsc}"; WORK="${2:?workdir}"; FAKE="${3:?faketunneld}"
RECV="${4:?seccheck-receiver}"; WORKLOAD="${5:?workload.sh}"

FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"
BULK="bulk.peer-a:9000"
DROP="drop.peer-a:9001"
SLOW_BYTES=16777216
SLOW_CHUNK=65536
SLOW_PAUSE=50ms
SHM="/dev/shm/t26-e1-$$"
mkdir -p "$SHM"; chmod 700 "$SHM"
trap 'rm -rf "$SHM"' EXIT

echo "runsc sha256:          $(sha256sum "$RUNSC" | cut -d' ' -f1)"
echo "faketunneld sha256:    $(sha256sum "$FAKE" | cut -d' ' -f1)"
echo "receiver sha256:       $(sha256sum "$RECV" | cut -d' ' -f1)"
echo "workload sha256:       $(sha256sum "$WORKLOAD" | cut -d' ' -f1)"
echo "busybox sha256:        $(sha256sum /bin/busybox | cut -d' ' -f1)"
echo "date:                  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "slow body:             $SLOW_BYTES bytes, $SLOW_CHUNK per $SLOW_PAUSE"
echo

# ---- the rootfs, shared by both runs ----
R="$WORK/rootfs"
rm -rf "$WORK"; mkdir -p "$R"/{bin,proc,tmp,etc}
install -m 755 /bin/busybox "$R/bin/busybox"
for a in sh wget nslookup wc date sleep echo tr cat; do ln -sf busybox "$R/bin/$a"; done
install -m 755 "$WORKLOAD" "$R/e1-workload.sh"
printf '127.0.0.1\tlocalhost\n' > "$R/etc/hosts"
printf 'hosts: files dns\n'      > "$R/etc/nsswitch.conf"
printf 'nameserver 127.0.0.53\n' > "$R/etc/resolv.conf"
chmod -R a+rX "$R"

# ---- the table: the two names the workload uses and ten fillers ----
# Sorted, so the addresses are 100.64.1.0 upward in this order:
#   bulk.peer-a  drop.peer-a  fill01..fill10
table() { # table <dir>
	local dir="$1"; mkdir -p "$dir"
	{
		printf '{"default_exit":"b","names":{'
		printf '"bulk.peer-a":{"port":9000},"drop.peer-a":{"port":9001}'
		for i in 01 02 03 04 05 06 07 08 09 10; do
			printf ',"fill%s.peer-a":{"port":9002}' "$i"
		done
		printf '}}\n'
	} > "$dir/table.json"
	echo "$dir/table.json"
}

# ---- the policies ----
# n is written as {host, ports}; f and x are fixed by the first push and are the
# same in every one of them, so that only n ever moves.
policy() { # policy <path> <name:port>...
	local out="$1"; shift
	{
		printf '{"format":"policy","version":1,"n":['
		local first=1 hp host port
		for hp in "$@"; do
			host="${hp%:*}"; port="${hp#*:}"
			[ $first = 1 ] || printf ','
			first=0
			printf '{"host":"%s","ports":[%s]}' "$host" "$port"
		done
		printf '],"f":[{"path":"/tmp","modes":["r"]}],"x":[]}\n'
	} > "$out"
	echo "$out"
}

fillers() { # fillers <first-to-keep-index>
	local i
	for i in $(seq -w 1 "$1"); do printf 'fill%s.peer-a:9002\n' "$i"; done
}

podinit() { # podinit <dir> <events-socket>
	local dir="$1"; mkdir -p "$dir"
	cat > "$dir/pod-init.json" <<PODINIT
{
	"trace_session": {
		"name": "Default",
		"points": [
			{"name": "sentry/egress_refused", "context_fields": ["time", "container_id", "thread_id"]},
			{"name": "sentry/exec_refused", "context_fields": ["time", "container_id", "thread_id"]}
		],
		"sinks": [
			{"name": "remote", "config": {"endpoint": "$2", "retries": 3}, "ignore_setup_error": true}
		]
	}
}
PODINIT
	echo "$dir/pod-init.json"
}

bundle() { # bundle <dir> <which>
	local dir="$1/bundle" which="$2"
	mkdir -p "$dir"
	cat > "$dir/config.json" <<JSON
{
	"ociVersion": "1.0.0",
	"process": {
		"terminal": false,
		"user": {"uid": 0, "gid": 0},
		"args": ["/bin/busybox", "sh", "/e1-workload.sh"],
		"env": ["PATH=/bin", "HOME=/tmp",
		        "BULK=$BULK", "DROP=$DROP", "EXPECT=$SLOW_BYTES",
		        "DROPADDR=$3", "WHICH=$which"],
		"cwd": "/",
		"capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": []},
		"rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}]
	},
	"root": {"path": "$R", "readonly": true},
	"hostname": "workload",
	"mounts": [
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["ro", "noexec"]}
	],
	"linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}]}
}
JSON
	echo "$dir"
}

run() { # run <name> <which: other|self>
	local name="$1" which="$2"
	local dir="$WORK/$name"; mkdir -p "$dir/logs" "$dir/policies"
	local t b p ev cmd
	t=$(table "$dir")
	ev="$SHM/$name.events"
	p=$(podinit "$dir" "$ev")
	# The removed name's old synthetic address: the table is sorted, so
	# bulk.peer-a is 100.64.1.0 and drop.peer-a is 100.64.1.1. The workload
	# prints what the resolver actually said as well, so the two can be read
	# against each other.
	local dropaddr=100.64.1.1
	[ "$which" = self ] && dropaddr=100.64.1.0
	b=$(bundle "$dir" "$which" "$dropaddr")

	# The policies, in the order they are pushed.
	local all=("$BULK" "$DROP")
	local i
	for i in $(fillers 10); do all+=("$i"); done
	policy "$dir/policies/p00-all.json" "${all[@]}" > /dev/null
	# The narrowing the workload watches for.
	local narrowed=()
	if [ "$which" = self ]; then narrowed=("$DROP"); else narrowed=("$BULK"); fi
	for i in $(fillers 10); do narrowed+=("$i"); done
	policy "$dir/policies/p01-narrow.json" "${narrowed[@]}" > /dev/null
	# Ten more, each dropping one filler.
	local k
	for k in 10 09 08 07 06 05 04 03 02 01; do
		local next=()
		if [ "$which" = self ]; then next=("$DROP"); else next=("$BULK"); fi
		local j
		for j in $(seq -w 1 "$k"); do
			[ "$j" = "$k" ] && continue
			next+=("fill$j.peer-a:9002")
		done
		policy "$dir/policies/p$(printf '%02d' $((12 - 10#$k)))-drop-fill$k.json" "${next[@]}" > /dev/null
	done
	# And one that tries to put a name back.
	policy "$dir/policies/p99-widen.json" "${all[@]}" > /dev/null

	"$RECV" "$ev" > "$dir/events.txt" 2>&1 &
	local recvpid=$!
	for i in $(seq 1 100); do [ -S "$ev" ] && break; sleep 0.05; done

	cmd="$SHM/$name.cmd"
	mkfifo "$cmd"
	"$FAKE" -socket "$SHM/$name.sock" -peer b \
		-allow "$BULK,$DROP,fill01.peer-a:9002" \
		-slow "$BULK" -slow-bytes "$SLOW_BYTES" -slow-chunk "$SLOW_CHUNK" -slow-pause "$SLOW_PAUSE" \
		< "$cmd" > "$dir/faketunneld.txt" 2>&1 &
	local fakepid=$!
	exec 3>"$cmd"
	for i in $(seq 1 200); do [ -S "$SHM/$name.sock" ] && break; sleep 0.05; done
	[ -S "$SHM/$name.sock" ] || { echo "the stand-in never bound its socket"; cat "$dir/faketunneld.txt"; return 1; }

	echo
	echo "===== $name ====="
	echo "table: $(tr -s ' \n' ' ' < "$t")"
	# The state directory is short and on /dev/shm on purpose. The sentry's
	# control socket lives under --root and is an AF_UNIX path, so --root plus
	# "runsc-<container id>.sock" has to fit in sockaddr_un's 108 bytes: a
	# deeper root makes `unet.Connect` fail with EINVAL, which is what this
	# harness hit on its first run and what the notes record.
	local state="$SHM/$name-state"
	mkdir -p "$state"
	echo "\$ $RUNSC --root=$state $FLAGS --tunnel-socket=$SHM/$name.sock --tunnel-table=$t --pod-init-config=$p --debug --debug-log=$dir/logs/ run --bundle $b t26-e1-$name-$$"
	timeout 300 "$RUNSC" --root="$state" $FLAGS \
		--tunnel-socket="$SHM/$name.sock" --tunnel-table="$t" \
		--pod-init-config="$p" \
		--debug --debug-log="$dir/logs/" \
		run --bundle "$b" "t26-e1-$name-$$" </dev/null > "$dir/workload.txt" 2>&1 &
	local runpid=$!

	# Wait for the sentry to say the adapter is in, then push.
	local ready=0
	for i in $(seq 1 400); do
		if grep -q "Tunnel adapter installed" "$dir"/logs/*boot* 2>/dev/null; then ready=1; break; fi
		sleep 0.1
	done
	echo "the adapter was installed: ready=$ready after $i tenths of a second"

	echo "apply $dir/policies/p00-all.json" >&3

	# Wait until the workload says its long stream is running, and then let it
	# run for a few seconds before narrowing. A fixed sleep here is what the
	# first version of this script had, and it pushed the narrowing ten seconds
	# BEFORE the stream started: the workload's two nslookups take about seven
	# seconds each through the sentry's responder. "Under traffic" has to be
	# synchronised on the traffic.
	local flowing=0
	for i in $(seq 1 600); do
		if grep -q "LONG STARTED" "$dir/workload.txt" 2>/dev/null; then flowing=1; break; fi
		sleep 0.1
	done
	echo "the workload's long stream is running: flowing=$flowing after $i tenths of a second"
	sleep 3
	echo "echo ---- the narrowing goes in now, with the stream in flight ----" >&3
	echo "apply $dir/policies/p01-narrow.json" >&3
	sleep 1
	for f in "$dir"/policies/p0[2-9]-*.json "$dir"/policies/p1[01]-*.json; do
		[ -e "$f" ] || continue
		echo "apply $f" >&3
		sleep 0.4
	done
	echo "echo ---- and one that widens ----" >&3
	echo "apply $dir/policies/p99-widen.json" >&3
	sleep 1

	wait $runpid; echo "RUNSC_EXIT=$?"
	echo "quit" >&3
	exec 3>&-
	wait $fakepid 2>/dev/null
	sleep 0.5
	kill $recvpid 2>/dev/null; wait $recvpid 2>/dev/null
	rm -f "$cmd"

	echo "---- what the workload said ----"
	cat "$dir/workload.txt"
	echo "---- what the stand-in said ----"
	cat "$dir/faketunneld.txt"
	echo "---- the sentry on the tunnel and the narrowings ----"
	grep -h "tunnel\|policy\|Policy" "$dir"/logs/*boot* 2>/dev/null
	echo "---- what the helper said ----"
	grep -h "Tunnel helper\|policy" "$dir"/logs/*tunnel-helper* 2>/dev/null
	echo "---- sentry events ----"
	cat "$dir/events.txt"
	echo "---- the policies pushed, with their digests ----"
	for f in "$dir"/policies/*.json; do
		printf '%s  %s\n  %s\n' "$(basename "$f")" "$(sha256sum "$f" | cut -d' ' -f1)" "$(cat "$f")"
	done
}

run narrow-other other
run narrow-self  self
echo
echo "===== E1 complete ====="
