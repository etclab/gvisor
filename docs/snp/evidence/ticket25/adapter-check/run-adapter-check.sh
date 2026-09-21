#!/bin/bash
# Ticket 25's adapter check: the sentry's egress adapter, end to end, with a
# stand-in where tunneld would be.
#
#   run-adapter-check.sh <runsc> <workdir> <faketunneld> <seccheck-receiver> <adapterclient> <adapternode.js>
#
# Six runs. Four are the adapter doing its job and being refused:
#
#   go            the Go workload, whose resolver is Go's own
#   node          the Node workload, whose resolver is glibc's
#   wrong-peer    the same table with a peer the stand-in does not answer for
#   no-helper     --tunnel-socket pointed at a socket nothing is listening on
#
# and two are the flags being refused before a sandbox exists:
#
#   validate-network   --network=sandbox with the two tunnel flags
#   validate-lonely    --tunnel-table without --tunnel-socket
#
# The sandbox has no network of its own (--network=none), so the only way a byte
# leaves it is the handoff, and the only way a name becomes an address is the
# sentry's responder: the rootfs has NO /etc/hosts entry for any of the names
# the workloads use.
set -uo pipefail
RUNSC="${1:?runsc}"; WORK="${2:?workdir}"; FAKE="${3:?faketunneld}"
RECV="${4:?seccheck-receiver}"; GOC="${5:?adapterclient}"; NODEJS="${6:?adapternode.js}"

FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"
ALLOW="www.rfc-editor.org:443"
SHM="/dev/shm/t25-adapter-$$"
mkdir -p "$SHM"; chmod 700 "$SHM"
trap 'rm -rf "$SHM"' EXIT

echo "runsc sha256:          $(sha256sum "$RUNSC" | cut -d' ' -f1)"
echo "faketunneld sha256:    $(sha256sum "$FAKE" | cut -d' ' -f1)"
echo "receiver sha256:       $(sha256sum "$RECV" | cut -d' ' -f1)"
echo "adapterclient sha256:  $(sha256sum "$GOC" | cut -d' ' -f1)"
echo "node:                  $(node --version 2>/dev/null || echo absent)"
echo "date:                  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

# ---- the rootfs, shared by every run ----
R="$WORK/rootfs"
rm -rf "$WORK"; mkdir -p "$R"/{bin,proc,tmp,etc/ssl/certs,lib/x86_64-linux-gnu,lib64,usr/bin,usr/share/nodejs}
install -m 755 /bin/busybox "$R/bin/busybox"; ln -sf busybox "$R/bin/sh"
install -m 755 "$GOC" "$R/bin/adapterclient"
install -m 644 "$NODEJS" "$R/bin/adapternode.js"
install -m 644 /etc/ssl/certs/ca-certificates.crt "$R/etc/ssl/certs/ca-certificates.crt"
if [ -x /usr/bin/node ]; then
	install -m 755 /usr/bin/node "$R/usr/bin/node"
	for lib in $(ldd /usr/bin/node | awk '{print $3}' | grep '^/'); do
		install -m 755 "$lib" "$R/lib/x86_64-linux-gnu/$(basename "$lib")"
	done
	install -m 755 /lib64/ld-linux-x86-64.so.2 "$R/lib64/ld-linux-x86-64.so.2"
	# glibc resolves through a dlopen'd NSS module; without it every getaddrinfo
	# is a files-only lookup and the responder is never asked.
	for nss in /lib/x86_64-linux-gnu/libnss_dns.so.2 /lib/x86_64-linux-gnu/libresolv.so.2; do
		[ -f "$nss" ] && install -m 755 "$nss" "$R/lib/x86_64-linux-gnu/$(basename "$nss")"
	done
fi
# The whole point of the check: a resolver pointed at the sentry, and NO hosts
# file entry for any name a workload asks for.
cat > "$R/etc/hosts" <<HOSTS
127.0.0.1	localhost
HOSTS
echo "hosts: files dns" > "$R/etc/nsswitch.conf"
echo "nameserver 127.0.0.53" > "$R/etc/resolv.conf"
echo "127.0.0.53" > "$R/etc/gai.conf.unused"

bundle() { # bundle <name> <argv-json>
	local name="$1" argv="$2" dir="$WORK/$1/bundle"
	mkdir -p "$dir"
	# The rootfs is built once and named absolutely from every bundle: runsc
	# refuses a bundle whose rootfs is a symlink (it checks that the path it
	# opened is the path it asked for), and copying it per run would be five
	# copies of node.
	cat > "$dir/config.json" <<JSON
{
	"ociVersion": "1.0.0",
	"process": {
		"terminal": false,
		"user": {"uid": 0, "gid": 0},
		"args": $argv,
		"env": ["PATH=/bin:/usr/bin", "HOME=/tmp", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"],
		"cwd": "/tmp",
		"capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": []},
		"rlimits": [{"type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096}]
	},
	"root": {"path": "$R", "readonly": true},
	"hostname": "workload",
	"mounts": [
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
		{"destination": "/usr/share/nodejs", "type": "bind", "source": "/usr/share/nodejs", "options": ["ro", "rbind"]}
	],
	"linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}]}
}
JSON
	chmod -R a+rX "$dir" 2>/dev/null || true
	echo "$dir"
}

table() { # table <name> <peer>
	local dir="$WORK/$1"; mkdir -p "$dir"
	cat > "$dir/table.json" <<TABLE
{
	"default_exit": "$2",
	"names": {
		"www.rfc-editor.org": {"port": 443},
		"refused.example": {"port": 443}
	}
}
TABLE
	echo "$dir/table.json"
}

podinit() { # podinit <name> <events-socket>
	local dir="$WORK/$1"; mkdir -p "$dir"
	cat > "$dir/pod-init.json" <<PODINIT
{
	"trace_session": {
		"name": "Default",
		"points": [
			{"name": "sentry/egress_refused", "context_fields": ["time", "container_id", "thread_id"]}
		],
		"sinks": [
			{"name": "remote", "config": {"endpoint": "$2", "retries": 3}, "ignore_setup_error": true}
		]
	}
}
PODINIT
	echo "$dir/pod-init.json"
}

# ---- the stand-in for tunneld ----
SOCKET="$SHM/tunneld.sock"
"$FAKE" -socket "$SOCKET" -allow "$ALLOW" -peer b > "$WORK/faketunneld.txt" 2>&1 &
FAKEPID=$!
for i in $(seq 1 100); do [ -S "$SOCKET" ] && break; sleep 0.1; done
[ -S "$SOCKET" ] || { echo "the stand-in never bound $SOCKET"; cat "$WORK/faketunneld.txt"; exit 1; }
echo "the stand-in for tunneld is serving $SOCKET, allow=$ALLOW"

run() { # run <name> <argv-json> <peer> <socket-override>
	local name="$1" argv="$2" peer="$3" socket="${4:-$SOCKET}"
	local dir="$WORK/$name"; mkdir -p "$dir/logs"
	local b t p ev
	b=$(bundle "$name" "$argv")
	t=$(table "$name" "$peer")
	ev="$SHM/$name.events"
	p=$(podinit "$name" "$ev")
	"$RECV" "$ev" > "$dir/events.txt" 2>&1 &
	local recvpid=$!
	for i in $(seq 1 100); do [ -S "$ev" ] && break; sleep 0.05; done

	echo
	echo "===== $name ====="
	echo "table: $(cat "$t" | tr -s ' \n' ' ')"
	echo "\$ $RUNSC --root=$dir/state $FLAGS --tunnel-socket=$socket --tunnel-table=$t --pod-init-config=$p --debug --debug-log=$dir/logs/ run --bundle $b t25-$name-$$"
	mkdir -p "$dir/state"
	timeout 180 "$RUNSC" --root="$dir/state" $FLAGS \
		--tunnel-socket="$socket" --tunnel-table="$t" \
		--pod-init-config="$p" \
		--debug --debug-log="$dir/logs/" \
		run --bundle "$b" "t25-$name-$$" </dev/null > "$dir/workload.txt" 2>&1
	echo "RUNSC_EXIT=$?"
	sleep 1
	kill $recvpid 2>/dev/null; wait $recvpid 2>/dev/null
	echo "---- workload ----"
	cat "$dir/workload.txt"
	echo "---- sentry/egress_refused ----"
	cat "$dir/events.txt"
	echo "---- what the sentry said about the tunnel ----"
	grep -h "tunnel" "$dir"/logs/*boot* 2>/dev/null | sed 's/^.*\] //' | head -40
	echo "---- the names the workload asked the responder for ----"
	grep -ho "tunnel dns: .*" "$dir"/logs/*boot* 2>/dev/null | sort | uniq -c
}

run go   '["/bin/sh", "-c", "exec /bin/adapterclient"]' b
if [ -x /usr/bin/node ]; then
	run node '["/bin/sh", "-c", "exec /usr/bin/node /bin/adapternode.js"]' b
else
	echo; echo "===== node ====="; echo "skipped: no /usr/bin/node on this host"
fi
run wrong-peer '["/bin/sh", "-c", "exec /bin/adapterclient"]' zz
run no-helper  '["/bin/sh", "-c", "exec /bin/adapterclient"]' b "$SHM/nothing-here.sock"

echo
echo "===== validate-network ====="
T=$(table validate-network b)
B=$(bundle validate-network '["/bin/sh", "-c", "true"]')
mkdir -p "$WORK/validate-network/state"
echo "\$ $RUNSC --root=$WORK/validate-network/state --platform=systrap --network=sandbox --tunnel-socket=$SOCKET --tunnel-table=$T run ..."
"$RUNSC" --root="$WORK/validate-network/state" --platform=systrap --network=sandbox --ignore-cgroups --rootless \
	--tunnel-socket="$SOCKET" --tunnel-table="$T" run --bundle "$B" "t25-vn-$$" 2>&1 | tail -3
echo "RUNSC_EXIT=${PIPESTATUS[0]}"

echo
echo "===== validate-lonely ====="
echo "\$ $RUNSC --root=$WORK/validate-network/state --platform=systrap --network=none --tunnel-table=$T run ..."
"$RUNSC" --root="$WORK/validate-network/state" --platform=systrap --network=none --ignore-cgroups --rootless \
	--tunnel-table="$T" run --bundle "$B" "t25-vl-$$" 2>&1 | tail -3
echo "RUNSC_EXIT=${PIPESTATUS[0]}"

echo
echo "===== the stand-in's own log ====="
kill $FAKEPID 2>/dev/null; wait $FAKEPID 2>/dev/null
cat "$WORK/faketunneld.txt"
