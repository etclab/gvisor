#!/bin/bash
# Ticket 25, spike E1b. Runs an unmodified Go or Node client INSIDE a runsc
# sandbox whose sentry carries the prototype FD-backed endpoint, with the helper
# (E3's supervisor) attached over the control socket.
#
#   run-e1b.sh <runsc> <workdir> <supervisor> <goclient> <nodeclient.js> <go|node> <sync|started>
#
# The sandbox has no network (S1's flag set, --network=none), so the ONLY way a
# byte leaves it is the handoff. /etc/hosts points the two names at the synthetic
# 100.64.0.0/10 addresses the sentry intercepts; the clients are unmodified.
set -euo pipefail
RUNSC="${1:?runsc}"; WORK="${2:?workdir}"; SUP="${3:?supervisor}"
GOC="${4:?goclient}"; NODEJS="${5:?nodeclient.js}"; WHICH="${6:?go|node}"; MODE="${7:?sync|started}"
FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"
ID="e1b-$WHICH-$MODE"
REAL_HOST="www.rfc-editor.org:443"

rm -rf "$WORK/bundle" "$WORK/state" "$WORK/logs"
mkdir -p "$WORK/bundle/rootfs"/{bin,proc,tmp,etc/ssl/certs,lib/x86_64-linux-gnu,lib64,usr/bin} "$WORK/state" "$WORK/logs"
R="$WORK/bundle/rootfs"
install -m 755 /bin/busybox "$R/bin/busybox"
ln -sf busybox "$R/bin/sh"
install -m 755 "$GOC" "$R/bin/goclient"
install -m 644 "$NODEJS" "$R/bin/nodeclient.js"
install -m 644 /etc/ssl/certs/ca-certificates.crt "$R/etc/ssl/certs/ca-certificates.crt"

# Node and the libraries ldd names for it.
install -m 755 /usr/bin/node "$R/usr/bin/node"
for lib in $(ldd /usr/bin/node | awk '{print $3}' | grep '^/' ); do
	install -m 755 "$lib" "$R/lib/x86_64-linux-gnu/$(basename "$lib")"
done
install -m 755 /lib64/ld-linux-x86-64.so.2 "$R/lib64/ld-linux-x86-64.so.2"
# Ubuntu's node externalises some builtins to /usr/share/nodejs and aborts at
# startup without them ("Cannot load externalized builtin"). The directory is
# bind-mounted read-only rather than copied (154 MB).
mkdir -p "$R/usr/share/nodejs"

# The whole trick, and the only thing that makes the clients "unmodified": two
# names resolving to the synthetic addresses. glibc's getaddrinfo needs
# nsswitch.conf; Go's pure resolver reads /etc/hosts on its own.
cat > "$R/etc/hosts" <<HOSTS
127.0.0.1	localhost
100.64.0.1	www.rfc-editor.org
100.64.0.2	echo.spike.test
HOSTS
cat > "$R/etc/nsswitch.conf" <<NSS
hosts: files dns
NSS
echo "nameserver 127.0.0.53" > "$R/etc/resolv.conf"

# The client sleeps first: `runsc run` starts the container as soon as the
# sandbox is up, and the helper can only attach once the control socket exists.
if [ "$WHICH" = go ]; then
	ARGS='["/bin/sh", "-c", "sleep 5; exec /bin/goclient"]'
else
	ARGS='["/bin/sh", "-c", "sleep 5; exec /usr/bin/node /bin/nodeclient.js"]'
fi
cat > "$WORK/bundle/config.json" <<JSON
{
	"ociVersion": "1.0.0",
	"process": {
		"terminal": false,
		"user": {"uid": 0, "gid": 0},
		"args": $ARGS,
		"env": ["PATH=/bin:/usr/bin", "TERM=xterm", "HOME=/tmp", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"],
		"cwd": "/tmp",
		"capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": []},
		"rlimits": [{"type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096}]
	},
	"root": {"path": "rootfs", "readonly": true},
	"hostname": "workload",
	"mounts": [
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"},
		{"destination": "/usr/share/nodejs", "type": "bind", "source": "/usr/share/nodejs", "options": ["ro", "rbind"]}
	],
	"linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}]}
}
JSON
chmod -R a+rX "$WORK/bundle"

echo "runsc sha256:      $(sha256sum "$RUNSC" | cut -d' ' -f1)"
echo "supervisor sha256: $(sha256sum "$SUP" | cut -d' ' -f1)"
echo "client:            $WHICH, connect mode: $MODE"
echo "\$ $RUNSC --root=$WORK/state $FLAGS --debug --debug-log=$WORK/logs/ --strace run --bundle $WORK/bundle $ID &"
"$RUNSC" --root="$WORK/state" $FLAGS --debug --debug-log="$WORK/logs/" --strace \
	run --bundle "$WORK/bundle" "$ID" </dev/null > "$WORK/workload.txt" 2>&1 &
RUNPID=$!

SOCK="$WORK/state/runsc-$ID.sock"
for i in $(seq 1 120); do [ -S "$SOCK" ] && break; sleep 0.5; done
if [ ! -S "$SOCK" ]; then echo "NO CONTROL SOCKET at $SOCK"; kill $RUNPID 2>/dev/null; exit 1; fi
echo "control socket: $SOCK"

set +e
"$SUP" -ctrl "$SOCK" -mode "e1b-$MODE" -map "100.64.0.1:443=$REAL_HOST" -hold 180s 2>&1 &
SUPPID=$!
wait $RUNPID
echo "RUNSC_EXIT=$?"
kill $SUPPID 2>/dev/null
wait $SUPPID 2>/dev/null
echo "---- workload stdout ----"
cat "$WORK/workload.txt"
