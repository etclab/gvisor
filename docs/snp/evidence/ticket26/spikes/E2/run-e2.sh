#!/bin/bash
# Spike E2: the exec sink's cost and reach.
#
#   run-e2.sh <runsc> <workdir> <faketunneld> <seccheck-receiver> <execbench> [claude-elf]
#
# Four runs, and the fourth only if this host has the pieces for it.
#
#   a-no-sink     no policy is pushed, so no exec sink and no execve point at
#                 all. This is the baseline the cost is measured against.
#   b-sink        a policy whose x names every binary this workload runs, so
#                 the sink is installed, the hash is computed and nothing is
#                 refused. The difference from (a) is what X costs.
#   c-sink-trace  the same, with a remote sink receiving the execve point, so
#                 that every (path, sha256) the sandbox executed is listed. The
#                 difference from (b) is what the TRACE costs, which is not the
#                 same thing as what the decision costs.
#   d-claude      Claude Code's own execs, with the execve point enabled by the
#                 trace session and NO policy pushed, so nothing is refused and
#                 the list is complete. NO NETWORK IS REACHABLE (the tunnel
#                 table is empty of the API host) and NO API KEY IS PASSED: the
#                 CLI is asked for --version and then for a prompt it cannot
#                 send, and what is recorded is what it exec'd on the way.
#
# There is no tunneld here; `faketunneld` is E1's stand-in, and it is only used
# to push. Nothing in this run is evidence about tunneld, and nothing in it
# spends money.
set -uo pipefail
RUNSC="${1:?runsc}"; WORK="${2:?workdir}"; FAKE="${3:?faketunneld}"
RECV="${4:?seccheck-receiver}"; BENCH="${5:?execbench}"; CLAUDE="${6:-}"

FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"
N="${N:-200}"
SHM="/dev/shm/t26-e2-$$"
mkdir -p "$SHM"; chmod 700 "$SHM"
trap 'rm -rf "$SHM"' EXIT

echo "runsc sha256:          $(sha256sum "$RUNSC" | cut -d' ' -f1)"
echo "faketunneld sha256:    $(sha256sum "$FAKE" | cut -d' ' -f1)"
echo "receiver sha256:       $(sha256sum "$RECV" | cut -d' ' -f1)"
echo "execbench sha256:      $(sha256sum "$BENCH" | cut -d' ' -f1)"
echo "busybox sha256:        $(sha256sum /bin/busybox | cut -d' ' -f1)"
echo "date:                  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "execs per benchmark:   $N"
echo "ANTHROPIC_API_KEY is deliberately NOT passed into any bundle in this run."
echo

HERE="$(dirname "$(readlink -f "$0")")"

# ---- the busybox rootfs ----
R="$WORK/rootfs"
rm -rf "$WORK"; mkdir -p "$R"/{bin,proc,tmp,etc}
install -m 755 /bin/busybox "$R/bin/busybox"
for a in sh uname echo cat head sleep date wc tr; do ln -sf busybox "$R/bin/$a"; done
install -m 755 "$BENCH" "$R/bin/execbench"
install -m 755 "$HERE/e2-workload.sh" "$R/e2-workload.sh"
install -m 755 "$HERE/e2-script.sh" "$R/e2-script.sh"
# /bin/probe is the same busybox with a comment appended: a different file, at a
# different path, so neither its path nor its digest is one busybox's is.
cp /bin/busybox "$R/bin/probe"
printf '\n# E2: this copy of busybox is a different file, so it has a different sha256.\n' >> "$R/bin/probe"
chmod 755 "$R/bin/probe"
printf '127.0.0.1\tlocalhost\n' > "$R/etc/hosts"
printf 'hosts: files dns\n'      > "$R/etc/nsswitch.conf"
printf 'nameserver 127.0.0.53\n' > "$R/etc/resolv.conf"
chmod -R a+rX "$R"
echo "the busybox rootfs:"
echo "  /bin/busybox   $(sha256sum "$R/bin/busybox" | cut -d' ' -f1)"
echo "  /bin/probe     $(sha256sum "$R/bin/probe" | cut -d' ' -f1)"
echo "  /bin/execbench $(sha256sum "$R/bin/execbench" | cut -d' ' -f1)"
echo

table() { # table <dir>
	mkdir -p "$1"
	printf '{"default_exit":"b","names":{"nowhere.example":{"port":443}}}\n' > "$1/table.json"
	echo "$1/table.json"
}

podinit() { # podinit <dir> <events-socket>
	mkdir -p "$1"
	cat > "$1/pod-init.json" <<PODINIT
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
	echo "$1/pod-init.json"
}

# podinit_exec also asks for the execve point itself, with the digest field, so
# that a run with no policy pushed still lists every identity.
podinit_exec() { # podinit_exec <dir> <events-socket>
	mkdir -p "$1"
	cat > "$1/pod-init.json" <<PODINIT
{
	"trace_session": {
		"name": "Default",
		"points": [
			{"name": "sentry/execve", "optional_fields": ["binary_sha256"], "context_fields": ["time", "container_id", "thread_id"]},
			{"name": "sentry/egress_refused", "context_fields": ["time", "container_id", "thread_id"]},
			{"name": "sentry/exec_refused", "context_fields": ["time", "container_id", "thread_id"]}
		],
		"sinks": [
			{"name": "remote", "config": {"endpoint": "$2", "retries": 3}, "ignore_setup_error": true}
		]
	}
}
PODINIT
	echo "$1/pod-init.json"
}

# ---- the runner ----
# run <name> <push: none|x> <trace: none|refusals|execve> <bundle-dir>
run() {
	local name="$1" push="$2" trace="$3" bundle="$4"
	local dir="$WORK/$name"; mkdir -p "$dir/logs"
	local t p ev cmd sock state recvpid fakepid runpid
	t=$(table "$dir")
	ev="$SHM/$name.events"
	case "$trace" in
	none)    p="" ;;
	refusals) p=$(podinit "$dir" "$ev") ;;
	execve)  p=$(podinit_exec "$dir" "$ev") ;;
	esac
	if [ -n "$p" ]; then
		"$RECV" "$ev" > "$dir/events.txt" 2>&1 &
		recvpid=$!
		for i in $(seq 1 100); do [ -S "$ev" ] && break; sleep 0.05; done
	fi

	sock="$SHM/$name.sock"
	cmd="$SHM/$name.cmd"
	mkfifo "$cmd"
	"$FAKE" -socket "$sock" -peer b -allow "nowhere.example:443" < "$cmd" > "$dir/faketunneld.txt" 2>&1 &
	fakepid=$!
	exec 3>"$cmd"
	for i in $(seq 1 200); do [ -S "$sock" ] && break; sleep 0.05; done

	state="$SHM/$name-state"
	mkdir -p "$state"
	echo
	echo "===== $name (push=$push trace=$trace) ====="
	local podflag=()
	[ -n "$p" ] && podflag=(--pod-init-config="$p")
	echo "\$ $RUNSC --root=$state $FLAGS --tunnel-socket=$sock --tunnel-table=$t ${podflag[*]-} --debug --debug-log=$dir/logs/ run --bundle $bundle t26-e2-$name-$$"
	timeout 600 "$RUNSC" --root="$state" $FLAGS \
		--tunnel-socket="$sock" --tunnel-table="$t" \
		"${podflag[@]}" \
		--debug --debug-log="$dir/logs/" \
		run --bundle "$bundle" "t26-e2-$name-$$" </dev/null > "$dir/workload.txt" 2>&1 &
	runpid=$!

	if [ "$push" = x ]; then
		local ready=0
		for i in $(seq 1 600); do
			if grep -q "Tunnel adapter installed" "$dir"/logs/*boot* 2>/dev/null; then ready=1; break; fi
			sleep 0.1
		done
		echo "the adapter was installed: ready=$ready after $i tenths of a second"
		echo "apply $WORK/policy-x.json" >&3
	fi

	wait $runpid; echo "RUNSC_EXIT=$?"
	echo "quit" >&3
	exec 3>&-
	wait $fakepid 2>/dev/null
	sleep 0.5
	if [ -n "${recvpid:-}" ]; then kill $recvpid 2>/dev/null; wait $recvpid 2>/dev/null; fi
	rm -f "$cmd"

	echo "---- what the workload said ----"
	cat "$dir/workload.txt"
	if [ "$push" = x ]; then
		echo "---- what the stand-in said ----"
		cat "$dir/faketunneld.txt"
	fi
	echo "---- what the sentry said about the exec sink ----"
	grep -h "exec sink\|exec refused\|policy x\|tunnel narrow" "$dir"/logs/*boot* 2>/dev/null
	if [ -n "$p" ]; then
		echo "---- the points the receiver got ----"
		cat "$dir/events.txt"
		echo "---- the distinct (path, sha256) in this run ----"
		grep -o 'execve path=[^ ]* sha256=[^ ]*' "$dir/events.txt" 2>/dev/null | sort | uniq -c | sort -rn
	fi
}

# ---- the busybox bundle ----
bbbundle() { # bbbundle <dir>
	local dir="$1/bundle"
	mkdir -p "$dir"
	cat > "$dir/config.json" <<JSON
{
	"ociVersion": "1.0.0",
	"process": {
		"terminal": false,
		"user": {"uid": 0, "gid": 0},
		"args": ["/bin/busybox", "sh", "/e2-workload.sh"],
		"env": ["PATH=/bin", "HOME=/tmp", "N=$N"],
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

# The policy the sink is installed from: x names, by path, every binary the
# busybox workload runs, so nothing is refused and the run measures the decision
# rather than a refusal. /bin/probe is deliberately NOT in it.
cat > "$WORK/policy-x.json" <<POLICY
{"format":"policy","version":1,"n":[],"f":[],"x":[{"path":"/bin/busybox"},{"path":"/bin/execbench"}]}
POLICY
echo "the policy pushed in runs b and c:"
echo "  $(cat "$WORK/policy-x.json")"
echo "  sha256 $(sha256sum "$WORK/policy-x.json" | cut -d' ' -f1)"

BB=$(bbbundle "$WORK/bb")
run a-no-sink    none none     "$BB"
run b-sink       x    refusals "$BB"
run c-sink-trace x    execve   "$BB"

# ---- Claude Code, if this host has it ----
if [ -z "$CLAUDE" ] || [ ! -x "$CLAUDE" ]; then
	echo
	echo "===== d-claude ====="
	echo "skipped: no Claude Code ELF was named, or it is not executable: '$CLAUDE'"
else
	CR="$WORK/claude-rootfs"
	mkdir -p "$CR"/{usr/local/bin,usr/bin,lib64,lib/x86_64-linux-gnu,etc/ssl/certs,home/agent,work,tmp,proc,sys,bin}
	chmod 1777 "$CR/tmp"
	install -m 755 "$CLAUDE" "$CR/usr/local/bin/claude"
	install -m 755 /lib64/ld-linux-x86-64.so.2 "$CR/lib64/ld-linux-x86-64.so.2"
	for lib in /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/librt.so.1 \
	           /lib/x86_64-linux-gnu/libpthread.so.0 /lib/x86_64-linux-gnu/libdl.so.2 \
	           /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/libnss_files.so.2 \
	           /lib/x86_64-linux-gnu/libnss_dns.so.2 /lib/x86_64-linux-gnu/libresolv.so.2; do
		[ -f "$lib" ] && install -m 644 "$lib" "$CR/lib/x86_64-linux-gnu/$(basename "$lib")"
	done
	if [ -x /usr/bin/git ]; then
		install -m 755 /usr/bin/git "$CR/usr/bin/git"
		for lib in /lib/x86_64-linux-gnu/libpcre2-8.so.0 /lib/x86_64-linux-gnu/libz.so.1; do
			[ -f "$lib" ] && install -m 644 "$lib" "$CR/lib/x86_64-linux-gnu/$(basename "$lib")"
		done
	fi
	install -m 755 /bin/busybox "$CR/bin/busybox"
	for a in sh env uname; do ln -sf busybox "$CR/bin/$a"; done
	[ -f /etc/ssl/certs/ca-certificates.crt ] && install -m 644 /etc/ssl/certs/ca-certificates.crt "$CR/etc/ssl/certs/ca-certificates.crt"
	printf 'nameserver 127.0.0.53\noptions timeout:5 attempts:2\n' > "$CR/etc/resolv.conf"
	printf 'hosts: files dns\npasswd: files\ngroup: files\n' > "$CR/etc/nsswitch.conf"
	printf '127.0.0.1\tlocalhost\n::1\tlocalhost\n' > "$CR/etc/hosts"
	printf 'root:x:0:0:root:/home/agent:/bin/sh\n' > "$CR/etc/passwd"
	printf 'root:x:0:\n' > "$CR/etc/group"
	chmod -R a+rX "$CR"
	echo
	echo "the Claude Code rootfs: $CLAUDE at /usr/local/bin/claude, sha256 $(sha256sum "$CLAUDE" | cut -d' ' -f1)"

	CB="$WORK/claude/bundle"; mkdir -p "$CB"
	cat > "$CB/config.json" <<JSON
{
	"ociVersion": "1.0.0",
	"process": {
		"terminal": false,
		"user": {"uid": 0, "gid": 0},
		"args": ["/bin/sh", "-c", "/usr/local/bin/claude --version; echo CLAUDE-VERSION-RC=\$?; /usr/local/bin/claude -p 'say hi' </dev/null; echo CLAUDE-PROMPT-RC=\$?"],
		"env": ["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/home/agent", "TERM=dumb",
		        "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"],
		"cwd": "/work",
		"capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": []},
		"rlimits": [{"type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096}]
	},
	"root": {"path": "$CR", "readonly": false},
	"hostname": "workload",
	"mounts": [
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["ro", "nosuid", "noexec"]},
		{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"}
	],
	"linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "ipc"}, {"type": "uts"}]}
}
JSON
	run d-claude none execve "$CB"
fi

echo
echo "===== E2 complete ====="
