#!/bin/bash
# E4 part 2: is a user namespace enough for systrap's RequiresCapSysPtrace, or
# does runsc demand host capabilities? The SAME workload
# (/bin/busybox sh -c 'echo hi; ls /') every time; only the caller's
# namespace/capability arrangement and the runsc flags change. No sudo.
#
# Each runsc invocation writes to its own file: runsc hands the caller's fd 1
# straight to the sandbox, and a shared file offset clobbers the output (the
# same trap E2 hit).
S="$(dirname "$(readlink -f "$0")")"
RUNSC="$S/../bin/runsc"
BUNDLE="$S/img/bundle-hi"
FLAGS="--platform=systrap --network=none --ignore-cgroups"
OUT="$S/capout"; rm -rf "$OUT"; mkdir -p "$OUT"

echo "######## caller identity and host capabilities, before anything runs"
id
grep -E '^(Cap|NoNewPrivs|Seccomp)' /proc/self/status
echo "uid_map: $(cat /proc/self/uid_map)"
echo "host /proc/mounts lines: $(wc -l < /proc/mounts)"
echo "null-netns lines in the host mount table: $(grep -c null-netns /proc/mounts)"

echo
echo "######## (d) yama ptrace_scope on this host"
echo "\$ cat /proc/sys/kernel/yama/ptrace_scope"
cat /proc/sys/kernel/yama/ptrace_scope

echo
echo "######## (b) plain shell: NO outer unshare, NO --rootless, unprivileged user"
rm -rf "$S/state-b"; mkdir -p "$S/state-b"
echo "\$ runsc --root=\$S/state-b $FLAGS run --bundle \$BUNDLE s1-e4-b"
"$RUNSC" --root="$S/state-b" $FLAGS run --bundle "$BUNDLE" s1-e4-b </dev/null >"$OUT/b" 2>&1
echo "EXIT=$?"; cat "$OUT/b"

echo
echo "######## (b') the same with --debug, to see which check refuses and where"
rm -rf "$S/state-bd" "$S/dbg-b"; mkdir -p "$S/state-bd" "$S/dbg-b"
"$RUNSC" --root="$S/state-bd" $FLAGS --debug --debug-log="$S/dbg-b/" run --bundle "$BUNDLE" s1-e4-bd </dev/null >"$OUT/bd" 2>&1
echo "EXIT=$?"; cat "$OUT/bd"
echo "---- the directfs userns decision, and the refusal, from the debug log"
grep -hE "userns|UID mapping|GID mapping|Mapping host|newuidmap|FATAL" "$S"/dbg-b/*.run.txt

echo
echo "######## (b'') plain shell again, NO unshare, NO --rootless, but --directfs=false"
echo "   (directfs is what makes runsc copy the caller's whole identity mapping;"
echo "    without it runsc creates the user namespace itself)"
rm -rf "$S/state-bn"; mkdir -p "$S/state-bn"
echo "\$ runsc --root=\$S/state-bn $FLAGS --directfs=false run --bundle \$BUNDLE s1-e4-bn"
"$RUNSC" --root="$S/state-bn" $FLAGS --directfs=false run --bundle "$BUNDLE" s1-e4-bn </dev/null >"$OUT/bn" 2>&1
echo "EXIT=$?"; cat "$OUT/bn"

echo
echo "######## (b-userns) plain shell again, NO unshare, NO --rootless, but the SPEC"
echo "   declares a user namespace with a single-ID mapping (0 -> $(id -u), size 1),"
echo "   which an unprivileged process is allowed to write itself."
echo "   Workload has a trailing sleep so the sentry can be read while it lives."
rm -rf "$S/state-un"; mkdir -p "$S/state-un"
echo "\$ runsc --root=\$S/state-un $FLAGS run --bundle \$S/bundle-userns s1-e4-un"
"$RUNSC" --root="$S/state-un" $FLAGS run --bundle "$S/bundle-userns" s1-e4-un </dev/null >"$OUT/un" 2>&1 &
UNPID=$!
for i in $(seq 1 60); do pgrep -u "$(id -u)" -f "runsc-sandbox.*s1-e4-un" >/dev/null && break; sleep 1; done
sleep 3
for p in $(pgrep -u "$(id -u)" -f "runsc-(sandbox|gofer).*s1-e4-un"); do
  echo "---- $(tr '\0' ' ' < /proc/$p/cmdline | awk '{print $1}') pid $p"
  echo "uid_map: $(cat /proc/$p/uid_map)"
  grep -E '^(Uid|Gid|NoNewPrivs|Seccomp):|^Cap' /proc/$p/status
done
wait $UNPID; echo "EXIT=$?"; cat "$OUT/un"

echo
echo "######## (a-control) E1's configuration: NO outer unshare, WITH --rootless"
rm -rf "$S/state-a"; mkdir -p "$S/state-a"
echo "\$ runsc --root=\$S/state-a $FLAGS --rootless run --bundle \$BUNDLE s1-e4-a"
"$RUNSC" --root="$S/state-a" $FLAGS --rootless run --bundle "$BUNDLE" s1-e4-a </dev/null >"$OUT/a" 2>&1
echo "EXIT=$?"; cat "$OUT/a"

echo
echo "######## (c) outer 'unshare -Ur' ONLY (user ns, no mount ns), WITH --rootless"
rm -rf "$S/state-c"; mkdir -p "$S/state-c"
echo "\$ unshare -Ur sh -c '...; runsc --root=\$S/state-c $FLAGS --rootless run --bundle \$BUNDLE s1-e4-c'"
unshare -Ur sh -c "
  echo '---- inside unshare -Ur, before runsc'
  id
  echo 'uid_map:'; cat /proc/self/uid_map
  grep -E '^Cap' /proc/self/status
  '$RUNSC' --root='$S/state-c' $FLAGS --rootless run --bundle '$BUNDLE' s1-e4-c </dev/null >'$OUT/c' 2>&1
  echo \"EXIT=\$?\"
"
echo "OUTER_EXIT=$?"
echo "---- workload output"; cat "$OUT/c"

echo
echo "######## (c') the same with --debug, to see what pinNullNetNS did with no mount namespace"
rm -rf "$S/state-cd" "$S/dbg-c"; mkdir -p "$S/state-cd" "$S/dbg-c"
unshare -Ur sh -c "
  '$RUNSC' --root='$S/state-cd' $FLAGS --rootless --debug --debug-log='$S/dbg-c/' run --bundle '$BUNDLE' s1-e4-cd </dev/null >'$OUT/cd' 2>&1
  echo \"EXIT=\$?\"
"
echo "OUTER_EXIT=$?"
echo "---- workload output"; cat "$OUT/cd"
echo "---- every line mentioning the null network namespace"
grep -h "null network namespace\|null-netns" "$S"/dbg-c/* | sort -u

echo
echo "######## the host afterwards"
echo "host /proc/mounts lines: $(wc -l < /proc/mounts)"
echo "null-netns lines in the host mount table: $(grep -c null-netns /proc/mounts)"
echo "state dirs left behind:"
for d in state-a state-b state-bd state-bn state-un state-c state-cd; do
  echo "== \$S/$d"; (cd "$S/$d" && find . | sort)
done
