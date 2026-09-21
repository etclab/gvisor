#!/busybox sh
# Ticket 24 E1, the per-variant recorder. Runs under whatever `busybox unshare`
# flag set is being tested, inside the guest-like image when there is a mount
# namespace to build one in, and on the workstation's own root when there is not
# (variant d, `-Ur`, cannot mount anything at all).
#
# Environment, so that one script serves every variant:
#   TAG    a label for the output
#   DRIVER the exact driver command line, echoed for the record
#   PFX    path prefix of the image contents; "" inside the pivot_root
#   STATE  runsc --root
#   TMPD   TMPDIR for runsc
# Records, for each variant: the caller's uid_map, gid_map, setgroups and
# capabilities; /proc/mounts and the guest init's check against it; the `true`
# and `sh -c 'echo hi; ls /'` workloads with their exit codes; a live `sleep`
# container's sandbox and gofer maps, capabilities and mount tables; and the
# check again while the sandbox lives and after everything has exited.
BB="$PFX/busybox"
RUNSC="$PFX/runsc"
CHECK="$PFX/init-mount-check.sh"
: "${STATE:=/run/runsc-state}"
: "${TMPD:=/tmp}"
: "${TAG:=variant}"
FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"
export TMPDIR="$TMPD"
$BB mkdir -p "$STATE" "$TMPD/out"

echo "######## $TAG 0. the driver"
echo "\$ $DRIVER"
echo "   (PFX='$PFX' STATE='$STATE' TMPDIR='$TMPD')"

echo
echo "######## $TAG 1. what the busybox unshare applet gave this caller"
echo "---- /proc/self/uid_map";    $BB cat /proc/self/uid_map
echo "---- /proc/self/gid_map";    $BB cat /proc/self/gid_map
echo "---- /proc/self/setgroups";  $BB cat /proc/self/setgroups
echo "---- Cap* from /proc/self/status"; $BB grep Cap /proc/self/status
echo "---- id"; $BB id
echo "---- own pid (1 means the pid namespace is ours)"; echo $$
echo "---- namespace links"; $BB ls -l /proc/self/ns

echo
echo "######## $TAG 2. the guest init's check, before runsc has run"
$BB cat /proc/mounts
echo "---- the /proc lines"; $BB grep -E " proc | /proc " /proc/mounts
echo "---- check ----"
$BB sh "$CHECK" /proc/mounts; echo "CHECK_EXIT=$?"
# The variants that keep the driver's procfs must bring it in with --rbind (a
# plain bind of /proc is refused in a user namespace when /proc has child
# mounts), and that drags this workstation's /proc/sys/fs/binfmt_misc autofs
# along, which is rw with no noexec. The measured guest mounts nothing under
# /proc (docs/snp/image/init.rootfs:15-19), so that mount is a harness artifact;
# the check is therefore also run with everything below /proc/ removed.
echo "---- check again, with mounts under /proc/ removed (harness artifact) ----"
$BB grep -vE " /proc/[^ ]+ " /proc/mounts > "$TMPD/mounts-no-proc-submounts"
$BB sh "$CHECK" "$TMPD/mounts-no-proc-submounts"; echo "CHECK_EXIT=$?"

echo
echo "######## $TAG 3. the trivial workload, /bin/busybox true"
echo "\$ $RUNSC --root=$STATE $FLAGS run --bundle $PFX/bundle-true t24-e1-$TAG-true"
$RUNSC --root="$STATE" $FLAGS run --bundle "$PFX/bundle-true" "t24-e1-$TAG-true" </dev/null >"$TMPD/out/true" 2>&1
echo "EXIT=$?"; $BB cat "$TMPD/out/true"

echo
echo "######## $TAG 4. S1 E4's workload, /bin/busybox sh -c 'echo hi; ls /'"
echo "\$ $RUNSC --root=$STATE $FLAGS run --bundle $PFX/bundle-hi t24-e1-$TAG-hi"
$RUNSC --root="$STATE" $FLAGS run --bundle "$PFX/bundle-hi" "t24-e1-$TAG-hi" </dev/null >"$TMPD/out/hi" 2>&1
echo "EXIT=$?"; $BB cat "$TMPD/out/hi"

echo
echo "######## $TAG 5. a live sleeping container, so the sandbox and gofer can be read"
echo "\$ $RUNSC --root=$STATE $FLAGS run --bundle $PFX/bundle-sleep t24-e1-$TAG-sleep &"
$RUNSC --root="$STATE" $FLAGS run --bundle "$PFX/bundle-sleep" "t24-e1-$TAG-sleep" </dev/null >"$TMPD/out/sleep" 2>&1 &
RUNPID=$!
i=0
while [ $i -lt 40 ]; do
  PIDS=$($BB ps -o pid,args 2>/dev/null | $BB grep -E "runsc-(sandbox|gofer)" | $BB grep -v grep | $BB awk '{print $1}')
  [ -n "$PIDS" ] && break
  $BB sleep 1; i=$((i+1))
done
echo "runsc processes seen:"
$BB ps -o pid,args 2>/dev/null | $BB grep -E "runsc" | $BB grep -v grep
for p in $PIDS; do
  echo
  echo "---- /proc/$p/cmdline"; $BB tr '\0' ' ' < /proc/$p/cmdline; echo
  echo "---- /proc/$p/mounts"; $BB cat /proc/$p/mounts
  echo "---- /proc/$p/uid_map"; $BB cat /proc/$p/uid_map
  echo "---- /proc/$p/gid_map"; $BB cat /proc/$p/gid_map
  echo "---- Cap* from /proc/$p/status"; $BB grep Cap /proc/$p/status
  echo "---- the guest init's check against /proc/$p/mounts"
  $BB sh "$CHECK" /proc/$p/mounts; echo "CHECK_EXIT=$?"
done
echo
echo "######## $TAG 6. the check against /proc/mounts while the sandbox lives"
$BB cat /proc/mounts
echo "---- check ----"
$BB sh "$CHECK" /proc/mounts; echo "CHECK_EXIT=$?"
wait $RUNPID
echo "SLEEP_WORKLOAD_EXIT=$?"; $BB cat "$TMPD/out/sleep"

echo
echo "######## $TAG 7. the state dir and the check, after everything exited"
$BB find "$STATE" -exec $BB ls -ld {} \;
$BB sh "$CHECK" /proc/mounts; echo "CHECK_EXIT=$?"
