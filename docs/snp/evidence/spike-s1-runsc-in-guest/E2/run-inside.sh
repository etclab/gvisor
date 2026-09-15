#!/busybox sh
# Runs INSIDE the guest-like namespace, after pivot_root. / is the read-only
# image (the stand-in for the guest's squashfs); every writable mount here is
# noexec. The state dir and TMPDIR are on those noexec mounts.
# Each runsc invocation writes to its own file: runsc hands the workload's
# stdout straight to the sandbox, and a shared file offset clobbers it.
BB=/busybox
RUNSC=/runsc
STATE=/run/runsc-state
FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless"
export TMPDIR=/tmp
$BB mkdir -p $STATE /tmp/out

echo "######## 0. the guest init's check, before runsc has run"
$BB cat /proc/mounts
echo "---- check ----"
$BB sh /init-mount-check.sh /proc/mounts; echo "CHECK_EXIT=$?"

echo
echo "######## 1. the workload, root filesystem read-only, every writable mount noexec"
echo "\$ $RUNSC --root=$STATE $FLAGS run --bundle /bundle s1-e2"
$RUNSC --root=$STATE $FLAGS run --bundle /bundle s1-e2 </dev/null >/tmp/out/1 2>&1
echo "EXIT=$?"; $BB cat /tmp/out/1

echo
echo "######## 2. same, but the workload prints the sandbox-internal mount table"
$RUNSC --root=$STATE $FLAGS run --bundle /bundle-mounts s1-e2-mounts </dev/null >/tmp/out/2 2>&1
echo "EXIT=$?"; $BB cat /tmp/out/2

echo
echo "######## 3. a sleeping workload, so the host side can be read while it lives"
$RUNSC --root=$STATE $FLAGS run --bundle /bundle-sleep s1-e2-sleep </dev/null >/tmp/out/3 2>&1 &
RUNPID=$!
i=0
while [ $i -lt 60 ]; do
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
  $BB sh /init-mount-check.sh /proc/$p/mounts; echo "CHECK_EXIT=$?"
done
echo
echo "######## 4. the guest init's check against /proc/mounts while the sandbox lives"
$BB cat /proc/mounts
echo "---- check ----"
$BB sh /init-mount-check.sh /proc/mounts; echo "CHECK_EXIT=$?"
wait $RUNPID
echo "SLEEP_WORKLOAD_EXIT=$?"; $BB cat /tmp/out/3

echo
echo "######## 5. what runsc left in the state dir, after the container exited"
$BB find $STATE -exec $BB ls -ld {} \;
echo "---- and the check again, after everything exited"
$BB sh /init-mount-check.sh /proc/mounts; echo "CHECK_EXIT=$?"

echo
echo "######## 6. variation: the bundle and its rootfs on a NOEXEC writable mount"
echo "   (/tmp is rw,noexec; the workload binary then lives on a noexec mount)"
$BB cp -a /bundle /tmp/bundle-noexec
$BB sed -i "s#\"rootfs\"#\"/tmp/bundle-noexec/rootfs\"#" /tmp/bundle-noexec/config.json
echo "\$ $RUNSC --root=$STATE $FLAGS run --bundle /tmp/bundle-noexec s1-e2-noexec"
$RUNSC --root=$STATE $FLAGS run --bundle /tmp/bundle-noexec s1-e2-noexec </dev/null >/tmp/out/6 2>&1
echo "EXIT=$?"; $BB cat /tmp/out/6
