#!/busybox sh
BB=/busybox
RUNSC=/runsc
STATE=/run/runsc-state
FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless"
export TMPDIR=/tmp
$BB mkdir -p $STATE /tmp/dbg
echo "######## the bundle and its rootfs on /tmp, which is rw,noexec"
$BB grep " /tmp " /proc/mounts
$BB cp -a /bundle /tmp/bundle-noexec
echo "\$ $RUNSC --root=$STATE $FLAGS --debug --debug-log=/tmp/dbg/ run --bundle /tmp/bundle-noexec s1-noexec"
$RUNSC --root=$STATE $FLAGS --debug --debug-log=/tmp/dbg/ run --bundle /tmp/bundle-noexec s1-noexec </dev/null >/tmp/o 2>&1
echo "EXIT=$?"; $BB cat /tmp/o
echo
echo "---- the last lines of each debug log"
for f in /tmp/dbg/*; do echo "== $f"; $BB tail -6 "$f"; done
echo
echo "---- every line mentioning EACCES / permission / noexec / exec format"
$BB grep -iE "eacces|permission denied|noexec|exec format|Error|FATAL|panic" /tmp/dbg/* | $BB tail -20
