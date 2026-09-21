#!/busybox sh
# Ticket 24 E1: variant b under --debug, to see which of runsc's steps fails and
# what it logged just before. Runs inside the guest-like namespace built by
# guest-like-ns-procbind.sh under `unshare -Urmnpf`, i.e. with the DRIVER's procfs
# (which numbers pids in the DRIVER's pid namespace, not runsc's).
BB=/busybox
RUNSC=/runsc
STATE=/run/runsc-state
FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"
export TMPDIR=/tmp
$BB mkdir -p $STATE /tmp/dbg
echo "---- my pid in MY pid namespace: $$ ; as the inherited procfs numbers me:"
$BB readlink /proc/self
echo "\$ $RUNSC --root=$STATE $FLAGS --debug --debug-log=/tmp/dbg/ run --bundle /bundle-true t24-e1-b-debug"
$RUNSC --root=$STATE $FLAGS --debug --debug-log=/tmp/dbg/ run --bundle /bundle-true t24-e1-b-debug </dev/null >/tmp/o 2>&1
echo "EXIT=$?"; $BB cat /tmp/o
echo
echo "---- every debug log, last 25 lines each"
for f in /tmp/dbg/*; do echo "== $f"; $BB tail -25 "$f"; done
echo
echo "---- lines about the mappings, the gofer and the userns"
$BB grep -iE "Mapping host|user namespace|userns|Starting gofer|uid_map|gid_map|rootless|Nss|namespace" /tmp/dbg/* | $BB tail -40
