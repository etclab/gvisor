#!/busybox sh
# E3: one candidate per invocation. Runs INSIDE the guest-like namespace built
# by E2/guest-like-ns.sh, after pivot_root: / is the read-only image, every
# writable mount (/run /tmp /dev /proc /sys) is noexec.
#
# One case per `unshare` so that no case inherits another case's mounts: the
# null-netns pin is not transient, so a single namespace could only ever fail
# once and then stay failed.
BB=/busybox
RUNSC=/runsc
BASE="--platform=systrap --network=none --ignore-cgroups --rootless"
export TMPDIR=/tmp
CASE="$1"
DBG=/tmp/dbg-$CASE
$BB mkdir -p $DBG /tmp/out

check() {
  echo "---- /proc/mounts lines mentioning null-netns:"
  $BB grep null-netns /proc/mounts || echo "   (none)"
  echo "---- the guest init's check (docs/snp/image/init.rootfs:31-44) ----"
  $BB sh /init-mount-check.sh /proc/mounts
  echo "CHECK_EXIT=$?"
}

goferlog() {
  echo "---- what the debug log says about the null network namespace:"
  $BB grep -hE "null network namespace|Pinned null|Unable to pin" $DBG/* 2>/dev/null \
    | $BB sed 's/^.*\] //' | $BB head -4 || true
}

echo "######## CASE $CASE"
echo "---- writable mounts before runsc runs:"
$BB grep -E " rw," /proc/mounts
echo "---- check before runsc runs ----"
$BB sh /init-mount-check.sh /proc/mounts; echo "CHECK_EXIT=$?"
echo

case "$CASE" in

baseline)
  # E2 again, in the E3 harness, with and without --debug: the fail to beat.
  STATE=/run/st-$CASE; $BB mkdir -p $STATE
  echo "\$ $RUNSC --root=$STATE $BASE run --bundle /bundle e3-$CASE"
  $RUNSC --root=$STATE $BASE run --bundle /bundle e3-$CASE </dev/null >/tmp/out/$CASE 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE
  check
  echo
  echo "---- and the same run with --debug, to read runsc's own account of it"
  STATE2=/run/st-$CASE-dbg; $BB mkdir -p $STATE2
  $RUNSC --root=$STATE2 $BASE --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE-dbg </dev/null >/tmp/out/$CASE-dbg 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE-dbg
  goferlog
  check
  ;;

gnn-new|gnn-host)
  case "$CASE" in
    gnn-new)  GNN=new ;;
    gnn-host) GNN=host ;;
  esac
  STATE=/run/st-$CASE; $BB mkdir -p $STATE
  echo "\$ $RUNSC --root=$STATE $BASE --gofer-network-namespace=$GNN --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE"
  $RUNSC --root=$STATE $BASE --gofer-network-namespace=$GNN --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE </dev/null >/tmp/out/$CASE 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE
  goferlog
  echo "---- what is left in the state directory afterwards:"
  $BB find $STATE -exec $BB ls -ld {} \;
  check
  echo
  echo "---- a second container in the same state directory, same flag:"
  $RUNSC --root=$STATE $BASE --gofer-network-namespace=$GNN run --bundle /bundle e3-$CASE-2 </dev/null >/tmp/out/$CASE-2 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE-2
  check
  ;;

shared-ro)
  # --root stays writable (runsc needs it); only the pin's directory is the
  # read-only image root.
  STATE=/run/st-$CASE; $BB mkdir -p $STATE
  echo "---- /roshared is on the read-only image root:"
  $BB grep -E " / " /proc/mounts
  $BB touch /roshared/probe; echo "touch /roshared/probe: EXIT=$?"
  echo "\$ $RUNSC --root=$STATE --shared-root=/roshared $BASE --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE"
  $RUNSC --root=$STATE --shared-root=/roshared $BASE --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE </dev/null >/tmp/out/$CASE 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE
  goferlog
  check
  ;;

root-ro)
  echo "\$ $RUNSC --root=/roroot $BASE --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE"
  $RUNSC --root=/roroot $BASE --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE </dev/null >/tmp/out/$CASE 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE
  echo "---- last lines of each debug log:"
  for f in $DBG/*; do echo "== $f"; $BB tail -4 "$f"; done
  check
  ;;

nested)
  # The pin still happens, but inside a private mount namespace under the
  # guest-like one, so the guest's own /proc/mounts never shows it.
  STATE=/run/st-$CASE; $BB mkdir -p $STATE
  echo "\$ $BB unshare -m $BB sh -c '$RUNSC --root=$STATE $BASE run --bundle /bundle-sleep e3-$CASE ...'"
  $BB unshare -m $BB sh -c "
    $RUNSC --root=$STATE $BASE run --bundle /bundle-sleep e3-$CASE </dev/null >/tmp/out/$CASE 2>&1
    echo NESTED_RUNSC_EXIT=\$?
    echo '---- /proc/mounts inside the nested mount namespace, after the run:'
    $BB grep null-netns /proc/mounts || echo '   (none)'
  " >/tmp/out/$CASE-nested 2>&1 &
  NPID=$!
  i=0
  while [ $i -lt 60 ]; do
    PIDS=$($BB ps -o pid,args 2>/dev/null | $BB grep "runsc-sandbox" | $BB grep -v grep | $BB awk '{print $1}')
    [ -n "$PIDS" ] && break
    $BB sleep 1; i=$((i+1))
  done
  echo "---- runsc processes seen from the guest-level namespace: "
  $BB ps -o pid,args 2>/dev/null | $BB grep runsc | $BB grep -v grep
  echo
  echo "######## the guest init's check, at guest level, WHILE the sandbox lives"
  check
  echo
  echo "---- the nested mount namespace's own view, from the guest level:"
  for p in $PIDS; do echo "== /proc/$p/mounts (sandbox)"; $BB grep null-netns /proc/$p/mounts || echo "   (none)"; done
  NRUNSC=$($BB ps -o pid,args 2>/dev/null | $BB grep -E "^ *[0-9]+ +$RUNSC" | $BB grep -v grep | $BB awk '{print $1}' | $BB head -1)
  [ -n "$NRUNSC" ] && { echo "== /proc/$NRUNSC/mounts (the runsc CLI, inside the nested ns)"; $BB grep null-netns /proc/$NRUNSC/mounts || echo "   (none)"; }
  wait $NPID
  echo "WAIT_EXIT=$?"
  $BB cat /tmp/out/$CASE-nested; $BB cat /tmp/out/$CASE
  echo
  echo "######## the guest init's check, at guest level, AFTER everything exited"
  check
  ;;

guard-dir)
  # Pre-create <shared-root>/null-netns as a NON-EMPTY directory: the bind
  # mount fails with ENOTDIR and the best-effort os.Remove cannot clear it.
  STATE=/run/st-$CASE; $BB mkdir -p $STATE/null-netns
  echo "guard" > $STATE/null-netns/.keep
  $BB ls -la $STATE $STATE/null-netns
  echo "\$ $RUNSC --root=$STATE $BASE --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE"
  $RUNSC --root=$STATE $BASE --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE </dev/null >/tmp/out/$CASE 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE
  goferlog
  check
  echo
  echo "---- the guard survived the run?"; $BB ls -la $STATE
  echo "---- a second container in the same state directory:"
  $RUNSC --root=$STATE $BASE run --bundle /bundle e3-$CASE-2 </dev/null >/tmp/out/$CASE-2 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE-2
  check
  ;;

guard-file)
  # Pre-create it as a read-only regular file instead.
  STATE=/run/st-$CASE; $BB mkdir -p $STATE
  : > $STATE/null-netns; $BB chmod 0444 $STATE/null-netns
  $BB ls -la $STATE
  echo "\$ $RUNSC --root=$STATE $BASE --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE"
  $RUNSC --root=$STATE $BASE --debug --debug-log=$DBG/ run --bundle /bundle e3-$CASE </dev/null >/tmp/out/$CASE 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE
  goferlog
  check
  ;;

characterise)
  # Make the pin, then ask what it actually is.
  STATE=/run/st-$CASE; $BB mkdir -p $STATE
  $RUNSC --root=$STATE $BASE run --bundle /bundle e3-$CASE </dev/null >/tmp/out/$CASE 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE
  P=$STATE/null-netns
  echo
  echo "---- /proc/mounts line (what the guest init reads):"
  $BB grep null-netns /proc/mounts
  echo "---- /proc/self/mountinfo line (per-mount options | fs type | super options):"
  $BB grep null-netns /proc/self/mountinfo
  echo "---- the mount underneath it, /run:"
  $BB grep -E " /run " /proc/self/mountinfo
  echo "---- stat -f $P"
  $BB stat -f $P
  echo "---- stat $P"
  $BB stat $P
  echo "---- ls -la $STATE"
  $BB ls -la $STATE
  echo "---- ls -la $P"
  $BB ls -la $P
  echo
  echo "---- can anything be put on it? (it is one inode, not a directory)"
  $BB touch $P/x 2>&1; echo "touch $P/x: EXIT=$?"
  $BB mkdir $P/d 2>&1; echo "mkdir $P/d: EXIT=$?"
  $BB cp /busybox $P 2>&1; echo "cp /busybox over it: EXIT=$?"
  echo "---- can it be made executable, or read, or run?"
  $BB chmod +x $P 2>&1; echo "chmod +x: EXIT=$?"; $BB ls -la $P
  $BB cat $P >/tmp/catout 2>&1; echo "cat: EXIT=$?"; $BB head -2 /tmp/catout
  $P 2>&1; echo "exec it: EXIT=$?"
  $BB sh -c "exec $P" 2>&1; echo "exec via sh: EXIT=$?"
  echo "---- for contrast, the same on the tmpfs underneath (which IS noexec):"
  $BB cp /busybox /run/probe-bin; $BB chmod +x /run/probe-bin
  /run/probe-bin true 2>&1; echo "exec a binary on the noexec /run: EXIT=$?"
  echo "---- what the pin points at: the gofer's netns, long dead"
  $BB readlink /proc/self/ns/net
  ;;

noexec-rootfs)
  # E2's second finding, reconfirmed: the bundle and its rootfs on a writable
  # noexec mount.
  STATE=/run/st-$CASE; $BB mkdir -p $STATE
  echo "---- /tmp is:"; $BB grep -E " /tmp " /proc/mounts
  $BB cp -a /bundle /tmp/bundle-noexec
  echo "\$ $RUNSC --root=$STATE $BASE --debug --debug-log=$DBG/ run --bundle /tmp/bundle-noexec e3-$CASE"
  $RUNSC --root=$STATE $BASE --debug --debug-log=$DBG/ run --bundle /tmp/bundle-noexec e3-$CASE </dev/null >/tmp/out/$CASE 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE
  echo "---- the gofer's account:"
  $BB grep -hE "Remounting root|FATAL ERROR|operation not permitted" $DBG/* | $BB head -6
  echo
  echo "---- and the same bundle on the read-only, exec-permitted image root (the guest's shape):"
  STATE2=/run/st-$CASE-ro; $BB mkdir -p $STATE2
  $RUNSC --root=$STATE2 $BASE --gofer-network-namespace=new run --bundle /bundle e3-$CASE-ro </dev/null >/tmp/out/$CASE-ro 2>&1
  echo "EXIT=$?"; $BB cat /tmp/out/$CASE-ro
  check
  ;;

timing)
  # What the pin buys, which is the reason it exists: three sequential
  # containers with the default (`null`, pin and reuse) against three with
  # `new` (a fresh empty netns per gofer).
  S1=/run/st-$CASE-null; S2=/run/st-$CASE-new; $BB mkdir -p $S1 $S2
  echo "---- --gofer-network-namespace=null (the default): run 1 pins, runs 2-3 reuse"
  for i in 1 2 3; do
    $BB time $RUNSC --root=$S1 $BASE run --bundle /bundle e3-$CASE-null-$i </dev/null >/dev/null 2>/tmp/t
    echo "run $i:"; $BB grep -E "real|user|sys" /tmp/t
  done
  echo "---- --gofer-network-namespace=new: every run creates its own"
  for i in 1 2 3; do
    $BB time $RUNSC --root=$S2 $BASE --gofer-network-namespace=new run --bundle /bundle e3-$CASE-new-$i </dev/null >/dev/null 2>/tmp/t
    echo "run $i:"; $BB grep -E "real|user|sys" /tmp/t
  done
  check
  ;;

*)
  echo "unknown case: $CASE"; exit 2 ;;
esac
