#!/busybox sh
# Ticket 24 E1, item 3: the `uname -a` workload under the recommended driver,
# written in the shape the guest's /sbin/init will use.
#
# The namespace was built by guest-like-ns-procbind.sh, which brings the DRIVER's
# /proc into the new root rather than mounting a fresh one — that is the guest's
# situation: init mounted /proc in the initial namespaces
# (docs/snp/image/init.rootfs:15) and `unshare` inherits a copy of it. So this
# script sees exactly the /proc the driver left, and MODE says what to do about it:
#
#   MODE=mountproc  the driver was `unshare -Urmnpf --mount-proc`, so busybox has
#                   already mounted a fresh procfs; nothing to do here. The guest's
#                   init line is then just `unshare ... --mount-proc sh -c 'exec runsc …'`.
#   MODE=explicit   the driver was `unshare -Urmnpf` and this script does the
#                   remount itself, with busybox's `mount` applet (the only `mount`
#                   the measured image has), spelling the guest's own options from
#                   init.rootfs:15. The guest's init line is then
#                   `unshare -Urmnpf sh -c 'mount -t proc -o nosuid,nodev,noexec proc /proc; exec runsc …'`.
#
# In the guest the body is one `sh -c` argument and runsc is `exec`'d. Here runsc
# is not exec'd, only so that the check can be printed afterwards.
BB=/busybox
RUNSC=/runsc
STATE=/run/runsc-state
FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless --gofer-network-namespace=new"
export TMPDIR=/tmp
$BB mkdir -p $STATE

echo "######## MODE=$MODE"
echo "######## the /proc this script inherited from the driver"
$BB grep -E " proc | /proc" /proc/mounts
echo "######## own pid (1 means the pid namespace is ours)"; echo $$
if [ "$MODE" = explicit ]; then
  echo "######## \$ $BB mount -t proc -o nosuid,nodev,noexec proc /proc"
  $BB mount -t proc -o nosuid,nodev,noexec proc /proc
  echo "MOUNT_EXIT=$?"
  echo "######## the /proc lines after the remount"
  $BB grep -E " proc | /proc" /proc/mounts
  echo "######## own pid in the remounted procfs"; echo $$
else
  echo "######## no remount: busybox's --mount-proc already did it"
fi

echo
echo "######## the guest init's check, before runsc runs"
$BB cat /proc/mounts
$BB sh /init-mount-check.sh /proc/mounts; echo "CHECK_EXIT=$?"
echo "---- and with mounts under /proc/ removed (harness artifact, see notes.md)"
$BB grep -vE " /proc/[^ ]+ " /proc/mounts > /tmp/mounts-no-proc-submounts
$BB sh /init-mount-check.sh /tmp/mounts-no-proc-submounts; echo "CHECK_EXIT=$?"

echo
echo "######## the workload, output straight to the console (no redirection)"
echo "\$ $RUNSC --root=$STATE $FLAGS run --bundle /bundle-uname t24-e1-uname-$MODE"
$RUNSC --root=$STATE $FLAGS run --bundle /bundle-uname "t24-e1-uname-$MODE" </dev/null
echo "EXIT=$?"

echo
echo "######## the same workload with its output captured, for an unclobbered copy"
$RUNSC --root=$STATE $FLAGS run --bundle /bundle-uname "t24-e1-uname-$MODE-2" </dev/null >/tmp/uname.txt 2>&1
echo "EXIT=$?"; echo "---- /tmp/uname.txt ----"; $BB cat /tmp/uname.txt

echo
echo "######## the guest-like namespace's own uname -a, for comparison"
$BB uname -a

echo
echo "######## the state dir and the check, after"
$BB find $STATE -exec $BB ls -ld {} \;
$BB sh /init-mount-check.sh /proc/mounts; echo "CHECK_EXIT=$?"
