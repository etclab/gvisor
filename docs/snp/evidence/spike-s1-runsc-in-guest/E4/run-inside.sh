#!/busybox sh
# E4. Runs INSIDE the guest-like namespace built by E2's guest-like-ns.sh,
# after pivot_root. / is the read-only image; every writable mount is noexec.
# Same runsc flags and same state-dir placement as E2; only the workload changes.
BB=/busybox
RUNSC=/runsc
FLAGS="--platform=systrap --network=none --ignore-cgroups --rootless"
export TMPDIR=/tmp
$BB mkdir -p /tmp/out

# Each runsc invocation gets its own output file: runsc hands the caller's fd 1
# straight to the sandbox and a shared file offset clobbers the workload output.
run_one() {   # $1 = bundle name, $2 = state dir, $3 = container id, $4 = out file
  $BB mkdir -p "$2"
  echo "\$ $RUNSC --root=$2 $FLAGS run --bundle /bundle-$1 $3"
  $RUNSC --root="$2" $FLAGS run --bundle "/bundle-$1" "$3" </dev/null >"$4" 2>&1
  echo "EXIT=$?"
  echo "---- stdout+stderr of the workload ----"
  $BB cat "$4"
  echo "---- state dir after the container exited ----"
  $BB find "$2" | $BB sort
  echo "---- the guest init's check against /proc/mounts ----"
  $BB sh /init-mount-check.sh /proc/mounts; echo "CHECK_EXIT=$?"
}

dump_live() { # $1 = tag
  PIDS=$($BB ps -o pid,args 2>/dev/null | $BB grep -E "runsc-(sandbox|gofer)" | $BB grep -v grep | $BB awk '{print $1}')
  echo "runsc processes seen:"
  $BB ps -o pid,args 2>/dev/null | $BB grep -E "runsc" | $BB grep -v grep
  for p in $PIDS; do
    NAME=$($BB tr '\0' ' ' < /proc/$p/cmdline | $BB awk '{print $1}')
    echo
    echo "---- $1 $NAME /proc/$p/mounts"; $BB cat /proc/$p/mounts
    echo "---- $1 $NAME /proc/$p/uid_map"; $BB cat /proc/$p/uid_map
    echo "---- $1 $NAME /proc/$p/gid_map"; $BB cat /proc/$p/gid_map
    echo "---- $1 $NAME Cap* from /proc/$p/status"; $BB grep Cap /proc/$p/status
  done
  echo
  echo "---- $1 the namespace's own /proc/mounts while the sandbox lives"
  $BB cat /proc/mounts
}

echo "######## 0. the guest init's check, before runsc has run"
$BB cat /proc/mounts
echo "---- check ----"
$BB sh /init-mount-check.sh /proc/mounts; echo "CHECK_EXIT=$?"

echo
echo "######## 1. the E1/E2 trivial workload: /bin/busybox true"
run_one true /run/state-true s1-e4-true /tmp/out/true

echo
echo "######## 2. E4's workload: /bin/busybox sh -c 'echo hi; ls /'"
run_one hi /run/state-hi s1-e4-hi /tmp/out/hi

echo
echo "######## 3. E4's second workload: the sandbox's view of its filesystem"
echo "   /bin/busybox sh -c 'cat /proc/mounts; ls -la /; id; cat /proc/self/status | grep -i cap'"
run_one view /run/state-view s1-e4-view /tmp/out/view

echo
echo "######## 4. LIVE, trivial workload (/bin/busybox sleep 25), for the mount-table comparison"
$BB mkdir -p /run/state-tl
$RUNSC --root=/run/state-tl $FLAGS run --bundle /bundle-true-live s1-e4-tl </dev/null >/tmp/out/tl 2>&1 &
TLPID=$!
i=0; while [ $i -lt 60 ]; do
  $BB ps -o pid,args 2>/dev/null | $BB grep -qE "runsc-sandbox" && break
  $BB sleep 1; i=$((i+1))
done
$BB sleep 2
dump_live TRUE-LIVE
echo "---- TRUE-LIVE state dir while the container lives"
$BB find /run/state-tl | $BB sort
wait $TLPID; echo "TRUE_LIVE_EXIT=$?"; $BB cat /tmp/out/tl

echo
echo "######## 5. LIVE, busybox sh workload (sh -c 'echo hi; ls /; sleep 25'), same comparison"
$BB mkdir -p /run/state-hl
$RUNSC --root=/run/state-hl $FLAGS run --bundle /bundle-hi-live s1-e4-hl </dev/null >/tmp/out/hl 2>&1 &
HLPID=$!
i=0; while [ $i -lt 60 ]; do
  $BB ps -o pid,args 2>/dev/null | $BB grep -qE "runsc-sandbox" && break
  $BB sleep 1; i=$((i+1))
done
$BB sleep 2
dump_live HI-LIVE
echo "---- HI-LIVE state dir while the container lives"
$BB find /run/state-hl | $BB sort
wait $HLPID; echo "HI_LIVE_EXIT=$?"; $BB cat /tmp/out/hl

echo
echo "######## 6. the state dirs after everything exited"
$BB find /run/state-true /run/state-hi /run/state-view /run/state-tl /run/state-hl -exec $BB ls -ld {} \;
echo "---- the guest init's check, after everything exited"
$BB sh /init-mount-check.sh /proc/mounts; echo "CHECK_EXIT=$?"
