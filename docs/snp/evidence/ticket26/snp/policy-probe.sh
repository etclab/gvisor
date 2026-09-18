#!/bin/sh
# The workload of ticket 26's two-guest run, inside the sandbox and nowhere else.
#
# One script, one disk, two guests. Nothing in here knows which guest it is on:
# what decides every outcome below is the tunnel table on each guest's config
# device, which the measured sentry enforces, and the policy the peer pushed over
# the tunnel, which the measured sentry narrowed that table with. The script
# works out which guest it is on the only way a sandbox can — by asking which
# name resolves — and the two branches differ in their timing and in nothing
# else.
#
# Everything this prints goes to the sandbox's stdout, which runsc puts on the
# guest's serial console, which the harness captures. There is no network in here
# to put it on: --network=none, one loopback-only stack, and the adapter.
#
# ---------------------------------------------------------------------------
# Every exec is /bin/busybox, and that is the whole of the X control
# ---------------------------------------------------------------------------
#
# The pushed policy's `x` names one path, `/bin/busybox`, and no digest. So every
# command this script runs is spelled `/bin/busybox <applet>` rather than through
# an applet symlink: what the sentry hashes and compares is the file an execve
# named, and /bin/busybox is the file this policy permits however the sentry
# resolves a symlink. That question — what path the sentry reports for
# /bin/sh — is open, and this script ASKS it rather than depending on the
# answer: the two OBSERVE lines near the end exec through symlinks and record
# what came back, and nothing asserts on them.
#
# The control that does assert is /bin/probe. It is a copy of the same busybox
# with a comment appended, so it is a different file at a different path: its
# path is not in `x` and its sha256 is not in `x`, and an execve of it must fail
# EACCES once a policy with an `x` is in force. Before that policy lands exec is
# unrestricted and the same execve succeeds, which is why the control is a loop
# that records the moment it flips rather than one attempt at a guessed time.
# If `x` had named the digest instead of the path, /bin/probe would have to be a
# genuinely different program — a copy of busybox has the path wrong and the
# bytes right — and this is the reason the appended comment is there.
BB=/bin/busybox
say() { echo "workload: $*"; }

# The body /run/httpd/large carries, in bytes. The guest's init generates it from
# /dev/zero at a fixed size (docs/snp/image/init.rootfs, docs/snp/cloud/tdx/init.tdx)
# so that this number is a constant both ends agree on without either measuring
# the other.
LONG_EXPECT=8388608
# How much of it to take per read, and how long to wait between reads. 64 reads
# a second apart is about a minute of one stream being open, which is what makes
# "the policy was replaced while it was in flight" a statement about this fetch
# and not about a race.
LONG_CHUNK=131072
LONG_PAUSE=1

# ---------------------------------------------------------------------------
# fetch — one GET, retried, and what it will not retry is the point of it
# ---------------------------------------------------------------------------
#
# Both guests boot at once and this sandbox starts about a tenth of a second
# after its own tunneld. The peer may still be acquiring evidence or may have no
# exit attached yet, and a fetch that gave up on the first attempt would record
# that race as a refusal. So an ordinary failure is tried again for about twenty
# seconds.
#
# A name that did not resolve is NOT tried again. That is not a race: the sentry
# answers NXDOMAIN for a name this sandbox's policy does not carry and will
# answer NXDOMAIN for the next twenty seconds too.
fetch() { # URL
  n=1
  while :; do
    say "--- GET $1 (attempt $n)"
    out=$($BB wget -q -O - "$1" 2>&1)
    rc=$?
    [ -n "$out" ] && echo "$out"
    if [ "$rc" = 0 ]; then
      say "wget exit 0 for $1"
      return 0
    fi
    case "$out" in
    *"bad address"*)
      say "wget exit $rc for $1: the name did not resolve, so this sandbox's policy does not carry it; not retrying"
      return 1
      ;;
    esac
    if [ "$n" -ge 10 ]; then
      say "wget exit $rc for $1 after $n attempts"
      return 1
    fi
    n=$((n + 1))
    $BB sleep 2
  done
}

# resolves NAME — one attempt, and the only thing it reports is whether the name
# resolved. Used once, to learn which guest this is.
resolves() { # NAME
  out=$($BB wget -q -O - "http://$1/" 2>&1)
  case "$out" in
  *"bad address"*) return 1 ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# the long stream
# ---------------------------------------------------------------------------
#
# wget writes the body to a pipe and this reads it a chunk a second. The pipe
# fills, wget blocks writing to it, the socket's receive window closes and the
# server stalls: the connection stays open for as long as this loop takes, which
# is the whole point. Nothing is written to a file, because the bundle's root is
# read-only and there is no writable mount in this sandbox at all — `f` is
# approximated by mounts and this is what that looks like from inside.
#
# The byte count is the evidence. A stream that was cut when the policy under it
# was replaced stops short; one that was left alone arrives whole.
slow_read() {
  total=0
  n=0
  while :; do
    c=$($BB head -c "$LONG_CHUNK" | $BB wc -c)
    [ "$c" -gt 0 ] || break
    total=$((total + c))
    n=$((n + 1))
    if [ $((n % 16)) -eq 0 ]; then say "LONG reading bytes=$total"; fi
    $BB sleep "$LONG_PAUSE"
  done
  if [ "$total" = "$LONG_EXPECT" ]; then
    say "LONG COMPLETE bytes=$total (the whole body arrived, and the stream outlived whatever happened to the policy under it)"
  else
    say "LONG SHORT bytes=$total expected=$LONG_EXPECT"
  fi
}

long_stream() { # NAME
  say "LONG start http://$1/large, $LONG_CHUNK bytes every ${LONG_PAUSE}s until $LONG_EXPECT arrive"
  $BB wget -q -O - "http://$1/large" 2>/dev/null | slow_read
}

# ---------------------------------------------------------------------------
# the exec control
# ---------------------------------------------------------------------------
#
# What is asserted is the errno the shell reports, not what /bin/probe prints:
# an execve the sentry refused gives EACCES and ash says "Permission denied", and
# an execve that happened gives whatever the program did. So this records both
# and stops at the first refusal, and the transcript carries the moment exec went
# from unrestricted to governed.
exec_control() {
  i=1
  while :; do
    out=$(/bin/probe 2>&1)
    rc=$?
    case "$out" in
    *"Permission denied"* | *"permission denied"*)
      say "EXEC REFUSED /bin/probe on attempt $i: $out"
      say "(a path the pushed x does not name and a digest it does not name; /bin/busybox is the only identity in x)"
      return 0
      ;;
    esac
    say "exec /bin/probe attempt $i: it ran (rc=$rc); no policy carrying an x is in force in this sandbox yet"
    if [ "$i" -ge 30 ]; then
      say "EXEC NOT REFUSED after $i attempts over about 60s"
      return 1
    fi
    i=$((i + 1))
    $BB sleep 2
  done
}

# ---------------------------------------------------------------------------
# the narrowing control
# ---------------------------------------------------------------------------
#
# The name this sandbox has been fetching all along, asked for again every few
# seconds until the sentry stops resolving it. Before the narrowing it resolves
# and is served; after it, the responder answers NXDOMAIN and wget reports a bad
# address, because a name that is not in the policy in force never becomes an
# address to dial. The transition is what this prints; a run in which it never
# flips prints that instead.
narrowing_control() { # NAME SECONDS
  i=1
  limit=$(( $2 / 3 ))
  while :; do
    out=$($BB wget -q -O - "http://$1/" 2>&1)
    case "$out" in
    *"bad address"*)
      say "NARROWED $1 stopped resolving on attempt $i: $out"
      say "(the second push dropped it from n; the sentry's responder answers NXDOMAIN for a name the policy in force does not carry)"
      return 0
      ;;
    esac
    if [ "$i" -ge "$limit" ]; then
      say "NOT NARROWED: $1 still resolved on attempt $i, after about $2 seconds"
      return 1
    fi
    i=$((i + 1))
    $BB sleep 3
  done
}

say "=== ticket 26: a sandbox that honours a pushed policy ==="
say "this process has no interface of its own; its only way out is the adapter"

# 0. the exec control's other half, and it has to be first.
#
# What makes /bin/probe a control is that the same execve succeeds before a
# policy carrying an `x` is in force and fails after it, and the window in which
# it succeeds is the one between this sandbox starting and the peer's tunneld
# dialing — about a fifth of a second on the bench, and gone by the time a page
# has been fetched. The first run of this scenario put the exec loop after two
# fetches and recorded a refusal on attempt 1 and nothing before it, which is a
# true observation of a governed sandbox and no observation at all of the
# transition. So one attempt is made here, before anything else this script does,
# and whichever way it comes out is printed: it is a race with the push and the
# transcript says which side won it.
out=$(/bin/probe 2>&1)
rc=$?
case "$out" in
*"Permission denied"* | *"permission denied"*)
  say "exec /bin/probe attempt 0: already refused ($out); the push landed before this sandbox ran a thing"
  ;;
*)
  say "exec /bin/probe attempt 0: it ran (rc=$rc); no policy carrying an x is in force in this sandbox yet"
  ;;
esac

# Which guest is this? The only thing that differs between them from in here is
# which name the sentry will resolve, so that is the question asked. Guest A's
# table names web.peer-b and guest B's names web.peer-a, and the policy each
# guest's peer pushes may only narrow that.
if resolves web.peer-b; then
  ROLE=a
  PEER=web.peer-b
elif resolves web.peer-a; then
  ROLE=b
  PEER=web.peer-a
else
  ROLE=unknown
  PEER=
fi
say "ROLE=$ROLE peer-page=$PEER"
if [ -z "$PEER" ]; then
  say "neither peer name resolves in this sandbox; there is nothing this workload can do"
  say "=== done ==="
  exit 0
fi

# 1. the page, through the peer's exit. The body names the guest that served it,
#    which is what makes this a statement about where the bytes came from.
fetch "http://$PEER/"

if [ "$ROLE" = a ]; then
  # 2. the long stream, started now and left running in the background: the
  #    policy under it is replaced while it is in flight, and the byte count at
  #    the end says whether the sentry kept its promise about live streams.
  long_stream "$PEER" &
  LONGPID=$!
  say "the long stream is pid $LONGPID; the controls below run while it is open"
fi

# 3. the control that is in nobody's table on either guest, and never was.
fetch http://not-in-the-table.example/

# 4. the exec control.
exec_control

# 5. two observations and no assertion: what the sentry resolves a symlink to.
#    Both of these are /bin/busybox by inode and neither is /bin/busybox by path,
#    so whether they run says which of the two the exec sink compares. Recorded
#    here because the answer decides what an `x` written by path can mean, and
#    nothing in this run depends on it.
out=$(/bin/uname -a 2>&1); rc=$?
say "OBSERVE exec /bin/uname (a symlink to busybox): rc=$rc out='$out'"
out=$(/bin/sh -c 'echo ran' 2>&1); rc=$?
say "OBSERVE exec /bin/sh (a symlink to busybox): rc=$rc out='$out'"

# 6. and the line that says this ran in a sandbox at all: the sentry's own
#    compile-time kernel string, with the bundle's hostname as the nodename.
$BB uname -a

if [ "$ROLE" = a ]; then
  # 7. the narrowing, watched from inside: the name this sandbox has been using
  #    stops resolving, and the stream that was already open does not stop.
  narrowing_control "$PEER" 120
  say "waiting for the long stream (pid $LONGPID)"
  wait "$LONGPID"
else
  # Guest B is not narrowed in this run, so it takes the long body in one go —
  # enough to show the same bytes are servable from this side too — and then
  # stands still.
  say "--- GET http://$PEER/large in one read (this guest is not the one being narrowed)"
  c=$($BB wget -q -O - "http://$PEER/large" 2>/dev/null | $BB wc -c)
  say "LONG-B bytes=$c expected=$LONG_EXPECT"
fi

# 8. and then nothing, for longer than the guest's kill-after. What ends this
#    workload is a signal from outside and not a script that ran out of work:
#    the liveness the contract watches ends because the sandbox died, which is
#    the only honest way to ask what tunneld does then. A run with no kill-after
#    reaches the end of this sleep and exits 0, and says so.
say "=== controls done; standing still so that a kill is what ends this workload ==="
$BB sleep 300
say "=== nothing killed this workload; it ran out of sleep ==="
say "=== done ==="
