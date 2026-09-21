#!/usr/bin/env bash
# E1a -- host half of ticket 25's experiment E1.
#
# Question: on a connected TCP socket, which syscalls do an unmodified Go
# runtime (net.Dial / net/http / crypto/tls) and an unmodified Node runtime
# (libuv: net.connect / https.get) actually make, in what order, and which
# answers can they NOT tolerate being wrong or refused?  That is the contract
# the sentry's FD-backed endpoint (an AF_UNIX socketpair end dressed up as an
# AF_INET SOCK_STREAM socket) has to satisfy.
#
# Everything here runs on the HOST, outside any sandbox.  Nothing needs an API
# key and nothing needs root.
#
#   ./run.sh              # build + every run, writing output-NN-*.txt here
#
# Environment knobs:
#   E1_URL      https URL for phase 2 (default https://www.rfc-editor.org/)
#   E1_OUTDIR   where output-NN-*.txt go (default: this directory)
#   E1_ONLY     space-separated run numbers to (re)do, e.g. E1_ONLY="07 08"
#   E1_TIMEOUT  per-run wall clock limit in seconds (default 25)
#
# Note on errno spellings: strace 6.8 does not accept the name ENOTSUP; on
# Linux ENOTSUP and EOPNOTSUPP are the same value (95), so the getsockname
# injection below is spelled EOPNOTSUPP and means exactly ENOTSUP.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="${E1_OUTDIR:-$HERE}"
BUILD="${E1_BUILD:-${TMPDIR:-/tmp}/e1a-build}"
URL="${E1_URL:-https://www.rfc-editor.org/}"
ONLY="${E1_ONLY:-}"
RUN_TIMEOUT="${E1_TIMEOUT:-25}"

GO=/usr/local/go/bin/go
NODE=/usr/bin/node
export GOTOOLCHAIN=go1.26.3      # /usr/local/go is a 1.22.3 shim; 1.26.3 is in the module cache
export GOFLAGS=-mod=mod
export GOCACHE="$BUILD/gocache"

# The exact strace selection the experiment is specified with.
TRACE='%network,poll,ppoll,epoll_ctl,epoll_wait,epoll_pwait,epoll_pwait2,fcntl,ioctl,shutdown,close'
# Same, plus the data-transfer forms, for the two "-with-rw" runs.
TRACE_RW="$TRACE,read,write,readv,writev,sendfile"
# Same, plus io_uring: libuv >= 1.46 can submit EPOLL_CTL through io_uring
# instead of calling epoll_ctl(2), which is why the node baselines show no
# EPOLL_CTL_ADD for the connected fd.  Run 19 proves that.
TRACE_IOU="$TRACE,io_uring_setup,io_uring_enter,io_uring_register"

mkdir -p "$BUILD" "$OUTDIR"

echo "== build =="
( cd "$HERE/goclient"   && "$GO" build -o "$BUILD/goclient"   . ) || exit 1
( cd "$HERE/echoserver" && "$GO" build -o "$BUILD/echoserver" . ) || exit 1
"$NODE" --check "$HERE/nodeclient.js" || exit 1

echo "== versions =="
"$GO" version; "$NODE" --version
"$NODE" -p "'node '+process.versions.node+' uv '+process.versions.uv+' openssl '+process.versions.openssl"
strace --version | head -1

# ---- loopback echo server for phase 1 (no internet needed) -----------------
"$BUILD/echoserver" 127.0.0.1:0 > "$BUILD/echo.log" 2>&1 &
ECHO_PID=$!
trap 'kill $ECHO_PID 2>/dev/null' EXIT
for _ in $(seq 1 50); do grep -q '^LISTEN ' "$BUILD/echo.log" && break; sleep 0.1; done
ECHO_ADDR="$(awk '/^LISTEN /{print $2}' "$BUILD/echo.log")"
[ -n "$ECHO_ADDR" ] || { echo "echo server did not start"; exit 1; }
ECHO_HOST="${ECHO_ADDR%:*}"; ECHO_PORT="${ECHO_ADDR##*:}"
echo "== echo server on $ECHO_ADDR (pid $ECHO_PID) =="

# ---- resolve phase-2 host once, for the injection runs --------------------
# Fault injection is process-wide, so an unpinned run would also break the
# resolver's own sockets and confound the result.  DNS is out of scope for E1
# (the adapter supplies sentry DNS), so the injection runs pin the address.
URL_HOST="$(printf '%s' "$URL" | sed -E 's#^https?://##; s#/.*##; s#:.*##')"
PIN_IP="$(getent ahostsv4 "$URL_HOST" | awk '{print $1; exit}')"
echo "== phase-2 host $URL_HOST pinned to ${PIN_IP:-<unresolved>} for injection runs =="

# run <nn> <slug> <trace-set> <inject-or-empty> <runtime: go|node> <pin: 0|1>
run() {
  local nn="$1" slug="$2" tr="$3" inject="$4" rt="$5" pin="$6"
  if [ -n "$ONLY" ] && [[ " $ONLY " != *" $nn "* ]]; then return 0; fi
  local out="$OUTDIR/output-$nn-$slug.txt"
  local st="$BUILD/$nn.strace" so="$BUILD/$nn.stdout"
  local -a pre=() cmd=()
  [ -n "$inject" ] && pre=(-e "inject=$inject")
  if [ "$rt" = go ]; then
    cmd=("$BUILD/goclient" "$ECHO_ADDR" "$URL")
  else
    cmd=("$NODE" "$HERE/nodeclient.js" "$ECHO_HOST" "$ECHO_PORT" "$URL")
  fi
  local -a env=()
  if [ "$pin" = 1 ] && [ -n "$PIN_IP" ]; then env=(env "E1_DIAL_IP=$PIN_IP"); fi

  echo "-- $nn $slug"
  local t0 t1 rc
  t0=$(date +%s.%N)
  : > "$st"; : > "$so"
  # Per-run wall-clock limit: a refused answer can make a runtime block for
  # ever rather than fail (run 08 does exactly that), so no run may hang the
  # script.  Exit status 124 below means "killed by this timeout".
  "${env[@]}" timeout -k 5 "$RUN_TIMEOUT" \
      strace -f -yy -s 128 -e trace="$tr" "${pre[@]}" -o "$st" "${cmd[@]}" >"$so" 2>&1
  rc=$?
  t1=$(date +%s.%N)
  local verdict="completed"
  [ "$rc" = 124 ] && verdict="TIMED OUT after ${RUN_TIMEOUT}s (the runtime blocked; see the tail of the strace)"

  {
    echo "### E1a run $nn: $slug"
    echo "### date: $(date -Is)"
    echo "### runtime: $rt"
    echo "### command: ${env[*]} strace -f -yy -s 128 -e trace=$tr ${pre[*]} -o <strace> ${cmd[*]}"
    echo "### echo server: $ECHO_ADDR   phase-2 url: $URL   pinned: $pin ${PIN_IP:-}"
    echo "### exit status: $rc   wall: $(awk "BEGIN{printf \"%.2f\", $t1-$t0}")s"
    echo "### outcome: $verdict"
    echo
    echo "########## CLIENT STDOUT+STDERR ##########"
    cat "$so"
    echo
    echo "########## STRACE (untrimmed) ##########"
    cat "$st"
  } > "$out"
  echo "   -> $out  ($(wc -l < "$out") lines, exit $rc)"
}

# ---- baselines ------------------------------------------------------------
run 01 go-baseline               "$TRACE"    ""  go   0
run 02 node-baseline             "$TRACE"    ""  node 0
run 03 go-baseline-with-rw       "$TRACE_RW" ""  go   0
run 04 node-baseline-with-rw     "$TRACE_RW" ""  node 0
# pinned controls: identical to the injection runs except for the injection
run 05 go-baseline-pinned        "$TRACE"    ""  go   1
run 06 node-baseline-pinned      "$TRACE"    ""  node 1

# ---- fault injection ------------------------------------------------------
run 07 go-inject-getsockname-ENOTSUP        "$TRACE" "getsockname:error=EOPNOTSUPP"       go   1
run 08 go-inject-getpeername-ENOTCONN       "$TRACE" "getpeername:error=ENOTCONN"         go   1
run 09 go-inject-setsockopt-ENOPROTOOPT     "$TRACE" "setsockopt:error=ENOPROTOOPT"       go   1
run 10 go-inject-getsockopt-ENOPROTOOPT-all "$TRACE" "getsockopt:error=ENOPROTOOPT"       go   1
run 11 go-inject-getsockopt-ENOPROTOOPT-first "$TRACE" "getsockopt:error=ENOPROTOOPT:when=1" go 1
run 12 go-inject-shutdown-ENOTCONN          "$TRACE" "shutdown:error=ENOTCONN"            go   1

run 13 node-inject-getsockname-ENOTSUP        "$TRACE" "getsockname:error=EOPNOTSUPP"       node 1
run 14 node-inject-getpeername-ENOTCONN       "$TRACE" "getpeername:error=ENOTCONN"         node 1
run 15 node-inject-setsockopt-ENOPROTOOPT     "$TRACE" "setsockopt:error=ENOPROTOOPT"       node 1
run 16 node-inject-getsockopt-ENOPROTOOPT-all "$TRACE" "getsockopt:error=ENOPROTOOPT"       node 1
run 17 node-inject-getsockopt-ENOPROTOOPT-first "$TRACE" "getsockopt:error=ENOPROTOOPT:when=1" node 1
run 18 node-inject-shutdown-ENOTCONN          "$TRACE" "shutdown:error=ENOTCONN"            node 1

# ---- where did node's EPOLL_CTL_ADD go? -----------------------------------
run 19 node-baseline-io-uring  "$TRACE_IOU" "" node 1

echo "== done =="
