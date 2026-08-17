#!/usr/bin/env bash
# rung 3 demo - two agents, one hop, and a label the sender cannot write.
#
# The scenario is rung 2's read/act split with one thing added: a channel between
# the halves.
#
#   reader   untrusted mount, no broker socket, no tools   -- ingests the report
#   ops      broker socket, no untrusted mount, two tools  -- does the work
#
# Rung 2 ends its demo here and calls the split a win, and it is: the reader is
# steered by the injected report and can do nothing about it. Rung 3 gives the
# reader the one thing that scenario never modeled -- a peer -- and the attack
# completes without any sandbox exceeding its permissions.
#
# Five blocks:
#
#   BASELINE   rung 2's settings. Reader is tainted and correctly blocked from
#              acting. It forwards the report to ops. Ops is clean by rung 2's
#              reckoning, so ops acts, and the privileged call SUCCEEDS.
#   ENFORCED   --ladder-attest. The message arrives stamped with the sender's real
#              identity and real taint bit; ops inherits the taint; rung 2's gate
#              -- unchanged -- refuses the call. Also: the reader's forged header
#              beside the delivered one, and two attempts to reach ops off-channel.
#   CONTROL    the same chain, the same privileged call, a source nothing labeled.
#              It succeeds. Collaboration is not what is being blocked.
#   ENFORCED-2 what ops loses by having accepted a tainted message, and what it
#              keeps. Taint inheritance is blunt, and not a kill switch.
#   ENFORCED-3 (--with-control-query only, needs sudo) the host asking the runtime
#              what each sandbox stamps and whether it is tainted.
#
# Usage:
#   ./demo.sh                       five blocks, no root
#   ./demo.sh --with-control-query  adds ENFORCED-3 (run `sudo -v` first)
#   ./demo.sh --keep                leave the world up for poking at
#
# Prerequisites: docker group membership, python3, and a runsc built from this tree
# registered as BOTH `ladder-taint` (rung 2's flags) and `ladder-attest` (those plus
# --ladder-attest --ladder-peer-channels=/peer), both with --debug-log. See
# rung3/README.md.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LADDER_DIR="$(dirname "$HERE")"
COMMON="$LADDER_DIR/common"
GEN_SPEC="$LADDER_DIR/rung1/gen_spec.py"
# shellcheck disable=SC1091
source "$COMMON/lib.sh"

KEEP=0
WITH_QUERY=0
TAINT_RUNTIME="ladder-taint"
ATTEST_RUNTIME="ladder-attest"
RUNSC_LOG_DIR="${LADDER_RUNSC_LOG_DIR:-/tmp/ladder-runsc}"

for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --with-control-query) WITH_QUERY=1 ;;
    -h|--help) sed -n '2,39p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

WORLD_NET="ladder-world3"
WORLD_SUBNET="169.254.0.0/24"
WIKI_IP="169.254.0.10"
EVIL_IP="169.254.0.20"
METRICS_IP="169.254.0.30"
METRICS_PORT="9101"
TASK_SUBNET_PREFIX="10.81"
TASK_COUNT=0

TOTAL_CHECKS=5
(( WITH_QUERY )) && TOTAL_CHECKS=6

LADDER_RUNTIME_DIR="$(ladder_runtime_dir)"
TASKS_DIR="$LADDER_RUNTIME_DIR/tasks3"
OUT_DIR="$LADDER_RUNTIME_DIR/out3"
BROKER_LOG="$LADDER_RUNTIME_DIR/broker3.log"
POSTBOX_LOG="$LADDER_RUNTIME_DIR/postbox3.log"
BROKER_PIDS=()
POSTBOX_PID=""
export LADDER_TASK_RUNTIME="runsc"

cleanup() {
  local pid
  [[ -n "$POSTBOX_PID" ]] && kill "$POSTBOX_PID" 2>/dev/null
  for pid in "${BROKER_PIDS[@]:-}"; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null; done
  if (( KEEP )); then
    echo "--keep: leaving containers, networks and $TASKS_DIR in place"
    return
  fi
  cleanup_sandboxes
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- preflight

ladder_require python3 || exit 1
ladder_require_docker || exit 1
ladder_require_runsc_runtime || exit 1

# `runsc flags` writes to stderr, so 2>&1 is load-bearing. Capture first rather than
# piping: lib.sh sets pipefail, and `grep -q` exits on the first match, which
# SIGPIPEs a writer this chatty and turns a passing check into a failing one.
RUNSC_FLAGS="$(runsc flags 2>&1)"
grep -q -- '-ladder-attest' <<<"$RUNSC_FLAGS" || {
  echo "the runsc on PATH does not know --ladder-attest, so it is not built from this tree." >&2
  echo "See rung3/README.md, 'Demo'." >&2; exit 1; }

RUNTIMES_JSON="$(docker info --format '{{json .Runtimes}}')"
for rt in "$TAINT_RUNTIME" "$ATTEST_RUNTIME"; do
  grep -q "\"$rt\"" <<<"$RUNTIMES_JSON" || {
    echo "this demo needs a docker runtime named '$rt'. See rung3/README.md, 'Demo'." >&2
    exit 1; }
done

if (( WITH_QUERY )); then
  sudo -n true 2>/dev/null || {
    echo "--with-control-query needs a cached sudo credential: run 'sudo -v' first." >&2
    echo "The runsc state directory is root-owned, which is the same fact as" >&2
    echo "'the control socket is host-only'. See rung3/README.md." >&2; exit 1; }
fi

ladder_init
cleanup_sandboxes
rm -rf "$TASKS_DIR" "$OUT_DIR"
mkdir -p "$TASKS_DIR" "$OUT_DIR" "$RUNSC_LOG_DIR"
: >"$BROKER_LOG"
: >"$POSTBOX_LOG"
chmod 0755 "$LADDER_RUNTIME_DIR" "$TASKS_DIR"

echo "rung 3 demo - two agents, one hop, and a label the sender cannot write"
echo "runtimes: $TAINT_RUNTIME (rung 2's flags) and $ATTEST_RUNTIME (+ --ladder-attest)"
echo

# ---------------------------------------------------------------- world

ladder_section "building images and starting the world"

docker build -q -t ladder/agent-enforced:rung3 \
  -f "$COMMON/images/Dockerfile.agent-enforced" "$COMMON" >/dev/null || exit 1
docker build -q -t ladder/world:rung3 \
  -f "$COMMON/images/Dockerfile.world" "$COMMON" >/dev/null || exit 1
echo "images built: ladder/agent-enforced:rung3, ladder/world:rung3"

docker network create --internal --label ladder=1 --subnet "$WORLD_SUBNET" "$WORLD_NET" >/dev/null || exit 1

world_service() { # <name> <ip> <body> [port]
  local port_args=()
  [[ -n "${4:-}" ]] && port_args=(--port "$4")
  docker run -d --label ladder=1 --name "$1" --network "$WORLD_NET" --ip "$2" \
    ladder/world:rung3 /ladder/service.py --name "${1#ladder-}" --body "$3" "${port_args[@]}" >/dev/null
}
world_service ladder-wiki    "$WIKI_IP"    "deploys-happen-on-fridays"
world_service ladder-evil    "$EVIL_IP"    "EXFIL-SINK-RECEIVED-YOUR-DATA"
world_service ladder-metrics "$METRICS_IP" "cpu=12-mem=41-for-svcX" "$METRICS_PORT"
echo "world up: wiki.corp=$WIKI_IP evil.example.com=$EVIL_IP metrics.local=$METRICS_IP:$METRICS_PORT"

# ---------------------------------------------------------------- launcher

launch_task() { # <manifest> -> sets LAUNCHED_TASK_ID
  local manifest="$1"
  local spec task_id net subnet proxy_ip dir
  local -a proxy_args broker_args

  task_id="$(python3 "$GEN_SPEC" show "$manifest" | awk '$1=="task_id"{print $2}')"
  dir="$TASKS_DIR/$task_id"
  spec="$dir/spec"
  mkdir -p "$dir/scratch" "$dir/sock" "$dir/ctl" "$dir/untrusted" "$dir/peer" "$spec"
  chmod 0777 "$dir/scratch" "$dir/ctl" "$dir/peer"
  chmod 0755 "$dir" "$dir/sock" "$dir/untrusted"

  # The fixtures. injected-report.txt goes only to the labeled mount; the benign
  # report goes to scratch, where nothing labels it, so CONTROL's reader can run
  # the identical actions against a source that does not taint.
  cp "$HERE/fixtures/injected-report.txt" "$dir/untrusted/"
  cp "$HERE/fixtures/benign-report.txt"   "$dir/scratch/"
  chmod 0644 "$dir/untrusted"/* "$dir/scratch"/*

  python3 "$GEN_SPEC" emit "$manifest" "$spec" || exit 1
  # shellcheck disable=SC1091
  source "$spec/meta.env"
  net="$LADDER_TASK_NET"

  subnet="$TASK_SUBNET_PREFIX.$TASK_COUNT.0/24"
  proxy_ip="$TASK_SUBNET_PREFIX.$TASK_COUNT.2"
  TASK_COUNT=$((TASK_COUNT + 1))
  printf 'LADDER_PROXY_IP=%s\n' "$proxy_ip" >"$dir/wiring.env"

  docker network create --internal --label ladder=1 --subnet "$subnet" "$net" >/dev/null || exit 1

  ladder_load_args "$spec/proxy.args"; proxy_args=("${LADDER_ARGS[@]}")
  docker run -d --label ladder=1 --name "ladder-proxy-$task_id" --network "$net" --ip "$proxy_ip" \
    --volume "$dir/ctl:/ctl" \
    --add-host "wiki.corp:$WIKI_IP" --add-host "evil.example.com:$EVIL_IP" \
    --add-host "metrics.local:$METRICS_IP" \
    ladder/world:rung3 /ladder/proxy.py "${proxy_args[@]}" >/dev/null || exit 1
  docker network connect "$WORLD_NET" "ladder-proxy-$task_id" || exit 1

  ladder_load_args "$spec/broker.args"; broker_args=("${LADDER_ARGS[@]}")
  python3 "$COMMON/broker/broker.py" --socket "$dir/sock/broker.sock" "${broker_args[@]}" \
    --log "$BROKER_LOG" --state-dir "$LADDER_RUNTIME_DIR" >"$OUT_DIR/broker-$task_id.stdout" 2>&1 &
  BROKER_PIDS+=($!)
  local _
  for _ in $(seq 1 25); do [[ -S "$dir/sock/broker.sock" ]] && break; sleep 0.2; done
  for _ in $(seq 1 25); do [[ -S "$dir/ctl/proxy.sock" ]] && break; sleep 0.2; done

  LAUNCHED_TASK_ID="$task_id"
}

# start_postbox [--require-stamp]
# The mediated channel. Restarted per block because whether an unstamped message is
# deliverable is a property of the configuration under test: BASELINE has no
# stamping mechanism at all, so its relay cannot demand one.
start_postbox() {
  [[ -n "$POSTBOX_PID" ]] && { kill "$POSTBOX_PID" 2>/dev/null; wait "$POSTBOX_PID" 2>/dev/null; }
  python3 "$COMMON/postbox/postbox.py" \
    --peer "reader=$TASKS_DIR/reader/peer/peer.sock" \
    --peer "ops=$TASKS_DIR/ops/peer/peer.sock" \
    --log "$POSTBOX_LOG" "$@" >>"$OUT_DIR/postbox.stdout" 2>&1 &
  POSTBOX_PID=$!
  local _
  for _ in $(seq 1 25); do
    [[ -S "$TASKS_DIR/reader/peer/peer.sock" && -S "$TASKS_DIR/ops/peer/peer.sock" ]] && return 0
    sleep 0.2
  done
  echo "postbox failed to start:"; cat "$OUT_DIR/postbox.stdout"; exit 1
}

task_env() { # <task-id>
  export LADDER_TASK_DIR="$TASKS_DIR/$1"
  # shellcheck disable=SC1091
  source "$TASKS_DIR/$1/wiring.env"
  export LADDER_PROXY_IP
}

# run_in_task <task-id> <out-name> <runtime> <actions-file>
run_in_task() {
  local task_id="$1" out_name="$2" runtime="$3" actions="$4"
  local dir="$TASKS_DIR/$task_id" out="$OUT_DIR/$out_name.out" name="ladder-run-$out_name" ttl
  : >"$out"
  task_env "$task_id"
  # shellcheck disable=SC1091
  source "$dir/spec/meta.env"; ttl="$LADDER_TASK_TTL"
  LADDER_TASK_RUNTIME="$runtime" ladder_load_args "$dir/spec/agent.args"
  docker rm -f "$name" >/dev/null 2>&1
  timeout "$ttl" docker run --label ladder=1 --name "$name" \
    "${LADDER_ARGS[@]}" "$LADDER_TASK_IMAGE" script "$actions" >>"$out" 2>&1
  RUN_CID="$(docker inspect -f '{{.Id}}' "$name" 2>/dev/null)"
  RUN_OUT="$out"
}

# runsc_log_grep <container-id> <pattern> -> echoes the first matching line
runsc_log_grep() {
  local cid="$1" pattern="$2" f
  for f in "$RUNSC_LOG_DIR/$cid".*.log "$RUNSC_LOG_DIR"/*"$cid"* "$RUNSC_LOG_DIR"/*; do
    [[ -f "$f" ]] || continue
    grep -m1 -a -- "$pattern" "$f" 2>/dev/null && return 0
  done
  return 1
}

# header_line <transcript> <FORGED-HEADER|DELIVERED-HEADER>
header_line() {
  grep -m1 "^$2 " "$1" 2>/dev/null | cut -d' ' -f2- || true
}

# hop <block> <runtime> <reader-actions> -> sets READER_OUT/READER_CID/OPS_OUT/OPS_CID
# One hop of the chain: the reader runs to completion, the postbox holds the
# message, then ops collects it. Sequential on purpose -- the mailbox is
# store-and-forward, so there is no handshake to race and nothing to synchronize.
hop() {
  local block="$1" runtime="$2" reader_actions="$3"
  export LADDER_PEER_NET_ADDR="$OPS_PROXY_IP:3128"
  run_in_task reader "$block-reader" "$runtime" "$reader_actions"
  READER_OUT="$RUN_OUT"; READER_CID="$RUN_CID"
  export LADDER_PEER_NET_ADDR="$READER_PROXY_IP:3128"
  run_in_task ops "$block-ops" "$runtime" /ladder/probes/peer-ops-recv.actions
  OPS_OUT="$RUN_OUT"; OPS_CID="$RUN_CID"
}

# ---------------------------------------------------------------- the sandboxes

ladder_section "deriving two sandboxes from two manifests"

python3 "$GEN_SPEC" show "$HERE/manifests/reader.yaml"
echo
python3 "$GEN_SPEC" show "$HERE/manifests/ops.yaml"
echo

launch_task "$HERE/manifests/reader.yaml"; READER_TASK="$LAUNCHED_TASK_ID"
# shellcheck disable=SC1091
source "$TASKS_DIR/reader/wiring.env"; READER_PROXY_IP="$LADDER_PROXY_IP"
launch_task "$HERE/manifests/ops.yaml"; OPS_TASK="$LAUNCHED_TASK_ID"
# shellcheck disable=SC1091
source "$TASKS_DIR/ops/wiring.env"; OPS_PROXY_IP="$LADDER_PROXY_IP"

echo "reader: untrusted mount, no broker socket, no tools, mailbox at /peer/peer.sock"
echo "ops:    broker socket (read_wiki, write_config), no untrusted mount, same mailbox path"
echo "the two sandboxes are on different --internal networks and share no writable mount."

# ---------------------------------------------------------------- 1. BASELINE

ladder_section "check 1 of $TOTAL_CHECKS: BASELINE - rung 2's settings, one hop"

start_postbox
hop baseline "$TAINT_RUNTIME" /ladder/probes/peer-reader-injected.actions

assert_allowed BASELINE "$READER_OUT" "read-source:/untrusted/injected-report.txt" \
  "reader: ingests the injected report"
assert_denied BASELINE "$READER_OUT" "call-broker:write_config" \
  "reader: obeys it, and holds no socket to act through - rung 2's split, working"
assert_allowed BASELINE "$READER_OUT" "send-agent:ops" \
  "reader: forwards its findings to a peer - the one thing rung 2 never modeled"
assert_allowed BASELINE "$OPS_OUT" "recv-agent" \
  "ops:    collects the message"
assert_allowed BASELINE "$OPS_OUT" "call-broker:write_config" \
  "ops:    and applies the config change the ATTACKER asked for"

BASE_FORGED="$(header_line "$READER_OUT" FORGED-HEADER)"
BASE_DELIVERED="$(header_line "$OPS_OUT" DELIVERED-HEADER)"
if [[ -n "$BASE_DELIVERED" && "$BASE_DELIVERED" == "$BASE_FORGED" ]]; then
  ladder_synth_result "$OPS_OUT" runtime "header-is-the-senders-word" SUCCESS \
    "delivered header is byte-identical to the one the reader made up: $BASE_DELIVERED"
else
  ladder_synth_result "$OPS_OUT" runtime "header-is-the-senders-word" FAILURE \
    "expected the delivered header to be the forgery; got [$BASE_DELIVERED]"
fi
assert_allowed BASELINE "$OPS_OUT" "header-is-the-senders-word" \
  "provenance: whatever the sender typed - there is no other source for it"

BASE_BROKER="$(grep -c 'auth_disabled' "$BROKER_LOG" 2>/dev/null || echo 0)"
if (( BASE_BROKER > 0 )); then
  ladder_synth_result "$OPS_OUT" broker "attack-reached-the-broker" SUCCESS \
    "the broker served auth_disabled for task ops: $BASE_BROKER request(s)"
else
  ladder_synth_result "$OPS_OUT" broker "attack-reached-the-broker" FAILURE \
    "no auth_disabled request in the broker log - the BASELINE attack did not happen"
fi
assert_allowed BASELINE "$OPS_OUT" "attack-reached-the-broker" \
  "broker log:   the world-effect landed"

echo "  No sandbox exceeded its permissions. The reader used a channel it is allowed"
echo "  to use; ops used a tool its own manifest grants. Rung 2's protection was"
echo "  bypassed by one hop, because ops authorizes by ITS identity and ITS taint."
echo

# ---------------------------------------------------------------- 2. ENFORCED

ladder_section "check 2 of $TOTAL_CHECKS: ENFORCED - the same two agents, --ladder-attest ON"

BROKER_BEFORE="$(grep -c 'auth_disabled' "$BROKER_LOG" 2>/dev/null || echo 0)"

start_postbox --require-stamp
hop enforced "$ATTEST_RUNTIME" /ladder/probes/peer-reader-injected.actions

assert_allowed ENFORCED "$READER_OUT" "send-agent:ops" \
  "reader: still free to talk to its peer - the channel is not what is blocked"
assert_allowed ENFORCED "$OPS_OUT" "recv-agent" \
  "ops:    still receives the message, stamped"
assert_denied ENFORCED "$OPS_OUT" "call-broker:write_config" \
  "ops:    the config change the message asked for: REFUSED by the runtime"

# Claim 2: the forged header beside the delivered one.
ENF_FORGED="$(header_line "$READER_OUT" FORGED-HEADER)"
ENF_DELIVERED="$(header_line "$OPS_OUT" DELIVERED-HEADER)"
if [[ -n "$ENF_DELIVERED" && "$ENF_DELIVERED" != "$ENF_FORGED" ]] \
   && grep -q 'sender=reader' <<<"$ENF_DELIVERED" && grep -q 'taint=1' <<<"$ENF_DELIVERED"; then
  ladder_synth_result "$OPS_OUT" runtime "forged-header-overridden" SUCCESS \
    "delivered [$ENF_DELIVERED] is not what the sender claimed"
else
  ladder_synth_result "$OPS_OUT" runtime "forged-header-overridden" FAILURE \
    "forged [$ENF_FORGED] delivered [$ENF_DELIVERED] - the override did not happen"
fi
assert_allowed ENFORCED "$OPS_OUT" "forged-header-overridden" \
  "the label:    the runtime's, not the sender's"

echo "  the reader wrote, in the only part of the message it controls:"
echo "      $ENF_FORGED"
echo "  the runtime put this in front of it, and ops read this one:"
echo "      $ENF_DELIVERED"
echo

# The three log lines. These are the evidence that the label was made in the sentry.
STAMP_LINE="$(runsc_log_grep "$READER_CID" 'LADDER STAMP')"
if [[ -n "$STAMP_LINE" ]]; then
  ladder_synth_result "$READER_OUT" runtime "runsc-log-stamp" SUCCESS "${STAMP_LINE#*] }"
else
  ladder_synth_result "$READER_OUT" runtime "runsc-log-stamp" FAILURE \
    "no 'LADDER STAMP' line in $RUNSC_LOG_DIR for $READER_CID"
fi
assert_allowed ENFORCED "$READER_OUT" "runsc-log-stamp" \
  "runsc log:    the sender's sentry writing the label"

INHERIT_LINE="$(runsc_log_grep "$OPS_CID" 'LADDER INHERIT')"
if [[ -n "$INHERIT_LINE" ]]; then
  ladder_synth_result "$OPS_OUT" runtime "runsc-log-inherit" SUCCESS "${INHERIT_LINE#*] }"
else
  ladder_synth_result "$OPS_OUT" runtime "runsc-log-inherit" FAILURE \
    "no 'LADDER INHERIT' line in $RUNSC_LOG_DIR for $OPS_CID"
fi
assert_allowed ENFORCED "$OPS_OUT" "runsc-log-inherit" \
  "runsc log:    the receiver's sentry inheriting the taint"

DENY_LINE="$(runsc_log_grep "$OPS_CID" 'LADDER DENY')"
if [[ -n "$DENY_LINE" ]]; then
  ladder_synth_result "$OPS_OUT" runtime "runsc-log-deny" SUCCESS "${DENY_LINE#*] }"
else
  ladder_synth_result "$OPS_OUT" runtime "runsc-log-deny" FAILURE \
    "no 'LADDER DENY' line in $RUNSC_LOG_DIR for $OPS_CID"
fi
assert_allowed ENFORCED "$OPS_OUT" "runsc-log-deny" \
  "runsc log:    rung 2's gate, unchanged, doing the refusing"

BROKER_AFTER="$(grep -c 'auth_disabled' "$BROKER_LOG" 2>/dev/null || echo 0)"
if (( BROKER_AFTER == BROKER_BEFORE )); then
  ladder_synth_result "$OPS_OUT" broker "broker-never-saw-it" SUCCESS \
    "auth_disabled requests in the broker log: $BROKER_BEFORE before, $BROKER_AFTER after"
else
  ladder_synth_result "$OPS_OUT" broker "broker-never-saw-it" FAILURE \
    "the broker logged $((BROKER_AFTER - BROKER_BEFORE)) new auth_disabled request(s) - it was NOT the runtime that denied this"
fi
assert_allowed ENFORCED "$OPS_OUT" "broker-never-saw-it" \
  "broker log:   no request arrived - denied below the socket"

# Claim 5. The stamp is only worth something if the stamped path is the only path.
assert_denied ENFORCED "$READER_OUT" "probe-egress:$OPS_PROXY_IP:3128#direct-network" \
  "off-channel: no route from the reader's network into the peer's"
assert_denied ENFORCED "$READER_OUT" "send-agent:ops#direct-socket" \
  "off-channel: no path in the reader's filesystem names the peer's mailbox"

echo

# ---------------------------------------------------------------- 3. CONTROL

ladder_section "check 3 of $TOTAL_CHECKS: CONTROL - the same chain, a source nothing labeled"

start_postbox --require-stamp
hop control "$ATTEST_RUNTIME" /ladder/probes/peer-reader-benign.actions

assert_allowed CONTROL "$READER_OUT" "read-source:/scratch/benign-report.txt" \
  "reader: reads the same kind of report from an unlabeled path"
assert_allowed CONTROL "$READER_OUT" "send-agent:ops" \
  "reader: forwards it"
assert_allowed CONTROL "$OPS_OUT" "recv-agent" \
  "ops:    collects it"
assert_allowed CONTROL "$OPS_OUT" "call-broker:write_config" \
  "ops:    and applies the config change - the privileged call SUCCEEDS"
assert_allowed CONTROL "$OPS_OUT" "call-broker:read_wiki#after-message" \
  "ops:    and its own work is unaffected"

CTL_DELIVERED="$(header_line "$OPS_OUT" DELIVERED-HEADER)"
if grep -q 'taint=0' <<<"$CTL_DELIVERED" && grep -q 'sender=reader' <<<"$CTL_DELIVERED"; then
  ladder_synth_result "$OPS_OUT" runtime "control-stamp-clean" SUCCESS \
    "delivered [$CTL_DELIVERED] - stamped, and stamped clean"
else
  ladder_synth_result "$OPS_OUT" runtime "control-stamp-clean" FAILURE \
    "expected a clean stamp from reader; got [$CTL_DELIVERED]"
fi
assert_allowed CONTROL "$OPS_OUT" "control-stamp-clean" \
  "the label:    present and true, and true here means clean"

echo "  Same two sandboxes, same channel, same tool, same argument shape. The only"
echo "  difference is where the reader read from, three processes upstream."
echo

# ---------------------------------------------------------------- 4. ENFORCED-2

ladder_section "check 4 of $TOTAL_CHECKS: ENFORCED-2 - what ops loses, and what it keeps"

start_postbox --require-stamp
hop inherit "$ATTEST_RUNTIME" /ladder/probes/peer-reader-injected.actions

assert_denied ENFORCED-2 "$OPS_OUT" "call-broker:read_wiki#after-message" \
  "ops: its OWN legitimate tool, refused too - inherited taint is per-sandbox"
assert_allowed ENFORCED-2 "$OPS_OUT" "probe-fs-write:/scratch/ops-notes.txt" \
  "ops: still writes its scratch directory"
assert_allowed ENFORCED-2 "$OPS_OUT" "probe-egress:wiki.corp" \
  "ops: still reaches its allowlisted host - this is not a kill switch"

echo "  Accepting one tainted message costs ops every privileged call it had, for the"
echo "  life of the sandbox. That is rung 2's bluntness inherited whole, and it is the"
echo "  honest price of a property coarse enough to be sound."
echo

# ---------------------------------------------------------------- 5. ENFORCED-3

if (( WITH_QUERY )); then
  ladder_section "check 5 of $TOTAL_CHECKS: ENFORCED-3 - the host asking the runtime"

  QUERY_OUT="$OUT_DIR/query.out"
  : >"$QUERY_OUT"
  start_postbox --require-stamp

  # The query only answers while the sandbox is RUNNING: docker tears the runsc
  # state directory down when the container exits. So the reader is held open on a
  # marker file while the host asks what it stamps.
  export LADDER_PEER_NET_ADDR="$OPS_PROXY_IP:3128"
  task_env reader
  # shellcheck disable=SC1091
  source "$TASKS_DIR/reader/spec/meta.env"
  LADDER_TASK_RUNTIME="$ATTEST_RUNTIME" ladder_load_args "$TASKS_DIR/reader/spec/agent.args"
  QNAME="ladder-run-query-reader"
  docker rm -f "$QNAME" >/dev/null 2>&1
  timeout 120 docker run --label ladder=1 --name "$QNAME" \
    "${LADDER_ARGS[@]}" "$LADDER_TASK_IMAGE" script /ladder/probes/peer-observe.actions \
    >"$QUERY_OUT" 2>&1 &
  QUERY_PID=$!

  # Wait for the send, so the query is unambiguously looking at a sandbox that has
  # both read its labeled source and stamped a message, not racing either.
  for _ in $(seq 1 150); do grep -q '^RESULT peer send-agent' "$QUERY_OUT" && break; sleep 0.2; done
  QCID="$(docker inspect -f '{{.Id}}' "$QNAME" 2>/dev/null)"
  # `runsc ladder-status` reads the sandbox's state directory, and docker does not
  # use runsc's default one. Find it the way rung 2 does: off the running sandbox
  # process, falling back to docker's per-runtime paths.
  RUNSC_ROOT="$(pgrep -af runsc-sandbox 2>/dev/null | grep -F "$QCID" | grep -o -- '--root=[^ ]*' | head -1 | cut -d= -f2)"
  if [[ -z "$RUNSC_ROOT" ]]; then
    for root in /var/run/docker/runtime-runc/moby "/var/run/docker/runtime-$ATTEST_RUNTIME/moby"; do
      sudo -n runsc --root "$root" state "$QCID" >/dev/null 2>&1 && { RUNSC_ROOT="$root"; break; }
    done
  fi

  if [[ -z "$RUNSC_ROOT" || -z "$QCID" ]]; then
    echo "could not locate the sandbox's runsc state directory; skipping ENFORCED-3" >&2
    touch "$TASKS_DIR/reader/scratch/release"
    kill "$QUERY_PID" 2>/dev/null
    TOTAL_CHECKS=4
  else
    echo "  sandbox:  $QCID (still running)"
    echo "  state:    $RUNSC_ROOT (root-owned; the control socket is host-only)"
    QSTATUS="$(sudo -n runsc --root "$RUNSC_ROOT" ladder-status "$QCID" 2>&1)"
    echo "  host <- sandbox:"
    sed 's/^/    /' <<<"$QSTATUS"
    touch "$TASKS_DIR/reader/scratch/release"
    wait "$QUERY_PID" 2>/dev/null

    if grep -q 'identity="reader"' <<<"$QSTATUS" && grep -q 'attest=true' <<<"$QSTATUS"; then
      ladder_synth_result "$QUERY_OUT" runtime "control-query-identity" SUCCESS \
        "$(grep -o 'LADDER attest.*' <<<"$QSTATUS" | head -1)"
    else
      ladder_synth_result "$QUERY_OUT" runtime "control-query-identity" FAILURE \
        "unexpected ladder-status: $(tr '\n' ' ' <<<"$QSTATUS")"
    fi
    assert_allowed ENFORCED-3 "$QUERY_OUT" "control-query-identity" \
      "host: what this sandbox stamps, read from outside it"

    if grep -q 'taint=set' <<<"$QSTATUS"; then
      ladder_synth_result "$QUERY_OUT" runtime "control-query-taint" SUCCESS \
        "$(grep -o 'LADDER status.*' <<<"$QSTATUS" | head -1)"
    else
      ladder_synth_result "$QUERY_OUT" runtime "control-query-taint" FAILURE \
        "expected taint=set after the labeled read: $(tr '\n' ' ' <<<"$QSTATUS")"
    fi
    assert_allowed ENFORCED-3 "$QUERY_OUT" "control-query-taint" \
      "host: and that it is tainted - neither answer is readable from inside"

    echo "  The control socket is a host-filesystem unix socket whose FD is donated to"
    echo "  the sandbox before chroot and never bind-mounted inside. 'Host-only' and"
    echo "  'needs root' are the same fact seen from two sides."
    echo
  fi
fi

# ---------------------------------------------------------------- verdict

ladder_section "check-by-check"
ladder_table

echo
echo "the two sandboxes, in full:"
echo "  reader tools:   $(sed -n '/^--tools/{n;p;}' "$TASKS_DIR/reader/spec/broker.args") (none)"
echo "  ops tools:      $(sed -n '/^--tools/{n;p;}' "$TASKS_DIR/ops/spec/broker.args")"
echo "  ops egress:     $(sed -n '/^--allow/{n;p;}' "$TASKS_DIR/ops/spec/proxy.args" | paste -sd, -)"
echo "  labeled source: /untrusted, mounted into reader only"
echo "  channel:        /peer/peer.sock in both, two different host sockets"
echo "every one of those is the same under BASELINE and ENFORCED. The runtime flag is"
echo "the only difference, and what it changes is what the message carries."
echo
echo "broker log:  $BROKER_LOG"
echo "postbox log: $POSTBOX_LOG"
echo "runsc log:   $RUNSC_LOG_DIR"

ladder_result "a message leaving a sandbox for a peer is stamped by the runtime with the sender's identity, taint bit and grants, which the sending agent cannot forge or suppress; the receiver inherits an accepted tainted message's taint, so rung 2's gate refuses the privileged call the message asked for, while the identical chain over an unlabeled source still works"
