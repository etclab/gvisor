#!/usr/bin/env bash
# rung 5a demo - two hosts, standing services, and a stamp that has to cross a network.
#
# Rungs 3 and 4 made the stamp unforgeable because ONE trusted relay was every sandbox's
# only path and the sender and receiver shared it. That is a statement about one process
# boundary, and rung 4's own threat model says what happens when you move the second hop:
# "Two hosts running this patch would believe each other's stamps for no reason at all."
#
# The scenario is the ecosystem's shape rather than the ladder's: agents as STANDING
# SERVICES, long-lived and addressable, the way A2A and MCP deployments actually look.
#
#   host A   trigger  -- the user's request, sandboxed so rung 3's stamp rule holds
#            reader   -- a standing service; fetches the incident page, relays findings
#   host B   ops      -- a standing service; holds the production tools
#
# Five blocks:
#
#   BASELINE   --ladder-fed off: plain TCP between the two proxies. A MITM reads the
#              message and rewrites cache_size into auth_disabled, and ops applies it.
#              Then an IMPOSTOR host nobody enrolled delivers a forged clean-stamp
#              message and ops applies that too. Both succeed.
#   ENFORCED   flag on. The impostor is refused at the handshake; the MITM relays
#              ciphertext; and eight per-message checks are exercised one at a time by an
#              enrolled-but-misbehaving sender, each with its own rejection code.
#   CONTROL    the legitimate cross-host chain still works, and the burst numbers are
#              printed: handshake vs stream-open vs end-to-end, and 32 concurrent
#              exchanges completing unattended.
#   ENFORCED-2 the rung-4 chain, cross-host. The reader reads the page from the LABELED
#              path, and taint, origin and the hop list arrive intact at a machine that
#              observed none of them. The privileged call is refused.
#   ENFORCED-3 the recycle policy. The tainted standing service is destroyed and
#              restarted from its image, and taint clears only by rebirth.
#
# Usage:
#   ./demo.sh            five blocks, no root
#   ./demo.sh --keep     leave the world up for poking at
#
# Prerequisites: docker group membership, python3, Go (the module declares 1.25; the
# gVisor tree's own toolchain is newer, so any checkout that builds runsc builds this),
# and a runsc built from this tree registered as `ladder-chain`. See rung5a/README.md.
#
# NOT required: root, network namespaces, a second machine, or internet access.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LADDER_DIR="$(dirname "$HERE")"
COMMON="$LADDER_DIR/common"
GEN_SPEC="$LADDER_DIR/rung1/gen_spec.py"
CHAIND="$COMMON/chaind/chaind.py"
FED_SRC="$COMMON/fed"
# shellcheck disable=SC1091
source "$COMMON/lib.sh"

KEEP=0
CHAIN_RUNTIME="ladder-chain"
RUNSC_LOG_DIR="${LADDER_RUNSC_LOG_DIR:-/tmp/ladder-runsc}"

for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,46p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# quic-go warns about the UDP receive buffer on every start; raising it needs root and
# nothing here is throughput-bound. Suppressed so the projector shows the demo.
export QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=true

WORLD_NET="ladder-world5a"
WORLD_SUBNET="169.254.0.0/24"
WIKI_IP="169.254.0.10"
EVIL_IP="169.254.0.20"
METRICS_IP="169.254.0.30"
METRICS_PORT="9101"
TASK_SUBNET_PREFIX="10.90"
TASK_COUNT=0

# The two "hosts". Loopback aliases rather than network namespaces, because netns needs
# root and every claim rung 5a makes is about what crosses BETWEEN the two proxies, not
# about which kernel they run on. Said plainly in README.md under "Two hosts on one box".
HOSTA_ADDR="127.0.0.1:14801"
HOSTB_ADDR="127.0.0.2:14802"
MITM_ADDR="127.0.0.3:14803"

TOTAL_CHECKS=5

LADDER_RUNTIME_DIR="$(ladder_runtime_dir)"
# Short on purpose: AF_UNIX paths cap at 108 bytes and this rung nests two hosts inside
# the runtime dir. Every component here learned that the hard way at least once.
FED_DIR="$LADDER_RUNTIME_DIR/f5a"
OUT_DIR="$FED_DIR/out"
FED_BIN="$FED_DIR/ladder-fed"
CONFIG_FILE="$LADDER_RUNTIME_DIR/broker-config.txt"
GOAL="$HERE/scenario/goal-svcx-latency.json"
GOAL_ID="svcX-latency-2026-08-17"
OPS_ROLE="$HERE/scenario/roles/ops-role.json"

SERVICE_PIDS=()
BG_PIDS=()
FED_PIDS=()

stop_bg() {
  local pid
  for pid in "${FED_PIDS[@]:-}" "${BG_PIDS[@]:-}"; do
    [[ -n "$pid" ]] && { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; }
  done
  FED_PIDS=(); BG_PIDS=()
  return 0
}

cleanup() {
  stop_bg
  if (( KEEP )); then
    echo "--keep: leaving containers, networks and $FED_DIR in place"
    return
  fi
  cleanup_sandboxes
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- preflight

ladder_require python3 || exit 1
ladder_require_docker || exit 1
ladder_require_runsc_runtime || exit 1

RUNSC_FLAGS="$(runsc flags 2>&1)"
grep -q -- '-ladder-chain' <<<"$RUNSC_FLAGS" || {
  echo "the runsc on PATH does not know --ladder-chain, so it is not built from this tree." >&2
  echo "See rung5a/README.md, 'Demo'." >&2; exit 1; }

docker info --format '{{json .Runtimes}}' | grep -q "\"$CHAIN_RUNTIME\"" || {
  echo "this demo needs a docker runtime named '$CHAIN_RUNTIME'. See rung5a/README.md." >&2
  exit 1; }

# Go. Pick the first toolchain that can build the module; the gVisor tree's own go.mod
# already demands a newer one than the distro's, so a checkout that builds runsc has one.
GO_BIN=""
for candidate in "${LADDER_GO:-}" go /usr/local/go/bin/go; do
  [[ -z "$candidate" ]] && continue
  command -v "$candidate" >/dev/null 2>&1 || continue
  GO_BIN="$candidate"; break
done
[[ -z "$GO_BIN" ]] && { echo "no go toolchain found; set LADDER_GO. See rung5a/README.md." >&2; exit 1; }

ladder_init
cleanup_sandboxes
rm -rf "$FED_DIR"
mkdir -p "$OUT_DIR" "$RUNSC_LOG_DIR"
chmod 0755 "$LADDER_RUNTIME_DIR"
: >"$CONFIG_FILE"

echo "rung 5a demo - two hosts, standing services, and a stamp that has to cross a network"
echo "runtime:  $CHAIN_RUNTIME (rungs 2-4's flags; rung 5a adds no runsc flag at all)"
echo "hosts:    hosta=$HOSTA_ADDR  hostb=$HOSTB_ADDR  (loopback aliases, no root, no netns)"
echo "goal:     $GOAL_ID, minted on host A only"
echo

# ---------------------------------------------------------------- build

ladder_section "building"

docker build -q -t ladder/agent-enforced:rung5a \
  -f "$COMMON/images/Dockerfile.agent-enforced" "$COMMON" >/dev/null || exit 1
docker build -q -t ladder/world:rung5a \
  -f "$COMMON/images/Dockerfile.world" "$COMMON" >/dev/null || exit 1
echo "images:   ladder/agent-enforced:rung5a, ladder/world:rung5a"

# GOFLAGS=-mod=mod and GOPROXY unset: the module's deps are pinned in go.mod/go.sum and
# are in the module cache after one warm fetch. Nothing at demo time reaches the network.
( cd "$FED_SRC" && GOFLAGS=-mod=mod GOPROXY=off "$GO_BIN" build -o "$FED_BIN" . ) 2>"$OUT_DIR/gobuild.err" || {
  echo "building ladder-fed failed:"; cat "$OUT_DIR/gobuild.err"; exit 1; }
echo "binary:   $FED_BIN ($("$GO_BIN" version | cut -d' ' -f3), offline from the module cache)"

# ---------------------------------------------------------------- the world

ladder_section "starting the world"

docker network create --internal --label ladder=1 --subnet "$WORLD_SUBNET" "$WORLD_NET" >/dev/null || exit 1

world_service() { # <name> <ip> <body> [port]
  local port_args=()
  [[ -n "${4:-}" ]] && port_args=(--port "$4")
  docker run -d --label ladder=1 --name "$1" --network "$WORLD_NET" --ip "$2" \
    ladder/world:rung5a /ladder/service.py --name "${1#ladder-}" --body "$3" "${port_args[@]}" >/dev/null
}
world_service ladder-evil    "$EVIL_IP"    "EXFIL-SINK-RECEIVED-YOUR-DATA"
world_service ladder-metrics "$METRICS_IP" "cpu=12-mem=41-p99=812ms-for-svcX" "$METRICS_PORT"

serve_wiki() { # <fixture-basename>
  local fixture="$1" _
  docker rm -f ladder-wiki >/dev/null 2>&1
  docker run -d --label ladder=1 --name ladder-wiki --network "$WORLD_NET" --ip "$WIKI_IP" \
    --volume "$HERE/fixtures:/ladder/pages:ro" \
    ladder/world:rung5a /ladder/service.py --name wiki --body-file "/ladder/pages/$fixture" >/dev/null || exit 1
  for _ in $(seq 1 50); do
    docker logs ladder-wiki 2>&1 | grep -q 'listening' && return 0
    sleep 0.2
  done
  echo "wiki failed to start serving $fixture" >&2; exit 1
}
serve_wiki benign-page.txt
echo "world up: wiki.corp=$WIKI_IP  evil.example.com=$EVIL_IP  metrics.local=$METRICS_IP:$METRICS_PORT"

# ---------------------------------------------------------------- launcher (rung 1's)

launch_task() { # <host-letter> <manifest>
  local h="$1" manifest="$2"
  local spec task_id net subnet proxy_ip dir
  local -a proxy_args

  task_id="$(python3 "$GEN_SPEC" show "$manifest" | awk '$1=="task_id"{print $2}')"
  dir="$FED_DIR/$h/$task_id"
  spec="$dir/spec"
  mkdir -p "$dir/scratch" "$dir/sock" "$dir/ctl" "$dir/untrusted" "$dir/peer" "$spec"
  chmod 0777 "$dir/scratch" "$dir/ctl" "$dir/peer"
  chmod 0755 "$dir" "$dir/sock" "$dir/untrusted"

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
    ladder/world:rung5a /ladder/proxy.py "${proxy_args[@]}" >/dev/null || exit 1
  docker network connect "$WORLD_NET" "ladder-proxy-$task_id" || exit 1
  local _
  for _ in $(seq 1 25); do [[ -S "$dir/ctl/proxy.sock" ]] && break; sleep 0.2; done
}

task_dir() { printf '%s' "$FED_DIR/$1/$2"; }

# ---------------------------------------------------------------- the two hosts

# Each host gets its own registry, its own capability authority, its own relay, its own
# brokers and its own federation proxy. Nothing is shared between them except the
# loopback network -- which is the point: the two policy layers know about each other
# only through what one enrolled about the other.

start_chaind() { # <host-letter> <assign-hop>
  local h="$1" assign="$2"
  python3 "$CHAIND" serve --socket "$FED_DIR/$h/chd.sock" --goal "$GOAL" --assign "$assign" \
    --log "$FED_DIR/$h/chaind.log" >>"$OUT_DIR/chaind-$h.stdout" 2>&1 &
  BG_PIDS+=($!)
  local _
  for _ in $(seq 1 25); do [[ -S "$FED_DIR/$h/chd.sock" ]] && return 0; sleep 0.2; done
  echo "chaind on host $h failed to start:"; cat "$OUT_DIR/chaind-$h.stdout"; exit 1
}

start_chaind_empty() { # <host-letter> -- host B holds no goal record and mints nothing
  local h="$1"
  python3 "$CHAIND" serve --socket "$FED_DIR/$h/chd.sock" \
    --log "$FED_DIR/$h/chaind.log" >>"$OUT_DIR/chaind-$h.stdout" 2>&1 &
  BG_PIDS+=($!)
  local _
  for _ in $(seq 1 25); do [[ -S "$FED_DIR/$h/chd.sock" ]] && return 0; sleep 0.2; done
  echo "chaind on host $h failed to start:"; cat "$OUT_DIR/chaind-$h.stdout"; exit 1
}

start_brokers() { # <host-letter> <task...>
  local h="$1"; shift
  local task dir
  local -a broker_args
  for task in "$@"; do
    dir="$(task_dir "$h" "$task")"
    ladder_load_args "$dir/spec/broker.args"; broker_args=("${LADDER_ARGS[@]}")
    python3 "$COMMON/broker/broker.py" --socket "$dir/sock/broker.sock" "${broker_args[@]}" \
      --chaind "$FED_DIR/$h/chd.sock" --log "$FED_DIR/$h/broker.log" \
      --state-dir "$LADDER_RUNTIME_DIR" >>"$OUT_DIR/broker-$h-$task.stdout" 2>&1 &
    BG_PIDS+=($!)
  done
  local _
  for task in "$@"; do
    for _ in $(seq 1 25); do [[ -S "$(task_dir "$h" "$task")/sock/broker.sock" ]] && break; sleep 0.2; done
  done
}

start_postbox() { # <host-letter> <host-name> <peer...>
  local h="$1" hostname="$2"; shift 2
  local peer_args=() task last=""
  for task in "$@"; do
    if [[ "$task" == "bench" ]]; then
      mkdir -p "$FED_DIR/$h/bench"; chmod 0777 "$FED_DIR/$h/bench"
      peer_args+=(--peer "bench=$FED_DIR/$h/bench/peer.sock"); last="$FED_DIR/$h/bench/peer.sock"
    else
      peer_args+=(--peer "$task=$(task_dir "$h" "$task")/peer/peer.sock")
      last="$(task_dir "$h" "$task")/peer/peer.sock"
    fi
  done
  python3 "$COMMON/postbox/postbox.py" "${peer_args[@]}" --require-stamp \
    --chaind "$FED_DIR/$h/chd.sock" --host "$hostname" \
    --fed-gateway "$FED_DIR/$h/gw" --fed-ingest "$FED_DIR/$h/in" \
    --log "$FED_DIR/$h/postbox.log" >>"$OUT_DIR/postbox-$h.stdout" 2>&1 &
  BG_PIDS+=($!)
  local _
  for _ in $(seq 1 40); do [[ -S "$last" && -S "$FED_DIR/$h/in" ]] && return 0; sleep 0.2; done
  echo "postbox on host $h failed to start:"; cat "$OUT_DIR/postbox-$h.stdout"; exit 1
}

# start_fed <host-letter> <host-name> <listen> <fed: on|off> <peer-override> <service-args...>
start_fed() {
  local h="$1" hostname="$2" listen="$3" mode="$4" peer="$5"; shift 5
  local -a fedarg=()
  [[ "$mode" == on ]] && fedarg=(--ladder-fed)
  local -a peerarg=()
  [[ -n "$peer" ]] && peerarg=(--peer "$peer")
  "$FED_BIN" serve --host "$hostname" --key "$FED_DIR/$h/key" \
    --registry "$FED_DIR/$h/registry" --listen "$listen" \
    --gateway "$FED_DIR/$h/gw" --ingest "$FED_DIR/$h/in" \
    "${fedarg[@]}" "${peerarg[@]}" "$@" \
    --log "$FED_DIR/$h/fed.log" >>"$OUT_DIR/fed-$h.stdout" 2>&1 &
  FED_PIDS+=($!)
  local _
  for _ in $(seq 1 50); do [[ -S "$FED_DIR/$h/gw" ]] && return 0; sleep 0.2; done
  echo "federation proxy on host $h failed to start:"; cat "$OUT_DIR/fed-$h.stdout"; exit 1
}

start_mitm() { # <mode: tcp|udp> [rewrite...]
  local mode="$1"; shift
  local -a rw=() r
  for r in "$@"; do rw+=(--rewrite "$r"); done
  : >"$FED_DIR/mitm.log"
  "$FED_BIN" mitm --listen "$MITM_ADDR" --forward "$HOSTB_ADDR" --mode "$mode" "${rw[@]}" \
    --log "$FED_DIR/mitm.log" >>"$OUT_DIR/mitm.stdout" 2>&1 &
  FED_PIDS+=($!)
  sleep 0.5
}

# start_federation <fed: on|off> [mitm-rewrite...]
# Everything that differs between BASELINE and ENFORCED is the first argument.
start_federation() {
  local mode="$1"; shift
  local -a rewrites=("$@")
  stop_bg
  rm -f "$FED_DIR"/{a,b}/{gw,in} "$FED_DIR/recycle.log"
  : >"$FED_DIR/recycle.log"

  start_chaind a trigger
  start_chaind_empty b
  start_brokers a trigger reader
  start_brokers b ops
  start_postbox a hosta trigger reader
  start_postbox b hostb ops bench

  local mitm_mode="tcp"
  [[ "$mode" == on ]] && mitm_mode="udp"
  start_mitm "$mitm_mode" ${rewrites[@]+"${rewrites[@]}"}

  # Host A is pointed at the MITM's address for host B. The registry still decides which
  # KEY is acceptable, so the relay is a position on the network and not a trust
  # decision -- which is exactly the difference the two blocks measure.
  start_fed b hostb "$HOSTB_ADDR" "$mode" "" --service "ops=$OPS_ROLE" --service "bench=-"
  start_fed a hosta "$HOSTA_ADDR" "$mode" "hostb=$MITM_ADDR" --service "reader=-" \
    --service "trigger=-" --recycle-on-taint --recycle-log "$FED_DIR/recycle.log"
  sleep 0.8
}

# ---------------------------------------------------------------- sandboxes

place_labeled_page() { cp "$HERE/fixtures/$1" "$(task_dir a reader)/untrusted/incident-page.txt"
                       chmod 0644 "$(task_dir a reader)/untrusted/incident-page.txt"; }

reset_scratch() {
  local h task dir
  for spec in "a trigger" "a reader" "b ops"; do
    set -- $spec; h="$1"; task="$2"
    dir="$(task_dir "$h" "$task")"
    rm -rf "$dir/scratch"; mkdir -p "$dir/scratch"; chmod 0777 "$dir/scratch"
  done
  cp "$HERE/scenario/delegate-trigger-to-reader.json" "$(task_dir a trigger)/scratch/delegate.json"
  cp "$HERE/scenario/delegate-reader-to-ops.json"     "$(task_dir a reader)/scratch/delegate.json"
  chmod 0644 "$(task_dir a trigger)/scratch/delegate.json" "$(task_dir a reader)/scratch/delegate.json"
}

# start_service <host-letter> <task> <name> <actions-file>
# Detached, because a standing service outlives the request that reached it. That is the
# only mechanical difference between this launcher and rung 4's, and it is the model.
start_service() {
  local h="$1" task="$2" name="$3" actions="$4"
  local dir; dir="$(task_dir "$h" "$task")"
  export LADDER_TASK_DIR="$dir"
  # shellcheck disable=SC1091
  source "$dir/wiring.env"; export LADDER_PROXY_IP
  export LADDER_PEER_NET_ADDR="127.0.0.1:1"
  # shellcheck disable=SC1091
  source "$dir/spec/meta.env"
  LADDER_TASK_RUNTIME="$CHAIN_RUNTIME" ladder_load_args "$dir/spec/agent.args"
  docker rm -f "ladder-svc-$name" >/dev/null 2>&1
  docker run -d --label ladder=1 --name "ladder-svc-$name" \
    "${LADDER_ARGS[@]}" "$LADDER_TASK_IMAGE" script "$actions" >/dev/null || {
      echo "failed to start service $name" >&2; exit 1; }
}

collect() { # <name> -> sets RUN_OUT, RUN_CID
  RUN_OUT="$OUT_DIR/$1.out"
  docker logs "ladder-svc-$1" >"$RUN_OUT" 2>&1 || true
  RUN_CID="$(docker inspect -f '{{.Id}}' "ladder-svc-$1" 2>/dev/null)"
}

wait_for_line() { # <name> <pattern> <tries>
  local name="$1" pattern="$2" tries="${3:-150}" _
  for _ in $(seq 1 "$tries"); do
    docker logs "ladder-svc-$name" 2>&1 | grep -q -- "$pattern" && return 0
    sleep 0.2
  done
  return 1
}

stop_services() { docker rm -f $(docker ps -aq --filter 'name=ladder-svc-') >/dev/null 2>&1; return 0; }

# ---------------------------------------------------------------- helpers

config_count() { local n; n="$(grep -c -- "$1" "$CONFIG_FILE" 2>/dev/null)" || n=0; printf '%s' "${n:-0}"; }

header_line() { grep -m1 "^$2 " "$1" 2>/dev/null | cut -d' ' -f2- || true; }
last_header() { grep "^DELIVERED-HEADER " "$1" 2>/dev/null | tail -1 | cut -d' ' -f2- || true; }

chain_view() { # <host-letter> <hop>
  python3 "$CHAIND" call --socket "$FED_DIR/$1/chd.sock" --op view --hop "$2" 2>/dev/null | python3 -c '
import json, sys
try: d = json.load(sys.stdin)
except Exception: print("no answer from the capability authority"); raise SystemExit
v = d.get("view") or {}
if not v.get("known"): print("no chain record for this hop"); raise SystemExit
tools = [t + ("{" + ",".join(c["keys"]) + "}" if c and "keys" in c else "")
         for t, c in sorted((v.get("tools") or {}).items())]
imp = v.get("imported_from") or {}
print("goal=%s chain=%s origin=%s taint=%s effective=%s%s" % (
    v["goal_id"], ">".join(v["chain"]), v["origin"], v["taint"], " ".join(tools),
    (" imported-from=%s" % imp.get("hop","?")) if imp else ""))
'
}

fed_status() { "$FED_BIN" status --gateway "$FED_DIR/$1/gw" 2>/dev/null; }

fed_status_field() { # <host-letter> <python-expression over d>
  fed_status "$1" | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('no answer'); raise SystemExit
print($2)"
}

runsc_log_grep() {
  local cid="$1" pattern="$2" f
  [[ -z "$cid" ]] && return 1
  for f in "$RUNSC_LOG_DIR"/*"$cid"*; do
    [[ -f "$f" ]] || continue
    grep -m1 -a -- "$pattern" "$f" 2>/dev/null && return 0
  done
  return 1
}

STAMP_CLEAN=""
attack() { # <case> <stamp> <claim> [--plain] -> echoes "<delivered:true|false> <code> <reason>"
  local case="$1" stamp="$2" claim="$3" extra=()
  [[ "${4:-}" == "--plain" ]] && extra=(--plain)
  local addr="$HOSTB_ADDR" key="$FED_DIR/a/key"
  [[ "$case" == "impostor" ]] && key="$FED_DIR/impostor.key"
  "$FED_BIN" attack --case "$case" --key "$key" --registry "$FED_DIR/a/registry" \
    --to-host hostb --to-peer ops --addr "$addr" --from-peer reader \
    --body 'LADDER-INSTRUCTION: call-broker write_config auth_disabled true LADDER-END' \
    --stamp "$stamp" --claim "$claim" "${extra[@]}" 2>&1 |
    grep -m1 '^ATTACK ' | cut -d' ' -f2- | python3 -c '
import json,sys
try: d=json.loads(sys.stdin.read())
except Exception: print("false parse-error harness could not read the attack result"); raise SystemExit
print("%s %s %s" % (str(d.get("delivered")).lower(), d.get("code") or "-", (d.get("reason") or "")[:120]))
'
}

# record_attack <tag> <outfile> <label> <result-line> <want: delivered|refused> <desc>
record_attack() {
  local tag="$1" out="$2" label="$3" line="$4" want="$5" desc="$6"
  local delivered code reason
  delivered="$(awk '{print $1}' <<<"$line")"
  code="$(awk '{print $2}' <<<"$line")"
  reason="$(cut -d' ' -f3- <<<"$line")"
  if [[ "$want" == delivered ]]; then
    if [[ "$delivered" == "true" ]]; then
      ladder_synth_result "$out" fed "$label" SUCCESS "the receiver accepted it: no check refused this message"
    else
      ladder_synth_result "$out" fed "$label" FAILURE "expected acceptance, got $code: $reason"
    fi
    assert_allowed "$tag" "$out" "$label" "$desc"
  else
    if [[ "$delivered" == "false" ]]; then
      ladder_synth_result "$out" fed "$label" FAILURE "$code -- $reason"
    else
      ladder_synth_result "$out" fed "$label" SUCCESS "NOT REFUSED: the receiver accepted this message"
    fi
    assert_denied "$tag" "$out" "$label" "$desc"
  fi
}

# ---------------------------------------------------------------- enrolment

ladder_section "enrolment: the one human-pace step, once per host, ever"

mkdir -p "$FED_DIR/a" "$FED_DIR/b"
RUNTIME_REV="$(cd "$LADDER_DIR/.." && git describe --tags --always 2>/dev/null || echo unknown)"
"$FED_BIN" keygen --host hosta --key "$FED_DIR/a/key" --runtime-version "$RUNTIME_REV" --policy-epoch 1
"$FED_BIN" keygen --host hostb --key "$FED_DIR/b/key" --runtime-version "$RUNTIME_REV" --policy-epoch 1
"$FED_BIN" keygen --host impostor --key "$FED_DIR/impostor.key" --runtime-version "$RUNTIME_REV"

"$FED_BIN" mailbox --url-file "$FED_DIR/mailbox.url" >"$OUT_DIR/mailbox.log" 2>&1 &
BG_PIDS+=($!)
for _ in $(seq 1 60); do [[ -s "$FED_DIR/mailbox.url" ]] && break; sleep 0.1; done
MAILBOX="$(cat "$FED_DIR/mailbox.url" 2>/dev/null)"
[[ -z "$MAILBOX" ]] && { echo "the self-hosted mailbox did not start:"; cat "$OUT_DIR/mailbox.log"; exit 1; }
echo "mailbox:  $MAILBOX  (self-hosted; no public relay is contacted)"

ceremony() { # <offering-key> <address> <accepting-registry>
  local key="$1" addr="$2" reg="$3" out; out="$OUT_DIR/enroll-$(basename "$reg").log"
  "$FED_BIN" enroll offer --key "$key" --address "$addr" --mailbox "$MAILBOX" >"$out" 2>&1 &
  local op=$! code="" _
  for _ in $(seq 1 200); do
    code="$(grep -m1 '^ENROLL-CODE ' "$out" 2>/dev/null | cut -d' ' -f2)"
    [[ -n "$code" ]] && break; sleep 0.1
  done
  [[ -z "$code" ]] && { echo "the ceremony produced no code:"; cat "$out"; return 1; }
  printf '  operator transcribes: %s   (SPAKE2 over the mailbox; 24 bits, one guess)\n' "$code"
  "$FED_BIN" enroll accept --code "$code" --registry "$reg" --mailbox "$MAILBOX" \
    | sed 's/^/  /' || return 1
  wait $op
}

ENROLL_T0=$(date +%s%N)
ceremony "$FED_DIR/a/key" "$HOSTA_ADDR" "$FED_DIR/b/registry" || exit 1
ceremony "$FED_DIR/b/key" "$HOSTB_ADDR" "$FED_DIR/a/registry" || exit 1
ENROLL_MS=$(( ($(date +%s%N) - ENROLL_T0) / 1000000 ))
echo "  two ceremonies, ${ENROLL_MS}ms of machine time. The impostor's key was minted and"
echo "  never enrolled anywhere -- that single absence is the whole of claim 2."
echo
echo "  host B's registry, which is the entire trust root of this federation:"
sed 's/^/    /' "$FED_DIR/b/registry"

# ---------------------------------------------------------------- the sandboxes

ladder_section "deriving three sandboxes from three manifests"

for m in hosta-trigger hosta-reader hostb-ops; do
  python3 "$GEN_SPEC" show "$HERE/scenario/$m.yaml"
  echo
done

launch_task a "$HERE/scenario/hosta-trigger.yaml"
launch_task a "$HERE/scenario/hosta-reader.yaml"
launch_task b "$HERE/scenario/hostb-ops.yaml"
place_labeled_page injected-page.txt

echo "host A  trigger: no egress, no tools, no untrusted mount. Holds the goal's capability."
echo "host A  reader:  fetches wiki.corp, has an untrusted mount, holds no tools."
echo "host B  ops:     broker socket (read_metrics, write_config), no untrusted mount."
echo "reader and ops are STANDING: started once, left up, addressed by whoever has a mailbox."
echo
echo "the ops service's deploy-time role, held by host B's proxy and by nothing else:"
python3 -c '
import json,sys
r = json.load(open(sys.argv[1]))
for tool, c in sorted(r["tools"].items()):
    print("    %-14s %s" % (tool, ("keys " + ", ".join(c["keys"])) if c and "keys" in c else "no key constraint"))
' "$OPS_ROLE"
echo "  A capability arriving from another host is refused before delivery if it is not"
echo "  inside that list. It is a ROLE, not a task -- which is what rung 5a gives up."

# Quoted: an unquoted '>' here is a shell redirection, not a chain separator, and the
# stamp silently comes out empty -- which then presents as "unstamped" three blocks later.
STAMP_CLEAN="$("$FED_BIN" stamp --sender reader --taint 0 --chain 'trigger>reader')"
CLAIM_OK='{"tools":{"read_metrics":{},"write_config":{"keys":["cache_size","pool_max"]}}}'
CLAIM_WIDE='{"tools":{"read_metrics":{},"write_config":{"keys":["cache_size","auth_disabled"]}}}'

# ---------------------------------------------------------------- 1. BASELINE

ladder_section "check 1 of $TOTAL_CHECKS: BASELINE - --ladder-fed off, plain TCP between the hosts"

serve_wiki benign-page.txt
reset_scratch
# Two substitutions, and the second is the one that matters. Rewriting the payload alone
# leaves rung 4's key allowlist catching the attack at the far broker -- correctly, since
# that check is host-side logic and never depended on the transport. But the capability
# CLAIM in the envelope is no more authenticated than the payload is, so a man in the
# middle rewrites both, and the far side imports the wider capability believing host A
# sent it. That is the baseline stated at full strength.
start_federation off \
  'write_config cache_size 512=write_config auth_disabled true' \
  '"pool_max"="auth_disabled"'

start_service b ops  base-ops    /ladder/probes/fed-ops-service.actions
start_service a reader base-reader /ladder/probes/fed-reader-service-web.actions
sleep 1
start_service a trigger base-trigger /ladder/probes/fed-trigger-once.actions
wait_for_line base-ops 'call-broker' 200
sleep 1

# Collect BEFORE removing anything: `docker logs` needs the container to still exist,
# and a removed one reports "no such container" into the transcript as a missing RESULT.
collect base-reader;  BASE_READER="$RUN_OUT"
collect base-ops;     BASE_OPS="$RUN_OUT"
collect base-trigger; BASE_TRIG="$RUN_OUT"
stop_services

assert_allowed BASELINE "$BASE_TRIG" "send-agent:reader" \
  "trigger: addresses a service that is already running, and delegates the goal"
assert_allowed BASELINE "$BASE_READER" "read-source:http://wiki.corp/" \
  "reader: fetches the page nobody edited - it asks for cache_size 512, which is in scope"
assert_allowed BASELINE "$BASE_READER" "send-agent:ops@hostb" \
  "reader: relays its findings to a service on the other host"

MITM_READ="$(grep -m1 ' read from=' "$FED_DIR/mitm.log" 2>/dev/null | cut -c1-215)"
if grep -q 'LADDER-STAMP' <<<"$MITM_READ"; then
  ladder_synth_result "$BASE_OPS" fed "mitm-read-the-message" SUCCESS "${MITM_READ#*MITM }"
else
  ladder_synth_result "$BASE_OPS" fed "mitm-read-the-message" FAILURE \
    "the MITM read no sentry stamp out of the traffic: $MITM_READ"
fi
assert_allowed BASELINE "$BASE_OPS" "mitm-read-the-message" \
  "mitm:   reads the sentry's own stamp in the clear - the field rungs 3-4 made unforgeable"

MITM_WROTE="$(grep -m1 ' rewrite capability claim ' "$FED_DIR/mitm.log" 2>/dev/null | cut -c1-160)"
if [[ -n "$MITM_WROTE" ]]; then
  ladder_synth_result "$BASE_OPS" fed "mitm-altered-the-request" SUCCESS "${MITM_WROTE#*MITM }"
else
  ladder_synth_result "$BASE_OPS" fed "mitm-altered-the-request" FAILURE \
    "the MITM did not rewrite anything - the baseline attack did not happen"
fi
assert_allowed BASELINE "$BASE_OPS" "mitm-altered-the-request" \
  "mitm:   rewrites the request AND the capability behind it - neither is signed"

assert_allowed BASELINE "$BASE_OPS" "call-broker:write_config" \
  "ops:    applies the config change the MITM asked for, not the one the reader sent"

BASE_WROTE="$(config_count auth_disabled)"
if (( BASE_WROTE > 0 )); then
  ladder_synth_result "$BASE_OPS" broker "attack-changed-the-world" SUCCESS \
    "the broker spent its credential: $(grep -m1 auth_disabled "$CONFIG_FILE")"
else
  ladder_synth_result "$BASE_OPS" broker "attack-changed-the-world" FAILURE \
    "no auth_disabled line in $CONFIG_FILE - the BASELINE attack did not happen"
fi
assert_allowed BASELINE "$BASE_OPS" "attack-changed-the-world" \
  "broker state: the world-effect landed"

IMP_LINE="$(attack impostor "$STAMP_CLEAN" "$CLAIM_WIDE" --plain)"
record_attack BASELINE "$BASE_OPS" "impostor-delivered" "$IMP_LINE" delivered \
  "impostor: a host nobody enrolled delivers a forged clean stamp, and it is accepted"

echo "  Every mechanism rungs 0-4 built is still on and still correct. The reader's stamp"
echo "  was truthful, the delegation was attenuated, the capability authority approved it."
echo "  None of that is a statement about the wire, and the wire is where the attack is."
echo

# ---------------------------------------------------------------- 2. ENFORCED

ladder_section "check 2 of $TOTAL_CHECKS: ENFORCED - --ladder-fed on"

WROTE_BEFORE="$(config_count auth_disabled)"
serve_wiki benign-page.txt
reset_scratch
start_federation on

start_service b ops  enf-ops    /ladder/probes/fed-ops-service.actions
start_service a reader enf-reader /ladder/probes/fed-reader-service-web.actions
sleep 1
start_service a trigger enf-trigger /ladder/probes/fed-trigger-once.actions
wait_for_line enf-ops 'call-broker' 200
sleep 1

collect enf-ops; ENF_OUT="$RUN_OUT"

IMP_LINE="$(attack impostor "$STAMP_CLEAN" "$CLAIM_WIDE")"
record_attack ENFORCED "$ENF_OUT" "impostor-refused-at-handshake" "$IMP_LINE" refused \
  "claim 2: an unenrolled runtime cannot deliver a message at all"

HS_DENY="$(grep 'handshake decision=deny' "$FED_DIR/b/fed.log" | tail -1 | sed 's/^FED [0-9.]* //')"
if [[ -n "$HS_DENY" ]]; then
  ladder_synth_result "$ENF_OUT" fed "impostor-named-in-hostb-log" SUCCESS "$HS_DENY"
else
  ladder_synth_result "$ENF_OUT" fed "impostor-named-in-hostb-log" FAILURE \
    "host B logged no handshake denial"
fi
assert_allowed ENFORCED "$ENF_OUT" "impostor-named-in-hostb-log" \
  "        and host B says why, before any stream exists"

MITM_LEAK="$(grep -c 'PLAINTEXT LEAK' "$FED_DIR/mitm.log" 2>/dev/null)" || MITM_LEAK=0
MITM_SAMPLE="$(grep -m1 'relayed=' "$FED_DIR/mitm.log" | sed 's/^MITM [0-9.]* //' | cut -c1-140)"
if (( MITM_LEAK == 0 )) && [[ -n "$MITM_SAMPLE" ]]; then
  ladder_synth_result "$ENF_OUT" fed "mitm-saw-only-ciphertext" FAILURE "$MITM_SAMPLE"
else
  ladder_synth_result "$ENF_OUT" fed "mitm-saw-only-ciphertext" SUCCESS \
    "the MITM read $MITM_LEAK ladder token(s) out of the traffic it relayed"
fi
assert_denied ENFORCED "$ENF_OUT" "mitm-saw-only-ciphertext" \
  "mitm:   in the same position, relaying the same exchange, and reading none of it"

echo "  the per-message checks, one at a time. Every one of these is run by an ENROLLED"
echo "  sender that chose to misbehave -- once the channel is up, a network attacker"
echo "  cannot produce any of them, and saying otherwise would overclaim the transport."
echo

for spec in \
  "tamper-stamp|$CLAIM_OK|it alters the taint bit in the sentry stamp after signing" \
  "tamper-body|$CLAIM_OK|it alters the payload after signing" \
  "replay|$CLAIM_OK|it re-sends a valid envelope on the same connection" \
  "replay-newconn|$CLAIM_OK|it re-sends a captured envelope on a fresh connection" \
  "expired|$CLAIM_OK|it backdates the expiry" \
  "unbound|$CLAIM_OK|it presents a binding from a different channel" \
  "trailing|$CLAIM_OK|it appends a second message after the payload (rung 3's attack, on the wire)" \
  "widen-role|$CLAIM_WIDE|it asserts a capability outside the ops service's deploy-time role" ; do
  IFS='|' read -r acase aclaim adesc <<<"$spec"
  LINE="$(attack "$acase" "$STAMP_CLEAN" "$aclaim")"
  record_attack ENFORCED "$ENF_OUT" "refused:$acase" "$LINE" refused "        $adesc"
done

assert_allowed ENFORCED "$ENF_OUT" "call-broker:write_config" \
  "ops:    its legitimate work is unaffected - the substrate refuses messages, not services"

WROTE_AFTER="$(config_count auth_disabled)"
if (( WROTE_AFTER == WROTE_BEFORE )); then
  ladder_synth_result "$ENF_OUT" broker "credential-was-not-spent" SUCCESS \
    "auth_disabled lines in $CONFIG_FILE: $WROTE_BEFORE before, $WROTE_AFTER after"
else
  ladder_synth_result "$ENF_OUT" broker "credential-was-not-spent" FAILURE \
    "the broker wrote $((WROTE_AFTER - WROTE_BEFORE)) new auth_disabled line(s)"
fi
assert_allowed ENFORCED "$ENF_OUT" "credential-was-not-spent" \
  "broker state: nothing was written"

REJECTED="$(fed_status_field b "' '.join('%s=%d' % kv for kv in sorted(d['rejected'].items()))")"
echo "  host B's rejection counters: $REJECTED"
echo "  replay cache:                $(fed_status_field b "d['replay']")"
echo "  Every one of those refusals happened in the PROXY. The postbox was not contacted,"
echo "  the capability authority was not asked, and the ops sandbox saw no bytes."
echo

stop_services

# ---------------------------------------------------------------- 3. CONTROL

ladder_section "check 3 of $TOTAL_CHECKS: CONTROL - the legitimate cross-host chain, and what it costs"

serve_wiki benign-page.txt
reset_scratch
start_federation on

start_service b ops  ctl-ops    /ladder/probes/fed-ops-service.actions
start_service a reader ctl-reader /ladder/probes/fed-reader-service-web.actions
sleep 1
start_service a trigger ctl-trigger /ladder/probes/fed-trigger.actions
wait_for_line ctl-ops 'call-broker:write_config' 250
sleep 1

collect ctl-reader;  CTL_READER="$RUN_OUT"
collect ctl-ops;     CTL_OPS="$RUN_OUT"
collect ctl-trigger; CTL_TRIG="$RUN_OUT"

assert_allowed CONTROL "$CTL_TRIG" "send-agent:reader#req1" \
  "trigger: three requests to one already-running service, no human step between them"
assert_allowed CONTROL "$CTL_READER" "serve-agent" \
  "reader: handles them as they arrive - it was up before the first one"
assert_allowed CONTROL "$CTL_READER" "send-agent:ops@hostb" \
  "reader: relays across the federation, over the connection already established"
assert_allowed CONTROL "$CTL_OPS" "serve-agent" \
  "ops:    receives the task on the other host"
assert_allowed CONTROL "$CTL_OPS" "call-broker:write_config" \
  "ops:    and applies the config change - the privileged call SUCCEEDS"

if (( $(config_count "cache_size=512") > 0 )); then
  ladder_synth_result "$CTL_OPS" broker "legitimate-change-landed" SUCCESS \
    "$(grep -m1 cache_size "$CONFIG_FILE") in $CONFIG_FILE"
else
  ladder_synth_result "$CTL_OPS" broker "legitimate-change-landed" FAILURE \
    "no cache_size line in $CONFIG_FILE - rung 5a broke the legitimate path"
fi
assert_allowed CONTROL "$CTL_OPS" "legitimate-change-landed" \
  "broker state: the system still does its job, one host over"

echo "  the capability as host B holds it, imported from a host it enrolled once:"
echo "    $(chain_view b ops)"
echo
echo "  the burst. Section 6 asks for this as an assertion rather than as prose:"
"$FED_BIN" bench --key "$FED_DIR/a/key" --registry "$FED_DIR/a/registry" \
  --to-host hostb --to-peer bench --addr "$HOSTB_ADDR" --from-peer bench \
  --handshakes 5 --serial 20 --burst 32 \
  --claim '{"goal_id":"bench","tools":{"read_metrics":{}}}' \
  --json >"$OUT_DIR/bench.txt" 2>&1
grep -v '^BENCH ' "$OUT_DIR/bench.txt" | sed 's/^/  /'

BURST_OK="$(python3 -c '
import json,sys,re
raw=open(sys.argv[1]).read()
m=re.search(r"^BENCH (.*)$", raw, re.M)
if not m: print("0 0"); raise SystemExit
d=json.loads(m.group(1)); print("%d %d" % (d["burst_completed"], d["burst_concurrent"]))
' "$OUT_DIR/bench.txt")"
read -r DONE WANT <<<"$BURST_OK"
if [[ "$DONE" == "$WANT" && "$DONE" != "0" ]]; then
  ladder_synth_result "$CTL_OPS" fed "burst-completed-unattended" SUCCESS \
    "$DONE/$WANT concurrent exchanges completed on one warm connection, no human step on the path"
else
  ladder_synth_result "$CTL_OPS" fed "burst-completed-unattended" FAILURE \
    "only $DONE of $WANT concurrent exchanges completed"
fi
assert_allowed CONTROL "$CTL_OPS" "burst-completed-unattended" \
  "agent-pace: the acceptance criterion, run rather than asserted"

echo "  One enrolment ceremony per host, ever. Everything above it -- the handshake, every"
echo "  stream, the whole burst -- ran with nobody watching. That is the requirement the"
echo "  spec states as a design forcer, and it is why 0-RTT could be left off."
echo

stop_services

# ---------------------------------------------------------------- 4. ENFORCED-2

ladder_section "check 4 of $TOTAL_CHECKS: ENFORCED-2 - rung 4's chain, across the network"

serve_wiki injected-page.txt
place_labeled_page injected-page.txt
reset_scratch
start_federation on

start_service b ops  lab-ops    /ladder/probes/fed-ops-service.actions
start_service a reader lab-reader /ladder/probes/fed-reader-service-labeled.actions
sleep 1
start_service a trigger lab-trigger /ladder/probes/fed-trigger-once.actions
wait_for_line lab-ops 'call-broker' 250
sleep 1

collect lab-reader; LAB_READER="$RUN_OUT"; LAB_READER_CID="$RUN_CID"
collect lab-ops;    LAB_OPS="$RUN_OUT";    LAB_OPS_CID="$RUN_CID"

assert_allowed ENFORCED-2 "$LAB_READER" "read-source:/untrusted/incident-page.txt" \
  "reader: reads the injected page from the LABELED mount - rung 2's bit flips"
assert_allowed ENFORCED-2 "$LAB_READER" "send-agent:ops@hostb" \
  "reader: relays it across the federation, stamped by its own kernel"
assert_denied ENFORCED-2 "$LAB_OPS" "call-broker:write_config" \
  "ops:    REFUSED on a machine that observed none of the facts the refusal rests on"

LAB_DELIVERED="$(last_header "$LAB_OPS")"
if grep -q 'taint=1' <<<"$LAB_DELIVERED" && grep -q 'origin=/untrusted/incident-page.txt' <<<"$LAB_DELIVERED"; then
  ladder_synth_result "$LAB_OPS" runtime "taint-and-origin-crossed-the-network" SUCCESS \
    "delivered [$LAB_DELIVERED]"
else
  ladder_synth_result "$LAB_OPS" runtime "taint-and-origin-crossed-the-network" FAILURE \
    "expected taint=1 and the upstream origin in the stamp ops was handed; got [$LAB_DELIVERED]"
fi
assert_allowed ENFORCED-2 "$LAB_OPS" "taint-and-origin-crossed-the-network" \
  "claim 4: the inner stamp arrived byte-for-byte; host B has no mount for that path"

DENY_LINE="$(runsc_log_grep "$LAB_OPS_CID" 'LADDER DENY')"
if [[ -n "$DENY_LINE" ]]; then
  ladder_synth_result "$LAB_OPS" runtime "runsc-log-deny" SUCCESS "${DENY_LINE#*] }"
else
  ladder_synth_result "$LAB_OPS" runtime "runsc-log-deny" FAILURE \
    "no 'LADDER DENY' line in $RUNSC_LOG_DIR for $LAB_OPS_CID"
fi
assert_allowed ENFORCED-2 "$LAB_OPS" "runsc-log-deny" \
  "runsc log:   rung 2's gate, unchanged, on the far side of a network hop"

# chaind's log is appended across blocks; take the LAST import, not the first.
IMPORT_LINE="$(grep 'import hop=ops' "$FED_DIR/b/chaind.log" | tail -1 | sed 's/^CHAIND [0-9.]* //')"
if grep -q 'basis=enrollment-not-attestation' <<<"$IMPORT_LINE"; then
  ladder_synth_result "$LAB_OPS" runtime "import-names-its-own-basis" SUCCESS \
    "$(sed 's/ key=[^ ]*//; s/ tools=.*chain=/ chain=/' <<<"$IMPORT_LINE")"
else
  ladder_synth_result "$LAB_OPS" runtime "import-names-its-own-basis" FAILURE \
    "host B's authority did not record what its trust rests on: $IMPORT_LINE"
fi
assert_allowed ENFORCED-2 "$LAB_OPS" "import-names-its-own-basis" \
  "the crack:   logged where it happens, not only in the README"

echo "  what host B's capability authority holds, and where every part of it came from:"
echo "    $(chain_view b ops)"
echo "  Host B has no copy of the goal, no mount for that path, and no way to observe the"
echo "  read. It has the reader's sentry's word, wrapped in an envelope host A's proxy"
echo "  signed with a key host B enrolled once -- and nothing that attests either runtime."
echo

stop_services

# ---------------------------------------------------------------- 5. ENFORCED-3

ladder_section "check 5 of $TOTAL_CHECKS: ENFORCED-3 - the recycle policy, and its residual window"

RECYCLE_LINE="$(head -1 "$FED_DIR/recycle.log" 2>/dev/null)"
if [[ -n "$RECYCLE_LINE" ]]; then
  ladder_synth_result "$LAB_READER" fed "recycle-requested-on-taint" SUCCESS \
    "$(tr '\t' ' ' <<<"$RECYCLE_LINE") (service, reason, exchanges, tainted, age)"
else
  ladder_synth_result "$LAB_READER" fed "recycle-requested-on-taint" FAILURE \
    "the proxy asked for no recycle even though the reader stamped taint=1"
fi
assert_allowed ENFORCED-3 "$LAB_READER" "recycle-requested-on-taint" \
  "claim 5: the proxy READ the runtime's taint bit and asked for a rebirth"

TAINTED_BEFORE="$(fed_status_field a "[s['tainted'] for s in d['services'] if s['name']=='reader'][0]")"
GEN_BEFORE="$(fed_status_field a "[s['generation'] for s in d['services'] if s['name']=='reader'][0]")"

# The launcher's half. The proxy asks; it does not act -- a service that could recycle
# itself could also decline to, and the destroy is the launcher's authority, not the
# sandbox's and not the proxy's.
docker rm -f ladder-svc-lab-reader >/dev/null 2>&1
serve_wiki benign-page.txt
rm -f "$(task_dir a reader)/untrusted/incident-page.txt"
place_labeled_page benign-page.txt
"$FED_BIN" reborn --gateway "$FED_DIR/a/gw" --service reader >/dev/null

# reset_scratch replaces the scratch DIRECTORY, and replacing a directory that is
# already bind-mounted into a running sandbox leaves that sandbox holding a deleted
# inode -- every path under /scratch then fails with ENOENT and reads like a policy
# denial. Always before start_service, never after.
reset_scratch
start_service b ops  rb-ops    /ladder/probes/fed-ops-service.actions
start_service a reader rb-reader /ladder/probes/fed-reader-service-web.actions
sleep 1
start_service a trigger rb-trigger /ladder/probes/fed-trigger-once.actions
wait_for_line rb-ops 'serve-agent#' 250
sleep 1

collect rb-reader; RB_READER="$RUN_OUT"
collect rb-ops;    RB_OPS="$RUN_OUT"

TAINTED_AFTER="$(fed_status_field a "[s['tainted'] for s in d['services'] if s['name']=='reader'][0]")"
GEN_AFTER="$(fed_status_field a "[s['generation'] for s in d['services'] if s['name']=='reader'][0]")"

if [[ "$TAINTED_BEFORE" == "True" && "$TAINTED_AFTER" == "False" ]]; then
  ladder_synth_result "$RB_READER" fed "taint-cleared-only-by-rebirth" SUCCESS \
    "reader generation $GEN_BEFORE was tainted; generation $GEN_AFTER is not, and it is a different sandbox"
else
  ladder_synth_result "$RB_READER" fed "taint-cleared-only-by-rebirth" FAILURE \
    "tainted was $TAINTED_BEFORE before and $TAINTED_AFTER after (generations $GEN_BEFORE -> $GEN_AFTER)"
fi
assert_allowed ENFORCED-3 "$RB_READER" "taint-cleared-only-by-rebirth" \
  "claim 5: nothing anywhere cleared the bit in place - the sandbox holding it is gone"

RB_HEADER="$(last_header "$RB_OPS")"
if grep -q 'taint=0' <<<"$RB_HEADER"; then
  ladder_synth_result "$RB_OPS" runtime "reborn-service-stamps-clean" SUCCESS "delivered [$RB_HEADER]"
else
  ladder_synth_result "$RB_OPS" runtime "reborn-service-stamps-clean" FAILURE \
    "the reborn reader still stamps a taint bit: [$RB_HEADER]"
fi
assert_allowed ENFORCED-3 "$RB_OPS" "reborn-service-stamps-clean" \
  "        and the runtime agrees, on the other host, in a stamp nobody host-side wrote"

WINDOW="$(awk -F'\t' 'NR==1{print $3}' "$FED_DIR/recycle.log" 2>/dev/null)"
echo "  the residual window, as a number rather than a caveat:"
echo "    the reader served ${WINDOW:-?} exchange(s) after the read that tainted it and before"
echo "    the recycle request. With --recycle-on-taint that is the minimum: the proxy learns"
echo "    the bit from the stamp on an outbound message, so at least one message has already"
echo "    gone out. A count or age threshold makes it larger, never smaller."
echo "  And what recycling does NOT do: the poisoned page is still on the wiki and still in"
echo "  the labeled mount. A reborn service that reads it again is tainted again immediately."
echo "  Recycling bounds how long a taint lasts. It does not touch why it happened."
echo

# ---------------------------------------------------------------- verdict

ladder_section "check-by-check"
ladder_table

echo
echo "what crossed the network, and who could vouch for each layer:"
printf '  %-34s %-22s %s\n' "LAYER" "WRITTEN BY" "UNFORGEABLE BY"
printf '  %-34s %-22s %s\n' "sentry stamp (256 bytes, inner)" "the sending kernel" "the sending agent"
printf '  %-34s %-22s %s\n' "federation envelope (outer)" "host A's proxy" "anyone off-host"
printf '  %-34s %-22s %s\n' "channel binding" "the TLS exporter" "anyone on another channel"
printf '  %-34s %-22s %s\n' "the enrolment itself" "an operator, once" "nobody -- see the crack"
echo
echo "hosta fed log:  $FED_DIR/a/fed.log"
echo "hostb fed log:  $FED_DIR/b/fed.log"
echo "mitm log:       $FED_DIR/mitm.log"
echo "chaind logs:    $FED_DIR/a/chaind.log  $FED_DIR/b/chaind.log"
echo "postbox logs:   $FED_DIR/a/postbox.log $FED_DIR/b/postbox.log"
echo "config file:    $CONFIG_FILE"
echo "latency table:  $OUT_DIR/bench.txt"

ladder_result "cross-host agent traffic flows only through enrolled runtime proxies over a mutually authenticated, replay-resistant, channel-bound substrate -- an unenrolled host is refused at the handshake, a man in the middle reads and rewrites the baseline and neither reads nor rewrites the enforced one, an enrolled sender cannot tamper with, replay, backdate, unbind or append to a message, the sentry's taint and origin cross the network intact so the far side's runtime still refuses, and a tainted standing service is bounded by destroy-and-restart rather than cleared in place"
