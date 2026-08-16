#!/usr/bin/env bash
# rung 1 demo - role is not task.
#
# Four blocks. The first three are the conventions-section-3 contract:
#   BASELINE   - one role-scoped sandbox does task A's work AND task B's work. Both
#                succeed. That is rung 0 working as claimed, and it is the problem.
#   ENFORCED   - task A's sandbox, derived from task A's manifest, is asked to do task
#                B's work. Both halves blocked, at the network and at the broker, and a
#                file task A left in scratch is not there in task B's sandbox.
#   CONTROL    - each task does its OWN work and succeeds. Scoping, not blanket denial.
# The fourth is claim 4:
#   ENFORCED-2 - inside ONE running sandbox, a grant is narrowed and takes effect on
#                the next syscall, and an attempt to widen it back is refused.
#
# ENFORCED-2b, when enabled, runs BEFORE ENFORCED-2 rather than after it. Narrowing is
# irreversible by construction, so once ENFORCED-2 has taken metrics.local away from
# task A's proxy, nothing can hand it back for a later block to take away again.
#
# ROOT IS NOT REQUIRED for any of the above. Membership in the docker group is, plus a
# 'runsc' runtime registered with the docker daemon.
#
# Offline: no internet access, no API keys, no cloud account. Every host the agent can
# see is a local container.
#
# ENFORCED-2 has a second half, off by default. The narrowing above is enforced by the
# proxy, outside the sandbox; --with-runtime-patch repeats it at the netstack layer
# INSIDE runsc, through a control call only the host can make. That half needs a runsc
# built from this tree, a docker runtime registered with --ladder-task-scope, and root
# (docker's runsc state directory is root-owned). See README, "Mechanism".
#
# Usage:
#   ./demo.sh                       the four blocks above, stock runsc, no root
#   ./demo.sh --with-runtime-patch  adds ENFORCED-2b; needs the ladder-scope runtime
#   ./demo.sh --keep                leave the world running for poking at

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LADDER_DIR="$(cd "$HERE/.." && pwd)"
COMMON="$LADDER_DIR/common"
# shellcheck source=../common/lib.sh
source "$COMMON/lib.sh"

KEEP=0
WITH_PATCH=0
PATCH_RUNTIME="ladder-scope"
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --with-runtime-patch) WITH_PATCH=1 ;;
    -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# The world. Fixed addresses so the manifests can name hosts and a reader can follow
# the wiring without running anything.
WORLD_NET="ladder-world"
WORLD_SUBNET="169.254.0.0/16"
WIKI_IP="169.254.0.10"
EVIL_IP="169.254.0.20"
METRICS_IP="169.254.0.30"
METRICS_PORT="9101"
# Each task gets its own /24 out of 10.78.0.0/16, assigned in launch order. This is
# wiring, not policy: nothing in a manifest picks an address.
TASK_SUBNET_PREFIX="10.78"

# ENFORCED-2b only exists with --with-runtime-patch, so the check count is not fixed.
TOTAL_CHECKS=4
ENF2_NUM=4
if (( WITH_PATCH )); then TOTAL_CHECKS=5; ENF2_NUM=5; fi

LADDER_RUNTIME_DIR="$(ladder_runtime_dir)"
export LADDER_DIR LADDER_RUNTIME_DIR
TASKS_DIR="$LADDER_RUNTIME_DIR/tasks"
OUT_DIR="$LADDER_RUNTIME_DIR/out"
BROKER_LOG="$LADDER_RUNTIME_DIR/broker.log"
BROKER_PIDS=()
TASK_COUNT=0

# Stock runsc unless a block overrides it. Referenced as ${LADDER_TASK_RUNTIME} by the
# generated agent.args, so switching runtimes never means regenerating a spec.
export LADDER_TASK_RUNTIME="runsc"

cleanup() {
  local pid
  for pid in "${BROKER_PIDS[@]:-}"; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null; done
  if (( KEEP )); then
    echo "--keep: leaving containers, networks and $TASKS_DIR in place"
    return
  fi
  cleanup_sandboxes
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- preflight

ladder_require_docker || exit 1
ladder_require_runsc_runtime || exit 1
ladder_require python3 || exit 1
if (( WITH_PATCH )); then
  docker info --format '{{json .Runtimes}}' | grep -q "\"$PATCH_RUNTIME\"" || {
    echo "--with-runtime-patch needs a docker runtime named '$PATCH_RUNTIME' registered with" >&2
    echo "--ladder-task-scope. See rung1/README.md, 'Demo'." >&2; exit 1; }
  # runsc keeps a container's state under a root-owned directory, so the control call
  # is reachable only by root on the host. That is the property, not an inconvenience.
  sudo -n true 2>/dev/null || {
    echo "--with-runtime-patch needs a live sudo credential (docker's runsc state dir is" >&2
    echo "root-owned). Run 'sudo -v' in this terminal first, then re-run." >&2; exit 1; }
fi

ladder_init
cleanup_sandboxes
rm -rf "$TASKS_DIR" "$OUT_DIR"
mkdir -p "$TASKS_DIR" "$OUT_DIR"
chmod 0755 "$LADDER_RUNTIME_DIR" "$TASKS_DIR"

echo "rung 1 demo"
echo "  gVisor:        $(runsc --version 2>/dev/null | head -1)"
echo "  kernel:        $(uname -sr)"
echo "  task runtime:  $LADDER_TASK_RUNTIME"
echo "  runtime dir:   $LADDER_RUNTIME_DIR"

# ---------------------------------------------------------------- build + world

ladder_section "building images and starting the world (all local, no network)"

docker build -q -t ladder/agent-enforced:rung1 \
  -f "$COMMON/images/Dockerfile.agent-enforced" "$COMMON" >/dev/null || exit 1
docker build -q -t ladder/world:rung1 \
  -f "$COMMON/images/Dockerfile.world" "$COMMON" >/dev/null || exit 1
echo "images built: ladder/agent-enforced:rung1, ladder/world:rung1"

docker network create --internal --label ladder=1 --subnet "$WORLD_SUBNET" "$WORLD_NET" >/dev/null || exit 1

world_service() { # <name> <ip> <body> [port]
  local port_args=()
  [[ -n "${4:-}" ]] && port_args=(--port "$4")
  docker run -d --label ladder=1 --name "$1" --network "$WORLD_NET" --ip "$2" \
    ladder/world:rung1 /ladder/service.py --name "${1#ladder-}" --body "$3" "${port_args[@]}" >/dev/null
}
world_service ladder-wiki    "$WIKI_IP"    "deploys-happen-on-fridays"
world_service ladder-evil    "$EVIL_IP"    "EXFIL-SINK-RECEIVED-YOUR-DATA"
world_service ladder-metrics "$METRICS_IP" "cpu=12-mem=41-for-svcX" "$METRICS_PORT"
echo "world up: wiki.corp=$WIKI_IP evil.example.com=$EVIL_IP metrics.local=$METRICS_IP:$METRICS_PORT"

# ---------------------------------------------------------------- the launcher
#
# Everything a task is allowed to do is established HERE, on the host, before the
# sandbox exists. The sandbox is never told its task id and never asks for a grant: it
# finds one network, one proxy and one broker socket, and those are its scope. Nothing
# it can say changes them, which is why the binding does not have to be trusted.

# Sets LAUNCHED_TASK_ID rather than echoing it: a command substitution would run this
# in a subshell, where the subnet counter would not advance and a failed docker call
# would exit the subshell instead of the demo.
launch_task() { # <manifest> -> sets LAUNCHED_TASK_ID
  local manifest="$1"
  local spec task_id net image ttl subnet proxy_ip dir
  local -a proxy_args broker_args

  task_id="$(python3 "$HERE/gen_spec.py" show "$manifest" | awk '$1=="task_id"{print $2}')"
  dir="$TASKS_DIR/$task_id"
  spec="$dir/spec"
  mkdir -p "$dir/scratch" "$dir/sock" "$dir/ctl" "$spec"
  # The agent runs as uid 65534 and the proxy as root in its own container; both must
  # reach paths created by this user.
  chmod 0777 "$dir/scratch" "$dir/ctl"
  chmod 0755 "$dir" "$dir/sock"

  python3 "$HERE/gen_spec.py" emit "$manifest" "$spec" || exit 1
  # shellcheck disable=SC1091
  source "$spec/meta.env"
  net="$LADDER_TASK_NET"; image="$LADDER_TASK_IMAGE"; ttl="$LADDER_TASK_TTL"

  subnet="$TASK_SUBNET_PREFIX.$TASK_COUNT.0/24"
  proxy_ip="$TASK_SUBNET_PREFIX.$TASK_COUNT.2"
  TASK_COUNT=$((TASK_COUNT + 1))
  # Wiring the launcher assigns, kept beside the spec rather than inside it: no
  # manifest picks an address, and the generated spec stays a function of the manifest.
  printf 'LADDER_PROXY_IP=%s\n' "$proxy_ip" >"$dir/wiring.env"

  docker network create --internal --label ladder=1 --subnet "$subnet" "$net" >/dev/null || exit 1

  # This task's proxy: its allowlist is the manifest's network_allow and nothing else.
  ladder_load_args "$spec/proxy.args"; proxy_args=("${LADDER_ARGS[@]}")
  docker run -d --label ladder=1 --name "ladder-proxy-$task_id" --network "$net" --ip "$proxy_ip" \
    --volume "$dir/ctl:/ctl" \
    --add-host "wiki.corp:$WIKI_IP" --add-host "evil.example.com:$EVIL_IP" \
    --add-host "metrics.local:$METRICS_IP" \
    ladder/world:rung1 /ladder/proxy.py "${proxy_args[@]}" >/dev/null || exit 1
  docker network connect "$WORLD_NET" "ladder-proxy-$task_id" || exit 1

  # This task's broker: its tool scope is the manifest's broker_tools and nothing else.
  ladder_load_args "$spec/broker.args"; broker_args=("${LADDER_ARGS[@]}")
  python3 "$COMMON/broker/broker.py" --socket "$dir/sock/broker.sock" "${broker_args[@]}" \
    --log "$BROKER_LOG" --state-dir "$LADDER_RUNTIME_DIR" >"$OUT_DIR/broker-$task_id.stdout" 2>&1 &
  BROKER_PIDS+=($!)
  local _
  for _ in $(seq 1 25); do [[ -S "$dir/sock/broker.sock" ]] && break; sleep 0.2; done
  [[ -S "$dir/sock/broker.sock" ]] || {
    echo "broker for $task_id failed to start:"; cat "$OUT_DIR/broker-$task_id.stdout"; exit 1; }
  for _ in $(seq 1 25); do [[ -S "$dir/ctl/proxy.sock" ]] && break; sleep 0.2; done

  LAUNCHED_TASK_ID="$task_id"
}

# Resolve the per-task runtime values the generated spec left as ${VAR}, then run.
task_env() { # <task-id>
  export LADDER_TASK_DIR="$TASKS_DIR/$1"
  # shellcheck disable=SC1091
  source "$TASKS_DIR/$1/wiring.env"
  export LADDER_PROXY_IP
}

run_in_task() { # <task-id> <out-name> <actions-file...> -> echoes the out path
  local task_id="$1" out_name="$2"; shift 2
  local dir="$TASKS_DIR/$task_id" out="$OUT_DIR/$out_name.out" actions ttl
  : >"$out"
  task_env "$task_id"
  # shellcheck disable=SC1091
  source "$dir/spec/meta.env"; ttl="$LADDER_TASK_TTL"
  ladder_load_args "$dir/spec/agent.args"
  for actions in "$@"; do
    # ttl_seconds is a real bound, not a comment: the sandbox does not outlive it.
    timeout "$ttl" docker run --rm --label ladder=1 --name "ladder-run-$task_id-$RANDOM" \
      "${LADDER_ARGS[@]}" "$LADDER_TASK_IMAGE" script "$actions" >>"$out" 2>&1
  done
  printf '%s' "$out"
}

ladder_section "deriving three sandboxes from three manifests"

python3 "$HERE/gen_spec.py" show "$HERE/manifests/task-a-read-metrics.yaml"

# Acceptance criterion: the generator is deterministic. Same manifest, same spec.
python3 "$HERE/gen_spec.py" emit "$HERE/manifests/task-a-read-metrics.yaml" "$OUT_DIR/determinism-1" || exit 1
python3 "$HERE/gen_spec.py" emit "$HERE/manifests/task-a-read-metrics.yaml" "$OUT_DIR/determinism-2" || exit 1
if diff -r "$OUT_DIR/determinism-1" "$OUT_DIR/determinism-2" >/dev/null; then
  echo
  echo "generator is deterministic: two independent emits of the same manifest are identical"
else
  echo "GENERATOR IS NOT DETERMINISTIC - two emits of one manifest differ" >&2; exit 1
fi

launch_task "$HERE/manifests/role-union.yaml";        ROLE_TASK="$LAUNCHED_TASK_ID"
launch_task "$HERE/manifests/task-a-read-metrics.yaml"; TASK_A="$LAUNCHED_TASK_ID"
launch_task "$HERE/manifests/task-b-update-config.yaml"; TASK_B="$LAUNCHED_TASK_ID"
echo "launched: $ROLE_TASK (baseline role), $TASK_A, $TASK_B"
echo "          each with its own network, its own proxy and its own broker socket"

# ---------------------------------------------------------------- 1. BASELINE

ladder_section "check 1 of $TOTAL_CHECKS: BASELINE - one role-scoped sandbox, both tasks' work"

BASE_OUT="$(run_in_task "$ROLE_TASK" baseline \
  /ladder/probes/task-a.actions /ladder/probes/task-b.actions)"

assert_allowed BASELINE "$BASE_OUT" "call-broker:read_metrics"   "task A tool:  read_metrics"
assert_allowed BASELINE "$BASE_OUT" "probe-egress:metrics.local" "task A host:  metrics.local:9101"
assert_allowed BASELINE "$BASE_OUT" "call-broker:write_config"   "task B tool:  write_config"
assert_allowed BASELINE "$BASE_OUT" "probe-egress:wiki.corp"     "task B host:  wiki.corp"

# ---------------------------------------------------------------- 2. ENFORCED

ladder_section "check 2 of $TOTAL_CHECKS: ENFORCED - task A's sandbox, asked to do task B's work"

# The same bytes that succeed in task B's sandbox, run in task A's.
CROSS_OUT="$(run_in_task "$TASK_A" enforced-cross /ladder/probes/task-b.actions)"

assert_denied ENFORCED "$CROSS_OUT" "call-broker:write_config" "task B tool:  write_config, from task A"
assert_denied ENFORCED "$CROSS_OUT" "probe-egress:wiki.corp"   "task B host:  wiki.corp, from task A"

# Task A does its own work, which leaves a file in its scratch. Asserted under CONTROL
# below; run here because the next check needs the file to exist.
CTRL_A_OUT="$(run_in_task "$TASK_A" control-task-a /ladder/probes/task-a.actions)"

# ...and a fresh task B sandbox cannot see it, though it is on the host right now.
PEEK_OUT="$(run_in_task "$TASK_B" enforced-peek /ladder/probes/peek-prior-task.actions)"
if [[ -f "$TASKS_DIR/$TASK_A/scratch/task-a-was-here" ]]; then
  ladder_synth_result "$PEEK_OUT" fs "task-a-scratch-on-host" SUCCESS \
    "the bytes exist on the host at tasks/$TASK_A/scratch/task-a-was-here"
else
  ladder_synth_result "$PEEK_OUT" fs "task-a-scratch-on-host" FAILURE \
    "task A never wrote its scratch file - the isolation check below would prove nothing"
fi
assert_allowed ENFORCED "$PEEK_OUT" "task-a-scratch-on-host"          "task A state: written, and still on the host"
assert_denied  ENFORCED "$PEEK_OUT" "read-source:/scratch/task-a-was-here" "task A state: unreachable from task B"

# ---------------------------------------------------------------- 3. CONTROL

ladder_section "check 3 of $TOTAL_CHECKS: CONTROL - each task does its own work"

CTRL_B_OUT="$(run_in_task "$TASK_B" control-task-b /ladder/probes/task-b.actions)"

assert_allowed CONTROL "$CTRL_A_OUT" "call-broker:read_metrics"   "task A tool:  read_metrics, in task A"
assert_allowed CONTROL "$CTRL_A_OUT" "probe-egress:metrics.local" "task A host:  metrics.local:9101, in task A"
assert_allowed CONTROL "$CTRL_B_OUT" "call-broker:write_config"   "task B tool:  write_config, in task B"
assert_allowed CONTROL "$CTRL_B_OUT" "probe-egress:wiki.corp"     "task B host:  wiki.corp, in task B"

# ---------------------------------------------------------------- 5. ENFORCED-2b
#
# The same claim as ENFORCED-2, moved from the proxy into the runtime. The proxy is
# still there and still allowlisting; what changes is that netstack now drops the
# packet before it leaves the sandbox, so the agent never reaches the proxy at all --
# which is why the evidence is a transport error rather than an HTTP 403.

if (( WITH_PATCH )); then
ladder_section "check 4 of $TOTAL_CHECKS: ENFORCED-2b - the same narrowing, enforced inside runsc"

ATTEN2_OUT="$OUT_DIR/attenuation-runsc.out"
: >"$ATTEN2_OUT"
rm -f "$TASKS_DIR/$TASK_A/scratch/narrowed"
CNAME="ladder-run-$TASK_A-runsc-atten"

task_env "$TASK_A"
# The only difference from ENFORCED-2 is the runtime. Same manifest, same generated
# spec, same probes -- ${LADDER_TASK_RUNTIME} is why no spec had to be regenerated.
LADDER_TASK_RUNTIME="$PATCH_RUNTIME"
ladder_load_args "$TASKS_DIR/$TASK_A/spec/agent.args"
timeout 150 docker run --rm --label ladder=1 --name "$CNAME" \
  "${LADDER_ARGS[@]}" ladder/agent-enforced:rung1 script /ladder/probes/attenuation.actions \
  >"$ATTEN2_OUT" 2>&1 &
ATTEN2_PID=$!
LADDER_TASK_RUNTIME="runsc"

for _ in $(seq 1 150); do grep -q '^RESULT network probe-egress' "$ATTEN2_OUT" && break; sleep 0.2; done

CID="$(docker inspect -f '{{.Id}}' "$CNAME" 2>/dev/null)"
# Ask the sandbox where its state lives rather than guessing: docker keeps runsc state
# under one root for every runtime it manages, not a per-runtime path, and the value is
# right there in the sandbox process's own argv.
RUNSC_ROOT="$(pgrep -af runsc-sandbox | grep -F "$CID" | grep -o -- '--root=[^ ]*' | head -1 | cut -d= -f2)"
if [[ -z "$RUNSC_ROOT" ]]; then
  for root in /var/run/docker/runtime-runc/moby "/var/run/docker/runtime-$PATCH_RUNTIME/moby"; do
    sudo -n runsc --root "$root" state "$CID" >/dev/null 2>&1 && { RUNSC_ROOT="$root"; break; }
  done
fi

narrow_runsc() { sudo -n runsc --root "$RUNSC_ROOT" ladder-narrow "$CID" "$@" 2>&1; }

if [[ -z "$RUNSC_ROOT" || -z "$CID" ]]; then
  echo "could not locate the sandbox's runsc state directory; skipping ENFORCED-2b" >&2
  kill "$ATTEN2_PID" 2>/dev/null
else
  echo "  sandbox:  $CID"
  echo "  state:    $RUNSC_ROOT (root-owned; the control path is host-only)"
  # First call establishes the scope. It is unconstrained by design -- there is nothing
  # yet to be narrower than -- and it is the last time this sandbox can gain reach.
  echo "  host -> sandbox: $(narrow_runsc "$LADDER_PROXY_IP/32")"
  # Second call narrows it to loopback, which strands the proxy.
  echo "  host -> sandbox: $(narrow_runsc 127.0.0.1/32)"
  touch "$TASKS_DIR/$TASK_A/scratch/narrowed"
  # Third call asks for the proxy back. The handler in the sandbox refuses it.
  WIDEN2_MSG="$(narrow_runsc "$LADDER_PROXY_IP/32")"; WIDEN2_RC=$?
  echo "  host -> sandbox: $WIDEN2_MSG"

  wait "$ATTEN2_PID" 2>/dev/null

  awk '/RESULT sync wait-for/{seen=1; next} !seen' "$ATTEN2_OUT" >"$OUT_DIR/atten2-before.out"
  awk '/RESULT sync wait-for/{seen=1; next} seen'  "$ATTEN2_OUT" >"$OUT_DIR/atten2-after.out"

  assert_allowed ENFORCED-2b "$OUT_DIR/atten2-before.out" "probe-egress:metrics.local" \
    "task A host:  metrics.local, before the control call"
  assert_denied ENFORCED-2b "$OUT_DIR/atten2-after.out" "probe-egress:metrics.local" \
    "netstack:     same sandbox, after - dropped before the proxy"

  if (( WIDEN2_RC != 0 )); then
    ladder_synth_result "$ATTEN2_OUT" network "runsc-widening-attempt" FAILURE "$WIDEN2_MSG"
  else
    ladder_synth_result "$ATTEN2_OUT" network "runsc-widening-attempt" SUCCESS "$WIDEN2_MSG"
  fi
  assert_denied ENFORCED-2b "$ATTEN2_OUT" "runsc-widening-attempt" \
    "monotonicity: widening, refused in the sentry"
fi
fi

# ---------------------------------------------------------------- 4. ENFORCED-2

ladder_section "check $ENF2_NUM of $TOTAL_CHECKS: ENFORCED-2 - narrowing a grant inside one running sandbox"

ATTEN_OUT="$OUT_DIR/attenuation.out"
: >"$ATTEN_OUT"
CTL_SOCK="$TASKS_DIR/$TASK_A/ctl/proxy.sock"
rm -f "$TASKS_DIR/$TASK_A/scratch/narrowed"

task_env "$TASK_A"
ladder_load_args "$TASKS_DIR/$TASK_A/spec/agent.args"
timeout 90 docker run --rm --label ladder=1 --name "ladder-run-$TASK_A-atten" \
  "${LADDER_ARGS[@]}" ladder/agent-enforced:rung1 script /ladder/probes/attenuation.actions \
  >"$ATTEN_OUT" 2>&1 &
ATTEN_PID=$!

# Wait for the first probe to land, so the narrowing is unambiguously mid-task.
for _ in $(seq 1 100); do grep -q '^RESULT network probe-egress' "$ATTEN_OUT" && break; sleep 0.2; done

# Narrow to the empty set, then release the agent. The agent is still running; nothing
# was restarted.
NARROW_MSG="$(python3 "$HERE/narrow.py" "$CTL_SOCK")"
echo "  host -> task A's proxy: $NARROW_MSG"
touch "$TASKS_DIR/$TASK_A/scratch/narrowed"

# And the widening that must not work, issued through the same channel.
WIDEN_MSG="$(python3 "$HERE/narrow.py" "$CTL_SOCK" metrics.local:9101)"
WIDEN_RC=$?
echo "  host -> task A's proxy: $WIDEN_MSG"

wait "$ATTEN_PID" 2>/dev/null

# One transcript, two halves: the wait-for line is the moment the narrowing landed.
awk '/RESULT sync wait-for/{seen=1; next} !seen' "$ATTEN_OUT" >"$OUT_DIR/atten-before.out"
awk '/RESULT sync wait-for/{seen=1; next} seen'  "$ATTEN_OUT" >"$OUT_DIR/atten-after.out"

assert_allowed ENFORCED-2 "$OUT_DIR/atten-before.out" "probe-egress:metrics.local" \
  "task A host:  metrics.local, before the narrowing"
assert_denied ENFORCED-2 "$OUT_DIR/atten-after.out" "probe-egress:metrics.local" \
  "task A host:  same host, same sandbox, after"

if (( WIDEN_RC != 0 )); then
  ladder_synth_result "$ATTEN_OUT" network "narrow-widening-attempt" FAILURE "$WIDEN_MSG"
else
  ladder_synth_result "$ATTEN_OUT" network "narrow-widening-attempt" SUCCESS "$WIDEN_MSG"
fi
assert_denied ENFORCED-2 "$ATTEN_OUT" "narrow-widening-attempt" \
  "monotonicity: widening the scope back"

# ---------------------------------------------------------------- verdict

ladder_section "task-by-task"
ladder_table

echo
echo "world-effects available to task $TASK_A, in full:"
echo "  - broker tools:    $(sed -n '/^--tools/{n;p;}' "$TASKS_DIR/$TASK_A/spec/broker.args")"
echo "  - egress:          $(sed -n '/^--allow/{n;p;}' "$TASKS_DIR/$TASK_A/spec/proxy.args" | paste -sd, -)"
echo "  - writes under /scratch, in tasks/$TASK_A/scratch, visible to no other task"
echo "and the same three lines for $TASK_B name different values, from the same image."
echo "broker log (every decision, with its task): $BROKER_LOG"

ladder_result "a task's authority is its manifest, not its agent's role; a sibling task's grants are denied at the network and at the broker, and a grant can be narrowed mid-task but never widened"
