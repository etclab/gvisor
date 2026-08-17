#!/usr/bin/env bash
# Run one pass of boundclaw-agent-usecase against this tree's runsc.
# See usecase/README.md.  Usage: run.sh {1|2|3}
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
US="$REPO/usecase"

# Where the use case comes from.  UC_PIN is the revision the passes below were
# measured against; override it to test the use case's own newer work.
UC_URL="${USECASE_URL:-git@github.com:jbcallv/boundclaw-agent-usecase.git}"
UC_PIN="${USECASE_REV:-12b1e9f82900bba4cd23946c82d795ba140e0dfd}"

# Resolve the use case in three steps: an explicit override, then a sibling
# checkout, then a clone of our own under usecase/.agent-usecase (gitignored).
# The sibling is preferred when present so local edits to it are picked up.
resolve_usecase() {
  if [ -n "${USECASE_DIR:-}" ]; then
    [ -d "$USECASE_DIR" ] || { echo "USECASE_DIR=$USECASE_DIR does not exist" >&2; exit 5; }
    ( cd "$USECASE_DIR" && pwd ); return
  fi
  if [ -d "$REPO/../boundclaw-agent-usecase" ]; then
    ( cd "$REPO/../boundclaw-agent-usecase" && pwd ); return
  fi
  local own="$US/.agent-usecase"
  if [ ! -d "$own/.git" ]; then
    echo "use case not found as a sibling -- cloning $UC_URL" >&2
    git clone -q "$UC_URL" "$own" >&2 || {
      echo "clone failed.  Point at an existing checkout instead:" >&2
      echo "  USECASE_DIR=/path/to/boundclaw-agent-usecase $0 <pass>" >&2
      exit 5; }
    git -C "$own" checkout -q "$UC_PIN" 2>/dev/null \
      || echo "warning: pin $UC_PIN not found; using default branch" >&2
    echo "cloned to $own, pinned to ${UC_PIN:0:9}" >&2
  fi
  ( cd "$own" && pwd )
}

UC="$(resolve_usecase)"
[ -f "$UC/deploy/docker-compose.yml" ] || {
  echo "no deploy/docker-compose.yml under $UC -- is that the use-case repo?" >&2; exit 5; }
COMPOSE_DIR="$UC/deploy"
RUNTIME_NAME="boundclaw-runsc"
PROJECT="boundclaw-uc"                 # stable compose project name across passes
LLM_MODE="${LLM_MODE:-stub}"
PASS="${1:-1}"

# Static addressing, applied to every pass so the only thing that varies across
# passes is the runtime.  Required under gVisor: Docker's embedded DNS resolver
# at 127.0.0.11 is unreachable from the sandbox.  See net-static.yml.
HEALTH_IP=172.31.77.11
FIN_IP=172.31.77.13
BASE=(-f "$COMPOSE_DIR/docker-compose.yml" -f "$US/net-static.yml")

case "$PASS" in
  1) FILES=("${BASE[@]}")
     RUNTIME_DESC="default runtime (runc) for all three agents"
     EXPECT="ATTACK SUCCEEDED" ;;
  2) FILES=("${BASE[@]}" -f "$COMPOSE_DIR/docker-compose.boundclaw.yml")
     RUNTIME_DESC="$RUNTIME_NAME for all three agents"
     # The fork carries provenance only over this HTTP path today (no --ladder-*
     # HTTP enforcement yet), so the honest baseline is still SUCCEEDED. See README.
     EXPECT="ATTACK SUCCEEDED" ;;
  3) FILES=("${BASE[@]}" -f "$COMPOSE_DIR/docker-compose.mixed.yml")
     RUNTIME_DESC="$RUNTIME_NAME for health+insurer, runc for financial"
     EXPECT="ATTACK SUCCEEDED" ;;
  *) echo "usage: $0 {1|2|3}" >&2; exit 2 ;;
esac

dc() { docker compose -p "$PROJECT" --project-directory "$COMPOSE_DIR" "${FILES[@]}" "$@"; }

log() { printf '\n=== %s ===\n' "$*"; }

# --- preflight (before creating a results dir, so an aborted run leaves none) --
log "PASS $PASS  ($RUNTIME_DESC)"
if [ "$PASS" != "1" ]; then
  if ! docker info --format '{{range $k,$v := .Runtimes}}{{$k}} {{end}}' | grep -qw "$RUNTIME_NAME"; then
    echo "ERROR: runtime '$RUNTIME_NAME' is not registered with docker." >&2
    echo "       Run:  make -C $REPO/usecase register" >&2
    exit 3
  fi
fi

TS="$(date +%Y%m%d-%H%M%S)"
OUT="$REPO/usecase/results/pass${PASS}-${TS}"
mkdir -p "$OUT"

# Marker for selecting this run's sentry logs.  /tmp/boundclaw-runsc is created
# by runsc as root, so an unprivileged caller cannot clear it between passes --
# without this, each pass would also capture every earlier pass's logs.
touch "$OUT/.started"

cleanup() { log "tearing down"; dc down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

# --- bring the stack up ----------------------------------------------------
log "building + starting agents (LLM_MODE=$LLM_MODE)"
LLM_MODE="$LLM_MODE" \
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-claude-sonnet-5}" \
  dc up -d --build 2>&1 | tee "$OUT/compose-up.log"

# --- record the authoritative runtime each container actually got ----------
log "runtime per container (docker inspect)"
dc ps -q | while read -r cid; do
  [ -n "$cid" ] && docker inspect -f '{{.Name}}  runtime={{.HostConfig.Runtime}}' "$cid"
done | tee "$OUT/runtimes.txt"

# --- wait for readiness ----------------------------------------------------
log "waiting for agents to answer"
ready=0
for _ in $(seq 1 60); do
  if curl -fs http://localhost:8003/audit >/dev/null 2>&1 \
     && curl -fs http://localhost:8001/audit >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[ "$ready" = 1 ] || { echo "agents did not become ready in time" >&2; dc logs >"$OUT/compose-fail.log" 2>&1; exit 4; }
echo "ready."

# --- run the attack harness inside a throwaway container on the net --------
# Reuses the built image; no host uv/httpx needed.  ENTRYPOINT is
# `uv run python -m`, so the arg below runs `python -m attack.run <variant>`.
#
# Deliberately plain `docker run` under runc rather than `docker compose run`:
# the harness is the test driver, not part of the system under test, so it
# should not inherit the pass's runtime.  Under runc it resolves names normally
# (no static-IP conflict with the already-running health-assistant, which
# `compose run` would hit), and it still reaches the agents by their fixed
# addresses.
run_variant() {
  local variant="$1"
  docker run --rm --runtime=runc --network "${PROJECT}_agent-net" \
    -e HEALTH_URL="http://${HEALTH_IP}:8001" \
    -e FINANCIAL_URL="http://${FIN_IP}:8003" \
    "${PROJECT}-health-assistant" "attack.run" "$variant" 2>&1
}

# '|| true': a failing harness container must not abort the run before the
# verdict block below — a broken pass should be reported, not silently truncated.
log "attack: clean (control)"
run_variant clean    | tee "$OUT/attack-clean.log"    || true
log "attack: poisoned"
run_variant poisoned | tee "$OUT/attack-poisoned.log" || true

# --- capture the evidence the paper cares about ----------------------------
curl -s http://localhost:8003/audit | jq . > "$OUT/financial-audit.json" 2>/dev/null || \
  curl -s http://localhost:8003/audit > "$OUT/financial-audit.json"

# The fork's per-container sentry logs (pass 2/3 only).  -newer picks out just
# this run's; cp -p rather than -a because the files are root-owned and
# preserving ownership would fail for an unprivileged caller.
if [ "$PASS" != "1" ] && [ -d /tmp/boundclaw-runsc ]; then
  mkdir -p "$OUT/runsc-logs"
  find /tmp/boundclaw-runsc -maxdepth 1 -name '*.log' -newer "$OUT/.started" \
    -exec cp -p {} "$OUT/runsc-logs/" \; 2>/dev/null
  n=$(ls "$OUT/runsc-logs" 2>/dev/null | wc -l)
  echo "captured $n sentry log(s) from this run"
  [ "$n" -eq 0 ] && echo "(none matched; /tmp/boundclaw-runsc is root-owned — sudo ls to inspect)"
fi

# --- verdict ---------------------------------------------------------------
log "VERDICT"
observed="$(grep -Eo 'ATTACK SUCCEEDED|attack blocked' "$OUT/attack-poisoned.log" | head -1 || true)"
echo "expected : $EXPECT"
echo "observed : ${observed:-<no verdict line>}"
echo "results  : $OUT"
if [ "$observed" = "$EXPECT" ]; then
  echo "PASS $PASS: OK (observed == expected)"
else
  echo "PASS $PASS: MISMATCH (observed != expected)"; exit 1
fi
