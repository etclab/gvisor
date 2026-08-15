#!/usr/bin/env bash
# lib.sh - shared helpers for every rung's demo.sh.
#
# All rungs use these so the three-check output looks the same on a projector no
# matter which rung is running. Source it, do not execute it.
#
# Vocabulary, per conventions section 3:
#   BASELINE - the attack under the previous rung's settings. Must SUCCEED.
#   ENFORCED - the same attack under this rung. Must be BLOCKED, with evidence.
#   CONTROL  - a legitimate task under this rung. Must SUCCEED.

set -o pipefail

LADDER_PASS=0
LADDER_FAIL=0
LADDER_TABLE_FILE="${LADDER_TABLE_FILE:-}"

ladder_init() {
  LADDER_TABLE_FILE="$(mktemp -t ladder-table.XXXXXX)"
  LADDER_PASS=0
  LADDER_FAIL=0
}

ladder_section() {
  printf '\n=== %s ===\n\n' "$1"
}

# ladder_agent_result <outfile> <action-substring>
# Echoes the RESULT line for an action, or nothing if the agent never reported it.
ladder_agent_result() {
  grep -m1 -F -- "$2" "$1" 2>/dev/null | grep -m1 '^RESULT ' || true
}

# ladder_expect <TAG> <outfile> <action-substring> <SUCCESS|FAILURE> <description>
# The one assertion every check is built from. Prints the conventions-section-3 line
# plus a single line of evidence, and records the outcome for the summary table.
ladder_expect() {
  local tag="$1" out="$2" action="$3" want="$4" desc="$5"
  local line got evidence verb suffix
  line="$(ladder_agent_result "$out" "$action")"

  if [[ -z "$line" ]]; then
    got="MISSING"
    evidence="agent produced no RESULT line for '${action}' (harness bug, not a policy outcome)"
  else
    got="$(awk '{print $4}' <<<"$line")"
    evidence="$(cut -d' ' -f5- <<<"$line")"
  fi

  case "$got" in
    SUCCESS) verb="SUCCEEDED" ;;
    FAILURE) verb="BLOCKED" ;;
    *)       verb="MISSING" ;;
  esac

  if [[ "$got" == "$want" ]]; then
    suffix="(expected)"
    LADDER_PASS=$((LADDER_PASS + 1))
  else
    suffix="(UNEXPECTED - wanted $([[ $want == SUCCESS ]] && echo SUCCEEDED || echo BLOCKED))"
    LADDER_FAIL=$((LADDER_FAIL + 1))
  fi

  printf '[%s] %s => %s %s\n' "$tag" "$desc" "$verb" "$suffix"
  printf '          %s\n\n' "$evidence"

  if [[ -n "$LADDER_TABLE_FILE" ]]; then
    printf '%s\t%s\t%s\t%s\n' "$tag" "$desc" "$verb" "$evidence" >>"$LADDER_TABLE_FILE"
  fi
}

# ladder_synth_result <outfile> <channel> <action> <SUCCESS|FAILURE> <evidence...>
# Records an observation the harness made from OUTSIDE the sandbox, in the same format
# the agent uses, so it can be asserted on with the same helpers. Used for facts the
# agent is not in a position to report -- e.g. whether a write it believes succeeded
# actually reached a host path.
ladder_synth_result() {
  local out="$1" channel="$2" action="$3" outcome="$4"; shift 4
  printf 'RESULT %s %s %s %s\n' "$channel" "$action" "$outcome" "$*" >>"$out"
}

# assert_allowed / assert_denied - the names conventions section 4 asks for.
assert_allowed() { ladder_expect "$1" "$2" "$3" SUCCESS "$4"; }
assert_denied()  { ladder_expect "$1" "$2" "$3" FAILURE "$4"; }

# ladder_table <channel-count-note>
# Renders the channel-by-channel table the rung-0 acceptance criteria asks for:
# every check, under every config, with the evidence that decided it.
ladder_table() {
  [[ -s "$LADDER_TABLE_FILE" ]] || return 0
  printf '\n%-10s %-44s %-10s %s\n' "CONFIG" "CHANNEL / PROBE" "OUTCOME" "EVIDENCE"
  printf '%s\n' "$(printf '%.0s-' {1..118})"
  while IFS=$'\t' read -r tag desc verb evidence; do
    printf '%-10s %-44s %-10s %.44s\n' "$tag" "$desc" "$verb" "$evidence"
  done <"$LADDER_TABLE_FILE"
  printf '%s\n' "$(printf '%.0s-' {1..118})"
}

# ladder_result <one-line-claim>
# Final verdict. Exit code of the demo is the exit code of this function.
ladder_result() {
  local claim="$1"
  printf '\nchecks: %d passed, %d failed\n' "$LADDER_PASS" "$LADDER_FAIL"
  printf 'claim exercised: %s\n' "$claim"
  if (( LADDER_FAIL == 0 && LADDER_PASS > 0 )); then
    printf 'RESULT: PASS\n'
    return 0
  fi
  printf 'RESULT: FAIL\n'
  return 1
}

# ladder_load_args <args-file>
# Reads a config file of one docker-run argument per line into the LADDER_ARGS array,
# skipping comments and blank lines and expanding ${VAR} from the environment. The
# config files are the rung-0 deliverable, so they are kept readable at the cost of
# this small loader.
ladder_load_args() {
  local file="$1" line
  LADDER_ARGS=()
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    LADDER_ARGS+=("$(eval printf '%s' "\"$line\"")")
  done <"$file"
}

# ---------------------------------------------------------------- environment

ladder_require() {
  local missing=0
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "missing required command: $cmd" >&2; missing=1; }
  done
  return $missing
}

# The ladder demos need docker but not root: membership in the docker group plus
# gVisor's per-container annotation allowlist covers everything rung 0 asks for.
ladder_require_docker() {
  ladder_require docker || return 1
  docker info >/dev/null 2>&1 || {
    echo "cannot talk to the docker daemon (are you in the docker group?)" >&2
    return 1
  }
}

ladder_require_runsc_runtime() {
  docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"runsc"' || {
    echo "docker has no 'runsc' runtime registered; see ladder/README.md" >&2
    return 1
  }
}

# AF_UNIX paths are capped at 108 bytes and the failure mode looks like a permissions
# problem, so every rung puts its runtime state somewhere short and predictable.
ladder_runtime_dir() {
  local dir="${LADDER_RUNTIME_DIR:-/tmp/ladder-$(id -u)}"
  mkdir -p "$dir"
  printf '%s' "$dir"
}

# capture_runsc_log <container-name> <destination>
# runsc debug logs are per-container and only exist if the runtime was asked for them;
# rung 0 does not need them, later rungs (which log denials from inside the sentry) do.
capture_runsc_log() {
  local name="$1" dest="$2"
  docker logs "$name" >"$dest" 2>&1 || true
}

# cleanup_sandboxes - remove everything this harness creates, on success or failure.
# Every ladder object is named ladder-* or labelled ladder=1 so nothing else is touched.
cleanup_sandboxes() {
  local ids
  ids="$(docker ps -aq --filter 'label=ladder=1' 2>/dev/null || true)"
  [[ -n "$ids" ]] && docker rm -f $ids >/dev/null 2>&1
  for net in $(docker network ls --filter 'label=ladder=1' --format '{{.Name}}' 2>/dev/null); do
    docker network rm "$net" >/dev/null 2>&1 || true
  done
  return 0
}
