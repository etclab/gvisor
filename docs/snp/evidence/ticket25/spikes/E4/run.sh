#!/bin/sh
# E4, exactly as it was run. ANTHROPIC_API_KEY comes from the environment and
# is never written anywhere under this directory: nothing here echoes the
# environment, and run.sh checks its own output for the key before it exits.
#
#   usage: run.sh WORKDIR      (WORKDIR is scratch; the evidence lands beside
#                               this script)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?usage: run.sh WORKDIR}
claude=${CLAUDE:-/home/pniroula/.local/bin/claude}
model=${MODEL:-claude-haiku-4-5-20251001}
prompt='Reply with exactly the word OK.'
: "${ANTHROPIC_API_KEY:?ANTHROPIC_API_KEY must be in the environment}"

# The parent process here is itself a Claude Code session, so its own session
# variables are in the environment: CLAUDECODE, CLAUDE_CODE_MESSAGING_SOCKET,
# CLAUDE_CODE_SESSION_ID and friends. A workload disk in a sandbox has none of
# them, so they are stripped. Nothing that disables telemetry or auto-update is
# set: the point of the spike is the natural host list.
run() {                       # run HOME_DIR CWD -- argv...
    _home=$1; _cwd=$2; shift 3
    mkdir -p "$_cwd"
    ( cd "$_cwd" && env \
        -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT -u CLAUDE_CODE_EXECPATH \
        -u CLAUDE_CODE_MESSAGING_SOCKET -u CLAUDE_CODE_MESSAGING_TOKEN \
        -u CLAUDE_CODE_SESSION_ID -u CLAUDE_CODE_SESSION_ATTENDED \
        -u CLAUDE_CODE_CHILD_SESSION -u CLAUDE_EFFORT -u CLAUDE_PID \
        -u CLAUDE_CONFIG_DIR -u ANTHROPIC_DEFAULT_HAIKU_MODEL \
        HOME="$_home" "$@" )
}

mkdir -p "$work"

# 0. One run with nothing watching, in a fresh empty HOME, to be sure the CLI
#    runs non-interactively at all. It does: no trust prompt, no onboarding.
rm -rf "$work/home0" "$work/work0"; mkdir -p "$work/home0"
run "$work/home0" "$work/work0" -- \
    timeout 300 "$claude" -p "$prompt" --output-format json --model "$model" \
    > "$here/run-plain.log" 2> "$here/run-plain.err"

# 1. Traced, in a HOME that has never been used: this is what a bare workload
#    disk sees on its first boot.
rm -rf "$work/home1" "$work/work1"; mkdir -p "$work/home1"
run "$work/home1" "$work/work1" -- \
    timeout 600 strace -f -o "$here/run1-strace.raw" -e trace=%network,%file,%process -s 256 \
    "$claude" -p "$prompt" --output-format json --model "$model" \
    > "$here/run1.log" 2> "$here/run1.err"

# 2. Traced again against the HOME run 1 just populated: steady state, after
#    the config, the statsig cache and the project entry already exist.
run "$work/home1" "$work/work1" -- \
    timeout 600 strace -f -o "$here/run2-strace.raw" -e trace=%network,%file,%process -s 256 \
    "$claude" -p "$prompt" --output-format json --model "$model" \
    > "$here/run2.log" 2> "$here/run2.err"

# 3. Traced against the operator's own HOME, untouched, for comparison: a
#    fully configured install with settings, MCP servers and history.
mkdir -p "$work/work3"
( cd "$work/work3" && timeout 600 strace -f -o "$here/run3-strace.raw" \
    -e trace=%network,%file,%process -s 256 \
    "$claude" -p "$prompt" --output-format json --model "$model" ) \
    > "$here/run3.log" 2> "$here/run3.err"

python3 "$here/derive.py" run1="$here/run1-strace.raw" run2="$here/run2-strace.raw" \
    run3="$here/run3-strace.raw" \
    --home run1="$work/home1" --home run2="$work/home1" --home run3="$HOME" \
    > "$here/table.md"

# The key never gets written here; this is the check that says so. The prefix is
# computed inside the subshell below and never printed.
hits=$( { grep -rlF "$(printf %s "$ANTHROPIC_API_KEY" | cut -c1-12)" "$here" || true; } | wc -l )
# The key prefix every Anthropic key carries, built at runtime so that this
# script is not itself a hit for it.
needle=$(printf 'sk%sant' -)
hits2=$( { grep -rlF "$needle" "$here" || true; } | wc -l )
echo "key-prefix hits: $hits   key-scheme hits: $hits2"
