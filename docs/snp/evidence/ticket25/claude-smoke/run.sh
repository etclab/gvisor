#!/bin/sh
# Claude Code inside the sandbox, exactly as it was run.
#
# The harness is a test in the tree — attest/cmd/agent-probe/claude_test.go —
# and it shares everything but the rootfs with adapter_test.go: the same two
# tunnelds with the fake SNP platform, the same ticket 23 exit, the same table,
# the same capture and the same key handling. What differs is what goes inside
# the sandbox: a 232 MB dynamically linked ELF with a loader, six libraries,
# git, a writable HOME and an empty working directory.
#
# What is asked of the run is narrow, and the test asserts only that much: the
# CLI starts. Task completion is not required and its absence is not a failure.
#
#   claude -p "Reply with exactly the word OK." --output-format json \
#          --model claude-haiku-4-5-20251001
#
# The table names api.anthropic.com and http-intake.logs.us5.datadoghq.com, both
# on 443, which is the whole host list spike E4 measured
# (docs/snp/evidence/ticket25/spikes/E4/notes.md). The Datadog log intake is
# contacted on a fresh HOME with no opt-in, so a table with the model endpoint
# alone would make a real agent runtime retry its log flush.
#
# ANTHROPIC_API_KEY must already be in the environment. It reaches the sandbox
# through process.env in the bundle's config.json, which is written under a 0700
# directory in /dev/shm — tmpfs, never a disk — and removed when the test ends.
# Every captured file is searched for the key before it is copied into the
# evidence; one that carries it is left behind and a .redacted copy put in its
# place, and anything over 4 MiB is gzipped rather than trimmed. The sentry's
# debug log always carries the key, because runsc logs the container spec and
# process.env is in it.
#
# Variables:
#   AGENT_PROBE_RUNSC              the runsc to use; defaults to the tree's build
#   AGENT_PROBE_CLAUDE             the Claude Code ELF (not the ~/.local/bin shim)
#   AGENT_PROBE_SECCHECK_RECEIVER  optional; records sentry/egress_refused
#   AGENT_PROBE_ADAPTER=0          drop the --tunnel-* flags. That is the
#                                  rehearsal in rehearsal-stock-runsc/, which
#                                  says the ELF runs under runsc and says
#                                  nothing about the adapter.
set -eu
export PATH=/usr/local/go/bin:$PATH
here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../../../../.." && pwd)     # the worktree root
: "${AGENT_PROBE_RUNSC:=$tree/bazel-bin/runsc/runsc_/runsc}"
: "${AGENT_PROBE_CLAUDE:=$HOME/.local/share/claude/versions/2.1.276}"
export AGENT_PROBE_RUNSC AGENT_PROBE_CLAUDE
cd "$tree/attest"
AGENT_PROBE_LIVE=1 \
  go test ./cmd/agent-probe/ -run TestClaudeCodeSmoke -count=1 -v -timeout 40m \
  > "$here/run.log" 2>&1
