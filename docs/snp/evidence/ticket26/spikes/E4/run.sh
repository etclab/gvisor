#!/bin/sh
# E4 — Claude Code under a pushed policy, exactly as it was run.
#
# The harness is attest/cmd/agent-probe/governed_test.go, `TestClaudeGoverned`.
# It is ticket 25's Claude Code smoke (claude_test.go) with a third tunneld
# added: `root` dials `a` and pushes
#
#   {"format":"policy","version":1,"n":[{"host":"api.anthropic.com","ports":[443]}],"f":[],"x":[]}
#
# once the sandbox has attached to a's socket. The boot table still names both
# of E4's hosts — api.anthropic.com:443 and http-intake.logs.us5.datadoghq.com:443
# — so the push narrows it by the log intake, which the CLI contacts on a fresh
# HOME with no opt-in.
#
# Four sandboxes: three governed and one with no push at all, in that order, so
# that the comparison is the same binary in the same rootfs behind the same exit
# on the same afternoon. The command is ticket 25's:
#
#   claude -p "Reply with exactly the word OK." --output-format json \
#          --model claude-haiku-4-5-20251001
#
# What is being asked is E4's question: the task's outcome, every refusal with
# its errno, and whether the run is distinguishable from an unrestricted one
# from the outside. The README the run writes answers all three; notes.md beside
# this script is the reading of it.
#
# ANTHROPIC_API_KEY must already be in the environment. It reaches the sandbox
# through process.env in the bundle's config.json, written under a 0700
# directory in /dev/shm and removed when the test ends. Every captured file is
# searched for the key before it is copied into the evidence; the sentry's
# debug log always carries it, because runsc logs the container spec.
#
# Variables:
#   AGENT_PROBE_RUNSC              the runsc to use; defaults to the tree's build
#   AGENT_PROBE_CLAUDE             the Claude Code ELF (not the ~/.local/bin shim)
#   AGENT_PROBE_SECCHECK_RECEIVER  the receiver the egress_refused lines come from
set -eu
export PATH=/usr/local/go/bin:$PATH
here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../../../../.." && pwd)     # the worktree root
: "${AGENT_PROBE_RUNSC:=$tree/bazel-bin/runsc/runsc_/runsc}"
: "${AGENT_PROBE_CLAUDE:=$HOME/.local/share/claude/versions/2.1.276}"
export AGENT_PROBE_RUNSC AGENT_PROBE_CLAUDE
cd "$tree/attest"
AGENT_PROBE_LIVE=1 \
  go test ./cmd/agent-probe/ -run TestClaudeGoverned -count=1 -v -timeout 45m \
  > "$here/run.log" 2>&1
