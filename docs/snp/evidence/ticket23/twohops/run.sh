#!/bin/sh
# The two hops, exactly as they were run.
#
# The harness is a test in the tree — attest/cmd/agent-probe/twohops_test.go —
# and not a file copied in to run, because everything it needs is now a package:
# the loop is attest/cmd/agent-probe, the far sandbox is attest/sandbox/deno and
# the three tunnelds are the loopback harness with the fake platform. It skips
# unless both variables below are set, so `go test ./...` in attest/ stays green
# and free.
#
# ANTHROPIC_API_KEY must already be in the environment. The agent on a reads it
# from there; the sandbox on b copies that one variable — and only that one,
# beside PATH and HOME — into the Deno process, because the pushed policy has an
# `e` entry naming it. It is not written in this script and not in the logs.
set -eu
export PATH=/usr/local/go/bin:$PATH
here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../../../../.." && pwd)     # the worktree root
cd "$tree/attest"
for n in 1 2; do
  AGENT_PROBE_LIVE=1 AGENT_PROBE_DENO=$HOME/.deno/bin/deno \
    go test ./cmd/agent-probe/ -run TestTwoHops -count=1 -v > "$here/run$n.log" 2>&1
done
