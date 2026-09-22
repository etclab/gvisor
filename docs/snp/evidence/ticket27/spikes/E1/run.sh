#!/bin/bash
# Ticket 27, spike E1: the window, and who is in it.
#
#   run.sh [<output-directory>]
#
# Twenty-five runs on loopback. Each one starts a sandbox host on a unix socket,
# attaches the exit's client to it as a network client, starts runsc, and enters
# Host.Apply with a policy a millisecond or two later — before the runsc helper
# can have attached. What is measured is when each client attached, how long the
# push waited, who was offered the document, and what the push was answered.
#
# The header below is part of the output, so that a reader of output.txt knows
# which tree and which runsc the numbers came off without being told.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE}"
REPO="$(cd "$HERE/../../../../../.." && pwd)"
export PATH=/usr/local/go/bin:$PATH
export AGENT_PROBE_RUNSC="${AGENT_PROBE_RUNSC:-$REPO/bazel-bin/runsc/runsc_/runsc}"

cd "$REPO/attest"
{
  echo "=== Ticket 27, spike E1 ==="
  echo "date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "branch:      $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
  echo "commit:      $(git -C "$REPO" rev-parse HEAD)"
  echo "runsc:       $AGENT_PROBE_RUNSC"
  echo "runsc sha256: $(sha256sum "$AGENT_PROBE_RUNSC" | cut -d' ' -f1)"
  echo "kernel:      $(uname -sr)"
  echo
  go run "$HERE/e1_spike.go"
  echo "=== Spike E1 complete ==="
} 2>&1 | tee "$OUT/output.txt"
