#!/bin/bash
# Ticket 27, spike E1: the window, and who is in it.
#
#   run.sh [<output-directory>]
#
# Measures across 25 runs:
#   - Time from tunneld listening on sandbox socket to exit client attaching
#   - Time to runsc helper attaching
#   - Time at which an early push lands relative to both
#   - Which client answered each push and what it answered
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE}"
REPO="$(cd "$HERE/../../../../../.." && pwd)"
export PATH=/usr/local/go/bin:$PATH
export AGENT_PROBE_RUNSC="$REPO/bazel-bin/runsc/runsc_/runsc"

echo "=== Running Ticket 27 Spike E1 ==="
echo "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "commit:  $(git -C "$REPO" rev-parse HEAD)"
echo "runsc:   $AGENT_PROBE_RUNSC"

cd "$REPO/attest"
go run "$HERE/e1_spike.go" | tee "$OUT/output.txt"
echo "=== Spike E1 Complete ==="
