#!/bin/bash
# Ticket 27, spike E2: a policy delivered twice.
#
#   run.sh [<output-directory>]
#
# Delivers a policy to a sandbox, then delivers the same bytes again to the same sentry,
# and separately to a sentry that has just attached with no policy in force.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE}"
REPO="$(cd "$HERE/../../../../../.." && pwd)"
export PATH=/usr/local/go/bin:$PATH
export AGENT_PROBE_RUNSC="$REPO/bazel-bin/runsc/runsc_/runsc"

echo "=== Running Ticket 27 Spike E2 ==="
echo "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "commit:  $(git -C "$REPO" rev-parse HEAD)"
echo "runsc:   $AGENT_PROBE_RUNSC"

cd "$REPO/attest"
go run "$HERE/e2_spike.go" | tee "$OUT/output.txt"
echo "=== Spike E2 Complete ==="
