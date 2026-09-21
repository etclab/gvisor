#!/bin/bash
# Ticket 27, spike E3: liveness after the tunnel is gone.
#
#   run.sh [<output-directory>]
#
# Copies e3_spike_test.go into attest/tunneld, runs it, and captures output.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE}"
REPO="$(cd "$HERE/../../../../../.." && pwd)"
ATTEST="$REPO/attest"
COPY="$ATTEST/tunneld/e3_ticket27_spike_test.go"

export PATH=/usr/local/go/bin:$PATH
trap 'rm -f "$COPY"' EXIT
cp "$HERE/e3_spike_test.go" "$COPY"

echo "=== Running Ticket 27 Spike E3 ==="
echo "date:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "commit:  $(git -C "$REPO" rev-parse HEAD)"

go test -C "$ATTEST" ./tunneld -run '^TestE3LivenessAfterTunnelGone$' -v -count=1 -timeout 10m \
	2>&1 | tee "$OUT/output.txt"

echo "=== Spike E3 Complete ==="
