#!/bin/bash
# Ticket 26, spike E3. What one `alive` per second costs, how far a one-second
# ticker drifts, and how long a tunnel takes to go down after the sandbox at the
# far end stops enforcing what was pushed to it.
#
#   run.sh [<output-directory>]
#
# The spike is a throwaway test file that belongs to this directory and not to
# the tree: it is copied into attest/tunneld, run there against the contract v3
# code, and removed again whatever happens. It needs no network, no hardware and
# no key — two tunnelds on loopback with the fake platform, a unix socket
# between one of them and a sandbox in a second process, and signals.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE}"
REPO="$(cd "$HERE/../../../../../.." && pwd)"
ATTEST="$REPO/attest"
COPY="$ATTEST/tunneld/e3_spike_test.go"

export PATH=/usr/local/go/bin:$PATH
trap 'rm -f "$COPY"' EXIT
cp "$HERE/e3_spike_test.go" "$COPY"

{
	echo "date:    $(date -Is)"
	echo "host:    $(uname -srm)"
	echo "cpu:     $(nproc) online, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
	echo "load:    $(cut -d' ' -f1-3 /proc/loadavg)"
	echo "go:      $(go version)"
	echo "repo:    $REPO"
	echo "commit:  $(git -C "$REPO" rev-parse HEAD)"
	echo "spike:   sha256:$(sha256sum "$HERE/e3_spike_test.go" | cut -d' ' -f1)"
} | tee "$OUT/output-00-setup.txt"

echo "\$ go test ./tunneld -run '^TestE3\$/^cost\$' -v -count=1 -timeout 30m"
go test -C "$ATTEST" ./tunneld -run '^TestE3$/^cost$' -v -count=1 -timeout 30m \
	2>&1 | tee "$OUT/output-01-cost.txt"

echo "\$ go test ./tunneld -run '^TestE3\$/^drift\$' -v -count=1 -timeout 30m"
go test -C "$ATTEST" ./tunneld -run '^TestE3$/^drift$' -v -count=1 -timeout 30m \
	2>&1 | tee "$OUT/output-02-drift.txt"

echo "\$ go test ./tunneld -run '^TestE3\$/^teardown\$' -v -count=1 -timeout 30m"
go test -C "$ATTEST" ./tunneld -run '^TestE3$/^teardown$' -v -count=1 -timeout 30m \
	2>&1 | tee "$OUT/output-03-teardown.txt"

echo "E3 done; outputs in $OUT"
