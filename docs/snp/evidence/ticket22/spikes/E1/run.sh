#!/bin/sh
# Rebuild and rerun spike E1. Usage: [TAG=n] ./run.sh [runs]
#
# Writes run.log and results.json beside this script (run-$TAG.log,
# results-$TAG.json when TAG is set, which is how the repeat invocation in the
# README was captured). Set BINDIR to build the binary somewhere other than a
# fresh temporary directory.
set -eu
export PATH="/usr/local/go/bin:$PATH"
here=$(cd "$(dirname "$0")" && pwd)
bin="${BINDIR:-$(mktemp -d)}/fdhandoff"
cd "$here"
GOPROXY=off go build -o "$bin" .
{
	echo "# $(date -Is)"
	echo "# $(uname -a)"
	echo "# $(go version)"
	echo "# nproc=$(nproc) loadavg=$(cut -d' ' -f1-3 /proc/loadavg)"
	echo "# cpufreq governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
	echo "# net.core.rmem_max=$(cat /proc/sys/net/core/rmem_max)"
	echo
} >"$here/run${TAG:+-$TAG}.log"
"$bin" -runs="${1:-7}" -out="$here/results${TAG:+-$TAG}.json" 2>&1 | tee -a "$here/run${TAG:+-$TAG}.log"
