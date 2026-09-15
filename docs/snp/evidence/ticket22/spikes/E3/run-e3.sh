#!/bin/sh
# Run experiment E3 end to end, on a workstation, with no sudo.
#
#   docs/snp/evidence/ticket22/spikes/E3/run-e3.sh [SCRATCHDIR]
#
# SCRATCHDIR defaults to a directory under /tmp. Nothing is written into the
# repository except the captures under E3/out/.
#
# What it does:
#   1. builds tunneld from attest/ — the real binary, unmodified, the one whose
#      -egress probe ticket 19 ran inside two TDX guests;
#   2. builds the three spike programs in E3/spike/ (a nested Go module, so the
#      gvisor root module never sees them);
#   3. writes a minimum config device, whose ONLY job is to get tunneld as far
#      as its probe: the probe is behind a signature check, and E3 wants the
#      real probe rather than a copy of it. Nothing on it feeds the ceiling;
#   4. enters a user + network namespace with `unshare -rn` and runs
#      netns-inner.sh, which stands up one guest's network, installs the
#      ceiling twice — once from the constant text with `nft -f`, once through
#      the same Go renderer egress.go uses — and runs the probe and the
#      controls against each.
#
# Why no sudo: `unshare -rn` maps this user to root inside a new user namespace
# and gives it a new network namespace. nf_tables honours that namespace's own
# capabilities, so nft, netlink and the dummy interface all work, and the
# workstation's real network and real ruleset are untouched and out of reach.
set -e

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(CDPATH= cd -- "$HERE/../../../../../.." && pwd)
SCRATCH=${1:-/tmp/e3-ceiling-$$}
BIN=$SCRATCH/bin
CFG=$SCRATCH/config
OUT=$HERE/out

export PATH="/usr/local/go/bin:$PATH"

echo "e3: repository   $REPO"
echo "e3: scratch      $SCRATCH"
echo "e3: captures     $OUT"

mkdir -p "$BIN" "$CFG" "$OUT"

echo "e3: building the real tunneld from $REPO/attest"
(cd "$REPO/attest" && go build -o "$BIN/tunneld" ./cmd/tunneld)

echo "e3: building the spike programs from $HERE/spike"
(cd "$HERE/spike" && GOPROXY=off go build -o "$BIN/" ./...)

echo "e3: writing the minimum config device at $CFG"
"$BIN/mkconfig" -dir "$CFG"

echo "e3: SHA-256 of the constant (the name the ticket prints at boot):"
(cd "$HERE" && sha256sum ceiling.nft) | tee "$OUT/ceiling.nft.sha256"

echo "e3: entering a user + network namespace"
BIN="$BIN" CEILING="$HERE/ceiling.nft" CFG="$CFG" OUT="$OUT" \
	unshare -rn "$HERE/netns-inner.sh"

echo "e3: captures written:"
ls -l "$OUT"
