#!/bin/bash
# Package tunneld into the measured image (ticket 14, criteria 1 and 2).
#
#   package-tunneld.sh [-out DIR] [-keep-key]
#
# The order is the whole point of this script and it is the order the criteria
# are written in: check the binary, then build the binary, then measure the
# image it goes into. A measurement over a binary nobody checked is a
# measurement of whatever was there — and by the time a guest boots and says
# something is wrong, the measurement is fixed, the reference value set is
# signed, and every peer has been told what to admit.
#
#   1. go test ./cmd/tunneld   the import-graph guard and the artifact guard:
#                              no attest/internal/snpfake, no
#                              attest/internal/tdxfake, no
#                              attest/internal/fixture, no
#                              go-sev-guest/testing, no go-tdx-guest/testing,
#                              no testing, nothing dynamically linked
#                              (attest/README.md).
#   2. CGO_ENABLED=0 go build  the binary the image embeds. Confirmed static
#                              again here with file(1), because the guard runs
#                              on a build of its own and this is the file that
#                              is actually installed.
#   2b. CGO_ENABLED=0 go build attest/cmd/agent-probe, the exit the measured
#                              init runs when the config device carries a tunnel
#                              table (ticket 25). It is built exactly as tunneld
#                              is and checked exactly as tunneld is — static, and
#                              carrying no checkout path — and it is deliberately
#                              *not* run through a guard of its own: the guard in
#                              step 1 is about a binary that acquires evidence and
#                              judges a peer's, and agent-probe does neither. What
#                              it does is dial what a stream asked for if a list
#                              permits it, and the thing that could go wrong there
#                              is the list, which is on the config device.
#   3. build-image.sh          with TUNNELD, RUNSC and AGENT_PROBE set and
#                              nothing else set. Every byte of the image is a
#                              byte in the measurement, so the build is the one
#                              ticket 06 wrote and the only parameters set here
#                              are those three. runsc is not built here — `make
#                              runsc` is the only thing that builds it on this
#                              branch — so it is named, hashed and passed
#                              through, and the build refuses one that is not
#                              static.
#
# It emits, in OUT: the image (OVMF.fd, vmlinuz, initrd.img, cmdline.txt,
# rootfs.img), the predicted launch measurement, the signed reference value set
# and the signed policy for it, the manifest, and packaging.txt recording what
# went in.
#
# Environment:
#   OUT         output directory (default $STACK/image-ticket14)
#   AUTHOR_KEY  the reference value author's Ed25519 private key, PKCS#8 PEM.
#               Generated into OUT/author.key if unset — a throwaway, which is
#               what every run so far has used (spec, Out of Scope: key custody).
#   AGENT_PROBE not read: this script builds it from attest/cmd/agent-probe and
#               passes it to build-image.sh. A binary this tree builds is built
#               here, and one it does not (runsc) is named.
#   RUNSC       required. The static runsc the image carries at /usr/bin/runsc
#               (ticket 24), from `make runsc`: bazel-bin/runsc/runsc_/runsc.
#               Passed through to build-image.sh untouched; its sha256 and size
#               are recorded here beside tunneld's.
#   STACK       ticket 01's host stack
#   Anything else build-image.sh reads (VCPUS, VCPU_TYPE, POLICY, TCB_FLOOR) is
#   passed through untouched.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
OUT="${OUT:-$STACK/image-ticket14}"
: "${RUNSC:?set RUNSC to the static runsc the image carries as /usr/bin/runsc; make runsc builds it into bazel-bin/runsc/runsc_/runsc}"
# A virtualenv's scripts carry an absolute shebang, so the one ticket 07 built
# names a worktree that no longer exists and cannot be run from here. Each
# ticket therefore gets its own; predict-measurement.sh creates it if it is
# absent and pins the version either way.
export SEV_SNP_MEASURE_VENV="${SEV_SNP_MEASURE_VENV:-$STACK/sev-snp-measure-venv-ticket14}"
export PATH="/usr/local/go/bin:$PATH"
command -v go >/dev/null || { echo "go not found; attest/README.md says how" >&2; exit 1; }

# Beside OUT and not inside it: build-image.sh starts by removing OUT, so a
# packaging record kept in there would be deleted by the step it records.
WORK="$OUT-packaging"
rm -rf "$WORK"; mkdir -p "$WORK"
LOG="$WORK/packaging.txt"
exec > >(tee "$LOG") 2>&1
echo "=== package-tunneld: $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)"
echo "repo $(git -C "$REPO" rev-parse HEAD) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
echo "go   $(go version)"
echo

echo "=== 1. the guard, BEFORE anything is built or measured"
echo "\$ go test ./cmd/tunneld"
(cd "$REPO/attest" && go test -v -count=1 ./cmd/tunneld) \
  || { echo "GUARD FAILED: not building an image around this binary" >&2; exit 1; }
echo "guard passed: the packaged graph reaches no fake platform and no test support"
echo

echo "=== 2. the binary"
BIN="$WORK/tunneld"
# -trimpath, because without it a Go binary carries the absolute path of every
# file compiled into it, and the launch measurement over that binary would then
# depend on which directory it was built in — the same source in two worktrees
# would produce two measurements and nobody outside this machine could
# reproduce either. -buildvcs=false for the same reason one level up: the
# commit belongs in the manifest, which records it, and not in the bytes the
# measurement covers.
echo "\$ CGO_ENABLED=0 go build -trimpath -buildvcs=false -o $BIN ./cmd/tunneld"
(cd "$REPO/attest" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$BIN" ./cmd/tunneld)
if strings -a "$BIN" | grep -q "$REPO"; then
  echo "REFUSING: $BIN embeds the checkout path $REPO, so its measurement is not reproducible elsewhere" >&2
  exit 1
fi
file "$BIN"
file "$BIN" | grep -q 'statically linked' || {
  echo "REFUSING: $BIN is not statically linked. The image's root filesystem carries no dynamic" >&2
  echo "loader, so this would fail at exec inside the guest, after the measurement is fixed." >&2
  exit 1
}
echo "tunneld sha256: $(sha256sum "$BIN" | cut -d' ' -f1)"
echo "tunneld bytes : $(stat -c %s "$BIN")"
# And the binary this script does not build. runsc comes from `make runsc` and a
# bazel tree, so there is nothing here to check an import graph of; what this
# record owes is which file went in, so the two numbers sit beside tunneld's.
echo "runsc path    : $RUNSC"
echo "runsc sha256  : $(sha256sum "$RUNSC" | cut -d' ' -f1)"
echo "runsc bytes   : $(stat -c %s "$RUNSC")"
echo

echo "=== 2b. the exit the measured init runs (ticket 25)"
PROBE="$WORK/agent-probe"
echo "\$ CGO_ENABLED=0 go build -trimpath -buildvcs=false -o $PROBE ./cmd/agent-probe"
(cd "$REPO/attest" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$PROBE" ./cmd/agent-probe)
if strings -a "$PROBE" | grep -q "$REPO"; then
  echo "REFUSING: $PROBE embeds the checkout path $REPO, so its measurement is not reproducible elsewhere" >&2
  exit 1
fi
file "$PROBE"
file "$PROBE" | grep -q 'statically linked' || {
  echo "REFUSING: $PROBE is not statically linked; the image's root filesystem carries no dynamic loader" >&2
  exit 1
}
echo "agent-probe sha256: $(sha256sum "$PROBE" | cut -d' ' -f1)"
echo "agent-probe bytes : $(stat -c %s "$PROBE")"
echo

echo "=== 3. the image, with TUNNELD, RUNSC and AGENT_PROBE set and nothing else"
if [ -z "${AUTHOR_KEY:-}" ]; then
  AUTHOR_KEY="$WORK/author.key"
  openssl genpkey -algorithm ed25519 -out "$AUTHOR_KEY" 2>/dev/null
  chmod 600 "$AUTHOR_KEY"
  echo "generated a throwaway reference value author key at $AUTHOR_KEY"
fi
export AUTHOR_KEY OUT STACK RUNSC
AGENT_PROBE="$PROBE"
export AGENT_PROBE
TUNNELD="$BIN" bash "$HERE/build-image.sh"

cp "$LOG" "$OUT/packaging.txt" 2>/dev/null || true
cp "$BIN" "$OUT/tunneld"
cp "$PROBE" "$OUT/agent-probe"

echo
echo "=== packaged"
M=$(sed -n 's/^launch_measurement: //p' "$OUT/manifest.txt")
echo "predicted launch measurement: $M"
echo "reference value set:          $OUT/reference-values.json (+ .sig)"
echo "policy:                       $OUT/policy.json (+ .sig; archived beside the image, on no config device)"
echo "ceiling digest:               $(sed -n 's/^policy_digest: //p' "$OUT/manifest.txt") (what a guest presents)"
echo "emitted policy digest:        $(sed -n 's/^emitted_policy_digest: //p' "$OUT/manifest.txt") (pushed, not delivered)"
echo "author public key:            $(cat "$OUT/build/author.pub" 2>/dev/null || echo '?')"
echo "author key:                   $AUTHOR_KEY (keep it: re-signing a set needs it)"
echo "packaged binary:              $OUT/tunneld (the copy inside rootfs.img is what is measured)"
echo "runsc:                        $RUNSC (the copy inside rootfs.img is what is measured)"
echo "agent-probe:                  $OUT/agent-probe (the copy inside rootfs.img is what is measured)"
echo "packaging record:             $LOG, copied to $OUT/packaging.txt"
