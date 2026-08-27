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
#                              no snpfake, no go-sev-guest/testing, no testing,
#                              nothing dynamically linked (attest/README.md).
#   2. CGO_ENABLED=0 go build  the binary the image embeds. Confirmed static
#                              again here with file(1), because the guard runs
#                              on a build of its own and this is the file that
#                              is actually installed.
#   3. build-image.sh          with TUNNELD set and nothing else set. Every
#                              byte of the image is a byte in the measurement,
#                              so the build is the one ticket 06 wrote and the
#                              only parameter ticket 14 touches is this one.
#
# It emits, in OUT: the image (OVMF.fd, vmlinuz, initrd.img, cmdline.txt,
# rootfs.img), the predicted launch measurement, the signed reference value set
# for it, the manifest, and packaging.txt recording what went in.
#
# Environment:
#   OUT         output directory (default $STACK/image-ticket14)
#   AUTHOR_KEY  the reference value author's Ed25519 private key, PKCS#8 PEM.
#               Generated into OUT/author.key if unset — a throwaway, which is
#               what every run so far has used (spec, Out of Scope: key custody).
#   STACK       ticket 01's host stack
#   Anything else build-image.sh reads (VCPUS, VCPU_TYPE, POLICY, TCB_FLOOR) is
#   passed through untouched.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
OUT="${OUT:-$STACK/image-ticket14}"
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
echo "\$ CGO_ENABLED=0 go build -o $BIN ./cmd/tunneld"
(cd "$REPO/attest" && CGO_ENABLED=0 go build -o "$BIN" ./cmd/tunneld)
file "$BIN"
file "$BIN" | grep -q 'statically linked' || {
  echo "REFUSING: $BIN is not statically linked. The image's root filesystem carries no dynamic" >&2
  echo "loader, so this would fail at exec inside the guest, after the measurement is fixed." >&2
  exit 1
}
echo "tunneld sha256: $(sha256sum "$BIN" | cut -d' ' -f1)"
echo "tunneld bytes : $(stat -c %s "$BIN")"
echo

echo "=== 3. the image, with TUNNELD set and nothing else"
if [ -z "${AUTHOR_KEY:-}" ]; then
  AUTHOR_KEY="$WORK/author.key"
  openssl genpkey -algorithm ed25519 -out "$AUTHOR_KEY" 2>/dev/null
  chmod 600 "$AUTHOR_KEY"
  echo "generated a throwaway reference value author key at $AUTHOR_KEY"
fi
export AUTHOR_KEY OUT STACK
TUNNELD="$BIN" bash "$HERE/build-image.sh"

cp "$LOG" "$OUT/packaging.txt" 2>/dev/null || true
cp "$BIN" "$OUT/tunneld"

echo
echo "=== packaged"
M=$(sed -n 's/^launch_measurement: //p' "$OUT/manifest.txt")
echo "predicted launch measurement: $M"
echo "reference value set:          $OUT/reference-values.json (+ .sig)"
echo "author public key:            $(cat "$OUT/build/author.pub" 2>/dev/null || echo '?')"
echo "author key:                   $AUTHOR_KEY (keep it: re-signing a set needs it)"
echo "packaged binary:              $OUT/tunneld (the copy inside rootfs.img is what is measured)"
echo "packaging record:             $LOG, copied to $OUT/packaging.txt"
