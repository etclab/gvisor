#!/bin/bash
# Predict the SEV-SNP launch measurement of a measured image from its build
# inputs alone, before anything boots (ticket 07).
#
#   predict-measurement.sh IMAGE_DIR [-vcpus N] [-vcpu-type T] [-out FILE]
#
# Inputs, all from IMAGE_DIR as build-image.sh wrote them: OVMF.fd, vmlinuz,
# initrd.img, cmdline.txt (the -append string; the file's trailing newline is
# not part of it, exactly as launch-measured-guest.sh passes it). Plus the two
# launch parameters that are not files: the vCPU count (one measured VMSA per
# vCPU) and the vCPU model (its family/model/stepping is in each VMSA's RDX at
# reset). Both must equal what launch-measured-guest.sh uses (-smp 4,
# -cpu EPYC-v4), or the prediction is for a different launch.
#
# What is modelled, and by what: AMD's sev-snp-measure (pinned below, in a
# virtualenv under the host stack so nothing system-wide changes) reproduces
# what the PSP does at launch — hashes the firmware image page by page, with
# the hashes table QEMU writes into the page the firmware advertises
# (kernel-hashes=on: SHA-256 of kernel, initrd and command line plus NUL), then
# one VMSA per vCPU — and folds each into the SNP launch digest. Nothing here
# reads the platform, and this script does not need root, /dev/sev, or a guest.
#
# The output is a prediction. Reading the measurement off a booted guest is
# permitted exactly once, to check that this computation is right, and never
# as the means of producing a reference value (docs/snp-measurement-prediction.md).
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
SEV_SNP_MEASURE_VERSION=0.0.13
VENV="${SEV_SNP_MEASURE_VENV:-$STACK/sev-snp-measure-venv}"

IMAGE="${1:?usage: predict-measurement.sh IMAGE_DIR [-vcpus N] [-vcpu-type T] [-out FILE]}"; shift
VCPUS=4; VCPU_TYPE=EPYC-v4; OUTFILE=""
while [ -n "${1:-}" ]; do
  case "$1" in
    -vcpus) VCPUS="$2"; shift 2 ;;
    -vcpu-type) VCPU_TYPE="$2"; shift 2 ;;
    -out) OUTFILE="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done
for f in OVMF.fd vmlinuz initrd.img cmdline.txt; do
  [ -f "$IMAGE/$f" ] || { echo "missing $IMAGE/$f" >&2; exit 1; }
done

# The tool, pinned. A different version is a different model of the PSP and
# must be re-cross-checked, so the version is refused rather than tolerated.
if [ ! -x "$VENV/bin/sev-snp-measure" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q "sev-snp-measure==$SEV_SNP_MEASURE_VERSION"
fi
GOT=$("$VENV/bin/sev-snp-measure" --version | awk '{print $2}')
[ "$GOT" = "$SEV_SNP_MEASURE_VERSION" ] || { echo "sev-snp-measure is $GOT, pinned $SEV_SNP_MEASURE_VERSION" >&2; exit 1; }

CMDLINE="$(cat "$IMAGE/cmdline.txt")"
M=$("$VENV/bin/sev-snp-measure" --mode snp --vmm-type QEMU \
      --vcpus "$VCPUS" --vcpu-type "$VCPU_TYPE" \
      --ovmf "$IMAGE/OVMF.fd" --kernel "$IMAGE/vmlinuz" --initrd "$IMAGE/initrd.img" \
      --append "$CMDLINE" --output-format hex)
[[ "$M" =~ ^[0-9a-f]{96}$ ]] || { echo "unexpected output from sev-snp-measure: $M" >&2; exit 1; }

REC="${OUTFILE:-/dev/stdout}"
{
  echo "# Predicted SEV-SNP launch measurement, computed offline from the inputs below."
  echo "# Not read from any machine. Cross-checked once: docs/snp-measurement-prediction.md."
  echo "launch_measurement: $M"
  echo
  echo "## Inputs (sha256 of each file as measured; cmdline is the -append string plus NUL)"
  (cd "$IMAGE" && sha256sum OVMF.fd vmlinuz initrd.img)
  printf '%s  cmdline (%d bytes + NUL)\n' "$(printf '%s' "$CMDLINE" | sha256sum | cut -d' ' -f1)" "${#CMDLINE}"
  echo "cmdline: $CMDLINE"
  echo "vcpus: $VCPUS"
  echo "vcpu_type: $VCPU_TYPE"
  echo "vmm: QEMU (sev-snp-guest, kernel-hashes=on; firmware OvmfPkg/AmdSev/AmdSevX64 with BlobVerifierLibSevHashes)"
  echo "guest_features: 0x1 (sev-snp-measure default: SNPActive)"
  echo "tool: sev-snp-measure $SEV_SNP_MEASURE_VERSION (pip, virtualenv $VENV)"
} > "$REC"
[ -n "$OUTFILE" ] && echo "$M"
exit 0
