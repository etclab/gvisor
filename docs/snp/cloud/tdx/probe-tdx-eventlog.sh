#!/bin/bash
# The question probes 1 to 3 raise but cannot answer: is an RTMR value
# *interpretable*, or only comparable?
#
#   probe-tdx-eventlog.sh [-out DIR] [-zone ZONE] [-keep]
#
# refvals.go says a launch measurement "is a prediction computed offline from
# the image build inputs, not a value read off a booted guest — a measurement
# learned by asking the machine is not a prediction, and a check built on one
# cannot fail." An RTMR is a hash chain, so a bare RTMR value satisfies neither
# half: it cannot be predicted from a disk image without knowing every
# extension in order, and reading one off a running VM is exactly the thing
# that sentence forbids.
#
# The mechanism that would change that is the Confidential Computing Event Log:
# a UEFI-format record of every measurement made into an RTMR, exposed to the
# guest through the CCEL ACPI table, which a verifier replays to check that the
# events it was given hash to the RTMR the quote carries. With it, an RTMR
# becomes a statement about named components. Without it, an RTMR is an opaque
# 48 bytes whose only use is comparison against another observation.
#
# So this asks three things of a stock GCP TDX guest, and nothing else:
#   1. Is the CCEL ACPI table present, and is its data readable by the guest?
#   2. How many events does it hold, and which RTMRs do they extend?
#   3. Do those events, replayed, reproduce the RTMRs in the quote?
#
# One c3-standard-4 TDX instance, tdx-eventlog, deleted at the end unless -keep.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT="${OUT:-$REPO/docs/snp/evidence/tdx/eventlog}"
ZONE="${ZONE:-us-central1-a}"
VM=tdx-eventlog
KEEP=0
while [ -n "${1:-}" ]; do
  case "$1" in
    -out)  OUT="$2"; shift 2 ;;
    -zone) ZONE="$2"; shift 2 ;;
    -keep) KEEP=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"
exec > >(tee "$OUT/eventlog.txt") 2>&1
echo "=== TDX event log probe: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "project $(gcloud config get-value project 2>/dev/null) zone $ZONE"
echo "repo    $(git -C "$REPO" rev-parse HEAD)"
echo

if ! gcloud compute instances describe "$VM" --zone "$ZONE" >/dev/null 2>&1; then
  gcloud beta compute instances create "$VM" --zone "$ZONE" \
    --machine-type c3-standard-4 \
    --confidential-compute-type TDX --maintenance-policy TERMINATE \
    --image-project ubuntu-os-cloud --image-family ubuntu-2404-lts-amd64 \
    --boot-disk-size 20GB --boot-disk-type pd-balanced \
    --labels purpose=tdx-feasibility-probe \
    --format 'value(name,zone,machineType,status)'
else
  echo "$VM exists already; reusing"
fi
echo

ssh_vm() { gcloud compute ssh "$VM" --zone "$ZONE" --quiet -- -o StrictHostKeyChecking=no -o ConnectTimeout=20 "$@"; }
for i in $(seq 1 40); do ssh_vm true 2>/dev/null && break; sleep 10; done

gcloud compute scp --zone "$ZONE" --quiet "$HERE/guest-evidence-tdx.sh" "$VM:/tmp/guest-evidence-tdx.sh" >/dev/null
gcloud compute scp --zone "$ZONE" --quiet "$HERE/replay-ccel.py" "$VM:/tmp/replay-ccel.py" >/dev/null

echo "### 1. is the CCEL table there?"
ssh_vm 'ls -l /sys/firmware/acpi/tables/CCEL /sys/firmware/acpi/tables/data/CCEL 2>&1;
        echo "--- all ACPI tables that look confidential ---";
        ls /sys/firmware/acpi/tables/ | grep -iE "ccel|tdel|tpm|eventlog" || echo "(none matched)";
        echo "--- can the guest read the data table? ---";
        sudo head -c 64 /sys/firmware/acpi/tables/data/CCEL 2>&1 | od -An -t x1 | head -4' 2>&1 | tee "$OUT/ccel-present.txt"
echo

echo "### 2 and 3. the events, and whether they replay to the quote"
ssh_vm 'sudo bash /tmp/guest-evidence-tdx.sh /tmp/evidence >/tmp/ev.txt 2>&1;
        sudo python3 /tmp/replay-ccel.py /tmp/evidence/quote.bin' 2>&1 | tee "$OUT/replay.txt"
ssh_vm 'sudo cat /tmp/evidence/quote.bin | base64 -w 100' > "$OUT/quote.b64" 2>/dev/null || true
base64 -d < "$OUT/quote.b64" > "$OUT/quote.bin" 2>/dev/null || true
ssh_vm 'sudo base64 -w 100 /sys/firmware/acpi/tables/data/CCEL' > "$OUT/ccel.b64" 2>/dev/null || true
base64 -d < "$OUT/ccel.b64" > "$OUT/ccel.bin" 2>/dev/null || true
echo
echo "recovered: quote.bin $(stat -c %s "$OUT/quote.bin" 2>/dev/null || echo 0) bytes, ccel.bin $(stat -c %s "$OUT/ccel.bin" 2>/dev/null || echo 0) bytes"

if [ "$KEEP" = 0 ]; then
  echo; echo "deleting $VM"
  gcloud compute instances delete "$VM" --zone "$ZONE" --quiet
fi
echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
gcloud compute instances list --filter="labels.purpose=tdx-feasibility-probe" --format='value(name,zone,status)' || true
