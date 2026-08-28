#!/bin/bash
# The three probes, before anything else is built (gcp-two-vms.md, "Probes first").
#
#   probe-platform.sh [-out DIR] [-zone ZONE] [-keep]
#
# Each answer changes the shape of the run after it, and all three come from
# two throwaway confidential VMs and one raw report apiece:
#
#   1. Does the launch measurement cover the boot disk?  Two VMs of identical
#      shape from two different images; if MEASUREMENT differs, there is a
#      provider analogue of the measured image. If it does not, membership on
#      this provider means "some VM booted by the provider's firmware" and
#      nothing about the workload. The measurement is also looked up in the
#      provider's published launch endorsements (gs://gce_tcb_integrity): a hit
#      there is a signed statement by the provider that this is a measurement
#      of *their firmware*, which is the same answer from the other direction.
#   2. Is auxblob populated?  Ticket 01 found it empty on this host and no
#      operator action fills it, and ADR-0005 rests on that. A provider that
#      caches the VCEK on the VM fills it, and then ticket 01's finding is
#      host-specific, and so is ADR-0005's premise.
#   3. Do two VMs land on two chips?  CHIP_ID from each report.
#
# docs/snp/guest-evidence.sh reads the report and auxblob by hand, inside the
# VM, with no chain directory needed; docs/snp/parse-snp-report.py decodes
# them here. Nothing from attest/ runs in the cloud yet.
#
# What it creates, and deletes at the end unless -keep: two n2d-standard-2
# SEV-SNP instances named probe-a and probe-b. Flags are the provider's as of
# 2026-08-27 and belong here and in provision-vms.sh and nowhere else.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT="${OUT:-$REPO/docs/snp/evidence/cloud/probes}"
ZONE="${ZONE:-us-east1-b}"
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
exec > >(tee "$OUT/probes.txt") 2>&1
PROJECT=$(gcloud config get-value project 2>/dev/null)
echo "=== cloud probes: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "project $PROJECT zone $ZONE account $(gcloud config get-value account 2>/dev/null)"
echo "repo    $(git -C "$REPO" rev-parse HEAD)"
echo

# Two different images, identical shape otherwise. Debian 12 has no
# /dev/sev-guest and is not a candidate; both of these carry the guest driver
# and the configfs report interface.
declare -A IMAGE=( [probe-a]="ubuntu-os-cloud/ubuntu-2404-lts-amd64" [probe-b]="ubuntu-os-cloud/ubuntu-2204-lts" )

create() { # NAME PROJECT/FAMILY
  local name="$1" proj="${2%%/*}" family="${2##*/}"
  if gcloud compute instances describe "$name" --zone "$ZONE" >/dev/null 2>&1; then
    echo "$name exists already; reusing"; return
  fi
  echo "\$ gcloud compute instances create $name ($family)"
  gcloud compute instances create "$name" --zone "$ZONE" \
    --machine-type n2d-standard-2 --min-cpu-platform "AMD Milan" \
    --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
    --image-project "$proj" --image-family "$family" \
    --boot-disk-size 10GB --labels purpose=attested-tunnel-probe \
    --format 'value(name,zone,machineType,status)'
}
for n in probe-a probe-b; do create "$n" "${IMAGE[$n]}"; done
echo

ssh_vm() { gcloud compute ssh "$1" --zone "$ZONE" --quiet -- -o StrictHostKeyChecking=no -o ConnectTimeout=20 "${@:2}"; }
wait_ssh() {
  local name="$1" i
  for i in $(seq 1 30); do
    ssh_vm "$name" true 2>/dev/null && return 0
    sleep 10
  done
  echo "$name never answered ssh" >&2; return 1
}

for n in probe-a probe-b; do
  echo "### $n"
  wait_ssh "$n"
  d="$OUT/$n"; mkdir -p "$d"
  gcloud compute scp --zone "$ZONE" --quiet "$REPO/docs/snp/guest-evidence.sh" "$n:/tmp/guest-evidence.sh" >/dev/null
  ssh_vm "$n" 'uname -r; cat /etc/os-release | head -2; ls -l /dev/sev-guest 2>&1;
     sudo modprobe tsm 2>/dev/null; sudo modprobe sev-guest 2>/dev/null;
     sudo dmesg | grep -iE "SEV|Memory Encryption" | head -5;
     curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/machine-type"; echo;
     sudo bash /tmp/guest-evidence.sh /tmp/evidence' > "$d/guest-evidence.txt" 2>&1 || true
  sed -n '/===BEGIN report.bin===/,/===END report.bin===/p' "$d/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$d/report.bin" || true
  sed -n '/===BEGIN certs.bin===/,/===END certs.bin===/p'   "$d/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$d/certs.bin" || true
  grep -E '^(auxblob|outblob|provider)' "$d/guest-evidence.txt" || true
  if [ -s "$d/certs.bin" ]; then
    python3 "$REPO/docs/snp/parse-snp-report.py" "$d/report.bin" --certs "$d/certs.bin" --extract-certs "$d/certs" > "$d/report.txt" 2>&1 || true
  else
    python3 "$REPO/docs/snp/parse-snp-report.py" "$d/report.bin" > "$d/report.txt" 2>&1 || true
  fi
  grep -E 'LAUNCH MEASUREMENT|chip_id|current_tcb|reported_tcb|policy  |current firmware|family_id|image_id' "$d/report.txt" || true
  echo
done

m() { sed -n 's/^LAUNCH MEASUREMENT (M) : //p' "$OUT/$1/report.txt"; }
chip() { sed -n 's/^chip_id *: //p' "$OUT/$1/report.txt"; }
aux() { sed -n 's/^auxblob *: \([0-9]*\) bytes.*/\1/p' "$OUT/$1/guest-evidence.txt" | head -1; }

echo "=== answers ==="
MA=$(m probe-a); MB=$(m probe-b)
echo "1. launch measurement, ubuntu 24.04 : $MA"
echo "   launch measurement, ubuntu 22.04 : $MB"
if [ -n "$MA" ] && [ "$MA" = "$MB" ]; then
  echo "   SAME: the measurement does not cover the boot disk; it is over the provider's firmware."
else
  echo "   DIFFERENT (or missing): if different, there is a provider analogue of the measured image."
fi
for x in "$MA" "$MB"; do
  [ -n "$x" ] || continue
  url="https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/$x.binarypb"
  if curl -sf -o "$OUT/endorsement-$x.binarypb" "$url"; then
    echo "   provider endorsement for $x: PUBLISHED, $(stat -c %s "$OUT/endorsement-$x.binarypb") bytes ($url)"
  else
    echo "   provider endorsement for $x: not found at $url"
  fi
done
echo "2. auxblob probe-a: $(aux probe-a) bytes; probe-b: $(aux probe-b) bytes"
if [ "$(aux probe-a)" != "0" ] && [ -n "$(aux probe-a)" ]; then
  echo "   POPULATED: the provider fills the certificate table; ticket 01's finding is host-specific and so is ADR-0005's premise."
else
  echo "   EMPTY, as on this host."
fi
CA=$(chip probe-a); CB=$(chip probe-b)
echo "3. chip_id probe-a: $CA"
echo "   chip_id probe-b: $CB"
if [ -n "$CA" ] && [ "$CA" != "$CB" ]; then echo "   TWO CHIPS."; else echo "   ONE CHIP (or missing): ticket 14's situation with more steps."; fi

if [ "$KEEP" = 0 ]; then
  echo; echo "deleting probe-a probe-b"
  gcloud compute instances delete probe-a probe-b --zone "$ZONE" --quiet
fi
