#!/bin/bash
# What moves RTMR0 on a Google TDX VM: does attaching a second disk change it?
# (ticket 19, after the smoke boot said it does.)
#
#   probe-tdx-rtmr0.sh -config-image IMAGE [-out DIR] [-keep]
#
# The smoke boot's guest reported an RTMR0 that no reference value in this
# repository lists. Every RTMR0 on record here — five boots across four VMs
# between 2026-08-31 and 2026-09-10 — is c0b8b19c…896d, and the smoke guest
# said c2fc12a5…850a. Two things about that guest were new: it booted a custom
# image, and it had a second persistent disk attached for its config device.
# Only the second can plausibly reach RTMR0, which is the firmware's
# configuration rather than anything on a disk, so this probe changes exactly
# that and nothing else.
#
# One instance, the *stock* image, two boots:
#
#   boot 1  one disk. The control: it should reproduce the recorded value.
#   boot 2  the same instance with a second disk attached, and nothing else
#           touched. If RTMR0 moves here, the register counts devices.
#
# The instance is deleted at the end and a row is printed for RESOURCES.md.
# This probe reads registers off a running machine on purpose: RTMR0 is an
# observed constant of the provider, not a prediction, and the only way to learn
# what a provider does is to ask a machine and write down the answer
# (docs/tdx-rtmr2-prediction.md draws the line: RTMR2 is predicted, the rest are
# pinned from observation).
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
ZONE="${ZONE:-us-central1-a}"
VM="${VM:-tdx-rtmr0}"
IMAGE="${IMAGE:-ubuntu-2404-noble-amd64-v20260826}"
OUT="${OUT:-$REPO/docs/snp/evidence/ticket19/rtmr0}"
CONFIG_IMAGE=""
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    -config-image) CONFIG_IMAGE="$2"; shift 2 ;;
    -out) OUT="$2"; shift 2 ;;
    -keep) KEEP=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
: "${CONFIG_IMAGE:?-config-image IMAGE, a small custom image to attach as the second disk}"
mkdir -p "$OUT"; OUT="$(readlink -f "$OUT")"
exec > >(tee "$OUT/rtmr0-probe.txt") 2>&1

CREATED="" DELETED="(not deleted)" VERDICT="incomplete"
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  echo
  if [ "$KEEP" = 1 ]; then
    echo "keeping $VM (-keep); delete it with:"
    echo "  gcloud compute instances delete $VM --zone $ZONE --quiet"
    DELETED="(kept, -keep)"
  elif [ -n "$CREATED" ]; then
    echo "deleting $VM"
    if gcloud compute instances delete "$VM" --zone "$ZONE" --quiet; then
      DELETED="$(date -u +%Y-%m-%dT%H:%MZ)"
    else
      DELETED="**DELETE FAILED -- STILL RUNNING**"
    fi
    gcloud compute disks delete "$VM-probe-config" --zone "$ZONE" --quiet 2>/dev/null || true
  fi
  gcloud compute instances list --filter="labels.purpose=attested-tunnel-t19" --format='value(name,zone,status)' || true
  echo
  echo "############ for docs/snp/cloud/tdx/RESOURCES.md ############"
  echo "| created | name | type | purpose | state |"
  echo "|---|---|---|---|---|"
  printf '| %s | %s (+ disk %s-probe-config) | c3-standard-4 TDX, %s, 20GB pd-balanced, stock image `%s` | ticket 19: does attaching a second disk move RTMR0? two boots of one instance, one disk then two | **deleted %s** |\n' \
    "${CREATED:-(never created)}" "$VM" "$VM" "$ZONE" "$IMAGE" "$DELETED"
  echo
  echo "verdict: $VERDICT"
  echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ), exit $rc ==="
  exit "$rc"
}
trap cleanup EXIT
trap 'echo interrupted; exit 130' INT TERM

echo "=== RTMR0 probe (ticket 19): $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "project $(gcloud config get-value project 2>/dev/null) zone $ZONE image $IMAGE"
echo "second disk from image $CONFIG_IMAGE"
echo

ssh_vm() { gcloud compute ssh "$VM" --zone "$ZONE" --quiet -- -o StrictHostKeyChecking=no -o ConnectTimeout=20 "$@"; }
wait_ssh() { local i; for i in $(seq 1 40); do ssh_vm true 2>/dev/null && return 0; sleep 10; done; echo "never answered ssh" >&2; return 1; }
boot_id() { ssh_vm cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n'; }

gather() {
  local label="$1" d="$OUT/$1"; mkdir -p "$d"
  gcloud compute scp --zone "$ZONE" --quiet "$HERE/guest-evidence-tdx.sh" "$VM:/tmp/guest-evidence-tdx.sh" >/dev/null
  ssh_vm 'sudo bash /tmp/guest-evidence-tdx.sh /tmp/evidence' > "$d/guest-evidence.txt" 2>&1 || true
  sed -n '/===BEGIN quote.bin===/,/===END quote.bin===/p' "$d/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$d/quote.bin" 2>/dev/null || true
  [ -s "$d/quote.bin" ] && python3 "$HERE/parse-tdx-quote.py" "$d/quote.bin" > "$d/quote.txt" 2>&1 || true
  ssh_vm 'lsblk -o NAME,SERIAL,SIZE,TYPE; echo; ls -l /dev/disk/by-id/ | sed "s/^/by-id: /"' > "$d/disks.txt" 2>&1 || true
  echo "--- $label ---"
  sed -n 's/^\(mrtd\|rtmr0\|rtmr1\|rtmr2\) *: /  &/p' "$d/quote.txt" 2>/dev/null || echo "  (no quote)"
}

CREATED="$(date -u +%Y-%m-%dT%H:%MZ)"
echo "############ creating $VM at $CREATED, with one disk ############"
gcloud beta compute instances create "$VM" --zone "$ZONE" \
  --machine-type c3-standard-4 \
  --confidential-compute-type TDX --maintenance-policy TERMINATE \
  --image-project ubuntu-os-cloud --image "$IMAGE" \
  --boot-disk-size 20GB --boot-disk-type pd-balanced --boot-disk-auto-delete \
  --labels purpose=attested-tunnel-t19 \
  --format 'value(name,zone,machineType,status)'
wait_ssh
gather one-disk
echo

echo "############ attaching a second disk and rebooting ############"
gcloud compute disks create "$VM-probe-config" --zone "$ZONE" \
  --image "$CONFIG_IMAGE" --size 10GB --type pd-balanced \
  --labels purpose=attested-tunnel-t19 --format 'value(name,sizeGb)'
gcloud compute instances attach-disk "$VM" --zone "$ZONE" \
  --disk "$VM-probe-config" --device-name attested-config
OLD=$(boot_id)
ssh_vm 'sudo systemctl reboot' >/dev/null 2>&1 || true
for i in $(seq 1 60); do
  sleep 10
  NOW=$(boot_id) || true
  if [ -n "$NOW" ] && [ "$NOW" != "$OLD" ]; then echo "  boot_id $OLD -> $NOW (barrier crossed on attempt $i)"; break; fi
done
gather two-disks
echo

R1=$(sed -n 's/^rtmr0 *: //p' "$OUT/one-disk/quote.txt" 2>/dev/null || true)
R2=$(sed -n 's/^rtmr0 *: //p' "$OUT/two-disks/quote.txt" 2>/dev/null || true)
M1=$(sed -n 's/^rtmr1 *: //p' "$OUT/one-disk/quote.txt" 2>/dev/null || true)
M2=$(sed -n 's/^rtmr1 *: //p' "$OUT/two-disks/quote.txt" 2>/dev/null || true)
{
  echo "rtmr0, one disk : $R1"
  echo "rtmr0, two disks: $R2"
  echo "rtmr1, one disk : $M1"
  echo "rtmr1, two disks: $M2"
} | tee "$OUT/rtmr0.txt"
if [ -n "$R1" ] && [ -n "$R2" ] && [ "$R1" != "$R2" ]; then
  VERDICT="RTMR0 MOVES when a second disk is attached: $R1 -> $R2"
elif [ -n "$R1" ] && [ "$R1" = "$R2" ]; then
  VERDICT="RTMR0 is unchanged by the second disk ($R1); something else moved it on the smoke guest"
else
  VERDICT="INCOMPLETE: one of the two boots produced no quote"
fi
echo "$VERDICT"
