#!/bin/bash
# Ticket 16, the on-hardware half: does RTMR2 hold still across the three things
# the study left untested -- `update-grub`, a boot after a failed boot, and a
# kernel upgrade -- and, where it moves, can the new value still be predicted
# from the disk bytes alone?
#
#   probe-tdx-upgrade.sh [-out DIR] [-zone ZONE] [-image NAME] [-keep]
#
# One c3-standard-4 TDX instance, tdx-upgrade, booted from the SAME pinned
# image the ticket's CCEL came from (not the family alias, which has rolled),
# crossing four boots with the boot_id barrier from probe-tdx-mutate.sh:
#
#   boot 1  baseline       fresh image                       (expect: the known RTMR2)
#   boot 2  update-grub    `update-grub` with nothing changed (expect: unchanged if grub.cfg bytes are)
#   boot 3  recordfail     grubenv has recordfail=1, as after a boot that never
#                          reached grub-common's `unset`   (expect: MOVES; grub takes the other branch)
#   boot 4  kernel-upgrade newest linux-image-gcp installed   (expect: MOVES)
#
# Before every reboot the run captures the disk state grub will see -- the
# whole of /boot (grub tree, kernels, initrds) and the ESP's EFI/ tree -- as a
# tarball, so that predict-rtmr2.py can be run on those bytes on the
# workstation and its output compared with the quote the NEXT boot produces.
# The tarball is files read from a filesystem, before the boot whose register
# it predicts; no register is ever read into a prediction. After every boot
# the run also records the sha256 of the same files so a tarball can be shown
# to be what was actually booted.
#
# Every sample is quote + CCEL, so a mismatch can be diffed at the record.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT="${OUT:-$REPO/docs/snp/evidence/tdx/predict/upgrade}"
ZONE="${ZONE:-us-central1-a}"
IMAGE="${IMAGE:-ubuntu-2404-noble-amd64-v20260826}"
VM=tdx-upgrade
KEEP=0
while [ -n "${1:-}" ]; do
  case "$1" in
    -out)   OUT="$2"; shift 2 ;;
    -zone)  ZONE="$2"; shift 2 ;;
    -image) IMAGE="$2"; shift 2 ;;
    -keep)  KEEP=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"
exec > >(tee "$OUT/upgrade.txt") 2>&1
echo "=== TDX upgrade/stability probe: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "project $(gcloud config get-value project 2>/dev/null) zone $ZONE image $IMAGE"
echo "repo    $(git -C "$REPO" rev-parse HEAD)"
echo

if ! gcloud compute instances describe "$VM" --zone "$ZONE" >/dev/null 2>&1; then
  gcloud beta compute instances create "$VM" --zone "$ZONE" \
    --machine-type c3-standard-4 \
    --confidential-compute-type TDX --maintenance-policy TERMINATE \
    --image-project ubuntu-os-cloud --image "$IMAGE" \
    --boot-disk-size 20GB --boot-disk-type pd-balanced \
    --labels purpose=tdx-feasibility-probe \
    --format 'value(name,zone,machineType,status)'
else
  echo "$VM exists already; reusing"
fi
echo

ssh_vm() { gcloud compute ssh "$VM" --zone "$ZONE" --quiet -- -o StrictHostKeyChecking=no -o ConnectTimeout=20 "$@"; }
wait_ssh() { local i; for i in $(seq 1 40); do ssh_vm true 2>/dev/null && return 0; sleep 10; done; echo "never answered ssh" >&2; return 1; }
boot_id() { ssh_vm cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n'; }

reboot_and_wait() {
  local old="$1" i now
  ssh_vm 'sudo systemctl reboot' >/dev/null 2>&1 || true
  for i in $(seq 1 60); do
    sleep 10
    now=$(boot_id) || true
    if [ -n "$now" ] && [ "$now" != "$old" ]; then
      echo "  boot_id $old -> $now (barrier crossed on attempt $i)"
      return 0
    fi
  done
  echo "  BARRIER NEVER CROSSED (boot_id still $old); the sample after this is not trustworthy"
  return 1
}

# The files grub reads, hashed, so a boot can be tied to the bytes it saw.
BOOTFILES='/boot/efi/EFI/ubuntu/grub.cfg /boot/efi/EFI/ubuntu/shimx64.efi /boot/efi/EFI/ubuntu/grubx64.efi
           /boot/grub/grub.cfg /boot/grub/grubenv /boot/grub/x86_64-efi/command.lst /boot/grub/x86_64-efi/fs.lst
           /boot/grub/x86_64-efi/crypto.lst /boot/grub/x86_64-efi/terminal.lst /boot/grub/x86_64-efi/bli.mod /boot/vmlinuz-*'

# gather LABEL -- quote, CCEL, and the state of the boot that produced them.
gather() {
  local d="$OUT/$1"; mkdir -p "$d"
  gcloud compute scp --zone "$ZONE" --quiet "$HERE/guest-evidence-tdx.sh" "$VM:/tmp/guest-evidence-tdx.sh" >/dev/null
  ssh_vm 'sudo bash /tmp/guest-evidence-tdx.sh /tmp/evidence' > "$d/guest-evidence.txt" 2>&1 || true
  sed -n '/===BEGIN quote.bin===/,/===END quote.bin===/p' "$d/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$d/quote.bin" 2>/dev/null || true
  [ -s "$d/quote.bin" ] && python3 "$HERE/parse-tdx-quote.py" "$d/quote.bin" > "$d/quote.txt" 2>&1 || true
  ssh_vm 'sudo base64 -w 100 /sys/firmware/acpi/tables/data/CCEL' > "$d/ccel.b64" 2>/dev/null || true
  base64 -d < "$d/ccel.b64" > "$d/ccel.bin" 2>/dev/null || true
  ssh_vm "echo \"boot_id : \$(cat /proc/sys/kernel/random/boot_id)\";
          echo \"cmdline : \$(cat /proc/cmdline)\";
          echo \"kernel  : \$(uname -r)\";
          echo '--- sha256 of what grub read, as of this boot ---';
          sudo sha256sum $BOOTFILES 2>&1;
          echo '--- grubenv as of this boot (after grub-common ran) ---';
          sudo grub-editenv /boot/grub/grubenv list 2>&1" > "$d/state.txt" 2>&1 || true
  echo "--- $1 ---"; head -3 "$d/state.txt"
  grep -E '^(rtmr2)' "$d/quote.txt" 2>/dev/null || echo "  (no quote)"
  echo "  ccel $(stat -c %s "$d/ccel.bin" 2>/dev/null || echo 0) bytes"
}

# snapshot LABEL -- the disk bytes grub will see at the NEXT boot: /boot and
# the ESP's EFI tree, as a tarball in the mounted-root layout predict-rtmr2.py
# takes, plus the sha256 list and the partition table so (hd0,gptN) can be named.
snapshot() {
  local d="$OUT/$1"; mkdir -p "$d"
  ssh_vm "sudo tar -C / -cf /tmp/bootstate.tar boot/grub boot/efi/EFI \$(cd / && ls -d boot/vmlinuz-* boot/initrd.img-* boot/config-* 2>/dev/null | grep -v '\.old\$' | tr '\n' ' ') && sudo chmod a+r /tmp/bootstate.tar;
          echo '--- sha256 of what grub will read at the next boot ---';
          sudo sha256sum $BOOTFILES 2>&1;
          echo '--- partitions ---';
          lsblk -o NAME,PARTUUID,UUID,MOUNTPOINTS,SIZE 2>&1;
          echo '--- grubenv bytes ---';
          sudo base64 -w 100 /boot/grub/grubenv" > "$d/pre-boot-state.txt" 2>&1 || true
  gcloud compute scp --zone "$ZONE" --quiet "$VM:/tmp/bootstate.tar" "$d/bootstate.tar" >/dev/null 2>&1 || true
  echo "  snapshot for $1: $(stat -c %s "$d/bootstate.tar" 2>/dev/null || echo 0) bytes"
}

wait_ssh
echo "############ boot 1: baseline, the pinned image untouched ############"
gather baseline
B=$(boot_id)
echo

echo "############ boot 2: update-grub with nothing changed ############"
ssh_vm 'echo "grub.cfg before: $(sudo sha256sum /boot/grub/grub.cfg | cut -c1-32)"; sudo update-grub 2>&1 | tail -5;
        echo "grub.cfg after : $(sudo sha256sum /boot/grub/grub.cfg | cut -c1-32)"' | tee "$OUT/update-grub.log"
snapshot update-grub
reboot_and_wait "$B" || true
gather update-grub
B=$(boot_id)
echo

echo "############ boot 3: after a failed boot (recordfail=1 left in grubenv) ############"
ssh_vm 'sudo grub-editenv /boot/grub/grubenv set recordfail=1; sudo grub-editenv /boot/grub/grubenv list' | tee "$OUT/recordfail.log"
snapshot recordfail
reboot_and_wait "$B" || true
gather recordfail
B=$(boot_id)
echo

echo "############ boot 4: kernel upgrade ############"
ssh_vm 'sudo apt-get update -qq 2>&1 | tail -2; echo "candidate: $(apt-cache policy linux-image-gcp | grep -E "Installed|Candidate" | tr "\n" " ")";
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-image-gcp linux-modules-gcp 2>&1 | grep -E "^(Setting up|Unpacking|Processing|Generating|Found|done|Sourcing|Adding|update-initramfs)" | head -40;
        echo "kernels on disk now: $(ls /boot/vmlinuz-* | tr "\n" " ")"' | tee "$OUT/kernel-upgrade.log"
snapshot kernel-upgrade
reboot_and_wait "$B" || true
gather kernel-upgrade
echo

echo "############ registers across the four boots ############"
f() { sed -n "s/^$2 *: //p" "$OUT/$1/quote.txt" 2>/dev/null; }
for s in baseline update-grub recordfail kernel-upgrade; do
  printf '%-15s rtmr2 %s\n' "$s" "$(f $s rtmr2)"
done
echo "(the prediction for each is made on the workstation from that boot's bootstate.tar; see predict-rtmr2.py)"
echo

if [ "$KEEP" = 1 ]; then
  echo "keeping $VM (-keep)"
else
  echo "deleting $VM"
  gcloud compute instances delete "$VM" --zone "$ZONE" --quiet
fi
echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
