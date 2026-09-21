#!/bin/bash
# E5's local guest: the TDX image's kernel and initrd under plain KVM.
#
#   KERNEL=… INITRD=… DEV=… OUT=…/output-NN-name.txt boot-local.sh
#
# What this reproduces and what it does not. The kernel is the 6.17.0-1022-gcp
# vmlinuz the build took out of the pinned Ubuntu base image, and the initrd is a
# gzip of the same cpio list — so /init, busybox, runsc, tunneld and the modules
# are the same files, byte for byte, that grub measured into RTMR2 on the
# hardware. What is absent is everything TDX: no TD, no MRTD, no RTMR, no
# tsm_report, no gve. So `insmod tdx-guest` fails, the report interface is
# missing, and tunneld can acquire no evidence and says so.
#
# None of that is in the way, because the thing E5 is looking at happens before
# any of it matters. init.tdx's order is: modules, ceiling, config device,
# workload device, network, egress proof, **the workload under runsc**, tunneld.
# The workload is step 8 and tunneld is step 9, so a guest that gets as far as
# step 8 has answered E5's question whether or not step 9 can do anything.
#
# The one thing that must work for step 8 to be reached is step 6, the network,
# because a link that will not come up is fatal in init.tdx. That is why there is
# a NIC here and why network.conf carries QEMU's user-networking addressing.
#
# Both disks are found by their ext4 volume label. That is not a shortcut: E4
# showed it is the branch the hardware takes too, because there is no udev in the
# guest to turn --device-name into an NVMe serial. virtio-blk instead of NVMe
# changes the device node in the transcript and nothing else.
set -euo pipefail
QEMU="${QEMU:-/home/pniroula/Projects/gvisor/.scratch/attested-secure-tunnel/host-stack/usr/local/bin/qemu-system-x86_64}"
KERNEL="${KERNEL:?set KERNEL to the vmlinuz the TDX build used}"
INITRD="${INITRD:?set INITRD to the initrd to boot}"
DEV="${DEV:?set DEV to the directory holding config.raw and workload.raw}"
OUT="${OUT:?set OUT to the console file to write}"
MEM="${MEM:-2048}"
SMP="${SMP:-2}"
DEADLINE="${DEADLINE:-300}"

[ -r /dev/kvm ] || { echo "no /dev/kvm" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")"
: > "$OUT"

echo "=== E5 local boot $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "kernel  $KERNEL ($(stat -c %s "$KERNEL") bytes, sha256 $(sha256sum "$KERNEL" | cut -d' ' -f1))"
echo "initrd  $INITRD ($(stat -c %s "$INITRD") bytes, sha256 $(sha256sum "$INITRD" | cut -d' ' -f1))"
echo "config  $DEV/config.raw   sha256 $(sha256sum "$DEV/config.raw" | cut -d' ' -f1)"
echo "workload $DEV/workload.raw sha256 $(sha256sum "$DEV/workload.raw" | cut -d' ' -f1)"
echo "console $OUT"

set +e
timeout -k 5 "$DEADLINE" "$QEMU" \
  -enable-kvm -cpu host -m "$MEM" -smp "$SMP" \
  -nodefaults -display none -no-reboot \
  -kernel "$KERNEL" -initrd "$INITRD" \
  -append "console=ttyS0,115200 panic=-1 rdinit=/init" \
  -serial "file:$OUT" \
  -drive "file=$DEV/config.raw,if=none,id=cfg,format=raw,readonly=on" \
  -device virtio-blk-pci,drive=cfg \
  -drive "file=$DEV/workload.raw,if=none,id=wl,format=raw,readonly=on" \
  -device virtio-blk-pci,drive=wl \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0
rc=$?
set -e
echo "=== qemu exit $rc at $(date -u +%Y-%m-%dT%H:%M:%SZ); $(wc -l < "$OUT") console lines"
grep -nE 'initrd: (the workload|running:|workload exited|uptime|no workload)|4\.19\.0-gvisor|cannot (create|read)|EXIT status' "$OUT" || true
