#!/bin/bash
# Launch one guest of a ticket-14 two-guest run.
#
#   tunnel-guest.sh -image DIR -config IMG -relay HOST:PORT -console FILE
#                   [-mac MAC] [-mem MB] [-smp N] [-no-snp] [-firmware FILE]
#                   [-print]
#
# It is docs/snp/image/launch-measured-guest.sh with one thing changed, and the
# change is the only interesting thing about this script: the guest's network
# is a socket to docs/snp/l2relay.py rather than QEMU's user-mode NAT.
#
#   -netdev socket,connect=HOST:PORT
#
# That gives the two guests one ethernet segment with nothing else on it: no
# gateway, no resolver, no route off it, and no host stack in the middle. A
# guest on it can reach the other guest and nothing else, so "the exchange
# completes with egress to the vendor blocked" is a property of the topology
# rather than of a firewall rule that could have been written wrongly — and the
# relay in the middle is the on-path attacker at the same time.
#
# Everything the launch measurement covers is passed exactly as
# launch-measured-guest.sh passes it: the same four measured inputs from IMAGE,
# the same -cpu and -smp, the same policy. If any of those drifts from what
# predict-measurement.sh was given, the guest reports a measurement no peer
# admits, which is a confusing way to discover a typo.
#
# SNP needs root for /dev/sev, so this is what a spooled .job file runs.
# -no-snp is a control boot and needs only /dev/kvm; like the launch script's,
# it cannot use the image's own firmware, because AmdSevX64 refuses every
# fw_cfg blob when no hashes table was written.
set -eu
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || echo "$HERE/../..")"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
QEMU="${QEMU:-$STACK/usr/local/bin/qemu-system-x86_64}"
IMAGE=""; CONFIG=""; RELAY=""; CONSOLE=""; MAC="52:54:00:14:00:0a"
MEM=2048; SMP=4; SNP=1; FIRMWARE=""; PRINT=0
while [ -n "${1:-}" ]; do
  case "$1" in
    -image)    IMAGE="$2"; shift 2 ;;
    -config)   CONFIG="$2"; shift 2 ;;
    -relay)    RELAY="$2"; shift 2 ;;
    -console)  CONSOLE="$2"; shift 2 ;;
    -mac)      MAC="$2"; shift 2 ;;
    -mem)      MEM="$2"; shift 2 ;;
    -smp)      SMP="$2"; shift 2 ;;
    -no-snp)   SNP=0; shift ;;
    -firmware) FIRMWARE="$2"; shift 2 ;;
    -print)    PRINT=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done
[ -n "$IMAGE" ] && [ -n "$CONFIG" ] && [ -n "$RELAY" ] || { echo "need -image, -config and -relay" >&2; exit 1; }
for f in OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img; do
  [ -f "$IMAGE/$f" ] || { echo "missing $IMAGE/$f" >&2; exit 1; }
done
[ -f "$CONFIG" ] || { echo "missing config device $CONFIG" >&2; exit 1; }
[ -x "$QEMU" ] || { echo "missing QEMU at $QEMU" >&2; exit 1; }
CMDLINE="$(cat "$IMAGE/cmdline.txt")"
if [ -z "$FIRMWARE" ]; then
  if [ "$SNP" = 1 ]; then FIRMWARE="$IMAGE/OVMF.fd"
  else FIRMWARE="$STACK/usr/local/share/qemu/OVMF.fd"
       echo "control boot: non-verifying firmware $FIRMWARE, not the image's" >&2
  fi
fi

ARGS=(
  -enable-kvm
  -cpu "EPYC-v4,+la57,phys-bits=52"
  -machine q35,vmport=off
  -smp "$SMP,maxcpus=$SMP"
  -m "${MEM}M"
  -no-reboot -nodefaults -display none
  -bios "$FIRMWARE"
  -kernel "$IMAGE/vmlinuz"
  -initrd "$IMAGE/initrd.img"
  -append "$CMDLINE"
  -object "memory-backend-memfd,id=ram1,size=${MEM}M,share=true,prealloc=false"
  -machine memory-backend=ram1
  -drive "file=$IMAGE/rootfs.img,if=none,id=rootfs,format=raw,readonly=on"
  -device "virtio-blk-pci,drive=rootfs,serial=attested-rootfs,disable-legacy=on,iommu_platform=true"
  -drive "file=$CONFIG,if=none,id=config,format=raw,readonly=on"
  -device "virtio-blk-pci,drive=config,serial=attested-config,disable-legacy=on,iommu_platform=true"
  -netdev "socket,id=net0,connect=$RELAY"
  -device "virtio-net-pci,netdev=net0,mac=$MAC,disable-legacy=on,iommu_platform=true,romfile="
)
if [ -n "$CONSOLE" ]; then ARGS+=( -serial "file:$CONSOLE" ); else ARGS+=( -serial stdio ); fi
if [ "$SNP" = 1 ]; then
  [ "$(id -u)" -eq 0 ] || { echo "SNP launch must run as root (opens /dev/sev); -no-snp is the control" >&2; exit 1; }
  modprobe cpuid 2>/dev/null || true
  EBX=$(dd if=/dev/cpu/0/cpuid ibs=16 count=32 skip=134217728 2>/dev/null \
        | tail -c 16 | od -An -t u4 -j 4 -N 4 | tr -d ' ')
  CBITPOS=$((EBX & 0x3f)); REDUCED=$(((EBX >> 6) & 0x3f))
  # Policy 0x30000 and kernel-hashes=on, exactly as the prediction assumes:
  # SMT allowed, DEBUG clear, and the kernel, initrd and command line hashed
  # into the firmware's table before the measurement is taken.
  ARGS+=( -machine confidential-guest-support=sev0
          -object "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=$CBITPOS,reduced-phys-bits=$REDUCED,kernel-hashes=on" )
fi
if [ -n "$CONSOLE" ]; then printf '%q ' "$QEMU" "${ARGS[@]}" > "$CONSOLE.qemu-cmdline"; echo >> "$CONSOLE.qemu-cmdline"; fi
if [ "$PRINT" = 1 ]; then printf '%q ' "$QEMU" "${ARGS[@]}"; echo; exit 0; fi
exec "$QEMU" "${ARGS[@]}"
