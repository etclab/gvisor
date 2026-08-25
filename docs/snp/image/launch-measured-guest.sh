#!/bin/bash
# Launch the measured image built by build-image.sh.
#
#   launch-measured-guest.sh [-image DIR] [-config IMG] [-no-snp] [-mem MB] [-smp N] [-console FILE]
#
# The four measured inputs come from DIR: OVMF.fd (via -bios: an SNP guest has
# no variable store, so the unified image, never the split pflash pair),
# vmlinuz, initrd.img and cmdline.txt, passed verbatim. Nothing on this command
# line except those four, the vCPU count and the SEV policy affects the launch
# measurement; the disks do not.
#
# The root filesystem and the config device are virtio-blk, read-only, and
# identified inside the guest by serial, not by probe order.
#
# SNP launch needs root (/dev/sev). -no-snp is a plain KVM control boot of the
# same kernel, initrd, command line and root filesystem and needs only
# /dev/kvm. It cannot use the image's own firmware: AmdSevX64 refuses every
# fw_cfg blob when no hashes table was written (there is no sev object to
# write one), which is its fail-closed design. The control therefore boots
# with ticket 01's non-verifying OVMF.fd, and the guest reports that
# sev-guest will not load. -firmware overrides either choice.
set -eu
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || echo "$HERE/../../..")"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
QEMU="${QEMU:-$STACK/usr/local/bin/qemu-system-x86_64}"
IMAGE="$STACK/image"; CONFIG=""; SNP=1; MEM=2048; SMP=4; CONSOLE=""; REDUCED_OVERRIDE=""; FIRMWARE=""
while [ -n "${1:-}" ]; do
  case "$1" in
    -image)   IMAGE="$2"; shift 2 ;;
    -config)  CONFIG="$2"; shift 2 ;;
    -no-snp)  SNP=0; shift ;;
    -mem)     MEM="$2"; shift 2 ;;
    -smp)     SMP="$2"; shift 2 ;;
    -console) CONSOLE="$2"; shift 2 ;;
    -firmware) FIRMWARE="$2"; shift 2 ;;
    -reduced-phys-bits) REDUCED_OVERRIDE="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done
for f in OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img; do
  [ -f "$IMAGE/$f" ] || { echo "missing $IMAGE/$f" >&2; exit 1; }
done
[ -x "$QEMU" ] || { echo "missing QEMU at $QEMU" >&2; exit 1; }
CMDLINE="$(cat "$IMAGE/cmdline.txt")"
if [ -z "$FIRMWARE" ]; then
  if [ "$SNP" = 1 ]; then FIRMWARE="$IMAGE/OVMF.fd"
  else FIRMWARE="$STACK/usr/local/share/qemu/OVMF.fd"
       echo "control boot: using non-verifying firmware $FIRMWARE, not the image's" >&2
  fi
fi
[ -f "$FIRMWARE" ] || { echo "missing firmware $FIRMWARE" >&2; exit 1; }

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
  -netdev user,id=vmnic
  -device "virtio-net-pci,netdev=vmnic,disable-legacy=on,iommu_platform=true,romfile="
)
if [ -n "$CONFIG" ]; then
  [ -f "$CONFIG" ] || { echo "missing config device image $CONFIG" >&2; exit 1; }
  ARGS+=( -drive "file=$CONFIG,if=none,id=config,format=raw,readonly=on"
          -device "virtio-blk-pci,drive=config,serial=attested-config,disable-legacy=on,iommu_platform=true" )
fi
if [ -n "$CONSOLE" ]; then ARGS+=( -serial "file:$CONSOLE" ); else ARGS+=( -serial stdio ); fi

if [ "$SNP" = 1 ]; then
  [ "$(id -u)" -eq 0 ] || { echo "SNP launch must run as root (opens /dev/sev); use -no-snp for a control boot" >&2; exit 1; }
  # C-bit position and reduced-phys-bits from CPUID 0x8000001F EBX, as ticket 01's script does.
  modprobe cpuid 2>/dev/null || true
  EBX=$(dd if=/dev/cpu/0/cpuid ibs=16 count=32 skip=134217728 2>/dev/null \
        | tail -c 16 | od -An -t u4 -j 4 -N 4 | tr -d ' ')
  CBITPOS=$((EBX & 0x3f)); REDUCED=$(((EBX >> 6) & 0x3f))
  [ -n "$REDUCED_OVERRIDE" ] && REDUCED="$REDUCED_OVERRIDE"
  # Policy 0x30000: SMT allowed + reserved-must-be-one. DEBUG (bit 19) deliberately clear.
  # kernel-hashes=on: QEMU writes SHA-256 of kernel, initrd and command line into
  # the firmware's hashes table before the launch measurement is taken, and the
  # AmdSevX64 firmware refuses any blob that does not match. Without it the
  # three are not measured at all.
  ARGS+=( -machine confidential-guest-support=sev0
          -object "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=$CBITPOS,reduced-phys-bits=$REDUCED,kernel-hashes=on" )
fi
printf '%q ' "$QEMU" "${ARGS[@]}" > "$IMAGE/last-qemu-cmdline.txt"; echo >> "$IMAGE/last-qemu-cmdline.txt"
exec "$QEMU" "${ARGS[@]}"
