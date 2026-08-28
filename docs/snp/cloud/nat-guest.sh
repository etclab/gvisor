#!/bin/bash
# Launch the measured guest with a way off its segment (the cloud run).
#
#   nat-guest.sh -image DIR -config IMG -console FILE -pcap FILE
#                [-mac MAC] [-mem MB] [-smp N] [-no-snp] [-firmware FILE] [-print]
#
# It is docs/snp/tunnel-guest.sh with the netdev changed back to what
# launch-measured-guest.sh uses — QEMU's user-mode networking — and one thing
# added. In a ticket-14 run the guest's only link was a socket to l2relay.py,
# a segment with no gateway, and "no egress to the vendor" was a property of
# that wiring. Here the guest has to reach a public address, so it sits behind
# QEMU's NAT (10.0.2.0/24, gateway 10.0.2.2) with this host's unrestricted
# egress beyond it, and there *is* a path to the vendor now. What replaces the
# wiring is a capture:
#
#   -object filter-dump,netdev=net0,file=PCAP
#
# QEMU writes every frame the guest emits or receives on that netdev to an
# ordinary pcap, before NAT, so the file either shows exactly the addresses
# the run configuration names or it does not. That observes the guest rather
# than constraining it, which is the stronger claim, and it needs no change to
# the host's network.
#
# The run configuration on the config device must name the gateway:
#   "link": {"interface": "eth0", "address": "10.0.2.15", "prefix_length": 24, "gateway": "10.0.2.2"}
# and the guest is not reachable from outside, which is why it is the dialer.
#
# Everything the launch measurement covers is passed exactly as
# tunnel-guest.sh and launch-measured-guest.sh pass it.
set -eu
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || echo "$HERE/../../..")"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
QEMU="${QEMU:-$STACK/usr/local/bin/qemu-system-x86_64}"
IMAGE=""; CONFIG=""; CONSOLE=""; PCAP=""; MAC="52:54:00:c1:00:0a"
MEM=2048; SMP=4; SNP=1; FIRMWARE=""; PRINT=0
while [ -n "${1:-}" ]; do
  case "$1" in
    -image)    IMAGE="$2"; shift 2 ;;
    -config)   CONFIG="$2"; shift 2 ;;
    -console)  CONSOLE="$2"; shift 2 ;;
    -pcap)     PCAP="$2"; shift 2 ;;
    -mac)      MAC="$2"; shift 2 ;;
    -mem)      MEM="$2"; shift 2 ;;
    -smp)      SMP="$2"; shift 2 ;;
    -no-snp)   SNP=0; shift ;;
    -firmware) FIRMWARE="$2"; shift 2 ;;
    -print)    PRINT=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done
[ -n "$IMAGE" ] && [ -n "$CONFIG" ] && [ -n "$PCAP" ] || { echo "need -image, -config and -pcap" >&2; exit 1; }
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
  # No DHCP and no DNS offered: the guest configures itself from the config
  # device and dials addresses, so neither is needed, and a resolver on the
  # segment would be one more thing the capture had to explain.
  -netdev "user,id=net0,net=10.0.2.0/24,host=10.0.2.2,dhcpstart=10.0.2.200,dns=10.0.2.3"
  -device "virtio-net-pci,netdev=net0,mac=$MAC,disable-legacy=on,iommu_platform=true,romfile="
  -object "filter-dump,id=dump0,netdev=net0,file=$PCAP"
)
if [ -n "$CONSOLE" ]; then ARGS+=( -serial "file:$CONSOLE" ); else ARGS+=( -serial stdio ); fi
if [ "$SNP" = 1 ]; then
  [ "$(id -u)" -eq 0 ] || { echo "SNP launch must run as root (opens /dev/sev); -no-snp is the control" >&2; exit 1; }
  modprobe cpuid 2>/dev/null || true
  EBX=$(dd if=/dev/cpu/0/cpuid ibs=16 count=32 skip=134217728 2>/dev/null \
        | tail -c 16 | od -An -t u4 -j 4 -N 4 | tr -d ' ')
  CBITPOS=$((EBX & 0x3f)); REDUCED=$(((EBX >> 6) & 0x3f))
  ARGS+=( -machine confidential-guest-support=sev0
          -object "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=$CBITPOS,reduced-phys-bits=$REDUCED,kernel-hashes=on" )
fi
if [ -n "$CONSOLE" ]; then printf '%q ' "$QEMU" "${ARGS[@]}" > "$CONSOLE.qemu-cmdline"; echo >> "$CONSOLE.qemu-cmdline"; fi
if [ "$PRINT" = 1 ]; then printf '%q ' "$QEMU" "${ARGS[@]}"; echo; exit 0; fi
exec "$QEMU" "${ARGS[@]}"
