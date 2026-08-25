#!/bin/bash
# Launch a stock SEV-SNP confidential guest using the locally built QEMU + OVMF.
# Must run as root: QEMU opens /dev/sev, which is root-only on this host.
#
# Deliberately does NOT touch the distro QEMU or /usr/share/OVMF; everything is
# taken from the local prefix built by AMDSEV/build.sh.
set -u

STACK="$(dirname "$(readlink -f "$0")")"
PREFIX="$STACK/usr/local"
QEMU="$PREFIX/bin/qemu-system-x86_64"
BIOS="$PREFIX/share/qemu/OVMF.fd"
RUN="$STACK/guest"

DISK="$RUN/snp-stock.qcow2"
SEED="$RUN/seed.iso"
MEM="4096"
SMP="4"
SSH_PORT="10022"
NAME="snp-stock"
SNP=1
REDUCED_OVERRIDE=""
KERNEL=""
INITRD=""
APPEND=""

while [ -n "${1:-}" ]; do
  case "$1" in
    -disk)      DISK="$2"; shift 2 ;;
    -seed)      SEED="$2"; shift 2 ;;
    -mem)       MEM="$2"; shift 2 ;;
    -smp)       SMP="$2"; shift 2 ;;
    -ssh-port)  SSH_PORT="$2"; shift 2 ;;
    -name)      NAME="$2"; shift 2 ;;
    -kernel)    KERNEL="$2"; shift 2 ;;
    -initrd)    INITRD="$2"; shift 2 ;;
    -append)    APPEND="$2"; shift 2 ;;
    -no-snp)    SNP=0; shift ;;
    -reduced-phys-bits) REDUCED_OVERRIDE="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root (needs /dev/sev)" >&2; exit 1; }
[ -x "$QEMU" ] || { echo "missing QEMU at $QEMU" >&2; exit 1; }
[ -f "$BIOS" ] || { echo "missing OVMF at $BIOS" >&2; exit 1; }
[ -f "$DISK" ] || { echo "missing disk at $DISK" >&2; exit 1; }

CONSOLE="$RUN/$NAME-console.log"
SERSOCK="$RUN/$NAME-serial.sock"
MONSOCK="$RUN/$NAME-monitor.sock"
QEMULOG="$RUN/$NAME-qemu.log"
PIDFILE="$RUN/$NAME.pid"

# C-bit position and reduced-phys-bits come from CPUID 0x8000001F EBX:
#   EBX[5:0]   = C-bit position
#   EBX[11:6]  = number of physical address bits lost to memory encryption
modprobe cpuid 2>/dev/null
EBX=$(dd if=/dev/cpu/0/cpuid ibs=16 count=32 skip=134217728 2>/dev/null \
      | tail -c 16 | od -An -t u4 -j 4 -N 4 | tr -d ' ')
CBITPOS=$((EBX & 0x3f))
REDUCED=$(((EBX >> 6) & 0x3f))
echo "CPUID 0x8000001F EBX=$EBX -> cbitpos=$CBITPOS reduced-phys-bits=$REDUCED"
if [ -n "$REDUCED_OVERRIDE" ]; then
  echo "overriding reduced-phys-bits: $REDUCED -> $REDUCED_OVERRIDE"
  REDUCED="$REDUCED_OVERRIDE"
fi

# Guest policy: bit 17 SMT allowed, bit 16 reserved-must-be-1.
# Debug (bit 19) is deliberately NOT set: a debug-enabled guest is not confidential.
POLICY=0x30000

rm -f "$SERSOCK" "$MONSOCK" "$CONSOLE"

ARGS=(
  -enable-kvm
  -cpu "EPYC-v4,+la57,phys-bits=52"
  -machine q35
  -smp "$SMP,maxcpus=$SMP"
  -m "${MEM}M,slots=5,maxmem=$((MEM + 8192))M"
  -no-reboot
  -bios "$BIOS"
  -drive "file=$DISK,if=none,id=disk0,format=qcow2"
  -device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true
  -device scsi-hd,drive=disk0
  -netdev "user,id=vmnic,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22"
  -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile=
  -display none
  -chardev "socket,id=ser0,path=$SERSOCK,server=on,wait=off,logfile=$CONSOLE,logappend=off"
  -serial chardev:ser0
  -monitor "unix:$MONSOCK,server,nowait"
  -pidfile "$PIDFILE"
  -object "memory-backend-memfd,id=ram1,size=${MEM}M,share=true,prealloc=false"
  -machine memory-backend=ram1
)

[ -f "$SEED" ] && ARGS+=( -drive "file=$SEED,if=none,id=seed0,format=raw,readonly=on"
                          -device scsi-cd,drive=seed0 )

if [ "$SNP" = "1" ]; then
  ARGS+=(
    -machine confidential-guest-support=sev0,vmport=off
    -object "sev-snp-guest,id=sev0,policy=$POLICY,cbitpos=$CBITPOS,reduced-phys-bits=$REDUCED"
  )
fi

if [ -n "$KERNEL" ]; then
  ARGS+=( -kernel "$KERNEL" )
  [ -n "$INITRD" ] && ARGS+=( -initrd "$INITRD" )
  [ -n "$APPEND" ] && ARGS+=( -append "$APPEND" )
fi

printf '%q ' "$QEMU" "${ARGS[@]}" > "$RUN/$NAME-cmdline.txt"
echo >> "$RUN/$NAME-cmdline.txt"
echo "command line written to $RUN/$NAME-cmdline.txt"

setsid nohup "$QEMU" "${ARGS[@]}" > "$QEMULOG" 2>&1 &
sleep 3
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "guest '$NAME' running, pid $(cat "$PIDFILE")"
  echo "  console log : $CONSOLE"
  echo "  serial sock : $SERSOCK"
  echo "  monitor     : $MONSOCK"
  echo "  ssh         : ssh -p $SSH_PORT snp@127.0.0.1"
  chmod a+r "$CONSOLE" "$QEMULOG" 2>/dev/null
  exit 0
else
  echo "guest failed to start; qemu output follows:"
  cat "$QEMULOG"
  exit 1
fi
