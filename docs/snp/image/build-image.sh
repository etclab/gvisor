#!/bin/bash
# Build the minimal measured guest image (ticket 06).
#
# Output: firmware, kernel, initrd, a read-only dm-verity-protected root
# filesystem image, and the kernel command line that binds them. Every byte of
# the first three and the command line is in the launch measurement; the root
# filesystem is covered transitively through the verity root hash on the
# command line. Nothing else is in the image.
#
# Rebuildable and auditable, not bit-reproducible: every input is pinned by
# hash or version, every tool version is recorded, and the manifest lists
# every file that went in. Nothing here needs root.
#
# Build parameters (environment):
#   STACK           ticket 01's host stack (default: .scratch/attested-secure-tunnel/host-stack)
#   OUT             output directory (default: $STACK/image)
#   AUTHOR_PUBKEY   REQUIRED. The reference value author's Ed25519 public key:
#                   32 raw bytes, or 64 hex characters. Baked into the root
#                   filesystem at /etc/attested-tunnel/author.pub (ADR-0004);
#                   rotating it is a new measurement.
#   TUNNELD         static binary to embed as /usr/bin/tunneld. Default: build
#                   tunneld-placeholder.c. Ticket 14 sets this and nothing else.
#   BUSYBOX         static busybox (default /bin/busybox from busybox-static)
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
OUT="${OUT:-$STACK/image}"
BUSYBOX="${BUSYBOX:-/bin/busybox}"
TUNNELD="${TUNNELD:-}"
: "${AUTHOR_PUBKEY:?set AUTHOR_PUBKEY to the reference value author Ed25519 public key file}"

# ---- pinned inputs ---------------------------------------------------------
# From docs/snp-host-stack.md. A different firmware or kernel is a different
# measurement; refusing to build on a mismatch is what "pinned" means.
KERNEL_RELEASE=6.16.0-snp-guest-038d61fd6422
KERNEL_COMMIT=038d61fd642278bab63ee8ef722c50d10ab01e8f     # AMDESE/linux snp-guest-latest
OVMF_TAG=edk2-stable202502
OVMF_COMMIT=fbe0805b2091393406952e84724188f8c1941837       # tianocore/edk2
# AmdSevX64 firmware (BlobVerifierLibSevHashes), built by build-ovmf-amdsev.sh.
# NOT ticket 01's OVMF.fd: that is OvmfPkgX64 with BlobVerifierLibNull, under
# which kernel, initrd and command line are never measured.
OVMF_SHA256=ffd6bfa8c76c460a4dba62c39b2c9cf5a7ac425148eede7fb610f4c3cd96a895
GRUB_VERSION="2.12-1ubuntu7.3"                             # grub-efi-amd64-bin: grub image embedded in the firmware
KERNEL_SHA256=c3b443dbdafbaf3cb92d119482143a76876a752c7335a61faa917361d9724b75
BUSYBOX_VERSION="1:1.36.1-6ubuntu3.1"                     # Ubuntu busybox-static

FIRMWARE="$STACK/usr/local/share/qemu/OVMF.amdsev.fd"
KERNEL="$STACK/guest-kernel/vmlinuz-snp-guest"
MODDIR="$STACK/guest-kernel/staging/lib/modules/$KERNEL_RELEASE/kernel"
GEN_INIT_CPIO_SRC="$STACK/AMDSEV/linux/guest/usr/gen_init_cpio.c"

pin() { # pin FILE SHA256
  local got; got=$(sha256sum "$1" | cut -d' ' -f1)
  [ "$got" = "$2" ] || { echo "PINNED INPUT MISMATCH: $1 is $got, expected $2" >&2; exit 1; }
}
pin "$FIRMWARE" "$OVMF_SHA256"
pin "$KERNEL" "$KERNEL_SHA256"
BUSYBOX_PKG=$(dpkg-query -W busybox-static 2>/dev/null | cut -f2 || echo unknown)
[ "$BUSYBOX_PKG" = "$BUSYBOX_VERSION" ] \
  || echo "WARNING: busybox-static is not $BUSYBOX_VERSION; recorded in the manifest" >&2
file "$BUSYBOX" | grep -q 'statically linked' || { echo "$BUSYBOX is not static" >&2; exit 1; }

# ---- workspace -------------------------------------------------------------
B="$OUT/build"
rm -rf "$OUT"; mkdir -p "$B/rootfs" "$B/initrd"
cd "$B"

# Tools built from the checked-in sources, statically.
gcc -O2 -static -Wall -o veritymap "$HERE/veritymap.c"
gcc -O2 -static -Wall -o gen_init_cpio "$GEN_INIT_CPIO_SRC"
if [ -z "$TUNNELD" ]; then
  gcc -O2 -static -Wall -o tunneld-placeholder "$HERE/tunneld-placeholder.c"
  TUNNELD="$B/tunneld-placeholder"
  echo "TUNNELD not set: embedding tunneld-placeholder"
fi
file "$TUNNELD" | grep -q 'statically linked' || { echo "TUNNELD $TUNNELD is not static" >&2; exit 1; }

# Author key: normalise to one line of 64 lowercase hex characters.
case "$(stat -c %s "$AUTHOR_PUBKEY")" in
  32)    KEYHEX=$(xxd -p "$AUTHOR_PUBKEY" | tr -d '\n') ;;
  64|65) KEYHEX=$(tr -d '\n' < "$AUTHOR_PUBKEY" | tr 'A-F' 'a-f') ;;
  *)     echo "AUTHOR_PUBKEY must be 32 raw bytes or 64 hex chars" >&2; exit 1 ;;
esac
[[ "$KEYHEX" =~ ^[0-9a-f]{64}$ ]] || { echo "AUTHOR_PUBKEY is not an Ed25519 public key" >&2; exit 1; }
printf '%s\n' "$KEYHEX" > author.pub

# ---- root filesystem -------------------------------------------------------
# Enumerated by hand. Applets are the ones /sbin/init uses, no more.
R="$B/rootfs"
mkdir -p "$R"/{bin,sbin,usr/bin,etc/attested-tunnel,lib/modules,config,proc,sys,dev,run,tmp}
install -m 755 "$BUSYBOX" "$R/bin/busybox"
ROOT_APPLETS="sh mount umount insmod cat echo sleep ls dmesg grep sed poweroff sync"
for a in $ROOT_APPLETS; do ln -s busybox "$R/bin/$a"; done
install -m 755 "$HERE/init.rootfs" "$R/sbin/init"
install -m 755 "$TUNNELD" "$R/usr/bin/tunneld"
install -m 444 author.pub "$R/etc/attested-tunnel/author.pub"
install -m 444 "$MODDIR/drivers/virt/coco/guest/tsm_report.ko"   "$R/lib/modules/"
install -m 444 "$MODDIR/drivers/virt/coco/sev-guest/sev-guest.ko" "$R/lib/modules/"

# squashfs: read-only by construction, 4 KiB padded, timestamps zeroed, all root.
mksquashfs "$R" rootfs.squashfs -comp zstd -noappend -no-xattrs -all-root \
  -mkfs-time 0 -all-time 0 -root-time 0 -no-progress -quiet
DATA_BYTES=$(stat -c %s rootfs.squashfs)
[ $((DATA_BYTES % 4096)) -eq 0 ] || { echo "squashfs not 4 KiB aligned" >&2; exit 1; }
DATABLOCKS=$((DATA_BYTES / 4096))

# dm-verity hash tree appended to the same image, no superblock: every
# parameter the kernel needs travels on the measured command line instead.
cp rootfs.squashfs "$OUT/rootfs.img"
VERITY_OUT=$(veritysetup format --no-superblock --hash-offset="$DATA_BYTES" \
  --data-block-size=4096 --hash-block-size=4096 --data-blocks="$DATABLOCKS" \
  --hash=sha256 --salt=- "$OUT/rootfs.img" "$OUT/rootfs.img")
ROOTHASH=$(echo "$VERITY_OUT" | sed -n 's/^Root hash:[[:space:]]*//p')
[[ "$ROOTHASH" =~ ^[0-9a-f]{64}$ ]] || { echo "no root hash from veritysetup:"; echo "$VERITY_OUT"; exit 1; } >&2
veritysetup verify --no-superblock --hash-offset="$DATA_BYTES" \
  --data-block-size=4096 --hash-block-size=4096 --data-blocks="$DATABLOCKS" \
  --hash=sha256 --salt=- "$OUT/rootfs.img" "$OUT/rootfs.img" "$ROOTHASH"

# ---- initrd ----------------------------------------------------------------
I="$B/initrd"
install -m 755 "$BUSYBOX" "$I/busybox"
install -m 755 "$HERE/init.initrd" "$I/init"
cp "$MODDIR/drivers/md/dm-bufio.ko" "$MODDIR/drivers/md/dm-verity.ko" "$I/"
INITRD_APPLETS="sh mount umount insmod cat echo sleep switch_root"
{
  echo "dir /dev 0755 0 0"
  echo "nod /dev/console 0600 0 0 c 5 1"
  echo "dir /proc 0755 0 0"
  echo "dir /sys 0755 0 0"
  echo "dir /newroot 0755 0 0"
  echo "dir /bin 0755 0 0"
  echo "dir /sbin 0755 0 0"
  echo "dir /lib 0755 0 0"
  echo "file /init $I/init 0755 0 0"
  echo "file /bin/busybox $I/busybox 0755 0 0"
  for a in $INITRD_APPLETS; do echo "slink /bin/$a busybox 0755 0 0"; done
  echo "file /sbin/veritymap $B/veritymap 0755 0 0"
  echo "file /lib/dm-bufio.ko $I/dm-bufio.ko 0444 0 0"
  echo "file /lib/dm-verity.ko $I/dm-verity.ko 0444 0 0"
} > initrd.list
./gen_init_cpio -t 0 initrd.list > initrd.cpio
gzip -n -9 -c initrd.cpio > "$OUT/initrd.img"

# ---- kernel, firmware, command line ---------------------------------------
cp "$KERNEL" "$OUT/vmlinuz"
cp "$FIRMWARE" "$OUT/OVMF.fd"
# HASHSTART is in hash blocks; the tree starts right after the data.
CMDLINE="console=ttyS0 earlyprintk=serial panic=-1 rdinit=/init verity.roothash=$ROOTHASH verity.salt=- verity.datablocks=$DATABLOCKS verity.hashstart=$DATABLOCKS"
printf '%s\n' "$CMDLINE" > "$OUT/cmdline.txt"

# ---- manifest --------------------------------------------------------------
{
  echo "# Measured image manifest. Built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)."
  echo
  echo "## Measured inputs. The firmware is measured directly; kernel, initrd and command line"
  echo "## enter through the SEV hashes table QEMU writes into the firmware (kernel-hashes=on);"
  echo "## rootfs.img is covered through verity.roothash on the command line."
  (cd "$OUT" && sha256sum OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img)
  echo "verity root hash: $ROOTHASH  (sha256, no salt, 4096-byte blocks, $DATABLOCKS data blocks, hash tree at block $DATABLOCKS)"
  echo
  echo "## Provenance"
  echo "firmware: tianocore/edk2 $OVMF_TAG $OVMF_COMMIT OvmfPkg/AmdSev/AmdSevX64.dsc, built by docs/snp/image/build-ovmf-amdsev.sh"
  echo "          embedded grub built from grub-efi-amd64-bin $(dpkg-query -W grub-efi-amd64-bin 2>/dev/null | cut -f2 || echo unknown) (pinned: $GRUB_VERSION)"
  echo "kernel:   AMDESE/linux snp-guest-latest $KERNEL_COMMIT, release $KERNEL_RELEASE"
  echo "busybox:  $BUSYBOX  busybox-static $BUSYBOX_PKG"
  echo "tunneld:  $TUNNELD"
  echo "author key: $KEYHEX"
  echo
  echo "## Toolchain"
  echo "gcc:         $(gcc --version | head -1)"
  echo "veritysetup: $(veritysetup --version)"
  echo "mksquashfs:  $(mksquashfs -version | head -1)"
  echo "mke2fs:      $(mke2fs -V 2>&1 | head -1)"
  echo "gzip:        $(gzip --version | head -1)"
  echo "gen_init_cpio: from the kernel tree at $KERNEL_COMMIT"
  echo
  echo "## Root filesystem contents (path sha256 mode size)"
  (cd "$R" && find . -type f -o -type l | sort | while read -r p; do
     if [ -L "$p" ]; then printf '%s -> %s\n' "$p" "$(readlink "$p")"
     else printf '%s %s %s %s\n' "$p" "$(sha256sum "$p" | cut -d' ' -f1)" "$(stat -c %a "$p")" "$(stat -c %s "$p")"; fi
   done)
  echo
  echo "## Initrd contents (gen_init_cpio list)"
  sed "s#$B/[a-z]*/##; s#$B/##" initrd.list
  echo
  echo "## Guest kernel modules"
  for m in dm-bufio dm-verity tsm_report sev-guest; do
    f=$(find "$MODDIR" -name "$m.ko"); echo "$m.ko $(sha256sum "$f" | cut -d' ' -f1) vermagic=$(modinfo -F vermagic "$f")"
  done
} > "$OUT/manifest.txt"

cp "$HERE"/{build-image.sh,init.initrd,init.rootfs,veritymap.c,tunneld-placeholder.c} "$B/" 2>/dev/null || true
echo
echo "image in $OUT:"
ls -l "$OUT" | grep -v '^d\|^total'
echo "command line: $CMDLINE"
