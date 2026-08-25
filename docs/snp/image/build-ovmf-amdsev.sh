#!/bin/bash
# Build the AmdSev firmware (OvmfPkg/AmdSev/AmdSevX64.dsc) at the same pinned
# edk2 tag as ticket 01's OVMF.fd, into the same local prefix, as a SEPARATE
# file: OVMF.amdsev.fd. Nothing of ticket 01's is overwritten.
#
# Why a second firmware: ticket 01's OVMF.fd is OvmfPkgX64, which links
# BlobVerifierLibNull. That firmware loads whatever kernel, initrd and command
# line fw_cfg hands it and never checks them, and QEMU adds their hashes to the
# launch measurement only for a firmware that publishes a hashes table
# (kernel-hashes=on). So with OVMF.fd the measurement covers the firmware and
# nothing else. AmdSevX64 links BlobVerifierLibSevHashes: QEMU writes
# SHA-256 of kernel, initrd and command line into a page inside the measured
# firmware area, and the firmware refuses to boot a blob whose hash is absent
# or wrong. That is the direct measured boot the image needs.
#
# AmdSevX64 also embeds a grub image (OvmfPkg/AmdSev/Grub/, built by
# grub-mkimage from the host's grub modules) for its disk-boot path. It is
# unused here, since the kernel comes from fw_cfg, but its bytes are in the
# firmware and therefore in the measurement; grub-efi-amd64-bin's version is
# recorded in the image manifest for that reason.
set -eu
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
OVMF_TAG="${OVMF_TAG:-edk2-stable202502}"
SRC="$STACK/AMDSEV/ovmf"
DEST="$STACK/usr/local/share/qemu"

command -v grub-mkimage >/dev/null || { echo "grub-mkimage missing (grub-efi-amd64-bin)" >&2; exit 1; }
[ -d "$SRC" ] || { echo "no edk2 tree at $SRC; run docs/snp/build-ovmf-pinned.sh first" >&2; exit 1; }
cd "$SRC"
[ "$(git describe --tags --exact-match 2>/dev/null)" = "$OVMF_TAG" ] || { echo "edk2 tree is not at $OVMF_TAG" >&2; exit 1; }

# Deviation, recorded: grub.sh asks grub-mkimage for modules Ubuntu's grub
# 2.12 does not ship as separate files (`linuxefi`, `sevsecret`; its EFI Linux
# loader lives in `linux.mod`). The grub image is not on this image's boot
# path — the kernel comes from fw_cfg and is verified against the hashes
# table — so modules the host lacks are dropped from the list, each one named
# here, and the tree is left with the change visible to `git diff`.
GRUBSH=OvmfPkg/AmdSev/Grub/grub.sh
for m in $(sed -n '/^GRUB_MODULES="/,/"/p' "$GRUBSH" | tr -d '"' | sed 's/GRUB_MODULES=//'); do
  if [ ! -f "/usr/lib/grub/x86_64-efi/$m.mod" ]; then
    sed -i "/^ *$m\$/d" "$GRUBSH"
    echo "deviation: removed grub module '$m' from $GRUBSH (not shipped by $(dpkg-query -W grub-efi-amd64-bin | tr '\t' ' '))"
  fi
done

if grep -q '^DEFINE GCC5_' BaseTools/Conf/tools_def.template; then GCCVERS=GCC5; else GCCVERS=GCC; fi
[ -x BaseTools/Source/C/bin/GenFv ] || make -C BaseTools -j "$(getconf _NPROCESSORS_ONLN)"
set +u; . ./edksetup.sh --reconfig; set -u

nice build -q --cmd-len=64436 -n "$(getconf _NPROCESSORS_ONLN)" -t "$GCCVERS" \
     -a X64 -p OvmfPkg/AmdSev/AmdSevX64.dsc

mkdir -p "$DEST"
cp -f "Build/AmdSev/DEBUG_$GCCVERS/FV/OVMF.fd" "$DEST/OVMF.amdsev.fd"
sha256sum "$DEST/OVMF.amdsev.fd"
echo "grub-efi-amd64-bin $(dpkg-query -W grub-efi-amd64-bin | cut -f2)"
echo "AmdSevX64 firmware installed to $DEST/OVMF.amdsev.fd from $OVMF_TAG ($(git rev-parse HEAD))"
