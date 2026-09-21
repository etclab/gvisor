#!/bin/bash
# Rebuild the TDX initrd with a different /init, for a local boot only.
#
#   BUILD=… INIT=… OUT=… [EXTRA_APPLETS="tail ls"] mkinitrd-local.sh
#
# BUILD is build-tdx-image.sh's build directory from E4's run, which still holds
# the staged busybox, tunneld, runsc, author.pub and decompressed modules plus
# the initrd.list the build wrote. This script copies that list, points its
# `file /init` entry at INIT, optionally appends applet symlinks, and runs the
# build's own mkcpio.py and the same `gzip -n -9`. So an initrd built here from
# the unmodified init.tdx is byte for byte the measured one — which is checked
# below and is the only reason this script can be trusted to tell E5 anything.
#
# Every initrd this script writes other than that one has a different SHA-384 and
# therefore a different RTMR2. None of them was booted on TDX and none of them is
# a candidate for an image; they exist to be booted under plain KVM.
set -euo pipefail
BUILD="${BUILD:?set BUILD to the build directory of E4 build-tdx-image.sh run}"
INIT="${INIT:?set INIT to the /init to carry}"
OUT="${OUT:?set OUT to the initrd.img to write}"
EXTRA_APPLETS="${EXTRA_APPLETS:-}"
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"

LIST="$(mktemp)"
trap 'rm -f "$LIST" "$LIST.cpio"' EXIT
# The list entry is `file /init <staged path> 0755 0 0`; only the path moves.
awk -v init="$(readlink -f "$INIT")" \
    '$1=="file" && $2=="/init" { $3=init } { print }' \
    "$BUILD/initrd.list" > "$LIST"
for a in $EXTRA_APPLETS; do
  echo "slink /bin/$a busybox 0777 0 0" >> "$LIST"
done
python3 "$REPO/docs/snp/cloud/tdx/mkcpio.py" "$LIST" > "$LIST.cpio"
gzip -n -9 -c "$LIST.cpio" > "$OUT"
echo "initrd $OUT  $(stat -c %s "$OUT") bytes  sha256 $(sha256sum "$OUT" | cut -d' ' -f1)"
echo "  /init  $INIT  sha256 $(sha256sum "$INIT" | cut -d' ' -f1)"
ENTRIES=$(grep -c . "$LIST")
echo "  entries $ENTRIES (the list's own line count, comment included)  extra applets: ${EXTRA_APPLETS:-none}"
