#!/bin/bash
# E3's bundle: the OCI bundle the workload device carries, and the device.
#
# Everything here is outside the launch measurement. What the measurement covers
# is the runsc that runs this, the flag set init runs it with, and the options the
# initrd mounts the disk with — never these bytes.
#
#   make-bundle.sh SRCDIR OUT.img
#
# The workload is busybox running `uname -a`, which is the smallest thing that
# proves a sandbox really started: the string it prints is the sentry's own
# compile-time constant (4.19.0-gvisor), so it cannot have come from the guest
# kernel, and the nodename is the bundle's hostname, so it cannot have come from
# the guest either.
set -euo pipefail
SRC="${1:?SRCDIR}"; OUT="${2:?OUT.img}"
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"

rm -rf "$SRC"; mkdir -p "$SRC/rootfs/bin" "$SRC/rootfs/proc"
# The same pinned static busybox the image itself carries
# (busybox-static 1:1.36.1-6ubuntu3.1, docs/snp/image/build-image.sh).
install -m 755 /bin/busybox "$SRC/rootfs/bin/busybox"
ln -s busybox "$SRC/rootfs/bin/sh"
ln -s busybox "$SRC/rootfs/bin/uname"
install -m 644 "$HERE/config.json" "$SRC/config.json"
chmod 755 "$SRC" "$SRC/rootfs" "$SRC/rootfs/bin" "$SRC/rootfs/proc"

bash "$REPO/docs/snp/image/mkworkloaddev.sh" "$SRC" "$OUT"
