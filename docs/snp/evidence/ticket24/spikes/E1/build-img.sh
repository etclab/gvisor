#!/bin/bash
# Assemble the read-only "image" for ticket 24 E1. Same shape as S1's E2 and E4
# build-img.sh: it plays the part of the guest's squashfs root, so it carries
# runsc, busybox, the scripts and the bundles, and nothing is written into it
# once it is mounted read-only.
#
# Differences from S1's E2/build-img.sh, all of them bundles or scripts:
#   - the bundles are named bundle-<name> (S1 E4's convention) and there are
#     five: true, mounts, sleep, hi (S1 E4's `sh -c 'echo hi; ls /'`) and a new
#     uname one (`/bin/sh -c 'uname -a'`), so `uname` joins the applet symlinks;
#   - it copies the two inside-scripts and the two guest-like-ns variants'
#     consumers (variant-inside.sh, uname-inside.sh) as well as run-inside.sh;
#   - busybox comes from /bin/busybox, which on this workstation is the same
#     inode as /usr/bin/busybox (busybox-static 1:1.36.1-6ubuntu3.1).
set -e
S="$(dirname "$(readlink -f "$0")")"
IMG="$S/img"
rm -rf "$IMG"; mkdir -p "$IMG"/{proc,sys,run,tmp,dev,oldroot}
cp "$S/../bin/runsc" "$IMG/runsc"
cp /bin/busybox "$IMG/busybox"
cp "$S/init-mount-check.sh" "$IMG/init-mount-check.sh"
cp "$S/run-inside.sh"       "$IMG/run-inside.sh"
cp "$S/variant-inside.sh"   "$IMG/variant-inside.sh"
cp "$S/uname-inside.sh"     "$IMG/uname-inside.sh"
cp "$S/probe-procself.sh"   "$IMG/probe-procself.sh"
cp "$S/debug-b-inside.sh"   "$IMG/debug-b-inside.sh"
for b in true mounts sleep hi uname; do
  mkdir -p "$IMG/bundle-$b/rootfs/bin" "$IMG/bundle-$b/rootfs/proc" "$IMG/bundle-$b/rootfs/tmp"
  cp /bin/busybox "$IMG/bundle-$b/rootfs/bin/busybox"
  for a in sh true cat sleep ls uname id grep; do ln -sf busybox "$IMG/bundle-$b/rootfs/bin/$a"; done
  cp "$S/cfg/config-$b.json" "$IMG/bundle-$b/config.json"
done
chmod -R a+rX "$IMG"
du -sh "$IMG"
