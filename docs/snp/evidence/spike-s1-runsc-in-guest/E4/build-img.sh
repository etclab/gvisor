#!/bin/bash
# Assemble the read-only "image" for E4. Same shape as E2's build-img.sh: it
# plays the part of the guest's squashfs root, so it carries runsc, the bundles
# and busybox, and nothing is written into it once it is mounted read-only.
# The only difference from E2 is the bundles: E4's workloads are busybox sh.
set -e
S="$(dirname "$(readlink -f "$0")")"
IMG="$S/img"
rm -rf "$IMG"; mkdir -p "$IMG"/{proc,sys,run,tmp,dev,oldroot}
cp "$S/../bin/runsc" "$IMG/runsc"
cp /usr/bin/busybox "$IMG/busybox"
cp "$S/../e2/init-mount-check.sh" "$IMG/init-mount-check.sh"
cp "$S/run-inside.sh" "$IMG/run-inside.sh"
for b in true hi view true-live hi-live; do
  mkdir -p "$IMG/bundle-$b/rootfs/bin" "$IMG/bundle-$b/rootfs/proc" "$IMG/bundle-$b/rootfs/tmp"
  cp /usr/bin/busybox "$IMG/bundle-$b/rootfs/bin/busybox"
  for a in sh true cat sleep ls id grep; do ln -sf busybox "$IMG/bundle-$b/rootfs/bin/$a"; done
  cp "$S/cfg/config.$b.json" "$IMG/bundle-$b/config.json"
done
chmod -R a+rX "$IMG"
du -sh "$IMG"
