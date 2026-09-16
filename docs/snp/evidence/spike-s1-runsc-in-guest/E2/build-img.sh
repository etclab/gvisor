#!/bin/bash
# Assemble the read-only "image" for E2: it plays the part of the guest's
# squashfs root, so it carries runsc, the bundles and busybox, and nothing is
# written into it once it is mounted read-only.
set -e
S="$(dirname "$(readlink -f "$0")")"
IMG="$S/img"
rm -rf "$IMG"; mkdir -p "$IMG"/{proc,sys,run,tmp,dev,oldroot}
cp "$S/../bin/runsc" "$IMG/runsc"
cp /usr/bin/busybox "$IMG/busybox"
cp "$S/init-mount-check.sh" "$IMG/init-mount-check.sh"
cp "$S/run-inside.sh" "$IMG/run-inside.sh"
for b in bundle bundle-sleep bundle-mounts; do
  mkdir -p "$IMG/$b/rootfs/bin" "$IMG/$b/rootfs/proc" "$IMG/$b/rootfs/tmp"
  cp /usr/bin/busybox "$IMG/$b/rootfs/bin/busybox"
  for a in sh true cat sleep ls; do ln -sf busybox "$IMG/$b/rootfs/bin/$a"; done
done
cp "$S/../e1/bundle/config.json"  "$IMG/bundle/config.json"
cp "$S/../e1/config.sleep.json"   "$IMG/bundle-sleep/config.json"
cp "$S/../e1/config.mounts.json"  "$IMG/bundle-mounts/config.json"
chmod -R a+rX "$IMG"
du -sh "$IMG"
