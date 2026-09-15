#!/bin/bash
# Assemble the read-only "image" for E3. Same as E2's, plus two empty
# directories that exist only so that a read-only path can be handed to
# --shared-root and to --root, and the E3 case script.
#   EV      = docs/snp/evidence/spike-s1-runsc-in-guest  (this repo)
#   SCRATCH = the session scratch directory (holds bin/runsc and e1/ bundles)
set -e
: "${EV:?set EV to the evidence directory}"
: "${SCRATCH:?set SCRATCH to the session scratch directory}"
IMG="$SCRATCH/e3/img"
rm -rf "$IMG"; mkdir -p "$IMG"/{proc,sys,run,tmp,dev,oldroot,roshared,roroot}
cp "$SCRATCH/bin/runsc" "$IMG/runsc"
cp /usr/bin/busybox "$IMG/busybox"
cp "$EV/E2/init-mount-check.sh" "$IMG/init-mount-check.sh"   # verbatim from E2
cp "$EV/E3/case.sh" "$IMG/case.sh"
for b in bundle bundle-sleep; do
  mkdir -p "$IMG/$b/rootfs/bin" "$IMG/$b/rootfs/proc" "$IMG/$b/rootfs/tmp"
  cp /usr/bin/busybox "$IMG/$b/rootfs/bin/busybox"
  for a in sh true cat sleep ls; do ln -sf busybox "$IMG/$b/rootfs/bin/$a"; done
done
cp "$SCRATCH/e1/bundle/config.json"  "$IMG/bundle/config.json"
cp "$SCRATCH/e1/config.sleep.json"   "$IMG/bundle-sleep/config.json"
chmod -R a+rX "$IMG"
du -sh "$IMG"
