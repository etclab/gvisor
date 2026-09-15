#!/bin/sh
# Build a mount namespace shaped like the measured guest's and run $@ in it.
# Modelled on docs/snp/image/init.rootfs lines 15-19 and on build-image.sh:183
# (the guest root is a squashfs: read-only by construction, exec allowed).
#   /        ro bind of $IMG   -> read-only, executable: holds runsc + the bundle
#   /proc /sys /run /tmp /dev  -> writable, all noexec,nosuid,nodev
# Must already be inside `unshare -Urmn` (user+mount+net namespaces).
set -e
IMG="$1"; shift
NR=/tmp/s1-newroot
mount --make-rprivate /
mkdir -p "$NR"
# The new root is the read-only image itself, like the guest's squashfs.
mount --bind "$IMG" "$NR"
mount -o remount,bind,ro "$NR"
# mount points pre-exist in the read-only image (as they do in the guest squashfs)
mount -t proc  -o nosuid,nodev,noexec proc  "$NR/proc"
mount -t sysfs -o nosuid,nodev,noexec sysfs "$NR/sys" 2>/dev/null \
  || { mount --bind /sys "$NR/sys"; mount -o remount,bind,ro,nosuid,nodev,noexec "$NR/sys"; }
mount -t tmpfs -o nosuid,nodev,noexec,mode=755  tmpfs "$NR/run"
mount -t tmpfs -o nosuid,nodev,noexec,mode=1777 tmpfs "$NR/tmp"
mount -t tmpfs -o nosuid,nodev,noexec,mode=755  tmpfs "$NR/dev"
for n in null zero full random urandom tty; do
  : > "$NR/dev/$n" 2>/dev/null || true
  mount --bind "/dev/$n" "$NR/dev/$n" 2>/dev/null || continue
  # A bind inherits the source mount's flags, and the host devtmpfs is rw,exec.
  # The measured guest has static device nodes inside its read-only squashfs and
  # mounts no /dev at all (init.rootfs:15-19); mknod is refused in a user
  # namespace, so the bind is the stand-in and is remounted noexec to match.
  mount -o remount,bind,nosuid,noexec "$NR/dev/$n" 2>/dev/null || true
done
mkdir -p "$NR/dev/shm" "$NR/dev/pts" 2>/dev/null || true
cd "$NR"
pivot_root . oldroot
# PATH tools are gone after pivot_root; the image carries busybox.
/busybox umount -l /oldroot
cd /
exec "$@"
