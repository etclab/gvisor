#!/bin/sh
# E1 variant of S1's E2 guest-like-ns.sh. IDENTICAL except for two hunks, both
# marked "E1:" below:
#   1. it prints /proc/mounts as the *driver* left it, before anything is built,
#      so busybox unshare's own --mount-proc options can be read; and
#   2. it BIND-mounts the driver's /proc into the new root instead of mounting a
#      fresh procfs there. A fresh procfs needs a pid namespace owned by the
#      current user namespace, which variants c (-Urm) and d (-Ur) do not have,
#      and variant e's whole point is to look at the procfs busybox mounted.
#      A bind inherits the source mount's flags, so whatever the driver's /proc
#      carries is what the guest-like root gets.
# Everything else is S1's script byte for byte, including the /dev harness note.
# Must already be inside `unshare -Um` at least (user+mount namespaces).
set -e
IMG="$1"; shift
NR=/tmp/s1-newroot
# E1: hunk 1 — what the driver left us, before we build anything.
echo "### E1: /proc/mounts as the driver left it, before the namespace is built"
cat /proc/mounts
echo "### E1: the /proc lines only"
grep -E " /proc " /proc/mounts || echo "(no /proc mount)"
echo "### E1: /proc/self/mountinfo /proc lines"
grep -E " /proc " /proc/self/mountinfo || echo "(none)"
echo "### E1: end of the driver's view"
mount --make-rprivate /
mkdir -p "$NR"
# The new root is the read-only image itself, like the guest's squashfs.
mount --bind "$IMG" "$NR"
mount -o remount,bind,ro "$NR"
# E1: hunk 2 — bind the driver's /proc rather than `mount -t proc -o nosuid,nodev,noexec`.
# A plain (non-recursive) bind of /proc is refused with EINVAL inside a user
# namespace whenever /proc has child mounts: they are MNT_LOCKED in the copied
# mount namespace and a non-recursive bind would unhide what they cover, which
# the kernel does not allow an unprivileged mounter to do. This workstation has
# two such children (autofs and binfmt_misc on /proc/sys/fs/binfmt_misc); the
# measured guest has none (init.rootfs:15-19 mounts nothing under /proc), so
# there the plain bind is what would happen. Both are tried, and which one
# succeeded is recorded. --rbind drags the children along, and the autofs one is
# `rw,relatime` with no noexec, so the check then trips on a purely harness
# mount; an attempt to unmount them is made and recorded too.
if mount --bind /proc "$NR/proc" 2>&1; then
  echo "### E1: plain 'mount --bind /proc' SUCCEEDED"
else
  echo "### E1: plain 'mount --bind /proc' FAILED (exit $?); falling back to --rbind"
  mount --rbind /proc "$NR/proc"
  echo "### E1: 'mount --rbind /proc' exit $?"
  # Two stacked mounts live there on this workstation; try twice, no more.
  for try in 1 2; do
    echo "### E1: umount -l $NR/proc/sys/fs/binfmt_misc (attempt $try)"
    umount -l "$NR/proc/sys/fs/binfmt_misc" 2>&1 \
      || { echo "### E1: umount refused, the mount stays"; break; }
  done
  echo "### E1: what is left under $NR/proc"
  grep -E " $NR/proc" /proc/mounts || echo "(nothing under $NR/proc)"
fi
# E1: hunk 3 — S1's two-step sysfs fallback gains a third step. A fresh sysfs
# needs a network namespace owned by the current user namespace, which variant c
# (-Urm) has not got, and a plain bind of /sys is refused for the same
# locked-children reason as /proc, while an --rbind would drag a dozen of this
# workstation's mounts in. Nothing in this experiment reads /sys — the sentry has
# its own sysfs (S1 E4/output-02) — and the guest mounts its own at
# init.rootfs:16, so an empty noexec tmpfs is an honest stand-in when no real
# sysfs can be had. Which of the three was used is recorded.
if mount -t sysfs -o nosuid,nodev,noexec sysfs "$NR/sys" 2>/dev/null; then
  echo "### E1: /sys = a fresh sysfs"
elif mount --bind /sys "$NR/sys" 2>/dev/null \
     && mount -o remount,bind,ro,nosuid,nodev,noexec "$NR/sys" 2>/dev/null; then
  echo "### E1: /sys = a read-only bind of the driver's sysfs"
else
  mount -t tmpfs -o nosuid,nodev,noexec tmpfs "$NR/sys"
  echo "### E1: /sys = an empty noexec tmpfs stand-in (no fresh sysfs, no bind)"
fi
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
