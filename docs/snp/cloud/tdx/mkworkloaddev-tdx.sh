#!/bin/bash
# Build the workload device for a TDX guest: the read-only disk image the
# measured initrd mounts at /workload, OUTSIDE the measurement (ticket 24).
#
#   mkworkloaddev-tdx.sh SRCDIR OUT.raw
#
# SRCDIR is laid out exactly as it will appear under /workload:
#
#   config.json   the bundle's configuration (OCI runtime-spec). process.args is
#                 what runs; root.path names rootfs below; root.readonly must be
#                 true, which is what makes the container's own root read-only
#                 inside the guest and so not a writable executable path.
#   rootfs/       the root filesystem that configuration names. Whatever it runs
#                 must be static: the sandbox sees this tree and nothing else.
#
# It is docs/snp/image/mkworkloaddev.sh's counterpart and differs from it in one
# way only, the same way mkconfigdev-tdx.sh differs from mkconfigdev.sh: the
# image is sized for a cloud disk. Google's smallest pd-balanced disk is 10 GB
# and a custom image's raw file must be a whole number of gibibytes, so the
# filesystem is one gibibyte of mostly nothing, which tars and gzips down to a
# few megabytes and costs nothing to upload. On the SNP bench, where the file is
# handed straight to QEMU, 64 MiB is enough and that is what the sibling uses.
#
# This mount permits exec, which the config device does not, and that is the one
# interesting thing about it. The gofer bind-mounts the bundle's rootfs and
# remounts it read-only with MS_RDONLY|MS_NOSUID|MS_NODEV and no MS_NOEXEC; a
# mount made inside a user namespace has those three flags locked, so a remount
# that omits one is asking to clear it and the kernel answers EPERM. A noexec
# source therefore cannot be served at all
# (docs/snp/evidence/spike-s1-runsc-in-guest/E2/notes.md). Read-only and
# exec-permitted is the shape that works.
#
# Nothing on this device is measured and nothing on it is trusted. What the
# measurement covers is the runsc inside the initrd, the flag set /init launches
# it with and the options /init mounts this device with — never these bytes.
# Changing what is on this disk does not change RTMR2 and is not claimed to.
#
# Both halves are required. An image the initrd mounts and init then finds
# nothing to run on is a boot that looks like it worked, so a bundle missing
# either half is refused here rather than at the console of a guest.
set -eu
SRC="${1:?SRCDIR}"; OUT="${2:?OUT.raw}"
SIZE_MB="${SIZE_MB:-1024}"
# ext4 allows sixteen bytes of label and 'attested-workload' is seventeen, so
# mke2fs truncates it to 'attested-workloa' and says so. The warning is left
# visible rather than suppressed, and init.tdx looks for the truncated form,
# because that is what is actually on the disk. Nothing important rests on it:
# the label is the fallback, and the identifier that carries the whole name is
# the NVMe serial Google sets from --device-name.
LABEL="${LABEL:-attested-workload}"

[ -f "$SRC/config.json" ] || { echo "workload: refusing to build: no $SRC/config.json" >&2; exit 1; }
[ -d "$SRC/rootfs" ]     || { echo "workload: refusing to build: no $SRC/rootfs/" >&2; exit 1; }
echo "workload: config.json  $(sha256sum "$SRC/config.json" | cut -d' ' -f1)  $(stat -c %s "$SRC/config.json") bytes"
echo "workload: rootfs/  ($(find "$SRC/rootfs" \( -type f -o -type l \) | wc -l) files, $(du -sk "$SRC/rootfs" | cut -f1) KiB)"

# Every path is named to debugfs below, in a command file with no quoting of its
# own, so a path with whitespace in it would silently be left unowned. Refused
# here instead, where it is one line and not a boot that reads oddly.
if find "$SRC" -mindepth 1 -print | grep -q '[[:space:]]'; then
  echo "workload: refusing to build: a path under $SRC contains whitespace" >&2
  find "$SRC" -mindepth 1 -print | grep '[[:space:]]' | sed 's/^/workload:   /' >&2
  exit 1
fi

rm -f "$OUT"
truncate -s "${SIZE_MB}M" "$OUT"
# ext4, no journal (it is only ever mounted read-only), populated from SRC
# without needing root on the host.
mke2fs -q -t ext4 -O ^has_journal -L "$LABEL" -m 0 -E root_owner=0:0 -d "$SRC" "$OUT"

# Root-owned, and every inode, not just the root directory: -E root_owner sets
# that one and -d copies the caller's uid onto everything else. It has to be root
# for a reason that only shows up inside the guest. runsc runs in a user
# namespace mapping one id, 0 to 0, and a capability over a file is only a
# capability when that file's owner is mapped into the namespace
# (capable_wrt_inode_uidgid, user_namespaces(7)). A bundle owned by whoever ran
# this script is owned by an unmapped id in there, so CAP_DAC_OVERRIDE does not
# apply and the gofer is refused on a mode the host would have let root through.
# debugfs does it here because chown needs root and this script does not have it.
{ find "$SRC" -mindepth 1 | sed "s#^$SRC##" | while read -r f; do
    echo "sif $f uid 0"; echo "sif $f gid 0"
  done
} | debugfs -w -f /dev/stdin "$OUT" >/dev/null 2>&1

# And checked, because a silent miss here is a boot that fails inside runsc with
# a permission error and nothing pointing back at this script.
BAD=$( { echo "/"; find "$SRC" -mindepth 1 -type d | sed "s#^$SRC##"; } | while read -r d; do
         debugfs -R "ls -l $d" "$OUT" 2>/dev/null | awk 'NF>6 && ($4!=0 || $5!=0) {print $NF}'
       done )
[ -z "$BAD" ] || { echo "workload: refusing: not root-owned in the image: $BAD" >&2; exit 1; }

echo "workload device written to $OUT (root-owned, ext4 without a journal)"
echo "  size   $(stat -c %s "$OUT") bytes, label $LABEL (ext4 stores the first 16 bytes of it)"
echo "  sha256 $(sha256sum "$OUT" | cut -d' ' -f1)  (not measured, and nothing on it is trusted)"
