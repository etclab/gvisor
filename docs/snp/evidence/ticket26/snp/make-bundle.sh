#!/bin/bash
# Ticket 26's bundle: the OCI bundle the workload device carries, and the device.
#
#   make-bundle.sh SRCDIR OUT.img [-tdx]
#
# Everything here is outside the launch measurement. What the measurement covers
# is the runsc that runs this, the flag set init runs it with — including
# --tunnel-socket and --tunnel-table — and the options the initrd mounts the disk
# with. Never these bytes. It is ticket 25's script
# (docs/snp/evidence/ticket25/snp/make-bundle.sh) with two additions and one
# change, and nothing else.
#
#   -tdx          build the disk with mkworkloaddev-tdx.sh instead of
#                 mkworkloaddev.sh: one gibibyte instead of sixty-four mebibytes,
#                 because Google's smallest pd-balanced disk is 10 GB and a
#                 custom image's raw file must be a whole number of gibibytes.
#                 The bundle itself is byte for byte the same either way, which
#                 is what lets one recorded run be compared with the other.
#
#   /bin/probe    THE EXEC CONTROL, and the one file in this bundle that exists
#                 only to be refused. It is a copy of the same static busybox
#                 with a comment appended, so it is a different file at a
#                 different path: the path is not the one the pushed policy's
#                 `x` names and the sha256 is not one it names either, and an
#                 execve of it must fail EACCES once that policy is in force.
#
#                 The comment is load-bearing. A plain copy of busybox would have
#                 the same sha256, and a policy whose `x` listed the digest
#                 instead of the path would then permit it — which would make the
#                 control a test of nothing. A symlink would be worse: it
#                 resolves to the same inode AND, depending on what the sentry
#                 reports for a symlinked exec, possibly to the same path. Two
#                 bytes of difference make the file's identity unambiguous under
#                 either reading, and what remains open — what path the sentry
#                 reports for /bin/sh — the workload records rather than assumes
#                 (policy-probe.sh, the OBSERVE lines).
#
#   /policy-probe.sh
#                 ticket 25's adapter-probe.sh grown into ticket 26's workload:
#                 the page, a long stream held open across a narrowing, the
#                 name-not-in-the-table control, the exec control, the narrowing
#                 control, and then a stand-still long enough for the guest's
#                 kill-after to end it.
#
# The /etc it carries is ticket 25's, unchanged and for ticket 25's reasons:
# resolv.conf points at 127.0.0.53 where the sentry answers, nsswitch.conf says
# `hosts: files dns` so the order is a fact of the bundle, and /etc/hosts holds
# localhost and NEITHER peer name — if a peer name were in there the fetch would
# never reach the sentry and the run would prove nothing.
#
# The applet symlinks are ticket 25's too, and this bundle deliberately does not
# use them: policy-probe.sh spells every command /bin/busybox <applet>. They are
# here so that the two OBSERVE lines have something to exec through.
set -euo pipefail
SRC="${1:?SRCDIR}"; OUT="${2:?OUT.img}"; SHAPE="${3:-}"
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
MKDEV="$REPO/docs/snp/image/mkworkloaddev.sh"
case "$SHAPE" in
  "")      ;;
  -tdx)    MKDEV="$REPO/docs/snp/cloud/tdx/mkworkloaddev-tdx.sh" ;;
  *)       echo "make-bundle.sh: unknown argument $SHAPE (only -tdx)" >&2; exit 2 ;;
esac

rm -rf "$SRC"; mkdir -p "$SRC/rootfs/bin" "$SRC/rootfs/etc" "$SRC/rootfs/proc"
# The same pinned static busybox the image itself carries
# (busybox-static 1:1.36.1-6ubuntu3.1, docs/snp/image/build-image.sh).
install -m 755 /bin/busybox "$SRC/rootfs/bin/busybox"
for a in sh wget uname echo cat sleep head wc; do ln -s busybox "$SRC/rootfs/bin/$a"; done
# The exec control. `cat` and not `install`, because what is wanted is the bytes
# plus the comment and not a second name for one file.
cat /bin/busybox > "$SRC/rootfs/bin/probe"
printf '\n# ticket 26: a copy of busybox that is not /bin/busybox, so that an execve of it\n# is an identity the pushed policy does not name. The ELF loader reads the program\n# headers and ignores these bytes; sha256 does not.\n' >> "$SRC/rootfs/bin/probe"
chmod 755 "$SRC/rootfs/bin/probe"
install -m 755 "$HERE/policy-probe.sh" "$SRC/rootfs/policy-probe.sh"
install -m 644 "$HERE/config.json" "$SRC/config.json"

printf 'nameserver 127.0.0.53\n' > "$SRC/rootfs/etc/resolv.conf"
printf 'hosts: files dns\n'      > "$SRC/rootfs/etc/nsswitch.conf"
printf '127.0.0.1\tlocalhost\n::1\tlocalhost\n' > "$SRC/rootfs/etc/hosts"
chmod 644 "$SRC/rootfs/etc/resolv.conf" "$SRC/rootfs/etc/nsswitch.conf" "$SRC/rootfs/etc/hosts"
chmod 644 "$SRC/config.json"
chmod 755 "$SRC" "$SRC/rootfs" "$SRC/rootfs/bin" "$SRC/rootfs/etc" "$SRC/rootfs/proc"

echo "bundle:"
(cd "$SRC" && find . \( -type f -o -type l \) | sort | while read -r f; do
   if [ -L "$f" ]; then printf '  %s -> %s\n' "$f" "$(readlink "$f")"
   else printf '  %s  %s  %s bytes\n' "$f" "$(sha256sum "$f" | cut -c1-16)…" "$(stat -c %s "$f")"; fi
 done)
echo
echo "the two identities the exec control turns on, at full width:"
echo "  /bin/busybox  $(sha256sum "$SRC/rootfs/bin/busybox" | cut -d' ' -f1)"
echo "  /bin/probe    $(sha256sum "$SRC/rootfs/bin/probe" | cut -d' ' -f1)"
if [ "$(sha256sum "$SRC/rootfs/bin/busybox" | cut -d' ' -f1)" = "$(sha256sum "$SRC/rootfs/bin/probe" | cut -d' ' -f1)" ]; then
  echo "REFUSING: /bin/probe has the same sha256 as /bin/busybox, so the exec control would prove nothing" >&2
  exit 1
fi
echo

bash "$MKDEV" "$SRC" "$OUT"
