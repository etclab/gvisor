#!/bin/bash
# Ticket 25's bundle: the OCI bundle the workload device carries, and the device.
#
# Everything here is outside the launch measurement. What the measurement covers
# is the runsc that runs this, the flag set init runs it with — including
# --tunnel-socket and --tunnel-table — and the options the initrd mounts the disk
# with. Never these bytes. It is E3's script from ticket 24
# (docs/snp/evidence/ticket24/spikes/E3/make-bundle.sh) with three additions and
# no other change.
#
#   make-bundle.sh SRCDIR OUT.img
#
# The three additions, each because the workload now talks:
#
#   wget, sleep   two more applets of the same pinned static busybox. sleep is
#                 there because the fetch retries: both guests boot at once and
#                 the peer may not have an exit attached yet, so a failure that
#                 is not a name failure is tried again for about twenty seconds
#                 (adapter-probe.sh). A name that did not resolve is never
#                 retried, which is what keeps the two controls immediate.
#   /etc/resolv.conf
#                 nameserver 127.0.0.53, which is where the sentry answers. The
#                 sandbox has a loopback-only stack and no resolver of its own,
#                 and every name it asks about is answered by the sentry out of
#                 the tunnel table: a name in the table gets a synthetic address
#                 that connect() turns into a stream to a peer, and a name that
#                 is not gets NXDOMAIN and a refusal event. This file is what
#                 points glibc at it.
#   /etc/nsswitch.conf and /etc/hosts
#                 `hosts: files dns`, with /etc/hosts holding localhost and
#                 nothing else. Written out rather than left to the default so
#                 that the order is a fact of the bundle and not of whatever
#                 glibc happens to do with a missing file — and, more to the
#                 point, so that a reader can see that neither peer name is in
#                 here. If web.peer-a or web.peer-b were in this file the fetch
#                 would never reach the sentry and the run would prove nothing.
#
# The busybox in the bundle resolves through glibc's getaddrinfo. glibc 2.34
# moved nss_files and nss_dns into libc, so a statically linked busybox resolves
# names with no shared object to dlopen; checked on the workstation against this
# very binary before this script was written.
set -euo pipefail
SRC="${1:?SRCDIR}"; OUT="${2:?OUT.img}"
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"

rm -rf "$SRC"; mkdir -p "$SRC/rootfs/bin" "$SRC/rootfs/etc" "$SRC/rootfs/proc"
# The same pinned static busybox the image itself carries
# (busybox-static 1:1.36.1-6ubuntu3.1, docs/snp/image/build-image.sh).
install -m 755 /bin/busybox "$SRC/rootfs/bin/busybox"
for a in sh wget uname echo cat sleep; do ln -s busybox "$SRC/rootfs/bin/$a"; done
install -m 755 "$HERE/adapter-probe.sh" "$SRC/rootfs/adapter-probe.sh"
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

bash "$REPO/docs/snp/image/mkworkloaddev.sh" "$SRC" "$OUT"
