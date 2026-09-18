#!/bin/bash
# Build the config device for a TDX guest: the read-only disk image the
# measured initrd mounts at /config, OUTSIDE the measurement (ticket 19).
#
#   mkconfigdev-tdx.sh SRCDIR OUT.raw
#
# SRCDIR is laid out exactly as it will appear under /config:
#
#   reference-values.json       the reference value set: whom this guest admits
#   reference-values.json.sig   its detached Ed25519 signature (ADR-0006)
#   peers.json                  the peer table: names to addresses
#   tunneld.json                this run: sandbox id, listen address, limits,
#                               what to exercise
#   network.conf                the addressing, in four fields the initrd parses
#                               by hand: interface, address, prefix, gateway, mtu
#   collateral/                 Intel's provisioned TCB info, QE identity and
#                               revocation lists, in attest/verify/tdxcollateral.go's
#                               layout (ADR-0007). Never fetched at run time.
#
# It is docs/snp/image/mkconfigdev.sh's counterpart, and differs from it in
# three ways, each of which is a fact about the provider rather than a choice:
#
#   * there is no certificate-chain.bin. An Intel TDX quote carries the chain
#     that roots it (ticket 19 step zero: the acquirer bundles none and says so),
#     so the AMD-shaped provisioning of ADR-0005 has nothing to provision here.
#     What does need provisioning is Intel's collateral, and that is the
#     collateral/ directory.
#   * there is a network.conf, because on a cloud VM the address is not a
#     property of the segment the way it was on the two-guest bench: it is
#     assigned by the provider, differs per guest, and must therefore live
#     outside the measurement with everything else that differs between two
#     guests booted from one image.
#   * the image is sized for a cloud disk. Google's smallest pd-balanced disk is
#     10 GB and a custom image's raw file must be a whole number of gibibytes,
#     so the filesystem is one gibibyte of mostly nothing, which tars and gzips
#     down to a few megabytes and costs nothing to upload.
#
# Nothing on this device is trusted and nothing on it can admit a peer. The
# trust root is the author key inside the measurement; the set is refused unless
# that key signed it; the peer table resolves names to
# addresses and a wrong address is a failed handshake rather than a compromised
# one; the collateral is Intel's own, signed by Intel, and a substituted file
# fails to verify rather than admitting anybody. The device is mounted
# ro,noexec,nosuid,nodev and nothing on it ever executes.
set -eu
SRC="${1:?SRCDIR}"; OUT="${2:?OUT.raw}"
SIZE_MB="${SIZE_MB:-1024}"
LABEL="${LABEL:-attested-config}"

# policy.json and its signature are not on the list: ticket 22 took that document
# off the device, the egress ceiling it carried is compiled into the measured
# tunneld, and tunneld refuses to start on a device that still carries either
# half. The image is populated from the whole of SRCDIR, so one left in there
# would be on the device whatever this script printed — hence a refusal rather
# than a warning, and a refusal rather than a deletion, because the script that
# wrote the file is the thing to fix.
for f in policy.json policy.json.sig; do
  if [ -f "$SRC/$f" ]; then
    echo "config: refusing to build: $SRC/$f" >&2
    echo "config: ticket 22 took the policy off the config device; tunneld refuses to start on one that carries it" >&2
    exit 1
  fi
done

missing=0
for f in reference-values.json reference-values.json.sig \
         peers.json tunneld.json network.conf; do
  if [ -f "$SRC/$f" ]; then
    echo "config: $f  $(sha256sum "$SRC/$f" | cut -d' ' -f1)  $(stat -c %s "$SRC/$f") bytes"
  else
    echo "config: $f  (ABSENT)"
    missing=$((missing + 1))
  fi
done
if [ -d "$SRC/collateral" ]; then
  echo "config: collateral/  $(find "$SRC/collateral" -type f | wc -l) files"
  find "$SRC/collateral" -type f | sort | while read -r f; do
    echo "config:   ${f#"$SRC"/collateral/}  $(sha256sum "$f" | cut -d' ' -f1)"
  done
else
  echo "config: collateral/  (ABSENT: this guest will admit no Intel TDX peer)"
  missing=$((missing + 1))
fi
# Missing files are reported and not invented. A device with only some of them
# is a legitimate thing to build, because the loader must refuse it and a test
# of that refusal needs one.
[ "$missing" -eq 0 ] || echo "config: $missing item(s) absent; building the device anyway"
find "$SRC" -type f -perm /111 -print | sed 's/^/config: WARNING executable bit (ignored: mounted noexec): /' || true

rm -f "$OUT"
truncate -s "${SIZE_MB}M" "$OUT"
# ext4, no journal (it is only ever mounted read-only), every file owned by
# root, populated from SRC without needing root on the host. The label is what
# the initrd falls back to when the provider does not expose the device name
# the disk was attached with.
mke2fs -q -t ext4 -O ^has_journal -L "$LABEL" -m 0 -E root_owner=0:0 -d "$SRC" "$OUT"

# Root-owned, and every inode and not just the root directory: `-E root_owner`
# sets that one and `-d` copies the caller's uid onto everything else. This is
# docs/snp/image/mkconfigdev.sh's paragraph, one vendor over, and it is here
# because ticket 26's first TDX pair died of its absence. Until ticket 25 every
# reader of this device was tunneld, which runs as the initrd's root in the
# initial user namespace and has CAP_DAC_OVERRIDE over a file whoever owns it.
#
# The tunnel table broke that. It is read by `runsc run`, inside the user
# namespace busybox unshare makes, which maps exactly one id, 0 to 0. A
# capability over a file is only a capability when the file's owner is mapped
# into the namespace (capable_wrt_inode_uidgid, user_namespaces(7)), so a device
# built by an ordinary user hands runsc a table owned by an id that does not
# exist in there. Both guests of 2026-09-18T21:06Z said so and said nothing that
# pointed back here:
#
#   cannot create sandbox process: starting the tunnel helper:
#   opening the tunnel table "/config/tunnel-table.json":
#   open /config/tunnel-table.json: permission denied
#
# The modes are left alone rather than widened: mke2fs writes them through the
# caller's umask, so on a session with umask 077 every file is 0600, and owned by
# root that is readable by root in both namespaces, which is the whole
# requirement. debugfs does the chown because chown needs root and this script
# does not have it.
{ find "$SRC" -mindepth 1 | sed "s#^$SRC##" | while read -r f; do
    echo "sif $f uid 0"; echo "sif $f gid 0"
  done
} | debugfs -w -f /dev/stdin "$OUT" >/dev/null 2>&1

# And checked, because a silent miss here is a guest that boots, attests, and
# then cannot start its sandbox — which is what it cost to learn this.
BAD=$( { echo "/"; find "$SRC" -mindepth 1 -type d | sed "s#^$SRC##"; } | while read -r d; do
         debugfs -R "ls -l $d" "$OUT" 2>/dev/null | awk 'NF>6 && ($4!=0 || $5!=0) {print $NF}'
       done )
[ -z "$BAD" ] || { echo "config: refusing: not root-owned in the image: $BAD" >&2; exit 1; }

echo "config device written to $OUT (every inode root-owned)"
echo "  size   $(stat -c %s "$OUT") bytes, label $LABEL"
echo "  sha256 $(sha256sum "$OUT" | cut -d' ' -f1)  (not measured, and nothing on it is trusted)"
