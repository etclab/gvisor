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
#   policy.json                 this guest's own signed policy: what leaves it,
#                               and the measurements it will dial
#   policy.json.sig             its detached signature, same key, own domain
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
# trust root is the author key inside the measurement; the set and the policy
# are refused unless that key signed them; the peer table resolves names to
# addresses and a wrong address is a failed handshake rather than a compromised
# one; the collateral is Intel's own, signed by Intel, and a substituted file
# fails to verify rather than admitting anybody. The device is mounted
# ro,noexec,nosuid,nodev and nothing on it ever executes.
set -eu
SRC="${1:?SRCDIR}"; OUT="${2:?OUT.raw}"
SIZE_MB="${SIZE_MB:-1024}"
LABEL="${LABEL:-attested-config}"

missing=0
for f in reference-values.json reference-values.json.sig policy.json policy.json.sig \
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
echo "config device written to $OUT"
echo "  size   $(stat -c %s "$OUT") bytes, label $LABEL"
echo "  sha256 $(sha256sum "$OUT" | cut -d' ' -f1)  (not measured, and nothing on it is trusted)"
