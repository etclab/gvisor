#!/bin/bash
# Build the config device: the read-only block device the measured initrd
# mounts at /config, OUTSIDE the launch measurement. Updating anything on it
# does not change the measurement, which is the point (ADR-0004, ADR-0005).
#
#   mkconfigdev.sh SRCDIR OUT.img
#
# SRCDIR is laid out exactly as it will appear under /config:
#
#   reference-values.json       the reference value set (attest/README.md)
#   reference-values.json.sig   its detached Ed25519 signature (ADR-0006)
#   peers.json                  the peer table
#   chain/chain.pem             the provisioned certificate chain, VCEK first,
#                               then ASK, then ARK (ADR-0005, ticket 15)
#   chain/chain.json            the chip identity and TCB the chain was
#                               fetched for, so staleness is detectable
#
# Ticket 15 writes the files; this script only packages a directory. Missing
# files are reported, not invented: a device with the document alone is a
# legitimate thing to build, because the loader must refuse it.
set -eu
SRC="${1:?SRCDIR}"; OUT="${2:?OUT.img}"
SIZE_MB="${SIZE_MB:-16}"

for f in reference-values.json reference-values.json.sig peers.json chain/chain.pem chain/chain.json; do
  [ -f "$SRC/$f" ] && echo "config: $f" || echo "config: $f  (absent)"
done
find "$SRC" -type f -perm /111 -print | sed 's/^/config: WARNING executable bit (ignored: mounted noexec): /' || true

rm -f "$OUT"
truncate -s "${SIZE_MB}M" "$OUT"
# ext4, no journal (read-only), all files owned by root, populated from SRC
# without needing root on the host.
mke2fs -q -t ext4 -O ^has_journal -L attested-config -m 0 -E root_owner=0:0 -d "$SRC" "$OUT"
echo "config device written to $OUT ($(sha256sum "$OUT" | cut -c1-16)…, not measured)"
