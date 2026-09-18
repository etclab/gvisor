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
#   certificate-chain.bin       the provisioned certificate chain as an AMD
#                               certificate table, VCEK, ASK, ARK (ADR-0005;
#                               written by attest/cmd/attest-tool provision,
#                               ticket 15)
#   certificate-chain.json      the chip identity and TCB the chain was
#                               fetched for, so staleness is detectable
#
# Two more since ticket 25, and both optional, because their presence is what
# /sbin/init reads as "this guest runs its workload as a sandbox on the adapter":
#
#   tunnel-table.json           the names the sandbox may reach, the one port
#                               each, and the peer whose exit dials them. runsc
#                               is given it as --tunnel-table and the sentry
#                               enforces it; a name that is not in it does not
#                               resolve. Not measured, which is the whole reason
#                               two guests booted from one image can have
#                               different ones.
#   exit-allow                  one line, host:port comma separated: what THIS
#                               guest's exit will dial on behalf of a peer that
#                               opened a stream to it. It is a file rather than a
#                               field in tunneld.json because the run
#                               configuration refuses unknown fields
#                               (attest/cmd/tunneld/runconfig.go:289-302), and
#                               adding one would be a change to the measured
#                               binary for something that is not tunneld's
#                               business: the exit is another process and the
#                               list is its flag.
#
# Ticket 15 writes the files; this script only packages a directory. Missing
# files are reported, not invented: a device with the document alone is a
# legitimate thing to build, because the loader must refuse it.
#
# policy.json was on that list until ticket 22 and is deliberately not any more.
# The egress ceiling it carried is a constant compiled into the measured tunneld
# (attest/ceiling), and what a sandbox may delegate to whom is pushed over the
# tunnel after attestation. tunneld refuses to start on a device that still
# carries either half of it, so a device built by an older copy of this script
# stops the guest rather than being half-obeyed; it is not copied here even if
# SRCDIR holds one.
set -eu
SRC="${1:?SRCDIR}"; OUT="${2:?OUT.img}"
SIZE_MB="${SIZE_MB:-16}"

for f in reference-values.json reference-values.json.sig peers.json certificate-chain.bin certificate-chain.json; do
  [ -f "$SRC/$f" ] && echo "config: $f" || echo "config: $f  (absent)"
done
# The adapter's two, reported only when they are there: absent is the ordinary
# case and every scenario recorded before ticket 25 is that one.
for f in tunnel-table.json exit-allow; do
  [ -f "$SRC/$f" ] && echo "config: $f  ($(tr -d '\n' < "$SRC/$f" | cut -c1-120))"
done
# The image is populated from the whole of SRCDIR, so a policy left in there
# would be on the device whatever this script printed. It is refused rather than
# deleted: the file is the operator's, and the script that wrote it is the thing
# to fix.
for f in policy.json policy.json.sig; do
  if [ -f "$SRC/$f" ]; then
    echo "config: refusing to build: $SRC/$f" >&2
    echo "config: ticket 22 took the policy off the config device — the egress ceiling is compiled into the" >&2
    echo "config: measured tunneld and policy is pushed over the tunnel after attestation — and tunneld refuses" >&2
    echo "config: to start on a device that carries either half of it. Remove it from SRCDIR." >&2
    exit 1
  fi
done
find "$SRC" -type f -perm /111 -print | sed 's/^/config: WARNING executable bit (ignored: mounted noexec): /' || true

rm -f "$OUT"
truncate -s "${SIZE_MB}M" "$OUT"
# ext4, no journal (read-only), all files owned by root, populated from SRC
# without needing root on the host.
mke2fs -q -t ext4 -O ^has_journal -L attested-config -m 0 -E root_owner=0:0 -d "$SRC" "$OUT"
echo "config device written to $OUT ($(sha256sum "$OUT" | cut -c1-16)…, not measured)"
