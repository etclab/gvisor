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

# Every path is named to debugfs below in a command file with no quoting of its
# own, so a path with whitespace in it would silently be left unowned.
if find "$SRC" -mindepth 1 -print | grep -q '[[:space:]]'; then
  echo "config: refusing to build: a path under $SRC contains whitespace" >&2
  exit 1
fi

rm -f "$OUT"
truncate -s "${SIZE_MB}M" "$OUT"
# ext4, no journal (read-only), all files owned by root, populated from SRC
# without needing root on the host.
mke2fs -q -t ext4 -O ^has_journal -L attested-config -m 0 -E root_owner=0:0 -d "$SRC" "$OUT"

# Root-owned, and every inode and not just the root directory: -E root_owner
# sets that one and -d copies the caller's uid onto everything else. This is
# mkworkloaddev.sh:59-78's paragraph, one device over, and until ticket 25 it did
# not matter here — every reader of this device was tunneld, which runs as init's
# root in the initial user namespace and therefore has CAP_DAC_OVERRIDE over a
# file whoever it belongs to.
#
# The tunnel table broke that. It is read by `runsc run`, which runs inside the
# user namespace busybox unshare makes, and that namespace maps exactly one id,
# 0 to 0. A capability over a file is only a capability when the file's owner is
# mapped into the namespace (capable_wrt_inode_uidgid, user_namespaces(7)), so a
# device built by an ordinary user hands runsc a table owned by an id that does
# not exist in there — and the error is a flat `open /config/tunnel-table.json:
# permission denied` at the moment the helper starts, with nothing pointing back
# at this script. Found exactly that way, on a control boot, before the hardware
# run.
#
# The modes are left alone rather than widened. mke2fs writes them through the
# caller's umask, so on a session with umask 077 every file here is 0600; owned
# by root that is readable by root in both namespaces, which is the whole
# requirement. debugfs does the chown because chown needs root and this script
# does not have it.
{ find "$SRC" -mindepth 1 | sed "s#^$SRC##" | while read -r f; do
    echo "sif $f uid 0"; echo "sif $f gid 0"
  done
} | debugfs -w -f /dev/stdin "$OUT" >/dev/null 2>&1

# And checked, because a silent miss here is a guest that boots, attests, and
# then cannot start its sandbox.
BAD=$( { echo "/"; find "$SRC" -mindepth 1 -type d | sed "s#^$SRC##"; } | while read -r d; do
         debugfs -R "ls -l $d" "$OUT" 2>/dev/null | awk 'NF>6 && ($4!=0 || $5!=0) {print $NF}'
       done )
[ -z "$BAD" ] || { echo "config: refusing: not root-owned in the image: $BAD" >&2; exit 1; }

echo "config device written to $OUT ($(sha256sum "$OUT" | cut -c1-16)…, not measured; every inode root-owned)"
