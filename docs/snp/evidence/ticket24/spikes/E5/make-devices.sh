#!/bin/bash
# E5's two devices, built for a local QEMU guest rather than for Compute Engine.
#
#   make-devices.sh OUTDIR
#
# The measured initrd finds both of these by their ext4 volume label, which is
# the path E4 showed Google takes too: there is no udev in the guest, so
# --device-name never becomes a serial the kernel exposes, and init.tdx's
# fallback is the only branch that ever runs. So a virtio-blk disk carrying the
# same filesystem with the same label is, as far as init.tdx is concerned, the
# same device.
#
# Two differences from the cloud, both harness and neither measured:
#
#   * SIZE_MB=64 instead of 1024. A GCE custom image must be a whole number of
#     gibibytes; a file handed to QEMU need not be.
#   * network.conf carries QEMU's user-networking addressing (10.0.2.15/24,
#     gateway 10.0.2.2) instead of the VPC's /32 and off-link gateway. Step 6 of
#     init.tdx has to succeed for the boot to reach step 8, which is the step
#     E5 exists to look at.
#
# Everything else — the reference value set and its signature, the Intel
# collateral, the peer table, the run configuration, and the whole of the
# workload bundle — is byte for byte what E4's boot 2 was given.
set -euo pipefail
OUTDIR="${1:?OUTDIR}"
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
IMAGE_DIR="${IMAGE_DIR:?set IMAGE_DIR to the build-tdx-image.sh output E4 used}"

mkdir -p "$OUTDIR"
OUTDIR="$(readlink -f "$OUTDIR")"

# ---- the config device ----------------------------------------------------
D="$OUTDIR/config-src"
rm -rf "$D"; mkdir -p "$D"
cp "$IMAGE_DIR/reference-values.json" "$IMAGE_DIR/reference-values.json.sig" "$D/"
cp -r "$REPO/docs/snp/evidence/tdx/collateral" "$D/collateral"
cat > "$D/peers.json" <<'EOF'
{
  "format": "gvisor.dev/gvisor/attest/peer-table",
  "version": 1,
  "peers": {"self": "10.0.2.15:4433"}
}
EOF
cat > "$D/tunneld.json" <<'EOF'
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "e5-local",
  "listen": "10.0.2.15:4433",
  "limits": {"idle_timeout": "60s", "max_age": "15m"},
  "start_timeout": "60s",
  "exercise": {"dial": ["self"], "wait": "3s", "exchanges": 3, "timeout": "90s"},
  "hold": "5s"
}
EOF
cat > "$D/network.conf" <<'EOF'
# The guest's addressing, outside the measurement (ticket 19). This one is
# QEMU's user-networking segment, not a Google VPC: the gateway is on-link, so
# the host route init.tdx adds to it is redundant rather than necessary, and it
# is still added because that is what the measured init does.
interface=eth0
address=10.0.2.15
prefix=24
gateway=10.0.2.2
mtu=1500
EOF
# LABEL unset for this call, for the reason smoke-tdx-guest.sh unsets it: this
# script has no LABEL of its own, but a caller's exported one would become the
# ext4 volume label and the guest would halt looking for attested-config.
SIZE_MB=64 env -u LABEL bash "$REPO/docs/snp/cloud/tdx/mkconfigdev-tdx.sh" "$D" "$OUTDIR/config.raw"

# ---- the workload device --------------------------------------------------
# E3's bundle, built by E3's own script so that all three vendors — the
# workstation, SNP and TDX — ran the same bytes. That script writes an SNP-sized
# device on the way; it is thrown away and the local one is built beside it.
bash "$REPO/docs/snp/evidence/ticket24/spikes/E3/make-bundle.sh" \
     "$OUTDIR/workload-src" "$OUTDIR/throwaway-snp-sized.img"
rm -f "$OUTDIR/throwaway-snp-sized.img"
SIZE_MB=64 bash "$REPO/docs/snp/cloud/tdx/mkworkloaddev-tdx.sh" \
     "$OUTDIR/workload-src" "$OUTDIR/workload.raw"
