#!/bin/bash
# Confidentiality experiment: fill a known fraction of guest RAM with a canary,
# then read the guest's RAM backing from the host as root and count how many
# copies are visible.
#
# Run it twice on the same disk, kernel and initrd -- once with SEV-SNP and once
# without. The non-SNP run is the control: it shows the method finds the canary
# when the guest is not confidential, which is what makes the SNP run's result
# evidence rather than an absence of proof.
#
# The count is never expected to be exactly zero under SNP. Anything the guest
# sends out -- an ssh command line, console output -- crosses shared SWIOTLB
# bounce buffers, so a handful of copies of the marker text legitimately appear
# in host-visible memory. What must not appear is the bulk: the canary written
# into guest RAM pages.
set -u
STACK="$(dirname "$(readlink -f "$0")")"
MARKER="TICKET01-SNP-CANARY-0xDEADBEEFCAFEBABE"
FILL_MB="${FILL_MB:-1536}"

echo "filling ${FILL_MB} MiB of guest RAM (tmpfs) with the canary..."
bash "$STACK/gssh" "sudo mkdir -p /mnt/canary && (mountpoint -q /mnt/canary || sudo mount -t tmpfs -o size=2G tmpfs /mnt/canary) && sudo python3 -c \"
m=b'$MARKER'
blk=(m*(1024*1024//len(m)+1))[:1024*1024]
f=open('/mnt/canary/c.bin','wb')
for _ in range($FILL_MB): f.write(blk)
f.flush(); import os; os.fsync(f.fileno())
print('wrote', $FILL_MB, 'MiB')
\" && free -m | head -2"

PER_MB=$((1024 * 1024 / ${#MARKER}))
echo
echo "canary is ${#MARKER} bytes; ~$PER_MB copies per MiB; ~$((PER_MB * FILL_MB)) copies written into guest RAM"
echo "now read that RAM from the host, as root:"
