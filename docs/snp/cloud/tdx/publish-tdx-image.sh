#!/bin/bash
# Turn a raw disk image into a Google Compute Engine custom image (ticket 19).
#
#   publish-tdx-image.sh RAW IMAGE_NAME
#
# There is no way to hand Compute Engine a block of bytes directly: an image is
# created either from an existing disk or from a gzipped tar in Cloud Storage.
# A disk would need a helper VM to write it, so this takes the second route —
# one bucket, one object, one image, and the bucket is deleted on the way out
# because a bucket left behind is a resource nobody is watching.
#
# The tar is the shape Compute Engine insists on: exactly one member, named
# disk.raw, at the root, gzipped, in the old GNU format. It is written sparse,
# so a mostly-empty ten gibibyte image is a small upload.
#
# # Guest OS features are not decoration
#
# A custom image carries none unless it is told to, and a Confidential VM will
# not start from an image that does not say TDX_CAPABLE. The list here is the
# one the pinned Ubuntu image carries, minus the ones about live migration,
# which a confidential VM does not do. UEFI_COMPATIBLE is what makes the
# firmware boot shim rather than a BIOS loader, and GVNIC is what puts the
# guest on the driver its kernel has (docs/snp/evidence/ticket19/step-zero/:
# ens3 on gve).
#
# Environment:
#   BUCKET   the Cloud Storage bucket to stage through; created if absent, and
#            deleted afterwards unless KEEP_BUCKET=1
#   REGION   where the bucket lives (default us-central1)
#   LABELS   labels for the image (default purpose=attested-tunnel-t19)
set -euo pipefail
RAW="${1:?RAW disk image}"
IMAGE_NAME="${2:?IMAGE_NAME}"
REGION="${REGION:-us-central1}"
LABELS="${LABELS:-purpose=attested-tunnel-t19}"
BUCKET="${BUCKET:-attested-tunnel-t19-$(date -u +%Y%m%d%H%M%S)}"
KEEP_BUCKET="${KEEP_BUCKET:-0}"
FEATURES="${FEATURES:-UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC,VIRTIO_SCSI_MULTIQUEUE,SEV_CAPABLE,SEV_SNP_CAPABLE}"
LICENSE="${LICENSE:-https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/licenses/ubuntu-2404-lts}"

RAW="$(readlink -f "$RAW")"
WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK"
  if [ "$KEEP_BUCKET" != 1 ] && [ -n "${BUCKET_CREATED:-}" ]; then
    echo "deleting gs://$BUCKET"
    gcloud storage rm -r "gs://$BUCKET" --quiet || echo "  the bucket delete FAILED; gs://$BUCKET is still there"
  fi
}
trap cleanup EXIT

echo "=== publish-tdx-image $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "raw    $RAW ($(stat -c %s "$RAW") bytes, sha256 $(sha256sum "$RAW" | cut -d' ' -f1))"
echo "image  $IMAGE_NAME"

if gcloud compute images describe "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "image $IMAGE_NAME exists already; refusing to overwrite it" >&2
  exit 2
fi

# Compute Engine wants the member called disk.raw and nothing else in the tar.
ln -s "$RAW" "$WORK/disk.raw"
echo "packing $WORK/disk.tar.gz (sparse, old GNU format)"
if command -v pigz >/dev/null; then
  tar --format=oldgnu -Sc -C "$WORK" --dereference disk.raw | pigz -6 > "$WORK/disk.tar.gz"
else
  tar --format=oldgnu -Sczf "$WORK/disk.tar.gz" -C "$WORK" --dereference disk.raw
fi
echo "  $(stat -c %s "$WORK/disk.tar.gz") bytes"

# --soft-delete-duration=0s matters: without it Cloud Storage keeps deleted
# objects for a week, so a bucket that was "deleted" is still holding a
# gigabyte of image somewhere nobody is looking.
echo "creating gs://$BUCKET in $REGION"
gcloud storage buckets create "gs://$BUCKET" --location="$REGION" \
  --uniform-bucket-level-access --soft-delete-duration=0s --quiet
BUCKET_CREATED=1
gcloud storage buckets update "gs://$BUCKET" --update-labels="$LABELS" --quiet \
  || echo "  (could not label the bucket; it is deleted at the end of this run either way)"
gcloud storage cp "$WORK/disk.tar.gz" "gs://$BUCKET/$IMAGE_NAME.tar.gz" --quiet

echo "creating the image"
if ! gcloud compute images create "$IMAGE_NAME" \
      --source-uri "gs://$BUCKET/$IMAGE_NAME.tar.gz" \
      --guest-os-features="$FEATURES" \
      --licenses="$LICENSE" \
      --labels="$LABELS" \
      --description="attested tunnel guest, ticket 19; raw sha256 $(sha256sum "$RAW" | cut -d' ' -f1)" \
      --format='value(name,status,diskSizeGb)'; then
  echo "the create with --licenses failed; retrying without it"
  gcloud compute images create "$IMAGE_NAME" \
    --source-uri "gs://$BUCKET/$IMAGE_NAME.tar.gz" \
    --guest-os-features="$FEATURES" \
    --labels="$LABELS" \
    --format='value(name,status,diskSizeGb)'
fi

gcloud compute images describe "$IMAGE_NAME" \
  --format='yaml(name,status,diskSizeGb,guestOsFeatures,labels)'
echo "published $IMAGE_NAME"
echo "staged through gs://$BUCKET (created and deleted inside this run)"
