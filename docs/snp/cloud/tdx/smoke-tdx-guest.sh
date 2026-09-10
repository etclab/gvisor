#!/bin/bash
# Boot one attested-tunnel guest on Google Cloud TDX and read the console
# (ticket 19, the smoke boot before the three scenarios).
#
#   IMAGE_DIR=<build-tdx-image.sh output> smoke-tdx-guest.sh [-keep]
#
# One instance, one config device, one boot. It publishes the built image and a
# config device as Compute Engine images, creates the VM, watches the serial
# console until tunneld exits or the deadline passes, takes the guest's own
# quote off the console and judges it on this workstation with
# attest/cmd/verify-evidence, and deletes the instance. Everything it created is
# printed as rows for docs/snp/cloud/tdx/RESOURCES.md; the ledger is written by
# a person, because a script that edited it would be claiming an instance was
# gone before the delete returned.
#
# # What the boot is supposed to prove
#
# That the pieces exist and fit, and that the prediction is right. Specifically,
# on the console, in this order: the initrd runs; the TDX guest driver, the NIC
# driver and nf_tables load; the config device is found and mounted read-only;
# the address on the config device comes up with the VPC's on-link gateway
# route; the egress rule set the signed policy implies is installed and read
# back out of the kernel; every attempt to reach the metadata server, a public
# resolver and the gateway is refused by a rule rather than by the routing
# table; and tunneld starts, asks this platform for evidence, and judges that
# evidence with its own reference value set.
#
# The last one is the one that matters, and it is checked twice: once by the
# guest, which cannot be trusted about itself, and once here, from the quote the
# guest printed, against the same signed set — which is the check a peer would
# make.
#
# Environment:
#   IMAGE_DIR    REQUIRED. build-tdx-image.sh's output directory.
#   VM           instance name (default tdx-smoke-a)
#   IP           the address the guest is given, and the one its config device
#                names (default 10.128.0.40). It is a --private-network-ip so
#                that it is known before the guest boots: the guest has no DHCP
#                client, because a guest that learned its address from the
#                network would be a guest whose address the network chose.
#   GATEWAY      the VPC gateway (default 10.128.0.1)
#   PORT         the tunnel port (default 4433, which is what the project's
#                existing firewall rule attested-tunnel-udp-4433 opens)
#   ZONE, OUT, BOOT_IMAGE, CONFIG_IMAGE, DEADLINE
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
ZONE="${ZONE:-us-central1-a}"
VM="${VM:-tdx-smoke-a}"
IP="${IP:-10.128.0.40}"
GATEWAY="${GATEWAY:-10.128.0.1}"
PORT="${PORT:-4433}"
MTU="${MTU:-1460}"
DEADLINE="${DEADLINE:-600}"
KEEP=0
LABEL="purpose=attested-tunnel-t19"
: "${IMAGE_DIR:?set IMAGE_DIR to the output directory of build-tdx-image.sh}"
IMAGE_DIR="$(readlink -f "$IMAGE_DIR")"
OUT="${OUT:-$REPO/docs/snp/evidence/ticket19/smoke}"
[ "${1:-}" = "-keep" ] && KEEP=1
export PATH="/usr/local/go/bin:$PATH"

RTMR2=$(sed -n 's/^predicted_rtmr2: //p' "$IMAGE_DIR/manifest.txt")
[[ "$RTMR2" =~ ^[0-9a-f]{96}$ ]] || { echo "no predicted_rtmr2 in $IMAGE_DIR/manifest.txt" >&2; exit 2; }
POLICY_DIGEST=$(sed -n 's/^policy_digest: *\([0-9a-f]\{64\}\).*/\1/p' "$IMAGE_DIR/manifest.txt")
BOOT_IMAGE="${BOOT_IMAGE:-attested-tdx-${RTMR2:0:12}}"
CONFIG_IMAGE="${CONFIG_IMAGE:-attested-config-$VM-$(date -u +%Y%m%d%H%M%S)}"

mkdir -p "$OUT"
OUT="$(readlink -f "$OUT")"
exec > >(tee "$OUT/smoke-run.txt") 2>&1

CREATED="" DELETED="(not deleted)" VERDICT="incomplete"
resources_row() {
  echo
  echo "############ for docs/snp/cloud/tdx/RESOURCES.md ############"
  echo "| created | name | type | purpose | state |"
  echo "|---|---|---|---|---|"
  printf '| %s | %s | c3-standard-4 TDX, %s, 20GB pd-balanced boot from custom image `%s` + 10GB pd-balanced config disk from `%s`, `--private-network-ip %s` | ticket 19 smoke boot: one guest from the built image, egress rule set installed and probed, tunneld self-check | **deleted %s** |\n' \
    "${CREATED:-(never created)}" "$VM" "$ZONE" "$BOOT_IMAGE" "$CONFIG_IMAGE" "$IP" "$DELETED"
  printf '| %s | %s | custom image, 10GiB, label `%s` | ticket 19: the attested tunnel guest image, predicted RTMR2 `%s` | **kept for the scenario runs** |\n' \
    "${CREATED:-}" "$BOOT_IMAGE" "$LABEL" "${RTMR2:0:8}…${RTMR2: -5}"
  printf '| %s | %s | custom image, 1GiB, label `%s` | ticket 19: %s config device (set, policy, peers, run config, addressing, Intel collateral) | **kept for the scenario runs** |\n' \
    "${CREATED:-}" "$CONFIG_IMAGE" "$LABEL" "$VM"
  echo
  echo "verdict: $VERDICT"
}
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  echo
  if [ "$KEEP" = 1 ]; then
    echo "keeping $VM (-keep); delete it by hand:"
    echo "  gcloud compute instances delete $VM --zone $ZONE --quiet"
    DELETED="(kept, -keep)"
  elif [ -n "$CREATED" ]; then
    echo "deleting $VM"
    if gcloud compute instances delete "$VM" --zone "$ZONE" --quiet; then
      DELETED="$(date -u +%Y-%m-%dT%H:%MZ)"
    else
      DELETED="**DELETE FAILED -- STILL RUNNING**"
      echo "the delete failed; $VM is still running and RESOURCES.md must say so"
    fi
  else
    echo "no instance was created; nothing to delete"
  fi
  gcloud compute instances list --filter="labels.purpose=attested-tunnel-t19" --format='value(name,zone,status)' || true
  resources_row
  echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ), exit $rc ==="
  exit "$rc"
}
trap cleanup EXIT
trap 'echo interrupted; exit 130' INT TERM

echo "=== TDX smoke boot (ticket 19): $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "project $(gcloud config get-value project 2>/dev/null) zone $ZONE"
echo "repo    $(git -C "$REPO" rev-parse HEAD)"
echo "image   $IMAGE_DIR (predicted RTMR2 $RTMR2)"
echo "policy  digest $POLICY_DIGEST"
echo "out     $OUT"
echo

# ---- the config device ----------------------------------------------------
echo "############ the config device ############"
D="$OUT/config-src"
rm -rf "$D"; mkdir -p "$D"
cp "$IMAGE_DIR/reference-values.json" "$IMAGE_DIR/reference-values.json.sig" \
   "$IMAGE_DIR/policy.json" "$IMAGE_DIR/policy.json.sig" "$D/"
cp -r "$REPO/docs/snp/evidence/tdx/collateral" "$D/collateral"
cat > "$D/peers.json" <<EOF
{
  "format": "gvisor.dev/gvisor/attest/peer-table",
  "version": 1,
  "peers": {"self": "$IP:$PORT"}
}
EOF
# The smoke guest's only peer is itself. That is not a placeholder: this image's
# policy forwards to this image's measurement and its set admits this image's
# measurement paired with this image's policy digest, so a guest dialing itself
# exercises every step a real pair would — evidence, chain, reference value,
# policy digest, binding — with one instance instead of two.
cat > "$D/tunneld.json" <<EOF
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "$VM",
  "listen": "$IP:$PORT",
  "limits": {"idle_timeout": "60s", "max_age": "15m"},
  "start_timeout": "60s",
  "exercise": {"dial": ["self"], "wait": "3s", "exchanges": 3, "timeout": "90s"},
  "hold": "60s"
}
EOF
cat > "$D/network.conf" <<EOF
# The guest's addressing, outside the measurement (ticket 19). A Google VPC
# gives a guest a /32 and an off-link gateway, so the initrd adds a host route
# to the gateway first and then the default route through it.
interface=eth0
address=$IP
prefix=32
gateway=$GATEWAY
mtu=$MTU
EOF
bash "$HERE/mkconfigdev-tdx.sh" "$D" "$OUT/config.raw"
echo

# ---- publish ---------------------------------------------------------------
echo "############ publishing the two images ############"
if gcloud compute images describe "$BOOT_IMAGE" >/dev/null 2>&1; then
  echo "boot image $BOOT_IMAGE exists already; reusing it"
else
  bash "$HERE/publish-tdx-image.sh" "$IMAGE_DIR/disk.raw" "$BOOT_IMAGE"
fi
bash "$HERE/publish-tdx-image.sh" "$OUT/config.raw" "$CONFIG_IMAGE"
echo

# ---- the instance ----------------------------------------------------------
if gcloud compute instances describe "$VM" --zone "$ZONE" >/dev/null 2>&1; then
  echo "$VM exists already; refusing to reuse it" >&2
  exit 2
fi
CREATED="$(date -u +%Y-%m-%dT%H:%MZ)"
echo "############ creating $VM at $CREATED ############"
gcloud beta compute instances create "$VM" --zone "$ZONE" \
  --machine-type c3-standard-4 \
  --confidential-compute-type TDX --maintenance-policy TERMINATE \
  --image "$BOOT_IMAGE" \
  --boot-disk-size 20GB --boot-disk-type pd-balanced --boot-disk-auto-delete \
  --create-disk "name=$VM-config,image=$CONFIG_IMAGE,size=10GB,type=pd-balanced,device-name=attested-config,auto-delete=yes" \
  --private-network-ip "$IP" \
  --labels "$LABEL" \
  --format 'value(name,zone,machineType,status,networkInterfaces[0].networkIP)'
echo

# ---- the console -----------------------------------------------------------
echo "############ watching the serial console ############"
# The console is fetched INCREMENTALLY and appended, never re-fetched whole and
# never redirected straight onto the capture.
#
# Two things go wrong with the obvious loop. Compute Engine returns an empty
# body for an instance that has stopped, so a loop that redirected onto the
# capture erases the transcript at the exact moment the guest finishes
# producing it; and a guest that boots, runs and powers itself off inside one
# poll interval leaves nothing behind at all. Both happened on this ticket
# before this loop was written this way. --start takes a byte offset and gcloud
# prints the next one on stderr, so each pass appends only what is new and the
# file only ever grows.
: > "$OUT/console.txt"
started=$(date +%s)
start=0
fetch() {
  gcloud compute instances get-serial-port-output "$VM" --zone "$ZONE" --port 1 --start="$start" \
    > "$OUT/console.chunk" 2> "$OUT/console.hint" || true
  if [ -s "$OUT/console.chunk" ]; then
    cat "$OUT/console.chunk" >> "$OUT/console.txt"
  fi
  local next
  next=$(sed -n 's/.*--start=\([0-9]\{1,\}\).*/\1/p' "$OUT/console.hint" | tail -1)
  [ -n "$next" ] && start="$next"
  rm -f "$OUT/console.chunk" "$OUT/console.hint"
}
while :; do
  fetch
  if grep -q '^initrd: EXIT status=' "$OUT/console.txt" 2>/dev/null; then
    echo "the guest finished: $(grep -h '^initrd: EXIT status=' "$OUT/console.txt" | tail -1)"
    break
  fi
  if grep -q '^initrd: FATAL' "$OUT/console.txt" 2>/dev/null; then
    echo "the guest halted: $(grep -h '^initrd: FATAL' "$OUT/console.txt" | tail -1)"
    break
  fi
  state=$(gcloud compute instances describe "$VM" --zone "$ZONE" --format='value(status)' 2>/dev/null || echo UNKNOWN)
  if [ "$state" != RUNNING ] && [ "$state" != STAGING ] && [ "$state" != PROVISIONING ]; then
    fetch
    echo "the instance is $state; the guest powered itself off"
    break
  fi
  now=$(date +%s)
  if [ $((now - started)) -ge "$DEADLINE" ]; then
    echo "deadline of ${DEADLINE}s passed without the guest finishing; taking the console as it is"
    break
  fi
  sleep 5
done
echo "console: $(wc -l < "$OUT/console.txt") lines in $OUT/console.txt"
echo
echo "---- the lines that matter ----"
grep -E '^initrd: (loaded|config device|link|loopback|EXIT|FATAL|WARNING|report interface)|^tunneld: (EGRESS|SELFCHECK VERDICT|SELFCHECK measurement|SELFCHECK mrtd|SELFCHECK rtmr|SELFCHECK tcb|policy |listening|PEER |REFUSED|LATENCY|EXIT|refusing)' \
  "$OUT/console.txt" || true
echo

# ---- the quote, judged here rather than there ------------------------------
echo "############ the guest's own quote, verified on this workstation ############"
awk '/SELFCHECK EVIDENCE BEGIN/{f=1;next} /SELFCHECK EVIDENCE END/{f=0} f' "$OUT/console.txt" \
  | sed -n 's/^tunneld: SELFCHECK EVIDENCE //p' | tr -d ' \r\n' | base64 -d > "$OUT/quote.bin" 2>/dev/null || true
KEYHEX=$(sed -n 's/^tunneld: SELFCHECK PUBLIC KEY //p' "$OUT/console.txt" | tail -1 | tr -d ' \r')
if [ -s "$OUT/quote.bin" ] && [ -n "$KEYHEX" ]; then
  echo "quote: $(stat -c %s "$OUT/quote.bin") bytes, sha256 $(sha256sum "$OUT/quote.bin" | cut -d' ' -f1)"
  printf '%s' "$KEYHEX" | xxd -r -p > "$OUT/public-key.der"
  python3 "$HERE/parse-tdx-quote.py" "$OUT/quote.bin" > "$OUT/quote.txt" 2>&1 || true
  sed -n 's/^\(mrtd\|rtmr0\|rtmr1\|rtmr2\|td_attributes\) *: /  &/p' "$OUT/quote.txt" || true
  cp "$IMAGE_DIR/reference-values.json" "$IMAGE_DIR/reference-values.json.sig" "$IMAGE_DIR/policy.json" "$IMAGE_DIR/policy.json.sig" "$OUT/"
  AUTHOR_PUB=$(sed -n 's/^signed by author key: *\([0-9a-f]\{64\}\).*/\1/p' "$IMAGE_DIR/manifest.txt")
  printf '%s\n' "$AUTHOR_PUB" > "$OUT/author.pub"
  (cd "$REPO/attest" && GOPROXY=off go run ./cmd/verify-evidence \
      -vendor intel-tdx \
      -evidence "$OUT/quote.bin" \
      -key "$OUT/public-key.der" \
      -refvals "$OUT/reference-values.json" \
      -author "$OUT/author.pub" \
      -policy-digest "$POLICY_DIGEST" \
      -tdx-collateral-dir "$REPO/docs/snp/evidence/tdx/collateral") > "$OUT/verify-evidence.txt" 2>&1 \
    && VERIFIED=yes || VERIFIED=no
  tail -30 "$OUT/verify-evidence.txt"
  echo "verify-evidence admitted the guest: $VERIFIED"
else
  echo "no quote on the console; the guest never got as far as the self-check"
  VERIFIED=no
fi

# ---- the verdict -----------------------------------------------------------
{
  echo "predicted RTMR2 (from the image, before the boot): $RTMR2"
  echo "RTMR2 in the guest's quote:                        $(sed -n 's/^rtmr2 *: //p' "$OUT/quote.txt" 2>/dev/null)"
  echo "RTMR1 in the guest's quote:                        $(sed -n 's/^rtmr1 *: //p' "$OUT/quote.txt" 2>/dev/null)"
  echo "MRTD  in the guest's quote:                        $(sed -n 's/^mrtd *: //p' "$OUT/quote.txt" 2>/dev/null)"
  echo "RTMR0 in the guest's quote:                        $(sed -n 's/^rtmr0 *: //p' "$OUT/quote.txt" 2>/dev/null)"
} | tee "$OUT/measurements.txt"
QUOTED=$(sed -n 's/^rtmr2 *: //p' "$OUT/quote.txt" 2>/dev/null || true)
if [ "$QUOTED" = "$RTMR2" ] && [ "${VERIFIED:-no}" = yes ]; then
  VERDICT="MATCH: the predicted RTMR2 is the register the hardware reported, and the signed set admits it"
elif [ -n "$QUOTED" ] && [ "$QUOTED" != "$RTMR2" ]; then
  VERDICT="MISMATCH: predicted $RTMR2, quoted $QUOTED"
else
  VERDICT="INCOMPLETE: see $OUT/console.txt"
fi
echo
echo "$VERDICT"
