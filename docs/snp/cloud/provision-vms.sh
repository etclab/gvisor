#!/bin/bash
# Create the cloud side of the mixed run, and bring the listener up.
#
#   provision-vms.sh [create|chain|deploy|start|check|status|stop|delete]...
#
# The provider's flags live here and in probe-platform.sh and nowhere else.
# Steps, each idempotent, run in this order the first time:
#
#   create   the two instances and one firewall rule (below)
#   chain    a raw report off the listener, the chain from AMD's key
#            distribution service for it (attest/cmd/provision-chain), and the
#            auxblob the provider filled, compared against what KDS returned
#   deploy   the static tunneld, the unattested peer, the relay, and the
#            listener's config directory
#   start    tunneld on the listener, listening on 0.0.0.0:4433, holding
#   check    the non-confidential relay VM dials the listener with no evidence
#            and is refused (docs/snp/unattested-peer)
#   status / stop / delete   what they say; stop between sessions, delete at
#            the end. Every create/stop/delete is recorded in RESOURCES.md.
#
# Topology (gcp-two-vms.md, "Recommended topology"):
#
#   shs1 measured guest --UDP, NAT--> relay (e2-small, public IP) --internal--> listener (n2d SEV-SNP)
#
# The listener has no external ingress at all: the relay reaches it on the
# VPC's internal range, which default-allow-internal already permits. The
# relay's UDP 4433 is opened to THIS host's egress address only. The listener's
# chain and config live in /opt/attested-tunnel on the VM; the evidence copied
# back lives in docs/snp/evidence/cloud/listener/.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
export PATH="/usr/local/go/bin:$PATH"
ZONE="${ZONE:-us-central1-a}"          # us-east1-b cannot place an N2D SEV-SNP VM (probes, 2026-08-27)
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
IMAGE_DIR="${IMAGE_DIR:-$STACK/image-cloud}"
EV="$REPO/docs/snp/evidence/cloud"
REFVALS="${REFVALS:-$HERE/refvals}"
WORK="${WORK:-$STACK/cloud-provision}"; mkdir -p "$WORK" "$EV/listener" "$EV/unattested"
RES="$HERE/RESOURCES.md"
PORT=4433

ssh_vm() { gcloud compute ssh "$1" --zone "$ZONE" --quiet -- -o StrictHostKeyChecking=no -o ConnectTimeout=20 "${@:2}"; }
scp_to() { gcloud compute scp --zone "$ZONE" --quiet "${@:1:$#-1}" "${@: -1}"; }
wait_ssh() { local i; for i in $(seq 1 30); do ssh_vm "$1" true 2>/dev/null && return 0; sleep 10; done; echo "$1 never answered ssh" >&2; return 1; }
record() { printf '| %s | %s | %s | %s | %s |\n' "$(date -u +%Y-%m-%dT%H:%MZ)" "$1" "$2" "$3" "$4" >> "$RES"; }
internal_ip() { gcloud compute instances describe "$1" --zone "$ZONE" --format 'value(networkInterfaces[0].networkIP)'; }
external_ip() { gcloud compute instances describe "$1" --zone "$ZONE" --format 'value(networkInterfaces[0].accessConfigs[0].natIP)'; }
egress_ip() { curl -4 -s --max-time 10 https://ifconfig.me || curl -4 -s --max-time 10 https://api.ipify.org; }

step_create() {
  local me; me=$(egress_ip); [ -n "$me" ] || { echo "cannot learn this host's egress address" >&2; exit 1; }
  echo "this host's egress address: $me"
  if ! gcloud compute instances describe listener --zone "$ZONE" >/dev/null 2>&1; then
    gcloud compute instances create listener --zone "$ZONE" \
      --machine-type n2d-standard-2 --min-cpu-platform "AMD Milan" \
      --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
      --image-project ubuntu-os-cloud --image-family ubuntu-2404-lts-amd64 \
      --boot-disk-size 10GB --labels purpose=attested-tunnel --format 'value(name,status)'
    record listener "n2d-standard-2 SEV-SNP, $ZONE" "the attested peer in the cloud (~\$0.08/h)" created
  fi
  if ! gcloud compute instances describe relay --zone "$ZONE" >/dev/null 2>&1; then
    gcloud compute instances create relay --zone "$ZONE" \
      --machine-type e2-small --tags attested-tunnel-relay \
      --image-project ubuntu-os-cloud --image-family ubuntu-2404-lts-amd64 \
      --boot-disk-size 10GB --labels purpose=attested-tunnel --format 'value(name,status)'
    record relay "e2-small, $ZONE, public IP" "the on-path attacker and the non-confidential peer (~\$0.02/h)" created
  fi
  if ! gcloud compute firewall-rules describe attested-tunnel-udp-$PORT >/dev/null 2>&1; then
    gcloud compute firewall-rules create attested-tunnel-udp-$PORT --network default --direction INGRESS \
      --action ALLOW --rules udp:$PORT --source-ranges "$me/32" --target-tags attested-tunnel-relay --quiet
    record attested-tunnel-udp-$PORT "firewall rule, default network" "udp:$PORT to the relay from $me/32 only" created
  else
    gcloud compute firewall-rules update attested-tunnel-udp-$PORT --source-ranges "$me/32" --quiet
  fi
  step_status
}

step_chain() {
  wait_ssh listener
  scp_to "$REPO/docs/snp/guest-evidence.sh" listener:/tmp/guest-evidence.sh >/dev/null
  ssh_vm listener 'uname -r; sudo bash /tmp/guest-evidence.sh /tmp/evidence' > "$EV/listener/guest-evidence.txt" 2>&1
  sed -n '/===BEGIN report.bin===/,/===END report.bin===/p' "$EV/listener/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$EV/listener/report.bin"
  sed -n '/===BEGIN certs.bin===/,/===END certs.bin===/p'   "$EV/listener/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$EV/listener/auxblob.bin"
  rm -rf "$EV/listener/auxblob-certs"
  python3 "$REPO/docs/snp/parse-snp-report.py" "$EV/listener/report.bin" --certs "$EV/listener/auxblob.bin" \
      --extract-certs "$EV/listener/auxblob-certs" > "$EV/listener/report.txt" 2>&1
  grep -E 'LAUNCH MEASUREMENT|chip_id|reported_tcb|current firmware' "$EV/listener/report.txt"
  echo "\$ provision-chain fetch (from this host, against AMD's KDS)"
  (cd "$REPO/attest" && go run ./cmd/provision-chain fetch -report "$EV/listener/report.bin" -out "$EV/listener") 2>&1 | tee "$EV/listener/provision-chain.txt"
  cat "$EV/listener/certificate-chain.json"
  # Is the VCEK the provider cached the one KDS issues? Both are AMD
  # certificate tables keyed by GUID, so the same decoder reads both, and the
  # comparison is per certificate: bytes, and failing that the public key —
  # KDS re-issues the VCEK certificate on every fetch with the fetch time as
  # notBefore, so two fetches of one key are two certificates.
  rm -rf "$EV/listener/kds-certs"
  python3 "$REPO/docs/snp/parse-snp-report.py" "$EV/listener/report.bin" --certs "$EV/listener/certificate-chain.bin" \
      --extract-certs "$EV/listener/kds-certs" > /dev/null 2>&1
  for der in "$EV/listener"/auxblob-certs/*.der; do
    n=$(basename "$der"); k="$EV/listener/kds-certs/$n"
    subj=$(openssl x509 -inform DER -in "$der" -noout -subject | sed 's/.*CN = //')
    if [ ! -f "$k" ]; then echo "$n ($subj): in auxblob, not in the KDS chain"
    elif cmp -s "$der" "$k"; then echo "$n ($subj): byte-identical to the KDS chain's"
    elif [ "$(openssl x509 -inform DER -in "$der" -noout -pubkey)" = "$(openssl x509 -inform DER -in "$k" -noout -pubkey)" ]; then
      echo "$n ($subj): same public key, different certificate (auxblob notBefore $(openssl x509 -inform DER -in "$der" -noout -startdate | cut -d= -f2); KDS notBefore $(openssl x509 -inform DER -in "$k" -noout -startdate | cut -d= -f2))"
    else echo "$n ($subj): DIFFERENT KEY"; fi
  done | tee "$EV/listener/auxblob-vs-kds.txt"
}

listener_json() {
  cat <<JSON
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "gcp-listener",
  "listen": "0.0.0.0:$PORT",
  "limits": {"idle_timeout": "60s", "max_age": "15m"},
  "start_timeout": "60s",
  "hold": "6h"
}
JSON
}

step_deploy() {
  local bin="$WORK/tunneld" peer="$WORK/unattested-peer" want got
  (cd "$REPO/attest" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$bin" ./cmd/tunneld)
  want=$(sed -n 's/^tunneld sha256: //p' "$EV/packaging.txt"); got=$(sha256sum "$bin" | cut -c1-64)
  [ "$want" = "$got" ] || { echo "the tunneld built here ($got) is not the one packaged into the image ($want)" >&2; exit 1; }
  echo "tunneld $got, the same bytes the measured image embeds"
  (cd "$REPO/docs/snp/unattested-peer" && CGO_ENABLED=0 go build -o "$peer" .)
  local cfg="$WORK/listener-config"; rm -rf "$cfg"; mkdir -p "$cfg"
  cp "$REFVALS/reference-values.json" "$REFVALS/reference-values.json.sig" "$cfg/"
  cp "$EV/listener/certificate-chain.bin" "$EV/listener/certificate-chain.json" "$cfg/"
  echo '{"peers": {}}' > "$cfg/peers.json"
  listener_json > "$cfg/tunneld.json"
  wait_ssh listener; wait_ssh relay
  ssh_vm listener 'sudo mkdir -p /opt/attested-tunnel && sudo chown $USER /opt/attested-tunnel' >/dev/null
  scp_to --recurse "$bin" "$cfg" "$IMAGE_DIR/build/author.pub" listener:/opt/attested-tunnel/ >/dev/null
  ssh_vm listener 'cd /opt/attested-tunnel && mv -f listener-config config && chmod +x tunneld && ls -la . config' | sed 's/^/    /'
  ssh_vm relay 'mkdir -p ~/attested-tunnel' >/dev/null
  scp_to "$HERE/udprelay.py" "$peer" relay:~/attested-tunnel/ >/dev/null
  ssh_vm relay 'chmod +x ~/attested-tunnel/*; python3 --version; ls -la ~/attested-tunnel' | sed 's/^/    /'
}

step_start() {
  ssh_vm listener 'sudo pkill -x tunneld 2>/dev/null; sleep 1
    sudo modprobe tsm 2>/dev/null; sudo modprobe sev-guest 2>/dev/null; mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
    cd /opt/attested-tunnel && sudo bash -c "nohup ./tunneld -config /opt/attested-tunnel/config -author /opt/attested-tunnel/author.pub > console.txt 2>&1 &"
    sleep 5; cat console.txt'
}

step_check() {
  local lip; lip=$(internal_ip listener)
  echo "\$ unattested-peer -addr $lip:$PORT, from the relay (non-confidential, nothing to present)"
  local rc=0
  ssh_vm relay "~/attested-tunnel/unattested-peer -addr $lip:$PORT" > "$EV/unattested/unattested-peer.txt" 2>&1 || rc=$?
  echo "exit status $rc" | tee -a "$EV/unattested/unattested-peer.txt"
  sed 's/^/    | /' "$EV/unattested/unattested-peer.txt"
  sleep 1
  ssh_vm listener 'grep -E "REFUSED|no evidence" /opt/attested-tunnel/console.txt | tail -3' | tee "$EV/unattested/listener-console-excerpt.txt"
}

step_status() {
  gcloud compute instances list --filter 'labels.purpose=attested-tunnel' --format 'table(name,zone.basename(),machineType.basename(),status,networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP)'
}
step_stop()   { gcloud compute instances stop listener relay --zone "$ZONE" --quiet; record "listener, relay" instances "" stopped; }
step_delete() {
  gcloud compute instances delete listener relay --zone "$ZONE" --quiet && record "listener, relay" instances "" deleted
  gcloud compute firewall-rules delete attested-tunnel-udp-$PORT --quiet && record attested-tunnel-udp-$PORT "firewall rule" "" deleted
}

[ $# -gt 0 ] || set -- create chain deploy start check
for s in "$@"; do echo; echo "=== $s ==="; "step_$s"; done
