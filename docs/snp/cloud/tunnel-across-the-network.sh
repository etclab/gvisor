#!/bin/bash
# The attested tunnel across a real network: this host's measured guest
# dialing one confidential VM in Google Cloud (gcp-two-vms.md, mixed shape).
#
#   tunnel-across-the-network.sh -relay-ip IP -listener-ip IP
#                                [-zone Z] [-relay-vm NAME] [-listener-vm NAME]
#                                [-image DIR] [-refvals DIR] [-cloud-m HEX]
#                                [-out DIR] [-capture DIR] [-run-for SECONDS]
#                                [-quick] [-scenario NAME]... [-spool DIR]
#
# What this run is and is not, first. The cloud peer is booted by the
# provider's firmware and its launch measurement covers exactly that firmware
# (probe-platform.sh: two different boot disks, one measurement, and the value
# is in the provider's own published endorsements). Our binary is not in that
# measurement and nothing about the workload is, so ticket 14's criteria 1, 2
# and 6 are absent for the cloud peer, and admitting it means admitting any VM
# the provider booted. A mixed federation is exactly as fine-grained as its
# coarsest member. What this run establishes is attestation and transport
# across two confidential hosts: two chips, two product lines (Genoa here,
# Milan there), two certificate chains, a NAT and a real network in the path,
# and a latency figure for that path. The measured side keeps everything
# ticket 14 established about itself, which is why criterion 6 survives on
# this side: the `modified` scenario boots a mutated image here and the cloud
# peer refuses it.
#
# The shape: the local guest is THE DIALER, behind QEMU's user-mode NAT
# (docs/snp/cloud/nat-guest.sh), with a default route in its run configuration
# and every frame it emits captured by QEMU's filter-dump. Its peer table
# names not the listener but the RELAY — an ordinary, non-confidential VM with
# a public address running docs/snp/cloud/udprelay.py, which forwards to the
# listener's internal address and records everything it carries. The listener
# is a SEV-SNP VM running the same cmd/tunneld binary that is inside the
# measured image (same sha256, no link configuration, an ordinary directory
# for a config device), already up with a long hold before this script starts
# (docs/snp/cloud/provision-vms.sh). Its console is read over ssh; the local
# guest's is its serial console, as in ticket 14.
#
#   live       both attested, the exchange, the latency table; >15min so the
#              re-attestation appears. Also the control, run first and last.
#   nat-gap    the exercise repeats every 120s against a 60s idle timeout, so
#              the tunnel dies idle and the NAT mapping may or may not: what
#              the next dial costs is the answer to tunnel.Limits' question.
#   tamper     the relay flips a bit in every twentieth datagram.
#   modified   the local guest boots an image with one byte changed and the
#              cloud listener refuses it, naming the measurement internally.
#   tcbfloor   the local guest holds a set whose cloud value has a floor above
#              Milan's TCB, and refuses the listener.
#   live-again a short live run after the refusals, on the same wiring.
#
# Prerequisites: everything tunnel-on-two-guests.sh lists, plus gcloud
# authenticated for the project, the two VMs RUNNING with tunneld listening
# on the listener, and the root runner up in the primary checkout.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
SNPDIR="$(dirname "$HERE")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
export PATH="/usr/local/go/bin:$PATH"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
export SEV_SNP_MEASURE_VENV="${SEV_SNP_MEASURE_VENV:-$STACK/sev-snp-measure-venv-cloud}"
IMAGE="${IMAGE:-$STACK/image-cloud}"
REFVALS="${REFVALS:-$HERE/refvals}"
OUT="${OUT:-$STACK/cloud-run}"
CHAIN="${CHAIN:-$REPO/docs/snp/evidence}"
CLOUD_M="2d24cf9624ee36449e50c6c84042540b05898f6559f02741b7b354e0cc2ed18d108352ade7dfc4cecce4fa974e51c773"
RELAY_IP=""; LISTENER_IP=""; ZONE="us-central1-a"; RELAY_VM="relay"; LISTENER_VM="listener"
CAPTURE=""; RUN_FOR=1000; SCENARIOS=(); SPOOL=""
MARKER="attested-tunnel-plaintext-marker"
LISTENER_CONSOLE="/opt/attested-tunnel/console.txt"
GUEST_ADDR="10.0.2.15"; GATEWAY="10.0.2.2"
TAMPER=0
while [ -n "${1:-}" ]; do
  case "$1" in
    -relay-ip)    RELAY_IP="$2"; shift 2 ;;
    -listener-ip) LISTENER_IP="$2"; shift 2 ;;
    -zone)        ZONE="$2"; shift 2 ;;
    -relay-vm)    RELAY_VM="$2"; shift 2 ;;
    -listener-vm) LISTENER_VM="$2"; shift 2 ;;
    -image)       IMAGE="$2"; shift 2 ;;
    -refvals)     REFVALS="$2"; shift 2 ;;
    -cloud-m)     CLOUD_M="$2"; shift 2 ;;
    -out)         OUT="$2"; shift 2 ;;
    -scenario)    SCENARIOS+=("$2"); shift 2 ;;
    -spool)       SPOOL="$2"; shift 2 ;;
    -run-for)     RUN_FOR="$2"; shift 2 ;;
    -quick)       RUN_FOR=150; shift ;;
    -capture)     CAPTURE="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$RELAY_IP" ] && [ -n "$LISTENER_IP" ] || { echo "need -relay-ip and -listener-ip (provision-vms.sh prints them)" >&2; exit 2; }
[ ${#SCENARIOS[@]} -gt 0 ] || SCENARIOS=(live nat-gap tamper modified tcbfloor live-again)

mkdir -p "$OUT"
TRANSCRIPT="$OUT/tunnel-run.txt"
exec > >(tee "$TRANSCRIPT") 2>&1
PASSES=0; FAILURES=0

# The relay runs on another machine, so what is held here is the ssh that
# started it, and what has to be undone there is done by name over a fresh ssh.
RELAY_SSH_PID=""
stop_relay() {
  vm_ssh "$RELAY_VM" 'pkill -INT -f udprelay.py; sleep 2; pkill -f udprelay.py' >/dev/null 2>&1 || true
  if [ -n "$RELAY_SSH_PID" ] && kill -0 "$RELAY_SSH_PID" 2>/dev/null; then
    wait "$RELAY_SSH_PID" 2>/dev/null || true
  fi
  RELAY_SSH_PID=""
}
cleanup() { local rc=$?; stop_relay; return $rc; }
trap cleanup EXIT
trap 'echo "interrupted"; cleanup; exit 130' INT TERM
note()  { echo "$*"; }
pass()  { PASSES=$((PASSES+1)); echo "PASS  $*"; }
fail()  { FAILURES=$((FAILURES+1)); echo "FAIL  $*"; }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
in_file() { grep -qF -- "$2" "$1"; }
not_in_file() { ! grep -qF -- "$2" "$1"; }

vm_ssh() { local vm="$1"; shift; gcloud compute ssh "$vm" --zone "$ZONE" --quiet -- -o StrictHostKeyChecking=no -o ConnectTimeout=30 "$@"; }
vm_scp_from() { gcloud compute scp --zone "$ZONE" --quiet "$1:$2" "$3" >/dev/null; }

echo "=== the attested tunnel across a real network ==="
echo "date        : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "repo        : $(git -C "$REPO" rev-parse HEAD) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
echo "image       : $IMAGE (the dialer, this host, Genoa)"
echo "listener    : $LISTENER_VM $LISTENER_IP in $ZONE (SEV-SNP, Milan, provider firmware)"
echo "relay       : $RELAY_VM $RELAY_IP (ordinary VM; the attacker; what the dialer's peer table names)"
echo "refvals     : $REFVALS"
echo "scenarios   : ${SCENARIOS[*]}"
echo

for f in OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img manifest.txt; do
  [ -f "$IMAGE/$f" ] || { echo "missing $IMAGE/$f — run docs/snp/image/package-tunneld.sh with OUT=$IMAGE first" >&2; exit 1; }
done
for f in reference-values.json reference-values.json.sig; do
  [ -f "$REFVALS/$f" ] || { echo "missing $REFVALS/$f — provision-vms.sh authors the two-value set" >&2; exit 1; }
done
MEASUREMENT=$(sed -n 's/^launch_measurement: //p' "$IMAGE/manifest.txt")
echo "predicted launch measurement of the image the dialer boots:"
echo "  $MEASUREMENT"
echo "launch measurement of the provider's firmware, which is all the cloud peer attests:"
echo "  $CLOUD_M"
echo "both sides' reference value sets name both; the author key is inside the dialer's image"
echo "and is the file the listener was started with (-author)."
echo

# ---- the cloud side must already be up ------------------------------------
note "checking the cloud side"
for vm in "$LISTENER_VM" "$RELAY_VM"; do
  status=$(gcloud compute instances describe "$vm" --zone "$ZONE" --format 'value(status)' 2>/dev/null || echo ABSENT)
  [ "$status" = RUNNING ] || { echo "$vm is $status; provision-vms.sh brings it up" >&2; exit 1; }
done
if ! vm_ssh "$LISTENER_VM" "sudo grep -q 'tunneld: listening on' $LISTENER_CONSOLE && pgrep -x tunneld >/dev/null" 2>/dev/null; then
  echo "tunneld is not listening on $LISTENER_VM (no 'listening on' in $LISTENER_CONSOLE or no process); provision-vms.sh starts it" >&2
  exit 1
fi
vm_ssh "$RELAY_VM" 'test -f ~/attested-tunnel/udprelay.py || test -f ~/udprelay.py || test -f /tmp/udprelay.py' 2>/dev/null \
  || { echo "udprelay.py is not on $RELAY_VM; provision-vms.sh copies it" >&2; exit 1; }
RELAY_PY=$(vm_ssh "$RELAY_VM" 'ls ~/attested-tunnel/udprelay.py ~/udprelay.py /tmp/udprelay.py 2>/dev/null | head -1' 2>/dev/null | tr -d '\r')
note "listener is up; relay script at $RELAY_VM:$RELAY_PY"
MY_EGRESS=$(curl -4 -s --max-time 10 https://ifconfig.me || echo unknown)
note "this host's egress address: $MY_EGRESS (the relay's firewall rule admits it and nothing else)"
echo

# ---- the spool ------------------------------------------------------------
find_spool() {
  [ -n "$SPOOL" ] && { echo "$SPOOL"; return 0; }
  local main
  main=$(git -C "$REPO" worktree list | head -1 | awk '{print $1}')
  for d in "$main/docs/snp/root-spool" "$REPO/docs/snp/root-spool" "$STACK/root-spool"; do
    [ -d "$d" ] && { echo "$d"; return 0; }
  done
  return 1
}
if ! SPOOL=$(find_spool); then
  cat >&2 <<MSG
No spool directory. The dialer is an SNP guest and opens /dev/sev, which is root-only
here. The operator starts the runner once, in the PRIMARY checkout:

    sudo bash /home/pniroula/Projects/gvisor/docs/snp/root-runner.sh
MSG
  exit 3
fi
echo "spool       : $SPOOL"

spool_run() {
  local name="$1" script="$2" limit="$3"
  local job="$SPOOL/cloud-$$-$name"
  cp "$script" "$job.staging"
  mv "$job.staging" "$job.job"
  note "spooled $job.job; waiting up to ${limit}s for the runner"
  local waited=0
  while [ ! -f "$job.rc" ]; do
    sleep 2; waited=$((waited+2))
    if [ "$waited" -ge "$limit" ]; then
      fail "the runner never ran $name — is docs/snp/root-runner.sh up?"
      return 1
    fi
  done
  note "$name finished, rc=$(cat "$job.rc")"
  sed 's/^/    | /' "$job.out"
  return 0
}

# ---- the dialer's config device -------------------------------------------
#   make_config DIR RUN_JSON [-refvals DIR]
make_config() {
  local dir="$1" runjson="$2"; shift 2
  local refvals="$REFVALS"
  while [ -n "${1:-}" ]; do
    case "$1" in
      -refvals) refvals="$2"; shift 2 ;;
      *) echo "make_config: unknown option $1" >&2; exit 2 ;;
    esac
  done
  rm -rf "$dir"; mkdir -p "$dir"
  cp "$refvals/reference-values.json" "$refvals/reference-values.json.sig" "$dir/"
  cp "$CHAIN/certificate-chain.bin" "$CHAIN/certificate-chain.json" "$dir/"
  printf '{"peers": {"gcp-listener": "%s:4433"}}\n' "$RELAY_IP" > "$dir/peers.json"
  printf '%s\n' "$runjson" > "$dir/tunneld.json"
  bash "$SNPDIR/image/mkconfigdev.sh" "$dir" "$dir.img" | sed 's/^/    /'
}

# The dialer's run configuration. Limits identical to the listener's
# (provision-vms.sh: idle 60s, max_age 15m), because QUIC's idle timeout is
# the minimum of what the two peers advertise.
dialer_json() { # RUN_FOR WAIT REPEAT_EVERY
  cat <<JSON
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "shs1-guest",
  "listen": "$GUEST_ADDR:4433",
  "link": {"interface": "eth0", "address": "$GUEST_ADDR", "prefix_length": 24, "gateway": "$GATEWAY"},
  "limits": {"idle_timeout": "60s", "max_age": "15m"},
  "exercise": {
    "dial": ["gcp-listener"],
    "wait": "$2",
    "payload": "$MARKER",
    "exchanges": 20,
    "concurrency": 8,
    "rounds": 3,
    "repeat_every": "$3",
    "run_for": "$1"
  },
  "hold": "5s"
}
JSON
}

# ---- one scenario ---------------------------------------------------------
# run_dialer WORKDIR IMAGE SECONDS
# Starts the relay on the cloud VM, boots the dialer through the spool, then
# collects the relay's record and the listener's console slice.
run_dialer() {
  local work="$1" image="$2" seconds="$3"
  local name; name=$(basename "$work")
  local offset
  offset=$(vm_ssh "$LISTENER_VM" "sudo wc -c < $LISTENER_CONSOLE" 2>/dev/null | tr -dc '0-9')
  offset="${offset:-0}"
  echo "$offset" > "$work/listener-console.offset"

  local tamper_flag=""
  [ "$TAMPER" != 0 ] && tamper_flag="--tamper $TAMPER"
  vm_ssh "$RELAY_VM" "rm -f /tmp/$name.pcap /tmp/$name-relay.txt /tmp/$name-relay.log; nohup python3 $RELAY_PY \
      --listen 0.0.0.0:4433 --forward $LISTENER_IP:4433 --pcap /tmp/$name.pcap --marker $MARKER \
      --summary /tmp/$name-relay.txt --seconds $((seconds + 60)) $tamper_flag > /tmp/$name-relay.log 2>&1 &
      sleep 1; pgrep -f udprelay.py >/dev/null && echo relay-started || echo relay-FAILED" 2>/dev/null | tr -d '\r' | sed 's/^/    relay: /'

  cat > "$work/boot.job" <<JOB
# Cloud run: launch the dialing guest of $name.
#
# Privileged only because an SNP launch opens /dev/sev. One guest; the other
# side is a VM in Google Cloud that is already listening. The guest sits behind
# QEMU's user-mode NAT and every frame it sends is written to guest.pcap.
set -u
timeout $seconds bash "$HERE/nat-guest.sh" -image "$image" -config "$work/config.img" \\
    -console "$work/console.txt" -pcap "$work/guest.pcap" -mac 52:54:00:c1:00:0a
echo "guest qemu exited \$?"
chown -R $(id -u):$(id -g) "$work" 2>/dev/null
chmod -R a+rX "$work" 2>/dev/null
JOB
  spool_run "$name" "$work/boot.job" "$((seconds + 240))" || true

  stop_relay
  vm_scp_from "$RELAY_VM" "/tmp/$name-relay.txt" "$work/relay.txt" 2>/dev/null || note "no relay summary came back"
  vm_scp_from "$RELAY_VM" "/tmp/$name-relay.log" "$work/relay.log" 2>/dev/null || true
  vm_scp_from "$RELAY_VM" "/tmp/$name.pcap" "$work/relay.pcap" 2>/dev/null || note "no relay pcap came back"
  vm_ssh "$LISTENER_VM" "sudo tail -c +$((offset + 1)) $LISTENER_CONSOLE" 2>/dev/null | tr -d '\r' > "$work/listener-console.txt" || true
  # The listener's startup lines predate every scenario's slice; the tsm
  # observation about its certificate table is one of them.
  vm_ssh "$LISTENER_VM" "sudo grep -E 'tunneld: (sandbox|author key|tsm:|listening on|holding)' $LISTENER_CONSOLE | tail -5" 2>/dev/null | tr -d '\r' > "$work/listener-startup.txt" || true
  note "relay:"; sed 's/^/    | /' "$work/relay.txt" 2>/dev/null || true
  note "listener console during $name:"; sed 's/^/    | /' "$work/listener-console.txt" | head -40
  if [ -f "$work/guest.pcap" ]; then
    note "what the guest put on its link (guest.pcap):"
    python3 "$HERE/pcap-census.py" "$work/guest.pcap" | sed 's/^/    | /' | tee "$work/guest-census.txt" >/dev/null
    sed 's/^/    | /' "$work/guest-census.txt"
  fi
}

assert_dialer_booted() { # CONSOLE
  local c="$1"
  check "dialer: booted the measured image and ran the packaged tunneld" in_file "$c" "init: running /usr/bin/tunneld"
  check "dialer: no writable path in the image is executable" in_file "$c" "init: no writable path is executable"
  check "dialer: read the author key from inside the launch measurement" in_file "$c" "/etc/attested-tunnel/author.pub, inside the launch measurement"
  check "dialer: brought its link up with a default route" in_file "$c" "default route via $GATEWAY"
}
assert_dialer_attested() { # CONSOLE
  local c="$1"
  check "dialer: acquired its own evidence from the platform" in_file "$c" 'provider "sev_guest" (amd-sev-snp) returned 1184 bytes'
  check "dialer: bundled the chain provisioned on its config device; its own auxblob is empty, as on this host" \
        in_file "$c" "its own certificate table is empty (auxblob, 0 bytes)"
  check "dialer: is listening" in_file "$c" "tunneld: listening on"
}
peer_field() { sed -n "s/.*PEER SEEN .*$2=\([0-9a-f]*\).*/\1/p" "$1" | head -1; }
# The listener's console is one long file across scenarios and its PEER SEEN
# summary only appears at exit, so what it saw during a scenario is read from
# the abbreviated PEER line it prints when a peer first appears, and the
# full-length fields are matched by prefix.
listener_peer_prefix() { sed -n "s/.*tunneld: PEER key=.*$2=\([0-9a-f]*\)….*/\1/p" "$1" | head -1; }

# guest_census_bad PCAP-CENSUS: anything the guest sent that is not the relay
# or its own segment.
guest_census_bad() {
  local census="$1"
  grep -E '^  [0-9.]+ -> ' "$census" \
    | grep -v "^  $GUEST_ADDR -> $RELAY_IP proto=UDP" \
    | grep -v " -> $GUEST_ADDR " || true
}

# ---- scenario: live -------------------------------------------------------
scenario_live() {
  local work="$OUT/$1" seconds="$2"
  echo
  echo "### $1: the measured guest dials the cloud listener through the relay"
  mkdir -p "$work"
  make_config "$work/config" "$(dialer_json "${seconds}s" 90s 30s)"
  run_dialer "$work" "$IMAGE" "$((seconds + 240))"

  local c="$work/console.txt" l="$work/listener-console.txt"
  [ -f "$c" ] || { fail "$1: the dialer left no console"; return; }
  assert_dialer_booted "$c"; assert_dialer_attested "$c"
  check "listener: its evidence came with a populated certificate table (auxblob), unlike this host" \
        grep -qE 'auxblob, [1-9][0-9]* bytes' "$work/listener-startup.txt"

  check "listener admitted the dialer's evidence"        in_file "$l" "tunneld: PEER key="
  check "dialer admitted the listener's evidence"        in_file "$c" "tunneld: PEER key="
  check "dialer established a tunnel"                    in_file "$c" "kind=establish"
  check "dialer exchanged over it, warm"                 in_file "$c" "kind=warm_exchange"
  check "dialer ran concurrent exchanges on one tunnel"  in_file "$c" "kind=concurrent"
  check "the listener answered the dialer's exchanges"   in_file "$c" 'answered_by="gcp-listener"'
  check "dialer's exercise completed"                    in_file "$c" "tunneld: EXIT status=0"
  check "the dialer refused nobody"                      not_in_file "$c" "tunneld: REFUSED"
  check "the listener refused nobody during this scenario" not_in_file "$l" "tunneld: REFUSED"

  # What each side wrote down about the other. Two chips, so two chains — the
  # opposite of what ticket 14 asserted, for the opposite reason.
  local chain_of_listener chain_of_dialer m_of_listener m_of_dialer
  chain_of_listener=$(peer_field "$c" chain); m_of_listener=$(peer_field "$c" measurement)
  chain_of_dialer=$(listener_peer_prefix "$l" chain); m_of_dialer=$(listener_peer_prefix "$l" measurement)
  echo "    the dialer saw the listener's chain    $chain_of_listener"
  echo "    the listener saw the dialer's chain    $chain_of_dialer…"
  echo "    the dialer saw the listener's M        $m_of_listener"
  echo "    the listener saw the dialer's M        $m_of_dialer…"
  check "the two peers presented different chains: two chips, two product lines" \
        test -n "$chain_of_listener" -a -n "$chain_of_dialer" -a "${chain_of_listener:0:16}" != "$chain_of_dialer"
  check "the dialer saw the provider firmware's measurement, which is all the cloud peer attests" \
        test "$m_of_listener" = "$CLOUD_M"
  check "the listener saw the measurement predicted offline for the image the dialer booted" \
        test -n "$m_of_dialer" -a "${MEASUREMENT:0:16}" = "$m_of_dialer"

  # The relay carried it and could not read it; the guest sent to the relay and
  # nowhere else.
  check "the exchange went through the relay"           grep -qE "dialer_to_listener_dgrams=[1-9]" "$work/relay.txt"
  check "the relay found no plaintext on the wire"      in_file "$work/relay.txt" "MARKER not found"
  local bad
  bad=$(guest_census_bad "$work/guest-census.txt")
  [ -n "$bad" ] && echo "    off-plan traffic on the guest's link:" && echo "$bad" | sed 's/^/      /'
  check "the guest sent IPv4 to the relay's address and port and to nothing else" test -z "$bad"
  local arps
  arps=$(sed -n 's/^arp targets: //p' "$work/guest-census.txt" | tr ',' '\n' | tr -d ' ' | grep -v '^$' | grep -vE "^($GATEWAY|$GUEST_ADDR)$" || true)
  check "the guest resolved its gateway and nothing else" test -z "$arps"

  local passes handshakes
  passes=$(grep -c "kind=establish" "$c" || true)
  handshakes=$(grep -c "kind=establish .*verifier_calls=[1-9]" "$c" || true)
  echo "    passes: $passes, of which cost a verification: $handshakes (maximum age 15m, run ${seconds}s)"
  check "asking for a warm peer again cost no handshake" test "$passes" -gt "$handshakes"
  if [ "$seconds" -gt 900 ]; then
    check "the tunnel was re-attested when it reached its maximum age" test "$handshakes" -ge 2
  fi
}

# ---- scenario: the NAT gap ------------------------------------------------
# tunnel.Limits: "nothing is sent to hold the path open, deliberately, so a
# middlebox between two guests that drops an idle flow sooner than this closes
# the tunnel first: the re-dial covers it, but in a trace it looks like a lost
# tunnel rather than like a NAT." Ticket 14 could not produce a middlebox.
# This run has QEMU's user-mode NAT by construction, and the exercise here
# idles the tunnel past its own 60s idle timeout AND past whatever slirp's
# UDP mapping lifetime is, so each pass after the first meets a tunnel that
# is gone and a NAT mapping that may be. What that costs — a re-dial, a
# re-attestation, a failed attempt first — is recorded, not asserted.
scenario_natgap() {
  local work="$OUT/nat-gap" seconds=600
  echo
  echo "### nat-gap: the tunnel idles past its timeout and past the NAT mapping's"
  mkdir -p "$work"
  make_config "$work/config" "$(dialer_json "${seconds}s" 90s 120s)"
  run_dialer "$work" "$IMAGE" "$((seconds + 240))"
  local c="$work/console.txt"
  [ -f "$c" ] || { fail "nat-gap: the dialer left no console"; return; }
  check "nat-gap: the dialer's exercise completed"   in_file "$c" "tunneld: EXIT status=0"
  local passes verified retried
  passes=$(grep -c "kind=establish" "$c" || true)
  verified=$(grep -c "kind=establish .*verifier_calls=[1-9]" "$c" || true)
  retried=$(grep -c "not up yet, retrying" "$c" || true)
  echo "    passes: $passes; establishes that cost a verification: $verified; passes whose first attempt failed: $retried"
  grep -E "kind=establish|not up yet|FAILED" "$c" | sed 's/^tunneld: /    | /'
  if [ "$passes" -gt 0 ] && [ "$verified" = "$passes" ]; then
    echo "    NAT GAP: each pass cost a verification — the tunnel was gone every time (idle 60s < 120s) and re-dialed; re-attestation, not a lost tunnel"
  elif [ "$verified" -le 1 ]; then
    echo "    NAT GAP: cost nothing — the tunnel survived the gap, which means the idle timeout did not fire"
  else
    echo "    NAT GAP: mixed — $verified of $passes passes re-attested"
  fi
  [ "$retried" -gt 0 ] && echo "    and $retried pass(es) failed a first attempt, which is what a dropped NAT mapping looks like from inside" || echo "    and no pass failed a first attempt: the NAT mapping either survived or was re-created transparently"
  pass "nat-gap: recorded (the outcome is a finding, not an assertion)"
}

# ---- scenario: tamper -----------------------------------------------------
scenario_tamper() {
  local work="$OUT/tamper"
  echo
  echo "### tamper: the relay changes a bit in every twentieth datagram"
  mkdir -p "$work"
  make_config "$work/config" "$(dialer_json 60s 90s 30s)"
  TAMPER=20
  run_dialer "$work" "$IMAGE" 300
  TAMPER=0
  local c="$work/console.txt"
  [ -f "$c" ] || { fail "tamper: the dialer left no console"; return; }
  check "the attacker really did change datagrams"        grep -qE "tampered=[1-9]" "$work/relay.txt"
  check "no exchange took a changed datagram for its peer's answer" not_in_file "$c" "want <sandbox>:"
  check "the exchanges completed anyway, because QUIC discards what it cannot authenticate" in_file "$c" 'answered_by="gcp-listener"'
  check "and the attacker still read nothing"             in_file "$work/relay.txt" "MARKER not found"
}

# ---- scenario: modified ---------------------------------------------------
# Criterion 6 on the one side where it still means something: the dialer's
# image is the measured one, so a byte changed in it moves M, and the cloud
# listener — whose set names the predicted M — refuses it.
scenario_modified() {
  local work="$OUT/modified"
  echo
  echo "### modified: the dialer boots an image with one byte changed"
  mkdir -p "$work"
  local mutated="$OUT/image-modified"
  if [ ! -f "$mutated/rootfs.img" ]; then
    note "building the mutated image (ticket 08's mutate-image.sh, one byte of rootfs.img)"
    bash "$SNPDIR/image/mutate-image.sh" -base "$IMAGE" -out "$mutated" -mutation rootfs-byte | sed 's/^/    /'
  fi
  bash "$SNPDIR/image/predict-measurement.sh" "$mutated" -vcpus 4 -vcpu-type EPYC-v4 \
      -out "$work/mutated-measurement.txt" > /dev/null
  local mutated_m
  mutated_m=$(sed -n 's/^launch_measurement: //p' "$work/mutated-measurement.txt")
  echo "    the mutated image's predicted measurement: $mutated_m"
  echo "    the image both sets name:                  $MEASUREMENT"
  check "one byte of the root filesystem moved the launch measurement" \
        test -n "$mutated_m" -a "$mutated_m" != "$MEASUREMENT"
  make_config "$work/config" "$(dialer_json 0s 60s 30s)"
  run_dialer "$work" "$mutated" 300
  local c="$work/console.txt" l="$work/listener-console.txt"
  [ -f "$c" ] || { fail "modified: the dialer left no console"; return; }
  assert_dialer_attested "$c"
  check "the listener refused the modified guest, naming the measurement internally" \
        in_file "$l" "REFUSED verification refused: launch measurement not in the reference value set"
  check "the listener admitted nobody during this scenario" not_in_file "$l" "tunneld: PEER key="
  check "the modified guest was told nothing but that it did not get a tunnel" in_file "$c" "peer=gcp-listener FAILED"
  check "the modified guest itself admitted the listener, so the refusal is one-sided" in_file "$c" "tunneld: PEER key="
  check "the modified guest's exercise failed"            in_file "$c" "tunneld: EXIT status=2"
}

# ---- scenario: tcbfloor ---------------------------------------------------
# The dialer's set keeps both measurements and both policies and raises one
# number: the cloud value's microcode floor, to one the Milan platform does
# not meet. Same author key, so the set loads; the refusal is the floor's.
scenario_tcbfloor() {
  local work="$OUT/tcbfloor"
  echo
  echo "### tcbfloor: the dialer holds a set whose cloud value's floor is above Milan's TCB"
  mkdir -p "$work"
  local key="$IMAGE-packaging/author.key"
  [ -f "$key" ] || { fail "tcbfloor: no author key at $key; package-tunneld.sh keeps it"; return; }
  local refvals="$work/refvals-tcbfloor"
  (cd "$HERE/emit-refvals-multi" && go build -o "$work/emit-refvals-multi" .)
  "$work/emit-refvals-multi" -key "$key" -out "$refvals" \
      -value "$MEASUREMENT:9,0,23,72:0x30000" -value "$CLOUD_M:4,0,29,255:0x30000" | sed 's/^/    /'
  make_config "$work/config" "$(dialer_json 0s 60s 30s)" -refvals "$refvals"
  run_dialer "$work" "$IMAGE" 300
  local c="$work/console.txt" l="$work/listener-console.txt"
  [ -f "$c" ] || { fail "tcbfloor: the dialer left no console"; return; }
  check "the dialer refused a platform below its floor" in_file "$c" "REFUSED verification refused: platform below the TCB floor"
  check "the dialer admitted nobody"                    not_in_file "$c" "tunneld: PEER key="
  check "the dialer got no tunnel"                      in_file "$c" "peer=gcp-listener FAILED"
  # Not the mirror of ticket 14's one-sided refusal, and the first run of this
  # scenario asserted that it was and failed. There the refuser was the
  # listener and the refused dialer had already admitted it; here the refuser
  # IS the dialer, and a TLS 1.3 client judges the server's certificate before
  # it sends its own, so the listener never sees a certificate to judge: no
  # PEER line, no REFUSED line, only an aborted handshake. Which side refuses
  # decides whether the other side ever gets to admit.
  check "the listener saw nothing to judge: the dialer aborted before presenting anything" \
        not_in_file "$l" "tunneld: PEER key="
  check "and the listener refused nobody either" not_in_file "$l" "tunneld: REFUSED"
}

# ---- run them -------------------------------------------------------------
for s in "${SCENARIOS[@]}"; do
  case "$s" in
    live)       scenario_live live "$RUN_FOR" ;;
    live-again) scenario_live live-again 150 ;;
    nat-gap)    scenario_natgap ;;
    tamper)     scenario_tamper ;;
    modified)   scenario_modified ;;
    tcbfloor)   scenario_tcbfloor ;;
    *) echo "unknown scenario: $s" >&2; exit 2 ;;
  esac
done

echo
echo "=== latency, as the dialing guest measured it, across $MY_EGRESS -> $RELAY_IP -> $LISTENER_IP ==="
echo "GCP notice 2026-07-28: SEV-SNP instances may have longer boot times and performance changes Aug–Nov 2026 (guest kernel migration)"
grep -h "LATENCY" "$OUT"/*/console.txt 2>/dev/null | sed 's/^tunneld: /  /' || echo "  none recorded"

echo
echo "=== $PASSES passed, $FAILURES failed ==="
if [ -n "$CAPTURE" ]; then
  mkdir -p "$CAPTURE"
  cp "$TRANSCRIPT" "$CAPTURE/" 2>/dev/null || true
  for d in "$OUT"/*/; do
    n=$(basename "$d")
    case "$n" in image-*|config*) continue ;; esac
    mkdir -p "$CAPTURE/$n"
    cp "$d"/console.txt "$d"/listener-console.txt "$d"/listener-startup.txt "$d"/relay.txt "$d"/relay.log "$d"/relay.pcap "$d"/guest.pcap \
       "$d"/guest-census.txt "$d"/boot.job "$d"/mutated-measurement.txt "$d"/config/tunneld.json "$d"/config/peers.json "$CAPTURE/$n/" 2>/dev/null || true
    [ -d "$d/refvals-tcbfloor" ] && cp -r "$d/refvals-tcbfloor" "$CAPTURE/$n/" 2>/dev/null || true
  done
  mkdir -p "$CAPTURE/refvals"
  cp "$REFVALS"/reference-values.json "$REFVALS"/reference-values.json.sig "$REFVALS"/PROVENANCE.md "$CAPTURE/refvals/" 2>/dev/null || true
  cp "$IMAGE/manifest.txt" "$IMAGE/predicted-measurement.txt" "$IMAGE/packaging.txt" "$CAPTURE/" 2>/dev/null || true
  echo "captured into $CAPTURE"
fi
[ "$FAILURES" = 0 ]
