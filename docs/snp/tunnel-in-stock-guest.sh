#!/bin/bash
# Ticket 14: the packaged tunneld against real silicon, without launching a
# guest.
#
#   tunnel-in-stock-guest.sh [-capture DIR] [-keep]
#
# What it is for. The two-guest run needs root — an SNP launch opens /dev/sev —
# and root here means the operator's spool. This needs neither: it runs the
# binary the image embeds inside the stock SEV-SNP guest ticket 01 left
# running, reached through $STACK/gssh, where the one privileged thing (inblob
# is root-only) is the guest's own sudo.
#
# What it establishes, and it is worth being exact because the two-guest run is
# the ticket and this is not it. Real reports from a physical AMD processor,
# bound to keys generated a moment earlier, carried in certificates, verified
# against AMD's own root through the chain provisioned on this chip — and a
# tunnel that exists because both sides did that. Then three things a seam test
# cannot show:
#
#   1. two tunnelds present distinct keys over one chip's chain, and the peer
#      writes down what each presented;
#   2. a peer that presents no evidence at all is refused on the wire, by a
#      real tunneld, and learns nothing about why (docs/snp/unattested-peer);
#   3. the latency table, on hardware.
#
# What it does not establish: two guests, and the measured image. The set here
# is the one ticket 05 authored for the *stock* guest's measurement, which
# attests nothing about a workload. Both tunnelds are in one guest, so this is
# ticket 13's property on hardware rather than the two-guest gate.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
OUT="${OUT:-$STACK/ticket14-run/stock}"
GSSH="$STACK/gssh"
EV="$REPO/docs/snp/evidence"
CAPTURE=""; KEEP=0
while [ -n "${1:-}" ]; do
  case "$1" in
    -capture) CAPTURE="$2"; shift 2 ;;
    -keep)    KEEP=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
export PATH="/usr/local/go/bin:$PATH"
mkdir -p "$OUT"
TRANSCRIPT="$OUT/stock-guest-run.txt"
exec > >(tee "$TRANSCRIPT") 2>&1
PASSES=0; FAILURES=0
pass() { PASSES=$((PASSES+1)); echo "PASS  $*"; }
fail() { FAILURES=$((FAILURES+1)); echo "FAIL  $*"; }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
has() { grep -qF -- "$2" "$1"; }

echo "=== ticket 14: the packaged tunneld on real silicon, in ticket 01's stock guest ==="
echo "date : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "repo : $(git -C "$REPO" rev-parse HEAD) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
bash "$GSSH" 'echo "guest: $(uname -r)"; sudo dmesg | grep -m1 -i "Memory Encryption Features active" | sed "s/^/guest: /"'
echo

# ---- the bundle -----------------------------------------------------------
B="$OUT/bundle"
rm -rf "$B"; mkdir -p "$B/config"
echo "building the two binaries this run needs"
# Built exactly as package-tunneld.sh builds it, -trimpath and all, so that the
# binary this run exercises is byte-for-byte the one the image embeds at the
# same commit. Without the flags it would differ in nothing but the paths
# compiled into it, which is a difference nobody can check by eye and everybody
# has to explain.
(cd "$REPO/attest" && go test -count=1 ./cmd/tunneld >/dev/null \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$B/tunneld" ./cmd/tunneld)
(cd "$HERE/unattested-peer" && CGO_ENABLED=0 go build -o "$B/unattested-peer" .)
file "$B/tunneld" | grep -q 'statically linked' || { echo "tunneld is not static" >&2; exit 1; }
echo "tunneld sha256 $(sha256sum "$B/tunneld" | cut -d' ' -f1)"

# Ticket 05's set: authored for the stock guest's predicted measurement, signed
# by that run's throwaway author key. Nothing here reads a measurement off a
# machine.
cp "$EV/ticket05/reference-values.json" "$EV/ticket05/reference-values.json.sig" "$B/config/"
cp "$EV/ticket05/author.pub" "$B/"
cp "$EV/certificate-chain.bin" "$EV/certificate-chain.json" "$B/config/"
printf '{"peers": {"stock-a": "127.0.0.1:14433"}}\n' > "$B/config/peers.json"
cat > "$B/config/tunneld-a.json" <<'JSON'
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "stock-a",
  "listen": "127.0.0.1:14433",
  "limits": {"idle_timeout": "60s", "max_age": "15m"},
  "hold": "25s"
}
JSON
# The dialer's maximum age is deliberately absurd. The config device is outside
# the launch measurement, so this is what a host would write to stop
# re-attestation ever happening again; the binary clamps it and says so, and
# this run is where that is shown on hardware rather than only in a unit test.
cat > "$B/config/tunneld-b.json" <<'JSON'
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "stock-b",
  "listen": "127.0.0.1:14434",
  "limits": {"idle_timeout": "60s", "max_age": "8760h"},
  "exercise": {
    "dial": ["stock-a"],
    "wait": "60s",
    "payload": "attested-tunnel-plaintext-marker",
    "exchanges": 20,
    "concurrency": 8,
    "rounds": 3
  }
}
JSON
echo "copying it into the guest"
bash "$GSSH" 'rm -rf ~/ticket14-stock; mkdir -p ~/ticket14-stock'
bash "$GSSH" --scp -r "$B" G:ticket14-stock/ >/dev/null

# ---- the run --------------------------------------------------------------
cat > "$OUT/guest-run.sh" <<'EOS'
set -u
cd ~/ticket14-stock/bundle
# A tunneld from an earlier run holds its port for as long as its hold lasts,
# and a second one that cannot bind is a run whose exchanges were answered by
# the first. Ask any of them to go first.
sudo pkill -f 'tunneld -config' 2>/dev/null && sleep 2
sudo modprobe sev-guest 2>/dev/null
sudo mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
( sudo ./tunneld -config config -author author.pub -run config/tunneld-a.json > a.log 2>&1 & )
sleep 4
echo "### a peer presenting no evidence at all"
./unattested-peer -addr 127.0.0.1:14433 2>&1 | grep -v 'receive buffer size'
echo "unattested-peer exit=${PIPESTATUS[0]}"
sleep 1
echo "### the control: a peer that does present evidence"
sudo ./tunneld -config config -author author.pub -run config/tunneld-b.json > b.log 2>&1
echo "tunneld-b exit=$?"
# The answerer writes down what it saw when its hold runs out, so wait for it
# rather than reading a log it has not finished.
for i in $(seq 1 60); do grep -q "EXIT status" a.log && break; sleep 1; done
echo "=== BEGIN a.log"; cat a.log; echo "=== END a.log"
echo "=== BEGIN b.log"; cat b.log; echo "=== END b.log"
EOS
echo
bash "$GSSH" 'bash -s' < "$OUT/guest-run.sh" > "$OUT/run.txt" 2>&1 || true
sed 's/^/    | /' "$OUT/run.txt"
sed -n '/=== BEGIN a.log/,/=== END a.log/p' "$OUT/run.txt" > "$OUT/console-a.txt"
sed -n '/=== BEGIN b.log/,/=== END b.log/p' "$OUT/run.txt" > "$OUT/console-b.txt"

# ---- what it showed -------------------------------------------------------
echo
A="$OUT/console-a.txt"; Bl="$OUT/console-b.txt"; R="$OUT/run.txt"
check "both tunnelds acquired real evidence from the platform" \
      bash -c "test \$(grep -c 'returned 1184 bytes of evidence' '$R') -eq 2"
check "both tunnelds started; neither was answered by a leftover from an earlier run" \
      bash -c "test \$(grep -c 'tunneld: listening on' '$R') -eq 2"
check "both bundled the chain provisioned for this chip, not the platform's empty table" \
      has "$R" "its own certificate table is empty (auxblob, 0 bytes)"
check "a tunnel was established, which took both sides admitting the other" has "$Bl" "kind=establish"
check "exchanges succeeded over it"            has "$Bl" 'answered_by="stock-a"'
check "concurrent exchanges shared the one tunnel" has "$Bl" "kind=concurrent"
check "the peer that presented no evidence was refused" \
      has "$A" "REFUSED verification refused: no evidence presented"
check "and it learned nothing about why"       has "$R" "tls: bad certificate"
check "and it did not get an application round trip" has "$R" "no application round trip"
# The attacker's own verdict, which is a different claim from the tunneld's:
# status 0 is "the peer refused me", status 3 is "I never reached it". Without
# this the two are indistinguishable in a transcript, and an unreachable
# listener would read as a refusal that never happened.
check "the attacker reached the listener and was refused by it, rather than never reaching it" \
      has "$R" "unattested-peer exit=0"
check "the control peer, on the same listener in the same run, was admitted" \
      has "$A" "tunneld: PEER key="
# A maximum age the host could raise is a re-attestation the host could delete,
# so the ceiling is in the measured binary and a clamp that bites is loud.
check "a year-long maximum age from the config device was clamped" \
      has "$Bl" "CLAMPED"
check "and the tunneld ran on the ceiling, not on what it was handed" \
      has "$Bl" "maximum age 15m0s"
KEY_A=$(sed -n 's/.*PEER SEEN key=\([0-9a-f]*\).*/\1/p' "$Bl" | head -1)
KEY_B=$(sed -n 's/.*PEER SEEN key=\([0-9a-f]*\).*/\1/p' "$A" | head -1)
CHAIN_A=$(sed -n 's/.*PEER SEEN .*chain=\([0-9a-f]*\).*/\1/p' "$Bl" | head -1)
CHAIN_B=$(sed -n 's/.*PEER SEEN .*chain=\([0-9a-f]*\).*/\1/p' "$A" | head -1)
echo "    stock-a presented key $KEY_A"
echo "    stock-b presented key $KEY_B"
check "the two tunnelds presented distinct keys" \
      test -n "$KEY_A" -a -n "$KEY_B" -a "$KEY_A" != "$KEY_B"
check "over one chip's chain, which is what one guest means" \
      test -n "$CHAIN_A" -a -n "$CHAIN_B" -a "$CHAIN_A" = "$CHAIN_B"

echo
echo "=== latency on hardware, as the dialing tunneld measured it ==="
grep -h LATENCY "$Bl" | sed 's/^tunneld: /  /'
echo
echo "=== $PASSES passed, $FAILURES failed ==="
[ "$KEEP" = 1 ] || bash "$GSSH" 'rm -rf ~/ticket14-stock' || true
if [ -n "$CAPTURE" ]; then
  mkdir -p "$CAPTURE"
  # run.txt is not captured: the transcript already carries every line of it,
  # indented, and two copies of one file in an evidence directory invite a
  # reader to wonder which one is authoritative.
  for f in console-a.txt console-b.txt; do
    cp "$OUT/$f" "$CAPTURE/stock-$f" 2>/dev/null || true
  done
  cp "$TRANSCRIPT" "$CAPTURE/" 2>/dev/null || true
  echo "captured into $CAPTURE"
fi
[ "$FAILURES" = 0 ]
