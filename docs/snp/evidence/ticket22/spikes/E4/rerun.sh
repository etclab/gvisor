#!/bin/bash
# E4: a config device without a policy, and one with a stale policy beside it.
#
#   rerun.sh [WORKDIR]
#
# WORKDIR defaults to a fresh mktemp -d. Nothing here needs root: tunneld takes
# the config device as a DIRECTORY (-config), so no disk image and no mount is
# involved. -egress print reads the same documents a serving tunneld reads and
# touches neither the kernel nor the network.
#
# It rebuilds the two binaries, lays out the seven config directories this spike
# used, and replays every capture in logs/. On a machine with no
# /sys/kernel/config/tsm/report -- any host that is not itself a confidential
# guest -- the serving path stops in newVendorSeam before it reads a document,
# so the document order is observed through drv/ instead, a stub-seam driver
# that calls tunneld.New directly. See README.md.
set -eu

REPO=${REPO:-/home/pniroula/Projects/gvisor-t22}
GO=${GO:-/usr/local/go/bin/go}
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
W=${1:-$(mktemp -d)}
T19="$REPO/docs/snp/evidence/ticket19/scenario-one"

mkdir -p "$W/bin" "$W/logs" "$W/cfg"
echo "workdir: $W"

# --- binaries ---------------------------------------------------------------
( cd "$REPO/attest" && "$GO" build -o "$W/bin/tunneld" ./cmd/tunneld )
( cd "$REPO/attest" && "$GO" build -o "$W/bin/attest-tool" ./cmd/attest-tool )
( cd "$REPO/docs/snp/image/emit-refvals" && GOFLAGS=-mod=mod "$GO" build -o "$W/bin/emit-refvals" . )

# The stub-seam driver: its own module, outside the repository, so that nothing
# is added to attest/. Its go.mod is attest/go.mod with a replace pointing back.
mkdir -p "$W/drv"
cp "$HERE/drv/main.go" "$W/drv/main.go"
sed "s|=> .*/attest$|=> $REPO/attest|" "$HERE/drv/go.mod" > "$W/drv/go.mod"
cp "$REPO/attest/go.sum" "$W/drv/go.sum"
( cd "$W/drv" && GOFLAGS=-mod=mod GOPROXY=off "$GO" build -o "$W/bin/e4drv" . )

# --- C1: the config device ticket 22 wants -----------------------------------
# Ticket 19's own recorded reference value set and its signature, which load
# under the author key recorded beside them. The private half of that key is not
# on this branch and is not needed: verification takes the document, the
# detached signature and the public key.
mkdir -p "$W/cfg/C1"
cp "$T19/config-src/a/reference-values.json" "$T19/config-src/a/reference-values.json.sig" "$W/cfg/C1/"
cp "$T19/author.pub" "$W/cfg/author-t19.pub"
cp -r "$REPO/docs/snp/evidence/tdx/collateral" "$W/cfg/C1/collateral"
cat > "$W/cfg/C1/peers.json" <<'EOF'
{
  "format": "gvisor.dev/gvisor/attest/peer-table",
  "version": 1,
  "peers": {"guest-b": "127.0.0.1:4434"}
}
EOF
cat > "$W/cfg/C1/tunneld.json" <<'EOF'
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "e4-guest-a",
  "listen": "127.0.0.1:4433",
  "limits": {"idle_timeout": "5m", "max_age": "3m"},
  "start_timeout": "10s",
  "hold": "5s"
}
EOF

# --- the throwaway-key documents ---------------------------------------------
# Reused from this directory if they are here, so that a re-run reproduces F1's
# digest. The private half is deliberately not kept (ticket 21's harness keeps
# none either); regenerating one gives a different, equally valid, digest.
mkdir -p "$W/cfg/fresh"
if [ -f "$HERE/cfg/fresh/policy.json" ]; then
  cp "$HERE/cfg/fresh/"* "$W/cfg/fresh/"
  cp "$HERE/cfg/author-fresh.pub" "$W/cfg/author-fresh.pub"
else
  openssl genpkey -algorithm ed25519 -out "$W/cfg/throwaway.key.pem"
  M=$(printf 'ab%.0s' $(seq 1 48))
  "$W/bin/emit-refvals" -measurement "$M" -key "$W/cfg/throwaway.key.pem" -tcb 4,0,22,213 -out "$W/cfg/fresh"
  "$W/bin/emit-refvals" -emit-policy -key "$W/cfg/throwaway.key.pem" -out "$W/cfg/fresh"
  "$W/bin/emit-refvals" -digest-of "$W/cfg/fresh/policy.json"
  openssl pkey -in "$W/cfg/throwaway.key.pem" -pubout -outform DER |
    tail -c 32 | od -An -tx1 | tr -d ' \n' > "$W/cfg/author-fresh.pub"
  echo >> "$W/cfg/author-fresh.pub"
fi

# --- C2 and the variants ------------------------------------------------------
cd "$W/cfg"
for d in C2 C2b C3 C4 F1 F2; do rm -rf "$d"; cp -r C1 "$d"; done
cp "$T19/config-src/a/policy.json" "$T19/config-src/a/policy.json.sig" C2/   # same author key as the set
cp fresh/policy.json fresh/policy.json.sig                                C2b/  # today's format, different key
cp "$T19/config-src/a/policy.json.sig"                                    C3/   # the signature alone
cp "$T19/config-src/a/policy.json"                                        C4/   # the document alone
cp fresh/reference-values.json fresh/reference-values.json.sig fresh/policy.json fresh/policy.json.sig F1/
cp fresh/reference-values.json fresh/reference-values.json.sig            F2/
cp "$T19/config-src/a/policy.json" "$T19/config-src/a/policy.json.sig"    F2/

# --- the captures -------------------------------------------------------------
# Every capture below is expected to fail: a refusal is the answer this spike is
# after, and an exit status of 1 is most of the record. errexit therefore stops
# here and the status is written into each transcript instead.
set +e

cap() { # NAME CONFIGDIR AUTHORFILE
  n=$1; d=$2; a=$3
  {
    echo "\$ tunneld -config $d -author $a -egress print"
    timeout 15 "$W/bin/tunneld" -config "$W/cfg/$d" -author "$W/cfg/$a" -egress print 2>&1
    echo "EXIT_STATUS=$?"
  } > "$W/logs/$n-egress-print.txt"
  {
    echo "\$ e4drv -config $d -author $a"
    timeout 20 "$W/bin/e4drv" -config "$W/cfg/$d" -author "$W/cfg/$a" 2>&1
    echo "EXIT_STATUS=$?"
  } > "$W/logs/$n-tunneldNew.txt"
}
serve() { # NAME CONFIGDIR AUTHORFILE
  n=$1; d=$2; a=$3
  {
    echo "\$ tunneld -config $d -author $a -tdx-collateral-dir $d/collateral"
    timeout 15 "$W/bin/tunneld" -config "$W/cfg/$d" -author "$W/cfg/$a" \
      -tdx-collateral-dir "$W/cfg/$d/collateral" 2>&1
    echo "EXIT_STATUS=$?"
  } > "$W/logs/$n-serve.txt"
}
serve C1 C1 author-t19.pub
serve C2 C2 author-t19.pub
cap C1  C1  author-t19.pub
cap C2  C2  author-t19.pub
cap C2b C2b author-t19.pub
cap C3  C3  author-t19.pub
cap C4  C4  author-t19.pub
cap F1  F1  author-fresh.pub
cap F2  F2  author-fresh.pub

# --- ticket 19's recorded verdicts, replayed as they stand today --------------
H="$REPO/docs/snp/evidence/ticket21/harness"
REPLAY_REPO="$REPO" REPLAY_LIST="$H/verdict-invocations-v2.txt" REPLAY_AUTHORED="$H/authored" \
  bash "$H/replay-verdicts.sh" "$W/replay-v2" "$W/bin/attest-tool" verify > "$W/logs/replay-v2.txt" 2>&1

grep -h 'refusing\|policy .* loaded\|tunneld.New\|EXIT_STATUS' "$W"/logs/C*-*.txt "$W"/logs/F*-*.txt
tail -7 "$W/logs/replay-v2.txt"
echo "captures in $W/logs"
