#!/bin/bash
# Milestone 1: evidence from real AMD silicon, verified outside the guest that
# produced it, against a reference value set signed for it (ticket 05).
#
#   verify-on-hardware.sh [-work DIR] [-stack DIR] [-vcpus N] [-vcpu-type T]
#                         [-ssh-port P] [-capture DIR]
#
# This is the harness the ticket asks for: the property it establishes cannot
# be re-proven by a unit test, because it needs a confidential VM, so the
# record of the run is the evidence. Everything it prints goes to
# $WORK/verify-run.txt as well as to the terminal, and -capture copies the
# artifacts into the repository.
#
# What it establishes, in order:
#
#   1. The launch measurement in the reference value set is PREDICTED offline,
#      before the guest is asked for anything, by AMD's own sev-snp-measure
#      over the firmware image and the two launch parameters that are not
#      files. Nothing reads it off a machine — a reference value learned by
#      asking the platform cannot fail (docs/snp-measurement-prediction.md).
#   2. A live confidential guest produces evidence bound to a key it generated
#      a moment earlier, bundled with the chain provisioned on its config
#      device (ADR-0002, ADR-0005).
#   3. That evidence verifies OUTSIDE the guest, against AMD's root, against
#      the signed set — inside an empty network namespace, in which the same
#      shell has just failed to resolve or reach AMD. No network, at any point.
#   4. Substituting one byte of the launch measurement into the set — and
#      re-signing it with the same author key, so the signature still holds —
#      turns that acceptance into a refusal naming the measurement.
#   5. Removing the provisioned chain, and staling it with a genuine AMD-issued
#      certificate for a TCB this platform has moved off, each fail closed
#      naming ADR-0005 rather than fetching.
#   6. The control: after every negative case, the unmodified set still accepts
#      the same evidence.
#
# It needs the running stock guest of docs/snp-host-stack.md, reachable through
# $STACK/gssh, and no root on the host: the guest's own sudo does the one
# privileged thing (inblob is root-only), and the network namespace is an
# unprivileged user namespace.
#
# The one place the network is used is fetching the deliberately-stale VCEK for
# case 5, which is a provisioning-time operation by construction — the same
# public key distribution service ticket 15 provisions from, asked for the same
# chip at a lower TCB. Verification itself never reaches it; that is the point.
set -uo pipefail

HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
WORK="${TMPDIR:-/tmp}/ticket05-verify"
VCPUS=4
VCPU_TYPE=EPYC-v4
SSH_PORT="${SNP_SSH_PORT:-10022}"
CAPTURE=""
SEV_SNP_MEASURE_VERSION=0.0.13
GUEST_DIR=/tmp/ticket05

while [ -n "${1:-}" ]; do
  case "$1" in
    -work)      WORK="$2"; shift 2 ;;
    -stack)     STACK="$2"; shift 2 ;;
    -vcpus)     VCPUS="$2"; shift 2 ;;
    -vcpu-type) VCPU_TYPE="$2"; shift 2 ;;
    -ssh-port)  SSH_PORT="$2"; shift 2 ;;
    -capture)   CAPTURE="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

export PATH=/usr/local/go/bin:$PATH
export SNP_SSH_PORT="$SSH_PORT"
VENV="${SEV_SNP_MEASURE_VENV:-$STACK/sev-snp-measure-venv}"
EVIDENCE_DIR="$REPO/docs/snp/evidence"
OVMF="$STACK/usr/local/share/qemu/OVMF.fd"

rm -rf "$WORK"; mkdir -p "$WORK"
TRANSCRIPT="$WORK/verify-run.txt"
exec > >(tee "$TRANSCRIPT") 2>&1

FAILURES=0
say()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '    %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
pass() { printf 'PASS: %s\n' "$*"; }

# expect_rc WANT FILE_RC WHAT — the exit status recorded in FILE_RC is WANT.
expect_rc() {
  local want="$1" got; got="$(cat "$2" 2>/dev/null)"
  if [ "$got" = "$want" ]; then pass "$3 (exit $got)"; else fail "$3: exit $got, want $want"; fi
}
# expect_text FILE NEEDLE WHAT
expect_text() {
  if grep -qF -- "$2" "$1"; then pass "$3"; else fail "$3: no \"$2\" in $1"; fi
}
expect_no_text() {
  if grep -qF -- "$2" "$1"; then fail "$3: \"$2\" appears in $1"; else pass "$3"; fi
}

# sev_snp_measure runs the pinned predictor. The console script's shebang is an
# absolute path to whichever virtualenv created it, so it breaks when that
# directory moves; the module is invoked directly instead, which does not care.
# gssh is ticket 01's ssh/scp wrapper for the guest. It is invoked through bash
# because the file is not marked executable in the repository.
gssh() { bash "$STACK/gssh" "$@"; }

sev_snp_measure() {
  "$VENV/bin/python3" -c '
import sys
sys.argv[0] = "sev-snp-measure"
from sevsnpmeasure.cli import main
main()' "$@"
}

########################################################################
say "0. Provenance"
########################################################################
echo "date            : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host            : $(hostname)"
echo "repository      : $REPO at $(git -C "$REPO" rev-parse --short HEAD) ($(git -C "$REPO" rev-parse --abbrev-ref HEAD))"
echo "host kernel     : $(uname -r)"
echo "work directory  : $WORK"
echo "go              : $(go version)"
if [ ! -x "$VENV/bin/python3" ]; then
  python3 -m venv "$VENV" && "$VENV/bin/pip" install -q "sev-snp-measure==$SEV_SNP_MEASURE_VERSION"
fi
GOT="$(sev_snp_measure --version | awk '{print $2}')"
[ "$GOT" = "$SEV_SNP_MEASURE_VERSION" ] || { echo "sev-snp-measure is $GOT, pinned $SEV_SNP_MEASURE_VERSION" >&2; exit 1; }
echo "predictor       : sev-snp-measure $GOT ($VENV)"
echo "guest           : $(gssh 'uname -sr' 2>&1)"
echo "guest SNP state : $(gssh 'sudo dmesg | grep -m1 -i "Memory Encryption Features active"' 2>&1)"
echo "firmware        : $OVMF"
echo "                  sha256 $(sha256sum "$OVMF" | cut -d' ' -f1)"
echo "provisioned chain: $EVIDENCE_DIR/certificate-chain.bin"
echo "                  sha256 $(sha256sum "$EVIDENCE_DIR/certificate-chain.bin" | cut -d' ' -f1)"

########################################################################
say "1. Predict the launch measurement offline, before the guest is asked anything"
########################################################################
# The stock guest of ticket 01 runs OvmfPkgX64 without kernel-hashes, so its
# launch measurement covers the firmware image and one VMSA per vCPU and
# nothing else (docs/snp-host-stack.md). That is what makes it the right guest
# for this ticket and the wrong one for ticket 08: the measurement is genuine,
# it is predictable, and it attests nothing about the workload.
PREDICTED="$(sev_snp_measure --mode snp --vmm-type QEMU \
    --vcpus "$VCPUS" --vcpu-type "$VCPU_TYPE" --ovmf "$OVMF" --output-format hex)"
echo "predicted launch measurement: $PREDICTED"
cat > "$WORK/predicted-measurement.txt" <<EOF
# Predicted SEV-SNP launch measurement of the stock confidential guest, computed
# offline from the inputs below. Not read from any machine.
launch_measurement: $PREDICTED

## Inputs
$(sha256sum "$OVMF" | awk '{print $1"  OVMF.fd"}')
vcpus     : $VCPUS
vcpu_type : $VCPU_TYPE
vmm       : QEMU (sev-snp-guest, no kernel-hashes; firmware OvmfPkgX64 with BlobVerifierLibNull,
            so the kernel, initrd and command line are outside M — docs/snp-host-stack.md)
tool      : sev-snp-measure $GOT
EOF
note "written to $WORK/predicted-measurement.txt"

########################################################################
say "2. Author and sign the reference value set, and the mutated one"
########################################################################
# A throwaway author key. Who holds this key in production and how it is
# rotated is out of scope (spec, Out of Scope); what matters here is that the
# set the verifier admits against is one somebody signed, and that the mutated
# set is signed by the SAME key — otherwise its refusal would be the loader's
# and would say nothing about the measurement check.
openssl genpkey -algorithm ed25519 -out "$WORK/author.key.pem" 2>/dev/null
mkdir -p "$WORK/set" "$WORK/set-mutated"

EMIT="$WORK/emit-refvals"
( cd "$REPO/docs/snp/image/emit-refvals" && go build -o "$EMIT" . ) || { echo "cannot build emit-refvals" >&2; exit 1; }

echo "$ emit-refvals -measurement $PREDICTED -tcb 9,0,23,72 -policy 0x30000"
"$EMIT" -measurement "$PREDICTED" -key "$WORK/author.key.pem" -out "$WORK/set" \
        -tcb 9,0,23,72 -policy 0x30000 | tee "$WORK/emit.txt"
AUTHOR_PUB="$(awk '/^author public key: /{print $4}' "$WORK/emit.txt")"
printf '%s\n' "$AUTHOR_PUB" > "$WORK/author.pub"
note "author public key: $AUTHOR_PUB"

# One byte of the launch measurement, changed. Everything else — the floor, the
# policy, the author, the format — is identical, so the only thing that can
# account for a different verdict is the measurement.
MUTATED="$(python3 -c '
import sys
m = bytearray(bytes.fromhex(sys.argv[1]))
m[-1] ^= 0x01
print(m.hex())' "$PREDICTED")"
echo "$ emit-refvals -measurement $MUTATED   # one byte of the last, flipped"
"$EMIT" -measurement "$MUTATED" -key "$WORK/author.key.pem" -out "$WORK/set-mutated" \
        -tcb 9,0,23,72 -policy 0x30000 > /dev/null
note "authored : $WORK/set/reference-values.json"
note "mutated  : $WORK/set-mutated/reference-values.json"
diff <(python3 -m json.tool "$WORK/set/reference-values.json") \
     <(python3 -m json.tool "$WORK/set-mutated/reference-values.json") | sed 's/^/    /'
note "the two sets differ in exactly the launch measurement, and both are signed by $AUTHOR_PUB"

########################################################################
say "3. Acquire evidence from the live confidential guest"
########################################################################
CGO_ENABLED=0 go -C "$REPO/attest" build -o "$WORK/acquire-evidence" ./cmd/acquire-evidence || exit 1
go -C "$REPO/attest" build -o "$WORK/verify-evidence" ./cmd/verify-evidence || exit 1

gssh "rm -rf $GUEST_DIR && mkdir -p $GUEST_DIR/config-device $GUEST_DIR/empty-device $GUEST_DIR/stale-device"
gssh --scp "$WORK/acquire-evidence" "G:$GUEST_DIR/"
gssh --scp "$EVIDENCE_DIR/certificate-chain.bin" "$EVIDENCE_DIR/certificate-chain.json" \
              "G:$GUEST_DIR/config-device/"

echo "\$ acquire-evidence -chain-dir $GUEST_DIR/config-device -out $GUEST_DIR/bundle   # in the guest, as root"
gssh "sudo modprobe sev-guest;
         sudo mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config;
         echo \"report requests before: \$(sudo ls /sys/kernel/config/tsm/report | wc -l)\";
         sudo $GUEST_DIR/acquire-evidence -chain-dir $GUEST_DIR/config-device -out $GUEST_DIR/bundle;
         echo \"acquire rc=\$?\";
         echo \"report requests after: \$(sudo ls /sys/kernel/config/tsm/report | wc -l)\"" \
    > "$WORK/acquire.txt" 2>&1
cat "$WORK/acquire.txt"
grep -q 'acquire rc=0' "$WORK/acquire.txt" && pass "the guest produced evidence" || { fail "acquisition failed"; exit 1; }

mkdir -p "$WORK/bundle"
gssh --scp "G:$GUEST_DIR/bundle/*" "$WORK/bundle/"
ls -l "$WORK/bundle"
if cmp -s "$WORK/bundle/certificate-chain.bin" "$EVIDENCE_DIR/certificate-chain.bin"; then
  pass "the chain that came back is the provisioned one, byte for byte (ADR-0005)"
else
  fail "the chain in the bundle is not the provisioned chain"
fi

########################################################################
say "4. Fetch a genuinely stale certificate, for case 7"
########################################################################
# The platform reports microcode 72. AMD's key distribution service will issue
# a VCEK for this same chip at a lower TCB, and that certificate is exactly
# what a chain provisioned before a microcode update looks like afterwards:
# real, AMD-signed, and for a level this platform has moved off. Nothing about
# verification uses the network — this is the provisioning-time fetch ADR-0005
# says is the only one there is, run here to manufacture the failure.
CHIP="$(python3 -c '
import json,sys
print(json.load(open(sys.argv[1]))["chip_id"])' "$EVIDENCE_DIR/certificate-chain.json")"
STALE_UCODE=71
STALE_URL="https://kdsintf.amd.com/vcek/v1/Genoa/$CHIP?blSPL=9&teeSPL=0&snpSPL=23&ucodeSPL=$STALE_UCODE"
echo "$ curl $STALE_URL"
if curl -sS --max-time 60 -o "$WORK/stale-vcek.der" "$STALE_URL"; then
  note "fetched $(stat -c%s "$WORK/stale-vcek.der") bytes: a VCEK for chip ${CHIP:0:6}… at microcode $STALE_UCODE"
  mkdir -p "$WORK/stale-device"
  python3 - "$EVIDENCE_DIR/certificate-chain.bin" "$WORK/stale-vcek.der" "$WORK/stale-device/certificate-chain.bin" <<'PY'
# Rebuild AMD's certificate table with the VCEK replaced. The table is a header
# of (16-byte GUID, uint32 offset, uint32 length) entries terminated by a zero
# entry, followed by the DER blobs; only the VCEK entry changes, and the
# offsets are recomputed so the ASK and ARK are untouched and still AMD's.
import struct, sys
VCEK = bytes.fromhex('63da758de6644564adc5f4b93be8accd')
src, newvcek, dst = sys.argv[1], sys.argv[2], sys.argv[3]
raw = open(src, 'rb').read()
new = open(newvcek, 'rb').read()
entries, off = [], 0
while True:
    guid = raw[off:off+16]
    o, l = struct.unpack_from('<II', raw, off+16)
    off += 24
    if guid == b'\0'*16 and o == 0 and l == 0:
        break
    entries.append([guid, new if guid == VCEK else raw[o:o+l]])
header = (len(entries)+1) * 24
out, cursor, blobs = bytearray(), header, bytearray()
for guid, der in entries:
    out += guid + struct.pack('<II', cursor, len(der))
    blobs += der
    cursor += len(der)
out += b'\0' * 24
open(dst, 'wb').write(bytes(out) + bytes(blobs))
print('    wrote %s (%d bytes)' % (dst, len(out) + len(blobs)))
PY
  python3 - "$EVIDENCE_DIR/certificate-chain.json" "$STALE_UCODE" "$WORK/stale-device/certificate-chain.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m['tcb']['microcode'] = int(sys.argv[2])
json.dump(m, open(sys.argv[3], 'w'), indent=2)
open(sys.argv[3], 'a').write('\n')
print('    metadata records microcode %s, and so does the VCEK beside it' % sys.argv[2])
PY
  # The VCEK is *versioned*: AMD derives it from the chip secret and the TCB, so
  # the certificate for microcode 71 endorses a different key from the one for
  # 72 — not the same key with a different number written on it. That is what
  # decides which refusal a stale chain produces at a peer, so it is recorded.
  python3 - "$EVIDENCE_DIR/certificate-chain.bin" "$WORK/stale-device/certificate-chain.bin" <<'PY'
import hashlib, struct, subprocess, sys
VCEK = bytes.fromhex('63da758de6644564adc5f4b93be8accd')
def vcek(path):
    raw, off = open(path, 'rb').read(), 0
    while True:
        g = raw[off:off+16]
        o, l = struct.unpack_from('<II', raw, off+16)
        off += 24
        if g == b'\0'*16 and o == 0 and l == 0:
            return None
        if g == VCEK:
            return raw[o:o+l]
for label, path in (('provisioned (microcode 72)', sys.argv[1]), ('stale (microcode 71)', sys.argv[2])):
    der = vcek(path)
    pub = subprocess.run(['openssl', 'x509', '-inform', 'der', '-noout', '-pubkey'],
                         input=der, capture_output=True).stdout
    print('    %-27s VCEK public key sha256 %s' % (label, hashlib.sha256(pub).hexdigest()))
PY
  STALE=yes
else
  STALE=no
  fail "could not fetch a stale VCEK; case 7 is skipped, not passed"
fi

########################################################################
say "5. Verify, in an empty network namespace"
########################################################################
# Everything that must run without the vendor runs inside ONE unshare -rn, and
# that shell proves its own isolation before it verifies anything: it fails to
# resolve the key distribution service and fails to open a socket to it. The
# namespace has no interface up at all, not even loopback.
cat > "$WORK/inside-netns.sh" <<'INNER'
set -u
WORK="$1"
V="$WORK/verify-evidence"
COMMON="-refvals $WORK/set/reference-values.json -author $WORK/author.pub"

echo "--- this shell's network ---"
ip -o link show
ip -o addr show
echo "--- can it resolve the vendor? ---"
getent hosts kdsintf.amd.com; echo "getent rc=$?"
echo "--- can it open a socket to the vendor? ---"
timeout 5 bash -c 'exec 3<>/dev/tcp/165.204.91.78/443' ; echo "connect rc=$?"
timeout 5 curl -sS --max-time 4 -o /dev/null https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain; echo "curl rc=$?"

echo "--- case 1: the control — real evidence, the authored set ---"
$V -bundle "$WORK/bundle" $COMMON > "$WORK/case-control.txt" 2>&1
echo $? > "$WORK/case-control.rc"; cat "$WORK/case-control.txt"

echo "--- case 2: one byte of the launch measurement substituted, re-signed ---"
$V -bundle "$WORK/bundle" -refvals "$WORK/set-mutated/reference-values.json" \
   -author "$WORK/author.pub" > "$WORK/case-mutated.txt" 2>&1
echo $? > "$WORK/case-mutated.rc"; cat "$WORK/case-mutated.txt"

echo "--- case 3: the provisioned chain removed ---"
$V -bundle "$WORK/bundle" $COMMON -without-chain > "$WORK/case-nochain.txt" 2>&1
echo $? > "$WORK/case-nochain.rc"; cat "$WORK/case-nochain.txt"

if [ -f "$WORK/stale-device/certificate-chain.bin" ]; then
  echo "--- case 4: a genuinely stale chain that reached a verifier anyway ---"
  $V -bundle "$WORK/bundle" -chain "$WORK/stale-device/certificate-chain.bin" $COMMON \
     > "$WORK/case-stale.txt" 2>&1
  echo $? > "$WORK/case-stale.rc"; cat "$WORK/case-stale.txt"
fi

echo "--- case 5: the control again, after every refusal above ---"
$V -bundle "$WORK/bundle" $COMMON > "$WORK/case-control2.txt" 2>&1
echo $? > "$WORK/case-control2.rc"; tail -8 "$WORK/case-control2.txt"
INNER

echo "\$ unshare -rn bash $WORK/inside-netns.sh $WORK"
unshare -rn bash "$WORK/inside-netns.sh" "$WORK" > "$WORK/netns.txt" 2>&1
cat "$WORK/netns.txt"

say "5a. Assertions on the run above"
expect_no_text "$WORK/netns.txt" "getent rc=0"                      "the namespace cannot resolve the vendor"
expect_no_text "$WORK/netns.txt" "connect rc=0"                     "the namespace cannot open a socket to the vendor"
expect_no_text "$WORK/netns.txt" "curl rc=0"                        "the namespace cannot reach the vendor over HTTPS"

expect_rc 0 "$WORK/case-control.rc"                                 "M1: real evidence verifies outside the guest, offline"
expect_text "$WORK/case-control.txt" "ACCEPTED"                     "the verdict is acceptance"
expect_text "$WORK/case-control.txt" "$PREDICTED"                   "the accepted launch measurement is the predicted one"
expect_text "$WORK/case-control.txt" "embedded in the verification library" \
                                                                    "it was checked against AMD's root with no fetch and no file"

expect_rc 2 "$WORK/case-mutated.rc"                                 "a substituted launch measurement is refused"
expect_text "$WORK/case-mutated.txt" "launch measurement not in the reference value set" \
                                                                    "and the internal reason names the measurement"

expect_rc 2 "$WORK/case-nochain.rc"                                 "evidence with no provisioned chain is refused"
expect_text "$WORK/case-nochain.txt" "no certificate chain presented with the evidence" \
                                                                    "and the refusal names the missing chain"
expect_no_text "$WORK/case-nochain.txt" "ACCEPTED"                  "no silent fetch stood in for the missing chain"

if [ "$STALE" = yes ]; then
  expect_rc 2 "$WORK/case-stale.rc"                                 "a stale chain reaching a verifier is refused"
  expect_text "$WORK/case-stale.txt" "evidence does not chain to the vendor root" \
                                                                    "as evidence that does not chain to the vendor root"
  expect_text "$WORK/case-stale.txt" "report signature verification error" \
                                                                    "because the report is not signed by the stale chain's key"
  expect_no_text "$WORK/case-stale.txt" "ACCEPTED"                  "and nothing was fetched to rescue it"
  note ""
  note "FINDING. ADR-0005, docs/provisioning-certificate-chain.md and the comment in"
  note "attest/verify/snp.go all say a stale chain surfaces at the peer as MALFORMED"
  note "EVIDENCE, because the library compares the reported TCB against the one the"
  note "chain was issued for. On real silicon it does not. The VCEK is derived from"
  note "the chip secret AND the TCB, so a chain for microcode 71 endorses a different"
  note "key (the two public keys above), the report's own signature fails under it,"
  note "and the refusal is CHAIN NOT ROOTED — reported before the coherence check that"
  note "would have said malformed. Still fail-closed, still no fetch; but an operator"
  note "told to look for \"malformed evidence\" will not find it, and this refusal's"
  note "detail does not name ADR-0005. The local check in provision.CheckFor (case 6"
  note "below) does name it, and is where a stale chain is actually caught."
fi

expect_rc 0 "$WORK/case-control2.rc"                                "control: the unmodified set still accepts the same evidence"

########################################################################
say "6. The provisioned chain, removed and staled on the config device"
########################################################################
# The verifier's answer is the peer's half. This is the local half: an acquirer
# whose config device has no chain, or a chain for a TCB the platform has moved
# off, refuses to produce a bundle at all — naming ADR-0005, and never fetching.
echo "$ acquire-evidence -chain-dir $GUEST_DIR/empty-device   # nothing provisioned"
gssh "sudo $GUEST_DIR/acquire-evidence -chain-dir $GUEST_DIR/empty-device; echo rc=\$?" \
    > "$WORK/case-device-empty.txt" 2>&1
cat "$WORK/case-device-empty.txt"
expect_text "$WORK/case-device-empty.txt" "no certificate chain is provisioned here — provision one, do not fetch" \
                                                                    "an unprovisioned config device fails closed"
expect_text "$WORK/case-device-empty.txt" "(ADR-0005)"              "and names ADR-0005"
expect_text "$WORK/case-device-empty.txt" "rc=1"                    "and the acquisition exits non-zero"

if [ "$STALE" = yes ]; then
  gssh --scp "$WORK/stale-device/certificate-chain.bin" "$WORK/stale-device/certificate-chain.json" \
                "G:$GUEST_DIR/stale-device/"
  echo "$ acquire-evidence -chain-dir $GUEST_DIR/stale-device   # AMD-issued, for microcode $STALE_UCODE"
  gssh "sudo $GUEST_DIR/acquire-evidence -chain-dir $GUEST_DIR/stale-device; echo rc=\$?" \
      > "$WORK/case-device-stale.txt" 2>&1
  cat "$WORK/case-device-stale.txt"
  expect_text "$WORK/case-device-stale.txt" "the chain is stale"     "a stale config device fails closed locally"
  expect_text "$WORK/case-device-stale.txt" "(ADR-0005)"             "and names ADR-0005"
  expect_text "$WORK/case-device-stale.txt" "rc=1"                   "and the acquisition exits non-zero"
fi

########################################################################
say "7. The refusals are the code's, not the namespace's"
########################################################################
# Every refusal above was produced with the vendor unreachable, so a refusal
# could in principle have been a failed fetch rather than a decision. Repeat
# the two chain cases here, on the host's ordinary network, with AMD one
# round trip away.
curl -sS --max-time 20 -o /dev/null -w '    the vendor is reachable from this shell: HTTP %{http_code}\n' \
     https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain
"$WORK/verify-evidence" -bundle "$WORK/bundle" -refvals "$WORK/set/reference-values.json" \
     -author "$WORK/author.pub" -without-chain > "$WORK/case-nochain-online.txt" 2>&1
echo "rc=$?" >> "$WORK/case-nochain-online.txt"
tail -6 "$WORK/case-nochain-online.txt"
expect_text "$WORK/case-nochain-online.txt" "no certificate chain presented with the evidence" \
                                                                    "with the vendor reachable, a missing chain is still refused"
expect_text "$WORK/case-nochain-online.txt" "rc=2"                  "and the exit status is the same refusal"

if [ "$STALE" = yes ]; then
  "$WORK/verify-evidence" -bundle "$WORK/bundle" -chain "$WORK/stale-device/certificate-chain.bin" \
       -refvals "$WORK/set/reference-values.json" -author "$WORK/author.pub" \
       > "$WORK/case-stale-online.txt" 2>&1
  echo "rc=$?" >> "$WORK/case-stale-online.txt"
  tail -6 "$WORK/case-stale-online.txt"
  expect_text "$WORK/case-stale-online.txt" "evidence does not chain to the vendor root" \
                                                                    "with the vendor reachable, a stale chain is still refused"
fi
note "the structural guards for this are attest/verify's offlineGetter, which refuses every URL,"
note "and attest/tsm's import allowlist test, which fails if a fetch is ever written into the acquirer."

########################################################################
say "8. Result"
########################################################################
if [ -n "$CAPTURE" ]; then
  mkdir -p "$CAPTURE"
  cp "$WORK/bundle/evidence.bin" "$WORK/bundle/public-key.der" "$WORK/bundle/caller-supplied.bin" \
     "$WORK/bundle/observation.txt" "$CAPTURE/"
  cp "$WORK/set/reference-values.json" "$WORK/set/reference-values.json.sig" "$CAPTURE/"
  cp "$WORK/set-mutated/reference-values.json" "$CAPTURE/reference-values-mutated.json"
  cp "$WORK/set-mutated/reference-values.json.sig" "$CAPTURE/reference-values-mutated.json.sig"
  cp "$WORK/author.pub" "$WORK/predicted-measurement.txt" "$CAPTURE/"
  if [ "$STALE" = yes ]; then
    cp "$WORK/stale-device/certificate-chain.bin" "$CAPTURE/certificate-chain-stale.bin"
    cp "$WORK/stale-device/certificate-chain.json" "$CAPTURE/certificate-chain-stale.json"
  fi
  python3 "$REPO/docs/snp/parse-snp-report.py" "$WORK/bundle/evidence.bin" > "$CAPTURE/report-decoded.txt" 2>&1
  note "artifacts copied to $CAPTURE"
fi

if [ "$FAILURES" -eq 0 ]; then
  echo
  echo "ALL CHECKS PASSED — evidence from real AMD silicon verified outside its guest,"
  echo "against AMD's root and a signed reference value set, with no network at any point."
  RC=0
else
  echo
  echo "$FAILURES CHECK(S) FAILED"
  RC=1
fi
[ -n "$CAPTURE" ] && cp "$TRANSCRIPT" "$CAPTURE/verify-run.txt"
exit $RC
