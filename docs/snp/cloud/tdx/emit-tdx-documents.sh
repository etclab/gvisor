#!/bin/bash
# Author one TDX guest's two signed documents, without rebuilding an image.
#
#   emit-tdx-documents.sh -out DIR -key author.key.pem \
#       [-forward-to HEX]... [-admit HEX] [-admit-policy HEX|any]
#
# Writes DIR/policy.json(+.sig) and DIR/reference-values.json(+.sig), and prints
# the emitted policy's digest — the number the *other* guest puts in its own
# -admit-policy.
#
# # Why this is a separate script from the image build
#
# The image build emits a self-pinning pair, because that is what a smoke boot
# and a symmetric pair of guests need and because a build that produced no
# documents would leave an operator to compose them from a manifest by hand.
# But the documents live on the config device, outside the measurement, and the
# whole point of that is that two guests can differ in them while running one
# image. Scenario two is exactly that: one image, two config devices, and B's
# policy is one A does not list. Rebuilding an image to change a document would
# change the measurement, which is the one thing that must not move between
# those two guests.
#
# # The order the scenarios need
#
# A policy names measurements and no digests; a reference value set names a
# measurement and a policy digest. So for a pair A, B:
#
#   1. emit A's policy and B's policy, each forwarding to the image(s) it dials
#   2. take the two digests the runs printed
#   3. emit A's set admitting B's measurement paired with B's digest, and B's
#      set admitting A's measurement paired with A's digest
#
# Both directions can be authored because a policy names no digest — that is
# the cycle ticket 18 ran into and the reason the two documents were split
# (docs/policy-binding.md).
#
# This script does one guest's pair in one run, so a caller that wants the
# mutual arrangement runs it twice: once with -admit-policy left out to learn
# the digests, and once with them filled in. The two runs emit byte-identical
# policies, because the policy does not depend on what the set says.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
export PATH="/usr/local/go/bin:$PATH"

OUT= KEY= ADMIT= ADMIT_POLICY="__unset__"
FORWARD=()
MRTD="${MRTD:-c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5}"
RTMR0="${RTMR0:-c2fc12a52db868515eff7c657e42ce04b0b7363fa6ddf7c1cca87aa8e6a061a11f9981924a600ad6d2232f75182a850a}"
RTMR1_FIRST="${RTMR1_FIRST:-02c7f19c862b3dae1592c737358d9bb13f8f0a34d3b3eca67c39bf7941a12c347635b8a291d68d9cace45b16ec25913b}"
RTMR1_LATER="${RTMR1_LATER:-3a446943925fef7f1682fd54e1b6697df864692e28592ec373860d1868582ac14ca3029c48282eb964868a785bafd691}"
TCB_STATUS="${TCB_STATUS:-UpToDate}"
TCB_EVALUATION="${TCB_EVALUATION:-20}"

while [ $# -gt 0 ]; do
  case "$1" in
    -out) OUT="$2"; shift 2 ;;
    -key) KEY="$2"; shift 2 ;;
    -forward-to) FORWARD+=(-forward-to "$2"); shift 2 ;;
    -admit) ADMIT="$2"; shift 2 ;;
    -admit-policy) ADMIT_POLICY="$2"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
: "${OUT:?-out DIR}"; : "${KEY:?-key author.key.pem}"; : "${ADMIT:?-admit HEX, the predicted RTMR2 of the peer this guest admits}"
mkdir -p "$OUT"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
(cd "$REPO/docs/snp/image/emit-refvals" && GOPROXY=off go build -o "$W/emit-refvals" .)
(cd "$HERE/emit-tdx-refvals" && GOPROXY=off go build -o "$W/emit-tdx-refvals" .)

# The policy first: the set names its digest, and nothing names the set's.
EMITTED_POLICY=$("$W/emit-refvals" -emit-policy -key "$KEY" -out "$OUT" "${FORWARD[@]+"${FORWARD[@]}"}")
printf '%s\n' "$EMITTED_POLICY"
POLICY_DIGEST=$(printf '%s\n' "$EMITTED_POLICY" | sed -n 's/^policy digest: //p')

DIGEST_ARGS=()
case "$ADMIT_POLICY" in
  __unset__|any) ;;                                # unconstrained: admits any policy
  *) DIGEST_ARGS=(-policy-digest "$ADMIT_POLICY") ;;
esac
RTMR0_ARGS=()
IFS=',' read -r -a RTMR0_LIST <<< "$RTMR0"
for r in "${RTMR0_LIST[@]}"; do [ -n "$r" ] && RTMR0_ARGS+=(-rtmr0 "$r"); done
"$W/emit-tdx-refvals" -rtmr2 "$ADMIT" \
  -mrtd "$MRTD" "${RTMR0_ARGS[@]}" -rtmr1 "$RTMR1_FIRST" -rtmr1 "$RTMR1_LATER" \
  -tcb-status "$TCB_STATUS" -tcb-evaluation "$TCB_EVALUATION" \
  "${DIGEST_ARGS[@]+"${DIGEST_ARGS[@]}"}" -key "$KEY" -out "$OUT"

echo
echo "policy digest of the policy just written: $POLICY_DIGEST"
echo "  (this is the number the OTHER guest passes as -admit-policy)"
