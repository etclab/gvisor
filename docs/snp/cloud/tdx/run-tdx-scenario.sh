#!/bin/bash
# Run one of ticket 19's three two-guest scenarios on Google Cloud TDX.
#
#   run-tdx-scenario.sh one|two|three [-keep]
#
# Two Confidential VMs of the shape docs/snp/cloud/tdx/SCENARIOS.md pins — one
# boot disk from a custom image whose initrd is the whole guest, one config
# device, and nothing else — brought up together, watched on the serial console
# until each powers itself off, and then judged here: the quote each guest
# printed is taken off its console and put through attest/cmd/verify-evidence on
# this workstation, twice, once against its own signed set and once against the
# set its peer holds. The transcript ends in a PASS/FAIL count, in the shape
# docs/snp/tunnel-on-two-guests.sh writes on the bench.
#
# It is one script and not three because the three scenarios differ in four
# values and nothing else: which image each guest boots, what each policy
# forwards to, which policy digest each set admits, and how long the exercise
# runs. Everything around those — authoring, signing, the config device, the
# instance shape, the console loop, the verification, the inventory rows — is
# the same work, and three copies of it would be three places for it to drift.
#
# # The four values, scenario by scenario
#
#   one    both guests boot the 6.17 image. A's set admits that measurement
#          paired with B's policy digest and B's set admits it paired with A's,
#          so each pins the other and neither pins itself. The two policies
#          differ — B's forwards to one more measurement — so the two digests
#          are two numbers and "each names the other" says something. The
#          maximum age is three minutes and the exercise runs for eight, so a
#          tunnel reaches its age while a caller is still using it and is
#          re-attested underneath them.
#
#   two    both guests boot the 6.17 image. A's set admits that measurement
#          paired with A's OWN policy digest, which is a digest of a real
#          document that B does not present: B carries the other policy. A
#          refuses B as a policy mismatch, and B admits A. A's set naming A's
#          own pair is deliberate — it makes A's self-check a positive control,
#          so the console shows the set and the platform agreeing at the same
#          moment the set refuses the peer.
#
#   three  A boots the 6.17 image and B the 7.0 one, which differs from it in
#          the kernel and in nothing else. A's set admits the 6.17 measurement
#          paired with B's policy digest: everything about that value was
#          authored to admit B, and only the image is wrong. B is refused on the
#          register, and the refusal names it. B's set admits A, so B admits A on
#          the same handshake A refuses B on, which is this scenario's local
#          control. A's peer table also names an address no guest has, so the
#          console records what tunneld's own dialer does with a peer that is in
#          the table and not on the network.
#
# # What a set says, and why most of the self-checks here are refused
#
# A reference value set says whom this guest ADMITS. In every arrangement where
# two guests pin each other, that is the peer's (measurement, policy digest)
# pair and not the guest's own — so the self-check, which judges this guest's
# own evidence bound to this guest's own policy digest against this guest's own
# set, is refused. It is refused on the policy digest, with the measurement
# matching, and the registers are printed beside the refusal from the quote's
# own bytes. That is not a failure of the run: it is what "each pins the other"
# means, and the check that matters is the one the PEER makes, which this script
# also makes here, from the same quote, against the peer's set.
#
# Environment:
#   ZONE, DEADLINE, OUT, IP_A, IP_B, GATEWAY, PORT, MTU
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
export PATH="/usr/local/go/bin:$PATH"

SCENARIO="${1:-}"
case "$SCENARIO" in
  one|two|three) ;;
  *) echo "usage: $(basename "$0") one|two|three [-keep]" >&2; exit 2 ;;
esac
KEEP=0
[ "${2:-}" = "-keep" ] && KEEP=1

ZONE="${ZONE:-us-central1-a}"
IP_A="${IP_A:-10.128.0.40}"
IP_B="${IP_B:-10.128.0.41}"
IP_OUTSIDER="${IP_OUTSIDER:-10.128.0.42}"
GATEWAY="${GATEWAY:-10.128.0.1}"
PORT="${PORT:-4433}"
MTU="${MTU:-1460}"
LABEL="purpose=attested-tunnel-t19"
OUT="${OUT:-$REPO/docs/snp/evidence/ticket19/scenario-$SCENARIO}"

# The two images, their predicted RTMR2s, and the key whose public half is
# inside both of them. None of these is discovered at run time: the measurement
# is predicted from the image bytes (ticket 16's predictor) and the key is the
# one the build baked in, so a run that had to ask a machine for either would be
# a run that proved nothing.
IMAGE_A="${IMAGE_A:-attested-tdx-d5ddcc423b1a}"
IMAGE_B="${IMAGE_B:-attested-tdx-640de950bbdd}"
M_A="${M_A:-d5ddcc423b1aed530237a6c43b3005d317464a94217dd9477f113007379dbf0fc7601cac8fa69bb48a4efd4322c73e0d}"
M_B="${M_B:-640de950bbdde9300d2092da28885ec6455acdc3b6df99ea847d02d5cf7c99d86724bb4dff41bb037c4f212f33414be7}"
KEY="${KEY:-$REPO/.scratch/attested-secure-tunnel/host-stack/image-ticket19-tdx/author.key}"
AUTHOR_PUB="${AUTHOR_PUB:-665053d10032f5b9a46394a65b022c0bd7007392b8f445fe4ace5b0e5ed4c5a2}"
COLLATERAL="${COLLATERAL:-$REPO/docs/snp/evidence/tdx/collateral}"

# A launch measurement of the right width that names no image anybody has:
# sha384 of an ASCII sentence, with no trailing newline. It exists so that two
# guests booting one image can carry two DIFFERENT policies while both still say
# the true thing about this pair — each will dial the image the other runs —
# and therefore so that "each set names the other's digest" is two numbers
# rather than one. Ticket 18's mutual run did the same thing for the same
# reason (docs/snp/evidence/ticket18/mutual/digests.txt).
FICTION_TEXT='a TDX image this sandbox would also dial, which nothing in this project has built'
FICTION="$(printf '%s' "$FICTION_TEXT" | sha384sum | cut -d' ' -f1)"

VM_A="t19-$SCENARIO-a"
VM_B="t19-$SCENARIO-b"
STAMP="$(date -u +%Y%m%d%H%M%S)"
CONFIG_IMAGE_A="attested-config-t19-$SCENARIO-a-$STAMP"
CONFIG_IMAGE_B="attested-config-t19-$SCENARIO-b-$STAMP"

case "$SCENARIO" in
  one)   BOOT_A="$IMAGE_A"; BOOT_B="$IMAGE_A"; MEAS_A="$M_A"; MEAS_B="$M_A"; DEADLINE="${DEADLINE:-1500}" ;;
  two)   BOOT_A="$IMAGE_A"; BOOT_B="$IMAGE_A"; MEAS_A="$M_A"; MEAS_B="$M_A"; DEADLINE="${DEADLINE:-900}" ;;
  three) BOOT_A="$IMAGE_A"; BOOT_B="$IMAGE_B"; MEAS_A="$M_A"; MEAS_B="$M_B"; DEADLINE="${DEADLINE:-900}" ;;
esac

mkdir -p "$OUT"
OUT="$(readlink -f "$OUT")"
exec > >(tee "$OUT/tunnel-run.txt") 2>&1

PASSES=0; FAILURES=0
note()  { echo "$*"; }
pass()  { PASSES=$((PASSES+1)); echo "PASS  $*"; }
fail()  { FAILURES=$((FAILURES+1)); echo "FAIL  $*"; }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
in_file()     { grep -qF -- "$2" "$1"; }
not_in_file() { ! grep -qF -- "$2" "$1"; }
re_in_file()  { grep -qE -- "$2" "$1"; }
# Whether the serving tunneld's exercise succeeded.
#
# Not read off its "EXIT status=" line, because that line does not survive the
# guest. tunneld prints the peer summary and its status, the initrd prints its
# own, and then `poweroff -f` follows within milliseconds; Compute Engine
# serves an empty body for an instance that has stopped, so the last handful of
# lines a guest ever writes are not retrievable — observed on the smoke boot
# and on both of this script's first two runs, the second of which kept
# fetching for ninety seconds after the stop and then read the whole buffer
# once more, and got nothing further either way.
#
# So the exercise's verdict is read from the exercise itself, which prints one
# "exercise failed:" line naming every peer it could not establish to, and
# prints nothing when every peer worked. That line is what SETS the exit
# status (exitExerciseFailed, main.go), so it is the same fact one step
# earlier, and it arrives while the guest is still running.
exercise_failed() { grep -q '^tunneld: exercise failed:' "$1"; }
exercise_succeeded() { ! grep -q '^tunneld: exercise failed:' "$1"; }
# The platform's TCB, from whichever of the two places this run recorded it.
tcb_uptodate() { # CONSOLE VERIFY-EVIDENCE-TRANSCRIPT
  grep -qE 'status=UpToDate evaluation=20|tcb=UpToDate,evaluation=20' "$1" && return 0
  grep -qE 'status=UpToDate evaluation_data_number=20' "$2"
}

CREATED_A="" CREATED_B="" DELETED_A="(not deleted)" DELETED_B="(not deleted)"
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  echo
  echo "############ tearing down ############"
  if [ "$KEEP" = 1 ]; then
    echo "keeping $VM_A and $VM_B (-keep); delete them by hand:"
    echo "  gcloud compute instances delete $VM_A $VM_B --zone $ZONE --quiet"
    DELETED_A="(kept, -keep)"; DELETED_B="(kept, -keep)"
  else
    for pair in "$VM_A:A" "$VM_B:B"; do
      vm="${pair%:*}"; which="${pair#*:}"
      eval "created=\$CREATED_$which"
      [ -n "$created" ] || { echo "$vm was never created; nothing to delete"; continue; }
      if gcloud compute instances delete "$vm" --zone "$ZONE" --quiet; then
        eval "DELETED_$which=\"\$(date -u +%Y-%m-%dT%H:%MZ)\""
      else
        eval "DELETED_$which='**DELETE FAILED -- STILL RUNNING**'"
        echo "the delete of $vm FAILED; it is still running and RESOURCES.md must say so"
      fi
    done
    # The config devices are this scenario's and no other run needs them. The
    # two boot images and the smoke config image are NOT touched: re-uploading
    # ten gibibytes to get back to where the image build left off is the one
    # cost this ticket refuses to pay twice.
    for img in "$CONFIG_IMAGE_A" "$CONFIG_IMAGE_B"; do
      if gcloud compute images describe "$img" >/dev/null 2>&1; then
        gcloud compute images delete "$img" --quiet && echo "deleted image $img" \
          || echo "the delete of image $img FAILED"
      fi
    done
  fi
  echo
  echo "instances still carrying $LABEL:"
  gcloud compute instances list --filter="labels.purpose=attested-tunnel-t19" --format='value(name,zone,status)' || true
  echo "disks:"
  gcloud compute disks list --filter="name~t19" --format='value(name,zone,status)' || true
  resources_rows
  echo
  rm -rf "${TOOLS:-}"
  echo "=== $PASSES passed, $FAILURES failed ==="
  echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ), exit $rc ==="
  if [ "$rc" != 0 ]; then exit "$rc"; fi
  if [ "$FAILURES" != 0 ]; then exit 1; fi
  exit 0
}
resources_rows() {
  echo
  echo "############ rows for docs/snp/cloud/tdx/RESOURCES.md ############"
  printf '| %s | %s | c3-standard-4 TDX, %s, 20GB pd-balanced boot from `%s` + 10GB pd-balanced config disk from `%s`, `--private-network-ip %s` | ticket 19 scenario %s, guest A | **deleted %s** |\n' \
    "${CREATED_A:-(never created)}" "$VM_A" "$ZONE" "$BOOT_A" "$CONFIG_IMAGE_A" "$IP_A" "$SCENARIO" "$DELETED_A"
  printf '| %s | %s | c3-standard-4 TDX, %s, 20GB pd-balanced boot from `%s` + 10GB pd-balanced config disk from `%s`, `--private-network-ip %s` | ticket 19 scenario %s, guest B | **deleted %s** |\n' \
    "${CREATED_B:-(never created)}" "$VM_B" "$ZONE" "$BOOT_B" "$CONFIG_IMAGE_B" "$IP_B" "$SCENARIO" "$DELETED_B"
  printf '| %s | %s, %s | custom images, 1GiB each, `%s` | ticket 19 scenario %s: the two config devices (a signed set and policy each, peer table, run config, addressing, Intel collateral) | **deleted %s** |\n' \
    "${CREATED_A:-}" "$CONFIG_IMAGE_A" "$CONFIG_IMAGE_B" "$LABEL" "$SCENARIO" "$DELETED_A"
}
trap cleanup EXIT
trap 'echo interrupted; exit 130' INT TERM

echo "=== ticket 19, scenario $SCENARIO: two attested guests on Google Cloud TDX ==="
echo "date        : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "repo        : $(git -C "$REPO" rev-parse HEAD) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
echo "project     : $(gcloud config get-value project 2>/dev/null), zone $ZONE"
echo "guest A     : $VM_A at $IP_A, boot image $BOOT_A, predicted RTMR2 $MEAS_A"
echo "guest B     : $VM_B at $IP_B, boot image $BOOT_B, predicted RTMR2 $MEAS_B"
echo "author key  : $KEY (public half $AUTHOR_PUB, inside both measurements)"
echo "collateral  : $COLLATERAL (provisioned, never fetched)"
echo "out         : $OUT"
echo

[ -f "$KEY" ] || { echo "no author key at $KEY" >&2; exit 2; }
[ -d "$COLLATERAL" ] || { echo "no collateral at $COLLATERAL" >&2; exit 2; }

W="$OUT/config-src"
rm -rf "$W"; mkdir -p "$W/a" "$W/b" "$W/probe-a" "$W/probe-b"
TOOLS="$(mktemp -d)"
(cd "$REPO/docs/snp/image/emit-refvals" && GOPROXY=off go build -o "$TOOLS/emit-refvals" .)
# Built rather than `go run`: `go run` exits 1 whatever the program under it
# exits with, and this run turns on telling a refusal (2) from a failure (1).
(cd "$REPO/attest" && GOPROXY=off go build -o "$TOOLS/verify-evidence" ./cmd/verify-evidence)

# ---- 1. the four documents -------------------------------------------------
# A policy names measurements and no digests; a set names a measurement and a
# policy digest. So the policies are authored first, their digests read off the
# runs that wrote them, and only then are the two sets authored — each naming
# the digest of the document the OTHER guest carries. Under ticket 18 that pair
# could not be authored at all: each digest would have been taken over a
# document that had to contain the other. The split is why it can be
# (docs/policy-binding.md).
echo "############ 1. authoring the four documents ############"
# The two policies are the same in all three scenarios, and so is the
# measurement each set admits. A's policy forwards to the image A expects on
# this pair; B's forwards to that and to one more that names no image anybody
# has, so that the two digests are two numbers.
FWD_A=(-forward-to "$M_A")
FWD_B=(-forward-to "$M_A" -forward-to "$FICTION")

# What each set admits is a measurement this guest EXPECTS OF ITS PEER, not the
# one its peer turns out to be running. The difference is the whole of scenario
# three: A is handed the same value it is handed in scenario one — the 6.17
# image paired with B's policy digest, authored to admit B — and B then boots
# the 7.0 image instead, so the register does not match and A refuses it. A set
# written from the peer's actual measurement could never refuse anybody, which
# is what an earlier run of this script did by mistake and why this is spelled
# out rather than reused from MEAS_B.
ADMIT_MEAS_A="$M_A"
ADMIT_MEAS_B="$M_A"

echo "--- probe run: emit each policy once, with the set left unconstrained, to learn the two digests"
bash "$HERE/emit-tdx-documents.sh" -out "$W/probe-a" -key "$KEY" "${FWD_A[@]}" -admit "$ADMIT_MEAS_A" > "$W/probe-a/emit.txt" 2>&1
bash "$HERE/emit-tdx-documents.sh" -out "$W/probe-b" -key "$KEY" "${FWD_B[@]}" -admit "$ADMIT_MEAS_B" > "$W/probe-b/emit.txt" 2>&1
D_A_EMIT=$(sed -n 's/^policy digest of the policy just written: //p' "$W/probe-a/emit.txt")
D_B_EMIT=$(sed -n 's/^policy digest of the policy just written: //p' "$W/probe-b/emit.txt")
echo "    D_A (guest A's own policy) = $D_A_EMIT"
echo "    D_B (guest B's own policy) = $D_B_EMIT"

# Which digest each set admits. This is the whole of the difference between the
# three scenarios' documents.
case "$SCENARIO" in
  one)   ADMIT_POLICY_A="$D_B_EMIT"; ADMIT_POLICY_B="$D_A_EMIT" ;;
  two)   ADMIT_POLICY_A="$D_A_EMIT"; ADMIT_POLICY_B="$D_A_EMIT" ;;
  three) ADMIT_POLICY_A="$D_B_EMIT"; ADMIT_POLICY_B="$D_A_EMIT" ;;
esac

echo
echo "--- the real run: the same policies, and a set each"
bash "$HERE/emit-tdx-documents.sh" -out "$W/a" -key "$KEY" "${FWD_A[@]}" \
     -admit "$ADMIT_MEAS_A" -admit-policy "$ADMIT_POLICY_A" > "$W/a/emit.txt" 2>&1
bash "$HERE/emit-tdx-documents.sh" -out "$W/b" -key "$KEY" "${FWD_B[@]}" \
     -admit "$ADMIT_MEAS_B" -admit-policy "$ADMIT_POLICY_B" > "$W/b/emit.txt" 2>&1
cat "$W/a/emit.txt" | sed 's/^/    a| /'
cat "$W/b/emit.txt" | sed 's/^/    b| /'

D_A=$(sed -n 's/^policy digest of the policy just written: //p' "$W/a/emit.txt")
D_B=$(sed -n 's/^policy digest of the policy just written: //p' "$W/b/emit.txt")
D_A_DELIVERED=$("$TOOLS/emit-refvals" -digest-of "$W/a/policy.json" | sed -n 's/^policy digest: //p')
D_B_DELIVERED=$("$TOOLS/emit-refvals" -digest-of "$W/b/policy.json" | sed -n 's/^policy digest: //p')

check "the policy a guest carries does not depend on what its set says (probe run and real run wrote the same bytes)" \
      bash -c "cmp -s '$W/probe-a/policy.json' '$W/a/policy.json' && cmp -s '$W/probe-b/policy.json' '$W/b/policy.json'"
check "D_A: the digest emit-refvals printed is the digest of the document it delivered" \
      test "$D_A" = "$D_A_DELIVERED"
check "D_B: the digest emit-refvals printed is the digest of the document it delivered" \
      test "$D_B" = "$D_B_DELIVERED"
check "the two policies have distinct digests, so 'each names the other' is two numbers" \
      test "$D_A" != "$D_B"
check "guest A's policy is byte-identical to the one the image build emitted, so D_A is the image's own policy digest" \
      cmp -s "$W/a/policy.json" "$REPO/docs/snp/evidence/ticket19/images/image-a/policy.json"

# ---- 2. the rest of each config device ------------------------------------
echo
echo "############ 2. the two config devices ############"
case "$SCENARIO" in
  three)
    cat > "$W/a/peers.json" <<EOF
{
  "format": "gvisor.dev/gvisor/attest/peer-table",
  "version": 1,
  "peers": {"guest-b": "$IP_B:$PORT", "outsider": "$IP_OUTSIDER:$PORT"}
}
EOF
    ;;
  *)
    cat > "$W/a/peers.json" <<EOF
{
  "format": "gvisor.dev/gvisor/attest/peer-table",
  "version": 1,
  "peers": {"guest-b": "$IP_B:$PORT"}
}
EOF
    ;;
esac
cat > "$W/b/peers.json" <<EOF
{
  "format": "gvisor.dev/gvisor/attest/peer-table",
  "version": 1,
  "peers": {"guest-a": "$IP_A:$PORT"}
}
EOF

# The run configuration. The maximum age is the field scenario one turns on:
# tunnel.DefaultMaxAge is fifteen minutes and this binary clamps anything longer,
# so a shorter one is asked for and the exercise is run past it. Nothing here
# exceeds the ceiling, so no CLAMPED line is expected on any console.
case "$SCENARIO" in
  one)
    LIMITS='{"idle_timeout": "5m", "max_age": "3m"}'
    EX_A='{"dial": ["guest-b"], "wait": "180s", "exchanges": 5, "concurrency": 8, "rounds": 1, "repeat_every": "45s", "run_for": "8m", "timeout": "90s"}'
    EX_B='{"dial": ["guest-a"], "wait": "180s", "exchanges": 5, "concurrency": 8, "rounds": 1, "repeat_every": "45s", "run_for": "8m", "timeout": "90s"}'
    HOLD='60s'
    ;;
  two)
    LIMITS='{"idle_timeout": "60s", "max_age": "15m"}'
    EX_A='{"dial": ["guest-b"], "wait": "90s", "exchanges": 3, "concurrency": 8, "rounds": 1, "timeout": "30s"}'
    EX_B='{"dial": ["guest-a"], "wait": "90s", "exchanges": 3, "concurrency": 8, "rounds": 1, "timeout": "30s"}'
    HOLD='60s'
    ;;
  three)
    LIMITS='{"idle_timeout": "60s", "max_age": "15m"}'
    EX_A='{"dial": ["guest-b", "outsider"], "wait": "60s", "exchanges": 3, "concurrency": 8, "rounds": 1, "timeout": "20s"}'
    EX_B='{"dial": ["guest-a"], "wait": "90s", "exchanges": 3, "concurrency": 8, "rounds": 1, "timeout": "30s"}'
    HOLD='60s'
    ;;
esac
write_run_config() { # DIR SANDBOX IP EXERCISE
  cat > "$1/tunneld.json" <<EOF
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "$2",
  "listen": "$3:$PORT",
  "limits": $LIMITS,
  "start_timeout": "60s",
  "exercise": $4,
  "hold": "$HOLD"
}
EOF
}
write_run_config "$W/a" guest-a "$IP_A" "$EX_A"
write_run_config "$W/b" guest-b "$IP_B" "$EX_B"

write_network_conf() { # DIR IP
  cat > "$1/network.conf" <<EOF
# The guest's addressing, outside the measurement (ticket 19). A Google VPC
# gives a guest a /32 and an off-link gateway, so the initrd adds a host route
# to the gateway first and then the default route through it.
interface=eth0
address=$2
prefix=32
gateway=$GATEWAY
mtu=$MTU
EOF
}
write_network_conf "$W/a" "$IP_A"
write_network_conf "$W/b" "$IP_B"

cp -r "$COLLATERAL" "$W/a/collateral"
cp -r "$COLLATERAL" "$W/b/collateral"
rm -f "$W/a/emit.txt" "$W/b/emit.txt"

bash "$HERE/mkconfigdev-tdx.sh" "$W/a" "$OUT/config-a.raw" | sed 's/^/    a| /'
bash "$HERE/mkconfigdev-tdx.sh" "$W/b" "$OUT/config-b.raw" | sed 's/^/    b| /'

# ---- 3. the digests this scenario turns on --------------------------------
{
  echo "# scenario $SCENARIO: the measurements and policy digests this scenario turns on."
  echo "#"
  echo "# A policy digest is SHA-256 over the bytes the author signed over policy.json,"
  echo "# so it is not sha256sum of the file. Each number below was printed by"
  echo "# emit-refvals when it wrote the document, read back off the delivered document"
  echo "# with 'emit-refvals -digest-of', and read a third time off the console of the"
  echo "# guest holding it. The console column is filled in after the run."
  echo
  echo "guest A boots  : $BOOT_A, predicted RTMR2 $MEAS_A"
  echo "guest B boots  : $BOOT_B, predicted RTMR2 $MEAS_B"
  echo
  echo "D_A, guest A's own policy      : $D_A"
  echo "    emit-refvals -digest-of    : $D_A_DELIVERED"
  echo "    forwards to                :"
  grep -o '"[0-9a-f]\{96\}"' "$W/a/policy.json" | tr -d '"' | sed 's/^/        /'
  echo "D_B, guest B's own policy      : $D_B"
  echo "    emit-refvals -digest-of    : $D_B_DELIVERED"
  echo "    forwards to                :"
  grep -o '"[0-9a-f]\{96\}"' "$W/b/policy.json" | tr -d '"' | sed 's/^/        /'
  echo
  echo "set-a admits measurement       : $ADMIT_MEAS_A   (the measurement A EXPECTS of its peer)"
  echo "    guest B actually reports   : $MEAS_B"
  echo "set-a admits policy digest     : $ADMIT_POLICY_A"
  echo "set-b admits measurement       : $ADMIT_MEAS_B"
  echo "set-b admits policy digest     : $ADMIT_POLICY_B"
  echo
  echo "the fictitious measurement, where a policy carries one:"
  echo "    $FICTION"
  echo "    = sha384 of the ASCII string \"$FICTION_TEXT\", with no trailing newline."
  echo "      It is a launch measurement of the right width naming no image anybody has,"
  echo "      so one guest's policy is a different document from the other's while both"
  echo "      still say the true thing about this pair."
} > "$OUT/digests.txt"
sed 's/^/    /' "$OUT/digests.txt"

# ---- 4. publish the config devices ----------------------------------------
echo
echo "############ 3. publishing the two config devices ############"
bash "$HERE/publish-tdx-image.sh" "$OUT/config-a.raw" "$CONFIG_IMAGE_A" | tail -12 | sed 's/^/    a| /'
bash "$HERE/publish-tdx-image.sh" "$OUT/config-b.raw" "$CONFIG_IMAGE_B" | tail -12 | sed 's/^/    b| /'
rm -f "$OUT/config-a.raw" "$OUT/config-b.raw"

# ---- 5. the two instances, together ---------------------------------------
echo
echo "############ 4. creating both guests ############"
for vm in "$VM_A" "$VM_B"; do
  if gcloud compute instances describe "$vm" --zone "$ZONE" >/dev/null 2>&1; then
    echo "$vm exists already; refusing to reuse it" >&2
    exit 2
  fi
done
create_guest() { # VM BOOT_IMAGE CONFIG_IMAGE IP
  gcloud beta compute instances create "$1" --zone "$ZONE" \
    --machine-type c3-standard-4 \
    --confidential-compute-type TDX --maintenance-policy TERMINATE \
    --image "$2" \
    --boot-disk-size 20GB --boot-disk-type pd-balanced --boot-disk-auto-delete \
    --create-disk "name=$1-config,image=$3,size=10GB,type=pd-balanced,device-name=attested-config,auto-delete=yes" \
    --private-network-ip "$4" \
    --labels "$LABEL" \
    --format 'value(name,zone,machineType,status,networkInterfaces[0].networkIP)'
}
CREATED_A="$(date -u +%Y-%m-%dT%H:%MZ)"; CREATED_B="$CREATED_A"
echo "creating $VM_A and $VM_B at $CREATED_A"
create_guest "$VM_A" "$BOOT_A" "$CONFIG_IMAGE_A" "$IP_A" > "$OUT/create-a.txt" 2>&1 &
CPID_A=$!
create_guest "$VM_B" "$BOOT_B" "$CONFIG_IMAGE_B" "$IP_B" > "$OUT/create-b.txt" 2>&1 &
CPID_B=$!
CRC_A=0; CRC_B=0
wait "$CPID_A" || CRC_A=$?
wait "$CPID_B" || CRC_B=$?
sed 's/^/    a| /' "$OUT/create-a.txt"
sed 's/^/    b| /' "$OUT/create-b.txt"
[ "$CRC_A" = 0 ] && [ "$CRC_B" = 0 ] || { echo "an instance create failed" >&2; exit 2; }

# ---- 6. the consoles, both at once, by byte offset ------------------------
echo
echo "############ 5. watching both serial consoles ############"
# Incrementally, and never re-fetched whole: Compute Engine returns an empty
# body for an instance that has stopped, so a loop that re-fetched would erase
# the transcript at the moment the guest finished writing it. --start takes a
# byte offset and gcloud prints the next one on its own stderr.
watch_console() { # VM OUTFILE
  local vm="$1" out="$2" start=0 next state now started
  : > "$out"
  started=$(date +%s)
  fetch() {
    gcloud compute instances get-serial-port-output "$vm" --zone "$ZONE" --port 1 --start="$start" \
      > "$out.chunk" 2> "$out.hint" || true
    [ -s "$out.chunk" ] && cat "$out.chunk" >> "$out"
    next=$(sed -n 's/.*--start=\([0-9]\{1,\}\).*/\1/p' "$out.hint" | tail -1)
    [ -n "$next" ] && start="$next"
    rm -f "$out.chunk" "$out.hint"
  }
  while :; do
    fetch
    if grep -q '^initrd: EXIT status=' "$out" 2>/dev/null; then
      echo "finished: $(grep -h '^initrd: EXIT status=' "$out" | tail -1)" > "$out.state"; return 0
    fi
    if grep -q '^initrd: FATAL' "$out" 2>/dev/null; then
      echo "halted: $(grep -h '^initrd: FATAL' "$out" | tail -1)" > "$out.state"; return 0
    fi
    state=$(gcloud compute instances describe "$vm" --zone "$ZONE" --format='value(status)' 2>/dev/null || echo UNKNOWN)
    case "$state" in
      RUNNING|STAGING|PROVISIONING) ;;
      *) echo "the instance is $state; the guest powered itself off" > "$out.state"; break ;;
    esac
    now=$(date +%s)
    if [ $((now - started)) -ge "$DEADLINE" ]; then
      echo "deadline of ${DEADLINE}s passed without the guest finishing" > "$out.state"; break
    fi
    sleep 2
  done

  # The tail is the part that goes missing, and it is the part worth having:
  # the guest's last lines are the peer summary and the two EXIT statuses, and
  # `poweroff -f` follows them by milliseconds. Compute Engine serves the
  # console with some lag, so a loop that stops the moment the instance leaves
  # RUNNING stops one poll too early — scenario one's first run lost exactly
  # those lines that way. So the incremental fetch keeps going for a while
  # after the instance has stopped, and gives up early once the last line the
  # guest ever writes has arrived.
  local tries
  for tries in $(seq 1 30); do
    grep -q '^initrd: EXIT status=' "$out" 2>/dev/null && break
    sleep 3
    fetch
  done
  # And one whole-buffer read as the last resort, into its own file, kept only
  # if it is strictly longer than what the incremental capture built. A refetch
  # cannot be the loop — an instance that has stopped answers it with an empty
  # body, which is how a transcript gets erased at the moment it is finished —
  # but as a recovery that can only add, after the loop is done, it is safe.
  gcloud compute instances get-serial-port-output "$vm" --zone "$ZONE" --port 1 --start=0 \
    > "$out.full" 2>/dev/null || true
  local whole incremental recovered
  whole=$(stat -c %s "$out.full" 2>/dev/null || echo 0)
  incremental=$(stat -c %s "$out")
  recovered="the whole-buffer read after the stop returned $whole bytes against the $incremental the incremental capture holds"
  if [ "$whole" -gt "$incremental" ]; then
    mv "$out.full" "$out"
    recovered="$recovered; it was longer, so it replaced the capture"
  fi
  rm -f "$out.full"
  echo "$(cat "$out.state"); $recovered" > "$out.state"
  rm -f "$out.full"
  return 0
}
CONSOLE_A="$OUT/console-a.txt"
CONSOLE_B="$OUT/console-b.txt"
watch_console "$VM_A" "$CONSOLE_A" & WPID_A=$!
watch_console "$VM_B" "$CONSOLE_B" & WPID_B=$!
wait "$WPID_A" || true
wait "$WPID_B" || true
echo "guest A: $(cat "$CONSOLE_A.state" 2>/dev/null)"
echo "guest B: $(cat "$CONSOLE_B.state" 2>/dev/null)"
echo "console A: $(wc -l < "$CONSOLE_A") lines; console B: $(wc -l < "$CONSOLE_B") lines"
rm -f "$CONSOLE_A.state" "$CONSOLE_B.state"

echo
echo "---- guest A, the lines that matter ----"
grep -E '^initrd: (loaded|config device|link|loopback|EXIT|FATAL|report interface)|^tunneld: (EGRESS|SELFCHECK VERDICT|SELFCHECK measurement|SELFCHECK mrtd|SELFCHECK rtmr|SELFCHECK tcb|SELFCHECK \(unverified|CLAMPED|policy |reference value|listening|PEER |PEERS |REFUSED|LATENCY|EXIT|refusing|exercise)' \
  "$CONSOLE_A" | grep -v 'EGRESS RULES' | sed 's/^/    a| /' || true
echo
echo "---- guest B, the lines that matter ----"
grep -E '^initrd: (loaded|config device|link|loopback|EXIT|FATAL|report interface)|^tunneld: (EGRESS|SELFCHECK VERDICT|SELFCHECK measurement|SELFCHECK mrtd|SELFCHECK rtmr|SELFCHECK tcb|SELFCHECK \(unverified|CLAMPED|policy |reference value|listening|PEER |PEERS |REFUSED|LATENCY|EXIT|refusing|exercise)' \
  "$CONSOLE_B" | grep -v 'EGRESS RULES' | sed 's/^/    b| /' || true

# ---- 7. the quotes, judged here rather than there -------------------------
echo
echo "############ 6. each guest's quote, judged on this workstation ############"
printf '%s\n' "$AUTHOR_PUB" > "$OUT/author.pub"
cp "$W/a/reference-values.json" "$OUT/set-a.json"
cp "$W/a/reference-values.json.sig" "$OUT/set-a.json.sig"
cp "$W/b/reference-values.json" "$OUT/set-b.json"
cp "$W/b/reference-values.json.sig" "$OUT/set-b.json.sig"
cp "$W/a/policy.json" "$OUT/policy-a.json"; cp "$W/a/policy.json.sig" "$OUT/policy-a.json.sig"
cp "$W/b/policy.json" "$OUT/policy-b.json"; cp "$W/b/policy.json.sig" "$OUT/policy-b.json.sig"

extract_quote() { # CONSOLE PREFIX
  awk '/SELFCHECK EVIDENCE BEGIN/{f=1;next} /SELFCHECK EVIDENCE END/{f=0} f' "$1" \
    | sed -n 's/^tunneld: SELFCHECK EVIDENCE //p' | tr -d ' \r\n' | base64 -d > "$OUT/quote-$2.bin" 2>/dev/null || true
  local keyhex
  keyhex=$(sed -n 's/^tunneld: SELFCHECK PUBLIC KEY //p' "$1" | tail -1 | tr -d ' \r')
  [ -n "$keyhex" ] && printf '%s' "$keyhex" | xxd -r -p > "$OUT/public-key-$2.der"
  [ -s "$OUT/quote-$2.bin" ] && python3 "$HERE/parse-tdx-quote.py" "$OUT/quote-$2.bin" > "$OUT/quote-$2.txt" 2>&1 || true
}
extract_quote "$CONSOLE_A" a
extract_quote "$CONSOLE_B" b

# The two checks worth making on one quote, and they are different questions.
# "own set" is the check the guest made about itself, remade by somebody who
# trusts none of its machinery. "peer's set" is the check the PEER made, and in
# every arrangement where two guests pin each other it is the only one that can
# come back accepted.
verify_one() { # WHICH REFVALS POLICYDIGEST LABEL OUTFILE
  local which="$1" refvals="$2" digest="$3" label="$4" outfile="$5"
  {
    echo "=== $label ==="
    echo "evidence : $OUT/quote-$which.bin"
    echo "key      : $OUT/public-key-$which.der"
    echo "refvals  : $refvals"
    echo "policy   : $digest"
    echo
  } >> "$outfile"
  if [ ! -s "$OUT/quote-$which.bin" ] || [ ! -s "$OUT/public-key-$which.der" ]; then
    echo "no quote on this guest's console; nothing to verify" >> "$outfile"
    return 1
  fi
  "$TOOLS/verify-evidence" \
      -vendor intel-tdx \
      -evidence "$OUT/quote-$which.bin" \
      -key "$OUT/public-key-$which.der" \
      -refvals "$refvals" \
      -author "$OUT/author.pub" \
      -policy-digest "$digest" \
      -tdx-collateral-dir "$COLLATERAL" >> "$outfile" 2>&1
  local rc=$?
  echo "" >> "$outfile"
  echo "verify-evidence exit status: $rc  (0 accepted, 2 refused)" >> "$outfile"
  echo "" >> "$outfile"
  return $rc
}
: > "$OUT/verify-evidence-a.txt"; : > "$OUT/verify-evidence-b.txt"
VA_OWN=0; VA_PEER=0; VB_OWN=0; VB_PEER=0
verify_one a "$OUT/set-a.json" "$D_A" "guest A's quote against guest A's OWN set (the self-check, remade here)" "$OUT/verify-evidence-a.txt" || VA_OWN=$?
verify_one a "$OUT/set-b.json" "$D_A" "guest A's quote against guest B's set (the check guest B makes of A)"     "$OUT/verify-evidence-a.txt" || VA_PEER=$?
verify_one b "$OUT/set-b.json" "$D_B" "guest B's quote against guest B's OWN set (the self-check, remade here)" "$OUT/verify-evidence-b.txt" || VB_OWN=$?
verify_one b "$OUT/set-a.json" "$D_B" "guest B's quote against guest A's set (the check guest A makes of B)"     "$OUT/verify-evidence-b.txt" || VB_PEER=$?
grep -E '^(===|verify-evidence exit status|ACCEPTED|REFUSED|refused|accepted)' "$OUT/verify-evidence-a.txt" | sed 's/^/    a| /' || true
grep -E '^(===|verify-evidence exit status|ACCEPTED|REFUSED|refused|accepted)' "$OUT/verify-evidence-b.txt" | sed 's/^/    b| /' || true

# ---- 8. the registers each boot reported ----------------------------------
reg() { # CONSOLE NAME
  sed -n "s/^tunneld: SELFCHECK $2  *//p;s/^tunneld: SELFCHECK (unverified, read straight out of the quote's bytes) $2  *//p;s/^tunneld: SELFCHECK (unverified) $2  *//p" "$1" | tail -1
}
{
  echo "# scenario $SCENARIO: the registers each boot reported."
  echo "#"
  echo "# The RTMR2 column is the only one that had to be PREDICTED; MRTD, RTMR0 and"
  echo "# RTMR1 are the provider's constants for this shape and are pinned from"
  echo "# observation. RTMR1's first-boot value is the expected one here: this guest"
  echo "# never runs Ubuntu's initramfs, so nothing ever grows the root and the GPT"
  echo "# never changes (docs/snp/cloud/tdx/SCENARIOS.md)."
  echo
  for which in a b; do
    case $which in a) c="$CONSOLE_A"; vm="$VM_A"; want="$MEAS_A";; b) c="$CONSOLE_B"; vm="$VM_B"; want="$MEAS_B";; esac
    echo "guest $which ($vm)"
    echo "  predicted rtmr2 : $want"
    echo "  quoted    rtmr2 : $(sed -n 's/^rtmr2 *: //p' "$OUT/quote-$which.txt" 2>/dev/null)"
    echo "  console   rtmr2 : $(reg "$c" rtmr2)"
    echo "  console   mrtd  : $(reg "$c" mrtd)"
    echo "  console   rtmr0 : $(reg "$c" rtmr0)"
    echo "  console   rtmr1 : $(reg "$c" rtmr1)"
    echo "  quoted    mrtd  : $(sed -n 's/^mrtd *: //p' "$OUT/quote-$which.txt" 2>/dev/null)"
    echo "  quoted    rtmr0 : $(sed -n 's/^rtmr0 *: //p' "$OUT/quote-$which.txt" 2>/dev/null)"
    echo "  quoted    rtmr1 : $(sed -n 's/^rtmr1 *: //p' "$OUT/quote-$which.txt" 2>/dev/null)"
    echo "  tcb             : $(sed -n 's/^tunneld: SELFCHECK tcb  *//p' "$c" | tail -1)"
    echo
  done
} > "$OUT/measurements.txt"
sed 's/^/    /' "$OUT/measurements.txt"

# The three-way agreement on the policy digest, completed from the console.
D_A_CONSOLE=$(sed -n 's/^tunneld: policy digest \([0-9a-f]\{64\}\).*/\1/p' "$CONSOLE_A" | tail -1)
D_B_CONSOLE=$(sed -n 's/^tunneld: policy digest \([0-9a-f]\{64\}\).*/\1/p' "$CONSOLE_B" | tail -1)
{
  echo
  echo "the third reading, off the guests' own consoles:"
  echo "    guest A printed policy digest : $D_A_CONSOLE"
  echo "    guest B printed policy digest : $D_B_CONSOLE"
} >> "$OUT/digests.txt"

# ---- 9. the assertions ----------------------------------------------------
echo
echo "############ 7. what the run showed ############"
A="$CONSOLE_A"; B="$CONSOLE_B"

for which in a b; do
  case $which in a) c="$A"; g=A; ip="$IP_A";; b) c="$B"; g=B; ip="$IP_B";; esac
  check "guest $g: the initrd ran and loaded the TDX guest driver" in_file "$c" "initrd: loaded tdx-guest"
  check "guest $g: the config device was found and mounted read-only" in_file "$c" "initrd: config device mounted at /config (ro,noexec,nosuid,nodev)"
  check "guest $g: the address on the config device came up with the VPC's gateway route" in_file "$c" "initrd: link eth0 up: $ip/32 mtu $MTU, gateway $GATEWAY"
  check "guest $g: the egress rule set the signed policy implies was installed and read back out of the kernel" in_file "$c" "tunneld: EGRESS RULES INSTALLED; as the kernel holds them:"
  check "guest $g: every attempt at the egress the policy forbids was refused before it left" in_file "$c" "tunneld: EGRESS PROBE PASSED: every attempt was refused before it left"
  check "guest $g: the provider's metadata server is in the refused set" in_file "$c" "EGRESS REFUSED tcp/169.254.169.254:80"
  check "guest $g: it read the author key from inside the launch measurement" in_file "$c" "tunneld: author key ${AUTHOR_PUB:0:16}… (/etc/attested-tunnel/author.pub, inside the launch measurement)"
  check "guest $g: it acquired its own evidence from this platform" in_file "$c" "tunneld: SELFCHECK acquired"
  check "guest $g: it is listening" in_file "$c" "tunneld: listening on $ip:$PORT"
  check "guest $g: no reference value in its set is unconstrained" not_in_file "$c" "is unconstrained: it admits any policy"
  check "guest $g: nothing was clamped, so the maximum age in force is the one on its config device" not_in_file "$c" "tunneld: CLAMPED"
  # The one condition that stops this ticket rather than being recorded by it.
  # It is read from wherever this run has it: an admitted self-check and an
  # admitted peer both print the status on the console, and where neither
  # happened the workstation's own verification of the same quote does.
  check "guest $g: Intel reports this platform UpToDate at evaluation 20" \
        tcb_uptodate "$c" "$OUT/verify-evidence-$which.txt"
  check "guest $g: nothing was refused for being below the TCB floor" not_in_file "$c" "platform below the TCB floor"
  if in_file "$c" "initrd: EXIT status="; then
    note "      guest $g: the console survived the guest's own poweroff to the initrd's last line"
  else
    note "      guest $g: the console ends at $(tail -1 "$c" | cut -c1-60)…"
    note "      guest $g: the last lines this guest wrote — the peer summary, tunneld's EXIT status and"
    note "                the initrd's — are not on it. The guest writes them and powers off within"
    note "                milliseconds, and Compute Engine serves an empty body for an instance that has"
    note "                stopped, so they cannot be fetched afterwards either. The smoke boot's console"
    note "                ends the same way. What the exercise did is read from its own lines instead."
  fi
done
check "guest A printed the digest of the policy on its own config device" test "$D_A_CONSOLE" = "$D_A"
check "guest B printed the digest of the policy on its own config device" test "$D_B_CONSOLE" = "$D_B"
check "guest A's policy says which measurements it will dial" in_file "$A" "tunneld: policy forward_to: measurement"
check "guest B's policy says which measurements it will dial" in_file "$B" "tunneld: policy forward_to: measurement"

case "$SCENARIO" in
  one)
    check "scenario one: guest A admitted guest B, whose policy digest its value names" in_file "$A" "tunneld: PEER key="
    check "scenario one: guest B admitted guest A, whose policy digest its value names" in_file "$B" "tunneld: PEER key="
    check "scenario one: guest A refused nothing"  not_in_file "$A" "tunneld: REFUSED"
    check "scenario one: and neither did guest B"  not_in_file "$B" "tunneld: REFUSED"
    check "scenario one: guest A established a tunnel and exchanged over it, warm" in_file "$A" "kind=warm_exchange"
    check "scenario one: guest B established one too"                              in_file "$B" "kind=warm_exchange"
    check "scenario one: guest B answered guest A's exchanges" in_file "$A" 'answered_by="guest-b"'
    check "scenario one: guest A answered guest B's exchanges" in_file "$B" 'answered_by="guest-a"'
    check "scenario one: guest A's exercise completed with nothing failed"  exercise_succeeded "$A"
    check "scenario one: guest B's exercise completed with nothing failed"  exercise_succeeded "$B"
    # The re-attestation the ticket asks for. A pass later than the first that
    # cost a verification AND a real handshake is a tunnel that reached its
    # maximum age underneath a caller who kept using it: a reused tunnel costs
    # no verifier call and establishes in tens of microseconds.
    reattested() { # CONSOLE
      awk '/kind=establish/ {
             pass=0; calls=0; msv=0
             for (i=1;i<=NF;i++) {
               if ($i ~ /^pass=/)           { split($i,p,"="); pass=p[2]+0 }
               if ($i ~ /^verifier_calls=/) { split($i,v,"="); calls=v[2]+0 }
               if ($i ~ /^ms=/)             { split($i,m,"="); msv=m[2]+0 }
             }
             if (pass > 1 && calls >= 1 && msv > 1.0) found=1
           } END { exit found?0:1 }' "$1"
    }
    check "scenario one: guest A re-attested its peer mid-run — a pass after the first cost a verification and a real handshake" reattested "$A"
    check "scenario one: guest B re-attested its peer mid-run"                                                                   reattested "$B"
    # How many times each guest verified the other is also in the PEERS and
    # PEER SEEN summary lines, and those are in the tail the guest's poweroff
    # takes with it. The establishment lines above carry the same fact while
    # the guest is still running, so they are what this asserts on: the count
    # of passes that cost a verification.
    verifications() { # CONSOLE -- how many establishments cost a verifier call
      awk '/kind=establish/ { for (i=1;i<=NF;i++) if ($i ~ /^verifier_calls=/) { split($i,v,"="); if (v[2]+0 >= 1) n++ } }
           END { print n+0 }' "$1"
    }
    more_than_once() { [ "$(verifications "$1")" -ge 2 ]; }
    check "scenario one: guest A verified guest B's evidence on more than one pass — $(verifications "$A") of its establishments cost a verification" more_than_once "$A"
    check "scenario one: guest B verified guest A's evidence on more than one pass — $(verifications "$B") of its establishments cost a verification" more_than_once "$B"
    check "scenario one: guest A's quote is admitted by the set guest B holds" test "$VA_PEER" = 0
    check "scenario one: guest B's quote is admitted by the set guest A holds" test "$VB_PEER" = 0
    # And the consequence of mutual pinning, said out loud rather than left as a
    # surprise on the console: a set that names the peer's pair does not name
    # this guest's own, so the self-check is refused on the policy digest.
    check "scenario one: guest A's self-check is refused on the policy digest, because its set names B's digest and not its own" \
          re_in_file "$A" "SELFCHECK VERDICT REFUSED reason=guest policy or policy digest not permitted"
    check "scenario one: guest B's self-check is refused the same way, for the same reason" \
          re_in_file "$B" "SELFCHECK VERDICT REFUSED reason=guest policy or policy digest not permitted"
    check "scenario one: and this workstation reaches the same verdict on guest A's quote against guest A's own set" test "$VA_OWN" = 2
    check "scenario one: and on guest B's quote against guest B's own set"                                            test "$VB_OWN" = 2
    ;;
  two)
    check "scenario two: guest A refused guest B, naming the policy digest B presented" \
          in_file "$A" "REFUSED verification refused: guest policy or policy digest not permitted by the reference value: peer presents policy digest $D_B"
    check "scenario two: guest B admitted guest A" in_file "$B" "tunneld: PEER key="
    check "scenario two: guest B refused nothing"  not_in_file "$B" "tunneld: REFUSED"
    check "scenario two: no tunnel in either direction — guest A got none" in_file "$A" "peer=guest-b FAILED"
    check "scenario two: and guest B got none either"                      in_file "$B" "peer=guest-a FAILED"
    check "scenario two: nothing was exchanged either way (A)" not_in_file "$A" "kind=warm_exchange"
    check "scenario two: nothing was exchanged either way (B)" not_in_file "$B" "kind=warm_exchange"
    check "scenario two: guest A's exercise failed, and named the peer it could not establish to" exercise_failed "$A"
    check "scenario two: guest B's exercise failed too"                                            exercise_failed "$B"
    # The local control: A's own set names A's own pair, so A's self-check is
    # admitted at the same moment A refuses B. The wiring is demonstrably intact
    # when the refusal happens.
    check "scenario two: guest A's self-check is ADMITTED — its set and this platform agree, so the refusal of B is about B" \
          in_file "$A" "SELFCHECK VERDICT ADMITTED"
    check "scenario two: this workstation admits guest A's quote against guest A's own set too" test "$VA_OWN" = 0
    check "scenario two: this workstation admits guest A's quote against the set guest B holds" test "$VA_PEER" = 0
    check "scenario two: this workstation REFUSES guest B's quote against the set guest A holds — the refusal, remade here" test "$VB_PEER" = 2
    ;;
  three)
    check "scenario three: guest A refused guest B on the measurement, naming the register that disagreed" \
          in_file "$A" "REFUSED verification refused: launch measurement not in the reference value set: the TD's RTMR2 is $M_B"
    check "scenario three: the reference value A holds predicts the other image's register" \
          in_file "$A" "and this reference value predicts $M_A"
    check "scenario three: guest B admitted guest A on the same handshake — the local control" in_file "$B" "tunneld: PEER key="
    check "scenario three: guest B refused nothing" not_in_file "$B" "tunneld: REFUSED"
    check "scenario three: no tunnel to guest B"    in_file "$A" "peer=guest-b FAILED"
    check "scenario three: and none back to guest A" in_file "$B" "peer=guest-a FAILED"
    check "scenario three: guest A's exercise failed, and named the peers it could not establish to" exercise_failed "$A"
    check "scenario three: guest B's exercise failed too"                                              exercise_failed "$B"
    check "scenario three: guest B really is on the other kernel" in_file "$B" "7.0.0-1011-gcp"
    check "scenario three: this workstation REFUSES guest B's quote against the set guest A holds" test "$VB_PEER" = 2
    check "scenario three: and admits guest A's quote against the set guest B holds" test "$VA_PEER" = 0
    # A's peer table names one address no guest has, to ask what tunneld's own
    # dialer does with a peer that is in the table and not on the network.
    #
    # The answer is a fact about where the rule set comes from. It is generated
    # from the PEER TABLE and the listen port, not from the policy: a policy's
    # forward_to names measurements, and a measurement is not an address, so
    # the policy cannot say which addresses may be reached. Every address in
    # the peer table is therefore excepted by the rules, including this one —
    # and the dial to it dies of silence rather than of a rule. Both halves are
    # asserted, because together they are the finding.
    check "scenario three: the rule set excepts the address in the peer table that no guest has, since the rules come from the peer table and not from the policy" \
          in_file "$A" "ip daddr $IP_OUTSIDER"
    check "scenario three: guest A got no tunnel to it" in_file "$A" "peer=outsider FAILED"
    check "scenario three: and that dial died of silence, not of the netfilter rule — an address a rule refuses fails at once and this one timed out" \
          re_in_file "$A" "peer=outsider FAILED.*timeout: no recent network activity"
    ;;
esac

# The egress capture, for the record's egress/ directory.
for which in a b; do
  case $which in a) c="$A"; g=a;; b) c="$B"; g=b;; esac
  {
    echo "### scenario $SCENARIO, guest $g: the rule set as the kernel holds it, and every attempt refused"
    echo
    awk '/EGRESS RULES/{f=1} f{print} /^}/{if(f)f=0}' "$c"
    echo
    grep -E '^tunneld: (EGRESS PROBE|EGRESS REFUSED|EGRESS PERMITTED|EGRESS UNROUTED|EGRESS TIMEOUT)' "$c" || true
    echo
  } > "$OUT/egress-$g.txt"
done
echo
echo "the egress capture is in $OUT/egress-a.txt and $OUT/egress-b.txt"

# Keep the config sources as delivered, minus the collateral: it is byte for
# byte docs/snp/evidence/tdx/collateral, and each console lists every file of it
# with its sha256, so a third copy per guest would be three copies of a thing
# already recorded twice.
rm -rf "$W/a/collateral" "$W/b/collateral" "$W/probe-a" "$W/probe-b"
rm -f "$OUT/create-a.txt" "$OUT/create-b.txt"
