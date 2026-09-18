#!/bin/bash
# Ticket 26's proof on two Google Cloud TDX guests: a sandbox that honours a
# pushed policy, is narrowed while it is fetching, and takes the tunnel down
# with it when it dies.
#
#   run-tdx-t26.sh policy [-keep] [-dry-run]
#
# Two Confidential VMs of the shape docs/snp/cloud/tdx/SCENARIOS.md pins, with
# one more disk than ticket 19's pair — a boot disk from a custom image whose
# initrd is the whole guest, a config device, and a workload device carrying one
# OCI bundle — brought up together, watched on the serial console until each
# powers itself off, judged here from the quotes they printed, and then deleted.
# The transcript ends in a PASS/FAIL count in the shape
# docs/snp/tunnel-on-two-guests.sh writes on the bench, and in the rows a person
# copies into docs/snp/cloud/tdx/RESOURCES.md.
#
# It is a separate script from run-tdx-scenario.sh rather than a fourth scenario
# inside it, because it differs from those three in more than four values: a
# third disk, a workload, an adapter order in the measured init, two policies
# that are pushed rather than signed, two timing knobs, a second tunneld on one
# guest, and a different pass table. Sharing a file with them would have meant
# `case` arms inside every step.
#
# ---------------------------------------------------------------------------
# What the run is supposed to show, and in what order the guests show it
# ---------------------------------------------------------------------------
#
#   1. it is in force      each guest's tunneld pushes a policy at the other
#                          when it dials; the sentry narrows the boot table it
#                          already holds to what that policy names; the page the
#                          policy permits is fetched over the tunnel; a name
#                          nobody's policy carries does not resolve (NXDOMAIN);
#                          an execve of a file whose path and digest the policy's
#                          `x` does not name fails EACCES inside the sandbox.
#   2. it can be replaced  guest B's init starts a SECOND tunneld after
#                          `narrow-after` seconds, which dials guest A and pushes
#                          a narrower policy. Guest A's sandbox applies it with
#                          the workload running: the dropped name stops
#                          resolving, and the stream that was already open
#                          arrives whole.
#   3. it is watched       guest A's tunneld had applied guest B's FIRST policy
#                          and was watching guest A's sandbox for that digest.
#                          The narrowing makes the sandbox pulse a different one,
#                          and tunneld — which does not parse n, f or x and
#                          cannot tell a narrowing from a different policy —
#                          closes the tunnel that policy arrived on, naming
#                          liveness. That costs nothing here, because guest A's
#                          own fetch is on the tunnel guest A dialed.
#   4. it ends with the workload
#                          init kills the sandbox after `kill-after` seconds, the
#                          helper's socket closes, and the tunneld beside it says
#                          so and closes the tunnel the policy came in on.
#
# ---------------------------------------------------------------------------
# The three disks, and the register that moves because of them
# ---------------------------------------------------------------------------
#
# A three-disk c3-standard-4 TDX guest reports a different RTMR0 from a two-disk
# one — `8ee4fa36…b70a3f` against `c2fc12a5…850a` — and ticket 24 observed that
# twice and authored it nowhere, so every guest of this shape was refused. Ticket
# 26 authors it deliberately, in `build-tdx-image.sh` and
# `emit-tdx-documents.sh`, and the argument is in
# `docs/snp/evidence/ticket26/tdx/RTMR0-DECISION.md`. This script does not read
# any register off any machine: the sets it emits come from those defaults, and
# the only thing it does with a quote is judge it.
#
# So: build the image with this branch's build-tdx-image.sh, or the sets will
# name one RTMR0 and the guests will report the other. The script checks the
# emitted set for both values before it creates anything.
#
# ---------------------------------------------------------------------------
# What a set says, and why the self-checks here are refused
# ---------------------------------------------------------------------------
#
# A reference value set says whom this guest ADMITS. Each guest here pins the
# other's (measurement, policy digest) pair and not its own, so each guest's own
# self-check is REFUSED on the policy digest with the measurement matching — the
# same thing run-tdx-scenario.sh's scenario one records, for the same reason, and
# not a failure of the run. The check that matters is the one the PEER makes,
# which this script also makes here from the same quote against the peer's set.
#
# ---------------------------------------------------------------------------
# Nothing here runs without being printed first
# ---------------------------------------------------------------------------
#
# Every gcloud call that changes anything goes through `mutate`, which echoes the
# whole command line before running it. `-dry-run` prints every one of them and
# runs none, builds no disk, publishes nothing and creates nothing — it is for
# reading the run before paying for it, and it is what this script was checked
# with, because a TDX instance costs money and a recorded run costs a ticket.
#
# Environment:
#   IMAGE_DIR    REQUIRED. build-tdx-image.sh's output directory, built from this
#                branch (disk.raw, manifest.txt, reference-values.json).
#   OUT          where the record goes (default docs/snp/evidence/ticket26/tdx/run)
#   BUNDLE_SRC   scratch directory the bundle is assembled in, OUTSIDE the repo
#                (default $OUT/../workload-src is refused; there is no default)
#   WORKLOAD_RAW skip make-bundle.sh and use this disk image instead
#   POLICY_INPUTS  the twelve unmeasured files
#                (default docs/snp/evidence/ticket26/snp/config)
#   KEY          the reference value author key whose public half is in the image
#   COLLATERAL   Intel's provisioned documents (default docs/snp/evidence/tdx/collateral)
#   ZONE, IP_A, IP_B, GATEWAY, PORT, MTU, DEADLINE, TICKET, LABEL
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
export PATH="/usr/local/go/bin:$PATH"

SCENARIO="${1:-}"
case "$SCENARIO" in
  policy) ;;
  *) echo "usage: $(basename "$0") policy [-keep] [-dry-run]" >&2; exit 2 ;;
esac
shift
KEEP=0; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -keep)    KEEP=1; shift ;;
    -dry-run) DRY=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

ZONE="${ZONE:-us-central1-a}"
IP_A="${IP_A:-10.128.0.40}"
IP_B="${IP_B:-10.128.0.41}"
GATEWAY="${GATEWAY:-10.128.0.1}"
PORT="${PORT:-4433}"
MTU="${MTU:-1460}"
DEADLINE="${DEADLINE:-1500}"
TICKET="${TICKET:-26}"
LABEL="${LABEL:-purpose=attested-tunnel-t$TICKET}"
OUT="${OUT:-$REPO/docs/snp/evidence/ticket$TICKET/tdx/run}"
POLICY_INPUTS="${POLICY_INPUTS:-$REPO/docs/snp/evidence/ticket26/snp/config}"
COLLATERAL="${COLLATERAL:-$REPO/docs/snp/evidence/tdx/collateral}"
KEY="${KEY:-$REPO/.scratch/attested-secure-tunnel/host-stack/image-ticket26-tdx/author.key}"
BUNDLE_SRC="${BUNDLE_SRC:-}"
WORKLOAD_RAW="${WORKLOAD_RAW:-}"
: "${IMAGE_DIR:?set IMAGE_DIR to the output directory of build-tdx-image.sh}"
IMAGE_DIR="$(readlink -f "$IMAGE_DIR")"

# The three-disk RTMR0 this ticket authored. It is checked against the set the
# image build emitted, never read off a guest.
RTMR0_THREE_DISK="8ee4fa3614e96b5c7cdacf52675c069e9de399a3688f83510a9bc3b4180e0e8f06c427eab69fcb4deff05203c0b70a3f"

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
knob_of()     { tr -d ' \r\n\t' < "$1" 2>/dev/null; }

# Every command that changes something outside this workstation goes through
# this, which prints it first. In a dry run it prints and returns.
mutate() {
  echo "    + $*"
  [ "$DRY" = 1 ] && return 0
  "$@"
}
# The same for a shell pipeline or a script this run invokes for its effects.
mutate_sh() {
  echo "    + $1"
  [ "$DRY" = 1 ] && return 0
  shift
  "$@"
}
dry_note() { [ "$DRY" = 1 ] && echo "    (dry run: $*)"; return 0; }

# The sentence a tunneld writes when a policy it applied stops being live:
# attest/refusal.go's eleventh reason, in one variable so that the day it is
# worded differently this is a one-line change and not six assertions to find.
LIVENESS_REASON="${LIVENESS_REASON:-the policy pushed to the peer is no longer live}"
LONG_BYTES=8388608

VM_A="t$TICKET-policy-a"
VM_B="t$TICKET-policy-b"
STAMP="$(date -u +%Y%m%d%H%M%S)"
CONFIG_IMAGE_A="attested-config-t$TICKET-a-$STAMP"
CONFIG_IMAGE_B="attested-config-t$TICKET-b-$STAMP"
WORKLOAD_IMAGE="attested-workload-t$TICKET-$STAMP"

CREATED_A="" CREATED_B="" DELETED_A="(not deleted)" DELETED_B="(not deleted)"
CREATED_IMAGES=()
BOOT_IMAGE_REUSED=0

resources_rows() {
  echo
  echo "############ rows for docs/snp/cloud/tdx/RESOURCES.md ############"
  echo "| created | name | type | purpose | state |"
  echo "|---|---|---|---|---|"
  local disks="20GB pd-balanced boot from \`${BOOT_IMAGE:-?}\` + 10GB pd-balanced config disk + 10GB pd-balanced workload disk (\`device-name attested-workload\`) — a THREE-disk shape, whose RTMR0 \`8ee4fa36…b70a3f\` this ticket authored"
  printf '| %s | %s | c3-standard-4 TDX, %s, %s, `--private-network-ip %s` | ticket %s %s, guest A: the sandbox that is narrowed mid-fetch and killed at %ss | **deleted %s** |\n' \
    "${CREATED_A:-(never created)}" "$VM_A" "$ZONE" "$disks" "$IP_A" "$TICKET" "$SCENARIO" "${KILL_A:-?}" "$DELETED_A"
  printf '| %s | %s | c3-standard-4 TDX, %s, %s, `--private-network-ip %s` | ticket %s %s, guest B: the second pusher (narrow-after %ss), killed at %ss | **deleted %s** |\n' \
    "${CREATED_B:-(never created)}" "$VM_B" "$ZONE" "$disks" "$IP_B" "$TICKET" "$SCENARIO" "${NARROW_B:-?}" "${KILL_B:-?}" "$DELETED_B"
  local i
  local imgstate="**deleted with the run**"
  [ "$DRY" = 1 ] && imgstate="(dry run: never created)"
  [ "$KEEP" = 1 ] && imgstate="**kept, -keep — delete by hand**"
  for i in "${CREATED_IMAGES[@]+"${CREATED_IMAGES[@]}"}"; do
    printf '| %s | %s | custom image, label `%s` | ticket %s %s | %s |\n' \
      "${CREATED_A:-}" "$i" "$LABEL" "$TICKET" "$SCENARIO" "$imgstate"
  done
  if [ "$BOOT_IMAGE_REUSED" = 1 ]; then
    printf '| (pre-existing) | %s | custom image, 10GiB | the boot image this run BOOTED and did not create; it is not deleted here | **left as it was** |\n' "${BOOT_IMAGE:-?}"
  fi
  echo
  echo "Every bucket this run used was created and deleted inside publish-tdx-image.sh, which is"
  echo "where Compute Engine takes bytes from; none survives the call that made it."
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  echo
  echo "############ tearing down ############"
  if [ "$DRY" = 1 ]; then
    echo "dry run: nothing was created, so nothing is deleted"
    DELETED_A="(dry run: never created)"; DELETED_B="(dry run: never created)"
  elif [ "$KEEP" = 1 ]; then
    echo "keeping $VM_A and $VM_B (-keep); delete them by hand, the same hour they were created:"
    echo "  gcloud compute instances delete $VM_A $VM_B --zone $ZONE --quiet"
    DELETED_A="(kept, -keep)"; DELETED_B="(kept, -keep)"
  else
    local pair vm which created
    for pair in "$VM_A:A" "$VM_B:B"; do
      vm="${pair%:*}"; which="${pair#*:}"
      eval "created=\$CREATED_$which"
      [ -n "$created" ] || { echo "$vm was never created; nothing to delete"; continue; }
      if mutate gcloud compute instances delete "$vm" --zone "$ZONE" --quiet; then
        eval "DELETED_$which=\"\$(date -u +%Y-%m-%dT%H:%MZ)\""
      else
        eval "DELETED_$which='**DELETE FAILED -- STILL RUNNING**'"
        echo "the delete of $vm FAILED; it is still running and RESOURCES.md must say so"
      fi
    done
    # Only images THIS run created. A boot image that already existed is one a
    # previous run kept on purpose, and ten gibibytes is the one cost this
    # project refuses to pay twice.
    local img
    for img in "${CREATED_IMAGES[@]+"${CREATED_IMAGES[@]}"}"; do
      if gcloud compute images describe "$img" >/dev/null 2>&1; then
        mutate gcloud compute images delete "$img" --quiet && echo "deleted image $img" \
          || echo "the delete of image $img FAILED"
      fi
    done
  fi
  echo
  echo "what still carries $LABEL:"
  [ "$DRY" = 1 ] || gcloud compute instances list --filter="labels.purpose=attested-tunnel-t$TICKET" --format='value(name,zone,status)' || true
  echo "disks:"
  [ "$DRY" = 1 ] || gcloud compute disks list --filter="name~t$TICKET" --format='value(name,zone,status)' || true
  echo "images:"
  [ "$DRY" = 1 ] || gcloud compute images list --no-standard-images --format='value(name,status)' || true
  echo "buckets:"
  [ "$DRY" = 1 ] || gcloud storage buckets list --format='value(name)' 2>/dev/null || true
  resources_rows
  rm -rf "${TOOLS:-}"
  echo
  echo "=== $PASSES passed, $FAILURES failed ==="
  echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ), exit $rc ==="
  if [ "$rc" != 0 ]; then exit "$rc"; fi
  if [ "$FAILURES" != 0 ]; then exit 1; fi
  exit 0
}
trap cleanup EXIT
trap 'echo interrupted; exit 130' INT TERM

echo "=== ticket $TICKET, $SCENARIO: a sandbox that honours a pushed policy, on two Google Cloud TDX guests ==="
echo "date        : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "repo        : $(git -C "$REPO" rev-parse HEAD) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
echo "mode        : $([ "$DRY" = 1 ] && echo 'DRY RUN — every command is printed and none is run' || echo 'live')"
echo "project     : $(gcloud config get-value project 2>/dev/null || echo '(gcloud not answering)'), zone $ZONE"
echo "image dir   : $IMAGE_DIR"
echo "out         : $OUT"
echo "policy input: $POLICY_INPUTS"
echo "collateral  : $COLLATERAL (provisioned, never fetched)"
echo

# ---- 0. what has to be true before anything is created ---------------------
echo "############ 0. preconditions ############"
for f in disk.raw manifest.txt reference-values.json reference-values.json.sig; do
  [ -f "$IMAGE_DIR/$f" ] || { echo "missing $IMAGE_DIR/$f — run build-tdx-image.sh first" >&2; exit 2; }
done
[ -f "$KEY" ] || { echo "no author key at $KEY" >&2; exit 2; }
[ -d "$COLLATERAL" ] || { echo "no collateral at $COLLATERAL" >&2; exit 2; }
RTMR2=$(sed -n 's/^predicted_rtmr2: //p' "$IMAGE_DIR/manifest.txt")
[[ "$RTMR2" =~ ^[0-9a-f]{96}$ ]] || { echo "no predicted_rtmr2 in $IMAGE_DIR/manifest.txt" >&2; exit 2; }
echo "predicted RTMR2 of the image both guests boot: $RTMR2"

# The image must carry the two things ticket 26 needs in the measurement and
# ticket 19's image did not have: the exit, and the page it will be asked for.
grep -q '^/usr/bin/agent-probe ' "$IMAGE_DIR/manifest.txt" \
  || { echo "this image carries no /usr/bin/agent-probe; rebuild it with this branch's build-tdx-image.sh" >&2; exit 2; }
grep -q '^/srv/index.html ' "$IMAGE_DIR/manifest.txt" \
  || { echo "this image carries no /srv/index.html; rebuild it with this branch's build-tdx-image.sh" >&2; exit 2; }
echo "the image carries agent-probe, /srv/index.html and /etc/hosts, so its exit has something to serve"

# The set the build emitted has to name the shape these guests will be. Checked
# here rather than discovered on a console, because a set that names the wrong
# RTMR0 refuses both guests and costs two instances to find out.
grep -qF "$RTMR0_THREE_DISK" "$IMAGE_DIR/reference-values.json" \
  || { echo "the set in $IMAGE_DIR names no three-disk RTMR0 ($RTMR0_THREE_DISK); these guests would be refused. Rebuild with this branch's build-tdx-image.sh (docs/snp/evidence/ticket26/tdx/RTMR0-DECISION.md)" >&2; exit 2; }
echo "the emitted set names the three-disk RTMR0 this ticket authored"

# Intel's documents expire, and past that instant every TDX peer is refused as
# ChainNotRooted however healthy it is (ADR-0007). Checked, not assumed.
NEXT_UPDATE=$(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
print(d["tcbInfo"]["nextUpdate"])' "$COLLATERAL/tcbinfo-00806f050000.body" 2>/dev/null || echo "")
echo "collateral valid until: ${NEXT_UPDATE:-(could not be read)}"
if [ -n "$NEXT_UPDATE" ]; then
  NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if [ "$NOW" \> "$NEXT_UPDATE" ]; then
    echo "the provisioned Intel collateral expired at $NEXT_UPDATE; every TDX peer would be refused as ChainNotRooted." >&2
    echo "Re-provision it first: docs/snp/evidence/ticket24/collateral-refresh.txt has the four curl requests." >&2
    exit 2
  fi
fi

KILL_A=$(knob_of "$POLICY_INPUTS/a/kill-after")
KILL_B=$(knob_of "$POLICY_INPUTS/b/kill-after")
NARROW_B=$(knob_of "$POLICY_INPUTS/b/narrow-after")
LAST=$KILL_A; [ "$KILL_B" -gt "$LAST" ] && LAST=$KILL_B
HOLD=$((LAST + 150))
[ "$DEADLINE" -gt $((LAST + 330)) ] || DEADLINE=$((LAST + 330))
# A liveness watch lives exactly as long as the tunnel the policy arrived on:
# attest/tunneld/push.go's watchLiveness polls conn.Live() and returns the moment
# it is false, silently, because a watch whose tunnel is gone has nothing left to
# tear down. At the sixty seconds every other scenario uses, both tunnels here
# idle out about a minute after the last fetch and long before the first kill, so
# the kill that is supposed to end liveness has nobody watching — which is what
# the first SEV-SNP pair of this scenario recorded (../../evidence/ticket26/snp/run).
# The idle timeout therefore outlives this scenario's own hold: the tunnels stay
# up until the guests power off, and what ends a watch is the sandbox.
IDLE_TIMEOUT="${IDLE_TIMEOUT:-$((HOLD + 60))s}"
echo "kill-after  : guest A ${KILL_A}s, guest B ${KILL_B}s (from each guest's own workload start)"
echo "narrow-after: guest B ${NARROW_B}s — the second tunneld that pushes the narrower policy at guest A"
echo "tunneld hold: ${HOLD}s; console deadline ${DEADLINE}s. Both are derived from the knobs, not chosen here."
echo "idle timeout: ${IDLE_TIMEOUT} on every tunnel, so that no tunnel a policy arrived on idles out"
echo "              before the kill that is supposed to end it"
P0A=$(sha256sum "$POLICY_INPUTS/a/push-policy.json" | cut -d' ' -f1)
P0B=$(sha256sum "$POLICY_INPUTS/b/push-policy.json" | cut -d' ' -f1)
P1B=$(sha256sum "$POLICY_INPUTS/b/push-policy-narrow.json" | cut -d' ' -f1)
echo "the three documents this run turns on, and what each governs:"
echo "  A pushes at B : $P0A  $(cat "$POLICY_INPUTS/a/push-policy.json")"
echo "  B pushes at A : $P0B  $(cat "$POLICY_INPUTS/b/push-policy.json")"
echo "  B pushes at A : $P1B  $(cat "$POLICY_INPUTS/b/push-policy-narrow.json")   (second, narrower)"
echo

TOOLS="$(mktemp -d)"
if [ "$DRY" = 0 ]; then
  (cd "$REPO/attest" && GOPROXY=off go build -o "$TOOLS/attest-tool" ./cmd/attest-tool)
  (cd "$REPO/docs/snp/image/emit-refvals" && GOPROXY=off go build -o "$TOOLS/emit-refvals" .)
else
  dry_note "would build attest-tool and emit-refvals into $TOOLS"
fi

# ---- 1. the workload disk ---------------------------------------------------
echo "############ 1. the workload disk, one bundle, attached to both guests ############"
if [ -z "$WORKLOAD_RAW" ]; then
  [ -n "$BUNDLE_SRC" ] || { echo "set BUNDLE_SRC to a scratch directory OUTSIDE the repo, or WORKLOAD_RAW to a disk" >&2; exit 2; }
  WORKLOAD_RAW="$OUT/workload.raw"
  mutate_sh "bash $REPO/docs/snp/evidence/ticket26/snp/make-bundle.sh $BUNDLE_SRC $WORKLOAD_RAW -tdx" \
    bash "$REPO/docs/snp/evidence/ticket26/snp/make-bundle.sh" "$BUNDLE_SRC" "$WORKLOAD_RAW" -tdx
else
  WORKLOAD_RAW="$(readlink -f "$WORKLOAD_RAW")"
  echo "using the disk already built at $WORKLOAD_RAW"
fi
echo

# ---- 2. the four documents --------------------------------------------------
# A policy names measurements and no digests; a set names a measurement and a
# policy digest. So the policies are authored first, their digests read off the
# runs that wrote them, and only then are the two sets authored — each naming the
# digest of the document the OTHER guest carries. That is ticket 18's cycle and
# the reason the two documents were split (docs/policy-binding.md).
#
# Both guests boot the same image, so both sets admit the same measurement; what
# makes the two digests two numbers is that B's policy forwards to one more
# measurement, which names no image anybody has.
echo "############ 2. authoring the four signed documents ############"
W="$OUT/config-src"
rm -rf "$W"; mkdir -p "$W/a" "$W/b" "$W/probe-a" "$W/probe-b"
FICTION_TEXT='a TDX image this sandbox would also dial, which nothing in this project has built'
FICTION="$(printf '%s' "$FICTION_TEXT" | sha384sum | cut -d' ' -f1)"
if [ "$DRY" = 1 ]; then
  dry_note "would run emit-tdx-documents.sh four times (a probe pair to learn the digests, then the real pair)"
  D_A="<D_A>"; D_B="<D_B>"
else
  bash "$HERE/emit-tdx-documents.sh" -out "$W/probe-a" -key "$KEY" -forward-to "$RTMR2" -admit "$RTMR2" > "$W/probe-a/emit.txt" 2>&1
  bash "$HERE/emit-tdx-documents.sh" -out "$W/probe-b" -key "$KEY" -forward-to "$RTMR2" -forward-to "$FICTION" -admit "$RTMR2" > "$W/probe-b/emit.txt" 2>&1
  D_A_EMIT=$(sed -n 's/^policy digest of the policy just written: //p' "$W/probe-a/emit.txt")
  D_B_EMIT=$(sed -n 's/^policy digest of the policy just written: //p' "$W/probe-b/emit.txt")
  echo "    D_A (guest A's own policy) = $D_A_EMIT"
  echo "    D_B (guest B's own policy) = $D_B_EMIT"
  bash "$HERE/emit-tdx-documents.sh" -out "$W/a" -key "$KEY" -forward-to "$RTMR2" \
       -admit "$RTMR2" -admit-policy "$D_B_EMIT" > "$W/a/emit.txt" 2>&1
  bash "$HERE/emit-tdx-documents.sh" -out "$W/b" -key "$KEY" -forward-to "$RTMR2" -forward-to "$FICTION" \
       -admit "$RTMR2" -admit-policy "$D_A_EMIT" > "$W/b/emit.txt" 2>&1
  sed 's/^/    a| /' "$W/a/emit.txt"
  sed 's/^/    b| /' "$W/b/emit.txt"
  D_A=$(sed -n 's/^policy digest of the policy just written: //p' "$W/a/emit.txt")
  D_B=$(sed -n 's/^policy digest of the policy just written: //p' "$W/b/emit.txt")
  check "the two policies have distinct digests, so 'each names the other' is two numbers" test "$D_A" != "$D_B"
  check "guest A's set names the three-disk RTMR0 this ticket authored" grep -qF "$RTMR0_THREE_DISK" "$W/a/reference-values.json"
  check "guest B's set names it too"                                    grep -qF "$RTMR0_THREE_DISK" "$W/b/reference-values.json"
  rm -f "$W/a/emit.txt" "$W/b/emit.txt"
fi
echo

# ---- 3. the two config devices ---------------------------------------------
echo "############ 3. the two config devices ############"
write_side() { # a|b  OWN_IP  PEER_LABEL  PEER_IP  SANDBOX
  local g="$1" ip="$2" peer="$3" peerip="$4" sandbox="$5" d="$W/$g"
  cat > "$d/peers.json" <<EOF
{
  "format": "gvisor.dev/gvisor/attest/peer-table",
  "version": 1,
  "peers": {"$peer": "$peerip:$PORT"}
}
EOF
  # No "exercise" and no "link": the thing that opens a stream is the sandbox
  # beside this tunneld and the initrd brings the interface up. With a sandbox
  # socket configured tunneld's own echo stands down and the attached exit
  # answers, so what is left is an identity, a listener and a hold long enough
  # to outlive the workload that is using it.
  cat > "$d/tunneld.json" <<EOF
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "$sandbox",
  "listen": "$ip:$PORT",
  "limits": {"idle_timeout": "$IDLE_TIMEOUT", "max_age": "15m"},
  "start_timeout": "60s",
  "hold": "${HOLD}s"
}
EOF
  # The second run configuration, for the tunneld that pushes the narrower
  # policy. `listen` is empty so that it binds no port the first tunneld holds
  # (attest/cmd/tunneld/runconfig.go: an empty listen is the one the ceiling has
  # no opinion about, and package tunneld takes 127.0.0.1:0 for it); its dialer
  # opens a socket of its own, which the ceiling grants because it grants
  # udp/4433 outbound from any source port on eth0. The exercise is what makes
  # it dial, and the dial is what makes it push; the exchange after the push is
  # expected to fail, because the far end's exit reads a destination off the
  # first line of a stream and this payload is not one.
  cat > "$d/tunneld-narrow.json" <<EOF
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "$sandbox-narrow",
  "listen": "",
  "limits": {"idle_timeout": "$IDLE_TIMEOUT", "max_age": "15m"},
  "exercise": {
    "dial": ["$peer"],
    "wait": "2s",
    "payload": "the-second-pusher-does-not-exchange",
    "exchanges": 1,
    "concurrency": 1,
    "rounds": 1,
    "timeout": "20s"
  },
  "hold": "${HOLD}s"
}
EOF
  cat > "$d/network.conf" <<EOF
# The guest's addressing, outside the measurement (ticket 19). A Google VPC
# gives a guest a /32 and an off-link gateway, so the initrd adds a host route
# to the gateway first and then the default route through it.
interface=eth0
address=$ip
prefix=32
gateway=$GATEWAY
mtu=$MTU
EOF
  local f
  for f in tunnel-table.json exit-allow push-policy.json push-policy-narrow.json kill-after narrow-after; do
    cp "$POLICY_INPUTS/$g/$f" "$d/$f"
  done
  cp -r "$COLLATERAL" "$d/collateral"
}
if [ "$DRY" = 1 ]; then
  dry_note "would write peers.json, tunneld.json, tunneld-narrow.json, network.conf and the six unmeasured files into $W/{a,b}, plus a copy of the collateral"
else
  write_side a "$IP_A" guest-b "$IP_B" guest-a
  write_side b "$IP_B" guest-a "$IP_A" guest-b
  # The two policies stay in $W and do NOT go on either device: ticket 22 took
  # that document off the config device, tunneld refuses to start on one that
  # carries it, and mkconfigdev-tdx.sh refuses to build one.
  mkdir -p "$W/devices/a" "$W/devices/b"
  for g in a b; do
    find "$W/$g" -maxdepth 1 -mindepth 1 ! -name 'policy.json' ! -name 'policy.json.sig' \
         -exec cp -r {} "$W/devices/$g/" \;
    echo "    guest $g's device carries:"
    (cd "$W/devices/$g" && find . -maxdepth 1 -mindepth 1 | sort | sed 's/^/      /')
  done
  # env -u LABEL, and deliberately: this script's LABEL is the Compute Engine
  # resource label and mkconfigdev-tdx.sh's is the ext4 volume label the initrd
  # falls back to. A LABEL given in the environment is exported, and leaving it
  # through wrote `purpose=attested` onto a config device and cost ticket 24 an
  # instance (docs/snp/evidence/ticket24/spikes/E4/boot-1/).
  env -u LABEL bash "$HERE/mkconfigdev-tdx.sh" "$W/devices/a" "$OUT/config-a.raw" | sed 's/^/    a| /'
  env -u LABEL bash "$HERE/mkconfigdev-tdx.sh" "$W/devices/b" "$OUT/config-b.raw" | sed 's/^/    b| /'
fi
echo

# ---- 4. publish the three (or four) images ---------------------------------
echo "############ 4. publishing the images ############"
export LABELS="$LABEL"
BOOT_IMAGE="${BOOT_IMAGE:-attested-tdx-${RTMR2:0:12}}"
if [ "$DRY" = 0 ] && gcloud compute images describe "$BOOT_IMAGE" >/dev/null 2>&1; then
  echo "boot image $BOOT_IMAGE exists already; reusing it and NOT deleting it afterwards"
  BOOT_IMAGE_REUSED=1
else
  mutate_sh "bash $HERE/publish-tdx-image.sh $IMAGE_DIR/disk.raw $BOOT_IMAGE" \
    bash "$HERE/publish-tdx-image.sh" "$IMAGE_DIR/disk.raw" "$BOOT_IMAGE"
  CREATED_IMAGES+=("$BOOT_IMAGE")
fi
mutate_sh "bash $HERE/publish-tdx-image.sh $OUT/config-a.raw $CONFIG_IMAGE_A" \
  bash "$HERE/publish-tdx-image.sh" "$OUT/config-a.raw" "$CONFIG_IMAGE_A"
CREATED_IMAGES+=("$CONFIG_IMAGE_A")
mutate_sh "bash $HERE/publish-tdx-image.sh $OUT/config-b.raw $CONFIG_IMAGE_B" \
  bash "$HERE/publish-tdx-image.sh" "$OUT/config-b.raw" "$CONFIG_IMAGE_B"
CREATED_IMAGES+=("$CONFIG_IMAGE_B")
mutate_sh "bash $HERE/publish-tdx-image.sh $WORKLOAD_RAW $WORKLOAD_IMAGE" \
  bash "$HERE/publish-tdx-image.sh" "$WORKLOAD_RAW" "$WORKLOAD_IMAGE"
CREATED_IMAGES+=("$WORKLOAD_IMAGE")
[ "$DRY" = 1 ] || rm -f "$OUT/config-a.raw" "$OUT/config-b.raw"
echo

# ---- 5. the two instances, three disks each --------------------------------
echo "############ 5. creating both guests ############"
if [ "$DRY" = 0 ]; then
  for vm in "$VM_A" "$VM_B"; do
    if gcloud compute instances describe "$vm" --zone "$ZONE" >/dev/null 2>&1; then
      echo "$vm exists already; refusing to reuse it" >&2
      exit 2
    fi
  done
fi
create_guest() { # VM CONFIG_IMAGE IP
  mutate gcloud beta compute instances create "$1" --zone "$ZONE" \
    --machine-type c3-standard-4 \
    --confidential-compute-type TDX --maintenance-policy TERMINATE \
    --image "$BOOT_IMAGE" \
    --boot-disk-size 20GB --boot-disk-type pd-balanced --boot-disk-auto-delete \
    --create-disk "name=$1-config,image=$2,size=10GB,type=pd-balanced,device-name=attested-config,auto-delete=yes" \
    --create-disk "name=$1-workload,image=$WORKLOAD_IMAGE,size=10GB,type=pd-balanced,device-name=attested-workload,auto-delete=yes" \
    --private-network-ip "$3" \
    --labels "$LABEL" \
    --format 'value(name,zone,machineType,status,networkInterfaces[0].networkIP)'
}
CREATED_A="$(date -u +%Y-%m-%dT%H:%MZ)"; CREATED_B="$CREATED_A"
echo "creating $VM_A and $VM_B at $CREATED_A (three disks each; both auto-delete with the instance)"
if [ "$DRY" = 1 ]; then
  create_guest "$VM_A" "$CONFIG_IMAGE_A" "$IP_A"
  create_guest "$VM_B" "$CONFIG_IMAGE_B" "$IP_B"
  CREATED_A=""; CREATED_B=""
else
  create_guest "$VM_A" "$CONFIG_IMAGE_A" "$IP_A" > "$OUT/create-a.txt" 2>&1 & CPID_A=$!
  create_guest "$VM_B" "$CONFIG_IMAGE_B" "$IP_B" > "$OUT/create-b.txt" 2>&1 & CPID_B=$!
  CRC_A=0; CRC_B=0
  wait "$CPID_A" || CRC_A=$?
  wait "$CPID_B" || CRC_B=$?
  sed 's/^/    a| /' "$OUT/create-a.txt"
  sed 's/^/    b| /' "$OUT/create-b.txt"
  [ "$CRC_A" = 0 ] && [ "$CRC_B" = 0 ] || { echo "an instance create failed" >&2; exit 2; }
fi
echo

# ---- 6. the consoles, both at once, by byte offset -------------------------
# Incrementally, and never re-fetched whole while the guest is running: Compute
# Engine returns an empty body for an instance that has stopped, so a loop that
# re-fetched would erase the transcript at the moment the guest finished writing
# it. --start takes a byte offset and gcloud prints the next one on its own
# stderr. This is run-tdx-scenario.sh's loop, and it is reused rather than
# rewritten for the reason SCENARIOS.md gives.
CONSOLE_A="$OUT/console-a.txt"
CONSOLE_B="$OUT/console-b.txt"
watch_console() { # VM OUTFILE
  local vm="$1" out="$2" start=0 next state now started tries
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
  # The tail is the part that goes missing and it is the part worth having: the
  # guest's last lines are the liveness refusals and the two EXIT statuses, and
  # `poweroff -f` follows them by milliseconds.
  for tries in $(seq 1 30); do
    grep -q '^initrd: EXIT status=' "$out" 2>/dev/null && break
    sleep 3
    fetch
  done
  # One whole-buffer read as the last resort, kept only if it is strictly longer
  # than what the incremental capture built. A refetch cannot be the loop, but as
  # a recovery that can only add, after the loop is done, it is safe.
  gcloud compute instances get-serial-port-output "$vm" --zone "$ZONE" --port 1 --start=0 \
    > "$out.full" 2>/dev/null || true
  local whole incremental
  whole=$(stat -c %s "$out.full" 2>/dev/null || echo 0)
  incremental=$(stat -c %s "$out")
  if [ "$whole" -gt "$incremental" ]; then
    mv "$out.full" "$out"
    echo "$(cat "$out.state"); the whole-buffer read returned $whole bytes against $incremental and replaced the capture" > "$out.state"
  fi
  rm -f "$out.full"
  return 0
}
echo "############ 6. watching both serial consoles ############"
if [ "$DRY" = 1 ]; then
  dry_note "would watch both consoles incrementally for up to ${DEADLINE}s and stop at '^initrd: EXIT status='"
  echo
  echo "dry run complete: nothing was built, published, created or deleted."
  exit 0
fi
watch_console "$VM_A" "$CONSOLE_A" & WPID_A=$!
watch_console "$VM_B" "$CONSOLE_B" & WPID_B=$!
wait "$WPID_A" || true
wait "$WPID_B" || true
echo "guest A: $(cat "$CONSOLE_A.state" 2>/dev/null)"
echo "guest B: $(cat "$CONSOLE_B.state" 2>/dev/null)"
echo "console A: $(wc -l < "$CONSOLE_A") lines; console B: $(wc -l < "$CONSOLE_B") lines"
rm -f "$CONSOLE_A.state" "$CONSOLE_B.state"

for which in a b; do
  case $which in a) c="$CONSOLE_A";; b) c="$CONSOLE_B";; esac
  echo
  echo "---- guest $which, the lines that matter ----"
  grep -E '^initrd: (loaded|config device|workload device|link|loopback|the config device|the sandbox socket|busybox httpd|httpd (says|large)|narrow-after|kill-after|running|sentry:|uptime|EXIT|FATAL|WARNING|no writable|powering)|^tunneld: (EGRESS PROBE|SELFCHECK VERDICT|SELFCHECK rtmr|SELFCHECK mrtd|policy digest|push policy|SANDBOX|listening|PEER |REFUSED|EXIT|refusing)|^EXIT |^workload: ' \
    "$c" | sed "s/^/    $which| /" || true
done

# ---- 7. the quotes, judged here rather than there --------------------------
echo
echo "############ 7. each guest's quote, judged on this workstation ############"
sed -n 's/^signed by author key: *\([0-9a-f]\{64\}\).*/\1/p' "$IMAGE_DIR/manifest.txt" > "$OUT/author.pub"
cp "$W/a/reference-values.json" "$OUT/set-a.json"; cp "$W/a/reference-values.json.sig" "$OUT/set-a.json.sig"
cp "$W/b/reference-values.json" "$OUT/set-b.json"; cp "$W/b/reference-values.json.sig" "$OUT/set-b.json.sig"
cp "$W/a/policy.json" "$OUT/policy-a.json"; cp "$W/a/policy.json.sig" "$OUT/policy-a.json.sig"
cp "$W/b/policy.json" "$OUT/policy-b.json"; cp "$W/b/policy.json.sig" "$OUT/policy-b.json.sig"
extract_quote() { # CONSOLE a|b
  awk '/SELFCHECK EVIDENCE BEGIN/{f=1;next} /SELFCHECK EVIDENCE END/{f=0} f' "$1" \
    | sed -n 's/^tunneld: SELFCHECK EVIDENCE //p' | tr -d ' \r\n' | base64 -d > "$OUT/quote-$2.bin" 2>/dev/null || true
  local keyhex
  keyhex=$(sed -n 's/^tunneld: SELFCHECK PUBLIC KEY //p' "$1" | tail -1 | tr -d ' \r')
  [ -n "$keyhex" ] && printf '%s' "$keyhex" | xxd -r -p > "$OUT/public-key-$2.der"
  [ -s "$OUT/quote-$2.bin" ] && python3 "$HERE/parse-tdx-quote.py" "$OUT/quote-$2.bin" > "$OUT/quote-$2.txt" 2>&1 || true
}
extract_quote "$CONSOLE_A" a
extract_quote "$CONSOLE_B" b
verify_one() { # a|b REFVALS POLICYDIGEST LABEL OUTFILE
  local which="$1" refvals="$2" digest="$3" label="$4" outfile="$5"
  { echo "=== $label ==="; echo "evidence : $OUT/quote-$which.bin"; echo "refvals  : $refvals"; echo "policy   : $digest"; echo; } >> "$outfile"
  if [ ! -s "$OUT/quote-$which.bin" ] || [ ! -s "$OUT/public-key-$which.der" ]; then
    echo "no quote on this guest's console; nothing to verify" >> "$outfile"; return 1
  fi
  "$TOOLS/attest-tool" verify -vendor intel-tdx \
      -evidence "$OUT/quote-$which.bin" -key "$OUT/public-key-$which.der" \
      -refvals "$refvals" -author "$OUT/author.pub" -policy-digest "$digest" \
      -tdx-collateral-dir "$COLLATERAL" >> "$outfile" 2>&1
  local rc=$?
  { echo; echo "verify-evidence exit status: $rc  (0 accepted, 2 refused)"; echo; } >> "$outfile"
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

{
  echo "# ticket $TICKET, $SCENARIO: the registers each boot reported."
  echo "#"
  echo "# RTMR2 is the only one that had to be PREDICTED; MRTD, RTMR0 and RTMR1 are the"
  echo "# provider's constants for this shape and are pinned from observation. This is the"
  echo "# first run of this project on a THREE-disk shape whose RTMR0 the set names."
  echo
  echo "predicted rtmr2 (both guests): $RTMR2"
  for which in a b; do
    echo "guest $which"
    echo "  quoted rtmr2 : $(sed -n 's/^rtmr2 *: //p' "$OUT/quote-$which.txt" 2>/dev/null)"
    echo "  quoted mrtd  : $(sed -n 's/^mrtd *: //p'  "$OUT/quote-$which.txt" 2>/dev/null)"
    echo "  quoted rtmr0 : $(sed -n 's/^rtmr0 *: //p' "$OUT/quote-$which.txt" 2>/dev/null)"
    echo "  quoted rtmr1 : $(sed -n 's/^rtmr1 *: //p' "$OUT/quote-$which.txt" 2>/dev/null)"
  done
} > "$OUT/measurements.txt"
sed 's/^/    /' "$OUT/measurements.txt"

# ---- 8. what the run showed -------------------------------------------------
echo
echo "############ 8. what the run showed ############"
A="$CONSOLE_A"; B="$CONSOLE_B"

for which in a b; do
  case $which in a) c="$A"; g=a; ip="$IP_A";; b) c="$B"; g=b; ip="$IP_B";; esac
  check "guest $g: the initrd ran and loaded the TDX guest driver" in_file "$c" "initrd: loaded tdx-guest"
  check "guest $g: the config device was found and mounted read-only" in_file "$c" "initrd: config device mounted at /config (ro,noexec,nosuid,nodev)"
  check "guest $g: the workload device was found and mounted read-only and exec-permitted" in_file "$c" "mounted at /workload (ro,exec,nosuid,nodev; not measured)"
  check "guest $g: the address on the config device came up with the VPC's gateway route" in_file "$c" "initrd: link eth0 up: $ip/32 mtu $MTU, gateway $GATEWAY"
  check "guest $g: every attempt at the egress the ceiling forbids was refused before it left" in_file "$c" "tunneld: EGRESS PROBE PASSED: every attempt was refused before it left"
  check "guest $g: the config device's tunnel table put this guest on the adapter path" in_file "$c" "initrd: the config device carries a tunnel table"
  check "guest $g: runsc was launched with the adapter's two flags" in_file "$c" "--tunnel-socket=/run/tunneld/sandbox.sock --tunnel-table=/config/tunnel-table.json"
  check "guest $g: the sandbox socket came up for the adapter's helper to dial" in_file "$c" "initrd: the sandbox socket is up at /run/tunneld/sandbox.sock"
  check "guest $g: the exit attached and is holding the list its config device carries" in_file "$c" "EXIT serving, allow="
  check "guest $g: busybox httpd is serving the page on its own loopback" in_file "$c" "initrd: busybox httpd is serving"
  check "guest $g: and the long body beside it is the size both ends agree on" in_file "$c" "initrd: httpd large: /run/httpd/large is $LONG_BYTES bytes"
  check "guest $g: the page is really being served, fetched by init before any sandbox existed" in_file "$c" "initrd: httpd says: served-by: guest-$g"
  check "guest $g: it acquired its own evidence from this platform" in_file "$c" "tunneld: SELFCHECK acquired"
  check "guest $g: it is listening" in_file "$c" "tunneld: listening on $ip:$PORT"
  check "guest $g: it said what it was about to push, out of the file on its own config device" \
        in_file "$c" "tunneld: push policy /config/push-policy.json: format=policy version=1"
  check "guest $g: nothing was refused for being below the TCB floor" not_in_file "$c" "platform below the TCB floor"
  check "guest $g: the boot reached the end rather than being stopped" in_file "$c" "initrd: EXIT status="
done

# 0. the register this ticket authored, and the two verdicts it decides
check "guest A's quote reports the three-disk RTMR0 this ticket authored" \
      grep -qF "$RTMR0_THREE_DISK" "$OUT/quote-a.txt"
check "guest B's quote reports it too, so the shape is the shape the set names" \
      grep -qF "$RTMR0_THREE_DISK" "$OUT/quote-b.txt"
check "guest A's quote is admitted by the set guest B holds" test "$VA_PEER" = 0
check "guest B's quote is admitted by the set guest A holds" test "$VB_PEER" = 0
check "guest A's self-check is refused on the policy digest, because its set names B's digest and not its own" \
      in_file "$A" "SELFCHECK VERDICT REFUSED reason=guest policy or policy digest not permitted"
check "guest B's self-check is refused the same way, for the same reason" \
      in_file "$B" "SELFCHECK VERDICT REFUSED reason=guest policy or policy digest not permitted"

# 1. the policy is in force
applied_digests() { sed -n 's/.*tunneld: SANDBOX applied .*sha256=\([0-9a-f]\{64\}\).*/\1/p' "$1"; }
nth_applied()     { applied_digests "$1" | sed -n "$2p"; }
applied_count()   { applied_digests "$1" | wc -l | tr -d ' '; }
check "guest A's sandbox was given the policy guest B pushed, and the digest is that document's" test "$(nth_applied "$A" 1)" = "$P0B"
check "guest B's sandbox was given the policy guest A pushed, and the digest is that document's" test "$(nth_applied "$B" 1)" = "$P0A"
check "guest A's sandbox was served guest B's page, through guest B's exit, under that policy" in_file "$A" "served-by: guest-b"
check "guest B's sandbox was served guest A's page, through guest A's exit, under that policy" in_file "$B" "served-by: guest-a"
check "guest A's exit served a stream a peer opened and dialed the one destination its list permits" \
      bash -c "grep -qF 'EXIT dialed web.peer-a:80' '$A' || grep -qF 'EXIT web.peer-a:80 ended' '$A'"
check "guest B's exit served a stream a peer opened and dialed the one destination its list permits" \
      bash -c "grep -qF 'EXIT dialed web.peer-b:80' '$B' || grep -qF 'EXIT web.peer-b:80 ended' '$B'"
check "guest A: the fetching process was inside a gVisor sandbox" in_file "$A" "4.19.0-gvisor"
check "guest B: the fetching process was inside a gVisor sandbox" in_file "$B" "4.19.0-gvisor"
check "guest A: the name that is in nobody's policy did not resolve inside the sandbox" in_file "$A" "bad address 'not-in-the-table.example'"
check "guest B: the name that is in nobody's policy did not resolve inside the sandbox" in_file "$B" "bad address 'not-in-the-table.example'"
check "guest A: an exec outside the policy's x was refused inside the sandbox" in_file "$A" "workload: EXEC REFUSED /bin/probe"
check "guest B: an exec outside the policy's x was refused inside the sandbox" in_file "$B" "workload: EXEC REFUSED /bin/probe"
check "guest A: and it was allowed before the policy landed, so the control is a transition and not a constant" \
      in_file "$A" "no policy carrying an x is in force in this sandbox yet"

# 2. the policy can be replaced, with the workload running
check "guest A's sandbox was given a second policy without being restarted" test "$(applied_count "$A")" -ge 2
check "and the second one is the narrower document guest B pushed, by digest" test "$(nth_applied "$A" 2)" = "$P1B"
check "guest B started a second tunneld to push it, rather than restarting the first" \
      in_file "$B" "initrd: narrow-after: ${NARROW_B}s elapsed; starting a second tunneld"
check "guest B's own sandbox was never narrowed: one policy, one digest" test "$(applied_count "$B")" = "1"
check "guest A's sandbox stopped resolving the name the narrower policy dropped" in_file "$A" "workload: NARROWED web.peer-b stopped resolving"
check "and the stream that was already open when that happened arrived whole" in_file "$A" "workload: LONG COMPLETE bytes=$LONG_BYTES"
check "guest B took the same body in one read from the other side, so the bytes are not the finding" in_file "$B" "workload: LONG-B bytes=$LONG_BYTES"

# 3. the policy is watched
check "guest A's tunneld noticed its sandbox pulsing a digest it was not watching for" \
      grep -qF -- "tunneld: SANDBOX liveness lost: it pulsed" "$A"
check "and refused, naming liveness rather than inferring it from a tunnel that went quiet" \
      grep -qF -- "$LIVENESS_REASON" "$A"

# 4. the workload's exit ends liveness
check "guest A: init killed the sandbox after the seconds its config device asked for" in_file "$A" "initrd: kill-after: ${KILL_A}s elapsed"
check "guest B: and the same on the other guest, later"                                in_file "$B" "initrd: kill-after: ${KILL_B}s elapsed"
check "guest A: the sandbox's socket closing is what its tunneld saw, immediately and not after three misses" \
      grep -qF -- "tunneld: SANDBOX liveness lost: the sandbox closed its socket" "$A"
check "guest B: the same on the other guest" \
      grep -qF -- "tunneld: SANDBOX liveness lost: the sandbox closed its socket" "$B"
check "guest B's tunneld refused the tunnel it had applied a policy on, naming liveness" \
      grep -qF -- "$LIVENESS_REASON" "$B"
check "guest A: the workload was killed rather than running out of work" not_in_file "$A" "nothing killed this workload"
check "guest B: the same"                                                not_in_file "$B" "nothing killed this workload"

# Not an assertion: what the sentry resolved a symlinked exec to. It decides what
# an `x` written by path can mean, and nothing in this run depends on it.
echo
echo "    what the sentry did with an exec through a symlink, from both guests:"
grep -h "workload: OBSERVE exec" "$A" "$B" 2>/dev/null | sed 's/^/      /' || echo "      (no OBSERVE lines on either console)"

# The egress capture, for the record's egress/ directory.
for which in a b; do
  case $which in a) c="$A";; b) c="$B";; esac
  {
    echo "### ticket $TICKET $SCENARIO, guest $which: the rule set as the kernel holds it, and every attempt refused"
    echo
    awk '/EGRESS CEILING/{f=1} f{print} /^}/{if(f)f=0}' "$c"
    echo
    grep -E '^tunneld: (EGRESS PROBE|EGRESS REFUSED|EGRESS PERMITTED|EGRESS UNROUTED|EGRESS TIMEOUT)' "$c" || true
    echo
  } > "$OUT/egress-$which.txt"
done
echo
echo "the egress capture is in $OUT/egress-a.txt and $OUT/egress-b.txt"

# Keep the config sources as delivered, minus the collateral: it is byte for byte
# docs/snp/evidence/tdx/collateral and each console lists every file of it with
# its sha256, so a third copy per guest would be three copies of a thing already
# recorded twice.
rm -rf "$W/a/collateral" "$W/b/collateral" "$W/devices/a/collateral" "$W/devices/b/collateral" "$W/probe-a" "$W/probe-b"
rm -f "$OUT/create-a.txt" "$OUT/create-b.txt"
