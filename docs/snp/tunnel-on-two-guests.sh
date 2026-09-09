#!/bin/bash
# Two attested guests, live: ticket 14's harness, and ticket 18's policy scenarios.
#
#   tunnel-on-two-guests.sh [-image DIR] [-out DIR] [-scenario NAME]...
#                           [-no-snp] [-run-for SECONDS] [-quick]
#                           [-capture DIR] [-spool DIR]
#
# Every property in the memo's verification list that a unit test cannot reach
# is here, and each one is a scenario: a pair of guests booted from the measured
# image with a config device apiece, on one ethernet segment with an attacker in
# the middle of it and nothing else on it.
#
#   live      both guests attested, an exchange in both directions, and the
#             latency table. Also the control (spec, user story 49): it is run
#             before and after the refusals, on the same wiring, because a
#             refusal that would also happen with the tunnel broken is not
#             evidence of anything.
#   modified  guest B booted from an image with one byte changed (ticket 08's
#             mutate-image.sh). It boots, attests, and is refused by A, which
#             names the measurement internally and tells B nothing.
#   tcbfloor  guest A holding a set whose TCB floor is above what this platform
#             reports. A refuses B for being below the floor.
#   nosnp     guest B booted without SEV-SNP. It has no evidence to present,
#             fails closed before it listens, and A gets no peer.
#   tamper    the same pair, with the relay changing a bit in every twentieth
#             datagram it carries. The active half of the attacker.
#   stalechain guest B holding a chain provisioned for a TCB this platform is
#             not at. It fails closed before it presents anything.
#   policy-pinned  (ticket 18) guest A holding a set that names guest B's
#             policy digest and no other. B presents that digest, A admits it,
#             and the exchange completes. The positive control for the two
#             below it, and the strongest admitted shape this design has.
#   policy-mismatch (ticket 18) the same pair, with guest B's set naming a
#             policy digest nobody presents. A admits B and B refuses A as a
#             policy mismatch, whichever side dials, so no tunnel completes in
#             either direction.
#
# The topology is the evidence for two of the criteria on its own, so it is
# worth stating plainly. The guests' only network is
# docs/snp/l2relay.py: guest A's QEMU and guest B's QEMU each hold one TCP
# connection to it, and it copies ethernet frames between them. There is no
# gateway on that segment, no resolver, and no route off it, so no guest can
# reach AMD's key distribution service or anything else during the run — egress
# is absent rather than filtered. And because every frame between the two
# guests passes through it, it is also the on-path attacker: it records every
# datagram to a pcap file and searches each one for the plaintext an exchange
# carries. The legitimate exchange and the relay's failure to read it are the
# same run.
#
# Prerequisites, none of which this script installs, and each of which fails
# somewhere further in than where it was missing:
#
#   squashfs-tools   mksquashfs, for the root filesystem (build-image.sh)
#   cryptsetup-bin   veritysetup, for the hash tree over it
#   e2fsprogs        mke2fs -d, for the config devices (mkconfigdev.sh)
#   the cpuid module the launch path reads C-bit position from /dev/cpu/0/cpuid
#   go               /usr/local/go/bin, added to PATH here (attest/README.md)
#
# and two artifacts that are not tools:
#
#   docs/snp/evidence/ticket05/certificate-chain-stale.{bin,json} — the real
#   chain AMD issued for this chip one TCB level down, which the stalechain
#   scenario needs and which cannot be manufactured (docs/verification-on-hardware.md)
#   $STACK/image-ticket14-packaging/author.key — the key that signed the image's
#   reference value set. The tcbfloor and policy scenarios re-sign a set with
#   it, and a different key would need a different image, since the public half
#   is inside the measurement. package-tunneld.sh leaves it there when it
#   generated one; an image built by reusing an older key has it wherever that
#   key is kept, and AUTHOR_KEY names it. Either way this script checks the
#   public half against the image before signing anything with it.
#
# Privilege. Launching an SNP guest opens /dev/sev, which is root-only on this
# host, and sudo needs a password. Every privileged step is therefore written
# as a .job file into ticket 01's spool, where docs/snp/root-runner.sh — started
# by the operator, in a tmux session, once — picks it up and writes <name>.out
# and <name>.rc beside it. Nothing runs that was not placed there as a file
# somebody could read first. -no-snp runs the same scenarios as control boots,
# needs only /dev/kvm, and is what this script can exercise on its own.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
export PATH="/usr/local/go/bin:$PATH"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
IMAGE="${IMAGE:-$STACK/image-ticket14}"
# OUT is settled after the arguments are read, because it is named after the
# image: a second image (ticket 18 builds one) run into the first one's
# directory would overwrite a record of a different measurement.
OUT="${OUT:-}"
CHAIN="${CHAIN:-$REPO/docs/snp/evidence}"
STALE="${STALE:-$REPO/docs/snp/evidence/ticket05}"
SNP=1; CAPTURE=""; RUN_FOR=1000; SCENARIOS=(); SPOOL=""
RELAY_A_PORT="${RELAY_A_PORT:-15801}"; RELAY_B_PORT="${RELAY_B_PORT:-15802}"
MARKER="attested-tunnel-plaintext-marker"
TAMPER=0
while [ -n "${1:-}" ]; do
  case "$1" in
    -image)    IMAGE="$2"; shift 2 ;;
    -out)      OUT="$2"; shift 2 ;;
    -scenario) SCENARIOS+=("$2"); shift 2 ;;
    -spool)    SPOOL="$2"; shift 2 ;;
    -run-for)  RUN_FOR="$2"; shift 2 ;;
    -quick)    RUN_FOR=150; shift ;;
    -no-snp)   SNP=0; shift ;;
    -capture)  CAPTURE="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ ${#SCENARIOS[@]} -gt 0 ] || SCENARIOS=(live modified tcbfloor nosnp tamper stalechain live-again)
[ -n "$OUT" ] || OUT="$STACK/$(basename "$IMAGE")-run"

mkdir -p "$OUT"
TRANSCRIPT="$OUT/tunnel-run.txt"
exec > >(tee "$TRANSCRIPT") 2>&1
PASSES=0; FAILURES=0

# The relay outlives this script if this script dies, and then it is still
# holding its two ports: the next run fails to bind and the failure looks like
# a guest that would not start. It is killed by name here rather than left to
# the operating system, and only by the pid this run started — never with a
# bare `wait`, which would also wait for the `tee` in the process substitution
# above and hang forever.
#
# What this cannot undo is a job already in the spool. The runner is root and
# takes what it is given; a job handed over before an interrupt still runs and
# still boots its guests, which is a property of the spool being reviewable
# rather than revocable.
RELAY_PID=""
cleanup() {
  local rc=$?
  if [ -n "$RELAY_PID" ] && kill -0 "$RELAY_PID" 2>/dev/null; then
    echo "cleanup: stopping the relay (pid $RELAY_PID)"
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
  fi
  RELAY_PID=""
  return $rc
}
trap cleanup EXIT
trap 'echo "interrupted"; cleanup; exit 130' INT TERM
note()  { echo "$*"; }
pass()  { PASSES=$((PASSES+1)); echo "PASS  $*"; }
fail()  { FAILURES=$((FAILURES+1)); echo "FAIL  $*"; }
# check DESCRIPTION -- shell-condition...
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
in_file() { grep -qF -- "$2" "$1"; }
not_in_file() { ! grep -qF -- "$2" "$1"; }

echo "=== two attested guests, from $(basename "$IMAGE") ==="
echo "date        : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "repo        : $(git -C "$REPO" rev-parse HEAD) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
echo "image       : $IMAGE"
echo "mode        : $([ "$SNP" = 1 ] && echo 'SEV-SNP (privileged, through the spool)' || echo 'control boot, no SNP (unprivileged)')"
echo "scenarios   : ${SCENARIOS[*]}"
echo

for f in OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img reference-values.json reference-values.json.sig manifest.txt; do
  [ -f "$IMAGE/$f" ] || { echo "missing $IMAGE/$f — run docs/snp/image/package-tunneld.sh first" >&2; exit 1; }
done
MEASUREMENT=$(sed -n 's/^launch_measurement: //p' "$IMAGE/manifest.txt")
echo "predicted launch measurement of the image both guests boot:"
echo "  $MEASUREMENT"
echo "the reference value set on both config devices names exactly that, signed by the"
echo "author key baked into the image at /etc/attested-tunnel/author.pub (ADR-0004)."
echo

# ---- the spool ------------------------------------------------------------
# Two candidates, because root-runner.sh takes its spool from its own directory
# and there are two copies of it. Whichever exists is the one the operator is
# watching; if neither does, nothing privileged can run and this says so rather
# than hanging.
# root-runner.sh takes its spool from its own directory, and the operator runs
# the copy in the primary checkout — not in this worktree. A relative path here
# would write into a directory nothing is watching, and the job would sit there
# looking exactly like a hang, so the main checkout is found rather than
# assumed: `git worktree list` names it first.
find_spool() {
  [ -n "$SPOOL" ] && { echo "$SPOOL"; return 0; }
  local main
  main=$(git -C "$REPO" worktree list | head -1 | awk '{print $1}')
  for d in "$main/docs/snp/root-spool" "$REPO/docs/snp/root-spool" "$STACK/root-spool"; do
    [ -d "$d" ] && { echo "$d"; return 0; }
  done
  return 1
}
if [ "$SNP" = 1 ]; then
  if ! SPOOL=$(find_spool); then
    cat >&2 <<MSG
No spool directory. An SNP guest opens /dev/sev, which is root:root 0600 here, and
sudo needs a password, so nothing privileged can be launched from this session.
The operator starts the runner once, in a tmux session:

    sudo bash $REPO/docs/snp/root-runner.sh

It creates docs/snp/root-spool/, watches it, runs each *.job with bash and writes
<name>.out and <name>.rc beside it. Then run this script again. Everything that
does not need root — packaging, config devices, the relay, the control boots —
runs without it: $0 -no-snp
MSG
    exit 3
  fi
  echo "spool       : $SPOOL"
fi

# spool_run NAME SCRIPT TIMEOUT — hand a job to the runner and wait for it.
spool_run() {
  local name="$1" script="$2" limit="$3"
  local job="$SPOOL/tunnel-$$-$name"
  cp "$script" "$job.staging"
  # The runner globs *.job every second and would otherwise pick up a file that
  # is still being written.
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
  local rc; rc=$(cat "$job.rc")
  note "$name finished, rc=$rc"
  sed 's/^/    | /' "$job.out"
  return 0
}

# ---- config devices -------------------------------------------------------
# One per guest, built by ticket 06's mkconfigdev.sh from a directory laid out
# exactly as it appears under /config. Nothing on it is measured, which is why
# two guests booted from one image can differ at all.
#
#   make_config DIR SANDBOX ADDRESS PEER_NAME PEER_ADDRESS RUN_JSON [-stale] [-refvals DIR]
make_config() {
  local dir="$1" sandbox="$2" address="$3" peer="$4" peeraddr="$5" runjson="$6"; shift 6
  local refvals="$IMAGE" chainsrc="$CHAIN" chainbin="certificate-chain.bin" chainjson="certificate-chain.json"
  while [ -n "${1:-}" ]; do
    case "$1" in
      -stale)   chainsrc="$STALE"; chainbin="certificate-chain-stale.bin"; chainjson="certificate-chain-stale.json"; shift ;;
      -refvals) refvals="$2"; shift 2 ;;
      *) echo "make_config: unknown option $1" >&2; exit 2 ;;
    esac
  done
  rm -rf "$dir"; mkdir -p "$dir"
  cp "$refvals/reference-values.json" "$refvals/reference-values.json.sig" "$dir/"
  cp "$chainsrc/$chainbin"  "$dir/certificate-chain.bin"
  cp "$chainsrc/$chainjson" "$dir/certificate-chain.json"
  printf '{"peers": {"%s": "%s"}}\n' "$peer" "$peeraddr" > "$dir/peers.json"
  printf '%s\n' "$runjson" > "$dir/tunneld.json"
  bash "$HERE/image/mkconfigdev.sh" "$dir" "$dir.img" | sed 's/^/    /'
}

# The two run configurations. Both guests are configured alike on the limits,
# deliberately: QUIC's idle timeout is the minimum of what the two peers
# advertise, so two guests that differ there leave one of them running on a
# number that appears nowhere in its own configuration.
answerer_json() { # SANDBOX ADDRESS HOLD
  cat <<JSON
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "$1",
  "listen": "$2:4433",
  "link": {"interface": "eth0", "address": "$2", "prefix_length": 24},
  "limits": {"idle_timeout": "60s", "max_age": "15m"},
  "hold": "$3"
}
JSON
}
dialer_json() { # SANDBOX ADDRESS PEER RUN_FOR WAIT
  cat <<JSON
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "$1",
  "listen": "$2:4433",
  "link": {"interface": "eth0", "address": "$2", "prefix_length": 24},
  "limits": {"idle_timeout": "60s", "max_age": "15m"},
  "exercise": {
    "dial": ["$3"],
    "wait": "$5",
    "payload": "$MARKER",
    "exchanges": 20,
    "concurrency": 8,
    "rounds": 3,
    "repeat_every": "30s",
    "run_for": "$4"
  },
  "hold": "5s"
}
JSON
}

# ---- one scenario ---------------------------------------------------------
# boot_pair WORKDIR IMAGE_A IMAGE_B SECONDS [-no-snp-b]
# Guests are launched from one job so that the runner, which runs jobs one at a
# time, does not serialise the two halves of a conversation.
boot_pair() {
  local work="$1" image_a="$2" image_b="$3" seconds="$4" snp_b="$5"
  local relay_log="$work/relay.txt" pcap="$work/segment.pcap"
  python3 "$HERE/l2relay.py" \
      --listen "127.0.0.1:$RELAY_A_PORT" --listen "127.0.0.1:$RELAY_B_PORT" \
      --pcap "$pcap" --marker "$MARKER" --summary "$relay_log" --tamper "$TAMPER" \
      --seconds "$((seconds + 30))" --attach-timeout 120 > "$work/relay.log" 2>&1 &
  local relay=$!
  RELAY_PID=$relay
  sleep 1

  local guest_b_flags=""
  [ "$snp_b" = 0 ] && guest_b_flags="-no-snp"
  local common_flags=""
  [ "$SNP" = 0 ] && common_flags="-no-snp"
  cat > "$work/boot.job" <<JOB
# Launch the two guests of $(basename "$work").
#
# Privileged only because an SNP launch opens /dev/sev. Both guests are started
# from this one job and waited for together: they are two halves of one
# conversation, and a runner that ran them one after another would have each
# talking to nobody.
set -u
# The launcher takes QEMU and the non-verifying firmware from the host stack,
# and the stack is not inside this checkout when the harness runs from a
# worktree. The runner starts every job in an environment of its own, so the
# stack is named here rather than left to tunnel-guest.sh's default, which
# would look for it beside whichever tree this script was read from.
export STACK="$STACK"
A_LOG="$work/console-a.txt"
B_LOG="$work/console-b.txt"
timeout $seconds bash "$HERE/tunnel-guest.sh" -image "$image_a" -config "$work/config-a.img" \\
    -relay 127.0.0.1:$RELAY_A_PORT -console "\$A_LOG" -mac 52:54:00:14:00:0a $common_flags &
A=\$!
timeout $seconds bash "$HERE/tunnel-guest.sh" -image "$image_b" -config "$work/config-b.img" \\
    -relay 127.0.0.1:$RELAY_B_PORT -console "\$B_LOG" -mac 52:54:00:14:00:0b $common_flags $guest_b_flags &
B=\$!
wait \$A; echo "guest A qemu exited \$?"
wait \$B; echo "guest B qemu exited \$?"
chown -R $(id -u):$(id -g) "$work" 2>/dev/null
chmod -R a+rX "$work" 2>/dev/null
JOB
  if [ "$SNP" = 1 ]; then
    spool_run "$(basename "$work")" "$work/boot.job" "$((seconds + 240))" || true
  else
    note "running the same job without SNP, unprivileged"
    bash "$work/boot.job" 2>&1 | sed 's/^/    | /'
  fi
  wait "$relay" 2>/dev/null || true
  RELAY_PID=""
  note "relay:"; sed 's/^/    | /' "$relay_log" 2>/dev/null || true
}

# ---- assertions shared by every scenario ----------------------------------
assert_booted() { # CONSOLE SANDBOX
  local console="$1" sandbox="$2"
  check "$sandbox: booted the measured image and ran the packaged tunneld" \
        in_file "$console" "init: running /usr/bin/tunneld"
  check "$sandbox: no writable path in the image is executable" \
        in_file "$console" "init: no writable path is executable"
  check "$sandbox: read the author key from inside the launch measurement" \
        in_file "$console" "/etc/attested-tunnel/author.pub, inside the launch measurement"
  check "$sandbox: read the reference value set and chain from the config device" \
        in_file "$console" "/config (ro,noexec,nosuid,nodev)"
}
assert_attested() { # CONSOLE SANDBOX
  local console="$1" sandbox="$2"
  check "$sandbox: acquired its own evidence from the platform" \
        in_file "$console" 'provider "sev_guest" (amd-sev-snp) returned 1184 bytes'
  check "$sandbox: bundled the chain provisioned on its config device, not the platform's" \
        in_file "$console" "its own certificate table is empty (auxblob, 0 bytes)"
  check "$sandbox: is listening" in_file "$console" "tunneld: listening on"
}

# peer_field CONSOLE FIELD — what a guest wrote down about the peer it admitted.
peer_field() { sed -n "s/.*PEER SEEN .*$2=\([0-9a-f]*\).*/\1/p" "$1" | head -1; }
accepted_count() { sed -n 's/.*PEERS verifier_calls=[0-9]* accepted=\([0-9]*\).*/\1/p' "$1" | tail -1; }

# ---- sets this script authors itself (ticket 18) --------------------------
# Two of the scenarios below need reference value sets that differ from the
# image's own in one field, and only in that field: the same measurement, the
# same author, the same TCB floor and the same launch policy, with a
# policy_digest naming a peer's policy or naming none. The floor and the policy
# are read out of the record the build wrote beside its own set rather than
# repeated here, because a second copy of them here is a second thing to keep
# in step with build-image.sh, and a set that differed in two fields would make
# every verdict below ambiguous.
AUTHOR_KEY_PATH="${AUTHOR_KEY:-$IMAGE-packaging/author.key}"
EMIT="$OUT/emit-refvals"
build_emit_refvals() { [ -x "$EMIT" ] || (cd "$HERE/image/emit-refvals" && go build -o "$EMIT" .); }
image_tcb_floor()     { sed -n 's/^tcb floor (authoring choice): \([0-9,]*\).*/\1/p' "$IMAGE/reference-values.inputs.txt"; }
image_launch_policy() { sed -n 's/^launch policy: *//p' "$IMAGE/reference-values.inputs.txt"; }

# author_set DIR [-policy-digest HEX] — emit and sign one set into DIR and
# print its own policy digest, which is the number a peer puts in its
# policy_digest to admit a guest holding this set. It is SHA-256 over the bytes
# the author signed and not over the file, so it comes from the tool that knows
# that; this script never computes it.
author_set() {
  local dir="$1"; shift
  mkdir -p "$dir"
  if ! "$EMIT" -measurement "$MEASUREMENT" -key "$AUTHOR_KEY_PATH" -out "$dir" \
        -tcb "$(image_tcb_floor)" -policy "$(image_launch_policy)" "$@" > "$dir/emit.txt" 2>&1; then
    sed 's/^/    | /' "$dir/emit.txt" >&2
    return 1
  fi
  sed 's/^/    | /' "$dir/emit.txt" >&2
  sed -n 's/^policy digest: //p' "$dir/emit.txt"
}

# digest_of FILE — the same number read back off a document already written,
# without a key and without loading it. This is the operator's half of the
# workflow the ticket describes: a digest read off a document, put in a peer's
# allow-list, and then seen again on that guest's console at start.
digest_of() { "$EMIT" -digest-of "$1" | sed -n 's/^policy digest: //p'; }

# console_policy_digest CONSOLE — the digest a guest printed at start, which is
# the digest of the set it actually loaded off its own config device.
console_policy_digest() { sed -n 's/.*tunneld: policy digest \([0-9a-f]\{64\}\).*/\1/p' "$1" | head -1; }

# unconstrained_lines CONSOLE — how many values the guest reported as admitting
# any policy at all.
unconstrained_lines() { grep -c "is unconstrained: it admits any policy" "$1" 2>/dev/null || true; }

# require_author_key SCENARIO — the key is there, and it is the image's.
#
# Both halves matter and neither is obvious from a failure. package-tunneld.sh
# leaves the key beside the image only when it generated one; an image built
# around a reused key (ticket 18 rebuilds ticket 14's image around a new
# tunneld, and the author key has to stay the same or the measurement moves)
# has it elsewhere, and AUTHOR_KEY says where. And a set signed with the wrong
# key is refused by the loader inside the guest, which arrives as a guest that
# will not start — a failure that says nothing about the key.
require_author_key() {
  local scenario="$1" have want
  if [ ! -f "$AUTHOR_KEY_PATH" ]; then
    fail "$scenario: no author key at $AUTHOR_KEY_PATH; package-tunneld.sh keeps the one it generates, and AUTHOR_KEY names one it was given"
    return 1
  fi
  have=$(openssl pkey -in "$AUTHOR_KEY_PATH" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p | tr -d '\n')
  want=$(sed -n 's/^signed by author key: *\([0-9a-f]*\).*/\1/p' "$IMAGE/reference-values.inputs.txt")
  if [ -z "$have" ] || [ "$have" != "$want" ]; then
    fail "$scenario: $AUTHOR_KEY_PATH signs as ${have:-nothing}, and the image's own set was signed by $want; a set signed with it would be refused by the loader inside the guest"
    return 1
  fi
  pass "$scenario: re-signing with the key whose public half is inside the launch measurement"
  return 0
}

# keep_sets WORK — copy the two authored sets, as signed, next to the consoles
# they explain, so the captured evidence carries the documents and not only
# their digests.
keep_sets() {
  local work="$1" side
  for side in a b; do
    cp "$work/refvals-$side/reference-values.json"     "$work/set-$side.json"     2>/dev/null || true
    cp "$work/refvals-$side/reference-values.json.sig" "$work/set-$side.json.sig" 2>/dev/null || true
  done
}

# ---- scenario: two attested guests, a legitimate exchange, the table -------
scenario_live() {
  local work="$OUT/$1" seconds="$2"
  echo
  echo "### $1: two attested guests, an exchange, and the latency table"
  mkdir -p "$work"
  # The answerer outlives the dialer's whole run: a peer that powers off while
  # the other is still exchanging produces a failure that belongs to this
  # harness rather than to the tunnel.
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(answerer_json guest-a 10.14.0.2 "$((seconds + 90))s")"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a "${seconds}s" 90s)"
  boot_pair "$work" "$IMAGE" "$IMAGE" "$((seconds + 240))" 1

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "$1: one of the guests left no console"; return; }
  assert_booted "$a" "guest-a"; assert_booted "$b" "guest-b"
  if [ "$SNP" = 0 ]; then
    check "control boot: neither guest can attest, and both refuse to start rather than proceed" \
          in_file "$b" "refusing to start"
    return
  fi
  assert_attested "$a" "guest-a"; assert_attested "$b" "guest-b"

  check "guest-a admitted its peer's evidence"    in_file "$a" "tunneld: PEER key="
  check "guest-b admitted its peer's evidence"    in_file "$b" "tunneld: PEER key="
  check "guest-b established a tunnel"            in_file "$b" "kind=establish"
  check "guest-b exchanged over it, warm"         in_file "$b" "kind=warm_exchange"
  check "guest-b ran concurrent exchanges on one tunnel" in_file "$b" "kind=concurrent"
  check "guest-a answered guest-b's exchanges"    in_file "$b" 'answered_by="guest-a"'
  check "guest-b's exercise completed"            in_file "$b" "tunneld: EXIT status=0"
  check "neither guest refused the other"         not_in_file "$a" "tunneld: REFUSED"

  # What the two guests wrote down about each other. The chains are equal
  # because there is one chip under both guests: a chain is per chip and per
  # TCB (ADR-0005), so two guests on one host present the same one, and the
  # only thing that tells them apart is the key.
  local key_a key_b chain_a chain_b m_a m_b
  key_a=$(peer_field "$b" key);   key_b=$(peer_field "$a" key)
  chain_a=$(peer_field "$b" chain); chain_b=$(peer_field "$a" chain)
  m_a=$(peer_field "$b" measurement); m_b=$(peer_field "$a" measurement)
  echo "    guest-a presented key $key_a"
  echo "    guest-b presented key $key_b"
  echo "    both presented chain  $chain_a / $chain_b"
  check "the two guests presented distinct keys"  test -n "$key_a" -a "$key_a" != "$key_b"
  check "the two guests presented the same chain, which is what one chip means" \
        test -n "$chain_a" -a "$chain_a" = "$chain_b"
  check "each guest reported the measurement predicted offline for the image both booted" \
        test "$m_a" = "$MEASUREMENT" -a "$m_b" = "$MEASUREMENT"

  # The relay carried it and could not read it.
  check "the exchange went through the relay"     grep -q "a_to_b_frames=[1-9]" "$work/relay.txt"
  check "the relay found no plaintext on the wire" in_file "$work/relay.txt" "MARKER not found"
  # A guest reaching for anything off its own subnet has to resolve a gateway
  # first, so the addresses the two guests asked about are the whole story
  # about where they tried to go.
  local targets bad
  targets=$(sed -n 's/.*arp targets : //p' "$work/relay.txt" | head -1)
  bad=$(printf '%s' "$targets" | tr ',' '\n' | tr -d ' ' | grep -v '^$' | grep -vE '^10\.14\.0\.(2|3)$' || true)
  echo "    addresses resolved on the segment: ${targets:-none}"
  check "no guest looked for a gateway or anything else off the segment" test -z "$bad"

  # A run longer than the maximum age re-handshakes in the middle of itself.
  # Every pass asks for the peer again. Within the maximum age that costs no
  # handshake and no verification — the cache answers — so the number of passes
  # that cost a verification is the number of times the two guests attested to
  # each other, and it should be one until the tunnel reaches fifteen minutes.
  local passes handshakes
  passes=$(grep -c "kind=establish" "$b" || true)
  handshakes=$(grep -c "kind=establish .*verifier_calls=[1-9]" "$b" || true)
  echo "    passes: $passes, of which cost a verification: $handshakes (maximum age 15m, run ${seconds}s)"
  check "asking for a warm peer again cost no handshake" test "$passes" -gt "$handshakes"
  if [ "$seconds" -gt 900 ]; then
    check "the tunnel was re-attested when it reached its maximum age" test "$handshakes" -ge 2
  fi
}

# ---- scenario: a guest booted from a modified image ------------------------
scenario_modified() {
  local work="$OUT/modified"
  echo
  echo "### modified: guest B boots an image with one byte changed"
  mkdir -p "$work"
  local mutated="$OUT/image-modified"
  if [ ! -f "$mutated/rootfs.img" ]; then
    note "building the mutated image (ticket 08's mutate-image.sh, one byte of rootfs.img)"
    # Not -quiet: the mutated image's own predicted measurement is the number
    # that says the mutation moved M, and a refusal recorded without it is a
    # refusal whose cause the record does not name.
    bash "$HERE/image/mutate-image.sh" -base "$IMAGE" -out "$mutated" -mutation rootfs-byte | sed 's/^/    /'
  fi
  # mutate-image.sh reports the byte it changed and the verity root hash that
  # followed, but not a launch measurement — it does not predict one. Predict
  # it here, because the number that says the mutation moved M is the number
  # this scenario is about, and a refusal recorded without it is a refusal
  # whose cause the record does not name.
  bash "$HERE/image/predict-measurement.sh" "$mutated" -vcpus 4 -vcpu-type EPYC-v4 \
      -out "$work/mutated-measurement.txt" > /dev/null
  local mutated_m
  mutated_m=$(sed -n 's/^launch_measurement: //p' "$work/mutated-measurement.txt")
  echo "    the mutated image's predicted measurement: $mutated_m"
  echo "    the image both sets name:                  $MEASUREMENT"
  check "one byte of the root filesystem moved the launch measurement" \
        test -n "$mutated_m" -a "$mutated_m" != "$MEASUREMENT"
  # The mutated image is not re-authorised: its measurement appears in no
  # reference value set anywhere, which is the whole point. Guest B carries the
  # same set as guest A, so B admits A and only A has anything to refuse.
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(answerer_json guest-a 10.14.0.2 180s)"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a 0s 60s)"
  boot_pair "$work" "$IMAGE" "$mutated" 300 1

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "modified: one of the guests left no console"; return; }
  if [ "$SNP" = 0 ]; then note "control boot: nothing attests, nothing to refuse"; return; fi
  assert_attested "$b" "guest-b (modified image)"
  check "guest-a refused the modified guest, naming the measurement internally" \
        in_file "$a" "REFUSED verification refused: launch measurement not in the reference value set"
  check "guest-a admitted nobody"                 test "$(accepted_count "$a")" = "0"
  check "the modified guest was told nothing but that it did not get a tunnel" \
        in_file "$b" "peer=guest-a FAILED"
  check "the modified guest itself admitted guest-a, so the refusal is one-sided" \
        in_file "$b" "tunneld: PEER key="
  check "the modified guest's exercise failed"    in_file "$b" "tunneld: EXIT status=2"
}

# ---- scenario: a platform below the TCB floor -----------------------------
scenario_tcbfloor() {
  local work="$OUT/tcbfloor"
  echo
  echo "### tcbfloor: guest A holds a set whose floor is above this platform"
  mkdir -p "$work"
  local key="$AUTHOR_KEY_PATH"
  require_author_key tcbfloor || return
  local refvals="$work/refvals-tcbfloor"
  mkdir -p "$refvals"
  # The same measurement and the same author, one field different: a floor no
  # platform on this host meets. Anything else changing at the same time would
  # make the refusal ambiguous.
  (cd "$HERE/image/emit-refvals" && go build -o "$work/emit-refvals" .)
  "$work/emit-refvals" -measurement "$MEASUREMENT" -key "$key" -out "$refvals" \
      -tcb 9,0,23,255 -policy 0x30000 | sed 's/^/    /'
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(answerer_json guest-a 10.14.0.2 180s)" -refvals "$refvals"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a 0s 60s)"
  boot_pair "$work" "$IMAGE" "$IMAGE" 300 1

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "tcbfloor: one of the guests left no console"; return; }
  if [ "$SNP" = 0 ]; then note "control boot: nothing attests, nothing to refuse"; return; fi
  check "guest-a refused a platform below its floor" \
        in_file "$a" "REFUSED verification refused: platform below the TCB floor"
  check "guest-a admitted nobody"                 test "$(accepted_count "$a")" = "0"
  check "guest-b got no tunnel"                   in_file "$b" "peer=guest-a FAILED"
  check "guest-b, whose floor is the ordinary one, admitted guest-a" \
        in_file "$b" "tunneld: PEER key="
}

# ---- scenario: a non-confidential VM --------------------------------------
scenario_nosnp() {
  local work="$OUT/nosnp"
  echo
  echo "### nosnp: guest B is not a confidential VM and has nothing to present"
  mkdir -p "$work"
  # A dials here, because B is the one that will not be there to dial.
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(dialer_json guest-a 10.14.0.2 guest-b 0s 60s)"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(answerer_json guest-b 10.14.0.3 120s)"
  boot_pair "$work" "$IMAGE" "$IMAGE" 300 0

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "nosnp: one of the guests left no console"; return; }
  check "the non-confidential guest booted the same image" in_file "$b" "init: running /usr/bin/tunneld"
  check "its kernel would not load the guest driver"       in_file "$b" "sev-guest did not load"
  check "it refused to start rather than run without evidence" in_file "$b" "refusing to start"
  check "it never listened"                                not_in_file "$b" "tunneld: listening on"
  check "it exited saying so"                              in_file "$b" "tunneld: EXIT status=1"
  if [ "$SNP" = 1 ]; then
    check "the attested guest admitted nobody"             test "$(accepted_count "$a")" = "0"
    check "the attested guest got no tunnel to it"         in_file "$a" "peer=guest-b FAILED"
  fi
}

# ---- a stale chain, which never reaches a peer ----------------------------
# The criterion asks for a guest with a stale chain to fail at its peer rather
# than locally. On this design it fails locally first, and that is not a gap:
# the acquirer loads the provisioned chain, checks it against the report the
# platform just produced, and refuses to bundle a stale one (ADR-0005), so a
# tunneld with a stale chain never starts and never presents anything. Both
# halves are recorded: the guest refusing to start, and — because the peer-side
# verdict is the one ADR-0005 describes wrongly — the verdict a peer would
# reach, taken outside a guest on ticket 05's captured bundle.
scenario_stalechain() {
  local work="$OUT/stalechain"
  echo
  echo "### stalechain: a chain provisioned for a TCB this platform is not at"
  mkdir -p "$work"
  echo
  echo "the peer's verdict, on ticket 05's captured evidence with the stale chain:"
  (cd "$REPO/attest" && go run ./cmd/verify-evidence \
      -evidence "$STALE/evidence.bin" -chain "$STALE/certificate-chain-stale.bin" \
      -key "$STALE/public-key.der" -refvals "$STALE/reference-values.json" \
      -author "$STALE/author.pub" 2>&1 | sed 's/^/    | /' ) || true
  echo
  if [ "$SNP" = 0 ]; then note "the local half needs a real report to check the chain against; skipped"; return; fi
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(answerer_json guest-a 10.14.0.2 120s)"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a 0s 30s)" -stale
  boot_pair "$work" "$IMAGE" "$IMAGE" 240 1
  local b="$work/console-b.txt"
  [ -f "$b" ] || { fail "stalechain: guest B left no console"; return; }
  check "the guest with the stale chain refused to start" in_file "$b" "refusing to start"
  check "it named ADR-0005 and the remedy"                in_file "$b" "ADR-0005"
  check "it never presented anything to a peer"           not_in_file "$b" "tunneld: listening on"
}

# ---- scenario: an attacker that changes what it carries --------------------
# The recording relay is the passive half of the attacker; this is the active
# one. It flips a bit in the payload of every twentieth datagram it forwards.
# Nothing here is expected to break: QUIC authenticates every packet, so a
# changed one is discarded by the receiver and retransmitted by the sender, and
# the exchange completes anyway. What matters is what cannot happen — a changed
# datagram delivered as if it were the sender's — and tunneld would catch that
# too, because an exchange checks that the response is the peer's echo of the
# request it sent.
scenario_tamper() {
  local work="$OUT/tamper"
  echo
  echo "### tamper: the relay changes a bit in every twentieth datagram"
  mkdir -p "$work"
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(answerer_json guest-a 10.14.0.2 240s)"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a 60s 90s)"
  TAMPER=20
  boot_pair "$work" "$IMAGE" "$IMAGE" 300 1
  TAMPER=0

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "tamper: one of the guests left no console"; return; }
  if [ "$SNP" = 0 ]; then note "control boot: nothing attests, nothing to tamper with"; return; fi
  check "the attacker really did change datagrams" \
        grep -qE "tampered=[1-9]" "$work/relay.txt"
  check "no exchange took a changed datagram for its peer's answer" \
        not_in_file "$b" "want <sandbox>:"
  check "the exchanges completed anyway, because QUIC discards what it cannot authenticate" \
        in_file "$b" 'answered_by="guest-a"'
  check "and the attacker still read nothing" in_file "$work/relay.txt" "MARKER not found"
}

# ---- the two policy scenarios (ticket 18) ---------------------------------
# What shape two peers can be in at all, which is the thing to understand
# before reading either scenario's verdicts.
#
# Every handshake here verifies both ways: each guest judges the other's
# evidence against its own set, and a guest's policy *is* its own signed set —
# its digest is SHA-256 over that set's signed bytes. So a pair in which A's
# set names (M, digest of B's set) and B's set names (M, digest of A's set)
# cannot be authored: each digest would have to be fixed before the other, and
# the two sets are a hash cycle. Nobody can build it, on this design or any
# other that binds a policy to its own digest.
#
# That leaves exactly two admitted shapes and one refused one, and both
# scenarios below are worth having because between them they are all three:
#
#   policy-pinned    A's value names B's digest; B's value names nothing and
#                    admits any policy. Both directions succeed. This is the
#                    most constrained pair that can complete a tunnel, and the
#                    unconstrained line on B's console is what that costs.
#   policy-mismatch  A's value names B's digest; B's value names a digest
#                    nobody holds. A admits B and B refuses A, whichever side
#                    dials, and no tunnel completes in either direction.
#
# The ticket's sentence "B dials A and is admitted" is therefore a statement
# about A's verdict on B's evidence and not about a connection: A admits B, B
# refuses A, and the handshake that carries both fails. Both guests dial in the
# policy-mismatch scenario so that the record says so from both ends rather
# than leaving it to be inferred from one.

# write_digests WORK KIND D_A D_B [WRONG] — the three numbers the scenario
# turns on, beside the consoles that show two of them being printed by the
# guests themselves.
write_digests() {
  local work="$1" kind="$2" d_a="$3" d_b="$4" wrong="${5:-}"
  {
    echo "# ticket 18, $kind: the policy digests this scenario turns on."
    echo "#"
    echo "# A policy digest is SHA-256 over the bytes a reference value set's author"
    echo "# signed, so it is not sha256sum of reference-values.json. Each number below"
    echo "# was printed by emit-refvals when it wrote the set, checked against"
    echo "# 'emit-refvals -digest-of' on the document as delivered, and checked again"
    echo "# against the line the guest holding that set printed at start."
    echo
    echo "launch measurement, both guests : $MEASUREMENT"
    echo "D_A, guest A's own policy       : $d_a"
    echo "    the digest of set-a.json, which is on guest A's config device"
    echo "D_B, guest B's own policy       : $d_b"
    echo "    the digest of set-b.json, which is on guest B's config device"
    echo
    case "$kind" in
      policy-mismatch)
        echo "set-a.json's value admits policy : $d_b   (guest B's, so A admits B)"
        echo "set-b.json's value admits policy : $wrong"
        echo "    = sha256 of the ASCII string \"not the policy guest A presents\", with no"
        echo "    trailing newline. It is the digest of no document: guest A presents D_A,"
        echo "    so B refuses A as a policy mismatch and names D_A when it does."
        ;;
      policy-pinned)
        echo "set-a.json's value admits policy : $d_b   (guest B's, and no other)"
        echo "set-b.json's value admits policy : any — it lists no policy_digest, which"
        echo "    guest B reports at start as one unconstrained value. It cannot name D_A:"
        echo "    D_A is the digest of a set that names D_B, and a set naming the digest of"
        echo "    a set that names it does not exist."
        ;;
    esac
  } > "$work/digests.txt"
  sed 's/^/    /' "$work/digests.txt"
}

# ---- scenario: a policy digest a value names, and the peer that presents it -
scenario_policy_pinned() {
  local work="$OUT/policy-pinned"
  echo
  echo "### policy-pinned: guest A's value names guest B's policy digest and no other"
  mkdir -p "$work"
  require_author_key policy-pinned || return
  build_emit_refvals

  # B's set is authored first because A's names it, and B's names nothing: the
  # cycle argument above says it cannot name A's.
  local d_b d_a
  d_b=$(author_set "$work/refvals-b")                  || { fail "policy-pinned: could not author guest B's set"; return; }
  d_a=$(author_set "$work/refvals-a" -policy-digest "$d_b") || { fail "policy-pinned: could not author guest A's set"; return; }
  keep_sets "$work"
  check "the digest emit-refvals printed for guest A's set is the digest of the document it wrote" \
        test -n "$d_a" -a "$d_a" = "$(digest_of "$work/set-a.json")"
  check "the digest emit-refvals printed for guest B's set is the digest of the document it wrote" \
        test -n "$d_b" -a "$d_b" = "$(digest_of "$work/set-b.json")"
  write_digests "$work" policy-pinned "$d_a" "$d_b"

  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(answerer_json guest-a 10.14.0.2 240s)" -refvals "$work/refvals-a"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a 0s 90s)" -refvals "$work/refvals-b"
  boot_pair "$work" "$IMAGE" "$IMAGE" 360 1

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "policy-pinned: one of the guests left no console"; return; }
  assert_booted "$a" "guest-a"; assert_booted "$b" "guest-b"
  if [ "$SNP" = 0 ]; then note "control boot: nothing attests, no policy to admit"; return; fi
  assert_attested "$a" "guest-a"; assert_attested "$b" "guest-b"

  # The operator's workflow, closed: the number written into A's allow-list is
  # the number B prints off the file B loaded.
  check "guest-a printed the digest of the set on its own config device" \
        test "$(console_policy_digest "$a")" = "$d_a"
  check "guest-b printed the digest of the set on its own config device, which is what A's value names" \
        test "$(console_policy_digest "$b")" = "$d_b"
  check "guest-a's value names a policy, so it reports nothing unconstrained" \
        test "$(unconstrained_lines "$a")" = "0"
  check "guest-b's value names none, and says so once, per value" \
        test "$(unconstrained_lines "$b")" = "1"

  check "guest-a admitted guest-b, whose policy digest its value names" in_file "$a" "tunneld: PEER key="
  check "guest-b admitted guest-a"                in_file "$b" "tunneld: PEER key="
  check "neither guest refused the other"         not_in_file "$a" "tunneld: REFUSED"
  check "and neither did the other"               not_in_file "$b" "tunneld: REFUSED"
  check "guest-a admitted at least one peer"      test "$(accepted_count "$a")" -ge 1
  check "guest-b established a tunnel"            in_file "$b" "kind=establish"
  check "guest-b exchanged over it, warm"         in_file "$b" "kind=warm_exchange"
  check "guest-b ran concurrent exchanges on one tunnel" in_file "$b" "kind=concurrent"
  check "guest-a answered guest-b's exchanges"    in_file "$b" 'answered_by="guest-a"'
  check "guest-b's exercise completed"            in_file "$b" "tunneld: EXIT status=0"
  check "the exchange went through the relay"     grep -q "a_to_b_frames=[1-9]" "$work/relay.txt"
  check "the relay found no plaintext on the wire" in_file "$work/relay.txt" "MARKER not found"
  grep -h "LATENCY .*kind=establish" "$b" | sed 's/^/    /' || true
}

# ---- scenario: the right image under a policy no value lists ---------------
scenario_policy_mismatch() {
  local work="$OUT/policy-mismatch"
  echo
  echo "### policy-mismatch: guest B's value names a policy digest nobody presents"
  mkdir -p "$work"
  require_author_key policy-mismatch || return
  build_emit_refvals

  # A digest of a string rather than of a document, deliberately: what this
  # scenario needs is a policy no peer on the segment presents, and any 32
  # bytes that are not D_A are that. Printed here so the record says where it
  # came from rather than showing 64 characters from nowhere.
  local wrong
  wrong=$(printf '%s' 'not the policy guest A presents' | sha256sum | cut -d' ' -f1)
  echo "    the digest guest B's value will name: sha256(\"not the policy guest A presents\")"
  echo "    = $wrong"

  local d_b d_a
  d_b=$(author_set "$work/refvals-b" -policy-digest "$wrong") || { fail "policy-mismatch: could not author guest B's set"; return; }
  d_a=$(author_set "$work/refvals-a" -policy-digest "$d_b")   || { fail "policy-mismatch: could not author guest A's set"; return; }
  keep_sets "$work"
  check "the digest emit-refvals printed for guest A's set is the digest of the document it wrote" \
        test -n "$d_a" -a "$d_a" = "$(digest_of "$work/set-a.json")"
  check "the digest emit-refvals printed for guest B's set is the digest of the document it wrote" \
        test -n "$d_b" -a "$d_b" = "$(digest_of "$work/set-b.json")"
  write_digests "$work" policy-mismatch "$d_a" "$d_b" "$wrong"

  # Both guests dial, in one boot, so that the record carries the verdicts from
  # both ends of the segment. The verdicts do not depend on who dialled — the
  # handshake verifies both ways either way — and this says so rather than
  # asserting it.
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(dialer_json guest-a 10.14.0.2 guest-b 0s 60s)" -refvals "$work/refvals-a"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a 0s 60s)" -refvals "$work/refvals-b"
  boot_pair "$work" "$IMAGE" "$IMAGE" 300 1

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "policy-mismatch: one of the guests left no console"; return; }
  assert_booted "$a" "guest-a"; assert_booted "$b" "guest-b"
  if [ "$SNP" = 0 ]; then note "control boot: nothing attests, no policy to mismatch"; return; fi
  assert_attested "$a" "guest-a"; assert_attested "$b" "guest-b"

  check "guest-a printed the digest of the set on its own config device" \
        test "$(console_policy_digest "$a")" = "$d_a"
  check "guest-b printed the digest of the set on its own config device" \
        test "$(console_policy_digest "$b")" = "$d_b"
  check "guest-a's value names a policy, so it reports nothing unconstrained" \
        test "$(unconstrained_lines "$a")" = "0"
  check "guest-b's value names a policy too, so neither guest is admitting any" \
        test "$(unconstrained_lines "$b")" = "0"

  # A's verdict on B, which is the half of the ticket's sentence that is true.
  check "guest-a admitted guest-b's evidence, whose policy digest its value names" \
        in_file "$a" "tunneld: PEER key="
  check "guest-a refused nothing"                 not_in_file "$a" "tunneld: REFUSED"
  # B's verdict on A, which is the half that decides the connection.
  check "guest-b refused guest-a as a policy mismatch" \
        in_file "$b" "REFUSED verification refused: guest policy or policy digest not permitted by the reference value"
  check "and the refusal names the digest guest-a presented" \
        in_file "$b" "peer presents policy digest $d_a; no reference value for the measurement it is running lists that policy"

  # What guest B's own counter counts, and why it is not zero here.
  #
  # PEERS counts the vendor seam — the verifier that judges evidence against
  # the reference value set — and the policy digest is checked above it, on the
  # certificate payload, not in the report. So this line says that guest A's
  # evidence was genuine, its image was the one B's set names and its platform
  # was above B's floor: everything the platform can vouch for was right. The
  # refusal is the policy and nothing else, which is exactly the claim, and it
  # is the two numbers being equal that says so. The modified and tcbfloor
  # scenarios above are the contrast: there the same counter reports refusals,
  # because what was wrong was something the set could see.
  local b_calls b_refusals
  b_calls=$(sed -n 's/.*PEERS verifier_calls=\([0-9]*\) .*/\1/p' "$b" | tail -1)
  b_refusals=$(grep -ac "REFUSED verification refused: guest policy or policy digest not permitted by the reference value" "$b" || true)
  echo "    guest-b verified guest-a's evidence $b_calls time(s) and refused the policy $b_refusals time(s)"
  check "guest-b refused guest-a's policy on every verification, and never for anything else" \
        test -n "$b_calls" -a "${b_calls:-0}" -ge 1 -a "$b_calls" = "$b_refusals"
  check "nothing below the policy refused guest-a: evidence, image and platform were all admitted there" \
        test "$(accepted_count "$b")" = "$b_calls"
  # And so no tunnel completed, whichever side dialled.
  check "guest-b's dial of guest-a got no tunnel" in_file "$b" "peer=guest-a FAILED"
  check "guest-a's dial of guest-b got no tunnel either, though A admits B" \
        in_file "$a" "peer=guest-b FAILED"
  check "guest-a's exercise failed"               in_file "$a" "tunneld: EXIT status=2"
  check "guest-b's exercise failed"               in_file "$b" "tunneld: EXIT status=2"
  check "nothing was exchanged in either direction" not_in_file "$a" "answered_by="
  check "nor in the other"                          not_in_file "$b" "answered_by="
  check "the relay found no plaintext on the wire"  in_file "$work/relay.txt" "MARKER not found"
}

# ---- run them -------------------------------------------------------------
for s in "${SCENARIOS[@]}"; do
  case "$s" in
    live)       scenario_live live "$RUN_FOR" ;;
    live-again) scenario_live live-again 150 ;;
    modified)   scenario_modified ;;
    tcbfloor)   scenario_tcbfloor ;;
    nosnp)      scenario_nosnp ;;
    tamper)     scenario_tamper ;;
    stalechain) scenario_stalechain ;;
    policy-pinned)   scenario_policy_pinned ;;
    policy-mismatch) scenario_policy_mismatch ;;
    *) echo "unknown scenario: $s" >&2; exit 2 ;;
  esac
done

echo
echo "=== latency, as the guests measured it ==="
grep -h "LATENCY" "$OUT"/*/console-*.txt 2>/dev/null | sed 's/^tunneld: /  /' || echo "  none recorded"

echo
echo "=== $PASSES passed, $FAILURES failed ==="
if [ -n "$CAPTURE" ]; then
  mkdir -p "$CAPTURE"
  cp "$TRANSCRIPT" "$CAPTURE/" 2>/dev/null || true
  for d in "$OUT"/*/; do
    n=$(basename "$d")
    case "$n" in image-*|config-*) continue ;; esac
    mkdir -p "$CAPTURE/$n"
    cp "$d"/console-*.txt "$d"/relay.txt "$d"/segment.pcap "$d"/boot.job \
       "$d"/mutated-measurement.txt "$d"/digests.txt "$d"/set-a.json "$d"/set-a.json.sig \
       "$d"/set-b.json "$d"/set-b.json.sig "$CAPTURE/$n/" 2>/dev/null || true
  done
  cp "$IMAGE/manifest.txt" "$IMAGE/reference-values.json" "$IMAGE/reference-values.json.sig" \
     "$IMAGE/predicted-measurement.txt" "$IMAGE/packaging.txt" "$CAPTURE/" 2>/dev/null || true
  echo "captured into $CAPTURE"
fi
[ "$FAILURES" = 0 ]
