#!/bin/bash
# Ticket 14: two attested guests, live.
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
#   reference value set. The tcbfloor scenario re-signs a set with it, and a
#   different key would need a different image, since the public half is inside
#   the measurement.
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
OUT="${OUT:-$STACK/ticket14-run}"
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

echo "=== ticket 14: two attested guests ==="
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
  local job="$SPOOL/ticket14-$$-$name"
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
# Ticket 14: launch the two guests of $(basename "$work").
#
# Privileged only because an SNP launch opens /dev/sev. Both guests are started
# from this one job and waited for together: they are two halves of one
# conversation, and a runner that ran them one after another would have each
# talking to nobody.
set -u
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
  local key="$IMAGE-packaging/author.key"
  [ -f "$key" ] || { fail "tcbfloor: no author key at $key; package-tunneld.sh keeps it"; return; }
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
       "$d"/mutated-measurement.txt "$CAPTURE/$n/" 2>/dev/null || true
  done
  cp "$IMAGE/manifest.txt" "$IMAGE/reference-values.json" "$IMAGE/reference-values.json.sig" \
     "$IMAGE/predicted-measurement.txt" "$IMAGE/packaging.txt" "$CAPTURE/" 2>/dev/null || true
  echo "captured into $CAPTURE"
fi
[ "$FAILURES" = 0 ]
