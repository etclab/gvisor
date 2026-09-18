#!/bin/bash
# Two attested guests, live: ticket 14's harness, and the policy scenarios of
# tickets 18 and 19.
#
#   tunnel-on-two-guests.sh [-image DIR] [-out DIR] [-scenario NAME]...
#                           [-no-snp] [-run-for SECONDS] [-quick]
#                           [-capture DIR] [-spool DIR] [-workload IMG]
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
#             and the exchange completes.
#   policy-mismatch (ticket 18) the same pair, with guest B's set naming a
#             policy digest nobody presents. A admits B and B refuses A as a
#             policy mismatch, whichever side dials, so no tunnel completes in
#             either direction.
#   push-v1   (ticket 22) guest A pushes a version 1 policy at guest B on the
#             tunnel it has just established. B's null sandbox applies it and
#             acknowledges, the digest A said it was pushing is the digest B
#             says it applied, and only then is A handed a stream.
#   push-v2   the same pair with a version 2 document. B's tunneld refuses it
#             at the boundary without waking any sandbox, the tunnel closes
#             with the refusal, and A is told its policy did not land.
#   mutual    (ticket 19) each guest's set names the other's policy digest and
#             no other, and neither entry is unconstrained. Both admit, the
#             tunnel is established and exchanged over in both directions. This
#             is the shape ticket 18 could not author at all, and it is the
#             strongest admitted pair this design has.
#   adapter   (ticket 25) the same pair with a sandbox on each guest and the
#             adapter under it. Each guest runs tunneld first with a sandbox
#             socket, an exit attached to that socket, and a busybox httpd on its
#             own loopback; then one runsc sandbox, --network=none, given
#             --tunnel-socket and --tunnel-table. The one workload disk both
#             guests get carries one bundle that fetches three URLs, and the two
#             guests differ only in the tunnel table their config device carries,
#             so on each guest exactly one of the three is permitted: guest A
#             fetches guest B's page through guest B's exit, guest B fetches
#             guest A's, and the other two names do not resolve at all. Needs
#             -workload.
#   policy    (ticket 26) the adapter scenario with the policy each guest pushes
#             at the other actually enforced by the sentry, and three things done
#             to it: an exec outside the policy's `x` refused EACCES inside the
#             sandbox, a NARROWER policy pushed by a second tunneld on guest B
#             while guest A's sandbox is in the middle of a long fetch, and the
#             sandbox killed at the end so that the tunneld beside it loses the
#             liveness the contract's third version watches for. Needs
#             -workload, and it is driven by the knobs on the two config
#             devices rather than by -run-for.
#
# The topology is the evidence for two of the criteria on its own, so it is
# worth stating plainly. The guests' only network is
# docs/snp/l2relay.py: guest A's QEMU and guest B's QEMU each hold one TCP
# connection to it, and it copies ethernet frames between them. There is no
# gateway on that segment, no resolver, and no route off it, so no guest can
# reach AMD's key distribution service or anything else during the run — egress
# is absent rather than filtered. Since ticket 22 it is also filtered, and the
# two facts are kept apart on purpose: the ceiling compiled into the image goes
# into the kernel before the link is up, and each guest proves it by attempting
# the egress it forbids and reporting the errno — a rule refusing (EPERM,
# ECONNREFUSED) rather than a routing table with nothing to say (ENETUNREACH).
# That proof needs the routing table to have something to say, so the guest's
# init adds an on-link default route for it after the exercise is over; nothing
# leaves on it, because the output hook rejects those packets before the kernel
# resolves a neighbour, and the segment carries no ARP for any of them
# (docs/snp/image/init.rootfs). And because every frame between the two
# guests passes through it, it is also the on-path attacker: it records every
# datagram to a pcap file and searches each one for the plaintext an exchange
# carries. The legitimate exchange and the relay's failure to read it are the
# same run.
#
# -workload attaches one read-only OCI-bundle disk (docs/snp/image/mkworkloaddev.sh)
# to BOTH guests, which their init runs under runsc after the egress ceiling and
# before tunneld (ticket 24) — or after it, when the config device carries a
# tunnel table and the sandbox is on the adapter (ticket 25, the adapter
# scenario, which refuses to run without this flag). It is outside the launch measurement, so it changes
# no measurement, no document and no assertion below; the workload's own console
# lines are read by hand. Without it each guest logs that there is no bundle and
# carries on to tunneld, which is the ordinary case and what every scenario
# recorded before ticket 24 is. When it is given, the capture keeps the bundle's
# config.json — what ran — and not the disk, which is megabytes and not measured.
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
#   reference value set and its policy. The tcbfloor and policy scenarios
#   re-sign both with it, and a different key would need a different image,
#   since the public half is inside the measurement. package-tunneld.sh leaves it there when it
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
SNP=1; CAPTURE=""; RUN_FOR=1000; SCENARIOS=(); SPOOL=""; WORKLOAD=""
RELAY_A_PORT="${RELAY_A_PORT:-15801}"; RELAY_B_PORT="${RELAY_B_PORT:-15802}"
MARKER="attested-tunnel-plaintext-marker"
TAMPER=0
# What a policy to push is called on a config device. Anything but policy.json:
# that name and its signature are what ticket 22 took off the device, and a
# tunneld that finds either refuses to start before it reads anything else.
PUSH_POLICY_NAME="push-policy.json"
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
    -workload) WORKLOAD="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -z "$WORKLOAD" ] || [ -f "$WORKLOAD" ] || { echo "missing workload device image $WORKLOAD" >&2; exit 2; }
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

# How the exercise exited is read off init's line rather than tunneld's. Since
# ticket 22 a console carries two "tunneld: EXIT status=" lines — the serving
# tunneld's, and the one the egress probe init runs after it prints — and only
# init names which of the two it waited for (docs/snp/image/init.rootfs).

echo "=== two attested guests, from $(basename "$IMAGE") ==="
echo "date        : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "repo        : $(git -C "$REPO" rev-parse HEAD) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
echo "image       : $IMAGE"
echo "mode        : $([ "$SNP" = 1 ] && echo 'SEV-SNP (privileged, through the spool)' || echo 'control boot, no SNP (unprivileged)')"
echo "scenarios   : ${SCENARIOS[*]}"
[ -n "$WORKLOAD" ] && echo "workload    : $WORKLOAD (one OCI bundle on both guests, outside the launch measurement)"
echo

for f in OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img reference-values.json reference-values.json.sig \
         policy.json policy.json.sig manifest.txt; do
  [ -f "$IMAGE/$f" ] || { echo "missing $IMAGE/$f — run docs/snp/image/package-tunneld.sh first" >&2; exit 1; }
done
MEASUREMENT=$(sed -n 's/^launch_measurement: //p' "$IMAGE/manifest.txt")
echo "predicted launch measurement of the image both guests boot:"
echo "  $MEASUREMENT"
echo "the reference value set on both config devices names exactly that, signed by the"
echo "author key baked into the image at /etc/attested-tunnel/author.pub (ADR-0004),"
echo "and the policy beside it is signed by the same key under its own domain."
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
#   make_config DIR SANDBOX ADDRESS PEER_NAME PEER_ADDRESS RUN_JSON \
#               [-stale] [-refvals DIR] [-policy DIR] [-push FILE] \
#               [-tunnel-table FILE] [-exit-allow FILE] \
#               [-push-narrow FILE] [-run-narrow JSON] [-knobs DIR]
#
# The last three are ticket 26's and they are the whole of what that scenario
# adds to a config device: a second policy document, the run configuration the
# second tunneld is started with, and the two timing files init reads
# (kill-after, narrow-after). None of them is measured and none of them is
# signed, which is the point — a pushed policy is trustworthy at the far end
# because of the evidence the pushing guest presented, not because of the disk
# it was read from.
#
# The last two are ticket 25's and they are the only difference between the two
# guests of the adapter scenario. Both go onto the device unchanged: the table is
# what runsc is given as --tunnel-table and what the sentry enforces, and
# exit-allow is the one line this guest's exit is started with. Neither is
# measured — which is the point, because one image boots both guests.
#
# The device carried two signed documents between tickets 19 and 22: the set,
# which says whom this guest admits, and the policy, which says what it is. They
# default to the image's own emitted pair and are overridden separately, because
# every scenario below changes exactly one of them.
#
# Since ticket 22 only the set reaches the device. The policy is still authored
# into the config SOURCE, because that directory is what the record keeps and
# what the digests below are read off, but the device is built from a copy with
# the two policy files left behind: nothing in a guest loads one, tunneld
# refuses to start on a device that carries either half, and mkconfigdev.sh
# refuses to build one. A policy reaches a peer over the tunnel instead, and
# -push is how this harness hands one to the guest that will push it
# (docs/policy-push.md).
make_config() {
  local dir="$1" sandbox="$2" address="$3" peer="$4" peeraddr="$5" runjson="$6"; shift 6
  local refvals="$IMAGE" policysrc="" pushpolicy="" chainsrc="$CHAIN" chainbin="certificate-chain.bin" chainjson="certificate-chain.json"
  local tunneltable="" exitallow="" pushnarrow="" runnarrow="" knobs=""
  while [ -n "${1:-}" ]; do
    case "$1" in
      -stale)   chainsrc="$STALE"; chainbin="certificate-chain-stale.bin"; chainjson="certificate-chain-stale.json"; shift ;;
      -refvals) refvals="$2"; shift 2 ;;
      -policy)  policysrc="$2"; shift 2 ;;
      -push)    pushpolicy="$2"; shift 2 ;;
      -tunnel-table) tunneltable="$2"; shift 2 ;;
      -exit-allow)   exitallow="$2"; shift 2 ;;
      -push-narrow)  pushnarrow="$2"; shift 2 ;;
      -run-narrow)   runnarrow="$2"; shift 2 ;;
      -knobs)        knobs="$2"; shift 2 ;;
      *) echo "make_config: unknown option $1" >&2; exit 2 ;;
    esac
  done
  [ -n "$policysrc" ] || policysrc="$IMAGE"
  rm -rf "$dir" "$dir-device"; mkdir -p "$dir" "$dir-device"
  cp "$refvals/reference-values.json" "$refvals/reference-values.json.sig" "$dir/"
  cp "$policysrc/policy.json" "$policysrc/policy.json.sig" "$dir/"
  cp "$chainsrc/$chainbin"  "$dir/certificate-chain.bin"
  cp "$chainsrc/$chainjson" "$dir/certificate-chain.json"
  printf '{"peers": {"%s": "%s"}}\n' "$peer" "$peeraddr" > "$dir/peers.json"
  printf '%s\n' "$runjson" > "$dir/tunneld.json"
  if [ -n "$pushpolicy" ]; then cp "$pushpolicy" "$dir/$PUSH_POLICY_NAME"; fi
  if [ -n "$tunneltable" ]; then cp "$tunneltable" "$dir/tunnel-table.json"; fi
  if [ -n "$exitallow" ];   then cp "$exitallow"   "$dir/exit-allow";        fi
  if [ -n "$pushnarrow" ];  then cp "$pushnarrow"  "$dir/push-policy-narrow.json"; fi
  if [ -n "$runnarrow" ];   then printf '%s\n' "$runnarrow" > "$dir/tunneld-narrow.json"; fi
  if [ -n "$knobs" ]; then
    for k in kill-after narrow-after; do
      [ -f "$knobs/$k" ] && cp "$knobs/$k" "$dir/$k"
    done
  fi
  # The device, from a copy of the source with the policy left behind. The two
  # names are matched exactly rather than by pattern: a policy to push is a
  # policy too, and that one does go on the device, which is the whole point of
  # it. What is filtered is the two file names ticket 22 took off, and nothing
  # that merely looks like them.
  for f in "$dir"/*; do
    case "$(basename "$f")" in policy.json|policy.json.sig) continue ;; esac
    cp -r "$f" "$dir-device/"
  done
  bash "$HERE/image/mkconfigdev.sh" "$dir-device" "$dir.img" | sed 's/^/    /'
}

# The two run configurations. Both guests are configured alike on the limits,
# deliberately: QUIC's idle timeout is the minimum of what the two peers
# advertise, so two guests that differ there leave one of them running on a
# number that appears nowhere in its own configuration.
#
# IDLE_TIMEOUT is that number and it is a variable rather than a literal for one
# scenario's sake: a liveness watch lives exactly as long as the tunnel the
# policy arrived on, because attest/tunneld/push.go's watchLiveness returns —
# silently, with no line and no refusal — the moment conn.Live() is false. Sixty
# seconds is right for every scenario whose exchanges are over in ten, and wrong
# for the policy scenario, where the thing under test happens a hundred and fifty
# seconds after the last stream closed. scenario_policy sets it to outlive its
# own hold; nothing else sets it, so every other scenario's configuration is the
# byte-for-byte one the earlier records were made with.
IDLE_TIMEOUT="${IDLE_TIMEOUT:-60s}"
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

# The third, ticket 25's: a tunneld that neither exercises nor answers. It has no
# exercise block because the thing that opens a stream is the sandbox beside it
# and not this process, and it needs no handler because with a sandbox socket
# configured tunneld's own echo stands down and the attached exit answers
# (attest/cmd/tunneld/nullsandbox.go). What is left is what both guests need from
# it and nothing else: an identity, a link, a listener and a hold long enough to
# outlive the workload that is using it.
adapter_json() { # SANDBOX ADDRESS HOLD
  cat <<JSON
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "$1",
  "listen": "$2:4433",
  "link": {"interface": "eth0", "address": "$2", "prefix_length": 24},
  "limits": {"idle_timeout": "$IDLE_TIMEOUT", "max_age": "15m"},
  "hold": "$3"
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
  # One workload disk for both guests, read-only on each and never measured by
  # either: two QEMUs opening one raw file read-only is the same arrangement as
  # the two of them opening one rootfs.img.
  local workload_flags=""
  [ -n "$WORKLOAD" ] && workload_flags="-workload $WORKLOAD"
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
    -relay 127.0.0.1:$RELAY_A_PORT -console "\$A_LOG" -mac 52:54:00:14:00:0a $common_flags $workload_flags &
A=\$!
timeout $seconds bash "$HERE/tunnel-guest.sh" -image "$image_b" -config "$work/config-b.img" \\
    -relay 127.0.0.1:$RELAY_B_PORT -console "\$B_LOG" -mac 52:54:00:14:00:0b $common_flags $guest_b_flags $workload_flags &
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

# ---- documents this script authors itself (tickets 18 and 19) -------------
# The policy scenarios below need documents that differ from the image's own in
# one field, and only in that field.
#
# A set: the same measurement, the same author, the same TCB floor and the same
# launch policy, with a policy_digest naming a peer's policy or naming none. The
# floor and the policy are read out of the record the build wrote beside its own
# set rather than repeated here, because a second copy of them here is a second
# thing to keep in step with build-image.sh, and a set that differed in two
# fields would make every verdict below ambiguous.
#
# A policy: the egress section, which is not a parameter, and forward_to. Since
# ticket 19 that document is what a policy digest names, and the two are
# separate files for the reason docs/policy-binding.md gives — while a set was
# also a policy, no two peers could pin each other.
AUTHOR_KEY_PATH="${AUTHOR_KEY:-$IMAGE-packaging/author.key}"
EMIT="$OUT/emit-refvals"
build_emit_refvals() { [ -x "$EMIT" ] || (cd "$HERE/image/emit-refvals" && go build -o "$EMIT" .); }
image_tcb_floor()     { sed -n 's/^tcb floor (authoring choice): \([0-9,]*\).*/\1/p' "$IMAGE/reference-values.inputs.txt"; }
image_launch_policy() { sed -n 's/^launch policy: *//p' "$IMAGE/reference-values.inputs.txt"; }

# author_set DIR [-policy-digest HEX] — emit and sign one reference value set
# into DIR. It prints nothing a caller reads: a set has no digest of its own any
# more, and the number a peer needs comes from the policy beside it.
author_set() {
  local dir="$1"; shift
  mkdir -p "$dir"
  if ! "$EMIT" -measurement "$MEASUREMENT" -key "$AUTHOR_KEY_PATH" -out "$dir" \
        -tcb "$(image_tcb_floor)" -policy "$(image_launch_policy)" "$@" > "$dir/emit-set.txt" 2>&1; then
    sed 's/^/    | /' "$dir/emit-set.txt" >&2
    return 1
  fi
  sed 's/^/    | /' "$dir/emit-set.txt" >&2
}

# author_policy DIR [-forward-to HEX]... — emit and sign one policy into DIR and
# print its digest, which is the number a peer puts in its policy_digest to
# admit a guest holding this policy. It is SHA-256 over the bytes the author
# signed and not over the file, so it comes from the tool that knows that; this
# script never computes it.
author_policy() {
  local dir="$1"; shift
  mkdir -p "$dir"
  if ! "$EMIT" -emit-policy -key "$AUTHOR_KEY_PATH" -out "$dir" "$@" > "$dir/emit-policy.txt" 2>&1; then
    sed 's/^/    | /' "$dir/emit-policy.txt" >&2
    return 1
  fi
  sed 's/^/    | /' "$dir/emit-policy.txt" >&2
  sed -n 's/^policy digest: //p' "$dir/emit-policy.txt"
}

# digest_of FILE — the same number read back off a policy already written,
# without a key and without loading it. This is the operator's half of the
# workflow the ticket describes: a digest read off a document, put in a peer's
# allow-list, and then seen again on that guest's console at start.
digest_of() { "$EMIT" -digest-of "$1" | sed -n 's/^policy digest: //p'; }

# console_policy_digest CONSOLE — the digest a guest printed at start, which is
# the digest of the policy it actually loaded off its own config device.
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

# keep_sets WORK — copy the authored documents, as signed, next to the consoles
# they explain, so the captured evidence carries them and not only their
# digests. Four files a side since ticket 19: the set, the policy, and a
# signature each.
keep_sets() {
  local work="$1" side
  for side in a b; do
    cp "$work/refvals-$side/reference-values.json"     "$work/set-$side.json"     2>/dev/null || true
    cp "$work/refvals-$side/reference-values.json.sig" "$work/set-$side.json.sig" 2>/dev/null || true
    cp "$work/policy-$side/policy.json"                "$work/policy-$side.json"     2>/dev/null || true
    cp "$work/policy-$side/policy.json.sig"            "$work/policy-$side.json.sig" 2>/dev/null || true
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
  check "guest-b's exercise completed"            in_file "$b" "init: tunneld exited with status 0"
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

# ---- scenario: a policy pushed over the tunnel (ticket 22) -----------------
# The sandbox contract's other half, on hardware. Guest A dials guest B and
# pushes a policy at it on the tunnel it has just established — after both have
# judged the other's evidence, and before anything else crosses. B's tunneld
# reads the envelope, hands the document to the sandbox beside it, and answers.
#
# A is the dialer here, where scenario_live has B dial. It costs nothing and it
# makes the two consoles read the way the ticket is written: A pushes, B applies
# or refuses.
#
# The document is the smallest thing that is a policy: the envelope tunneld
# reads, and the three lists it does not. Nothing in this tree parses n, f or x
# (docs/policy-push.md), so a larger document would be a test of the framing
# rather than of the contract.
push_document() { # FILE VERSION
  printf '{"format":"policy","version":%s,"n":[],"f":[],"x":[]}\n' "$2" > "$1"
}

# What one console said it was about to push, and what the other said it
# applied. The two lines carry the same four fields; these read the digest off
# each, so that "the same document arrived" is a comparison and not an
# assertion.
pushed_digest()  { sed -n 's/.*tunneld: push policy .*sha256=\([0-9a-f]\{64\}\).*/\1/p' "$1" | head -1; }
applied_digest() { sed -n 's/.*tunneld: SANDBOX applied .*sha256=\([0-9a-f]\{64\}\).*/\1/p' "$1" | head -1; }

# image_ceiling_digest — the digest a guest booted from this image presents,
# read off the manifest the build wrote. Since ticket 22 that is sha256 over the
# egress ceiling compiled into the measured tunneld and not the digest of any
# document on a config device, and it is the number each guest prints at start.
image_ceiling_digest() { sed -n 's/^policy_digest: //p' "$IMAGE/manifest.txt"; }

scenario_push() { # NAME VERSION SECONDS
  local name="$1" version="$2" seconds="$3"
  local work="$OUT/$name"
  echo
  echo "### $name: guest A pushes a version $version policy at guest B over the tunnel"
  mkdir -p "$work"
  local doc="$work/push-policy.json" want ceiling
  push_document "$doc" "$version"
  want=$(sha256sum "$doc" | cut -d' ' -f1)
  ceiling=$(image_ceiling_digest)
  echo "    the document A will push : $(cat "$doc")"
  echo "    sha256                   : $want ($(stat -c %s "$doc") bytes)"
  echo "    it goes on A's config device as /config/$PUSH_POLICY_NAME, which is not the name"
  echo "    ticket 22 took off the device, and A's init passes it to tunneld as -push-policy."

  # B answers and outlives A's whole run; A dials, pushes, and exercises what it
  # is given. Both are configured alike otherwise, as everywhere else here.
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(answerer_json guest-b 10.14.0.3 "$((seconds + 90))s")"
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(dialer_json guest-a 10.14.0.2 guest-b "${seconds}s" 90s)" -push "$doc"
  boot_pair "$work" "$IMAGE" "$IMAGE" "$((seconds + 240))" 1

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "$name: one of the guests left no console"; return; }
  assert_booted "$a" "guest-a"; assert_booted "$b" "guest-b"
  if [ "$SNP" = 0 ]; then
    check "control boot: neither guest can attest, and both refuse to start rather than proceed" \
          in_file "$a" "refusing to start"
    return
  fi
  assert_attested "$a" "guest-a"; assert_attested "$b" "guest-b"

  # What each guest holds before a byte crosses.
  check "guest-a read the policy off its config device and said what it was about to push" \
        in_file "$a" "tunneld: push policy /config/$PUSH_POLICY_NAME: format=policy version=$version"
  check "guest-b was given nothing to push, so a push on this segment has one direction" \
        not_in_file "$b" "tunneld: push policy"
  check "neither guest found the document ticket 22 took off the config device" \
        not_in_file "$a" "the config device carries policy.json"
  check "the digest guest-a presents is the ceiling compiled into its image, not a document on its disk" \
        test "$(console_policy_digest "$a")" = "$ceiling"
  check "and guest-b presents the same one, because they boot the same image" \
        test "$(console_policy_digest "$b")" = "$ceiling"
  check "neither guest's set admits a peer under any policy at all" \
        test "$(unconstrained_lines "$a")" = "0" -a "$(unconstrained_lines "$b")" = "0"

  case "$version" in
    1)
      check "guest-b's null sandbox applied it and said so"  in_file "$b" "tunneld: SANDBOX applied format=policy version=1"
      check "it is the same document on both consoles: the digest A said it was pushing is the digest B says it applied" \
            test -n "$(applied_digest "$b")" -a "$(pushed_digest "$a")" = "$(applied_digest "$b")"
      check "and that digest is of the file this scenario wrote" \
            test "$(applied_digest "$b")" = "$want"
      check "guest-a established a tunnel"                   in_file "$a" "kind=establish"
      check "guest-b was opened to only after the acknowledgement was in" \
            in_file "$b" 'tunneld: SANDBOX stream from peer="guest-a"'
      check "guest-b answered guest-a's exchanges"           in_file "$a" 'answered_by="guest-b"'
      check "guest-a's exercise completed"                   in_file "$a" "init: tunneld exited with status 0"
      check "guest-a refused nothing"                        not_in_file "$a" "tunneld: REFUSED"
      check "and guest-b refused nothing"                    not_in_file "$b" "tunneld: REFUSED"
      ;;
    *)
      check "guest-b refused a version it does not read: the tenth reason, on the receiving side" \
            in_file "$b" "REFUSED verification refused: the policy pushed to the peer was not applied"
      check "guest-a was told its policy did not land, under that same reason" \
            in_file "$a" "REFUSED verification refused: the policy pushed to the peer was not applied"
      check "no sandbox was woken: guest-b applied nothing" \
            not_in_file "$b" "SANDBOX applied"
      check "and nothing reached guest-b on that tunnel: no stream was opened on it at all" \
            not_in_file "$b" "SANDBOX stream from peer="
      check "guest-a got no exchange answered either"        not_in_file "$a" 'answered_by="guest-b"'
      check "guest-a's exercise failed rather than carrying on without its policy" \
            in_file "$a" "init: tunneld exited with status 2"
      ;;
  esac

  {
    echo "# $name: the two numbers this scenario turns on."
    echo "#"
    echo "# A pushed policy is not signed and not measured. What makes it trustworthy is"
    echo "# the tunnel it arrived on, and what makes the transcript a claim is that the"
    echo "# digest the pushing guest printed before it sent anything is the digest the"
    echo "# receiving guest printed when it applied it (docs/policy-push.md)."
    echo
    echo "launch measurement, both guests : $MEASUREMENT"
    echo "egress ceiling digest           : $ceiling"
    echo "    sha256 over attest/ceiling/ceiling.nft, compiled into the measured tunneld."
    echo "    It is what each guest prints at start and what each set admits; no document"
    echo "    on either config device is named by it."
    echo
    echo "the pushed document                : $(cat "$doc")"
    echo "its sha256, as this script wrote it: $want"
    echo "as guest A said it was pushing it  : $(pushed_digest "$a")"
    echo "as guest B said it applied it      : $(applied_digest "$b")"
    echo "    An empty line above is the answer for the version 2 run: B's tunneld reads"
    echo "    the envelope before any sandbox does, so a version it does not read is"
    echo "    refused at the boundary and nothing is ever applied."
  } > "$work/digests.txt"
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
  check "the modified guest's exercise failed"    in_file "$b" "init: tunneld exited with status 2"
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
  check "it exited saying so"                              in_file "$b" "init: tunneld exited with status 1"
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
  (cd "$REPO/attest" && go run ./cmd/attest-tool verify \
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

# ---- the policy scenarios (tickets 18 and 19) -----------------------------
# What shape two peers can be in at all, which is the thing to understand
# before reading any of these verdicts.
#
# Every handshake here verifies both ways: each guest judges the other's
# evidence against its own set. Under ticket 18 a guest's policy *was* its own
# signed set — its digest was SHA-256 over that set's signed bytes — so a pair in
# which A's set named (M, digest of B's set) and B's named (M, digest of A's set)
# could not be authored: each digest would have to be fixed before the other, and
# the two sets were a hash cycle. That is what ticket 19 split. The policy is now
# its own document, naming measurements and no digests at all, so the two digests
# are fixed independently and the cycle is gone.
#
# The three scenarios below are the before, the impossible-then, and the after:
#
#   policy-pinned    A's value names B's policy digest; B's value names nothing
#                    and admits any policy. Both directions succeed. This was
#                    the most constrained pair ticket 18 could complete a tunnel
#                    with, and the unconstrained line on B's console is what it
#                    cost.
#   policy-mismatch  A's value names B's digest; B's value names a digest nobody
#                    holds. A admits B and B refuses A, whichever side dials, and
#                    no tunnel completes in either direction. Under ticket 18
#                    this was the shape of *every* fully constrained pair.
#   mutual           A's value names B's policy digest and B's names A's, both
#                    real, neither unconstrained. Both admit. This is the pair
#                    ticket 18 could not author, and it is the point of the
#                    split.
#
# The two policies in a pair have to differ, or the two digests are one number
# and "each names the other's" says nothing. They differ in the truthful way:
# forward_to. Both guests boot the same image, so both policies must name that
# image's measurement or neither could dial; one of them also names a second
# measurement nothing on this segment boots, which is a policy an operator might
# really write for a sandbox that also calls a peer elsewhere, and which is
# enough to make the two documents — and therefore the two digests — different.

# fictitious_measurement — a launch measurement of the right width that names no
# image anybody has. It is what the second entry in one policy of each pair is,
# so that the pair's two policy digests differ without either document saying
# anything untrue about the guests on this segment.
#
# sha384 because an SEV-SNP launch measurement is 384 bits; of a sentence,
# because the record should say where 96 hexadecimal characters came from rather
# than showing them from nowhere.
FICTITIOUS_IMAGE_TEXT='an image this sandbox would also dial, which nothing on this segment boots'
fictitious_measurement() { printf '%s' "$FICTITIOUS_IMAGE_TEXT" | sha384sum | cut -d' ' -f1; }

# write_digests WORK KIND D_A D_B [WRONG] — the numbers the scenario turns on,
# beside the consoles that show two of them being printed by the guests
# themselves.
write_digests() {
  local work="$1" kind="$2" d_a="$3" d_b="$4" wrong="${5:-}"
  {
    echo "# $kind: the policy digests this scenario turns on."
    echo "#"
    echo "# A policy digest is SHA-256 over the bytes a policy's author signed, so it is"
    echo "# not sha256sum of policy.json, and since ticket 19 it is the digest of the"
    echo "# policy and not of the reference value set beside it. Each number below was"
    echo "# printed by emit-refvals when it wrote the document, checked against"
    echo "# 'emit-refvals -digest-of' on the document as delivered, and checked again"
    echo "# against the line the guest holding that document printed at start."
    echo
    echo "launch measurement, both guests : $MEASUREMENT"
    echo "D_A, guest A's own policy       : $d_a"
    echo "    the digest of policy-a.json, which is on guest A's config device"
    echo "D_B, guest B's own policy       : $d_b"
    echo "    the digest of policy-b.json, which is on guest B's config device"
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
        echo "    guest B reports at start as one unconstrained value. This is ticket 18's"
        echo "    shape kept as a control: it is what a pair had to look like while a"
        echo "    sandbox's policy was its own allow-list."
        ;;
      mutual)
        echo "set-a.json's value admits policy : $d_b   (guest B's, and no other)"
        echo "set-b.json's value admits policy : $d_a   (guest A's, and no other)"
        echo "    Neither value is unconstrained, and each names a policy the other guest"
        echo "    really presents. Under ticket 18 this pair could not be authored: D_A was"
        echo "    the digest of a document that would have had to contain D_B, and D_B the"
        echo "    digest of one containing D_A."
        echo
        echo "why the two digests differ, given that both guests boot one image:"
        echo "    policy-a.json forwards to $MEASUREMENT"
        echo "    policy-b.json forwards to that and also to"
        echo "      $(fictitious_measurement)"
        echo "    = sha384 of the ASCII string \"$FICTITIOUS_IMAGE_TEXT\","
        echo "    with no trailing newline. It is a launch measurement of the right width"
        echo "    naming no image anybody has, so guest B's policy is a different document"
        echo "    from guest A's while both still say the true thing about this segment:"
        echo "    each guest will dial the image the other is running."
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
  # The two policies first, because the sets name their digests. They differ in
  # forward_to and in nothing else; guest B's names one image more, which is
  # what makes D_A and D_B two numbers.
  local d_b d_a
  d_a=$(author_policy "$work/policy-a" -forward-to "$MEASUREMENT") \
      || { fail "policy-pinned: could not author guest A's policy"; return; }
  d_b=$(author_policy "$work/policy-b" -forward-to "$MEASUREMENT" -forward-to "$(fictitious_measurement)") \
      || { fail "policy-pinned: could not author guest B's policy"; return; }
  author_set "$work/refvals-b"                       || { fail "policy-pinned: could not author guest B's set"; return; }
  author_set "$work/refvals-a" -policy-digest "$d_b" || { fail "policy-pinned: could not author guest A's set"; return; }
  keep_sets "$work"
  check "guest A's two policies have distinct digests, so each names one document" \
        test -n "$d_a" -a -n "$d_b" -a "$d_a" != "$d_b"
  check "the digest emit-refvals printed for guest A's policy is the digest of the document it wrote" \
        test -n "$d_a" -a "$d_a" = "$(digest_of "$work/policy-a.json")"
  check "the digest emit-refvals printed for guest B's policy is the digest of the document it wrote" \
        test -n "$d_b" -a "$d_b" = "$(digest_of "$work/policy-b.json")"
  write_digests "$work" policy-pinned "$d_a" "$d_b"

  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(answerer_json guest-a 10.14.0.2 240s)" -refvals "$work/refvals-a" -policy "$work/policy-a"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a 0s 90s)" -refvals "$work/refvals-b" -policy "$work/policy-b"
  boot_pair "$work" "$IMAGE" "$IMAGE" 360 1

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "policy-pinned: one of the guests left no console"; return; }
  assert_booted "$a" "guest-a"; assert_booted "$b" "guest-b"
  if [ "$SNP" = 0 ]; then note "control boot: nothing attests, no policy to admit"; return; fi
  assert_attested "$a" "guest-a"; assert_attested "$b" "guest-b"

  # The operator's workflow, closed: the number written into A's allow-list is
  # the number B prints off the file B loaded.
  check "guest-a printed the digest of the policy on its own config device" \
        test "$(console_policy_digest "$a")" = "$d_a"
  check "guest-b printed the digest of the policy on its own config device, which is what A's value names" \
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
  check "guest-b's exercise completed"            in_file "$b" "init: tunneld exited with status 0"
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
  d_a=$(author_policy "$work/policy-a" -forward-to "$MEASUREMENT") \
      || { fail "policy-mismatch: could not author guest A's policy"; return; }
  d_b=$(author_policy "$work/policy-b" -forward-to "$MEASUREMENT" -forward-to "$(fictitious_measurement)") \
      || { fail "policy-mismatch: could not author guest B's policy"; return; }
  author_set "$work/refvals-b" -policy-digest "$wrong" || { fail "policy-mismatch: could not author guest B's set"; return; }
  author_set "$work/refvals-a" -policy-digest "$d_b"   || { fail "policy-mismatch: could not author guest A's set"; return; }
  keep_sets "$work"
  check "the two policies have distinct digests, so each names one document" \
        test -n "$d_a" -a -n "$d_b" -a "$d_a" != "$d_b"
  check "the digest emit-refvals printed for guest A's policy is the digest of the document it wrote" \
        test -n "$d_a" -a "$d_a" = "$(digest_of "$work/policy-a.json")"
  check "the digest emit-refvals printed for guest B's policy is the digest of the document it wrote" \
        test -n "$d_b" -a "$d_b" = "$(digest_of "$work/policy-b.json")"
  write_digests "$work" policy-mismatch "$d_a" "$d_b" "$wrong"

  # Both guests dial, in one boot, so that the record carries the verdicts from
  # both ends of the segment. The verdicts do not depend on who dialled — the
  # handshake verifies both ways either way — and this says so rather than
  # asserting it.
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(dialer_json guest-a 10.14.0.2 guest-b 0s 60s)" -refvals "$work/refvals-a" -policy "$work/policy-a"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a 0s 60s)" -refvals "$work/refvals-b" -policy "$work/policy-b"
  boot_pair "$work" "$IMAGE" "$IMAGE" 300 1

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "policy-mismatch: one of the guests left no console"; return; }
  assert_booted "$a" "guest-a"; assert_booted "$b" "guest-b"
  if [ "$SNP" = 0 ]; then note "control boot: nothing attests, no policy to mismatch"; return; fi
  assert_attested "$a" "guest-a"; assert_attested "$b" "guest-b"

  check "guest-a printed the digest of the policy on its own config device" \
        test "$(console_policy_digest "$a")" = "$d_a"
  check "guest-b printed the digest of the policy on its own config device" \
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
  check "guest-a's exercise failed"               in_file "$a" "init: tunneld exited with status 2"
  check "guest-b's exercise failed"               in_file "$b" "init: tunneld exited with status 2"
  check "nothing was exchanged in either direction" not_in_file "$a" "answered_by="
  check "nor in the other"                          not_in_file "$b" "answered_by="
  check "the relay found no plaintext on the wire"  in_file "$work/relay.txt" "MARKER not found"
}

# ---- scenario: two guests that pin each other (ticket 19) ------------------
# The pair ticket 18 could not author. Each guest's value names the other's
# policy digest and no other, neither value is unconstrained, and both guests
# dial — so what the record shows is two verdicts and two tunnels, not one
# verdict with the other inferred from it.
scenario_mutual() {
  local work="$OUT/mutual" seconds="${1:-300}"
  echo
  echo "### mutual: each guest's value names the other's policy digest, and both admit"
  mkdir -p "$work"
  require_author_key mutual || return
  build_emit_refvals

  # Both policies first. Neither names a digest — that is what makes the pair
  # authorable at all — so their order does not matter and neither has to exist
  # before the other.
  local d_a d_b
  d_a=$(author_policy "$work/policy-a" -forward-to "$MEASUREMENT") \
      || { fail "mutual: could not author guest A's policy"; return; }
  d_b=$(author_policy "$work/policy-b" -forward-to "$MEASUREMENT" -forward-to "$(fictitious_measurement)") \
      || { fail "mutual: could not author guest B's policy"; return; }
  check "the two policies have distinct digests, so 'each names the other' is two numbers" \
        test -n "$d_a" -a -n "$d_b" -a "$d_a" != "$d_b"

  # Then the two sets, each naming the other guest's policy and nothing else.
  author_set "$work/refvals-a" -policy-digest "$d_b" || { fail "mutual: could not author guest A's set"; return; }
  author_set "$work/refvals-b" -policy-digest "$d_a" || { fail "mutual: could not author guest B's set"; return; }
  keep_sets "$work"
  check "the digest emit-refvals printed for guest A's policy is the digest of the document it wrote" \
        test -n "$d_a" -a "$d_a" = "$(digest_of "$work/policy-a.json")"
  check "the digest emit-refvals printed for guest B's policy is the digest of the document it wrote" \
        test -n "$d_b" -a "$d_b" = "$(digest_of "$work/policy-b.json")"
  write_digests "$work" mutual "$d_a" "$d_b"

  # Both guests dial, in one boot, so the record carries both directions.
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 "$(dialer_json guest-a 10.14.0.2 guest-b "${seconds}s" 90s)" -refvals "$work/refvals-a" -policy "$work/policy-a"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 "$(dialer_json guest-b 10.14.0.3 guest-a "${seconds}s" 90s)" -refvals "$work/refvals-b" -policy "$work/policy-b"
  boot_pair "$work" "$IMAGE" "$IMAGE" "$((seconds + 240))" 1

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "mutual: one of the guests left no console"; return; }
  assert_booted "$a" "guest-a"; assert_booted "$b" "guest-b"
  if [ "$SNP" = 0 ]; then note "control boot: nothing attests, no policy to pin"; return; fi
  assert_attested "$a" "guest-a"; assert_attested "$b" "guest-b"

  # The operator's workflow, closed in both directions at once: the number
  # written into each guest's allow-list is the number the other guest prints
  # off the file it loaded.
  check "guest-a printed the digest of the policy on its own config device" \
        test "$(console_policy_digest "$a")" = "$d_a"
  check "guest-b printed the digest of the policy on its own config device" \
        test "$(console_policy_digest "$b")" = "$d_b"
  check "guest-a's value names a policy, so it reports nothing unconstrained" \
        test "$(unconstrained_lines "$a")" = "0"
  check "guest-b's value names a policy too, so neither guest admits any policy at all" \
        test "$(unconstrained_lines "$b")" = "0"

  # Each guest says whom its own policy will dial, and each list holds the image
  # the other is running.
  check "guest-a's policy says it forwards to the image on this segment" \
        grep -q "policy forward_to: measurement ${MEASUREMENT:0:16}" "$a"
  check "guest-b's policy says the same" \
        grep -q "policy forward_to: measurement ${MEASUREMENT:0:16}" "$b"

  check "guest-a admitted guest-b, whose policy digest its value names" in_file "$a" "tunneld: PEER key="
  check "guest-b admitted guest-a, whose policy digest its value names" in_file "$b" "tunneld: PEER key="
  check "guest-a refused nothing"                 not_in_file "$a" "tunneld: REFUSED"
  check "and neither did guest-b"                 not_in_file "$b" "tunneld: REFUSED"
  check "guest-a admitted at least one peer"      test "$(accepted_count "$a")" -ge 1
  check "guest-b admitted at least one peer"      test "$(accepted_count "$b")" -ge 1

  check "guest-a established a tunnel"            in_file "$a" "kind=establish"
  check "guest-b established one too"             in_file "$b" "kind=establish"
  check "guest-a exchanged over it, warm"         in_file "$a" "kind=warm_exchange"
  check "guest-b exchanged over it, warm"         in_file "$b" "kind=warm_exchange"
  check "guest-b answered guest-a's exchanges"    in_file "$a" 'answered_by="guest-b"'
  check "guest-a answered guest-b's exchanges"    in_file "$b" 'answered_by="guest-a"'
  check "guest-a's exercise completed"            in_file "$a" "init: tunneld exited with status 0"
  check "guest-b's exercise completed"            in_file "$b" "init: tunneld exited with status 0"

  check "the exchange went through the relay"     grep -q "a_to_b_frames=[1-9]" "$work/relay.txt"
  check "the relay found no plaintext on the wire" in_file "$work/relay.txt" "MARKER not found"
  local targets bad
  targets=$(sed -n 's/.*arp targets : //p' "$work/relay.txt" | head -1)
  bad=$(printf '%s' "$targets" | tr ',' '\n' | tr -d ' ' | grep -v '^$' | grep -vE '^10\.14\.0\.(2|3)$' || true)
  echo "    addresses resolved on the segment: ${targets:-none}"
  check "no guest looked for a gateway or anything else off the segment" test -z "$bad"
  grep -h "LATENCY .*kind=establish" "$a" "$b" | sed 's/^/    /' || true
}

# ---- scenario: two sandboxes on the adapter (ticket 25) --------------------
# The topology ticket 25's loopback proof runs, inside the measurement and on
# two machines that are two SEV-SNP guests: two runsc sandboxes differing only in
# their tunnel table, two tunnelds, and ticket 23's exit at each end.
#
# What each guest holds, and which half of it is measured:
#
#   measured   runsc, the flag set init launches it with, agent-probe, the
#              busybox httpd applet, /srv/index.html and /etc/hosts — so the page
#              a peer can be served and the names that reach it are in the image.
#   not        the tunnel table (which names this guest's sandbox may reach and
#              through which peer), exit-allow (what this guest's exit will dial
#              for a peer), peers.json, the run configuration and the reference
#              value set. All on the config device, which is the only reason two
#              guests booted from one image differ at all.
#   not        the bundle on the workload disk, which is one disk and the SAME
#              disk on both guests.
#
# So the two guests run identical code over identical bytes and reach different
# destinations, and the only thing that differs is a table on an unmeasured disk
# that the measured sentry enforces. The bundle fetches three URLs on both
# guests and on each guest exactly one of them is in that guest's table:
#
#   guest A   web.peer-b  permitted   -> peer guest-b -> B's exit -> B's httpd
#             web.peer-a  not in A's table: the sentry's resolver says NXDOMAIN
#             not-in-the-table.example  the same, and it is in nobody's table
#   guest B   the mirror image.
#
# The fetched page names the guest that served it — /sbin/init appends the
# sandbox_id off the config device — so "A's console says served-by: guest-b" is
# a statement about where those bytes came from and not about what A itself is
# running. A's own page says served-by: guest-a and init fetches it once before
# the workload exists, which is what separates "the page was never served" from
# "the tunnel did not carry it".
#
# httpd binds 127.0.0.1 and nothing else, so the ethernet segment between the two
# guests cannot reach either page: the only route to B's httpd is B's own exit,
# at the far end of a tunnel B admitted A on.
#
# The relay's marker is the page's own text for this scenario rather than the
# exercise payload, because there is no exercise here. It is the same claim in
# the same form: the plaintext that crossed the segment is named, every frame is
# searched for it, and the relay reports that it found none.
ADAPTER_INPUTS="${ADAPTER_INPUTS:-$REPO/docs/snp/evidence/ticket25/snp/config}"
ADAPTER_MARKER="served-by: guest-"

# exit_served CONSOLE DEST — this guest's exit took a stream a peer opened and
# dialed DEST for it.
#
# Two different lines say so and either will do. `EXIT dialed DEST -> ADDR` is
# written when the dial returns and `EXIT DEST ended` when the pump finishes, and
# both come out of serveConnect *after* net.Dial succeeded — the refusal path
# answers REFUSED and returns before either of them
# (attest/cmd/agent-probe/exit.go:153-170). So neither line can appear for a
# destination that was refused or unreachable, and one of them is enough.
#
# It takes both because run 1 lost the first of the pair on one guest and kept it
# on the other, while the fetch each describes plainly succeeded: four processes
# were writing to one serial console and the exit's longest lines are the ones
# that did not survive it (docs/snp/evidence/ticket25/snp/run/notes.md, "what did
# not hold" 1 and 2). An assertion that names one of two equivalent lines is
# asserting something about a serial port.
exit_served() { # CONSOLE DEST
  grep -qF -- "EXIT dialed $2" "$1" || grep -qF -- "EXIT $2 ended" "$1"
}

# line_of CONSOLE TEXT — the line number of the first occurrence, or nothing.
line_of() { grep -nF -m1 -- "$2" "$1" 2>/dev/null | cut -d: -f1; }
# before CONSOLE EARLIER LATER — both present, in that order.
before() {
  local e l
  e=$(line_of "$1" "$2"); l=$(line_of "$1" "$3")
  [ -n "$e" ] && [ -n "$l" ] && [ "$e" -lt "$l" ]
}

scenario_adapter() {
  local work="$OUT/adapter" seconds="$1"
  echo
  echo "### adapter: two sandboxes on the adapter, a page fetched each way, and the names that are not in the table"
  if [ -z "$WORKLOAD" ]; then
    fail "adapter: needs -workload; the sandbox that does the fetching is the bundle on that disk"
    return
  fi
  local side
  for side in a b; do
    for f in tunnel-table.json exit-allow; do
      [ -f "$ADAPTER_INPUTS/$side/$f" ] || { fail "adapter: missing $ADAPTER_INPUTS/$side/$f"; return; }
    done
  done
  mkdir -p "$work"
  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 \
      "$(adapter_json guest-a 10.14.0.2 "$((seconds + 90))s")" \
      -tunnel-table "$ADAPTER_INPUTS/a/tunnel-table.json" -exit-allow "$ADAPTER_INPUTS/a/exit-allow"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 \
      "$(adapter_json guest-b 10.14.0.3 "$((seconds + 90))s")" \
      -tunnel-table "$ADAPTER_INPUTS/b/tunnel-table.json" -exit-allow "$ADAPTER_INPUTS/b/exit-allow"
  # The two files each guest was given, kept beside its console: a reader of the
  # capture should not have to open an ext4 image to see what differed.
  for side in a b; do
    cp "$work/config-$side/tunnel-table.json" "$work/tunnel-table-$side.json" 2>/dev/null || true
    cp "$work/config-$side/exit-allow"        "$work/exit-allow-$side"        2>/dev/null || true
  done

  local saved="$MARKER"
  MARKER="$ADAPTER_MARKER"
  boot_pair "$work" "$IMAGE" "$IMAGE" "$((seconds + 240))" 1
  MARKER="$saved"

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "adapter: one of the guests left no console"; return; }
  assert_booted "$a" "guest-a"; assert_booted "$b" "guest-b"

  # The order, which is the whole shape of ticket 25's init and is checkable on
  # a control boot too: tunneld is started before the sandbox that will use it.
  local g
  for g in a b; do
    local c="$work/console-$g.txt"
    check "guest-$g: the config device's tunnel table put this guest on the adapter path" \
          in_file "$c" "init: the config device carries a tunnel table"
    check "guest-$g: tunneld was started before the workload, not after it" \
          before "$c" "in the background, ahead of the workload" "the workload device carries a bundle"
    check "guest-$g: runsc was launched with the adapter's two flags" \
          in_file "$c" "--tunnel-socket=/run/tunneld/sandbox.sock --tunnel-table=/config/tunnel-table.json"
    check "guest-$g: busybox httpd is serving the page on its own loopback" \
          in_file "$c" "init: busybox httpd is serving"
    check "guest-$g: and the page is really being served, fetched by init before any sandbox existed" \
          in_file "$c" "init: httpd says: served-by: guest-$g"
    check "guest-$g: the boot reached the end and powered off rather than being stopped" \
          in_file "$c" "init: powering off"
    check "guest-$g: no writable executable path was ever found" \
          not_in_file "$c" "WRITABLE AND EXECUTABLE"
  done

  if [ "$SNP" = 0 ]; then
    # A control boot has no report interface, so tunneld refuses to start and
    # never creates the socket. Everything above still holds and is what a
    # control boot is for: the order, the page, and a guest that stays up.
    check "control boot: tunneld refused to start rather than proceeding without evidence" \
          in_file "$b" "refusing to start"
    check "control boot: init noticed there was no socket and did not start an exit into nothing" \
          in_file "$b" "not starting the exit"
    return
  fi

  assert_attested "$a" "guest-a"; assert_attested "$b" "guest-b"
  for g in a b; do
    local c="$work/console-$g.txt"
    check "guest-$g: the sandbox socket came up for the adapter's helper to dial" \
          in_file "$c" "init: the sandbox socket is up at /run/tunneld/sandbox.sock"
    check "guest-$g: tunneld handed the socket to a sandbox in another process and stopped answering itself" \
          in_file "$c" "a sandbox in another process opens and accepts streams here"
    check "guest-$g: the exit attached and is holding the list its config device carries" \
          in_file "$c" "EXIT serving, allow="
    check "guest-$g: admitted its peer's evidence" in_file "$c" "tunneld: PEER key="
    check "guest-$g: refused nobody"              not_in_file "$c" "tunneld: REFUSED"
  done

  # The two hops, one each way. A's console can only be holding B's page if those
  # bytes crossed the segment, and the same in the other direction.
  check "guest-a's sandbox was served guest-b's page, through guest-b's exit" \
        in_file "$a" "served-by: guest-b"
  check "guest-b's sandbox was served guest-a's page, through guest-a's exit" \
        in_file "$b" "served-by: guest-a"
  check "guest-b's exit served a stream a peer opened and dialed the one destination its list permits" \
        exit_served "$b" web.peer-b:80
  check "guest-a's exit served a stream a peer opened and dialed the one destination its list permits" \
        exit_served "$a" web.peer-a:80
  # And, once for the pair rather than once per guest, the line that carries the
  # identity the far end was serving: a peer name, a vendor, a measurement and a
  # policy digest at full width. It is the strong claim and it is asked of the
  # run and not of a particular console, because which of the two consoles keeps
  # it is a property of serial contention and not of the tunnel.
  check "an exit recorded the attested identity of the peer whose stream it served" \
        grep -qF -- "EXIT accepted a stream from peer=" "$a" "$b"

  # The controls. Two per guest, and both are the sandbox being told a name does
  # not exist rather than a connection being refused: a name the table does not
  # carry is not resolved at all, so wget never gets an address to dial.
  check "guest-a: the name that is in nobody's table did not resolve inside the sandbox" \
        in_file "$a" "bad address 'not-in-the-table.example'"
  check "guest-b: the name that is in nobody's table did not resolve inside the sandbox" \
        in_file "$b" "bad address 'not-in-the-table.example'"
  check "guest-a: the peer name that is in guest-b's table and not in guest-a's did not resolve" \
        in_file "$a" "bad address 'web.peer-a'"
  check "guest-b: the peer name that is in guest-a's table and not in guest-b's did not resolve" \
        in_file "$b" "bad address 'web.peer-b'"

  # And the sandbox really was a sandbox: the sentry's own kernel string, which
  # cannot have come from either guest (ticket 24's argument, unchanged).
  check "guest-a: the fetching process was inside a gVisor sandbox" in_file "$a" "4.19.0-gvisor"
  check "guest-b: the fetching process was inside a gVisor sandbox" in_file "$b" "4.19.0-gvisor"

  check "the exchange went through the relay"      grep -q "a_to_b_frames=[1-9]" "$work/relay.txt"
  check "the relay could not find the page's text on the wire" in_file "$work/relay.txt" "MARKER not found"
  local targets bad
  targets=$(sed -n 's/.*arp targets : //p' "$work/relay.txt" | head -1)
  bad=$(printf '%s' "$targets" | tr ',' '\n' | tr -d ' ' | grep -v '^$' | grep -vE '^10\.14\.0\.(2|3)$' || true)
  echo "    addresses resolved on the segment: ${targets:-none}"
  check "no guest looked for a gateway or anything else off the segment" test -z "$bad"
}

# ---- scenario: a sandbox that honours a pushed policy (ticket 26) ----------
# Ticket 25's topology with one thing added and it is the ticket: each guest's
# tunneld pushes a policy at the other when it dials, the sentry narrows the
# table it already holds to what that policy names, and the run asks four
# questions of the result.
#
#   1. it is in force      the page the policy permits is fetched, and two
#                          controls are refused — a name nobody's policy carries
#                          (NXDOMAIN, as in ticket 25) and an exec identity the
#                          policy's `x` does not name (EACCES, new here).
#   2. it can be replaced  a SECOND tunneld on guest B pushes a narrower policy
#                          at guest A while guest A's sandbox is in the middle of
#                          a fetch. The name that policy drops stops resolving,
#                          and the stream that was already open arrives whole.
#   3. it is watched       guest A's tunneld applied guest B's first policy and
#                          watches guest A's sandbox for the digest of it; the
#                          narrowing makes that sandbox pulse a different digest,
#                          and the tunnel the first policy came in on goes.
#   4. it ends when the workload does
#                          init kills the sandbox after `kill-after` seconds, the
#                          helper's socket closes, and the tunneld beside it says
#                          so and closes the tunnel.
#
# What each guest holds, and which half of it is measured, is ticket 25's answer
# with two more unmeasured files: the policy this guest pushes and the narrower
# one it pushes second. Nothing about them is signed and nothing about them needs
# to be — what makes a pushed policy trustworthy at the far end is the evidence
# the pushing guest presented, not the disk it was read from.
#
# Why only guest B pushes a second time: tunneld's liveness rule is
# sandbox-agnostic and compares digests, so it cannot tell a narrowing from a
# different policy. Narrowing guest A therefore costs the tunnel guest B dialed
# — which is asserted — and leaves the tunnel guest A dialed alone, which is the
# one carrying guest A's long fetch. Narrowing guest B instead would have torn
# down the tunnel under the fetch and the run would have shown the opposite of
# what it set out to. docs/snp/evidence/ticket26/snp/config/README.md has the
# picture.
POLICY_INPUTS="${POLICY_INPUTS:-$REPO/docs/snp/evidence/ticket26/snp/config}"
# The sentence a tunneld writes when a policy it applied stops being live. It is
# attest/refusal.go's eleventh reason and it is read out of one variable here so
# that the day it is worded differently this is a one-line change and not six
# assertions to find.
LIVENESS_REASON="${LIVENESS_REASON:-the policy pushed to the peer is no longer live}"
# The body /run/httpd/large carries, generated by init from /dev/zero at a fixed
# size. The workload compares against the same number from the other side.
POLICY_LONG_BYTES=8388608

# The second run configuration, for the tunneld that pushes the narrower policy.
#
# `listen` is empty on purpose: it binds no port the first tunneld already holds,
# and an empty listen is the one the ceiling has no opinion about
# (attest/cmd/tunneld/runconfig.go). It carries no `link` section, because this
# guest's interface is already up — the first tunneld brought it up out of its
# own run configuration — and a second one asking for the same address would
# fail. What is left is an identity, a peer to dial and a hold: the dial is what
# makes a push happen at all, and the exchange after it is expected to fail,
# because the far end's exit reads a destination off the first line of a stream
# and this payload is not one.
narrow_json() { # SANDBOX PEER HOLD
  cat <<JSON
{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "$1-narrow",
  "listen": "",
  "limits": {"idle_timeout": "$IDLE_TIMEOUT", "max_age": "15m"},
  "exercise": {
    "dial": ["$2"],
    "wait": "2s",
    "payload": "the-second-pusher-does-not-exchange",
    "exchanges": 1,
    "concurrency": 1,
    "rounds": 1,
    "timeout": "20s"
  },
  "hold": "$3"
}
JSON
}

# Every digest a console said its sandbox applied, in the order they were
# applied. Ticket 22's applied_digest takes the first; a narrowing is the second,
# and the difference between the two is what this scenario is about.
applied_digests() { sed -n 's/.*tunneld: SANDBOX applied .*sha256=\([0-9a-f]\{64\}\).*/\1/p' "$1"; }
nth_applied()     { applied_digests "$1" | sed -n "$2p"; }
applied_count()   { applied_digests "$1" | wc -l | tr -d ' '; }
knob_of()         { tr -d ' \r\n\t' < "$1" 2>/dev/null; }

scenario_policy() {
  local work="$OUT/policy"
  echo
  echo "### policy: two sandboxes under a pushed policy, one of them narrowed while it is fetching"
  if [ -z "$WORKLOAD" ]; then
    fail "policy: needs -workload; the sandbox that does the fetching is the bundle on that disk"
    return
  fi
  local side f
  for side in a b; do
    for f in tunnel-table.json exit-allow push-policy.json push-policy-narrow.json kill-after narrow-after; do
      [ -f "$POLICY_INPUTS/$side/$f" ] || { fail "policy: missing $POLICY_INPUTS/$side/$f"; return; }
    done
  done
  mkdir -p "$work"

  local kill_a kill_b narrow_b last hold boot
  kill_a=$(knob_of "$POLICY_INPUTS/a/kill-after")
  kill_b=$(knob_of "$POLICY_INPUTS/b/kill-after")
  narrow_b=$(knob_of "$POLICY_INPUTS/b/narrow-after")
  last=$kill_a; [ "$kill_b" -gt "$last" ] && last=$kill_b
  # The hold has to outlive the last thing that happens inside the guest, and
  # the boot timeout has to outlive the hold. Neither is -run-for: this scenario
  # is driven by the knobs on the config devices and not by a wall clock the
  # harness chose, so -quick and -run-for change nothing here and the numbers
  # below are derived from the files a reader can open.
  hold=$((last + 150))
  boot=$((last + 330))
  # And the third derived number, which the first run of this scenario did not
  # have. A liveness watch is polled against the tunnel the policy arrived on and
  # ends the moment that tunnel is not live — without a line, because a watch
  # whose tunnel is gone has nothing left to tear down. With the sixty seconds
  # every other scenario uses, both tunnels here idle out about a minute after
  # the last fetch and a hundred seconds before the first kill, so a kill has
  # nothing to say to anybody. The idle timeout is therefore set to outlive this
  # scenario's own hold: the tunnels stay up until the guests power off, and what
  # ends a watch is the sandbox and not the clock.
  local IDLE_TIMEOUT="${POLICY_IDLE_TIMEOUT:-$((hold + 60))s}"
  echo "    kill-after   : guest A ${kill_a}s, guest B ${kill_b}s (seconds after each guest starts its workload)"
  echo "    narrow-after : guest B ${narrow_b}s — the second tunneld that pushes the narrower policy at guest A"
  echo "    tunneld hold : ${hold}s, boot timeout ${boot}s, both derived from the knobs and not from -run-for"
  echo "    idle timeout : $IDLE_TIMEOUT on every tunnel of this scenario, so that no tunnel a policy"
  echo "                   arrived on idles out before the kill that is supposed to end it"

  local p0a p0b p1b
  p0a=$(sha256sum "$POLICY_INPUTS/a/push-policy.json" | cut -d' ' -f1)
  p0b=$(sha256sum "$POLICY_INPUTS/b/push-policy.json" | cut -d' ' -f1)
  p1b=$(sha256sum "$POLICY_INPUTS/b/push-policy-narrow.json" | cut -d' ' -f1)
  echo "    the three documents this run turns on, and what each governs:"
  echo "      A pushes at B : $p0a  $(cat "$POLICY_INPUTS/a/push-policy.json")"
  echo "      B pushes at A : $p0b  $(cat "$POLICY_INPUTS/b/push-policy.json")"
  echo "      B pushes at A : $p1b  $(cat "$POLICY_INPUTS/b/push-policy-narrow.json")   (second, narrower)"

  make_config "$work/config-a" guest-a 10.14.0.2 guest-b 10.14.0.3:4433 \
      "$(adapter_json guest-a 10.14.0.2 "${hold}s")" \
      -tunnel-table "$POLICY_INPUTS/a/tunnel-table.json" -exit-allow "$POLICY_INPUTS/a/exit-allow" \
      -push "$POLICY_INPUTS/a/push-policy.json" \
      -push-narrow "$POLICY_INPUTS/a/push-policy-narrow.json" \
      -run-narrow "$(narrow_json guest-a guest-b "${hold}s")" \
      -knobs "$POLICY_INPUTS/a"
  make_config "$work/config-b" guest-b 10.14.0.3 guest-a 10.14.0.2:4433 \
      "$(adapter_json guest-b 10.14.0.3 "${hold}s")" \
      -tunnel-table "$POLICY_INPUTS/b/tunnel-table.json" -exit-allow "$POLICY_INPUTS/b/exit-allow" \
      -push "$POLICY_INPUTS/b/push-policy.json" \
      -push-narrow "$POLICY_INPUTS/b/push-policy-narrow.json" \
      -run-narrow "$(narrow_json guest-b guest-a "${hold}s")" \
      -knobs "$POLICY_INPUTS/b"
  # Everything each guest was given, kept beside its console: a reader of the
  # capture should not have to open an ext4 image to see what differed.
  for side in a b; do
    cp "$work/config-$side/tunnel-table.json"       "$work/tunnel-table-$side.json"       2>/dev/null || true
    cp "$work/config-$side/exit-allow"              "$work/exit-allow-$side"              2>/dev/null || true
    cp "$work/config-$side/push-policy.json"        "$work/push-policy-$side.json"        2>/dev/null || true
    cp "$work/config-$side/push-policy-narrow.json" "$work/push-policy-narrow-$side.json" 2>/dev/null || true
    cp "$work/config-$side/tunneld-narrow.json"     "$work/tunneld-narrow-$side.json"     2>/dev/null || true
    cp "$work/config-$side/kill-after"              "$work/kill-after-$side"              2>/dev/null || true
    cp "$work/config-$side/narrow-after"            "$work/narrow-after-$side"            2>/dev/null || true
  done

  local saved="$MARKER"
  MARKER="$ADAPTER_MARKER"
  boot_pair "$work" "$IMAGE" "$IMAGE" "$boot" 1
  MARKER="$saved"

  local a="$work/console-a.txt" b="$work/console-b.txt"
  [ -f "$a" ] && [ -f "$b" ] || { fail "policy: one of the guests left no console"; return; }
  assert_booted "$a" "guest-a"; assert_booted "$b" "guest-b"

  # ---- it is the run that was intended (both guests, ticket 25's checks) ----
  local g c
  for g in a b; do
    c="$work/console-$g.txt"
    check "guest-$g: the config device's tunnel table put this guest on the adapter path" \
          in_file "$c" "init: the config device carries a tunnel table"
    check "guest-$g: tunneld was started before the workload, not after it" \
          before "$c" "in the background, ahead of the workload" "the workload device carries a bundle"
    check "guest-$g: runsc was launched with the adapter's two flags" \
          in_file "$c" "--tunnel-socket=/run/tunneld/sandbox.sock --tunnel-table=/config/tunnel-table.json"
    check "guest-$g: the config device carried a policy for this guest to push" \
          in_file "$c" "init: the config device carries a policy to push: /config/push-policy.json"
    check "guest-$g: busybox httpd is serving the page on its own loopback" \
          in_file "$c" "init: busybox httpd is serving"
    check "guest-$g: and the long body beside it is the size both ends agree on" \
          in_file "$c" "init: httpd large: /run/httpd/large is $POLICY_LONG_BYTES bytes"
    check "guest-$g: the page is really being served, fetched by init before any sandbox existed" \
          in_file "$c" "init: httpd says: served-by: guest-$g"
    check "guest-$g: no writable executable path was ever found" \
          not_in_file "$c" "WRITABLE AND EXECUTABLE"
  done

  if [ "$SNP" = 0 ]; then
    check "control boot: tunneld refused to start rather than proceeding without evidence" \
          in_file "$b" "refusing to start"
    check "control boot: init noticed there was no socket and did not start an exit into nothing" \
          in_file "$b" "not starting the exit"
    return
  fi

  assert_attested "$a" "guest-a"; assert_attested "$b" "guest-b"
  for g in a b; do
    c="$work/console-$g.txt"
    check "guest-$g: the sandbox socket came up for the adapter's helper to dial" \
          in_file "$c" "init: the sandbox socket is up at /run/tunneld/sandbox.sock"
    check "guest-$g: a sandbox in another process attached to it" \
          in_file "$c" "tunneld: SANDBOX attached on /run/tunneld/sandbox.sock"
    check "guest-$g: the exit attached and is holding the list its config device carries" \
          in_file "$c" "EXIT serving, allow="
    check "guest-$g: admitted its peer's evidence" in_file "$c" "tunneld: PEER key="
    check "guest-$g: said what it was about to push, out of the file on its own config device" \
          in_file "$c" "tunneld: push policy /config/push-policy.json: format=policy version=1"
  done

  # ---- 1. the policy is in force -------------------------------------------
  # Each guest's console carries the digest of the document the OTHER guest
  # pushed, because a push is applied by the tunneld beside the sandbox it
  # governs. So A's first applied digest is the sha256 of b/push-policy.json.
  check "guest-a's sandbox was given the policy guest-b pushed, and the digest is that document's" \
        test "$(nth_applied "$a" 1)" = "$p0b"
  check "guest-b's sandbox was given the policy guest-a pushed, and the digest is that document's" \
        test "$(nth_applied "$b" 1)" = "$p0a"
  check "guest-a's sandbox was served guest-b's page, through guest-b's exit, under that policy" \
        in_file "$a" "served-by: guest-b"
  check "guest-b's sandbox was served guest-a's page, through guest-a's exit, under that policy" \
        in_file "$b" "served-by: guest-a"
  check "guest-b's exit served a stream a peer opened and dialed the one destination its list permits" \
        exit_served "$b" web.peer-b:80
  check "guest-a's exit served a stream a peer opened and dialed the one destination its list permits" \
        exit_served "$a" web.peer-a:80
  check "an exit recorded the attested identity of the peer whose stream it served" \
        grep -qF -- "EXIT accepted a stream from peer=" "$a" "$b"
  check "guest-a: the fetching process was inside a gVisor sandbox" in_file "$a" "4.19.0-gvisor"
  check "guest-b: the fetching process was inside a gVisor sandbox" in_file "$b" "4.19.0-gvisor"

  # ---- the two controls, one per letter ------------------------------------
  # N: a name no policy on this segment carries never becomes an address, so the
  # sandbox is told the name does not exist rather than that a connection was
  # refused.
  check "guest-a: the name that is in nobody's policy did not resolve inside the sandbox" \
        in_file "$a" "bad address 'not-in-the-table.example'"
  check "guest-b: the name that is in nobody's policy did not resolve inside the sandbox" \
        in_file "$b" "bad address 'not-in-the-table.example'"
  # X: an execve of a file at a path the policy's x does not name, whose sha256
  # it does not name either. The workload runs it in a loop and prints the
  # attempt on which it flipped, so the transcript carries the moment exec went
  # from unrestricted to governed rather than one attempt at a guessed time.
  check "guest-a: an exec outside the policy's x was refused inside the sandbox" \
        in_file "$a" "workload: EXEC REFUSED /bin/probe"
  check "guest-b: an exec outside the policy's x was refused inside the sandbox" \
        in_file "$b" "workload: EXEC REFUSED /bin/probe"
  check "guest-a: and it was allowed before the policy landed, so the control is a transition and not a constant" \
        in_file "$a" "no policy carrying an x is in force in this sandbox yet"

  # ---- 2. the policy can be replaced, with the workload running -------------
  check "guest-a's sandbox was given a second policy without being restarted" \
        test "$(applied_count "$a")" -ge 2
  check "and the second one is the narrower document guest-b pushed, by digest" \
        test "$(nth_applied "$a" 2)" = "$p1b"
  check "guest-b started a second tunneld to push it, rather than restarting the first" \
        in_file "$b" "init: narrow-after: ${narrow_b}s elapsed; starting a second tunneld"
  check "guest-b's own sandbox was never narrowed: one policy, one digest" \
        test "$(applied_count "$b")" = "1"
  check "guest-a's sandbox stopped resolving the name the narrower policy dropped" \
        in_file "$a" "workload: NARROWED web.peer-b stopped resolving"
  check "and the stream that was already open when that happened arrived whole" \
        in_file "$a" "workload: LONG COMPLETE bytes=$POLICY_LONG_BYTES"
  check "guest-b took the same body in one read from the other side, so the bytes are not the finding" \
        in_file "$b" "workload: LONG-B bytes=$POLICY_LONG_BYTES"

  # ---- 3. the policy is watched --------------------------------------------
  # The narrowing is a digest guest-a's tunneld was not watching for, on the
  # tunnel guest-b's FIRST tunneld opened. Tunneld does not parse n, f or x, so
  # it cannot tell a narrowing from a different policy and closes that tunnel —
  # which is the mismatch branch of the liveness rule, and it costs nothing here
  # because the stream under test is on the tunnel guest-a dialed.
  check "guest-a's tunneld noticed its sandbox pulsing a digest it was not watching for" \
        grep -qF -- "tunneld: SANDBOX liveness lost: it pulsed" "$a"
  check "and refused, naming liveness rather than inferring it from a tunnel that went quiet" \
        grep -qF -- "$LIVENESS_REASON" "$a"

  # ---- 4. the workload's exit ends liveness --------------------------------
  check "guest-a: init killed the sandbox after the seconds its config device asked for" \
        in_file "$a" "init: kill-after: ${kill_a}s elapsed"
  check "guest-b: and the same on the other guest, later" \
        in_file "$b" "init: kill-after: ${kill_b}s elapsed"
  check "guest-a: the sandbox's socket closing is what its tunneld saw, immediately and not after three misses" \
        grep -qF -- "tunneld: SANDBOX liveness lost: the sandbox closed its socket" "$a"
  check "guest-b: the same on the other guest" \
        grep -qF -- "tunneld: SANDBOX liveness lost: the sandbox closed its socket" "$b"
  check "guest-b's tunneld refused the tunnel it had applied a policy on, naming liveness" \
        grep -qF -- "$LIVENESS_REASON" "$b"
  check "guest-a: the workload was killed rather than running out of work" \
        not_in_file "$a" "nothing killed this workload"
  check "guest-b: the same" \
        not_in_file "$b" "nothing killed this workload"

  # ---- and the segment ------------------------------------------------------
  check "the exchange went through the relay"      grep -q "a_to_b_frames=[1-9]" "$work/relay.txt"
  check "the relay could not find the page's text on the wire" in_file "$work/relay.txt" "MARKER not found"
  local targets bad
  targets=$(sed -n 's/.*arp targets : //p' "$work/relay.txt" | head -1)
  bad=$(printf '%s' "$targets" | tr ',' '\n' | tr -d ' ' | grep -v '^$' | grep -vE '^10\.14\.0\.(2|3)$' || true)
  echo "    addresses resolved on the segment: ${targets:-none}"
  check "no guest looked for a gateway or anything else off the segment" test -z "$bad"

  # Not an assertion: what the sentry resolved a symlinked exec to. It decides
  # what an `x` written by path can mean and nothing in this run depends on it.
  echo "    what the sentry did with an exec through a symlink, from both guests:"
  grep -h "workload: OBSERVE exec" "$a" "$b" 2>/dev/null | sed 's/^/      /' || echo "      (no OBSERVE lines on either console)"
}

# ---- run them -------------------------------------------------------------
for s in "${SCENARIOS[@]}"; do
  case "$s" in
    live)       scenario_live live "$RUN_FOR" ;;
    live-again) scenario_live live-again 150 ;;
    push-v1)    scenario_push push-v1 1 150 ;;
    push-v2)    scenario_push push-v2 2 150 ;;
    modified)   scenario_modified ;;
    tcbfloor)   scenario_tcbfloor ;;
    nosnp)      scenario_nosnp ;;
    tamper)     scenario_tamper ;;
    stalechain) scenario_stalechain ;;
    policy-pinned)   scenario_policy_pinned ;;
    policy-mismatch) scenario_policy_mismatch ;;
    mutual)          scenario_mutual "$RUN_FOR" ;;
    adapter)         scenario_adapter "$RUN_FOR" ;;
    policy)          scenario_policy ;;
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
       "$d"/set-b.json "$d"/set-b.json.sig \
       "$d"/policy-a.json "$d"/policy-a.json.sig "$d"/policy-b.json "$d"/policy-b.json.sig \
       "$d"/push-policy.json \
       "$d"/tunnel-table-a.json "$d"/tunnel-table-b.json "$d"/exit-allow-a "$d"/exit-allow-b \
       "$d"/push-policy-a.json "$d"/push-policy-b.json \
       "$d"/push-policy-narrow-a.json "$d"/push-policy-narrow-b.json \
       "$d"/tunneld-narrow-a.json "$d"/tunneld-narrow-b.json \
       "$d"/kill-after-a "$d"/kill-after-b "$d"/narrow-after-a "$d"/narrow-after-b \
       "$CAPTURE/$n/" 2>/dev/null || true

    # The egress record, cut out of each console into a file of its own: the
    # ceiling as this image carries it, the same rule set as the kernel handed
    # it back, and the verdict on every attempt to leave. One file per guest,
    # in the shape ticket 19's TDX run recorded
    # (docs/snp/evidence/ticket19/egress/).
    #
    # The awk turns on at each EGRESS CEILING line and off at the closing brace
    # of the table under it, which is how both blocks come out whole — the text
    # the image carries and the read-back, in that order. The grep is not
    # anchored: a console is a serial line with a kernel writing to it too, and
    # a probe verdict that arrived mid-line is still the verdict.
    for g in a b; do
      c="$d/console-$g.txt"
      [ -f "$c" ] || continue
      mkdir -p "$CAPTURE/egress"
      {
        echo "### scenario $n, guest $g: the ceiling as the kernel holds it, and every attempt to leave"
        echo
        awk '/EGRESS CEILING/{f=1} f{print} /^}/{if(f)f=0}' "$c"
        echo
        grep -E 'tunneld: (EGRESS PROBE|EGRESS REFUSED|EGRESS PERMITTED|EGRESS UNROUTED|EGRESS TIMEOUT)' "$c" || true
        echo
      } > "$CAPTURE/egress/$n-guest-$g.txt"
    done
  done
  cp "$IMAGE/manifest.txt" "$IMAGE/reference-values.json" "$IMAGE/reference-values.json.sig" \
     "$IMAGE/policy.json" "$IMAGE/policy.json.sig" \
     "$IMAGE/predicted-measurement.txt" "$IMAGE/packaging.txt" "$CAPTURE/" 2>/dev/null || true
  # What ran under runsc, read back out of the read-only ext4 image itself rather
  # than copied from whatever directory the disk was built from — the disk is
  # what the guests were given, so it is the disk the record should quote. The
  # image is not copied: it is not measured, it is megabytes, and this one file
  # is what says what ran.
  if [ -n "$WORKLOAD" ]; then
    if debugfs -R "dump /config.json $CAPTURE/workload-config.json" "$WORKLOAD" >/dev/null 2>&1; then
      echo "captured the workload bundle's config.json out of $(basename "$WORKLOAD") (the disk is not measured and is not copied)"
    else
      echo "could not read config.json out of $WORKLOAD"
    fi
  fi
  echo "captured into $CAPTURE"
fi
[ "$FAILURES" = 0 ]
