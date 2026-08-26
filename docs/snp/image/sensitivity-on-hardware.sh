#!/bin/bash
# Milestone 2: the measured image's integrity claim, demonstrated rather than
# asserted (ticket 08).
#
#   sensitivity-on-hardware.sh [-work DIR] [-stack DIR] [-capture DIR]
#                              [-vcpus N] [-vcpu-type T] [-root-mode M]
#
# The claim under test is the one docs/snp-measured-image.md and
# docs/snp-measurement-prediction.md make: changing any byte the launch
# measurement covers moves the measurement, and a guest booted from a changed
# image is refused. Both halves of that need a confidential VM, so no unit test
# can re-establish it and the record of this run is the evidence. Everything
# printed goes to $WORK/sensitivity-run.txt as well as to the terminal, and
# -capture copies the artifacts into the repository.
#
# What it establishes, in order:
#
#   1. A baseline image is built from pinned inputs, and its launch
#      measurement is PREDICTED OFFLINE by AMD's sev-snp-measure from those
#      inputs — no platform, no /dev/sev, no report. The build signs that
#      prediction into a reference value set (ticket 07). Every verdict in this
#      run is taken against that one set.
#   2. FIVE variants of that image are produced, four of them mutations of one
#      byte each and one of them the control on the mutator:
#        none         nothing changed, both regenerated inputs rebuilt from the
#                     same staging trees — must come out byte-identical
#        rootfs-file  one hexadecimal character of the reference value author's
#                     public key inside the root filesystem (ADR-0004)
#        rootfs-byte  one byte of rootfs.img, chosen for nothing but its offset
#        initrd       one byte of a COMMENT in the initrd's /init
#        cmdline      one trailing space on the kernel command line
#      Each is predicted offline, BEFORE anything boots. The control predicts
#      the baseline's measurement exactly; every mutation predicts a different
#      one, and all of them differ from each other.
#   3. The two rootfs mutations move the measurement THROUGH THE COMMAND LINE.
#      The root filesystem is not hashed into the firmware page. It is covered
#      transitively: its dm-verity root hash is on the kernel command line, the
#      command line's SHA-256 is in the hashes table QEMU writes into the
#      firmware, and that page is measured. The run shows this by displaying
#      both command lines and both of their hashes: the only thing that changed
#      on the command line is the 64 hexadecimal characters of the root hash.
#      A reader who thinks rootfs.img is hashed directly will look for it in
#      the wrong place and conclude the wrong thing when they do not find it.
#   4. Each variant is BOOTED as a confidential guest under the image's own
#      AmdSev firmware with kernel-hashes=on, and reports its measurement. Each
#      reported measurement equals that variant's own prediction, which is what
#      makes this a demonstration rather than a readback: the expectation was
#      written down before the guest existed.
#   5. Every guest's evidence is put to cmd/verify-evidence against the
#      BASELINE's signed set, in an empty network namespace. The baseline is
#      ACCEPTED. Every mutant is REFUSED, and the internal reason names the
#      launch measurement.
#   6. The control: the baseline is accepted again after every refusal. A
#      refusal test that would also pass with the whole path broken is not
#      evidence.
#   7. An aside with consequences: dm-verity does not catch any of this. A
#      root filesystem changed together with its root hash is internally
#      consistent, mounts without complaint, and is refused only because the
#      root hash is on the measured command line.
#
# The config device is the SAME device for every boot — the provisioned
# certificate chain, the baseline's reference value set, a peer table — so
# nothing on it can account for a difference between the verdicts. It is
# outside the launch measurement by design (ADR-0004, ADR-0005).
#
# ROOT. Building, mutating, predicting and verifying need no privilege at all.
# Launching an SNP guest opens /dev/sev and needs root, and that is the only
# thing here that does. -root-mode says how to get it:
#   auto     (default) direct if already root, else sudo -n, else the spool
#   sudo     sudo bash, prompting if it must
#   spool    drop the job in $STACK/root-spool for ticket 01's root-runner.sh,
#            which the operator starts once and types the password once
#   direct   run it in this shell, which must already be root
# -no-boots stops after everything that needs neither: the image builds, the
# mutations, the offline predictions and the one control boot. That half of
# this run establishes that every mutation moves the measurement. It does not
# establish that a guest booted from a mutated image is refused, which is the
# other half and needs the hardware.
set -uo pipefail

HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
WORK=""
CAPTURE=""
VCPUS=4
VCPU_TYPE=EPYC-v4
ROOT_MODE=auto
NO_BOOTS=0
BOOT_TIMEOUT=180
SEV_SNP_MEASURE_VERSION=0.0.13

while [ -n "${1:-}" ]; do
  case "$1" in
    -work)      WORK="$2"; shift 2 ;;
    -stack)     STACK="$2"; shift 2 ;;
    -capture)   CAPTURE="$2"; shift 2 ;;
    -vcpus)     VCPUS="$2"; shift 2 ;;
    -vcpu-type) VCPU_TYPE="$2"; shift 2 ;;
    -root-mode) ROOT_MODE="$2"; shift 2 ;;
    -no-boots)  NO_BOOTS=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
WORK="${WORK:-$STACK/image-ticket08}"

export PATH=/usr/local/go/bin:$PATH
# The pinned predictor, in a virtualenv of its own under the host stack.
# A virtualenv's console scripts carry an absolute shebang to the tree that
# created them, so one built inside a worktree that has since been removed is
# unusable; this one is built here if it is not already present.
VENV="${SEV_SNP_MEASURE_VENV:-$STACK/sev-snp-measure-venv-ticket08}"
export SEV_SNP_MEASURE_VENV="$VENV"
AUTHOR_KEY="${AUTHOR_KEY:-$STACK/image-inputs/author/reference-value-author.key}"
CHAIN_DIR="${CHAIN_DIR:-$REPO/docs/snp/evidence}"
IMAGE_SCRIPTS="$REPO/docs/snp/image"
SPOOL="$STACK/root-spool"
RUNID="ticket08-$$"

mkdir -p "$WORK"
TRANSCRIPT="$WORK/sensitivity-run.txt"
exec > >(tee "$TRANSCRIPT") 2>&1

FAILURES=0
say()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '    %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
pass() { printf 'PASS: %s\n' "$*"; }
expect_eq()   { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3: got $1, want $2"; fi; }
expect_ne()   { if [ "$1" != "$2" ]; then pass "$3"; else fail "$3: both are $1"; fi; }
expect_text() { if grep -qF -- "$2" "$1"; then pass "$3"; else fail "$3: no \"$2\" in $1"; fi; }
expect_no_text() { if grep -qF -- "$2" "$1"; then fail "$3: \"$2\" appears in $1"; else pass "$3"; fi; }

# The variants. "none" is first because it is the control on the mutator: if
# regenerating an input with nothing changed did not reproduce it byte for
# byte, every other row below would be this script's doing rather than the
# mutation's. BOOT says whether a variant is expected to reach userspace.
VARIANTS="none rootfs-file rootfs-byte initrd cmdline"
describe() {
  case "$1" in
    none)        echo "control: nothing changed, both regenerated inputs rebuilt" ;;
    rootfs-file) echo "root filesystem: one hex character of /etc/attested-tunnel/author.pub" ;;
    rootfs-byte) echo "root filesystem: one byte of rootfs.img, at a fixed offset" ;;
    initrd)      echo "initrd: one byte of a comment in /init" ;;
    cmdline)     echo "kernel command line: one trailing space" ;;
  esac
}
measurement_of() { sed -n 's/^launch_measurement: //p' "$1/predicted-measurement.txt"; }

########################################################################
# run_root NAME SCRIPT_FILE — run SCRIPT_FILE as root, however this host
# allows it, and leave its output in $WORK/root-NAME.out.
########################################################################
run_root() {
  local name="$1" script="$2" out="$WORK/root-$1.out" mode="$ROOT_MODE"
  if [ "$mode" = auto ]; then
    if [ "$(id -u)" -eq 0 ]; then mode=direct
    elif sudo -n true 2>/dev/null; then mode=sudo
    else mode=spool; fi
  fi
  case "$mode" in
    direct) bash "$script" > "$out" 2>&1; echo $? > "$out.rc" ;;
    sudo)   sudo bash "$script" > "$out" 2>&1; echo $? > "$out.rc"
            sudo chown "$(id -u):$(id -g)" "$out" 2>/dev/null || true ;;
    spool)
      mkdir -p "$SPOOL"
      local job="$SPOOL/$RUNID-$name"
      # Written under another name and moved into place: the runner globs for
      # *.job every second and would otherwise pick up a half-copied file.
      cp "$script" "$job.staging"
      mv "$job.staging" "$job.job"
      note "waiting for the privileged job $RUNID-$name in $SPOOL"
      note "if nothing happens, the root runner is not started; in another terminal:"
      note "    sudo bash $STACK/root-runner.sh"
      local waited=0
      until [ -f "$job.rc" ]; do
        sleep 2; waited=$((waited + 2))
        [ $((waited % 60)) -eq 0 ] && note "still waiting (${waited}s) for $RUNID-$name"
        [ "$waited" -lt 1800 ] || { fail "the privileged job $name never ran"; echo 124 > "$out.rc"; return 1; }
      done
      cp "$job.out" "$out"; cp "$job.rc" "$out.rc"
      ;;
    *) fail "unknown -root-mode $mode"; return 1 ;;
  esac
  cat "$out"
  return 0
}

########################################################################
say "0. Provenance"
########################################################################
echo "date              : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host              : $(hostname)"
echo "repository        : $REPO at $(git -C "$REPO" rev-parse --short HEAD) ($(git -C "$REPO" rev-parse --abbrev-ref HEAD))"
echo "host kernel       : $(uname -r)"
echo "work directory    : $WORK"
echo "go                : $(go version)"
if [ ! -x "$VENV/bin/sev-snp-measure" ]; then
  python3 -m venv "$VENV" && "$VENV/bin/pip" install -q "sev-snp-measure==$SEV_SNP_MEASURE_VERSION"
fi
GOT="$("$VENV/bin/sev-snp-measure" --version | awk '{print $2}')"
[ "$GOT" = "$SEV_SNP_MEASURE_VERSION" ] || { echo "sev-snp-measure is $GOT, pinned $SEV_SNP_MEASURE_VERSION" >&2; exit 1; }
echo "predictor         : sev-snp-measure $GOT ($VENV)"
echo "qemu              : $("$STACK/usr/local/bin/qemu-system-x86_64" --version | head -1)"
echo "firmware (AmdSev) : $STACK/usr/local/share/qemu/OVMF.amdsev.fd"
echo "                    sha256 $(sha256sum "$STACK/usr/local/share/qemu/OVMF.amdsev.fd" | cut -d' ' -f1)"
echo "author key        : $AUTHOR_KEY"
echo "provisioned chain : $CHAIN_DIR/certificate-chain.bin"
echo "                    sha256 $(sha256sum "$CHAIN_DIR/certificate-chain.bin" | cut -d' ' -f1)"
echo "root mode         : $ROOT_MODE"

########################################################################
say "1. Build the baseline image, and predict its measurement offline"
########################################################################
# The image is ticket 06's, built by ticket 06's script from ticket 01's pinned
# firmware and kernel, with one substitution: /usr/bin/tunneld is
# report-evidence rather than the placeholder, because the measured image has
# no shell and no writable storage that outlives the guest, so the only way a
# bundle leaves it is the serial console. That binary acquires and prints. It
# verifies nothing; the verdict is taken on this side.
#
# The build predicts the measurement of what it just built and signs it into a
# reference value set (ticket 07). Nothing in that path reads a platform.
BASE="$WORK/base"
CGO_ENABLED=0 go -C "$IMAGE_SCRIPTS/report-evidence" build -trimpath -ldflags='-s -w' \
    -o "$WORK/report-evidence" . || { echo "cannot build report-evidence" >&2; exit 1; }
note "TUNNELD = $WORK/report-evidence ($(stat -c %s "$WORK/report-evidence") bytes, $(file -b "$WORK/report-evidence" | cut -d, -f1-3))"
AUTHOR_KEY="$AUTHOR_KEY" OUT="$BASE" TUNNELD="$WORK/report-evidence" \
  VCPUS="$VCPUS" VCPU_TYPE="$VCPU_TYPE" \
  bash "$IMAGE_SCRIPTS/build-image.sh" > "$WORK/build-base.txt" 2>&1 \
  || { cat "$WORK/build-base.txt"; echo "baseline build failed" >&2; exit 1; }
tail -12 "$WORK/build-base.txt" | sed 's/^/    /'
M_BASE="$(measurement_of "$BASE")"
[[ "$M_BASE" =~ ^[0-9a-f]{96}$ ]] || { echo "no baseline prediction" >&2; exit 1; }
echo
note "baseline predicted launch measurement: $M_BASE"
note "signed into $BASE/reference-values.json, author $(openssl pkey -in "$AUTHOR_KEY" -pubout -outform DER | tail -c 32 | xxd -p | tr -d '\n')"
note "this is the ONE reference value set every verdict below is taken against"

########################################################################
say "2. Build the five variants and predict each of them, before any boot"
########################################################################
for v in $VARIANTS; do
  printf '\n--- %s: %s ---\n' "$v" "$(describe "$v")"
  bash "$IMAGE_SCRIPTS/mutate-image.sh" -base "$BASE" -out "$WORK/$v" -mutation "$v" -quiet \
    || { fail "mutation $v failed"; continue; }
  bash "$IMAGE_SCRIPTS/predict-measurement.sh" "$WORK/$v" -vcpus "$VCPUS" -vcpu-type "$VCPU_TYPE" \
    -out "$WORK/$v/predicted-measurement.txt" > /dev/null || { fail "prediction for $v failed"; continue; }
  sed 's/^/    /' "$WORK/$v/mutation.txt"
  note "predicted launch measurement: $(measurement_of "$WORK/$v")"
done

say "2a. Assertions on the predictions — all of them offline, none of them a readback"
expect_eq "$(measurement_of "$WORK/none")" "$M_BASE" \
  "CONTROL: regenerating both inputs with nothing changed predicts the baseline measurement"
for f in OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img; do
  if cmp -s "$BASE/$f" "$WORK/none/$f"; then pass "CONTROL: $f came back byte-identical"
  else fail "CONTROL: $f differs with nothing mutated — every row below would be this script's doing"; fi
done
for v in rootfs-file rootfs-byte initrd cmdline; do
  expect_ne "$(measurement_of "$WORK/$v")" "$M_BASE" "$v moves the launch measurement"
done
DISTINCT=$(for v in rootfs-file rootfs-byte initrd cmdline; do measurement_of "$WORK/$v"; done | sort -u | wc -l)
expect_eq "$DISTINCT" "4" "the four mutations predict four different measurements, not one shared \"changed\" value"

# The files each mutation did NOT touch must be identical, or the mutation is
# not isolated and the moved measurement could be anything's doing.
untouched() { # untouched VARIANT FILES...
  local v="$1"; shift
  for f in "$@"; do
    if cmp -s "$BASE/$f" "$WORK/$v/$f"; then pass "$v left $f byte-identical"
    else fail "$v changed $f as well; the mutation is not isolated"; fi
  done
}
untouched rootfs-file OVMF.fd vmlinuz initrd.img
untouched rootfs-byte OVMF.fd vmlinuz initrd.img
untouched initrd      OVMF.fd vmlinuz cmdline.txt rootfs.img
untouched cmdline     OVMF.fd vmlinuz initrd.img rootfs.img

########################################################################
say "3. How the root filesystem gets into the measurement, since it is not hashed into the firmware"
########################################################################
# Worth spelling out because the obvious reading is wrong. The hashes table
# QEMU writes into the measured firmware page holds SHA-256 of three things:
# the kernel, the initrd and the command line. rootfs.img is not one of them
# and no digest of it is anywhere in the measurement. It is covered because its
# dm-verity root hash is a parameter ON the command line, and the command line
# is hashed. So a changed root filesystem shows up as a changed command line.
for v in rootfs-file rootfs-byte; do
  printf '\n--- %s ---\n' "$v"
  note "base command line : $(cat "$BASE/cmdline.txt")"
  note "this command line : $(cat "$WORK/$v/cmdline.txt")"
  DIFFCHARS=$( { cmp -l "$BASE/cmdline.txt" "$WORK/$v/cmdline.txt" 2>/dev/null || true; } | wc -l)
  note "characters differing on the command line: $DIFFCHARS, all of them inside verity.roothash="
  note "sha256 of the measured command line: $(printf '%s' "$(cat "$BASE/cmdline.txt")" | sha256sum | cut -d' ' -f1)"
  note "                                  -> $(printf '%s' "$(cat "$WORK/$v/cmdline.txt")" | sha256sum | cut -d' ' -f1)"
  if [ "$(sed 's/verity\.roothash=[0-9a-f]*//' "$BASE/cmdline.txt")" \
     = "$(sed 's/verity\.roothash=[0-9a-f]*//' "$WORK/$v/cmdline.txt")" ]; then
    pass "$v: the command line differs in the verity root hash and in nothing else"
  else
    fail "$v: the command line differs somewhere other than the verity root hash"
  fi
done
note ""
note "So the chain is: rootfs byte -> dm-verity root hash -> kernel command line ->"
note "the command line's SHA-256 in the hashes table -> the measured firmware page -> M."
note "There is no digest of rootfs.img in the measurement, and looking for one finds nothing."

########################################################################
say "4. The config device — one device, every boot, outside the measurement"
########################################################################
CONFIG_SRC="$WORK/config-src"
rm -rf "$CONFIG_SRC"; mkdir -p "$CONFIG_SRC"
cp "$BASE/reference-values.json" "$BASE/reference-values.json.sig" "$CONFIG_SRC/"
cp "$CHAIN_DIR/certificate-chain.bin" "$CHAIN_DIR/certificate-chain.json" "$CONFIG_SRC/"
printf '{"peers":{}}\n' > "$CONFIG_SRC/peers.json"
bash "$IMAGE_SCRIPTS/mkconfigdev.sh" "$CONFIG_SRC" "$WORK/config.img" | sed 's/^/    /'
CONFIG="$WORK/config.img"
note "the same $CONFIG is attached to all $(echo $VARIANTS | wc -w) boots and to the baseline's"
note "nothing in the guest reads reference-values.json: report-evidence acquires and prints,"
note "and the verdict is taken outside the guest by cmd/verify-evidence."

########################################################################
say "5. What dm-verity catches at runtime, and what only the measurement catches"
########################################################################
# An aside, but one that decides how much the rest of this run is worth.
#
# Ticket 06 showed that flipping a byte of rootfs.img panics the guest. That
# was a byte flipped UNDER a root hash that was left alone: dm-verity compared
# the block against a tree that no longer described it, and refused. An
# attacker who changes the root filesystem does not leave the root hash alone.
# They re-derive the tree and put the new root hash on the command line — which
# is exactly what every rootfs variant above does — and dm-verity is then
# perfectly happy, because the image is internally consistent. The rootfs-byte
# guest below boots and mounts its root without a murmur.
#
# So dm-verity protects the root filesystem against changes made underneath a
# fixed root hash. What protects the root hash itself is that it is on the
# measured command line, and nothing else does.
#
# The control boot here is the same image with a byte changed in a place the
# guest actually reads — inside a compressed block rather than in the padding —
# to show that even then it is squashfs that complains and not verity. It needs
# no root and no SNP: it is about what the guest does at runtime, not about M.
INBLOCK="$WORK/rootfs-byte-in-block"
bash "$IMAGE_SCRIPTS/mutate-image.sh" -base "$BASE" -out "$INBLOCK" -mutation rootfs-byte \
     -offset 65536 -quiet || fail "the in-block variant could not be built"
bash "$IMAGE_SCRIPTS/predict-measurement.sh" "$INBLOCK" -vcpus "$VCPUS" -vcpu-type "$VCPU_TYPE" \
     -out "$INBLOCK/predicted-measurement.txt" > /dev/null
sed 's/^/    /' "$INBLOCK/mutation.txt"
note "predicted launch measurement: $(measurement_of "$INBLOCK")"
# Two control boots, unprivileged (they need /dev/kvm and nothing else): the
# padding-byte variant, which the guest never reads, and this one, which it
# does. Neither is a confidential guest and neither has a measurement; this is
# about what the guest does at runtime.
for d in "$WORK/rootfs-byte" "$INBLOCK"; do
  printf '\n    $ launch-measured-guest.sh -no-snp -image %s\n' "$d"
  timeout "$BOOT_TIMEOUT" bash "$IMAGE_SCRIPTS/launch-measured-guest.sh" -no-snp \
      -image "$d" -config "$CONFIG" -console "$d/console-nosnp.txt" 2>&1 | sed 's/^/    /'
  tr -d '\r' < "$d/console-nosnp.txt" \
    | grep -E '^initrd: (dm-verity|root filesystem mounted)|^init: (running|tunneld)|SQUASHFS error|Kernel panic|is corrupted' \
    | sed 's/^/    /' | head -8
done
expect_ne "$(measurement_of "$INBLOCK")" "$M_BASE" "a byte inside a compressed block moves the measurement too"
expect_text "$INBLOCK/console-nosnp.txt" "SQUASHFS error" \
  "and at runtime it is squashfs that fails, on a block it cannot decompress"
expect_no_text "$INBLOCK/console-nosnp.txt" "is corrupted" \
  "dm-verity reports no corruption: the tree was re-derived, so the image agrees with its root hash"
expect_no_text "$INBLOCK/console-nosnp.txt" "dm-verity device corrupted" \
  "and nothing panicked the way ticket 06's flipped byte under a stale root hash did"
expect_no_text "$WORK/rootfs-byte/console-nosnp.txt" "SQUASHFS error" \
  "while the padding-byte variant boots cleanly, dm-verity equally content"
expect_text "$WORK/rootfs-byte/console-nosnp.txt" "root filesystem mounted read-only" \
  "its modified root filesystem mounts without a complaint from anything"
note ""
note "So: dm-verity secures the root filesystem against a change made under a fixed root hash."
note "It cannot secure the root hash. The launch measurement is what does, and it is why a"
note "self-consistent modified image — verity-clean, mounting without complaint — is still refused."

if [ "$NO_BOOTS" = 1 ]; then
  say "Stopping before the confidential boots (-no-boots)"
  note "Everything above needed no privilege and no hardware. It establishes that every"
  note "mutation moves the launch measurement, predicted offline. It does not establish"
  note "that a guest booted from a mutated image is refused; run without -no-boots for that."
  if [ "$FAILURES" -eq 0 ]; then echo; echo "THE OFFLINE HALF PASSED"; exit 0
  else echo; echo "$FAILURES CHECK(S) FAILED"; exit 1; fi
fi

########################################################################
say "6. Boot each image as a confidential guest"
########################################################################
# The only privileged step. Every launch is launch-measured-guest.sh with the
# image's own AmdSev firmware and kernel-hashes=on, which is what puts the
# kernel, initrd and command line in the measurement at all; under generic OVMF
# without that flag none of the three is measured and every row below would
# read "identical".
BOOTLIST="base $VARIANTS"
cat > "$WORK/boot.job" <<JOB
# Privileged: launching an SNP guest opens /dev/sev. Nothing else here needs root.
set -u
for v in $BOOTLIST; do
  d="$WORK/\$v"
  echo "=== booting \$v ==="
  timeout $BOOT_TIMEOUT bash "$IMAGE_SCRIPTS/launch-measured-guest.sh" \\
      -image "\$d" -config "$CONFIG" -console "\$d/console-snp.txt"
  echo "\$v: qemu exited \$?"
done
chmod -R a+rX "$WORK" 2>/dev/null
chown -R $(id -u):$(id -g) "$WORK" 2>/dev/null
JOB
echo "\$ (as root) bash $WORK/boot.job"
run_root boot "$WORK/boot.job"
BOOTRC="$(cat "$WORK/root-boot.out.rc" 2>/dev/null || echo 1)"
note "the privileged job exited $BOOTRC"

say "6a. What each guest said"
for v in $BOOTLIST; do
  d="$WORK/$v"
  printf '\n--- %s ---\n' "$v"
  if [ ! -s "$d/console-snp.txt" ]; then fail "$v: no console output"; continue; fi
  grep -E 'Memory Encryption Features active|SNP running at VMPL|^initrd: |^init: |^report-evidence: |Kernel panic' \
       "$d/console-snp.txt" | sed 's/^/    /' | head -30
done

########################################################################
say "7. Recover each bundle from its console and take a verdict on it"
########################################################################
go -C "$REPO/attest" build -o "$WORK/verify-evidence" ./cmd/verify-evidence || exit 1
AUTHOR_PUB="$WORK/author.pub"
openssl pkey -in "$AUTHOR_KEY" -pubout -outform DER | tail -c 32 | xxd -p | tr -d '\n' > "$AUTHOR_PUB"
echo >> "$AUTHOR_PUB"

# recover DIR — pull the base64 blocks report-evidence printed out of a console
# log and write them back as a bundle cmd/verify-evidence can read.
recover() {
  local d="$1" b="$1/bundle" f
  rm -rf "$b"; mkdir -p "$b"
  for f in evidence.bin certificate-chain.bin public-key.der; do
    sed -n "/^===BEGIN $f /,/^===END $f===/p" "$d/console-snp.txt" \
      | grep -v '^===' | tr -d '\r\n' | base64 -d > "$b/$f" 2>/dev/null
    [ -s "$b/$f" ] || return 1
  done
  return 0
}
REPORTED=""
for v in $BOOTLIST; do
  d="$WORK/$v"
  if recover "$d"; then
    m=$(xxd -p -s 144 -l 48 "$d/bundle/evidence.bin" | tr -d '\n')
    note "$(printf '%-12s' "$v") evidence $(stat -c %s "$d/bundle/evidence.bin") bytes, chain $(stat -c %s "$d/bundle/certificate-chain.bin") bytes, reported M $m"
    eval "REPORTED_${v//-/_}=\$m"
  else
    note "$(printf '%-12s' "$v") no bundle on the console"
    eval "REPORTED_${v//-/_}="
  fi
done

# The verdicts, in an empty network namespace, so that nothing here can have
# been rescued or refused by something it fetched. Ticket 05 established that
# property for this code; it costs nothing to hold to it.
cat > "$WORK/inside-netns.sh" <<'INNER'
set -u
WORK="$1"; shift
V="$WORK/verify-evidence"
SET="$WORK/base/reference-values.json"
echo "--- this shell's network ---"
ip -o link show; ip -o addr show
getent hosts kdsintf.amd.com; echo "getent rc=$?"
for v in "$@"; do
  echo "--- verdict on the guest booted from: $v ---"
  if [ -s "$WORK/$v/bundle/evidence.bin" ]; then
    $V -bundle "$WORK/$v/bundle" -refvals "$SET" -author "$WORK/author.pub" \
       > "$WORK/verdict-$v.txt" 2>&1
    echo $? > "$WORK/verdict-$v.rc"
    cat "$WORK/verdict-$v.txt"
  else
    echo "no bundle; nothing to verify"
    echo 127 > "$WORK/verdict-$v.rc"
  fi
done
echo "--- the control again, after every refusal above ---"
$V -bundle "$WORK/base/bundle" -refvals "$SET" -author "$WORK/author.pub" \
   > "$WORK/verdict-base-again.txt" 2>&1
echo $? > "$WORK/verdict-base-again.rc"
tail -8 "$WORK/verdict-base-again.txt"
INNER
echo "\$ unshare -rn bash $WORK/inside-netns.sh $WORK base $VARIANTS"
unshare -rn bash "$WORK/inside-netns.sh" "$WORK" base $VARIANTS > "$WORK/netns.txt" 2>&1
cat "$WORK/netns.txt"

########################################################################
say "8. Assertions on the run above"
########################################################################
expect_no_text "$WORK/netns.txt" "getent rc=0" "the namespace cannot resolve the vendor"

# The baseline: predicted before it booted, reported by the platform, accepted.
eval 'M_REPORTED_BASE=$REPORTED_base'
expect_eq "$M_REPORTED_BASE" "$M_BASE" \
  "the baseline guest reported the measurement predicted for it before it existed"
expect_eq "$(cat "$WORK/verdict-base.rc" 2>/dev/null)" "0" "CONTROL: the unmodified image is ACCEPTED"
expect_text "$WORK/verdict-base.txt" "ACCEPTED" "the verdict is acceptance"
expect_text "$WORK/verdict-base.txt" "$M_BASE" "and the accepted measurement is the predicted one"
expect_text "$WORK/verdict-base.txt" "embedded in the verification library" \
  "checked against AMD's root with no fetch and no file"

# The control variant is the baseline image rebuilt; it must be accepted too,
# or the refusals below would be about rebuilding rather than about mutating.
expect_eq "$(cat "$WORK/verdict-none.rc" 2>/dev/null)" "0" \
  "CONTROL: the variant with nothing mutated is ACCEPTED as well"
expect_eq "$REPORTED_none" "$M_BASE" \
  "CONTROL: and its guest reported the same measurement as the baseline's, on a separate launch"

for v in rootfs-file rootfs-byte initrd cmdline; do
  eval "m=\$REPORTED_${v//-/_}"
  p="$(measurement_of "$WORK/$v")"
  if [ -n "$m" ]; then
    expect_eq "$m" "$p" "$v: the guest reported the measurement predicted for it before it booted"
    expect_eq "$(cat "$WORK/verdict-$v.rc" 2>/dev/null)" "2" "$v: the guest booted from it is REFUSED"
    expect_text "$WORK/verdict-$v.txt" "launch measurement not in the reference value set" \
      "$v: and the internal reason names the measurement mismatch"
    expect_no_text "$WORK/verdict-$v.txt" "ACCEPTED" "$v: nothing accepted it"
  else
    note "$v: produced no evidence — its measurement was predicted offline and moved,"
    note "    but no guest of it reached the report interface. See the console above."
  fi
done

expect_eq "$(cat "$WORK/verdict-base-again.rc" 2>/dev/null)" "0" \
  "CONTROL: the unmodified image is still accepted after every refusal"

########################################################################
say "9. The table"
########################################################################
printf '%-13s %-58s %-9s %s\n' "variant" "what changed" "M moved" "verdict on its guest"
printf '%-13s %-58s %-9s %s\n' "-------" "------------" "-------" "--------------------"
for v in base $VARIANTS; do
  if [ "$v" = base ]; then what="nothing — the image as built"; moved="—"; else
    what="$(describe "$v")"
    if [ "$(measurement_of "$WORK/$v")" = "$M_BASE" ]; then moved="no"; else moved="yes"; fi
  fi
  case "$(cat "$WORK/verdict-$v.rc" 2>/dev/null)" in
    0)   verdict="accepted" ;;
    2)   verdict="refused: launch measurement not in the set" ;;
    127) verdict="no evidence (guest produced none)" ;;
    *)   verdict="?" ;;
  esac
  printf '%-13s %-58s %-9s %s\n' "$v" "$what" "$moved" "$verdict"
done

########################################################################
say "10. Result"
########################################################################
if [ -n "$CAPTURE" ]; then
  mkdir -p "$CAPTURE"
  cp "$BASE/reference-values.json" "$BASE/reference-values.json.sig" \
     "$BASE/reference-values.inputs.txt" "$BASE/manifest.txt" "$AUTHOR_PUB" "$CAPTURE/"
  for v in $VARIANTS; do
    mkdir -p "$CAPTURE/$v"
    cp "$WORK/$v/mutation.txt" "$WORK/$v/predicted-measurement.txt" "$CAPTURE/$v/" 2>/dev/null
    cp "$WORK/$v/console-snp.txt" "$CAPTURE/$v/" 2>/dev/null
    cp "$WORK/verdict-$v.txt" "$CAPTURE/$v/verdict.txt" 2>/dev/null
    cp "$WORK/$v/console-nosnp.txt" "$CAPTURE/$v/" 2>/dev/null
    # evidence.bin and public-key.der together are what a verifier needs to
    # replay the verdict: the report, and the key its caller-supplied bytes
    # are the digest of (ADR-0002). attest/measurementsensitivity_test.go does.
    for f in evidence.bin public-key.der; do
      [ -f "$WORK/$v/bundle/$f" ] && cp "$WORK/$v/bundle/$f" "$CAPTURE/$v/"
    done
  done
  mkdir -p "$CAPTURE/rootfs-byte-in-block"
  cp "$INBLOCK/mutation.txt" "$INBLOCK/predicted-measurement.txt" "$INBLOCK/console-nosnp.txt" \
     "$CAPTURE/rootfs-byte-in-block/" 2>/dev/null
  mkdir -p "$CAPTURE/base"
  cp "$BASE/console-snp.txt" "$CAPTURE/base/" 2>/dev/null
  cp "$BASE/last-qemu-cmdline.txt" "$CAPTURE/base/qemu-cmdline.txt" 2>/dev/null
  cp "$WORK/verdict-base.txt" "$CAPTURE/base/verdict.txt" 2>/dev/null
  cp "$WORK/verdict-base-again.txt" "$CAPTURE/base/verdict-again.txt" 2>/dev/null
  cp "$WORK/base/bundle/evidence.bin" "$WORK/base/bundle/public-key.der" "$CAPTURE/base/" 2>/dev/null
  cp "$BASE/predicted-measurement.txt" "$CAPTURE/base/" 2>/dev/null
  python3 "$REPO/docs/snp/parse-snp-report.py" "$WORK/base/bundle/evidence.bin" \
    > "$CAPTURE/base/report-decoded.txt" 2>&1
  note "artifacts copied to $CAPTURE"
fi

if [ "$FAILURES" -eq 0 ]; then
  echo
  echo "ALL CHECKS PASSED — every covered byte moves the launch measurement, each move was"
  echo "predicted offline before the guest booted, and every guest booted from a changed"
  echo "image was refused by name while the unchanged one was accepted."
  RC=0
else
  echo
  echo "$FAILURES CHECK(S) FAILED"
  RC=1
fi
[ -n "$CAPTURE" ] && cp "$TRANSCRIPT" "$CAPTURE/sensitivity-run.txt"
exit $RC
