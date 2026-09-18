#!/bin/bash
# Build the minimal measured guest image (ticket 06).
#
# Output: firmware, kernel, initrd, a read-only dm-verity-protected root
# filesystem image, and the kernel command line that binds them. Every byte of
# the first three and the command line is in the launch measurement; the root
# filesystem is covered transitively through the verity root hash on the
# command line. Nothing else is in the image.
#
# Ticket 07: the build then predicts the launch measurement of what it just
# built, from those inputs alone (predict-measurement.sh), and emits it as the
# signed reference value set — reference-values.json and .sig, signed with the
# author key — beside a record of every input that went into the prediction.
# Building and authorising are one step. No part of this asks a platform
# anything; see docs/snp-measurement-prediction.md.
#
# Ticket 19: it emits a second signed document beside the first,
# policy.json and .sig, which is what a guest booting this image *is* rather
# than whom it admits — the egress section, and the measurements it will dial.
#
# Ticket 22: that document is no longer delivered and is no longer what a peer
# pins. It stays here, beside the image, as the thing an authoring station
# pushes over the tunnel after attestation (docs/policy-push.md); it goes onto
# no config device, and tunneld refuses to start on one that carries it. What a
# guest presents is the digest of the egress ceiling compiled into the tunneld
# this build measures — `attest-tool ceiling -digest`, which needs no guest, no
# key and no boot — and that is the number in policy_digest below and the number
# a peer's own policy_digest names (attest/ceiling, ADR-0008).
#
# Ticket 24: the root filesystem also carries the bazel-built static runsc and
# busybox's unshare applet, and an empty /workload for the bundle the initrd
# mounts there off a disk outside the measurement. What is measured is runsc,
# the flag set /sbin/init launches it with and that mount's options; what it
# runs is not.
#
# Ticket 25: it carries three things more, and all three are measured. agent-probe
# beside tunneld, which is the exit a peer's stream is answered by; busybox's
# httpd and wget applets and an /srv/index.html for the page that exit serves;
# and /etc/hosts, which is what makes the two peer names resolve to this guest's
# own loopback when the exit dials them. The per-guest half of all of it — which
# names the sandbox may reach, through which peer, and which destinations this
# guest's exit will dial — is on the config device and is not measured, exactly
# as the reference value set is not.
#
# Rebuildable and auditable, not bit-reproducible: every input is pinned by
# hash or version, every tool version is recorded, and the manifest lists
# every file that went in. Nothing here needs root.
#
# Build parameters (environment):
#   STACK           ticket 01's host stack (default: .scratch/attested-secure-tunnel/host-stack)
#   OUT             output directory (default: $STACK/image)
#   AUTHOR_KEY      REQUIRED. The reference value author's Ed25519 private key,
#                   PKCS#8 PEM (openssl genpkey -algorithm ed25519). Signs the
#                   emitted reference value set. Its public half is baked into
#                   the root filesystem at /etc/attested-tunnel/author.pub
#                   (ADR-0004); rotating it is a new measurement.
#   AUTHOR_PUBKEY   optional cross-check: 32 raw bytes or 64 hex characters that
#                   must equal the public half of AUTHOR_KEY.
#   VCPUS           vCPU count the image is launched with (default 4). One
#                   measured VMSA per vCPU, so it is a measurement input.
#   VCPU_TYPE       QEMU -cpu model (default EPYC-v4); its signature is in each VMSA.
#   POLICY          SEV-SNP guest policy (default 0x30000); the emitted
#                   guest_policy permits exactly its bits.
#   PEER_POLICY_DIGEST
#                   optional. The peer policy the emitted reference value
#                   admits: the digest another guest's tunneld prints at start.
#                   Left UNSET it is this image's own egress ceiling, so a pair
#                   of guests booted from this image admit each other on the
#                   policy as well as on the measurement. Set and EMPTY leaves
#                   the value unconstrained, admitting a peer running the named
#                   image under any policy — the weaker reading, and what every
#                   set authored before ticket 18 says.
#   FORWARD_TO      the measurements the emitted policy says this sandbox will
#                   dial, comma separated. Unset means this image's own
#                   measurement, so two guests booting it can call each other,
#                   which is what every scenario in the harness needs. Set and
#                   empty means the sandbox dials nobody. Whatever it says, the
#                   emitted policy's digest is recorded in the manifest as
#                   emitted_policy_digest, which is an archive entry and not
#                   what any peer pins: nothing loads that document off a disk
#                   any more, and forward_to decides nothing (ticket 22).
#   TCB_FLOOR       minimum TCB the reference value admits, as
#                   bootloader,tee,snp,microcode. Default 9,0,23,72 — the level
#                   ticket 01 observed on this host. An authoring decision,
#                   recorded in the emitted artifact; not a build input.
#   Every one of VCPUS, VCPU_TYPE and POLICY must match launch-measured-guest.sh
#   (-smp, -cpu, policy=) or the prediction is for a different launch.
#   TUNNELD         required. Static binary to embed as /usr/bin/tunneld.
#                   package-tunneld.sh checks the import graph and the built
#                   artifact, builds attest/cmd/tunneld with CGO_ENABLED=0, and
#                   calls this script with TUNNELD pointing at it. Run that
#                   rather than setting this by hand — the checks have to
#                   happen before the measurement is computed, and this script
#                   computes it. There is no default: ticket 21 removed the
#                   placeholder this script used to build when TUNNELD was
#                   empty, so a build now names the binary it measures.
#   RUNSC           required. Static runsc to embed as /usr/bin/runsc, which
#                   /sbin/init launches under a user namespace with spike S1's
#                   flag set. `make runsc` is the only thing that builds it on
#                   this branch (bazel, 108 MB); package-tunneld.sh passes it
#                   through and records its sha256 beside tunneld's. Refused
#                   unless it is statically linked, for the same reason TUNNELD
#                   is: the root filesystem carries no dynamic loader, and an
#                   exec that fails inside the guest fails after the measurement
#                   is fixed. There is no default.
#   AGENT_PROBE     required. Static agent-probe to embed as /usr/bin/agent-probe
#                   (ticket 25). /sbin/init runs it in its `-exit` role when the
#                   config device carries a tunnel table: it accepts the streams
#                   a peer opens over the tunnel, reads the destination off the
#                   first line of each and dials it if the list the config device
#                   carries permits it (attest/cmd/agent-probe/exit.go). Like
#                   TUNNELD it is built by package-tunneld.sh with CGO_ENABLED=0
#                   and refused unless it is static, for the same reason: the root
#                   filesystem carries no dynamic loader. There is no default —
#                   a build names every binary it measures.
#   BUSYBOX         static busybox (default /bin/busybox from busybox-static)
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
OUT="${OUT:-$STACK/image}"
BUSYBOX="${BUSYBOX:-/bin/busybox}"
VCPUS="${VCPUS:-4}"; VCPU_TYPE="${VCPU_TYPE:-EPYC-v4}"; POLICY="${POLICY:-0x30000}"
TCB_FLOOR="${TCB_FLOOR:-9,0,23,72}"
: "${AUTHOR_KEY:?set AUTHOR_KEY to the reference value author Ed25519 private key, PKCS8 PEM}"
: "${TUNNELD:?set TUNNELD to the static binary to embed as /usr/bin/tunneld; docs/snp/image/package-tunneld.sh builds it and sets this}"
: "${RUNSC:?set RUNSC to the static runsc to embed as /usr/bin/runsc; make runsc builds it into bazel-bin/runsc/runsc_/runsc}"
: "${AGENT_PROBE:?set AGENT_PROBE to the static agent-probe to embed as /usr/bin/agent-probe; docs/snp/image/package-tunneld.sh builds it and sets this}"
export PATH="/usr/local/go/bin:$PATH"
command -v go >/dev/null || { echo "go not found; attest/README.md says how" >&2; exit 1; }

# ---- pinned inputs ---------------------------------------------------------
# From docs/snp-host-stack.md. A different firmware or kernel is a different
# measurement; refusing to build on a mismatch is what "pinned" means.
KERNEL_RELEASE=6.16.0-snp-guest-038d61fd6422
KERNEL_COMMIT=038d61fd642278bab63ee8ef722c50d10ab01e8f     # AMDESE/linux snp-guest-latest
OVMF_TAG=edk2-stable202502
OVMF_COMMIT=fbe0805b2091393406952e84724188f8c1941837       # tianocore/edk2
# AmdSevX64 firmware (BlobVerifierLibSevHashes), built by build-ovmf-amdsev.sh.
# NOT ticket 01's OVMF.fd: that is OvmfPkgX64 with BlobVerifierLibNull, under
# which kernel, initrd and command line are never measured.
OVMF_SHA256=ffd6bfa8c76c460a4dba62c39b2c9cf5a7ac425148eede7fb610f4c3cd96a895
GRUB_VERSION="2.12-1ubuntu7.3"                             # grub-efi-amd64-bin: grub image embedded in the firmware
KERNEL_SHA256=c3b443dbdafbaf3cb92d119482143a76876a752c7335a61faa917361d9724b75
BUSYBOX_VERSION="1:1.36.1-6ubuntu3.1"                     # Ubuntu busybox-static

FIRMWARE="$STACK/usr/local/share/qemu/OVMF.amdsev.fd"
KERNEL="$STACK/guest-kernel/vmlinuz-snp-guest"
MODDIR="$STACK/guest-kernel/staging/lib/modules/$KERNEL_RELEASE/kernel"
GEN_INIT_CPIO_SRC="$STACK/AMDSEV/linux/guest/usr/gen_init_cpio.c"

pin() { # pin FILE SHA256
  local got; got=$(sha256sum "$1" | cut -d' ' -f1)
  [ "$got" = "$2" ] || { echo "PINNED INPUT MISMATCH: $1 is $got, expected $2" >&2; exit 1; }
}
pin "$FIRMWARE" "$OVMF_SHA256"
pin "$KERNEL" "$KERNEL_SHA256"
BUSYBOX_PKG=$(dpkg-query -W busybox-static 2>/dev/null | cut -f2 || echo unknown)
[ "$BUSYBOX_PKG" = "$BUSYBOX_VERSION" ] \
  || echo "WARNING: busybox-static is not $BUSYBOX_VERSION; recorded in the manifest" >&2
file "$BUSYBOX" | grep -q 'statically linked' || { echo "$BUSYBOX is not static" >&2; exit 1; }

# ---- workspace -------------------------------------------------------------
B="$OUT/build"
rm -rf "$OUT"; mkdir -p "$B/rootfs" "$B/initrd"
cd "$B"

# Tools built from the checked-in sources, statically.
gcc -O2 -static -Wall -o veritymap "$HERE/veritymap.c"
gcc -O2 -static -Wall -o gen_init_cpio "$GEN_INIT_CPIO_SRC"

file "$TUNNELD" | grep -q 'statically linked' || { echo "TUNNELD $TUNNELD is not static" >&2; exit 1; }
# runsc, the same demand for the same reason, and its hash and size printed here
# rather than only in the manifest: it is the largest thing in the measurement by
# two orders of magnitude and the number belongs in the build's own output.
file "$RUNSC" | grep -qE 'statically linked|static-pie linked' || { echo "RUNSC $RUNSC is not static" >&2; exit 1; }
RUNSC_SHA256=$(sha256sum "$RUNSC" | cut -d' ' -f1)
RUNSC_BYTES=$(stat -c %s "$RUNSC")
echo "runsc sha256: $RUNSC_SHA256"
echo "runsc bytes : $RUNSC_BYTES"
file "$AGENT_PROBE" | grep -q 'statically linked' || { echo "AGENT_PROBE $AGENT_PROBE is not static" >&2; exit 1; }
AGENT_PROBE_SHA256=$(sha256sum "$AGENT_PROBE" | cut -d' ' -f1)
AGENT_PROBE_BYTES=$(stat -c %s "$AGENT_PROBE")
echo "agent-probe sha256: $AGENT_PROBE_SHA256"
echo "agent-probe bytes : $AGENT_PROBE_BYTES"

# The document emitter: the author-side half of attest/refvalsfile.go and
# attest/policyfile.go, built from source so the documents shipped are the ones
# the loader reads.
(cd "$HERE/emit-refvals" && go build -o "$B/emit-refvals" .)

# Author key: the public half of AUTHOR_KEY, as one line of 64 lowercase hex.
KEYHEX=$(openssl pkey -in "$AUTHOR_KEY" -pubout -outform DER | tail -c 32 | xxd -p | tr -d '\n')
[[ "$KEYHEX" =~ ^[0-9a-f]{64}$ ]] || { echo "AUTHOR_KEY is not an Ed25519 private key" >&2; exit 1; }
if [ -n "${AUTHOR_PUBKEY:-}" ]; then
  case "$(stat -c %s "$AUTHOR_PUBKEY")" in
    32)    GIVEN=$(xxd -p "$AUTHOR_PUBKEY" | tr -d '\n') ;;
    64|65) GIVEN=$(tr -d '\n' < "$AUTHOR_PUBKEY" | tr 'A-F' 'a-f') ;;
    *)     echo "AUTHOR_PUBKEY must be 32 raw bytes or 64 hex chars" >&2; exit 1 ;;
  esac
  [ "$GIVEN" = "$KEYHEX" ] || { echo "AUTHOR_PUBKEY $GIVEN is not the public half of AUTHOR_KEY ($KEYHEX)" >&2; exit 1; }
fi
printf '%s\n' "$KEYHEX" > author.pub

# ---- root filesystem -------------------------------------------------------
# Enumerated by hand. Applets are the ones /sbin/init uses, no more.
R="$B/rootfs"
# /workload is empty here and stays empty in the image: the initrd mounts the
# workload device over it, and a guest booted without that disk finds nothing.
mkdir -p "$R"/{bin,sbin,usr/bin,etc/attested-tunnel,lib/modules,config,proc,sys,dev,run,tmp,workload,srv}
install -m 755 "$BUSYBOX" "$R/bin/busybox"
# unshare is ticket 24's one addition: init enters a user namespace with it
# before launching runsc, which inside one needs no host capability at all
# (docs/snp/evidence/spike-s1-runsc-in-guest/README.md). The driver's other two
# applets, sh and mount, are already here.
#
# Ticket 25 adds six, and each is one line of /sbin/init's adapter branch:
# mkdir for the directory the page is written into, httpd to serve it on
# loopback, wget for the one fetch init makes of its own page so that "not
# served" and "not carried" are told apart, and kill, which ash has as a builtin
# and which is here so that the poll for the sandbox socket does not depend on
# that; and tail and wc, which put the sentry's own account of the adapter on the
# console afterwards and say how big the log it came out of was. Six applets of a
# busybox that is already measured in whole; the file count changes and no byte
# of the binary does.
ROOT_APPLETS="sh mount umount insmod cat echo sleep ls dmesg grep sed poweroff sync ip unshare mkdir httpd wget kill tail wc"
for a in $ROOT_APPLETS; do ln -s busybox "$R/bin/$a"; done
install -m 755 "$HERE/init.rootfs" "$R/sbin/init"
install -m 755 "$TUNNELD" "$R/usr/bin/tunneld"
install -m 755 "$RUNSC" "$R/usr/bin/runsc"
install -m 755 "$AGENT_PROBE" "$R/usr/bin/agent-probe"
install -m 444 author.pub "$R/etc/attested-tunnel/author.pub"
# The page this guest's exit serves, and the names that reach it (ticket 25).
#
# Both are measured and both are the same in every guest booted from this image,
# which is the point: the image says what a peer may be served and the config
# device says who this guest is. /srv/index.html is the body; /sbin/init appends
# one line naming the sandbox id it read off the run configuration, into a copy
# on /run, because one image boots both guests and a page that could not say
# which guest served it would prove nothing about where a fetch went.
#
# /etc/hosts carries BOTH peer names and points both at this guest's own
# loopback. It is not a resolver for the sandbox — the sandbox resolves through
# the sentry, which answers only what the tunnel table names — it is what the
# *exit* uses when it dials the destination a stream asked for. Both lines are in
# both guests because the image is one image: guest A's exit is asked for
# web.peer-a and guest B's for web.peer-b, and which of the two a guest is ever
# asked for is decided by the other guest's table and by this guest's own
# exit-allow list, neither of which is in here.
install -m 444 "$HERE/index.html" "$R/srv/index.html"
cat > "$R/etc/hosts" <<HOSTS
127.0.0.1	localhost
127.0.0.1	web.peer-a
127.0.0.1	web.peer-b
::1	localhost ip6-localhost ip6-loopback
HOSTS
chmod 444 "$R/etc/hosts"
install -m 444 "$MODDIR/drivers/virt/coco/guest/tsm_report.ko"   "$R/lib/modules/"
install -m 444 "$MODDIR/drivers/virt/coco/sev-guest/sev-guest.ko" "$R/lib/modules/"
# The netfilter modules the egress ceiling needs (ticket 22). This kernel builds
# nf_tables as a module, so without them a guest comes up with no ceiling at all
# and its init powers it off rather than running unconstrained — which is what
# the first boot of this image did, and what this line is the fix for. Six and no
# more: nfnetlink and nf_tables are the table, and the four reject modules are
# what lets the output chain end in a refusal the local socket can read instead
# of a silent drop (attest/ceiling/ceiling.nft). They are in rootfs.img and so
# inside the launch measurement, like every other byte the guest runs.
for m in net/netfilter/nfnetlink.ko net/netfilter/nf_tables.ko \
         net/ipv4/netfilter/nf_reject_ipv4.ko net/ipv6/netfilter/nf_reject_ipv6.ko \
         net/netfilter/nft_reject.ko net/netfilter/nft_reject_inet.ko; do
  install -m 444 "$MODDIR/$m" "$R/lib/modules/"
done

# squashfs: read-only by construction, 4 KiB padded, timestamps zeroed, all root.
mksquashfs "$R" rootfs.squashfs -comp zstd -noappend -no-xattrs -all-root \
  -mkfs-time 0 -all-time 0 -root-time 0 -no-progress -quiet
DATA_BYTES=$(stat -c %s rootfs.squashfs)
[ $((DATA_BYTES % 4096)) -eq 0 ] || { echo "squashfs not 4 KiB aligned" >&2; exit 1; }
DATABLOCKS=$((DATA_BYTES / 4096))

# dm-verity hash tree appended to the same image, no superblock: every
# parameter the kernel needs travels on the measured command line instead.
cp rootfs.squashfs "$OUT/rootfs.img"
VERITY_OUT=$(veritysetup format --no-superblock --hash-offset="$DATA_BYTES" \
  --data-block-size=4096 --hash-block-size=4096 --data-blocks="$DATABLOCKS" \
  --hash=sha256 --salt=- "$OUT/rootfs.img" "$OUT/rootfs.img")
ROOTHASH=$(echo "$VERITY_OUT" | sed -n 's/^Root hash:[[:space:]]*//p')
[[ "$ROOTHASH" =~ ^[0-9a-f]{64}$ ]] || { echo "no root hash from veritysetup:"; echo "$VERITY_OUT"; exit 1; } >&2
veritysetup verify --no-superblock --hash-offset="$DATA_BYTES" \
  --data-block-size=4096 --hash-block-size=4096 --data-blocks="$DATABLOCKS" \
  --hash=sha256 --salt=- "$OUT/rootfs.img" "$OUT/rootfs.img" "$ROOTHASH"

# ---- initrd ----------------------------------------------------------------
I="$B/initrd"
install -m 755 "$BUSYBOX" "$I/busybox"
install -m 755 "$HERE/init.initrd" "$I/init"
cp "$MODDIR/drivers/md/dm-bufio.ko" "$MODDIR/drivers/md/dm-verity.ko" "$I/"
INITRD_APPLETS="sh mount umount insmod cat echo sleep switch_root"
{
  echo "dir /dev 0755 0 0"
  echo "nod /dev/console 0600 0 0 c 5 1"
  echo "dir /proc 0755 0 0"
  echo "dir /sys 0755 0 0"
  echo "dir /newroot 0755 0 0"
  echo "dir /bin 0755 0 0"
  echo "dir /sbin 0755 0 0"
  echo "dir /lib 0755 0 0"
  echo "file /init $I/init 0755 0 0"
  echo "file /bin/busybox $I/busybox 0755 0 0"
  for a in $INITRD_APPLETS; do echo "slink /bin/$a busybox 0755 0 0"; done
  echo "file /sbin/veritymap $B/veritymap 0755 0 0"
  echo "file /lib/dm-bufio.ko $I/dm-bufio.ko 0444 0 0"
  echo "file /lib/dm-verity.ko $I/dm-verity.ko 0444 0 0"
} > initrd.list
./gen_init_cpio -t 0 initrd.list > initrd.cpio
gzip -n -9 -c initrd.cpio > "$OUT/initrd.img"

# ---- kernel, firmware, command line ---------------------------------------
cp "$KERNEL" "$OUT/vmlinuz"
cp "$FIRMWARE" "$OUT/OVMF.fd"
# HASHSTART is in hash blocks; the tree starts right after the data.
CMDLINE="console=ttyS0 earlyprintk=serial panic=-1 rdinit=/init verity.roothash=$ROOTHASH verity.salt=- verity.datablocks=$DATABLOCKS verity.hashstart=$DATABLOCKS"
printf '%s\n' "$CMDLINE" > "$OUT/cmdline.txt"

# ---- predicted measurement, the reference value set and the policy ---------
# From the four files just written plus VCPUS and VCPU_TYPE, and nothing else:
# no platform is consulted (docs/snp-measurement-prediction.md).
MEASUREMENT=$(bash "$HERE/predict-measurement.sh" "$OUT" -vcpus "$VCPUS" -vcpu-type "$VCPU_TYPE" \
                -out "$OUT/predicted-measurement.txt")
[[ "$MEASUREMENT" =~ ^[0-9a-f]{96}$ ]] || { echo "no measurement predicted" >&2; exit 1; }

# The digest a guest booted from this image presents. Since ticket 22 it is the
# name of the egress ceiling compiled into the tunneld measured in above — not
# the digest of the policy emitted further down, which no longer travels on a
# config device and which no guest loads. It is asked of the tool rather than
# computed here, because the number has exactly one definition and it lives in
# the source the binary embeds (attest/ceiling).
POLICY_DIGEST=$(cd "$REPO/attest" && GOPROXY=off go run ./cmd/attest-tool ceiling -digest)
[[ "$POLICY_DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo "attest-tool ceiling -digest printed no digest" >&2; exit 1; }
echo "egress ceiling digest: $POLICY_DIGEST (what a guest from this image presents)"

# Whom a guest booting this image admits, and under which policy. Unset means
# this image's own ceiling, so two guests from it admit each other on both; set
# and empty is the unconstrained reading, kept because the sets authored before
# ticket 18 are that shape and the harness still authors one.
DIGEST_ARGS=()
if [ -z "${PEER_POLICY_DIGEST+set}" ]; then
  DIGEST_ARGS=(-policy-digest "$POLICY_DIGEST")
elif [ -n "$PEER_POLICY_DIGEST" ]; then
  DIGEST_ARGS=(-policy-digest "$PEER_POLICY_DIGEST")
fi
EMITTED=$("$B/emit-refvals" -measurement "$MEASUREMENT" -key "$AUTHOR_KEY" -out "$OUT" \
                  -tcb "$TCB_FLOOR" -policy "$POLICY" "${DIGEST_ARGS[@]}")
printf '%s\n' "$EMITTED"

# The policy: what a guest booting this image is. Two documents since ticket 19,
# because a set that was also a policy could not be pinned in both directions
# (docs/policy-binding.md). Unset FORWARD_TO means this image's own measurement,
# so a pair of guests booted from it can call each other; set and empty means the
# sandbox dials nobody, and that is written down rather than left out.
FORWARD_ARGS=()
if [ -z "${FORWARD_TO+set}" ]; then
  FORWARD_ARGS=(-forward-to "$MEASUREMENT")
else
  IFS=',' read -r -a FORWARD_LIST <<< "$FORWARD_TO"
  for m in "${FORWARD_LIST[@]}"; do
    [ -n "$m" ] && FORWARD_ARGS+=(-forward-to "$m")
  done
fi
EMITTED_POLICY=$("$B/emit-refvals" -emit-policy -key "$AUTHOR_KEY" -out "$OUT" "${FORWARD_ARGS[@]}")
printf '%s\n' "$EMITTED_POLICY"

# The emitted policy's own digest. It was what a peer put in its policy_digest
# until ticket 22 and it is an archive entry now: the document is pushed over a
# tunnel rather than delivered on a disk, and what a peer pins is the ceiling
# digest above. It is still SHA-256 over the bytes the author signed rather than
# over the file, so it comes from the tool that knows that and never from
# sha256sum.
EMITTED_POLICY_DIGEST=$(printf '%s\n' "$EMITTED_POLICY" | sed -n 's/^policy digest: //p')
[[ "$EMITTED_POLICY_DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo "emit-refvals printed no policy digest" >&2; exit 1; }
{
  echo "# Inputs of the two documents emitted beside this file (tickets 07 and 19)."
  echo "# The launch measurement in reference-values.json is a prediction from these"
  echo "# inputs. It was not read from any machine."
  echo
  echo "reference-values.json sha256: $(sha256sum "$OUT/reference-values.json" | cut -d' ' -f1)"
  echo "policy.json sha256:           $(sha256sum "$OUT/policy.json" | cut -d' ' -f1)"
  echo "egress ceiling digest:        $POLICY_DIGEST (sha256 over attest/ceiling/ceiling.nft, compiled"
  echo "                              into the measured tunneld; this is what a guest presents and what"
  echo "                              a peer's policy_digest names since ticket 22)"
  echo "emitted policy digest:        $EMITTED_POLICY_DIGEST (sha256 over the signed policy bytes, not over"
  echo "                              the file; the document beside this one, pushed rather than delivered)"
  if [ -z "${PEER_POLICY_DIGEST+set}" ]; then
    echo "admits peer policy:           $POLICY_DIGEST (this image's own ceiling, so a guest booting it admits itself)"
  elif [ -z "$PEER_POLICY_DIGEST" ]; then
    echo "admits peer policy:           any (this value lists no policy_digest, which is the weaker reading)"
  else
    echo "admits peer policy:           $PEER_POLICY_DIGEST"
  fi
  echo "forwards to:                  $(printf '%s\n' "$EMITTED_POLICY" | sed -n 's/^forwards to[:]* //p' | paste -sd, -)"
  echo "signed by author key:         $KEYHEX (Ed25519; also at /etc/attested-tunnel/author.pub in rootfs.img)"
  echo "launch policy:                $POLICY"
  echo "tcb floor (authoring choice): $TCB_FLOOR (bootloader,tee,snp,microcode)"
  echo
  cat "$OUT/predicted-measurement.txt"
  echo
  echo "## The measured files' provenance is in manifest.txt; rootfs.img enters through"
  echo "## verity.roothash on the command line: $ROOTHASH"
} > "$OUT/reference-values.inputs.txt"

# ---- manifest --------------------------------------------------------------
{
  echo "# Measured image manifest. Built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)."
  echo
  echo "## Measured inputs. The firmware is measured directly; kernel, initrd and command line"
  echo "## enter through the SEV hashes table QEMU writes into the firmware (kernel-hashes=on);"
  echo "## rootfs.img is covered through verity.roothash on the command line."
  (cd "$OUT" && sha256sum OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img)
  echo "verity root hash: $ROOTHASH  (sha256, no salt, 4096-byte blocks, $DATABLOCKS data blocks, hash tree at block $DATABLOCKS)"
  echo
  echo "## Predicted launch measurement (offline, from the files above + vcpus=$VCPUS vcpu_type=$VCPU_TYPE; not read from a machine)"
  echo "launch_measurement: $MEASUREMENT"
  echo "emitted as reference-values.json and policy.json (+ .sig each, signed by the author key);"
  echo "inputs in reference-values.inputs.txt"
  echo
  echo "## The digest a guest booted from this image presents (ticket 22): sha256 over the egress"
  echo "## ceiling compiled into its tunneld, which attest-tool ceiling -digest prints without a guest,"
  echo "## a key or a boot. A peer admits a guest running this image under this ceiling by naming this"
  echo "## number in its own policy_digest."
  echo "policy_digest: $POLICY_DIGEST"
  echo
  echo "## The digest of policy.json beside this file: sha256 over the bytes the author signed, which is"
  echo "## not sha256sum of the file. It is on no config device and no guest loads it — it is what an"
  echo "## authoring station pushes over an established tunnel (docs/policy-push.md)."
  echo "emitted_policy_digest: $EMITTED_POLICY_DIGEST"
  echo
  echo "## Provenance"
  echo "firmware: tianocore/edk2 $OVMF_TAG $OVMF_COMMIT OvmfPkg/AmdSev/AmdSevX64.dsc, built by docs/snp/image/build-ovmf-amdsev.sh"
  echo "          embedded grub built from grub-efi-amd64-bin $(dpkg-query -W grub-efi-amd64-bin 2>/dev/null | cut -f2 || echo unknown) (pinned: $GRUB_VERSION)"
  echo "kernel:   AMDESE/linux snp-guest-latest $KERNEL_COMMIT, release $KERNEL_RELEASE"
  echo "busybox:  $BUSYBOX  busybox-static $BUSYBOX_PKG"
  echo "tunneld:  $TUNNELD"
  echo "runsc:    $RUNSC"
  echo "          sha256 $RUNSC_SHA256, $RUNSC_BYTES bytes (make runsc, bazel; installed as /usr/bin/runsc)"
  echo "agent-probe: $AGENT_PROBE"
  echo "          sha256 $AGENT_PROBE_SHA256, $AGENT_PROBE_BYTES bytes (CGO_ENABLED=0; installed as /usr/bin/agent-probe)"
  echo "author key: $KEYHEX"
  echo
  echo "## Toolchain"
  echo "gcc:         $(gcc --version | head -1)"
  echo "veritysetup: $(veritysetup --version)"
  echo "mksquashfs:  $(mksquashfs -version | head -1)"
  echo "mke2fs:      $(mke2fs -V 2>&1 | head -1)"
  echo "gzip:        $(gzip --version | head -1)"
  echo "gen_init_cpio: from the kernel tree at $KERNEL_COMMIT"
  echo
  echo "## Root filesystem contents (path sha256 mode size)"
  (cd "$R" && find . -type f -o -type l | sort | while read -r p; do
     if [ -L "$p" ]; then printf '%s -> %s\n' "$p" "$(readlink "$p")"
     else printf '%s %s %s %s\n' "$p" "$(sha256sum "$p" | cut -d' ' -f1)" "$(stat -c %a "$p")" "$(stat -c %s "$p")"; fi
   done)
  echo
  echo "## Initrd contents (gen_init_cpio list)"
  sed "s#$B/[a-z]*/##; s#$B/##" initrd.list
  echo
  echo "## Guest kernel modules"
  for m in dm-bufio dm-verity tsm_report sev-guest \
           nfnetlink nf_tables nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_reject_inet; do
    f=$(find "$MODDIR" -name "$m.ko"); echo "$m.ko $(sha256sum "$f" | cut -d' ' -f1) vermagic=$(modinfo -F vermagic "$f")"
  done
} > "$OUT/manifest.txt"

cp "$HERE"/{build-image.sh,predict-measurement.sh,init.initrd,init.rootfs,index.html,veritymap.c} "$B/" 2>/dev/null || true
echo
echo "image in $OUT:"
ls -l "$OUT" | grep -v '^d\|^total'
echo "command line: $CMDLINE"
echo "predicted launch measurement: $MEASUREMENT"
