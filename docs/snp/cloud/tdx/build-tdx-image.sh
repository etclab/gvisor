#!/bin/bash
# Build the attested-tunnel guest image for a Google Cloud TDX VM (ticket 19).
#
#   AUTHOR_KEY=author.key.pem OUT=/some/dir build-tdx-image.sh
#
# Output, in OUT: disk.raw (the image to upload), initrd.img, grub.cfg,
# predicted-measurement.txt, reference-values.json(+.sig), policy.json(+.sig),
# manifest.txt, packaging.txt.
#
# # What this build actually does, and what it deliberately does not
#
# It takes the pinned Ubuntu 24.04 GCE image and changes two files on it:
# /boot/grub/grub.cfg becomes a fixed nine-line configuration, and
# /boot/initrd.img-attested appears. Nothing else on the disk is touched. The
# ESP is not opened for writing, no partition is added, moved or resized, and
# Ubuntu's root filesystem is left exactly as the provider shipped it — it is
# never mounted by this script and never mounted by the guest either.
#
# Every one of those restraints is a measurement argument rather than tidiness:
#
#   * RTMR1 covers the EFI boot chain and the GPT (docs/tdx-verifier.md), and
#     the two values a Google VM takes there are the two the reference value
#     pins. Adding a partition would produce a third that nothing predicted.
#   * RTMR0 is the provider's firmware configuration and MRTD its firmware.
#     Neither is anything this build can reach.
#   * RTMR2 is the only register this image decides, and it is the one
#     docs/snp/cloud/tdx/predict-rtmr2.py computes from these bytes.
#
# # Why the guest is an initrd and nothing else
#
# grub measures every file it opens, whole, and the initrd is one of those
# files (proved in docs/snp/evidence/ticket19/step-zero/: an initrd boot's
# RTMR2 was predicted from the disk before the boot and matched, 88 records of
# 88). So an initrd that contains the entire guest is covered by one digest a
# verifier can recompute offline. There is no dm-verity here and no pivot to a
# root filesystem, because there is nothing left for a second integrity
# mechanism to protect: docs/snp/image/build-image.sh needed one only because
# on SEV-SNP the launch digest covers the initrd's *hash*, not a filesystem it
# later mounts.
#
# # Why grub.cfg is replaced rather than edited
#
# Ubuntu's generated grub.cfg reads grubenv, writes grubenv through save_env,
# and branches on what it finds. grubenv is measured on every boot, so a config
# that writes it is a config whose RTMR2 depends on how the previous boot went
# (docs/tdx-rtmr2-prediction.md: a boot that does not complete leaves
# recordfail=1 and moves RTMR2). Nothing on the Ubuntu side of this image will
# ever run to reset it, because Ubuntu's userspace never boots. The fixed
# config therefore contains no load_env, no save_env, no recordfail, no
# initrdfail and no os-prober output: it reads exactly three files — itself, the
# kernel and the initrd — and grubenv is never opened at all. The prediction is
# then a function of the image and of nothing else, not even of history.
#
# `update-grub` would put the generated config back, so grub.cfg is given the
# immutable flag. That is a second line of defence and the first one is
# structural: there is no userspace in this image that could run update-grub,
# because the only thing that boots is the initrd.
#
# # Build parameters (environment)
#
#   AUTHOR_KEY    REQUIRED. The reference value author's Ed25519 private key,
#                 PKCS#8 PEM. Signs both emitted documents. Its public half is
#                 baked into the initrd at /etc/attested-tunnel/author.pub and
#                 is therefore inside RTMR2 (ADR-0004); rotating it is a new
#                 measurement.
#   OUT           output directory (default $PWD/tdx-image)
#   BASE_IMAGE    the pinned raw disk image (default $OUT/../base-disk.raw)
#   BASE_SHA256   what BASE_IMAGE must hash to; the build refuses otherwise
#   KERNEL_RELEASE  which kernel in the image to boot (default: the only one)
#   KERNEL_SOURCE an unpacked Ubuntu kernel package -- a directory with
#                 ./boot/vmlinuz-<release> and ./lib/modules/<release>/ under
#                 it, as `dpkg-deb -x linux-image-<release>-gcp.deb` and
#                 `dpkg-deb -x linux-modules-<release>-gcp.deb` produce. Set it
#                 to build the same guest on a different kernel, which is a
#                 different RTMR2 and nothing else: scenario three needs two
#                 images that differ only in the kernel they name and load.
#                 Left unset the build uses the kernel the provider's image
#                 already carries and writes no new file to /boot.
#   BUSYBOX       static busybox for the initrd (default /usr/bin/busybox)
#   TUNNELD       a prebuilt static tunneld; default is to build it here, after
#                 running its guards, exactly as docs/snp/image/package-tunneld.sh
#                 does and in the same order: check, build, then measure.
#   IMAGE_LABEL   a word that goes in the image's name and the manifest
#                 (default "a"); scenario three builds a second image and needs
#                 the two to be distinguishable by name.
#   FORWARD_TO    measurements the emitted policy says this sandbox will dial,
#                 comma separated. Unset means this image's own predicted
#                 RTMR2, so two guests booted from it can call each other. Set
#                 and empty means it dials nobody.
#   PEER_MEASUREMENTS  measurements the emitted reference value set admits,
#                 comma separated. Unset means this image's own predicted
#                 RTMR2.
#   PEER_POLICY_DIGEST  the peer policy the emitted set admits. Unset means the
#                 digest of the policy this build just emitted, which is the
#                 self-pinning pair a smoke boot and scenario one need. Set and
#                 empty leaves the value unconstrained, which admits any policy
#                 and says so on every guest's console.
#   MRTD, RTMR0, RTMR1_FIRST, RTMR1_LATER, TCB_STATUS, TCB_EVALUATION
#                 the provider constants and TCB floor the set pins. Defaults
#                 are what docs/snp/evidence/tdx/refvals/ recorded on this
#                 project's VMs. None of them is predictable from anything an
#                 author holds, which is why they are observed and pinned.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT="${OUT:-$PWD/tdx-image}"
BASE_IMAGE="${BASE_IMAGE:-}"
BASE_SHA256="${BASE_SHA256:-d0b2b2c29a0bcc42c9dc414706b2b45af99fabf375150afaabcd59cd0785474f}"
BUSYBOX="${BUSYBOX:-/usr/bin/busybox}"
TUNNELD="${TUNNELD:-}"
IMAGE_LABEL="${IMAGE_LABEL:-a}"
INITRD_NAME="${INITRD_NAME:-initrd.img-attested}"

# The provider's registers, observed rather than predicted
# (docs/snp/evidence/tdx/refvals/reference-values.v20260826.json). RTMR1 takes
# one value on a VM's first boot, before the root partition is grown, and
# another on every boot after; a set naming one would refuse its own peer after
# a reboot, so both are pinned.
#
# RTMR0 IS A FUNCTION OF THE MACHINE'S SHAPE, not only of the provider's
# firmware, and this ticket found that out the hard way. Every RTMR0 recorded
# before it -- five boots across four VMs -- was c0b8b19c…896d, and every one of
# those VMs had exactly one disk. The first guest with a config device attached
# reported c2fc12a5…850a instead, and its reference value refused it.
# docs/snp/cloud/tdx/probe-tdx-rtmr0.sh then changed one thing on one instance,
# attaching a second disk and rebooting, and watched RTMR0 move
# (docs/snp/evidence/ticket19/rtmr0/). The value below is therefore the one a
# guest of THIS shape reports -- c3-standard-4, one 20GB boot disk and one 10GB
# config disk -- and an author who changes the shape has to observe it again.
# It is a comma separated list, because a set may legitimately admit more than
# one observed value the way it already does for RTMR1.
MRTD="${MRTD:-c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5}"
RTMR0="${RTMR0:-c2fc12a52db868515eff7c657e42ce04b0b7363fa6ddf7c1cca87aa8e6a061a11f9981924a600ad6d2232f75182a850a}"
RTMR1_FIRST="${RTMR1_FIRST:-02c7f19c862b3dae1592c737358d9bb13f8f0a34d3b3eca67c39bf7941a12c347635b8a291d68d9cace45b16ec25913b}"
RTMR1_LATER="${RTMR1_LATER:-3a446943925fef7f1682fd54e1b6697df864692e28592ec373860d1868582ac14ca3029c48282eb964868a785bafd691}"
TCB_STATUS="${TCB_STATUS:-UpToDate}"
TCB_EVALUATION="${TCB_EVALUATION:-20}"

: "${AUTHOR_KEY:?set AUTHOR_KEY to the reference value author Ed25519 private key, PKCS#8 PEM}"
: "${BASE_IMAGE:?set BASE_IMAGE to the pinned Ubuntu raw disk image}"
BASE_IMAGE="$(readlink -f "$BASE_IMAGE")"
export PATH="/usr/local/go/bin:$PATH"
command -v go >/dev/null || { echo "go not found; attest/README.md says how" >&2; exit 1; }
for t in debugfs e2fsck sfdisk unzstd python3 openssl; do
  command -v "$t" >/dev/null || { echo "$t not found; this build needs it" >&2; exit 1; }
done

mkdir -p "$OUT"
OUT="$(readlink -f "$OUT")"
B="$OUT/build"
rm -rf "$B"; mkdir -p "$B/initrd" "$B/modules" "$B/documents"
LOG="$OUT/packaging.txt"
exec > >(tee "$LOG") 2>&1

echo "=== build-tdx-image: $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)"
echo "repo $(git -C "$REPO" rev-parse HEAD) on $(git -C "$REPO" rev-parse --abbrev-ref HEAD)"
echo "go   $(go version)"
echo "out  $OUT"
echo

# ---- 0. the pinned base image ---------------------------------------------
echo "=== 0. the base image, pinned by hash"
GOT=$(sha256sum "$BASE_IMAGE" | cut -d' ' -f1)
[ "$GOT" = "$BASE_SHA256" ] || {
  echo "PINNED INPUT MISMATCH: $BASE_IMAGE is $GOT, expected $BASE_SHA256" >&2
  echo "A different provider image is a different RTMR0/RTMR1 and a different grub; refusing." >&2
  exit 1
}
echo "$BASE_IMAGE $GOT ($(stat -c %s "$BASE_IMAGE") bytes)"

# The GPT, read rather than assumed: the partition numbers are Ubuntu's cloud
# layout (1 root, 14 BIOS boot, 15 ESP, 16 /boot) but their offsets are the
# thing this script needs and the thing it must not guess.
eval "$(python3 - "$BASE_IMAGE" <<'PYEOF'
import json, re, subprocess, sys
table = json.loads(subprocess.check_output(["sfdisk", "-J", sys.argv[1]]))["partitiontable"]
print("SECTOR=%d" % table.get("sectorsize", 512))
for part in table["partitions"]:
    n = int(re.search(r"(\d+)$", part["node"]).group(1))
    print("PART%d_START=%d" % (n, part["start"]))
    print("PART%d_SECTORS=%d" % (n, part["size"]))
PYEOF
)"
BOOT_PART=16; ESP_PART=15; ROOT_PART=1
BOOT_OFF=$((PART16_START * SECTOR))
ROOT_OFF=$((PART1_START * SECTOR))
echo "partitions: root at byte $ROOT_OFF, ESP at byte $((PART15_START * SECTOR)), /boot at byte $BOOT_OFF"
BOOT_UUID=$(dumpe2fs -h "$BASE_IMAGE?offset=$BOOT_OFF" 2>/dev/null | sed -n 's/^Filesystem UUID: *//p')
[ -n "$BOOT_UUID" ] || { echo "could not read the /boot filesystem UUID" >&2; exit 1; }
echo "/boot filesystem UUID $BOOT_UUID (what grub's \`search --fs-uuid\` will resolve)"
echo

# ---- 1. what the provider's image supplies --------------------------------
echo "=== 1. the kernel and the modules, taken out of the image itself"
KERNEL_SOURCE="${KERNEL_SOURCE:-}"
if [ -n "$KERNEL_SOURCE" ]; then
  KERNEL_SOURCE="$(readlink -f "$KERNEL_SOURCE")"
  KERNEL_RELEASE="${KERNEL_RELEASE:-$(ls "$KERNEL_SOURCE/boot" | sed -n 's/^vmlinuz-//p' | sort | tail -1)}"
  [ -n "$KERNEL_RELEASE" ] || { echo "no boot/vmlinuz-* under $KERNEL_SOURCE" >&2; exit 1; }
  [ -d "$KERNEL_SOURCE/lib/modules/$KERNEL_RELEASE" ] \
    || { echo "no lib/modules/$KERNEL_RELEASE under $KERNEL_SOURCE" >&2; exit 1; }
  cp "$KERNEL_SOURCE/boot/vmlinuz-$KERNEL_RELEASE" "$B/vmlinuz"
  echo "kernel release $KERNEL_RELEASE, from the package unpacked at $KERNEL_SOURCE"
  echo "  it is installed into /boot as a new file; the image's own kernel is left where it is"
else
  KERNEL_RELEASE="${KERNEL_RELEASE:-$(debugfs -R "ls -p /" "$BASE_IMAGE?offset=$BOOT_OFF" 2>/dev/null |
    awk -F/ '$6 ~ /^vmlinuz-/ {print substr($6, 9)}' | sort | tail -1)}"
  [ -n "$KERNEL_RELEASE" ] || { echo "no vmlinuz-* on the /boot partition" >&2; exit 1; }
  echo "kernel release $KERNEL_RELEASE, the one the provider's image carries"
  debugfs -R "dump /vmlinuz-$KERNEL_RELEASE $B/vmlinuz" "$BASE_IMAGE?offset=$BOOT_OFF" 2>/dev/null
fi
KERNEL_SHA=$(sha256sum "$B/vmlinuz" | cut -d' ' -f1)
echo "vmlinuz-$KERNEL_RELEASE $KERNEL_SHA ($(stat -c %s "$B/vmlinuz") bytes)"

# The modules Ubuntu's gcp kernel leaves out of vmlinuz. They are pulled from
# THIS image's /lib/modules and never from the build host: a module built for
# another kernel does not load, and a module from another kernel is not what a
# verifier reading this image would find there.
if [ -n "$KERNEL_SOURCE" ]; then
  # A kernel package carries no modules.dep -- depmod writes that at install
  # time -- so the modules are found by path instead. modules.builtin is in the
  # package and is still the thing that says which of them are not there
  # because they are already in vmlinuz.
  cp "$KERNEL_SOURCE/lib/modules/$KERNEL_RELEASE/modules.builtin" "$B/modules.builtin"
  : > "$B/modules.dep"
else
  debugfs -R "dump /lib/modules/$KERNEL_RELEASE/modules.dep $B/modules.dep" "$BASE_IMAGE?offset=$ROOT_OFF" 2>/dev/null
  debugfs -R "dump /lib/modules/$KERNEL_RELEASE/modules.builtin $B/modules.builtin" "$BASE_IMAGE?offset=$ROOT_OFF" 2>/dev/null
  [ -s "$B/modules.dep" ] || { echo "no modules.dep for $KERNEL_RELEASE on the root partition" >&2; exit 1; }
fi

# In dependency order: insmod resolves nothing and there is no modprobe in the
# guest. tdx-guest is the report interface's vendor driver, gve is the NIC, and
# the four netfilter modules are what an inet table with a reject rule needs.
WANTED_MODULES="tdx-guest gve nf_tables nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_reject_inet"
for m in $WANTED_MODULES; do
  if [ -n "$KERNEL_SOURCE" ]; then
    full=$(find "$KERNEL_SOURCE/lib/modules/$KERNEL_RELEASE/kernel" -name "$m.ko" -o -name "$m.ko.zst" | head -1)
    path="${full#"$KERNEL_SOURCE/lib/modules/$KERNEL_RELEASE/"}"
  else
    path=$(sed -n "s#^\(kernel/.*/$m\.ko\(\.zst\)\?\):.*#\1#p" "$B/modules.dep" | head -1)
    full=""
  fi
  if [ -z "$path" ]; then
    if grep -q "/$m\.ko" "$B/modules.builtin"; then
      echo "  $m: built into this kernel, nothing to carry"
      continue
    fi
    echo "  $m: NOT FOUND for $KERNEL_RELEASE" >&2
    exit 1
  fi
  if [ -n "$full" ]; then
    cp "$full" "$B/modules/$(basename "$path")"
  else
    debugfs -R "dump /lib/modules/$KERNEL_RELEASE/$path $B/modules/$(basename "$path")" \
      "$BASE_IMAGE?offset=$ROOT_OFF" 2>/dev/null
  fi
  case "$path" in
    *.zst) unzstd -q -f "$B/modules/$(basename "$path")" -o "$B/modules/$m.ko" ;;
    *)     mv "$B/modules/$(basename "$path")" "$B/modules/$m.ko" ;;
  esac
  rm -f "$B/modules/$(basename "$path")"
  echo "  $m.ko $(sha256sum "$B/modules/$m.ko" | cut -d' ' -f1) $(stat -c %s "$B/modules/$m.ko") bytes from $path"
done
echo

# ---- 2. tunneld, guarded before it is measured ----------------------------
echo "=== 2. tunneld, checked before it is built and built before it is measured"
if [ -z "$TUNNELD" ]; then
  echo "\$ go test ./cmd/tunneld"
  (cd "$REPO/attest" && GOPROXY=off go test -count=1 ./cmd/tunneld) \
    || { echo "GUARD FAILED: not building an image around this binary" >&2; exit 1; }
  echo "guard passed: the packaged graph reaches no fake platform and no test support"
  TUNNELD="$B/tunneld"
  echo "\$ CGO_ENABLED=0 go build -trimpath -buildvcs=false -o $TUNNELD ./cmd/tunneld"
  (cd "$REPO/attest" && GOPROXY=off CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$TUNNELD" ./cmd/tunneld)
  if strings -a "$TUNNELD" | grep -q "$REPO"; then
    echo "REFUSING: $TUNNELD embeds the checkout path $REPO, so its measurement is not reproducible elsewhere" >&2
    exit 1
  fi
fi
file "$TUNNELD"
file "$TUNNELD" | grep -q 'statically linked' || {
  echo "REFUSING: $TUNNELD is not statically linked; the initrd carries no dynamic loader" >&2
  exit 1
}
TUNNELD_SHA=$(sha256sum "$TUNNELD" | cut -d' ' -f1)
echo "tunneld $TUNNELD_SHA ($(stat -c %s "$TUNNELD") bytes)"
file "$BUSYBOX" | grep -q 'statically linked' || { echo "$BUSYBOX is not static" >&2; exit 1; }
BUSYBOX_PKG=$(dpkg-query -W busybox-static 2>/dev/null | cut -f2 || echo unknown)
echo "busybox $BUSYBOX $(sha256sum "$BUSYBOX" | cut -d' ' -f1) (busybox-static $BUSYBOX_PKG)"
echo

# ---- 3. the author key ----------------------------------------------------
KEYHEX=$(openssl pkey -in "$AUTHOR_KEY" -pubout -outform DER | tail -c 32 | xxd -p | tr -d '\n')
[[ "$KEYHEX" =~ ^[0-9a-f]{64}$ ]] || { echo "AUTHOR_KEY is not an Ed25519 private key" >&2; exit 1; }
printf '%s\n' "$KEYHEX" > "$B/author.pub"
echo "=== 3. author public key $KEYHEX (goes into the initrd, and therefore into RTMR2)"
echo

# ---- 4. the initrd --------------------------------------------------------
echo "=== 4. the initrd: the whole guest, in one file grub measures"
I="$B/initrd"
install -m 755 "$BUSYBOX" "$I/busybox"
install -m 755 "$HERE/init.tdx" "$I/init"
install -m 755 "$TUNNELD" "$I/tunneld"
# Exactly the applets init.tdx uses. A guest with more applets than its init
# needs is a guest with more that a foothold could reach, and every byte is in
# the measurement anyway.
APPLETS="sh mount insmod cat echo printf sleep sync uname dmesg grep sed cut sort tr dd od find stat sha256sum ip poweroff"
{
  echo "# initrd of the attested tunnel guest, $KERNEL_RELEASE, label $IMAGE_LABEL"
  echo "dir /dev 0755 0 0"
  echo "nod /dev/console 0600 0 0 c 5 1"
  echo "dir /proc 0755 0 0"
  echo "dir /sys 0755 0 0"
  echo "dir /run 0755 0 0"
  echo "dir /tmp 1777 0 0"
  echo "dir /config 0755 0 0"
  echo "dir /bin 0755 0 0"
  echo "dir /sbin 0755 0 0"
  echo "dir /usr 0755 0 0"
  echo "dir /usr/bin 0755 0 0"
  echo "dir /etc 0755 0 0"
  echo "dir /etc/attested-tunnel 0755 0 0"
  echo "dir /lib 0755 0 0"
  echo "dir /lib/modules 0755 0 0"
  echo "file /init $I/init 0755 0 0"
  echo "file /bin/busybox $I/busybox 0755 0 0"
  for a in $APPLETS; do echo "slink /bin/$a busybox 0777 0 0"; done
  echo "file /usr/bin/tunneld $I/tunneld 0755 0 0"
  echo "file /etc/attested-tunnel/author.pub $B/author.pub 0444 0 0"
  for m in "$B"/modules/*.ko; do
    [ -e "$m" ] || continue
    echo "file /lib/modules/$(basename "$m") $m 0444 0 0"
  done
} > "$B/initrd.list"
python3 "$HERE/mkcpio.py" "$B/initrd.list" > "$B/initrd.cpio"
gzip -n -9 -c "$B/initrd.cpio" > "$OUT/initrd.img"
INITRD_SHA=$(sha256sum "$OUT/initrd.img" | cut -d' ' -f1)
echo "initrd.img $INITRD_SHA ($(stat -c %s "$OUT/initrd.img") bytes, from $(wc -l < "$B/initrd.list") entries)"
echo

# ---- 5. the fixed grub.cfg ------------------------------------------------
# Only constructs docs/snp/cloud/tdx/predict-rtmr2.py models, and no more of
# them than the boot needs. `set timeout=0` is not cosmetic: with no timeout
# grub waits at the menu for a keystroke that will never come.
echo "=== 5. the fixed boot configuration"
CMDLINE="console=ttyS0,115200 panic=-1 rdinit=/init"
cat > "$B/grub.cfg" <<EOF
set default=0
set timeout=0
menuentry 'attested-tunnel' {
	insmod part_gpt
	insmod ext2
	search --no-floppy --fs-uuid --set=root $BOOT_UUID
	linux	/vmlinuz-$KERNEL_RELEASE $CMDLINE
	initrd	/$INITRD_NAME
}
EOF
cp "$B/grub.cfg" "$OUT/grub.cfg"
GRUBCFG_SHA=$(sha256sum "$B/grub.cfg" | cut -d' ' -f1)
sed 's/^/  /' "$B/grub.cfg"
echo "grub.cfg $GRUBCFG_SHA ($(stat -c %s "$B/grub.cfg") bytes)"
echo

# ---- 6. the image ---------------------------------------------------------
echo "=== 6. the image: two files changed on the /boot partition, nothing else"
cp --reflink=auto --sparse=always "$BASE_IMAGE" "$OUT/disk.raw"
dd if="$OUT/disk.raw" of="$B/boot.img" bs="$SECTOR" skip="$PART16_START" count="$PART16_SECTORS" status=none
# EXT4_IMMUTABLE_FL is 0x10 and must be OR'd into the flags the inode already
# carries; overwriting them would clear EXT4_EXTENTS_FL and corrupt the file.
OLDFLAGS=$(debugfs -R "stat /grub/grub.cfg" "$B/boot.img" 2>/dev/null | sed -n 's/.*Flags: 0x\([0-9a-f]*\).*/\1/p' | head -1)
NEWFLAGS=$(printf '0x%x' $(( 0x$OLDFLAGS | 0x10 )))
echo "grub.cfg inode flags 0x$OLDFLAGS -> $NEWFLAGS (immutable set)"
# When the kernel came out of a package rather than out of the image, it has to
# be put where grub.cfg says it is. It is a new file beside the provider's own
# kernel rather than a replacement for it: nothing reads the provider's any
# more, and leaving it alone is one less byte changed.
INSTALL_KERNEL_CMDS=""
if [ -n "$KERNEL_SOURCE" ]; then
  INSTALL_KERNEL_CMDS="write $B/vmlinuz vmlinuz-$KERNEL_RELEASE
sif vmlinuz-$KERNEL_RELEASE mode 0100400
sif vmlinuz-$KERNEL_RELEASE uid 0
sif vmlinuz-$KERNEL_RELEASE gid 0
sif vmlinuz-$KERNEL_RELEASE atime @0
sif vmlinuz-$KERNEL_RELEASE mtime @0
sif vmlinuz-$KERNEL_RELEASE ctime @0
sif vmlinuz-$KERNEL_RELEASE crtime @0"
  debugfs -w -R "rm /vmlinuz-$KERNEL_RELEASE" "$B/boot.img" >/dev/null 2>&1 || true
fi
cat > "$B/debugfs.cmds" <<EOF
rm /grub/grub.cfg
cd /grub
write $B/grub.cfg grub.cfg
sif grub.cfg mode 0100444
sif grub.cfg uid 0
sif grub.cfg gid 0
sif grub.cfg flags $NEWFLAGS
sif grub.cfg atime @0
sif grub.cfg mtime @0
sif grub.cfg ctime @0
sif grub.cfg crtime @0
cd /
$INSTALL_KERNEL_CMDS
write $OUT/initrd.img $INITRD_NAME
sif $INITRD_NAME mode 0100444
sif $INITRD_NAME uid 0
sif $INITRD_NAME gid 0
sif $INITRD_NAME atime @0
sif $INITRD_NAME mtime @0
sif $INITRD_NAME ctime @0
sif $INITRD_NAME crtime @0
EOF
debugfs -w -f "$B/debugfs.cmds" "$B/boot.img" > "$B/debugfs.log" 2>&1
grep -iE 'error|not found|failed' "$B/debugfs.log" && { echo "debugfs reported a problem; see $B/debugfs.log" >&2; exit 1; }
e2fsck -f -y "$B/boot.img" > "$B/e2fsck.log" 2>&1 || {
  echo "e2fsck did not return clean on the rewritten /boot; see $B/e2fsck.log" >&2
  tail -20 "$B/e2fsck.log" >&2
  exit 1
}
tail -2 "$B/e2fsck.log"
dd if="$B/boot.img" of="$OUT/disk.raw" bs="$SECTOR" seek="$PART16_START" count="$PART16_SECTORS" conv=notrunc status=none
DISK_SHA=$(sha256sum "$OUT/disk.raw" | cut -d' ' -f1)
echo "disk.raw $DISK_SHA ($(stat -c %s "$OUT/disk.raw") bytes)"
# The ESP is not written by this build, and the record says so by hashing it
# before and after nothing happened to it.
ESP_BEFORE=$(dd if="$BASE_IMAGE" bs="$SECTOR" skip="$PART15_START" count="$PART15_SECTORS" status=none | sha256sum | cut -d' ' -f1)
ESP_AFTER=$(dd if="$OUT/disk.raw" bs="$SECTOR" skip="$PART15_START" count="$PART15_SECTORS" status=none | sha256sum | cut -d' ' -f1)
[ "$ESP_BEFORE" = "$ESP_AFTER" ] || { echo "the ESP changed; this build must not touch it" >&2; exit 1; }
ROOT_BEFORE=$(dd if="$BASE_IMAGE" bs="$SECTOR" skip="$PART1_START" count="$PART1_SECTORS" status=none | sha256sum | cut -d' ' -f1)
ROOT_AFTER=$(dd if="$OUT/disk.raw" bs="$SECTOR" skip="$PART1_START" count="$PART1_SECTORS" status=none | sha256sum | cut -d' ' -f1)
[ "$ROOT_BEFORE" = "$ROOT_AFTER" ] || { echo "Ubuntu's root partition changed; this build must not touch it" >&2; exit 1; }
echo "ESP unchanged ($ESP_AFTER); Ubuntu's root partition unchanged ($ROOT_AFTER)"
GPT_BEFORE=$(dd if="$BASE_IMAGE" bs=512 count=34 status=none | sha256sum | cut -d' ' -f1)
GPT_AFTER=$(dd if="$OUT/disk.raw" bs=512 count=34 status=none | sha256sum | cut -d' ' -f1)
[ "$GPT_BEFORE" = "$GPT_AFTER" ] || { echo "the GPT changed; RTMR1 covers it" >&2; exit 1; }
echo "GPT unchanged ($GPT_AFTER); RTMR1 keeps the two values the reference value pins"
echo

# ---- 7. the prediction ----------------------------------------------------
echo "=== 7. RTMR2, predicted from the image just built and from nothing else"
python3 "$HERE/predict-rtmr2.py" --raw "$OUT/disk.raw" > "$OUT/predicted-measurement.txt" 2>&1 || {
  echo "the predictor refused this image:" >&2
  tail -20 "$OUT/predicted-measurement.txt" >&2
  exit 1
}
RTMR2=$(sed -n 's/^RTMR2 predicted     : //p' "$OUT/predicted-measurement.txt")
[[ "$RTMR2" =~ ^[0-9a-f]{96}$ ]] || { echo "no RTMR2 predicted" >&2; tail -5 "$OUT/predicted-measurement.txt" >&2; exit 1; }
RECORDS=$(sed -n 's/^records predicted   : //p' "$OUT/predicted-measurement.txt")
echo "predicted RTMR2 $RTMR2 over $RECORDS records"
echo

# ---- 8. the two signed documents ------------------------------------------
echo "=== 8. the policy and the reference value set"
(cd "$REPO/docs/snp/image/emit-refvals" && GOPROXY=off go build -o "$B/emit-refvals" .)
(cd "$HERE/emit-tdx-refvals" && GOPROXY=off go build -o "$B/emit-tdx-refvals" .)

# The policy first, because the set names its digest. Unset FORWARD_TO means
# this image's own measurement, so a pair of guests booted from it can call
# each other; set and empty means the sandbox dials nobody, written down rather
# than left out.
FORWARD_ARGS=()
if [ -z "${FORWARD_TO+set}" ]; then
  FORWARD_ARGS=(-forward-to "$RTMR2")
else
  IFS=',' read -r -a FORWARD_LIST <<< "$FORWARD_TO"
  for m in "${FORWARD_LIST[@]}"; do [ -n "$m" ] && FORWARD_ARGS+=(-forward-to "$m"); done
fi
EMITTED_POLICY=$("$B/emit-refvals" -emit-policy -key "$AUTHOR_KEY" -out "$OUT" "${FORWARD_ARGS[@]}")
printf '%s\n' "$EMITTED_POLICY"
POLICY_DIGEST=$(printf '%s\n' "$EMITTED_POLICY" | sed -n 's/^policy digest: //p')
[[ "$POLICY_DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo "emit-refvals printed no policy digest" >&2; exit 1; }

MEASUREMENT_ARGS=(-rtmr2 "$RTMR2")
if [ -n "${PEER_MEASUREMENTS:-}" ]; then
  # emit-tdx-refvals writes one reference value, so a set admitting several
  # images is several runs of it merged by hand; until a scenario needs that,
  # the first measurement is used and the rest are refused loudly rather than
  # silently dropped.
  IFS=',' read -r -a PEER_LIST <<< "$PEER_MEASUREMENTS"
  [ "${#PEER_LIST[@]}" -eq 1 ] || { echo "PEER_MEASUREMENTS names ${#PEER_LIST[@]} measurements; emit-tdx-refvals writes one reference value" >&2; exit 1; }
  MEASUREMENT_ARGS=(-rtmr2 "${PEER_LIST[0]}")
fi
DIGEST_ARGS=()
if [ -z "${PEER_POLICY_DIGEST+set}" ]; then
  DIGEST_ARGS=(-policy-digest "$POLICY_DIGEST")
elif [ -n "$PEER_POLICY_DIGEST" ]; then
  DIGEST_ARGS=(-policy-digest "$PEER_POLICY_DIGEST")
fi
RTMR0_ARGS=()
IFS=',' read -r -a RTMR0_LIST <<< "$RTMR0"
for r in "${RTMR0_LIST[@]}"; do [ -n "$r" ] && RTMR0_ARGS+=(-rtmr0 "$r"); done
EMITTED_SET=$("$B/emit-tdx-refvals" "${MEASUREMENT_ARGS[@]}" \
  -mrtd "$MRTD" "${RTMR0_ARGS[@]}" -rtmr1 "$RTMR1_FIRST" -rtmr1 "$RTMR1_LATER" \
  -tcb-status "$TCB_STATUS" -tcb-evaluation "$TCB_EVALUATION" \
  "${DIGEST_ARGS[@]}" -key "$AUTHOR_KEY" -out "$OUT")
printf '%s\n' "$EMITTED_SET"
echo

# ---- 9. the manifest ------------------------------------------------------
ADMITS_MEASUREMENT="${PEER_MEASUREMENTS:-$RTMR2 (this image itself)}"
if [ -z "${PEER_POLICY_DIGEST+set}" ]; then
  ADMITS_POLICY="$POLICY_DIGEST (the policy this build emitted, so a guest booting this image admits itself)"
elif [ -z "$PEER_POLICY_DIGEST" ]; then
  ADMITS_POLICY="any policy (this value lists no policy_digest, which is the weaker reading)"
else
  ADMITS_POLICY="$PEER_POLICY_DIGEST"
fi
{
  echo "# Attested tunnel guest image for Google Cloud TDX. Built $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)."
  echo "# label: $IMAGE_LABEL"
  echo
  echo "## The measurement"
  echo "predicted_rtmr2: $RTMR2"
  echo "records:         $RECORDS (predict-rtmr2.py --raw, offline; no machine was asked)"
  echo "policy_digest:   $POLICY_DIGEST (sha256 over the bytes the author signed over policy.json,"
  echo "                 which is not sha256sum of the file; a peer names this in its policy_digest)"
  echo
  echo "## Every input the measurement covers"
  echo "base_image:      $BASE_IMAGE $BASE_SHA256"
  echo "disk.raw:        $DISK_SHA"
  echo "grub.cfg:        $GRUBCFG_SHA ($(stat -c %s "$B/grub.cfg") bytes), installed at /boot/grub/grub.cfg, immutable flag set"
  echo "kernel:          vmlinuz-$KERNEL_RELEASE $KERNEL_SHA ${KERNEL_SOURCE:+(installed from the package unpacked at $KERNEL_SOURCE)}"
  echo "initrd:          /$INITRD_NAME $INITRD_SHA ($(stat -c %s "$OUT/initrd.img") bytes)"
  echo "kernel cmdline:  $CMDLINE"
  echo "boot fs uuid:    $BOOT_UUID"
  echo
  echo "## What was NOT changed, checked byte for byte after the rewrite"
  echo "esp (gpt15):     $ESP_AFTER"
  echo "root (gpt1):     $ROOT_AFTER  (Ubuntu's root; never mounted, by this build or by the guest)"
  echo "gpt:             $GPT_AFTER   (no partition added, moved or resized, so RTMR1 keeps its two values)"
  echo
  echo "## update-grub cannot move grub.cfg's bytes"
  echo "There is no userspace in this image that could run it: grub loads the initrd and the initrd"
  echo "is the guest, so Ubuntu's /sbin/init never executes. The immutable flag on the inode is the"
  echo "second line of defence, not the first. The configuration itself reads grubenv nowhere --"
  echo "no load_env, no save_env, no recordfail, no initrdfail -- so RTMR2 does not depend on how"
  echo "any previous boot ended, which is the one way docs/tdx-rtmr2-prediction.md found for a"
  echo "pristine image's RTMR2 to move."
  echo
  echo "## Initrd contents (path sha256 mode size)"
  echo "/init            $(sha256sum "$I/init" | cut -d' ' -f1) 0755 $(stat -c %s "$I/init")"
  echo "/bin/busybox     $(sha256sum "$I/busybox" | cut -d' ' -f1) 0755 $(stat -c %s "$I/busybox")  (busybox-static $BUSYBOX_PKG)"
  echo "/usr/bin/tunneld $TUNNELD_SHA 0755 $(stat -c %s "$TUNNELD")"
  echo "/etc/attested-tunnel/author.pub $(sha256sum "$B/author.pub" | cut -d' ' -f1) 0444 $(stat -c %s "$B/author.pub")"
  for m in "$B"/modules/*.ko; do
    [ -e "$m" ] || continue
    printf '/lib/modules/%-18s %s 0444 %s\n' "$(basename "$m")" "$(sha256sum "$m" | cut -d' ' -f1)" "$(stat -c %s "$m")"
  done
  echo "applets (symlinks to busybox): $APPLETS"
  echo
  echo "## The two signed documents (they ship on the config device, outside the measurement)"
  echo "reference-values.json sha256: $(sha256sum "$OUT/reference-values.json" | cut -d' ' -f1)"
  echo "policy.json sha256:           $(sha256sum "$OUT/policy.json" | cut -d' ' -f1)"
  echo "signed by author key:         $KEYHEX (also at /etc/attested-tunnel/author.pub, inside RTMR2)"
  echo "admits measurement:           $ADMITS_MEASUREMENT"
  echo "admits peer policy:           $ADMITS_POLICY"
  echo "forwards to:                  $(printf '%s\n' "$EMITTED_POLICY" | sed -n 's/^forwards to: //p' | paste -sd, -)"
  echo "provider constants pinned:    mrtd $MRTD"
  for r in "${RTMR0_LIST[@]}"; do echo "                              rtmr0 $r"; done
  echo "                              rtmr1 $RTMR1_FIRST (first boot)"
  echo "                              rtmr1 $RTMR1_LATER (every boot after)"
  echo "tcb floor:                    $TCB_STATUS, evaluation $TCB_EVALUATION"
  echo
  echo "## Toolchain"
  echo "go:        $(go version)"
  echo "debugfs:   $(debugfs -V 2>&1 | head -1)"
  echo "e2fsck:    $(e2fsck -V 2>&1 | head -1)"
  echo "gzip:      $(gzip --version | head -1)"
  echo "python3:   $(python3 --version)"
  echo "mkcpio.py: $(sha256sum "$HERE/mkcpio.py" | cut -d' ' -f1)"
  echo "init.tdx:  $(sha256sum "$HERE/init.tdx" | cut -d' ' -f1)"
  echo "repo:      $(git -C "$REPO" rev-parse HEAD)"
} > "$OUT/manifest.txt"

echo "=== built"
echo "image:                   $OUT/disk.raw ($DISK_SHA)"
echo "predicted RTMR2:         $RTMR2"
echo "policy digest:           $POLICY_DIGEST"
echo "reference value set:     $OUT/reference-values.json (+ .sig)"
echo "policy:                  $OUT/policy.json (+ .sig)"
echo "manifest:                $OUT/manifest.txt"
echo "packaging record:        $LOG"
