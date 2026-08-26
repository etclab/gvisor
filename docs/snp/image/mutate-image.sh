#!/bin/bash
# Produce a deliberately mutated copy of a measured image (ticket 08).
#
#   mutate-image.sh -base BASE -out OUT -mutation NAME [-quiet]
#
# BASE is a directory build-image.sh wrote, with its build/ staging trees still
# in place. OUT is a fresh directory that gets the same five measured files
# with exactly one thing changed, and everything downstream of that change
# re-derived the way build-image.sh derives it — so the only difference between
# BASE and OUT is the mutation and its consequences.
#
# This is a test fixture and nothing else. It is never part of building the
# image an operator ships: build-image.sh does not call it, nothing calls it
# but docs/snp/image/sensitivity-on-hardware.sh, and the images it writes go to
# a directory of their own.
#
# Mutations, one byte each:
#
#   none         Rebuild rootfs.img and initrd.img from BASE's staging trees
#                with nothing changed. The control on this script itself: both
#                must come out byte-identical to BASE's, or a difference this
#                script reports somewhere else might be its own doing rather
#                than the mutation's.
#   rootfs-file  One hexadecimal character of /etc/attested-tunnel/author.pub
#                inside the root filesystem — the reference value author's
#                public key, which ADR-0004 makes the trust root of the whole
#                system. The squashfs is rebuilt, the verity hash tree is
#                re-formatted, and the new root hash goes on the command line.
#   rootfs-byte  One byte of rootfs.img itself, with the hash tree re-formatted
#                over it and the new root hash on the command line. The literal
#                form of the claim: not a byte with meaning, just a byte. The
#                default offset is the last byte of the data region, which is
#                inside the padding mksquashfs writes to round the image up to
#                4 KiB — past the filesystem's own size, so nothing in the
#                guest ever reads it. -offset picks another.
#   initrd       One byte of a COMMENT in the initrd's /init — inert to the
#                guest, which is the point — with the cpio and gzip regenerated
#                exactly as build-image.sh does.
#   cmdline      One byte appended to the kernel command line: a trailing
#                space. Invisible in every rendering of the file, and the
#                kernel ignores it.
#
# Nothing here needs root. veritysetup formats a file, not a device.
set -euo pipefail
BASE=""; OUT=""; MUTATION=""; QUIET=0; OFFSET=""
while [ -n "${1:-}" ]; do
  case "$1" in
    -base)     BASE="$2"; shift 2 ;;
    -out)      OUT="$2"; shift 2 ;;
    -mutation) MUTATION="$2"; shift 2 ;;
    -offset)   OFFSET="$2"; shift 2 ;;
    -quiet)    QUIET=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$BASE" ] && [ -n "$OUT" ] && [ -n "$MUTATION" ] \
  || { echo "usage: mutate-image.sh -base BASE -out OUT -mutation NAME" >&2; exit 2; }
for f in OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img; do
  [ -f "$BASE/$f" ] || { echo "missing $BASE/$f" >&2; exit 1; }
done
say() { [ "$QUIET" = 1 ] || printf '    %s\n' "$*"; }
# cmp exits non-zero when the files differ, which is the case this counts, so
# its status is discarded deliberately rather than tripping over set -e.
differing() { { cmp -l "$1" "$2" 2>/dev/null || true; } | wc -l; }
NOTES=""
note() { NOTES="$NOTES$*"$'\n'; }

BB="$BASE/build"
rm -rf "$OUT"; mkdir -p "$OUT"
cp "$BASE"/{OVMF.fd,vmlinuz,initrd.img,cmdline.txt,rootfs.img} "$OUT/"

# The verity geometry travels on the command line, which is where the kernel
# reads it from too: there is no superblock to read it out of.
DATABLOCKS=$(sed -n 's/.*verity\.datablocks=\([0-9]*\).*/\1/p' "$BASE/cmdline.txt")
[ -n "$DATABLOCKS" ] || { echo "no verity.datablocks in $BASE/cmdline.txt" >&2; exit 1; }
DATA_BYTES=$((DATABLOCKS * 4096))

# reformat_verity re-derives the hash tree over $OUT/rootfs.img with exactly
# the parameters build-image.sh used, and puts the resulting root hash on the
# command line in place of the old one — the only thing on the command line
# that changes, so that a diff of the two command lines is 64 characters wide.
reformat_verity() {
  local out
  out=$(veritysetup format --no-superblock --hash-offset="$DATA_BYTES" \
          --data-block-size=4096 --hash-block-size=4096 --data-blocks="$DATABLOCKS" \
          --hash=sha256 --salt=- "$OUT/rootfs.img" "$OUT/rootfs.img")
  local rh; rh=$(echo "$out" | sed -n 's/^Root hash:[[:space:]]*//p')
  [[ "$rh" =~ ^[0-9a-f]{64}$ ]] || { echo "no root hash from veritysetup: $out" >&2; exit 1; }
  veritysetup verify --no-superblock --hash-offset="$DATA_BYTES" \
    --data-block-size=4096 --hash-block-size=4096 --data-blocks="$DATABLOCKS" \
    --hash=sha256 --salt=- "$OUT/rootfs.img" "$OUT/rootfs.img" "$rh"
  sed -i "s/verity\.roothash=[0-9a-f]\{64\}/verity.roothash=$rh/" "$OUT/cmdline.txt"
  say "verity root hash now $rh, and it is the only thing the command line changed"
}

# rebuild_rootfs remakes the squashfs from a staging tree with the same
# mksquashfs invocation build-image.sh uses, then re-derives verity over it.
rebuild_rootfs() { # rebuild_rootfs STAGING
  mksquashfs "$1" "$OUT/rootfs.squashfs" -comp zstd -noappend -no-xattrs -all-root \
    -mkfs-time 0 -all-time 0 -root-time 0 -no-progress -quiet
  local sz; sz=$(stat -c %s "$OUT/rootfs.squashfs")
  [ "$sz" = "$DATA_BYTES" ] || { echo "rebuilt squashfs is $sz bytes, base was $DATA_BYTES: the geometry moved and this script's premise is gone" >&2; exit 1; }
  mv "$OUT/rootfs.squashfs" "$OUT/rootfs.img"
  reformat_verity
}

# rebuild_initrd remakes the cpio and gzips it with the same flags
# build-image.sh uses, from a copy of the staging tree so that the list's
# absolute paths point at the copy.
rebuild_initrd() { # rebuild_initrd STAGING_COPY_PARENT
  local b="$1"
  sed "s#$BB/#$b/#g" "$BB/initrd.list" > "$b/initrd.list"
  "$BB/gen_init_cpio" -t 0 "$b/initrd.list" > "$b/initrd.cpio"
  gzip -n -9 -c "$b/initrd.cpio" > "$OUT/initrd.img"
}

stage_copy() { # stage_copy -> a private copy of BASE's whole build/ staging area
  [ -d "$BB/rootfs" ] && [ -d "$BB/initrd" ] && [ -x "$BB/gen_init_cpio" ] \
    || { echo "$BASE has no build/ staging trees; rebuild it with build-image.sh" >&2; exit 1; }
  mkdir -p "$OUT/build"
  cp -a "$BB/." "$OUT/build/"
}

case "$MUTATION" in
  none)
    stage_copy
    rebuild_rootfs "$OUT/build/rootfs"
    rebuild_initrd "$OUT/build"
    say "nothing mutated: rootfs.img and initrd.img rebuilt from BASE's staging trees"
    note "no source change: this is the control on the mutator, not a mutation"
    ;;

  rootfs-file)
    stage_copy
    K="$OUT/build/rootfs/etc/attested-tunnel/author.pub"
    [ -f "$K" ] || { echo "no $K" >&2; exit 1; }
    BEFORE=$(cat "$K")
    chmod 644 "$K"
    # The last hexadecimal character of the author's public key, moved on by
    # one. One byte, and the image now names a key nobody holds.
    LAST="${BEFORE:63:1}"
    NEXT=$(printf '%x' $(( (16#$LAST + 1) % 16 )))
    printf '%s%s\n' "${BEFORE:0:63}" "$NEXT" > "$K"
    chmod 444 "$K"
    say "/etc/attested-tunnel/author.pub: ...${BEFORE:56:8} -> ...${BEFORE:56:7}$NEXT (one hexadecimal character of the trust root, ADR-0004)"
    note "source change: /etc/attested-tunnel/author.pub, $(differing "$BB/rootfs/etc/attested-tunnel/author.pub" "$K") byte of $(stat -c %s "$K")"
    note "  the reference value author's public key (ADR-0004): ...${BEFORE:56:8} -> ...${BEFORE:56:7}$NEXT"
    note "  the squashfs is then rebuilt over it, so rootfs.img differs by more than one byte:"
    note "  zstd re-compresses the block the file sits in, and the metadata around it moves."
    rebuild_rootfs "$OUT/build/rootfs"
    ;;

  rootfs-byte)
    # The last byte of the data region by default: mksquashfs rounds the image
    # up to 4 KiB and the filesystem's own size (unsquashfs -s) stops short of
    # it, so this byte is padding that no software in the guest reads. It is
    # still a byte of the measured root filesystem, which is the whole point.
    OFFSET="${OFFSET:-$((DATA_BYTES - 1))}"
    [ "$OFFSET" -lt "$DATA_BYTES" ] || { echo "offset $OFFSET is past the data region" >&2; exit 1; }
    OLD=$(dd if="$OUT/rootfs.img" bs=1 skip="$OFFSET" count=1 status=none | od -An -tu1 | tr -d ' ')
    NEW=$(( OLD ^ 1 ))
    printf "$(printf '\\x%02x' "$NEW")" | dd of="$OUT/rootfs.img" bs=1 seek="$OFFSET" count=1 conv=notrunc status=none
    say "rootfs.img byte $OFFSET of $DATA_BYTES (0x$(printf '%x' "$OFFSET")): $OLD -> $NEW"
    note "source change: rootfs.img byte $OFFSET of $DATA_BYTES (0x$(printf '%x' "$OFFSET")), $OLD -> $NEW"
    note "  one byte of the measured root filesystem image, and nothing else"
    reformat_verity
    ;;

  initrd)
    stage_copy
    S="$OUT/build/initrd/init"
    [ -f "$S" ] || { echo "no $S" >&2; exit 1; }
    grep -q '^# Job: ' "$S" || { echo "the comment this mutation edits is not in $S" >&2; exit 1; }
    sed -i '0,/^# Job: /s//# job: /' "$S"
    say "initrd /init: one byte of a comment (\"# Job:\" -> \"# job:\"); nothing the guest executes changed"
    note "source change: the initrd's /init, $(differing "$BB/initrd/init" "$S") byte of $(stat -c %s "$S")"
    note "  a comment, \"# Job:\" -> \"# job:\": nothing the guest executes changed"
    rebuild_initrd "$OUT/build"
    note "cpio archive before gzip: $(differing "$BB/initrd.cpio" "$OUT/build/initrd.cpio") byte of $(stat -c %s "$OUT/build/initrd.cpio")"
    note "  gzip's output diverges from that byte onwards, which is why initrd.img differs in bulk"
    ;;

  cmdline)
    printf '%s \n' "$(cat "$BASE/cmdline.txt")" > "$OUT/cmdline.txt"
    say "kernel command line: one trailing space appended ($(stat -c %s "$BASE/cmdline.txt") -> $(stat -c %s "$OUT/cmdline.txt") bytes with the newline)"
    note "source change: one space appended to the kernel command line"
    note "  the measured string is the file without its newline, so it goes from $(( $(stat -c %s "$BASE/cmdline.txt") - 1 )) to $(( $(stat -c %s "$OUT/cmdline.txt") - 1 )) bytes"
    note "  the kernel ignores it, and no rendering of the file shows it"
    ;;

  *) echo "unknown mutation: $MUTATION" >&2; exit 2 ;;
esac

# What actually differs, file by file, counted rather than asserted.
{
  echo "# Mutation \"$MUTATION\" of $BASE, written to $OUT."
  echo
  printf '%s' "$NOTES"
  echo
  echo "## Byte differences against the base image, per measured file."
  for f in OVMF.fd vmlinuz initrd.img cmdline.txt rootfs.img; do
    if cmp -s "$BASE/$f" "$OUT/$f"; then
      echo "$f: identical"
    else
      n=$(differing "$BASE/$f" "$OUT/$f")
      sb=$(stat -c %s "$BASE/$f"); sn=$(stat -c %s "$OUT/$f")
      if [ "$sb" = "$sn" ]; then echo "$f: $n byte(s) differ of $sb"
      else echo "$f: $sb -> $sn bytes, $n byte(s) differ in the common prefix"; fi
    fi
  done
  if ! cmp -s "$BASE/rootfs.img" "$OUT/rootfs.img"; then
    d=$(differing <(head -c "$DATA_BYTES" "$BASE/rootfs.img") <(head -c "$DATA_BYTES" "$OUT/rootfs.img"))
    echo "rootfs.img data region (first $DATA_BYTES bytes): $d byte(s) differ; the rest is the re-derived hash tree"
  fi
  echo "base command line: $(cat "$BASE/cmdline.txt")"
  echo "this command line: $(cat "$OUT/cmdline.txt")"
  echo "base command line sha256 (as measured, no newline, plus NUL is added by QEMU): $(printf '%s' "$(cat "$BASE/cmdline.txt")" | sha256sum | cut -d' ' -f1)"
  echo "this command line sha256: $(printf '%s' "$(cat "$OUT/cmdline.txt")" | sha256sum | cut -d' ' -f1)"
} > "$OUT/mutation.txt"
[ "$QUIET" = 1 ] || sed 's/^/    /' "$OUT/mutation.txt"
