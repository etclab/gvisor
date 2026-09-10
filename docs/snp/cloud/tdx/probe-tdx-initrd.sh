#!/bin/bash
# Ticket 19, step zero: one throwaway TDX VM, two boots, and the one question
# that has to be answered before anything else in the ticket is worth doing.
#
#   probe-tdx-initrd.sh [OUT_DIR] [-zone ZONE] [-image NAME] [-keep]
#                       [-esp-part N] [-boot-part N] [-root-part N] [-fs-uuid UUID]
#
# # Why this probe exists
#
# docs/snp/cloud/tdx/predict-rtmr2.py predicts RTMR2 from a disk's bytes, and
# 86 of 86 records match on six independent boots -- but not one of those boots
# loaded an initrd. The image sets GRUB_FORCE_PARTUUID, so its default menu
# entry boots initrdless and grub never opens an initrd at all; the predictor's
# `initrd` handler has therefore never run against anything. Ticket 19 puts an
# initrd of our own into a measured guest, so a path nobody has tested is about
# to become load-bearing. This is where it gets tested, on a VM that exists for
# twenty minutes and is deleted.
#
# The prediction is made from bytes read off the guest BEFORE the boot whose
# register it predicts, and is compared with the quote and the CCEL that boot
# produced. No register is ever read into a prediction, and predict-rtmr2.py is
# not touched: if it disagrees with the hardware, that is the finding, and the
# fix is a change to its model, made deliberately and elsewhere. MISMATCH here
# stops the ticket and is reported as such.
#
# # The two boots
#
#   boot 1  baseline   the pinned image untouched     (the control: the known RTMR2)
#   boot 2  initrd     one line added to grub.cfg     (the question: +2 records, and are they right?)
#
# The line is inserted by docs/snp/cloud/tdx/grubcfg-add-initrd.py, which puts
# an `initrd` into the branch of the default entry that is actually taken and
# changes nothing else -- see that file for what the entry looks like and why
# `root=PARTUUID=` is left alone. The predicted difference between the two boots
# is four records: grub.cfg's own digest and the `menuentry` command string move
# because the file changed, and the two new ones are `grub_cmd: initrd ...` and
# the initrd file's own bytes. Anything else is a model error.
#
# # The other half of step zero
#
# The same VM is the first Intel machine attest/tsm's acquirer has ever produced
# evidence on. Until ticket 19 it loaded an AMD certificate chain unconditionally
# and knew no provider name but sev_guest, so it failed on TDX after a good quote
# had been read. The binary built here is this worktree's, with that fixed, and
# it is run against the guest's real configfs-tsm with no chain directory at all
# -- which is the whole claim: a TDX quote carries the chain that roots it, so
# there is nothing to provision and nothing to bundle.
#
# # Cost and cleanup
#
# One c3-standard-4 TDX instance, labelled purpose=tdx-feasibility-probe, with an
# auto-delete boot disk, deleted on the way out whichever way this ends -- the
# trap runs on success, on `set -e`, and on Ctrl-C. The created and deleted
# timestamps are printed as a row for docs/snp/cloud/tdx/RESOURCES.md, which is
# the ledger that says nothing was orphaned.
set -euo pipefail
export PATH="$PATH:/usr/local/go/bin"
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT=""
ZONE="${ZONE:-us-central1-a}"
IMAGE="${IMAGE:-ubuntu-2404-noble-amd64-v20260826}"
VM=tdx-initrd
KEEP=0
# The pinned image's layout. Derived from the guest at boot 1 and only used as
# a fallback, because a partition number guessed wrong makes the predictor read
# the wrong file rather than fail.
ESP_PART=15
BOOT_PART=16
ROOT_PART=1
FS_UUID=""
while [ -n "${1:-}" ]; do
  case "$1" in
    -zone)      ZONE="$2"; shift 2 ;;
    -image)     IMAGE="$2"; shift 2 ;;
    -esp-part)  ESP_PART="$2"; shift 2 ;;
    -boot-part) BOOT_PART="$2"; shift 2 ;;
    -root-part) ROOT_PART="$2"; shift 2 ;;
    -fs-uuid)   FS_UUID="$2"; shift 2 ;;
    -keep)      KEEP=1; shift ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *)  [ -z "$OUT" ] || { echo "two output directories: $OUT and $1" >&2; exit 2; }
        OUT="$1"; shift ;;
  esac
done
OUT="${OUT:-$REPO/docs/snp/evidence/ticket19/step-zero}"
mkdir -p "$OUT"
# Absolute from here on: the Go build runs from another directory, and a
# relative -o would put the binary somewhere nobody looks.
OUT="$(readlink -f "$OUT")"
exec > >(tee "$OUT/initrd.txt") 2>&1

CREATED=""
DELETED="(not deleted)"
VERDICT="incomplete"

echo "=== TDX initrd probe (ticket 19, step zero): $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "project $(gcloud config get-value project 2>/dev/null) zone $ZONE image $IMAGE"
echo "repo    $(git -C "$REPO" rev-parse HEAD)"
echo "out     $OUT"
echo

# resources_row is the line docs/snp/cloud/tdx/RESOURCES.md wants, printed
# rather than appended: the ledger is written by a person, and a script that
# edited it would be claiming an instance was gone before the delete returned.
resources_row() {
  echo
  echo "############ for docs/snp/cloud/tdx/RESOURCES.md ############"
  echo "| created | name | type | purpose | state |"
  echo "|---|---|---|---|---|"
  printf '| %s | %s | c3-standard-4 TDX, %s, 20GB pd-balanced, pinned image `%s` | ticket 19 step zero: two boots -- baseline and one with an `initrd` line in grub.cfg -- to test predict-rtmr2.py'"'"'s initrd path, plus attest/tsm'"'"'s acquirer run on Intel with no chain directory | **deleted %s** |\n' \
    "${CREATED:-(never created)}" "$VM" "$ZONE" "$IMAGE" "$DELETED"
  echo
  echo "verdict: $VERDICT"
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  echo
  if [ "$KEEP" = 1 ]; then
    echo "keeping $VM (-keep); delete it by hand:"
    echo "  gcloud compute instances delete $VM --zone $ZONE --quiet"
    DELETED="(kept, -keep)"
  elif [ -n "$CREATED" ]; then
    echo "deleting $VM"
    if gcloud compute instances delete "$VM" --zone "$ZONE" --quiet; then
      DELETED="$(date -u +%Y-%m-%dT%H:%MZ)"
    else
      DELETED="**DELETE FAILED -- STILL RUNNING**"
      echo "the delete failed; $VM is still running and RESOURCES.md must say so"
    fi
  else
    echo "no instance was created; nothing to delete"
  fi
  gcloud compute instances list --filter="labels.purpose=tdx-feasibility-probe" --format='value(name,zone,status)' || true
  resources_row
  echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ), exit $rc ==="
  exit "$rc"
}
trap cleanup EXIT
trap 'echo "interrupted"; exit 130' INT TERM

if gcloud compute instances describe "$VM" --zone "$ZONE" >/dev/null 2>&1; then
  echo "$VM exists already; refusing to reuse it -- step zero needs a first boot of a fresh image" >&2
  exit 2
fi
CREATED="$(date -u +%Y-%m-%dT%H:%MZ)"
echo "############ creating $VM at $CREATED ############"
gcloud beta compute instances create "$VM" --zone "$ZONE" \
  --machine-type c3-standard-4 \
  --confidential-compute-type TDX --maintenance-policy TERMINATE \
  --image-project ubuntu-os-cloud --image "$IMAGE" \
  --boot-disk-size 20GB --boot-disk-type pd-balanced --boot-disk-auto-delete \
  --labels purpose=tdx-feasibility-probe \
  --format 'value(name,zone,machineType,status)'
echo

ssh_vm() { gcloud compute ssh "$VM" --zone "$ZONE" --quiet -- -o StrictHostKeyChecking=no -o ConnectTimeout=20 "$@"; }
wait_ssh() { local i; for i in $(seq 1 40); do ssh_vm true 2>/dev/null && return 0; sleep 10; done; echo "never answered ssh" >&2; return 1; }
boot_id() { ssh_vm cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n'; }

# The boot_id barrier from probe-tdx-mutate.sh: a sample taken before the
# reboot has actually happened is a sample of the wrong boot.
reboot_and_wait() {
  local old="$1" i now
  ssh_vm 'sudo systemctl reboot' >/dev/null 2>&1 || true
  for i in $(seq 1 60); do
    sleep 10
    now=$(boot_id) || true
    if [ -n "$now" ] && [ "$now" != "$old" ]; then
      echo "  boot_id $old -> $now (barrier crossed on attempt $i)"
      return 0
    fi
  done
  echo "  BARRIER NEVER CROSSED (boot_id still $old); the sample after this is not trustworthy"
  return 1
}

# The files grub reads, hashed, so a boot can be tied to the bytes it saw. The
# initrd is on this list and is not on probe-tdx-upgrade.sh's, which is the
# whole difference between that probe and this one.
BOOTFILES='/boot/efi/EFI/ubuntu/grub.cfg /boot/efi/EFI/ubuntu/shimx64.efi /boot/efi/EFI/ubuntu/grubx64.efi
           /boot/grub/grub.cfg /boot/grub/grubenv /boot/grub/x86_64-efi/command.lst /boot/grub/x86_64-efi/fs.lst
           /boot/grub/x86_64-efi/crypto.lst /boot/grub/x86_64-efi/terminal.lst /boot/grub/x86_64-efi/bli.mod
           /boot/vmlinuz-* /boot/initrd.img-*'

# gather LABEL -- quote, CCEL, and the state of the boot that produced them.
gather() {
  local d="$OUT/$1"; mkdir -p "$d"
  gcloud compute scp --zone "$ZONE" --quiet "$HERE/guest-evidence-tdx.sh" "$VM:/tmp/guest-evidence-tdx.sh" >/dev/null
  ssh_vm 'sudo bash /tmp/guest-evidence-tdx.sh /tmp/evidence' > "$d/guest-evidence.txt" 2>&1 || true
  sed -n '/===BEGIN quote.bin===/,/===END quote.bin===/p' "$d/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$d/quote.bin" 2>/dev/null || true
  [ -s "$d/quote.bin" ] && python3 "$HERE/parse-tdx-quote.py" "$d/quote.bin" > "$d/quote.txt" 2>&1 || true
  ssh_vm 'sudo base64 -w 100 /sys/firmware/acpi/tables/data/CCEL' > "$d/ccel.b64" 2>/dev/null || true
  base64 -d < "$d/ccel.b64" > "$d/ccel.bin" 2>/dev/null || true
  ssh_vm "echo \"boot_id : \$(cat /proc/sys/kernel/random/boot_id)\";
          echo \"cmdline : \$(cat /proc/cmdline)\";
          echo \"kernel  : \$(uname -r)\";
          echo \"initrd  : \$(sudo dmesg | grep -ciE 'unpacking initramfs|trying to unpack rootfs') initramfs lines in dmesg\";
          echo '--- sha256 of what grub read, as of this boot ---';
          sudo sha256sum $BOOTFILES 2>&1;
          echo '--- grubenv as of this boot (after grub-common ran) ---';
          sudo grub-editenv /boot/grub/grubenv list 2>&1" > "$d/state.txt" 2>&1 || true
  echo "--- $1 ---"; head -4 "$d/state.txt"
  grep -E '^(rtmr2)' "$d/quote.txt" 2>/dev/null || echo "  (no quote)"
  echo "  ccel $(stat -c %s "$d/ccel.bin" 2>/dev/null || echo 0) bytes"
}

# snapshot LABEL -- the disk bytes grub will see at the boot this label names:
# /boot and the ESP's EFI tree, as a tarball in the mounted-root layout
# predict-rtmr2.py --tree takes, plus the sha256 list and the partition table.
snapshot() {
  local d="$OUT/$1"; mkdir -p "$d"
  ssh_vm "sudo tar -C / -cf /tmp/bootstate.tar boot/grub boot/efi/EFI \$(cd / && ls -d boot/vmlinuz-* boot/initrd.img-* boot/config-* 2>/dev/null | grep -v '\.old\$' | tr '\n' ' ') && sudo chmod a+r /tmp/bootstate.tar;
          echo '--- sha256 of what grub will read at the next boot ---';
          sudo sha256sum $BOOTFILES 2>&1;
          echo '--- size and sha256 of every initrd on disk ---';
          sudo stat -c '%n %s bytes' /boot/initrd.img-* 2>&1;
          echo '--- the grub.cfg that will be measured ---';
          sudo lsattr /boot/grub/grub.cfg 2>&1;
          sudo sed -n '/^menuentry /,/^}\$/p' /boot/grub/grub.cfg | cat -A 2>&1;
          echo '--- partitions ---';
          lsblk -o NAME,PARTUUID,UUID,MOUNTPOINTS,SIZE 2>&1;
          echo '--- grubenv bytes ---';
          sudo base64 -w 100 /boot/grub/grubenv" > "$d/pre-boot-state.txt" 2>&1 || true
  gcloud compute scp --zone "$ZONE" --quiet "$VM:/tmp/bootstate.tar" "$d/bootstate.tar" >/dev/null 2>&1 || true
  ssh_vm 'sudo cat /boot/grub/grub.cfg' > "$d/grub.cfg" 2>/dev/null || true   # 0600 root: scp cannot read it
  echo "  snapshot for $1: $(stat -c %s "$d/bootstate.tar" 2>/dev/null || echo 0) bytes of tar, grub.cfg $(stat -c %s "$d/grub.cfg" 2>/dev/null || echo 0) bytes"
}

# predict LABEL -- the offline half. The tree comes out of that label's own
# pre-reboot tarball; the quote and the CCEL come out of the boot it predicts.
# Returns predict-rtmr2.py's exit status: 0 MATCH, 1 MISMATCH, 3 the model gave
# up on something it does not know how to interpret.
predict() {
  local d="$OUT/$1" rc=0
  rm -rf "$d/unpacked"; mkdir -p "$d/unpacked"
  if ! tar -C "$d/unpacked" -xf "$d/bootstate.tar" 2>/dev/null; then
    echo "  no boot state to predict $1 from"
    return 1
  fi
  python3 "$HERE/predict-rtmr2.py" --tree "$d/unpacked" \
    --esp-part "$ESP_PART" --boot-part "$BOOT_PART" --root-part "$ROOT_PART" \
    --fs-uuid "$BOOT_PART=$FS_UUID" \
    --compare-quote "$d/quote.bin" --compare-ccel "$d/ccel.bin" > "$d/predict.txt" 2>&1 || rc=$?
  # The record-level diff, when there is one, and the verdict either way.
  sed -n '/^first divergence/,$p' "$d/predict.txt" | head -20
  grep -E '^(records predicted|records recorded|RTMR2 |RESULT)' "$d/predict.txt" || tail -5 "$d/predict.txt"
  return "$rc"
}

wait_ssh
echo "############ boot 1: baseline, the pinned image untouched ############"
gather baseline

# What the predictor has to be told about this disk, asked of the disk rather
# than assumed. The filesystem UUID is the one the default entry's `search`
# names, which is the only one the interpreter resolves.
DERIVED_UUID="$(ssh_vm "sudo sed -n 's/.*--fs-uuid --set=root \\([0-9a-fA-F-]*\\).*/\\1/p' /boot/grub/grub.cfg | head -1" 2>/dev/null | tr -d '\r\n' || true)"
[ -n "$FS_UUID" ] || FS_UUID="$DERIVED_UUID"
DERIVED_PARTS="$(ssh_vm "for m in / /boot /boot/efi; do printf '%s ' \"\$(findmnt -no SOURCE \$m | sed 's#.*[^0-9]\\([0-9][0-9]*\\)\$#\\1#')\"; done" 2>/dev/null | tr -d '\r\n' || true)"
if [ "$(echo "$DERIVED_PARTS" | wc -w)" = 3 ]; then
  ROOT_PART="$(echo "$DERIVED_PARTS" | awk '{print $1}')"
  BOOT_PART="$(echo "$DERIVED_PARTS" | awk '{print $2}')"
  ESP_PART="$(echo "$DERIVED_PARTS" | awk '{print $3}')"
fi
echo "  partitions: root gpt$ROOT_PART, /boot gpt$BOOT_PART, ESP gpt$ESP_PART; /boot fs-uuid $FS_UUID"
if [ -z "$FS_UUID" ]; then
  echo "  no fs-uuid could be read out of grub.cfg; the predictor would resolve every search to --boot-part silently" >&2
  exit 2
fi

snapshot baseline
B=$(boot_id)
echo

echo "############ the rewrite: one initrd line into the branch that is taken ############"
gcloud compute scp --zone "$ZONE" --quiet "$HERE/grubcfg-add-initrd.py" "$VM:/tmp/grubcfg-add-initrd.py" >/dev/null
ssh_vm 'set -e
  sudo cat /boot/grub/grub.cfg > /tmp/grub.cfg.orig   # the file is 0600 root; the copy must be readable by the rewrite
  python3 /tmp/grubcfg-add-initrd.py /tmp/grub.cfg.orig /tmp/grub.cfg.new --boot-dir /boot
  echo "--- what changed ---"
  diff -u /tmp/grub.cfg.orig /tmp/grub.cfg.new | cat -A || true

  # Installed as bytes, not through update-grub: update-grub would regenerate
  # the file from /etc/grub.d and put the initrdless shape straight back, and
  # would move records that have nothing to do with the initrd.
  sudo chattr -i /boot/grub/grub.cfg 2>/dev/null || true
  sudo cp /tmp/grub.cfg.new /boot/grub/grub.cfg
  sudo chmod 444 /boot/grub/grub.cfg

  # Nothing may rewrite it before the boot it is measured at. GRUB_FORCE_PARTUUID
  # is what makes 10_linux generate the initrdless shape, so it goes first --
  # not because grub reads /etc/default/grub at boot (it does not), but so that
  # anything that does run update-grub cannot restore the shape unnoticed.
  sudo sed -i "s/^GRUB_FORCE_PARTUUID=/#GRUB_FORCE_PARTUUID=/" /etc/default/grub
  sudo systemctl disable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer \
       apt-daily.service apt-daily-upgrade.service 2>&1 | tail -3 || true
  sudo chattr +i /boot/grub/grub.cfg 2>/dev/null || echo "chattr +i is not available on this filesystem"

  echo "--- installed ---"
  sudo lsattr /boot/grub/grub.cfg 2>&1 || true
  sudo sha256sum /boot/grub/grub.cfg /boot/initrd.img-* 2>&1
  sudo stat -c "%n %s bytes" /boot/grub/grub.cfg /boot/initrd.img-* 2>&1
  grep -n "GRUB_FORCE_PARTUUID" /etc/default/grub || echo "GRUB_FORCE_PARTUUID: commented out"' | tee "$OUT/rewrite.log"
echo

snapshot initrd
reboot_and_wait "$B" || true
echo "############ boot 2: the same image, one initrd line ############"
gather initrd
echo

echo "############ what the guest exposes, for the initrd ticket 19 has to write ############"
# Written out here rather than kept in a helper, so the questions asked are part
# of the transcript: ticket 19's initrd has to find the config disk by Google's
# device name, bring up the VPC interface and block egress, and every one of
# those is a fact about this provider rather than about TDX.
cat > "$OUT/guest-facts.sh" <<'FACTS'
#!/bin/bash
# Run inside the guest as root. Every question ticket 19's initrd will have to
# answer about this provider, asked once, on the boot that carries the initrd.
set -u
echo "############ 1. the report interface, and what drives it ############"
D=/sys/kernel/config/tsm/report/factsprobe
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
rmdir "$D" 2>/dev/null
if mkdir "$D" 2>/dev/null; then
  echo "attributes:"; ls -l "$D"
  for a in provider generation privlevel privlevel_floor; do
    echo "  $a : $(cat "$D/$a" 2>/dev/null || echo '(not exposed)')"
  done
  rmdir "$D" 2>/dev/null && echo "request removed" || echo "request NOT removed"
else
  echo "no report interface at $D"
fi
echo
echo "############ 2. is this a TDX guest, and with what loaded ############"
uname -r; head -2 /etc/os-release; cat /proc/cmdline
echo "--- dmesg, tdx ---"
dmesg 2>/dev/null | grep -i tdx || echo "(no tdx lines)"
echo "--- lsmod ---"
lsmod
echo
echo "############ 3. block devices, as Google names them ############"
echo "--- /dev/disk/by-id ---"
ls -l /dev/disk/by-id/ 2>&1
echo "--- lsblk ---"
lsblk -o NAME,SERIAL,SIZE,TYPE 2>&1
echo "--- /sys/block/*/serial ---"
for b in /sys/block/*; do
  [ -e "$b/serial" ] && echo "$(basename "$b"): $(cat "$b/serial" 2>/dev/null)"
done
cat /sys/block/*/serial 2>/dev/null
echo "--- udevadm info for the boot disk ---"
BOOTDEV="$(findmnt -no SOURCE /boot 2>/dev/null)"
echo "boot filesystem is on $BOOTDEV"
udevadm info --query=all --name="$BOOTDEV" 2>&1
udevadm info --query=all --name="$(lsblk -no PKNAME "$BOOTDEV" 2>/dev/null | head -1 | sed 's#^#/dev/#')" 2>&1
echo
echo "############ 4. the network, and the metadata server ############"
echo "--- ip -d link ---"
ip -d link 2>&1
echo "--- ip addr ---"
ip addr 2>&1
echo "--- ip route ---"
ip route 2>&1
echo "--- metadata server ---"
if curl -s -m 3 -H 'Metadata-Flavor: Google' http://169.254.169.254/ > /tmp/md.out 2>/tmp/md.err; then
  echo "169.254.169.254 answered:"; head -20 /tmp/md.out
else
  echo "169.254.169.254 did not answer (curl exit $?):"; head -3 /tmp/md.err
fi
echo "--- and one value out of it ---"
curl -s -m 3 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/id; echo " (curl exit $?)"
echo
FACTS
gcloud compute scp --zone "$ZONE" --quiet "$OUT/guest-facts.sh" "$VM:/tmp/guest-facts.sh" >/dev/null
ssh_vm 'sudo bash /tmp/guest-facts.sh' > "$OUT/guest-facts.txt" 2>&1 || true
grep -E '^  provider|^boot filesystem' "$OUT/guest-facts.txt" || true
echo "  guest-facts.txt: $(wc -l < "$OUT/guest-facts.txt") lines"
echo

echo "############ the acquirer, on Intel, with no chain directory ############"
echo "built from $(git -C "$REPO" rev-parse HEAD)"
( cd "$REPO/attest" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOPROXY=off go build -o "$OUT/acquire-evidence" ./cmd/acquire-evidence )
sha256sum "$OUT/acquire-evidence"
gcloud compute scp --zone "$ZONE" --quiet "$OUT/acquire-evidence" "$VM:/tmp/acquire-evidence" >/dev/null
ssh_vm 'set -u
  chmod +x /tmp/acquire-evidence
  sha256sum /tmp/acquire-evidence
  echo "=== no -chain-dir at all: a TDX quote carries the chain that roots it ==="
  sudo /tmp/acquire-evidence -out /tmp/bundle ; echo "exit status: $?"
  echo
  echo "=== and with a -chain-dir that holds nothing, which must be ignored rather than read ==="
  mkdir -p /tmp/nochain
  sudo /tmp/acquire-evidence -chain-dir /tmp/nochain ; echo "exit status: $?"
  echo
  echo "=== the bundle ==="
  sudo ls -l /tmp/bundle 2>&1
  sudo tar -C /tmp -cf /tmp/bundle.tar bundle && sudo chmod a+r /tmp/bundle.tar' > "$OUT/acquire-evidence.txt" 2>&1 || true
cat "$OUT/acquire-evidence.txt"
gcloud compute scp --zone "$ZONE" --quiet "$VM:/tmp/bundle.tar" "$OUT/acquire-evidence-bundle.tar" >/dev/null 2>&1 || true
echo "  bundle: $(stat -c %s "$OUT/acquire-evidence-bundle.tar" 2>/dev/null || echo 0) bytes"
echo

echo "############ the control: the pristine boot, predicted from its own bytes ############"
CONTROL=0
predict baseline || CONTROL=$?
if [ "$CONTROL" != 0 ]; then
  echo "the control did not reproduce a boot nothing was done to (exit $CONTROL);"
  echo "nothing this probe says about the initrd means anything until that is explained."
fi
echo

echo "############ the question: the initrd boot, predicted from the bytes it booted ############"
INITRD=0
predict initrd || INITRD=$?
echo

echo "############ the two boots, side by side ############"
f() { sed -n "s/^$2 *: //p" "$OUT/$1/quote.txt" 2>/dev/null; }
for s in baseline initrd; do
  printf '%-10s rtmr2 %s  records %s\n' "$s" "$(f $s rtmr2)" \
    "$(sed -n 's/^records predicted *: //p' "$OUT/$s/predict.txt" 2>/dev/null)"
done
echo

cat > "$OUT/README.txt" <<README
Ticket 19, step zero: does predict-rtmr2.py's initrd path survive contact with a
boot that actually loads an initrd? Produced by docs/snp/cloud/tdx/probe-tdx-initrd.sh
on $(date -u +%Y-%m-%dT%H:%M:%SZ) from $(git -C "$REPO" rev-parse HEAD), on one
c3-standard-4 TDX instance ($VM, $ZONE, image $IMAGE) that was deleted at the end.

Two boots of one disk. The prediction for each is made from bytes captured off
the guest before that boot, and compared with the quote and the CCEL that boot
produced.

  initrd.txt          the whole transcript of the run, console and log
  rewrite.log         the grub.cfg rewrite: the diff, and what was installed
  guest-facts.sh      the questions asked of the guest, as a script
  guest-facts.txt     their answers: the configfs-tsm provider, dmesg's tdx
                      lines, lsmod, /dev/disk/by-id, lsblk serials,
                      /sys/block/*/serial, udevadm for the boot disk, ip -d link,
                      ip addr, ip route, and the metadata server's answer --
                      the provider facts ticket 19's own initrd has to rely on
  acquire-evidence    the binary that was uploaded, built from this worktree
  acquire-evidence.txt attest/cmd/acquire-evidence run on the guest's real
                      configfs-tsm, twice: with no -chain-dir, and with one
                      that holds nothing and must be ignored
  acquire-evidence-bundle.tar  what it wrote: evidence.bin (the quote), the
                      public key it is bound to, the caller-supplied bytes, the
                      policy digest and the observation. There is no
                      certificate-chain.bin, and that is the result.

  baseline/           boot 1: the pinned image untouched, the control
  initrd/             boot 2: the same image with one line added to grub.cfg

  <label>/guest-evidence.txt  the transcript of guest-evidence-tdx.sh on that boot
  <label>/quote.bin           the TDX quote that boot produced (8000 bytes)
  <label>/quote.txt           parse-tdx-quote.py's reading of it
  <label>/ccel.b64, ccel.bin  that boot's CCEL event log
  <label>/state.txt           boot_id, /proc/cmdline, the kernel, and the sha256
                              of every file grub read, as of that boot
  <label>/pre-boot-state.txt  the same sha256 list taken BEFORE the boot, plus
                              the initrds on disk, the default menuentry with
                              its whitespace shown, lsblk and grubenv
  <label>/bootstate.tar       /boot and the ESP as grub would see them at that
                              boot, in the layout predict-rtmr2.py --tree takes
  <label>/grub.cfg            the grub.cfg inside that tarball, on its own
  <label>/unpacked/           the tarball unpacked, which is what was predicted from
  <label>/predict.txt         predict-rtmr2.py's full output for that boot,
                              every record, and MATCH or MISMATCH

The predictor was run as:

  predict-rtmr2.py --tree <label>/unpacked --esp-part $ESP_PART --boot-part $BOOT_PART \\
      --root-part $ROOT_PART --fs-uuid $BOOT_PART=$FS_UUID \\
      --compare-quote <label>/quote.bin --compare-ccel <label>/ccel.bin

Nothing in predict-rtmr2.py was changed to make either comparison come out.
README
echo "wrote $OUT/README.txt"
echo

if [ "$INITRD" = 0 ] && [ "$CONTROL" = 0 ]; then
  VERDICT="MATCH: the initrd boot's RTMR2 was predicted from the disk bytes; ticket 19 may proceed"
  echo "$VERDICT"
  exit 0
fi
if [ "$INITRD" = 3 ]; then
  VERDICT="STOP: predict-rtmr2.py gave up on the initrd boot's grub.cfg (exit 3) -- its interpreter does not model something the rewrite introduced"
else
  VERDICT="STOP: MISMATCH on the initrd boot (predict-rtmr2.py exit $INITRD, control exit $CONTROL)"
fi
echo "$VERDICT"
echo "The fix is a change to predict-rtmr2.py's model -- see $OUT/initrd/predict.txt for the"
echo "first record that diverges -- and it is not made here and not made by copying a value"
echo "out of a log. Ticket 19 stops until it is."
exit 1
