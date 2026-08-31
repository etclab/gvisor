#!/bin/bash
# The TDX feasibility probes, in the shape docs/snp/cloud/probe-platform.sh set.
#
#   probe-tdx.sh [-out DIR] [-zone ZONE] [-keep] [-skip-mutate]
#
# The SEV-SNP probe found that Google's launch measurement does not cover the
# boot disk: two VMs from two different Ubuntu images reported byte-identical
# MEASUREMENT. This asks the same question of Intel TDX, where there is more
# than one register it could be answered in.
#
#   1. Does anything in a TDX quote track the guest's disk?  Two c3-standard-4
#      TDX VMs from two different images, otherwise identical. Compare MRTD —
#      fixed when the domain is built — and RTMR0 through RTMR3, which are
#      runtime-extendable and are where a measured boot chain would put the
#      kernel, the initrd and the command line. If some register differs, TDX
#      on this provider offers workload granularity SEV-SNP there does not.
#   2. Does the acquisition half of the vendor seam already work?  attest/tsm
#      drives /sys/kernel/config/tsm/report and its package comment claims the
#      same four steps "yield an SEV-SNP report on AMD and TDX evidence on
#      Intel". Nobody has run it on Intel. Record whether the interface exists,
#      what provider name the kernel reports, and whether the bytes parse as a
#      TDX quote.
#   3. Does a deliberately altered guest move a register on the SAME image?
#      probe-c takes a baseline, then changes only the kernel command line and
#      reboots, then changes only the initrd and reboots. Three quotes from one
#      disk, so whatever moves is attributable to exactly one change.
#
# What it creates, and deletes at the end unless -keep: three c3-standard-4
# TDX instances named tdx-probe-a, tdx-probe-b, tdx-probe-c. a and b are
# deleted as soon as their evidence is in hand; c lives as long as the
# mutation stage. Flags are the provider's as of 2026-08-31 and belong here.
#
# TDX needs the beta surface: gcloud 493's GA --confidential-compute-type
# accepts only SEV and SEV_SNP.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT="${OUT:-$REPO/docs/snp/evidence/tdx/probes}"
ZONE="${ZONE:-us-central1-a}"
KEEP=0
MUTATE=1
while [ -n "${1:-}" ]; do
  case "$1" in
    -out)  OUT="$2"; shift 2 ;;
    -zone) ZONE="$2"; shift 2 ;;
    -keep) KEEP=1; shift ;;
    -skip-mutate) MUTATE=0; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"
exec > >(tee "$OUT/probes.txt") 2>&1
PROJECT=$(gcloud config get-value project 2>/dev/null)
echo "=== TDX probes: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "project $PROJECT zone $ZONE account $(gcloud config get-value account 2>/dev/null)"
echo "repo    $(git -C "$REPO" rev-parse HEAD)"
echo "gcloud  $(gcloud version 2>/dev/null | head -1)"
echo

# Two different images, identical shape otherwise — the same two families the
# SEV-SNP probe used, both tagged TDX_CAPABLE. probe-c repeats probe-a's image
# so that the mutation stage varies one thing.
declare -A IMAGE=(
  [tdx-probe-a]="ubuntu-os-cloud/ubuntu-2404-lts-amd64"
  [tdx-probe-b]="ubuntu-os-cloud/ubuntu-2204-lts"
  [tdx-probe-c]="ubuntu-os-cloud/ubuntu-2404-lts-amd64"
)
VMS=(tdx-probe-a tdx-probe-b)
[ "$MUTATE" = 1 ] && VMS+=(tdx-probe-c)

create() { # NAME PROJECT/FAMILY
  local name="$1" proj="${2%%/*}" family="${2##*/}"
  if gcloud compute instances describe "$name" --zone "$ZONE" >/dev/null 2>&1; then
    echo "$name exists already; reusing"; return
  fi
  echo "\$ gcloud beta compute instances create $name ($family)"
  gcloud beta compute instances create "$name" --zone "$ZONE" \
    --machine-type c3-standard-4 \
    --confidential-compute-type TDX --maintenance-policy TERMINATE \
    --image-project "$proj" --image-family "$family" \
    --boot-disk-size 20GB --boot-disk-type pd-balanced \
    --labels purpose=tdx-feasibility-probe \
    --format 'value(name,zone,machineType,status)'
}
for n in "${VMS[@]}"; do create "$n" "${IMAGE[$n]}"; done
echo

ssh_vm() { gcloud compute ssh "$1" --zone "$ZONE" --quiet -- -o StrictHostKeyChecking=no -o ConnectTimeout=20 "${@:2}"; }
wait_ssh() {
  local name="$1" i
  for i in $(seq 1 40); do
    ssh_vm "$name" true 2>/dev/null && return 0
    sleep 10
  done
  echo "$name never answered ssh" >&2; return 1
}

# gather NAME LABEL -- one quote into $OUT/LABEL/
gather() {
  local n="$1" label="$2" d="$OUT/$2"
  mkdir -p "$d"
  gcloud compute scp --zone "$ZONE" --quiet "$HERE/guest-evidence-tdx.sh" "$n:/tmp/guest-evidence-tdx.sh" >/dev/null
  ssh_vm "$n" 'sudo bash /tmp/guest-evidence-tdx.sh /tmp/evidence' > "$d/guest-evidence.txt" 2>&1 || true
  sed -n '/===BEGIN quote.bin===/,/===END quote.bin===/p' "$d/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$d/quote.bin" 2>/dev/null || true
  sed -n '/===BEGIN aux.bin===/,/===END aux.bin===/p'     "$d/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$d/aux.bin"   2>/dev/null || true
  grep -E '^(provider|generation|outblob|auxblob|inblob|privlevel)' "$d/guest-evidence.txt" || true
  if [ -s "$d/quote.bin" ]; then
    python3 "$HERE/parse-tdx-quote.py" "$d/quote.bin" > "$d/quote.txt" 2>&1 || true
    grep -E '^(quote version|tee_type|mrtd|rtmr[0-3]|td_attributes|xfam|mrseam|reportdata echoes)' "$d/quote.txt" || true
  else
    echo "no quote bytes recovered"
  fi
}

f() { sed -n "s/^$2 *: //p" "$OUT/$1/quote.txt" 2>/dev/null; }
same() { [ -n "$1" ] && [ "$1" = "$2" ] && echo SAME || echo DIFFERENT; }

for n in tdx-probe-a tdx-probe-b; do
  echo "### $n (${IMAGE[$n]##*/})"
  wait_ssh "$n"
  gather "$n" "$n"
  echo
done

echo "=== answers: probes 1 and 2 ==="
echo "probe-a image: ${IMAGE[tdx-probe-a]##*/}"
echo "probe-b image: ${IMAGE[tdx-probe-b]##*/}"
printf '%-8s %-10s %s\n' register verdict "probe-a / probe-b"
for r in mrtd rtmr0 rtmr1 rtmr2 rtmr3; do
  A=$(f tdx-probe-a "$r"); B=$(f tdx-probe-b "$r")
  printf '%-8s %-10s %s\n' "$r" "$(same "$A" "$B")" "${A:-(none)}"
  printf '%-8s %-10s %s\n' ""   ""                  "${B:-(none)}"
done
echo
echo "provider name reported by the kernel:"
for n in tdx-probe-a tdx-probe-b; do
  echo "  $n: $(sed -n 's/^provider *: //p' "$OUT/$n/guest-evidence.txt" | head -1)"
done
echo "auxblob:"
for n in tdx-probe-a tdx-probe-b; do
  echo "  $n: $(sed -n 's/^auxblob *: //p' "$OUT/$n/guest-evidence.txt" | head -1)"
done
echo

if [ "$KEEP" = 0 ]; then
  echo "deleting tdx-probe-a tdx-probe-b"
  gcloud compute instances delete tdx-probe-a tdx-probe-b --zone "$ZONE" --quiet
  echo
fi

if [ "$MUTATE" = 1 ]; then
  echo "### tdx-probe-c: same image as probe-a, three boots, one change each"
  wait_ssh tdx-probe-c
  gather tdx-probe-c "tdx-probe-c-baseline"
  echo

  echo "--- mutation 1: kernel command line only ---"
  ssh_vm tdx-probe-c 'set -x
    sudo cp /etc/default/grub /tmp/grub.orig
    sudo sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 tdx.probe.marker=alpha\"/" /etc/default/grub
    grep GRUB_CMDLINE_LINUX_DEFAULT /etc/default/grub
    sudo update-grub 2>&1 | tail -5' > "$OUT/mutation-1-cmdline.txt" 2>&1 || true
  tail -5 "$OUT/mutation-1-cmdline.txt"
  ssh_vm tdx-probe-c 'sudo systemctl reboot' >/dev/null 2>&1 || true
  sleep 25; wait_ssh tdx-probe-c
  gather tdx-probe-c "tdx-probe-c-cmdline"
  echo

  echo "--- mutation 2: initrd only, command line put back ---"
  ssh_vm tdx-probe-c 'set -x
    sudo cp /tmp/grub.orig /etc/default/grub
    grep GRUB_CMDLINE_LINUX_DEFAULT /etc/default/grub
    echo "a file that was not in the initrd before" | sudo tee /etc/tdx-probe-marker >/dev/null
    printf "/etc/tdx-probe-marker\n" | sudo tee /etc/initramfs-tools/hooks/../conf.d/tdx-probe >/dev/null
    sudo mkdir -p /usr/share/initramfs-tools/hooks
    printf "#!/bin/sh\n[ \"\$1\" = prereqs ] && { echo; exit 0; }\n. /usr/share/initramfs-tools/hook-functions\ncopy_file text /etc/tdx-probe-marker /etc/tdx-probe-marker\n" | sudo tee /usr/share/initramfs-tools/hooks/tdxprobe >/dev/null
    sudo chmod +x /usr/share/initramfs-tools/hooks/tdxprobe
    sudo update-initramfs -u 2>&1 | tail -5
    sudo update-grub 2>&1 | tail -3
    md5sum /boot/initrd.img-$(uname -r) 2>/dev/null || true' > "$OUT/mutation-2-initrd.txt" 2>&1 || true
  tail -8 "$OUT/mutation-2-initrd.txt"
  ssh_vm tdx-probe-c 'sudo systemctl reboot' >/dev/null 2>&1 || true
  sleep 25; wait_ssh tdx-probe-c
  gather tdx-probe-c "tdx-probe-c-initrd"
  echo

  echo "=== answers: probe 3, one disk, three boots ==="
  printf '%-8s %-24s %-24s %s\n' register 'baseline vs cmdline' 'baseline vs initrd' 'baseline value'
  for r in mrtd rtmr0 rtmr1 rtmr2 rtmr3; do
    BASE=$(f tdx-probe-c-baseline "$r"); CMD=$(f tdx-probe-c-cmdline "$r"); INI=$(f tdx-probe-c-initrd "$r")
    printf '%-8s %-24s %-24s %s\n' "$r" "$(same "$BASE" "$CMD")" "$(same "$BASE" "$INI")" "${BASE:0:32}…"
  done
  echo
  if [ "$KEEP" = 0 ]; then
    echo "deleting tdx-probe-c"
    gcloud compute instances delete tdx-probe-c --zone "$ZONE" --quiet
  fi
fi

echo
echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
gcloud compute instances list --filter="labels.purpose=tdx-feasibility-probe" --format='value(name,zone,status)' || true
