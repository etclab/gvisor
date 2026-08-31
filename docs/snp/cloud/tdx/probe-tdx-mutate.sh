#!/bin/bash
# Probe 3, done properly, and probe 2 taken all the way to the seam.
#
#   probe-tdx-mutate.sh [-out DIR] [-zone ZONE] [-keep]
#
# The first attempt (docs/snp/evidence/tdx/probes-run1/) established probes 1
# and 2 but its mutation stage was not a controlled experiment, and it is kept
# because the way it failed is worth reading: `sudo systemctl reboot` followed
# by `sleep 25` is not a reboot barrier, so one sample was a second read of the
# boot before it, and one mutation's ssh landed while the machine was going
# down and never ran. Three things are added here:
#
#   * A real barrier. /proc/sys/kernel/random/boot_id changes exactly once per
#     boot; every reboot waits for it to become something other than what it
#     was, so a sample can never be attributed to the wrong boot.
#   * A control on each mutation, taken BEFORE the reboot: the run asserts that
#     the thing it meant to change actually changed — the marker is in
#     /boot/grub/grub.cfg, the initrd's hash moved — so that a register which
#     does not move is a finding rather than a mutation that never happened.
#   * A control on the whole method: one plain reboot with nothing changed at
#     all. If a register moves across that, it is not measuring anything and
#     nothing after it can be read.
#
# It also answers the half of probe 2 that reading cannot: attest/tsm's own
# Acquirer, built and run on Intel for the first time, so that what this
# project does on a TDX guest is recorded as output rather than predicted.
#
# One c3-standard-4 TDX instance, tdx-mutate, deleted at the end unless -keep.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT="${OUT:-$REPO/docs/snp/evidence/tdx/mutate}"
ZONE="${ZONE:-us-central1-a}"
VM=tdx-mutate
KEEP=0
while [ -n "${1:-}" ]; do
  case "$1" in
    -out)  OUT="$2"; shift 2 ;;
    -zone) ZONE="$2"; shift 2 ;;
    -keep) KEEP=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"
exec > >(tee "$OUT/mutate.txt") 2>&1
echo "=== TDX mutation probe: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "project $(gcloud config get-value project 2>/dev/null) zone $ZONE"
echo "repo    $(git -C "$REPO" rev-parse HEAD)"
echo

if ! gcloud compute instances describe "$VM" --zone "$ZONE" >/dev/null 2>&1; then
  gcloud beta compute instances create "$VM" --zone "$ZONE" \
    --machine-type c3-standard-4 \
    --confidential-compute-type TDX --maintenance-policy TERMINATE \
    --image-project ubuntu-os-cloud --image-family ubuntu-2404-lts-amd64 \
    --boot-disk-size 20GB --boot-disk-type pd-balanced \
    --labels purpose=tdx-feasibility-probe \
    --format 'value(name,zone,machineType,status)'
else
  echo "$VM exists already; reusing"
fi
echo

ssh_vm() { gcloud compute ssh "$VM" --zone "$ZONE" --quiet -- -o StrictHostKeyChecking=no -o ConnectTimeout=20 "${@:2}"; }
wait_ssh() { local i; for i in $(seq 1 40); do ssh_vm x true 2>/dev/null && return 0; sleep 10; done; echo "never answered ssh" >&2; return 1; }
boot_id() { ssh_vm x cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n'; }

# reboot_and_wait OLD_BOOT_ID -- returns only when the machine is up on a
# different boot. This is the barrier run 1 did not have.
reboot_and_wait() {
  local old="$1" i now
  ssh_vm x 'sudo systemctl reboot' >/dev/null 2>&1 || true
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

# gather LABEL
gather() {
  local d="$OUT/$1"; mkdir -p "$d"
  gcloud compute scp --zone "$ZONE" --quiet "$HERE/guest-evidence-tdx.sh" "$VM:/tmp/guest-evidence-tdx.sh" >/dev/null
  ssh_vm x 'sudo bash /tmp/guest-evidence-tdx.sh /tmp/evidence' > "$d/guest-evidence.txt" 2>&1 || true
  sed -n '/===BEGIN quote.bin===/,/===END quote.bin===/p' "$d/guest-evidence.txt" | sed '1d;$d' | base64 -d > "$d/quote.bin" 2>/dev/null || true
  if [ -s "$d/quote.bin" ]; then
    python3 "$HERE/parse-tdx-quote.py" "$d/quote.bin" > "$d/quote.txt" 2>&1 || true
  fi
  ssh_vm x 'echo "boot_id : $(cat /proc/sys/kernel/random/boot_id)";
            echo "cmdline : $(cat /proc/cmdline)";
            echo "kernel  : $(uname -r)";
            echo "initrd  : $(sudo sha256sum /boot/initrd.img-$(uname -r) 2>/dev/null | cut -c1-32)";
            echo "grubcfg : $(sudo sha256sum /boot/grub/grub.cfg 2>/dev/null | cut -c1-32)"' > "$d/state.txt" 2>&1 || true
  echo "--- $1 ---"; cat "$d/state.txt"
  grep -E '^(mrtd|rtmr[0-3])' "$d/quote.txt" 2>/dev/null || echo "  (no quote)"
}

f() { sed -n "s/^$2 *: //p" "$OUT/$1/quote.txt" 2>/dev/null; }
st() { sed -n "s/^$2 *: //p" "$OUT/$1/state.txt" 2>/dev/null; }
same() { [ -n "$1" ] && [ "$1" = "$2" ] && echo SAME || echo DIFFERENT; }

wait_ssh
echo "### what this image's boot chain actually looks like"
ssh_vm x 'echo "--- /etc/default/grub.d/ ---"; ls -l /etc/default/grub.d/ 2>&1;
          echo "--- fragments ---"; sudo grep -H . /etc/default/grub.d/* 2>/dev/null | head -30;
          echo "--- /etc/default/grub ---"; grep -v "^#" /etc/default/grub | grep .;
          echo "--- what grub.cfg puts on the linux line ---"; sudo grep -m3 "linux.*vmlinuz" /boot/grub/grub.cfg' > "$OUT/bootchain.txt" 2>&1 || true
cat "$OUT/bootchain.txt"
echo

echo "############ boot 1: baseline ############"
gather baseline
B1=$(st baseline boot_id)
echo

echo "############ boot 2: plain reboot, NOTHING changed (the control) ############"
reboot_and_wait "$B1" || true
wait_ssh
gather control-reboot
B2=$(st control-reboot boot_id)
echo

echo "############ probe 2, at the seam: attest/tsm's own Acquirer on Intel ############"
ssh_vm x 'set -e
  if ! command -v go >/dev/null; then
    curl -sSL https://go.dev/dl/$(curl -sSL "https://go.dev/VERSION?m=text" | head -1).linux-amd64.tar.gz -o /tmp/go.tgz
    sudo tar -C /usr/local -xzf /tmp/go.tgz
  fi
  /usr/local/go/bin/go version' > "$OUT/go-install.txt" 2>&1 || true
tail -2 "$OUT/go-install.txt"
gcloud compute scp --zone "$ZONE" --quiet --recurse "$REPO/attest" "$VM:/tmp/attest" >/dev/null 2>&1 || true
ssh_vm x 'cd /tmp/attest && export PATH=$PATH:/usr/local/go/bin && export GOFLAGS=-mod=mod &&
  echo "=== building attest/cmd/acquire-evidence on the TDX guest ===" &&
  go build -o /tmp/acquire-evidence ./cmd/acquire-evidence 2>&1 | tail -20 &&
  echo "=== built; running it against a directory that holds no chain ===" &&
  mkdir -p /tmp/nochain &&
  sudo /tmp/acquire-evidence -chain-dir /tmp/nochain ; echo "exit status: $?"' > "$OUT/acquire-evidence.txt" 2>&1 || true
cat "$OUT/acquire-evidence.txt"
echo

echo "############ boot 3: kernel command line only ############"
ssh_vm x 'set -x
  printf "GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX tdx.probe.marker=alpha\"\n" | sudo tee /etc/default/grub.d/99-tdx-probe.cfg
  sudo update-grub 2>&1 | tail -3
  echo "--- CONTROL: is the marker in grub.cfg? ---"
  sudo grep -c "tdx.probe.marker=alpha" /boot/grub/grub.cfg
  echo "--- CONTROL: initrd hash, must not have moved ---"
  sudo sha256sum /boot/initrd.img-$(uname -r) | cut -c1-32' > "$OUT/mutation-cmdline.txt" 2>&1 || true
cat "$OUT/mutation-cmdline.txt"
B=$(boot_id); reboot_and_wait "$B" || true
wait_ssh
gather cmdline
echo

echo "############ boot 4: initrd only, command line put back ############"
ssh_vm x 'set -x
  sudo rm -f /etc/default/grub.d/99-tdx-probe.cfg
  echo "a file that was not in the initrd before" | sudo tee /etc/tdx-probe-marker >/dev/null
  sudo mkdir -p /etc/initramfs-tools/hooks
  printf "#!/bin/sh\n[ \"\$1\" = prereqs ] && { echo; exit 0; }\n. /usr/share/initramfs-tools/hook-functions\ncopy_file text /etc/tdx-probe-marker /etc/tdx-probe-marker\n" | sudo tee /etc/initramfs-tools/hooks/tdxprobe >/dev/null
  sudo chmod +x /etc/initramfs-tools/hooks/tdxprobe
  sudo update-initramfs -u 2>&1 | tail -3
  sudo update-grub 2>&1 | tail -2
  echo "--- CONTROL: marker gone from grub.cfg? (want 0) ---"
  sudo grep -c "tdx.probe.marker=alpha" /boot/grub/grub.cfg || true
  echo "--- CONTROL: is the marker file in the initrd? ---"
  sudo lsinitramfs /boot/initrd.img-$(uname -r) | grep -c tdx-probe-marker || true
  echo "--- CONTROL: initrd hash, must have moved ---"
  sudo sha256sum /boot/initrd.img-$(uname -r) | cut -c1-32' > "$OUT/mutation-initrd.txt" 2>&1 || true
cat "$OUT/mutation-initrd.txt"
B=$(boot_id); reboot_and_wait "$B" || true
wait_ssh
gather initrd
echo

echo "=== answers: one disk, four boots ==="
printf '%-8s %-14s %-14s %-14s\n' register 'plain reboot' 'cmdline' 'initrd'
for r in mrtd rtmr0 rtmr1 rtmr2 rtmr3; do
  BASE=$(f baseline "$r")
  printf '%-8s %-14s %-14s %-14s\n' "$r" \
    "$(same "$BASE" "$(f control-reboot "$r")")" \
    "$(same "$BASE" "$(f cmdline "$r")")" \
    "$(same "$BASE" "$(f initrd "$r")")"
done
echo
echo "the controls those verdicts depend on:"
printf '%-16s %s\n' 'boot' 'boot_id / cmdline / initrd hash'
for s in baseline control-reboot cmdline initrd; do
  printf '%-16s %s | %s | %s\n' "$s" "$(st $s boot_id)" "$(st $s cmdline)" "$(st $s initrd)"
done

if [ "$KEEP" = 0 ]; then
  echo; echo "deleting $VM"
  gcloud compute instances delete "$VM" --zone "$ZONE" --quiet
fi
echo "=== done $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
gcloud compute instances list --filter="labels.purpose=tdx-feasibility-probe" --format='value(name,zone,status)' || true
