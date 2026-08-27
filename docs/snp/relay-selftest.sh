#!/bin/bash
# Two controls on the relay, so that what it says in a real run means something.
#
#   relay-selftest.sh [-out DIR]
#
# The two-guest run rests on l2relay.py twice over: it is the only path between
# the guests, and it is the attacker that fails to read what it carries. Both
# claims have a way of being true for the wrong reason — a relay that carried
# nothing would also report no plaintext, and a scanner that never matches
# would report the same. So:
#
#   1. Two guests on the segment ping each other. This runs the real kernel and
#      initrd from the measured image with rdinit=/bin/sh — deliberately not the
#      measured boot, which has no shell — driven over the serial console. It
#      proves QEMU's socket netdev, the four-byte framing, ARP and IPv4 all
#      cross the relay, and it reports the round trip through it.
#   2. A frame carrying the marker in the clear is put on the segment by hand.
#      The relay must say MARKER FOUND and must deliver the frame unchanged.
#      Without this, "MARKER not found" in a real run is not evidence.
#
# Nothing here needs root: no SNP, so /dev/kvm is enough.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
STACK="${STACK:-$REPO/.scratch/attested-secure-tunnel/host-stack}"
IMAGE="${IMAGE:-$STACK/image-ticket14}"
QEMU="${QEMU:-$STACK/usr/local/bin/qemu-system-x86_64}"
OUT="${OUT:-$STACK/ticket14-run/relay-selftest}"
MARKER="attested-tunnel-plaintext-marker"
while [ -n "${1:-}" ]; do
  case "$1" in
    -out) OUT="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$OUT"
exec > >(tee "$OUT/relay-selftest.txt") 2>&1
PASSES=0; FAILURES=0
pass() { PASSES=$((PASSES+1)); echo "PASS  $*"; }
fail() { FAILURES=$((FAILURES+1)); echo "FAIL  $*"; }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }

echo "=== relay self-test, $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo

echo "### 1. two guests on the segment reach each other through the relay"
python3 "$HERE/l2relay.py" --listen 127.0.0.1:15951 --listen 127.0.0.1:15952 \
    --pcap "$OUT/reachability.pcap" --marker "$MARKER" --summary "$OUT/reachability.txt" \
    --seconds 70 --attach-timeout 60 > "$OUT/reachability.log" 2>&1 &
RELAY=$!
sleep 1
shell_guest() { # PORT ADDRESS MAC CONSOLE COMMAND
  { printf '\n'; sleep 8
    printf 'busybox ip link set eth0 up\nbusybox ip addr add %s/24 dev eth0\n' "$2"; sleep 3
    printf '%s\n' "$5"; sleep 8
    printf 'busybox poweroff -f\n'; sleep 3; } | \
  timeout 60 "$QEMU" -enable-kvm -cpu EPYC-v4 -machine q35 -smp 2 -m 1024M \
     -no-reboot -nodefaults -display none \
     -kernel "$IMAGE/vmlinuz" -initrd "$IMAGE/initrd.img" \
     -append "console=ttyS0 panic=-1 rdinit=/bin/sh" \
     -netdev "socket,id=net0,connect=127.0.0.1:$1" \
     -device "virtio-net-pci,netdev=net0,mac=$3" \
     -serial stdio > "$4" 2>&1
}
shell_guest 15951 10.14.0.2 52:54:00:14:00:0a "$OUT/console-a.txt" "busybox ping -c 3 -W 2 10.14.0.3" &
A=$!
shell_guest 15952 10.14.0.3 52:54:00:14:00:0b "$OUT/console-b.txt" "busybox sleep 8" &
B=$!
# Waited for by name, never with a bare `wait`: this script's own stdout goes
# through a `tee` in a process substitution, which is a child that never exits
# on its own, so a bare wait here waits for the log writer and deadlocks. A
# guest killed by its timeout is still a guest whose console is worth reading,
# so a non-zero status is not the end of the run either.
wait "$A" || true; wait "$B" || true; wait "$RELAY" || true
sed -n '/PING /,/round-trip/p' "$OUT/console-a.txt" | sed 's/^/    /'
sed 's/^/    /' "$OUT/reachability.txt"
check "frames crossed the relay in both directions" \
      bash -c "grep -qE 'a_to_b_frames=[1-9]' '$OUT/reachability.txt' && grep -qE 'b_to_a_frames=[1-9]' '$OUT/reachability.txt'"
check "the two guests reached each other over it" grep -q "0% packet loss" "$OUT/console-a.txt"
check "only the two guests' own addresses were ever resolved" \
      bash -c "test -z \"\$(sed -n 's/.*arp targets : //p' '$OUT/reachability.txt' | tr ',' '\n' | tr -d ' ' | grep -v '^\$' | grep -vE '^10\.14\.0\.(2|3)\$')\""

echo
echo "### 2. the scanner, on a frame that really does carry the marker"
python3 "$HERE/l2relay.py" --listen 127.0.0.1:15953 --listen 127.0.0.1:15954 \
    --marker "$MARKER" --summary "$OUT/scanner.txt" --seconds 20 --attach-timeout 20 \
    > "$OUT/scanner.log" 2>&1 &
SCANNER=$!
sleep 1
MARKER="$MARKER" python3 - "$OUT/scanner-delivery.txt" <<'PY'
import os, socket, struct, sys, time
marker = os.environ["MARKER"].encode()
a = socket.create_connection(("127.0.0.1", 15953))
b = socket.create_connection(("127.0.0.1", 15954))
time.sleep(0.5)
frame = (bytes.fromhex("525400140b00") + bytes.fromhex("525400140a00") + b"\x08\x00"
         + b"\x45" + b"\x00" * 8 + b"\x11" + b"\x00" * 2
         + bytes([10, 14, 0, 2]) + bytes([10, 14, 0, 3]) + marker)
a.sendall(struct.pack("!I", len(frame)) + frame)
time.sleep(1)
got = b.recv(65536)
open(sys.argv[1], "w").write("delivered=%d marker_present=%s\n" % (len(got), marker in got))
a.close(); b.close()
PY
wait "$SCANNER" || true
sed 's/^/    /' "$OUT/scanner.txt"
check "the relay saw the plaintext when there was plaintext to see" \
      grep -q "MARKER FOUND" "$OUT/scanner.txt"
check "and delivered the frame to the other guest unchanged" \
      grep -q "marker_present=True" "$OUT/scanner-delivery.txt"

echo
echo "=== $PASSES passed, $FAILURES failed ==="
[ "$FAILURES" = 0 ]
