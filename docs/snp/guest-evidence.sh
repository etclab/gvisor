#!/bin/bash
# Run INSIDE the confidential guest, as root.
#
# Reads evidence out of the platform by hand through the vendor-neutral report
# interface at /sys/kernel/config/tsm/report/ and prints everything base64-encoded
# so it can be recovered from a serial console or an ssh session.
#
# Nothing here is AMD-specific except the interpretation of the bytes: the same
# path yields a TDX quote on Intel. That is the seam the design depends on.
set -u

OUT="${1:-/tmp/evidence}"
mkdir -p "$OUT"

echo "############ 1. is this actually a confidential guest? ############"
echo "--- kernel memory-encryption line ---"
dmesg | grep -iE "Memory Encryption Features active|SEV-SNP|sev=|SNP" | head -20
echo "--- /sys/kernel/debug/x86/sev_status (if debugfs is mounted) ---"
mount -t debugfs none /sys/kernel/debug 2>/dev/null
cat /sys/kernel/debug/x86/sev_status 2>&1 || echo "(not available)"
echo "--- CPUID 0x8000001F ---"
modprobe cpuid 2>/dev/null
if [ -e /dev/cpu/0/cpuid ]; then
  dd if=/dev/cpu/0/cpuid ibs=16 count=32 skip=134217728 2>/dev/null \
    | tail -c 16 | od -An -t x4 | sed 's/^/  eax ebx ecx edx: /'
fi
echo

echo "############ 2. report interface ############"
modprobe tsm 2>/dev/null
modprobe sev-guest 2>/dev/null
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
ls -l /dev/sev-guest 2>&1
echo "--- configfs tsm tree ---"
ls -l /sys/kernel/config/tsm/ 2>&1
ls -l /sys/kernel/config/tsm/report/ 2>&1
echo

echo "############ 3. acquire evidence ############"
D=/sys/kernel/config/tsm/report/ticket01
rmdir "$D" 2>/dev/null
mkdir "$D" || { echo "FAILED to create $D"; exit 1; }
echo "--- attributes exposed by this kernel ---"
ls -l "$D"

# 64 caller-supplied bytes. Fixed and recognisable so we can prove the report
# carries exactly what we asked for. (Milestone 1 replaces this with
# H(pubkey || binding-context) per ADR-0002.)
python3 - "$OUT/inblob.bin" <<'PY'
import sys
data = bytes(range(64))          # 00 01 02 ... 3f
open(sys.argv[1], "wb").write(data)
PY

# Must be a single write of 64 bytes.
dd if="$OUT/inblob.bin" of="$D/inblob" bs=64 count=1 status=none \
  && echo "inblob written (64 bytes, single write)" \
  || echo "inblob write FAILED"

echo "provider   : $(cat "$D/provider" 2>&1)"
echo "generation : $(cat "$D/generation" 2>&1)"
echo "privlevel  : $(cat "$D/privlevel" 2>/dev/null || echo '(not exposed)')"

cat "$D/outblob" > "$OUT/report.bin" 2>"$OUT/outblob.err"
echo "outblob    : $(stat -c %s "$OUT/report.bin" 2>/dev/null || echo 0) bytes  $(cat "$OUT/outblob.err")"

# THE question this ticket has to answer: is the platform-provisioned
# certificate chain here, or does verification have to reach AMD?
if [ -e "$D/auxblob" ]; then
  cat "$D/auxblob" > "$OUT/certs.bin" 2>"$OUT/auxblob.err"
  SZ=$(stat -c %s "$OUT/certs.bin" 2>/dev/null || echo 0)
  echo "auxblob    : $SZ bytes  $(cat "$OUT/auxblob.err")"
  if [ "$SZ" = "0" ]; then
    echo "AUXBLOB IS EMPTY -- host did not provision a certificate chain"
  fi
else
  echo "auxblob    : ATTRIBUTE ABSENT -- this kernel does not expose one"
  : > "$OUT/certs.bin"
fi

echo "generation after read : $(cat "$D/generation" 2>&1)"
rmdir "$D"
echo

echo "############ 4. base64 of collected evidence ############"
echo "===BEGIN report.bin==="
base64 -w0 "$OUT/report.bin" 2>/dev/null; echo
echo "===END report.bin==="
echo "===BEGIN certs.bin==="
base64 -w0 "$OUT/certs.bin" 2>/dev/null; echo
echo "===END certs.bin==="
