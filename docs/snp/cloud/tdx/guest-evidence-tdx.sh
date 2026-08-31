#!/bin/bash
# Run INSIDE a TDX confidential guest, as root.
#
# The Intel counterpart of docs/snp/guest-evidence.sh, and deliberately the
# same four steps: create a request under /sys/kernel/config/tsm/report, write
# the caller-supplied bytes to inblob in one write, read outblob, remove the
# request. attest/tsm's package comment claims those four steps "yield an
# SEV-SNP report on AMD and TDX evidence on Intel"; this script is the first
# thing in this project that tests the second half of that sentence.
#
# Everything is printed base64-encoded so it survives an ssh session.
set -u

OUT="${1:-/tmp/evidence}"
mkdir -p "$OUT"

echo "############ 0. what is this guest ############"
uname -r
head -2 /etc/os-release
echo "--- kernel command line, as the running kernel sees it ---"
cat /proc/cmdline
echo

echo "############ 1. is this actually a TDX guest? ############"
echo "--- kernel memory-encryption line ---"
dmesg 2>/dev/null | grep -iE "Memory Encryption Features active|tdx|TDX" | head -20
echo "--- CPUID leaf 0x21 signature (TDX module reports 'IntelTDX    ') ---"
modprobe cpuid 2>/dev/null
if [ -e /dev/cpu/0/cpuid ]; then
  dd if=/dev/cpu/0/cpuid ibs=16 count=1 skip=2 2>/dev/null | od -An -c | head -2
fi
echo "--- guest device nodes ---"
ls -l /dev/tdx_guest /dev/tdx-guest /dev/sev-guest 2>&1
echo

echo "############ 2. report interface ############"
modprobe tsm 2>/dev/null
modprobe tdx-guest 2>/dev/null
modprobe tdx_guest 2>/dev/null
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
echo "--- configfs tsm tree ---"
ls -l /sys/kernel/config/tsm/ 2>&1
ls -l /sys/kernel/config/tsm/report/ 2>&1
echo

echo "############ 3. acquire evidence ############"
D=/sys/kernel/config/tsm/report/tdxprobe
rmdir "$D" 2>/dev/null
mkdir "$D" || { echo "FAILED to create $D"; exit 1; }
echo "--- attributes exposed by this kernel ---"
ls -l "$D"

# The same 64 recognisable caller-supplied bytes guest-evidence.sh uses: 00..3f.
# TDX REPORTDATA is 64 bytes, the same width as SEV-SNP REPORT_DATA, which is
# why attest.CallerSuppliedBytesSize needs no thought here.
python3 - "$OUT/inblob.bin" <<'PY'
import sys
open(sys.argv[1], "wb").write(bytes(range(64)))
PY

dd if="$OUT/inblob.bin" of="$D/inblob" bs=64 count=1 status=none \
  && echo "inblob written (64 bytes, single write)" \
  || echo "inblob write FAILED"

echo "provider   : $(cat "$D/provider" 2>&1)"
echo "generation : $(cat "$D/generation" 2>&1)"
echo "privlevel  : $(cat "$D/privlevel" 2>/dev/null || echo '(not exposed)')"

cat "$D/outblob" > "$OUT/quote.bin" 2>"$OUT/outblob.err"
echo "outblob    : $(stat -c %s "$OUT/quote.bin" 2>/dev/null || echo 0) bytes  $(cat "$OUT/outblob.err")"

# auxblob: on AMD this is where a host would put the VCEK chain, and probe 2 of
# the SEV-SNP run found Google fills it. Intel's collateral is not distributed
# that way, so the interesting answer here is whether the attribute exists at all.
if [ -e "$D/auxblob" ]; then
  cat "$D/auxblob" > "$OUT/aux.bin" 2>"$OUT/auxblob.err"
  echo "auxblob    : $(stat -c %s "$OUT/aux.bin" 2>/dev/null || echo 0) bytes  $(cat "$OUT/auxblob.err")"
else
  echo "auxblob    : ATTRIBUTE ABSENT -- this kernel does not expose one"
  : > "$OUT/aux.bin"
fi
rmdir "$D" 2>/dev/null && echo "request removed" || echo "request NOT removed"
echo

echo "############ 4. the bytes ############"
for f in quote.bin aux.bin; do
  [ -s "$OUT/$f" ] || continue
  echo "===BEGIN $f==="
  base64 -w 100 "$OUT/$f"
  echo "===END $f==="
done
