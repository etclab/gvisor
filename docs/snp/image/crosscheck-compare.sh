#!/bin/bash
# The one permitted cross-check (ticket 07): compare the launch measurement a
# booted guest reported against the prediction that was written BEFORE it booted.
#
#   crosscheck-compare.sh IMAGE_DIR [CONSOLE]
#
# IMAGE_DIR was built by build-image.sh with TUNNELD=<crosscheck-report binary>
# and holds predicted-measurement.txt; CONSOLE (default IMAGE_DIR/console-snp.txt)
# is the serial log of its SNP boot, which crosscheck-report.c fills with the
# report as hex. The report is decoded by docs/snp/parse-snp-report.py, ticket
# 01's by-hand decoder, and its MEASUREMENT field is compared with the
# prediction. The result is appended to IMAGE_DIR/crosscheck.txt.
#
# This is the only place in the build where a measurement read from a machine
# is looked at, and it is compared, never recorded as a reference value.
set -euo pipefail
HERE="$(dirname "$(readlink -f "$0")")"
IMAGE="${1:?usage: crosscheck-compare.sh IMAGE_DIR [CONSOLE]}"
CONSOLE="${2:-$IMAGE/console-snp.txt}"
PRED=$(sed -n 's/^launch_measurement: //p' "$IMAGE/predicted-measurement.txt")
[[ "$PRED" =~ ^[0-9a-f]{96}$ ]] || { echo "no prediction in $IMAGE/predicted-measurement.txt" >&2; exit 1; }

sed -n '/BEGIN REPORT HEX/,/END REPORT HEX/p' "$CONSOLE" | grep -v 'REPORT HEX' | tr -d '\r\n' \
  | xxd -r -p > "$IMAGE/report.bin"
SZ=$(stat -c %s "$IMAGE/report.bin")
[ "$SZ" = 1184 ] || { echo "report recovered from console is $SZ bytes, want 1184" >&2; exit 1; }
python3 "$HERE/../parse-snp-report.py" "$IMAGE/report.bin" > "$IMAGE/report.txt"
GOT=$(sed -n 's/^LAUNCH MEASUREMENT (M) *: *//p' "$IMAGE/report.txt")

{
  echo "cross-check $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "  predicted (before boot, from build inputs): $PRED"
  echo "  reported  (by the booted guest, once):      $GOT"
  if [ "$PRED" = "$GOT" ]; then echo "  RESULT: MATCH — the offline computation is validated"
  else echo "  RESULT: MISMATCH — the model of the launch is wrong; fix the prediction, never the reference value"; fi
  grep -E '^(reported_tcb|policy|guest_svn|vmpl)' "$IMAGE/report.txt" | sed 's/^/  /'
} | tee -a "$IMAGE/crosscheck.txt"
[ "$PRED" = "$GOT" ]
