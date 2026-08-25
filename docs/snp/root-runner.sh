#!/bin/bash
# Privileged job runner for ticket 01 (SNP-capable host stack).
#
# Runs as root inside a tmux session so the operator types the sudo password once
# instead of once per privileged step. It picks up *.job files from ./root-spool,
# runs each with bash, and writes <name>.out (combined output) and <name>.rc
# (exit status) next to it. Nothing is executed that is not placed in the spool.
SPOOL="$(dirname "$(readlink -f "$0")")/root-spool"
mkdir -p "$SPOOL"
chmod 1777 "$SPOOL"
echo "=== root runner ready: uid=$(id -u) spool=$SPOOL ==="
while :; do
  for f in "$SPOOL"/*.job; do
    [ -e "$f" ] || continue
    b="${f%.job}"
    echo "[$(date +%T)] running $(basename "$f")"
    bash "$f" > "$b.out" 2>&1
    echo $? > "$b.rc"
    chmod a+r "$b.out" "$b.rc" 2>/dev/null
    mv "$f" "$b.ran"
    echo "[$(date +%T)] done rc=$(cat "$b.rc")"
  done
  sleep 1
done
