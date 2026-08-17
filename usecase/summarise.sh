#!/usr/bin/env bash
# Print one comparison table over the most recent run of each pass.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

[ -d results ] || { echo "no results/ yet — run 'make sweep' or 'make pass1'"; exit 0; }

printf '\n%-6s %-38s %-22s %s\n' PASS RUNTIMES "SCOPE AT FINANCIAL" VERDICT
printf '%.0s-' {1..96}; printf '\n'

for p in 1 2 3; do
  dir="$(ls -d results/pass${p}-* 2>/dev/null | sort | tail -1)"
  if [ -z "$dir" ]; then
    printf '%-6s %-38s %-22s %s\n' "$p" "(not run)" - -
    continue
  fi
  # collapse "name runtime=X" lines into a compact per-runtime tally
  rts="$(awk '{split($2,a,"="); print a[2]}' "$dir/runtimes.txt" 2>/dev/null \
         | sort | uniq -c | awk '{printf "%sx%s ", $1, $2}')"
  scope="$(jq -r '[.[] | select(.event=="received") | .payload.scope] | last // "-"' \
           "$dir/financial-audit.json" 2>/dev/null || echo -)"
  verdict="$(grep -Eo 'ATTACK SUCCEEDED|attack blocked' "$dir/attack-poisoned.log" 2>/dev/null | head -1)"
  printf '%-6s %-38s %-22s %s\n' "$p" "${rts:-?}" "$scope" "${verdict:-?}"
done

printf '\nlatest results dirs:\n'
for p in 1 2 3; do ls -d results/pass${p}-* 2>/dev/null | sort | tail -1; done
echo
