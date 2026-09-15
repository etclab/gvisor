#!/bin/bash
# replay-verdicts.sh OUTDIR [COMMAND PREFIX ...]
#
# Replays every recorded verify-evidence invocation in verdict-invocations.txt
# and writes one transcript per invocation into OUTDIR:
#
#     NN-slug.txt
#         <the exact command line>
#         --- stdout ---
#         ...
#         --- stderr ---
#         ...
#         --- exit N ---
#
# NN is the invocation's position in the list, zero padded, so the ordering is
# the list's ordering and nothing else.
#
# The point of the split between this script and the list is that a later run
# changes only the command prefix.  Ticket 20 replayed
#
#     replay-verdicts.sh before                        # the default prefix
#
# and ticket 21, once cmd/verify-evidence is a subcommand of one workstation
# tool, replays the same list as
#
#     replay-verdicts.sh after /path/to/tool verify
#     replay-verdicts.sh after "/usr/local/go/bin/go run ./cmd/TOOL verify"
#
# and diffs the two directories.  Line 1 of each transcript is the command, so
# it differs by construction when the prefix does; the verdict itself is
# everything from line 2 on:
#
#     for f in after/*.txt; do
#       diff <(tail -n +2 "before/${f##*/}") <(tail -n +2 "$f") || echo "DIFF ${f##*/}"
#     done
#
# Defaults, each overridable by the environment:
#   REPLAY_PREFIX    /usr/local/go/bin/go run ./cmd/verify-evidence
#   REPLAY_CWD       $REPLAY_REPO/attest   (the prefix is run from here)
#   REPLAY_REPO      /home/pniroula/Projects/gvisor-tdx-work   (@REPO@)
#   REPLAY_AUTHORED  <dir of this script>/authored             (@AUTHORED@)
#   REPLAY_LIST      <dir of this script>/verdict-invocations.txt
#
# Two normalisations, both needed for a byte-for-byte before/after comparison:
#
#   * go-tdx-guest logs WARN lines carrying a wall-clock timestamp.  They are
#     rewritten to the literal TIMESTAMP, exactly as ticket 20's harness did.
#
#   * `go run` does not propagate a non-zero exit status: it prints
#     "exit status N" as the last line of stderr and itself exits 1.  When that
#     line is present and the wrapper exited 1, N is reported as the exit status
#     and the line is dropped, so a `go run` prefix and a built-binary prefix
#     produce identical transcripts.  A verify-evidence binary never writes that
#     line itself, so the rewrite cannot fire on real output.

set -u

usage() {
	sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-1}"
}

case "${1:-}" in
-h | --help | '') usage 0 ;;
esac

HERE=$(cd -- "$(dirname -- "$0")" && pwd)
OUT=$1
shift

REPO=${REPLAY_REPO:-/home/pniroula/Projects/gvisor-tdx-work}
AUTHORED=${REPLAY_AUTHORED:-$HERE/authored}
LIST=${REPLAY_LIST:-$HERE/verdict-invocations.txt}
CWD=${REPLAY_CWD:-$REPO/attest}

# The command prefix: the remaining arguments, or REPLAY_PREFIX, or the default.
# One argument containing whitespace is split, so both of these work:
#   replay-verdicts.sh out /path/to/tool verify
#   replay-verdicts.sh out "/path/to/tool verify"
if [ "$#" -gt 0 ]; then
	PREFIX=("$@")
else
	# shellcheck disable=SC2206
	PREFIX=(${REPLAY_PREFIX:-/usr/local/go/bin/go run ./cmd/verify-evidence})
fi
if [ "${#PREFIX[@]}" -eq 1 ]; then
	# shellcheck disable=SC2206
	PREFIX=(${PREFIX[0]})
fi

[ -r "$LIST" ] || { echo "replay-verdicts: no invocation list at $LIST" >&2; exit 2; }
[ -d "$CWD" ] || { echo "replay-verdicts: no working directory at $CWD" >&2; exit 2; }

mkdir -p "$OUT" || exit 2
OUT=$(cd -- "$OUT" && pwd)
rm -f "$OUT"/[0-9][0-9][0-9]-*.txt "$OUT/INDEX.txt" "$OUT/COMMANDS.txt"

TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT

SCRUB='s#[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?#TIMESTAMP#g'

{
	printf '# replay-verdicts.sh\n'
	printf '# list    : %s\n' "$LIST"
	printf '# prefix  : %s\n' "${PREFIX[*]}"
	printf '# cwd     : %s\n' "$CWD"
	printf '# @REPO@  : %s\n' "$REPO"
	printf '# @AUTHORED@: %s\n' "$AUTHORED"
	printf '#\n# NN\tslug\texit\n'
} > "$OUT/INDEX.txt"

n=0
while IFS=$'\t' read -r slug args || [ -n "${slug:-}" ]; do
	case "$slug" in '' | '#'*) continue ;; esac
	slug=${slug%$'\r'}
	args=${args-}
	args=${args//@REPO@/$REPO}
	args=${args//@AUTHORED@/$AUTHORED}

	n=$((n + 1))
	nn=$(printf '%03d' "$n")
	file="$OUT/$nn-$slug.txt"

	# Deliberately unquoted: the list holds no argument containing whitespace,
	# and this is what turns one line into an argument vector.
	# shellcheck disable=SC2086
	set -- $args

	( cd "$CWD" && "${PREFIX[@]}" "$@" ) < /dev/null > "$TMP/out" 2> "$TMP/err"
	code=$?

	sed -E "$SCRUB" "$TMP/out" > "$TMP/out.s"
	sed -E "$SCRUB" "$TMP/err" > "$TMP/err.s"

	# Undo `go run`'s swallowing of the exit status (see the header).
	if [ "$code" -eq 1 ] && [ -s "$TMP/err.s" ]; then
		last=$(tail -n 1 "$TMP/err.s")
		if [[ $last =~ ^exit\ status\ ([0-9]+)$ ]]; then
			code=${BASH_REMATCH[1]}
			sed -i '$ d' "$TMP/err.s"
		fi
	fi

	{
		printf '%s' "${PREFIX[*]}"
		for a in "$@"; do printf ' %s' "$a"; done
		printf '\n'
		printf -- '--- stdout ---\n'
		cat "$TMP/out.s"
		printf -- '--- stderr ---\n'
		cat "$TMP/err.s"
		printf -- '--- exit %s ---\n' "$code"
	} > "$file"

	printf '%s\t%s\t%s\n' "$nn" "$slug" "$code" >> "$OUT/INDEX.txt"
	printf '%s\t%s\n' "$slug" "$args" >> "$OUT/COMMANDS.txt"
done < "$LIST"

printf 'invocations: %d\n' "$n"
printf 'exit status histogram:\n'
awk -F'\t' '/^[0-9]/ {c[$3]++} END {for (k in c) printf "  exit %s: %d\n", k, c[k]}' "$OUT/INDEX.txt" | sort
printf 'transcripts in %s\n' "$OUT"
