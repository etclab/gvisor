#!/bin/sh
# E1, exactly as it was run. The API key comes from the environment and is
# never written anywhere under this directory.
set -eu
export PATH=/usr/local/go/bin:$PATH
here=$(cd "$(dirname "$0")" && pwd)
work=${1:?usage: run.sh WORKDIR}
mkdir -p "$work"
go build -o "$work/agent" "$here"

# One run with nothing watching, to be sure the agent works.
( cd "$work" && ./agent ) > "$work/run-plain.log"

# Two runs under the filter the ticket names.
for n in 1 2; do
  ( cd "$work" && strace -f -o run$n-strace.raw -e trace=network,execve,openat -s 256 ./agent ) > "$work/run$n.log"
done

# One run under the wider filter, to see whether the first form missed a
# connect() or a path. It missed neither; it missed readlinkat, newfstatat and
# access, which is why this run is here.
( cd "$work" && strace -f -o run3-strace.raw -e trace=%network,%file,%process -s 256 ./agent ) > "$work/run3.log"

python3 "$here/derive.py" \
  run1="$work/run1-strace.raw" run2="$work/run2-strace.raw" run3="$work/run3-strace.raw" \
  --host api.anthropic.com --host www.rfc-editor.org > "$work/table.md"
