#!/bin/sh
# E3, exactly as it was run. Nothing in the repository is changed by it: the
# agent and the probes are the files beside this script, and the working
# directory is a temporary one because write_file writes into it.
#
# The API key comes from the environment and is never written anywhere under
# this directory. Always `deno run`, never `deno eval`, which ignores
# permission flags; always --no-prompt, so a missing capability is a refusal
# and not an interactive hang.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
D=/home/pniroula/.deno/bin/deno            # deno 2.9.6, pinned
W=$(mktemp -d)
run() { echo "### $1"; shift; echo "\$ deno run --no-prompt $*"; "$D" run --no-prompt "$@" 2>&1; echo "EXIT=$?"; echo; }

# The flag set, derived only from E1's table: the two destinations, the one
# file written, the one environment variable the key lives in.
FLAGS="--allow-net=api.anthropic.com:443,www.rfc-editor.org:443 --allow-write=./summary.txt --allow-env=ANTHROPIC_API_KEY"

for n in 1 2 3; do
  ( cd "$W" && rm -f summary.txt && "$D" run --no-prompt $FLAGS "$here/agent.ts" ) > "$here/run$n.log" 2>&1
done

# The negative: only the model endpoint is granted, and the tool's is not.
( cd "$W" && rm -f summary.txt && "$D" run --no-prompt \
    --allow-net=api.anthropic.com:443 --allow-write=./summary.txt --allow-env=ANTHROPIC_API_KEY \
    "$here/agent.ts" ) > "$here/denied-fetch.log" 2>&1

# Deno's own resource use, once.
( cd "$W" && rm -f summary.txt && strace -f -o "$here/run-strace.raw" \
    -e trace=%network,%file,%process -s 256 \
    "$D" run --no-prompt $FLAGS "$here/agent.ts" ) > "$here/run-strace.log" 2>&1

# The probes. Each log is the block of runs named in its first line; the exact
# commands are echoed into the log beside their output.
cd "$W"
{
  run "the flag set the agent ran under" $FLAGS "$here/probe-perms.ts"
  run "no flags" "$here/probe-perms.ts"
} > "$here/probes-perms.log" 2>&1
{
  run "--allow-net=0.0.0.0/0:443, hostname in the URL" --allow-net=0.0.0.0/0:443 "$here/probe-net.ts" https://www.rfc-editor.org/rfc/rfc8446.txt
  run "--allow-net=0.0.0.0/0, no port" --allow-net=0.0.0.0/0 "$here/probe-net.ts" https://www.rfc-editor.org/rfc/rfc8446.txt
  run "--allow-net=:443, a port with no host" --allow-net=:443 "$here/probe-net.ts" https://www.rfc-editor.org/rfc/rfc8446.txt
  run "--allow-net=160.79.104.10:443, an IP, hostname in the URL" --allow-net=160.79.104.10:443 "$here/probe-net.ts" https://api.anthropic.com/v1/messages
  run "--allow-net=160.79.104.10:443, the same IP literally in the URL" --allow-net=160.79.104.10:443 "$here/probe-net.ts" https://160.79.104.10/v1/messages
  run "--allow-net bare" --allow-net "$here/probe-net.ts" https://www.rfc-editor.org/rfc/rfc8446.txt
  run "--allow-net=api.anthropic.com:443 only, fetching rfc-editor" --allow-net=api.anthropic.com:443 "$here/probe-net.ts" https://www.rfc-editor.org/rfc/rfc8446.txt
  run "--allow-net=www.rfc-editor.org (no port)" --allow-net=www.rfc-editor.org "$here/probe-net.ts" https://www.rfc-editor.org/rfc/rfc8446.txt
  run "--allow-net=www.rfc-editor.org:80, wrong port" --allow-net=www.rfc-editor.org:80 "$here/probe-net.ts" https://www.rfc-editor.org/rfc/rfc8446.txt
  run "--allow-net=nonsense///" --allow-net='nonsense///' "$here/probe-net.ts" https://www.rfc-editor.org/rfc/rfc8446.txt
} > "$here/probes-net.log" 2>&1
{
  run "states under --allow-net=0.0.0.0/0:443" --allow-net=0.0.0.0/0:443 "$here/probe-perms.ts"
  run "states under --allow-net=160.79.104.10:443" --allow-net=160.79.104.10:443 "$here/probe-perms.ts"
  run "IP literal in the URL under --allow-net=160.79.104.10:443" --allow-net=160.79.104.10:443 "$here/probe-net.ts" https://160.79.104.10/v1/messages
  run "the hostname under the IP grant" --allow-net=160.79.104.10:443 "$here/probe-net.ts" https://api.anthropic.com/v1/messages
} > "$here/probes-net2.log" 2>&1
{
  run "states under --allow-net=160.79.104.0/24:443" --allow-net=160.79.104.0/24:443 "$here/probe-perms.ts"
  run "states under --allow-net=:443" --allow-net=:443 "$here/probe-perms.ts"
  run "connect 160.79.104.10:443 under --allow-net=0.0.0.0/0:443" --allow-net=0.0.0.0/0:443 "$here/probe-connect.ts" 160.79.104.10 443
  run "connect 160.79.104.10:80 under --allow-net=0.0.0.0/0:443" --allow-net=0.0.0.0/0:443 "$here/probe-connect.ts" 160.79.104.10 80
  run "connect api.anthropic.com:443 by NAME under --allow-net=0.0.0.0/0:443" --allow-net=0.0.0.0/0:443 "$here/probe-connect.ts" api.anthropic.com 443
  run "connect 127.0.0.53:53 under the agent's flag set" --allow-net=api.anthropic.com:443,www.rfc-editor.org:443 "$here/probe-connect.ts" 127.0.0.53 53
} > "$here/probes-net3.log" 2>&1
{
  run "grant /bin/true, run /bin/true, no arguments" --allow-run=/bin/true "$here/probe-run.ts" /bin/true
  run "grant /bin/true, run /bin/true with arguments" --allow-run=/bin/true "$here/probe-run.ts" /bin/true --whatever -x 'rm -rf /'
  run "grant /bin/true, run /bin/false" --allow-run=/bin/true "$here/probe-run.ts" /bin/false
  run "grant /bin/true, run bare 'true'" --allow-run=/bin/true "$here/probe-run.ts" true
  run "grant bare 'true', run bare 'true'" --allow-run=true "$here/probe-run.ts" true
  run "grant bare 'true', run /bin/true" --allow-run=true "$here/probe-run.ts" /bin/true
  run "grant /bin/sh, run /bin/sh -c" --allow-run=/bin/sh "$here/probe-run.ts" /bin/sh -c 'echo anything at all; id -un'
  run "grant a sha256 in place of a path" --allow-run=sha256:f0b6a7b0c0d0 "$here/probe-run.ts" /bin/true
  run "grant a path with a digest suffix" --allow-run='/bin/true@sha256:f0b6a7b0' "$here/probe-run.ts" /bin/true
  run "querying run under --allow-run=/bin/true" --allow-run=/bin/true "$here/probe-perms.ts"
} > "$here/probes-run.log" 2>&1
{
  run "grant /usr/bin/true, run /bin/true" --allow-run=/usr/bin/true "$here/probe-run.ts" /bin/true
  run "grant /usr/bin/true, run /usr/bin/true" --allow-run=/usr/bin/true "$here/probe-run.ts" /usr/bin/true
  rm -f summary.txt
  run "write ./summary.txt, which does not exist" --allow-write=./summary.txt "$here/probe-write.ts" ./summary.txt
  rm -f summary.txt
  run "write ./summary.txt under --allow-write=." --allow-write=. "$here/probe-write.ts" ./summary.txt
  rm -f summary.txt
  run "write ./other.txt under --allow-write=./summary.txt" --allow-write=./summary.txt "$here/probe-write.ts" ./other.txt
  run "write summary.txt (no ./) under --allow-write=./summary.txt" --allow-write=./summary.txt "$here/probe-write.ts" summary.txt
  rm -f summary.txt
  run "write /tmp/e3-elsewhere.txt under --allow-write=./summary.txt" --allow-write=./summary.txt "$here/probe-write.ts" /tmp/e3-elsewhere.txt
  mkdir -p sub && cd sub
  run "the same grant from a different cwd" --allow-write=./summary.txt "$here/probe-write.ts" ./summary.txt
} > "$here/probes-fsx.log" 2>&1
rm -rf "$W"
