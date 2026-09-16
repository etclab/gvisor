#!/bin/sh
# E2, exactly as it was run. The harness is a _test.go file because
# attest/internal/fixture is an internal package and the two tunnelds this
# needs are the ones every test in attest/tunneld starts; it is copied back
# into the tree only to be run, and is not part of the tree.
#
# The API key comes from the environment and is never written anywhere under
# this directory.
set -eu
export PATH=/usr/local/go/bin:$PATH
here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../../../../.." && pwd)     # the worktree root
cp "$here/e2_agent_on_the_contract_test.go.txt" "$tree/attest/tunneld/spike23_e2_test.go"
trap 'rm -f "$tree/attest/tunneld/spike23_e2_test.go"' EXIT
cd "$tree/attest"
for n in 1 2 3; do
  go test ./tunneld/ -run TestSpike23E2 -v -count=1 -timeout 15m > "$here/run$n.log" 2>&1
done
