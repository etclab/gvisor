#!/bin/sh
# Ticket 27's loopback proof: an acknowledged policy means the sandbox has it.
#
# This is ticket 26's harness — attest/cmd/agent-probe/governed_test.go, a test
# in the tree and not a file copied in to run — re-run against this branch's
# runsc, with the `hold + 60` idle-timeout workaround gone and a fifth scenario
# added:
#
#   off-policy   the push leaves the model endpoint out. The workload is
#                refused and the run reaches nothing.
#   on-policy    the push is the whole table. The workload gets through its
#                steps, and its exit ends liveness.
#   narrowed     the push is the whole table; a second peer removes the
#                document host while the workload is between its two requests;
#                a third peer tries to put it back and is refused.
#   killed       `runsc kill … KILL` mid-run, which is the same teardown
#                reached from outside.
#   early-push   the push is inside `Host.Apply` at `a` before `runsc` is
#                started at all. Apply waits there for the enforcing helper to
#                attach, hands it the document, and acknowledges only once the
#                sentry has applied it. An acknowledgement that came back
#                before the helper attached fails the run.
#
#   root ──push P──▶ tunneld a ──▶ a.sock ──▶ runsc tunnel-helper ──urpc──▶ sentry
#                        │                                            Policy.Narrow
#                        └──tunnel──▶ tunneld b ──▶ this test's exit ──▶ the network
#
# No API key is needed and none is read. The workload runs with
# `-without-model`, which leaves out the one step that needs one: the request to
# api.anthropic.com is made for real over the same client and therefore the same
# tunnel, with the body the loop builds and no x-api-key header, so what comes
# back is the API's own authentication error — and a status that came back at all
# is a stream that crossed the tunnel and an exit that dialled the model's host.
# The document host is then fetched the way the fetch_url tool fetches it. Every
# figure in the evidence is a status, a byte count or a duration that was
# measured; none of it is model output.
#
# --root lives under /dev/shm and not under the test's temporary directory,
# because a pushed policy is delivered over the sentry's control socket, whose
# path is --root plus runsc-<container id>.sock, and a sockaddr_un holds 108
# bytes (ticket 26's spike E1 §7a). The harness refuses to start a sandbox whose
# control socket would be longer than that.
#
#   AGENT_PROBE_RUNSC              the runsc under test. Build it with
#                                  `make runsc` from the repo root; `make test`
#                                  flips the symlink to fastbuild, so re-run
#                                  `make runsc` after it.
#   AGENT_PROBE_SECCHECK_RECEIVER  the program that listens on the remote sink
#                                  and prints one line per event; build it with
#                                  `go build -o <path> ./docs/snp/evidence/ticket26/tools/seccheck-receiver`
set -eu
export PATH=/usr/local/go/bin:$PATH
here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../../../../.." && pwd)
: "${AGENT_PROBE_RUNSC:=$tree/bazel-bin/runsc/runsc_/runsc}"
: "${AGENT_PROBE_SECCHECK_RECEIVER:=$tree/bazel-bin/seccheck-receiver}"
export AGENT_PROBE_RUNSC AGENT_PROBE_SECCHECK_RECEIVER
cd "$tree/attest"
AGENT_PROBE_LIVE=1 \
  go test ./cmd/agent-probe/ -run '^TestGovernedLoopback$' -count=1 -v -timeout 40m \
  2>&1 | tee "$here/run.log"
