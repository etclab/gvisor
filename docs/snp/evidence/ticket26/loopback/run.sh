#!/bin/sh
# Ticket 26's loopback proof, exactly as it was run.
#
# The harness is a test in the tree — attest/cmd/agent-probe/governed_test.go —
# and not a file copied in to run, for ticket 23's reason: everything it needs
# is already a package. It is ticket 25's loopback world (adapter_test.go) with
# one thing added: a third tunneld, `root`, that dials `a` and pushes a policy
# at it, so that the document reaches the sentry inside the sandbox over a
# tunnel rather than through a flag.
#
#   root ──push P──▶ tunneld a ──▶ a.sock ──▶ runsc tunnel-helper ──urpc──▶ sentry
#                        │                                            Policy.Narrow
#                        └──tunnel──▶ tunneld b ──▶ this test's exit ──▶ the network
#
# This is where the model-backed agent task is proven under a pushed policy: the
# compiled-in egress ceiling (attest/ceiling) permits no TCP egress from a
# measured guest, so the two-guest proof cannot run an agent that talks to a
# model and this can.
#
# Four sandboxes, one after another, sharing a rootfs, a bundle shape, an exit,
# an allow list and a --tunnel-table that names both destinations. What differs
# is the policy pushed and when:
#
#   off-policy  the push leaves api.anthropic.com out. The agent is refused and
#               the run costs nothing.
#   on-policy   the push is the whole table. The task completes, and the
#               workload's exit ends liveness.
#   narrowed    the push is the whole table; a second peer removes
#               www.rfc-editor.org while the task runs; a third peer tries to
#               put it back and is refused.
#   killed      `runsc kill … KILL` mid-task, which is the same teardown reached
#               from outside.
#
# ANTHROPIC_API_KEY must already be in the environment. It is copied into the
# bundle's config.json, which is written under a 0700 directory in /dev/shm —
# tmpfs, never a disk — and removed when the test ends; the rootfs the sandbox
# executes holds no secret. Every captured file is searched for the key before
# it is copied into the evidence, and one that carries it is left behind with a
# .redacted copy in its place.
#
# --root lives under /dev/shm and not under the test's temporary directory,
# because a pushed policy is delivered over the sentry's control socket, whose
# path is --root plus runsc-<container id>.sock, and a sockaddr_un holds 108
# bytes (spike E1 §7a). The harness refuses to start a sandbox whose control
# socket would be longer than that.
#
#   AGENT_PROBE_SECCHECK_RECEIVER  the program that listens on the remote sink
#                                  and prints one line per event; build it with
#                                  `go build -o <path> ./docs/snp/evidence/ticket26/tools/seccheck-receiver`
set -eu
export PATH=/usr/local/go/bin:$PATH
here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../../../.." && pwd)        # the worktree root
: "${AGENT_PROBE_RUNSC:=$tree/bazel-bin/runsc/runsc_/runsc}"
export AGENT_PROBE_RUNSC
cd "$tree/attest"
AGENT_PROBE_LIVE=1 \
  go test ./cmd/agent-probe/ -run TestGovernedLoopback -count=1 -v -timeout 40m \
  > "$here/run.log" 2>&1
