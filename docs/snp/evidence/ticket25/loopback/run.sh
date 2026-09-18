#!/bin/sh
# The adapter over loopback, exactly as it was run.
#
# The harness is a test in the tree — attest/cmd/agent-probe/adapter_test.go —
# and not a file copied in to run, for ticket 23's reason: everything it needs
# is already a package. The two tunnelds are the loopback harness with the fake
# SNP platform, the exit is ticket 23's own `socketSandbox` + `ServeExit`, and
# the workload is attest/cmd/agent-probe built with CGO_ENABLED=0 and run as
# `-network plain`, which is `&http.Client{}` and nothing else. It skips unless
# the two variables below are set, so `go test ./...` in attest/ stays green and
# free.
#
# It runs two runsc sandboxes one after the other. They share a rootfs, a
# bundle shape, an exit and an allow list; the only thing that differs is
# --tunnel-table, and the second one's leaves out api.anthropic.com so that the
# refusal is attributable to the table and to nothing else.
#
# ANTHROPIC_API_KEY must already be in the environment. It is copied into the
# bundle's config.json, which is written under a 0700 directory in /dev/shm —
# tmpfs, never a disk — and removed when the test ends; the rootfs the sandbox
# executes holds no secret. Every captured file is searched for the key before
# it is copied into the evidence, and one that carries it is left behind with a
# .redacted copy in its place. The sentry writes the container's spec into its
# debug log and process.env is in the spec, so the boot, gofer and run logs
# always match and are always the withheld ones.
#
# Two switches, for the two things that may not be on the machine:
#   AGENT_PROBE_SECCHECK_RECEIVER  the program that listens on the remote sink
#                                  and prints one line per event; without it the
#                                  run records no sentry/egress_refused event
#                                  and says so in its README.
#   AGENT_PROBE_ADAPTER=0          drop the --tunnel-* flags, for a rehearsal
#                                  against a runsc that does not have them. Such
#                                  a run proves the bundle and nothing else, and
#                                  its evidence is not committed.
set -eu
export PATH=/usr/local/go/bin:$PATH
here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../../../../.." && pwd)     # the worktree root
: "${AGENT_PROBE_RUNSC:=$tree/bazel-bin/runsc/runsc_/runsc}"
export AGENT_PROBE_RUNSC
cd "$tree/attest"
AGENT_PROBE_LIVE=1 \
  go test ./cmd/agent-probe/ -run TestAdapterLoopback -count=1 -v -timeout 30m \
  > "$here/run.log" 2>&1
