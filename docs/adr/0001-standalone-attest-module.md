# Milestones 1-3 build as a standalone Go module outside the bazel graph

`attest/` carries its own `go.mod` and builds with plain `go build`, not through this repo's
bazel/gazelle graph, until the sentry integration in Milestone 4 forces the question. The
memo's Milestones 1-3 (offline evidence and verification, the measured image, RA-TLS between
two supervisors) are explicitly independent of the gVisor tree, and they are where the risk
sits; keeping them out of bazel means the dependencies they need — `go-sev-guest`, a QUIC
library and their transitives — cost a `go get` rather than a `go.mod` edit plus a `use_repo`
entry in `MODULE.bazel` per package.

## Consequences

Two build systems coexist in one tree for the duration, and integrating at Milestone 4 is a
real step rather than a no-op: every `attest/` dependency must then be registered in
`MODULE.bazel` and gain BUILD files. This is deliberate — that cost is paid once, against
proven code, instead of on every iteration of unproven code. It also deviates from gvisor's
`pkg/<name>` convention, which is why the directory sits at the repo root rather than
pretending to be an ordinary gvisor package.
