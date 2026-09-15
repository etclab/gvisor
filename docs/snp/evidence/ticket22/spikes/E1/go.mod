// Nested module: this spike is deliberately outside the gvisor root module and
// outside attest/, so that nothing in the tree builds or depends on it. It
// pins the same quic-go version attest/go.mod pins.
module gvisor.dev/gvisor/docs/snp/evidence/ticket22/spikes/E1

go 1.26.3

require (
	github.com/quic-go/quic-go v0.59.0
	golang.org/x/sys v0.35.0
)

require (
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
)
