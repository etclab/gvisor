// The rung-5a federation substrate, as its OWN Go module.
//
// Deliberately not part of the gVisor module. Conventions section 1 says nothing
// outside ladder/ and the gated patches should change, and adding quic-go and
// wormhole-william to the runtime's go.mod would change the thing the ladder is
// meant to leave alone. It also keeps the honest answer to "did rung 5a touch the
// gVisor tree?" a simple no.
module gvisor.dev/ladder/fed

// quic-go v0.59.0 needs 1.24; the repo's own toolchain is newer still, so this is
// the floor rather than a preference.
go 1.25.0

require (
	github.com/psanford/wormhole-william v1.0.7
	github.com/quic-go/quic-go v0.59.0
)

require (
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/net v0.45.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	nhooyr.io/websocket v1.8.17 // indirect
	salsa.debian.org/vasudev/gospake2 v0.0.0-20210510093858-d91629950ad1 // indirect
)
