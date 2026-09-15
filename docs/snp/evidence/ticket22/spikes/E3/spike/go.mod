// A nested module, deliberately: it keeps these spike programs out of the
// gvisor root module's ./... expansion, so nothing under docs/ is ever built
// or vetted as part of the repository proper.
//
// The versions are attest/go.mod's, exactly, so that ceilinginstall compiles
// against the same github.com/google/nftables the real tunneld does and the
// two agree about what they send the kernel.
module e3spike

go 1.26.3

require (
	github.com/google/nftables v0.3.0
	golang.org/x/sys v0.35.0
)

require (
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
)
