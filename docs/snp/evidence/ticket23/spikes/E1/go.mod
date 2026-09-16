// Nested module: this spike is deliberately outside the gvisor root module and
// outside attest/, so that nothing in the tree builds or depends on it. It
// needs nothing but the standard library.
module gvisor.dev/gvisor/docs/snp/evidence/ticket23/spikes/E1

go 1.26.3
