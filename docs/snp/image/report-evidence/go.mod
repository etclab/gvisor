module gvisor.dev/gvisor/docs/snp/image/report-evidence

go 1.26.3

require gvisor.dev/gvisor/attest v0.0.0

require (
	github.com/google/go-sev-guest v0.15.0 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20240902060211-1f7f7b9b42b9 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

replace gvisor.dev/gvisor/attest => ../../../../attest
