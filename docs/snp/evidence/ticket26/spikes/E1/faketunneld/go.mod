module faketunneld26

go 1.26.3

require gvisor.dev/gvisor/attest v0.0.0

require golang.org/x/sys v0.35.0 // indirect

replace gvisor.dev/gvisor/attest => ../../../../../../../attest
