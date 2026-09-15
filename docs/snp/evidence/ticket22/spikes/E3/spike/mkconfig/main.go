// Command mkconfig writes the minimum config device a real tunneld needs in
// order to reach `-egress probe`, and nothing more.
//
// It exists because the ticket 19 probe lives behind a signature check: main.go
// loads tunneld.json, peers.json and the author key, and runEgressMode then
// loads policy.json under that key before it looks at the mode. E3 wants the
// REAL runEgressProbes, not a copy of it, so it has to satisfy that loader.
//
// The signing is reproduced here from attest/policyfile.go and
// attest/refvalsfile.go rather than imported, so that this program is stdlib
// only and the spike module has no dependency on the attest module:
//
//	signed bytes = "gvisor.dev/gvisor/attest policy signature v1\x00" || document
//	signature file = lowercase hex of the 64-byte Ed25519 signature, plus "\n"
//	author.pub = 64 lowercase hex characters (main.go readAuthorKey accepts
//	             either 32 raw bytes or their hexadecimal)
//
// The key is derived from a fixed seed so that two runs of this spike produce
// byte-identical files. It is a throwaway: nothing outside this spike has ever
// seen it and nothing should.
//
// Note what this program does NOT feed: the ceiling. The whole point of E3 is
// that the rule set in the kernel came from a constant in the image and not
// from anything written here. This config device exists only to get the probe
// to run.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const policySignaturePrefix = "gvisor.dev/gvisor/attest policy signature v1\x00"

// policyDocument is ticket 19's own policy.json, byte for byte
// (docs/snp/evidence/ticket19/scenario-one/config-src/a/policy.json). Reusing
// it rather than inventing one keeps the loader on the same path it took live.
const policyDocument = `{
  "format": "gvisor.dev/gvisor/attest/policy",
  "version": 1,
  "egress": {
    "version": 1,
    "unattested": false
  },
  "forward_to": [
    "d5ddcc423b1aed530237a6c43b3005d317464a94217dd9477f113007379dbf0fc7601cac8fa69bb48a4efd4322c73e0d"
  ]
}
`

const peerTableDocument = `{
  "format": "gvisor.dev/gvisor/attest/peer-table",
  "version": 1,
  "peers": {}
}
`

// runConfigDocument names a sandbox and a listen address and stops there: no
// exercise, no hold. -egress probe never serves.
const runConfigDocument = `{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "e3-ceiling",
  "listen": "10.128.0.40:4433"
}
`

func main() {
	dir := flag.String("dir", "", "directory to write the config device contents into")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "mkconfig: -dir is required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkconfig:", err)
		os.Exit(1)
	}

	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i + 1) // fixed: reruns are byte-identical
	}
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	sig := ed25519.Sign(priv, append([]byte(policySignaturePrefix), policyDocument...))

	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(*dir, name), b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "mkconfig:", err)
			os.Exit(1)
		}
		fmt.Printf("mkconfig: wrote %s (%d bytes)\n", name, len(b))
	}
	write("author.pub", []byte(hex.EncodeToString(pub)+"\n"))
	write("policy.json", []byte(policyDocument))
	write("policy.json.sig", []byte(hex.EncodeToString(sig)+"\n"))
	write("peers.json", []byte(peerTableDocument))
	write("tunneld.json", []byte(runConfigDocument))
}
