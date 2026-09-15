// E4 serve-order driver. Not part of the repository; scratch only.
//
// This host is an SEV-SNP *host*, so /sys/kernel/config/tsm/report does not
// exist and the real tunneld's serve path dies in newVendorSeam (tsm.New)
// before it ever reaches tunneld.New. This driver stands in for that seam with
// a stub acquirer and verifier so that the document-loading order inside
// tunneld.New -- LoadReferenceValueSetFile, then LoadPolicyFile, then
// attest.New, then ratls.NewIdentity -- can be observed against a real config
// directory.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/tunneld"
)

type stubAcquirer struct{}

func (stubAcquirer) Vendor() attest.Vendor { return attest.VendorAMDSEVSNP }

func (stubAcquirer) Acquire(context.Context, [attest.CallerSuppliedBytesSize]byte) (attest.Evidence, error) {
	return attest.Evidence{}, errors.New("E4 stub acquirer: this host has no report interface; reaching this line means both config-device documents loaded")
}

type stubVerifier struct{}

func (stubVerifier) Vendor() attest.Vendor { return attest.VendorAMDSEVSNP }

func (stubVerifier) Verify(context.Context, attest.Evidence, attest.ReferenceValueSet) (attest.Attested, error) {
	return attest.Attested{}, errors.New("E4 stub verifier: never reached")
}

func main() {
	configDir := flag.String("config", "", "config directory")
	authorPath := flag.String("author", "", "author public key")
	listen := flag.String("listen", "127.0.0.1:0", "listen address")
	flag.Parse()

	raw, err := os.ReadFile(*authorPath)
	if err != nil {
		fmt.Printf("e4drv: %v\n", err)
		os.Exit(1)
	}
	author, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(author) != ed25519.PublicKeySize {
		fmt.Printf("e4drv: %s is not a hex Ed25519 public key\n", *authorPath)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	td, err := tunneld.New(ctx, tunneld.Config{
		SandboxID:             "e4-guest-a",
		Acquirer:              stubAcquirer{},
		Verifier:              stubVerifier{},
		ReferenceValueSetPath: filepath.Join(*configDir, "reference-values.json"),
		PolicyPath:            filepath.Join(*configDir, "policy.json"),
		AuthorPublicKey:       ed25519.PublicKey(author),
		Peers:                 tunneld.PeerTable{},
		ListenAddr:            *listen,
	})
	if err != nil {
		fmt.Printf("e4drv: tunneld.New refused: %v\n", err)
		fmt.Printf("e4drv: errors.Is(err, attest.ErrSetRefused)    = %v\n", errors.Is(err, attest.ErrSetRefused))
		fmt.Printf("e4drv: errors.Is(err, attest.ErrPolicyRefused) = %v\n", errors.Is(err, attest.ErrPolicyRefused))
		os.Exit(1)
	}
	defer td.Close()
	fmt.Printf("e4drv: tunneld.New returned; policy digest %s\n", td.PolicyDigest())
	os.Exit(0)
}
