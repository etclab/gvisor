// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// verify-evidence produces a verdict on one evidence bundle, outside the guest
// that produced it (ticket 05).
//
//	verify-evidence -bundle DIR -refvals PATH -author PATH
//
// It is what a tunneld does when it meets a peer, with the tunnel left out:
// load the reference value set the author signed, wire it to a verifier, and
// ask for a verdict on the evidence and the key it claims to be bound to.
//
// Everything it does is composition. The set is loaded by
// attest.LoadReferenceValueSetFile, the verdict is
// attest.Verification.Verify's, and the SEV-SNP answers behind it are
// attest/verify's; there is no verification, no parsing and no policy here.
// What this adds is a place to stand outside the guest, an exit status, and
// output an operator can read.
//
// It reaches no network, and there is no flag that would let it. The chain
// comes out of the bundle, having been provisioned onto the config device
// ahead of use (ADR-0005), and the vendor root is either a local file or the
// AMD roots embedded in the verification library. Ticket 05's harness runs it
// inside an empty network namespace to show that this is a property of the
// code and not of the machine it happens to run on.
//
// Exit status: 0 accepted, 2 refused, 3 the reference value set was refused,
// 1 anything else. A refusal is not an error in this program's sense — it is
// the answer — so it is a status of its own.
//
// The procedure this is part of is docs/verification-on-hardware.md.
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
	"gvisor.dev/gvisor/attest/verify"
)

// Exit statuses. A verdict of refused is an answer rather than a failure, so
// it does not share a status with a missing file or a bad flag.
const (
	exitAccepted   = 0
	exitFailed     = 1
	exitRefused    = 2
	exitSetRefused = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

func run(args []string, out *os.File) int {
	fs := flag.NewFlagSet("verify-evidence", flag.ContinueOnError)
	bundle := fs.String("bundle", "", "directory holding the bundle acquire-evidence wrote")
	evidencePath := fs.String("evidence", "", "the evidence; default <bundle>/evidence.bin")
	chainPath := fs.String("chain", "", "the certificate chain provisioned with it; default <bundle>/certificate-chain.bin")
	keyPath := fs.String("key", "", "the public key the evidence claims to be bound to, PKIX SubjectPublicKeyInfo; default <bundle>/public-key.der")
	refvals := fs.String("refvals", "", "the signed reference value set; its signature is the file at this path plus "+attest.SignatureFileSuffix)
	author := fs.String("author", "", "the reference value author's Ed25519 public key: 32 raw bytes or hexadecimal")
	vendorRoot := fs.String("vendor-root", "", "PEM file holding the vendor root (ASK and ARK); empty uses the AMD roots embedded in the verification library, which is the production path")
	productLine := fs.String("product-line", "", "the AMD product line -vendor-root is for, such as Genoa; required with -vendor-root")
	withoutChain := fs.Bool("without-chain", false, "present the evidence with no certificate chain at all, to exercise what a verifier does with one (ADR-0005)")
	nowFlag := fs.String("now", "", "RFC 3339 instant at which certificate validity is judged; empty means now")
	if err := fs.Parse(args); err != nil {
		return exitFailed
	}

	code, err := verdict(fs, out, options{
		bundle:       *bundle,
		evidencePath: *evidencePath,
		chainPath:    *chainPath,
		keyPath:      *keyPath,
		refvals:      *refvals,
		author:       *author,
		vendorRoot:   *vendorRoot,
		productLine:  *productLine,
		withoutChain: *withoutChain,
		now:          *nowFlag,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-evidence:", err)
	}
	return code
}

type options struct {
	bundle       string
	evidencePath string
	chainPath    string
	keyPath      string
	refvals      string
	author       string
	vendorRoot   string
	productLine  string
	withoutChain bool
	now          string
}

func verdict(fs *flag.FlagSet, out *os.File, o options) (int, error) {
	if o.refvals == "" || o.author == "" {
		fs.Usage()
		return exitFailed, errors.New("-refvals and -author are both required: a verifier with no reference value set admits nobody, and one that would take an unsigned set is not this design")
	}
	inBundle := func(explicit, name string) string {
		if explicit != "" {
			return explicit
		}
		if o.bundle == "" {
			return ""
		}
		return filepath.Join(o.bundle, name)
	}
	evidencePath := inBundle(o.evidencePath, "evidence.bin")
	chainPath := inBundle(o.chainPath, "certificate-chain.bin")
	keyPath := inBundle(o.keyPath, "public-key.der")
	if evidencePath == "" || keyPath == "" {
		fs.Usage()
		return exitFailed, errors.New("no -bundle, and no -evidence and -key to stand in for one")
	}

	evidence, err := os.ReadFile(evidencePath)
	if err != nil {
		return exitFailed, fmt.Errorf("reading the evidence: %w", err)
	}
	publicKey, err := os.ReadFile(keyPath)
	if err != nil {
		return exitFailed, fmt.Errorf("reading the public key the evidence is bound to: %w", err)
	}
	var chain []byte
	switch {
	case o.withoutChain:
		// Deliberately none. The acquirer will not produce a bundle without
		// one — provision.LoadFor refuses first — so this is how a peer that
		// skipped that step is modelled.
	case chainPath == "":
		return exitFailed, errors.New("no certificate chain path, and -without-chain was not asked for")
	default:
		if chain, err = os.ReadFile(chainPath); err != nil {
			return exitFailed, fmt.Errorf("reading the provisioned certificate chain: %w", err)
		}
	}

	authorKey, err := readAuthorKey(o.author)
	if err != nil {
		return exitFailed, err
	}
	var at time.Time
	if o.now != "" {
		if at, err = time.Parse(time.RFC3339, o.now); err != nil {
			return exitFailed, fmt.Errorf("-now: %w", err)
		}
	}
	var rootPEM []byte
	if o.vendorRoot != "" {
		if rootPEM, err = os.ReadFile(o.vendorRoot); err != nil {
			return exitFailed, fmt.Errorf("reading the vendor root: %w", err)
		}
	}

	fmt.Fprintf(out, "evidence            : %s, %d bytes\n", evidencePath, len(evidence))
	if o.withoutChain {
		fmt.Fprintf(out, "certificate chain   : none presented (-without-chain)\n")
	} else {
		fmt.Fprintf(out, "certificate chain   : %s, %d bytes (provisioned, ADR-0005)\n", chainPath, len(chain))
	}
	fmt.Fprintf(out, "public key (SPKI)   : %s, %d bytes, %x\n", keyPath, len(publicKey), publicKey)
	fmt.Fprintf(out, "binding context     : v1, %x\n", attest.BindingContextV1[:])
	if rootPEM == nil {
		fmt.Fprintf(out, "vendor root         : the AMD roots embedded in the verification library — no fetch, no file\n")
	} else {
		fmt.Fprintf(out, "vendor root         : %s (%s)\n", o.vendorRoot, o.productLine)
	}

	// The trust root. A set that is missing, unsigned, or signed by another
	// key is refused here and there is nothing to fall back to.
	set, err := attest.LoadReferenceValueSetFile(o.refvals, authorKey)
	if err != nil {
		fmt.Fprintf(out, "reference value set : %s — REFUSED\n", o.refvals)
		fmt.Fprintf(out, "\nSET REFUSED\n  %v\n", err)
		return exitSetRefused, nil
	}
	fmt.Fprintf(out, "reference value set : %s, %d value(s), author %x\n", o.refvals, len(set.Values), []byte(authorKey))
	for i, rv := range set.Values {
		fmt.Fprintf(out, "  [%d] launch measurement %x\n", i, rv.LaunchMeasurement)
		fmt.Fprintf(out, "      minimum TCB        bootloader=%d tee=%d snp=%d microcode=%d\n",
			rv.MinimumTCB.Bootloader, rv.MinimumTCB.TEE, rv.MinimumTCB.SNP, rv.MinimumTCB.Microcode)
		fmt.Fprintf(out, "      guest policy       %s\n", policyString(rv.GuestPolicy))
	}

	verifier, err := verify.New(verify.Options{VendorRootPEM: rootPEM, ProductLine: o.productLine, Now: at})
	if err != nil {
		return exitFailed, err
	}
	verification, err := attest.New(verifier, set)
	if err != nil {
		return exitFailed, err
	}

	binding := attest.Binding{PublicKey: publicKey, Context: attest.BindingContextV1}
	attested, err := verification.Verify(context.Background(), attest.Evidence{
		Vendor: attest.VendorAMDSEVSNP,
		Bytes:  evidence,
		Chain:  chain,
	}, binding)
	if err != nil {
		var refusal *attest.Refusal
		errors.As(err, &refusal)
		fmt.Fprintf(out, "\nREFUSED\n")
		fmt.Fprintf(out, "  reason            : %v\n", attest.ReasonOf(err))
		if refusal != nil {
			fmt.Fprintf(out, "  operator log      : %s\n", refusal.LogString())
		}
		fmt.Fprintf(out, "  a caller learns   : %v\n", err)
		return exitRefused, nil
	}

	fmt.Fprintf(out, "\nACCEPTED\n")
	fmt.Fprintf(out, "  vendor            : %s\n", attested.Vendor)
	fmt.Fprintf(out, "  launch measurement: %x\n", attested.Claims.LaunchMeasurement)
	fmt.Fprintf(out, "  reported TCB      : bootloader=%d tee=%d snp=%d microcode=%d\n",
		attested.Claims.TCB.Bootloader, attested.Claims.TCB.TEE, attested.Claims.TCB.SNP, attested.Claims.TCB.Microcode)
	fmt.Fprintf(out, "  caller-supplied   : %x\n", attested.Claims.CallerSuppliedBytes[:])
	fmt.Fprintf(out, "    = SHA-512(public key ‖ binding context), recomputed from the key above (ADR-0002)\n")
	fmt.Fprintf(out, "  satisfied         : reference value with launch measurement %x\n", attested.Satisfied.LaunchMeasurement)
	return exitAccepted, nil
}

// readAuthorKey reads the reference value author's public key from a file
// holding either the 32 raw bytes or their hexadecimal, with surrounding
// whitespace ignored. Both exist in the wild: emit-refvals prints hexadecimal
// and a key derived with openssl is raw.
func readAuthorKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the reference value author's public key: %w", err)
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is neither %d raw bytes nor their hexadecimal", path, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

// policyString renders what a reference value permits, naming every field, so
// that the record of a run shows the whole ceiling rather than the bits that
// happened to be set.
func policyString(p attest.GuestPolicy) string {
	return fmt.Sprintf("abi=%d.%d smt=%t migration_agent=%t debug=%t single_socket_required=%t",
		p.ABIMajor, p.ABIMinor, p.AllowSMT, p.AllowMigrationAgent, p.AllowDebug, p.RequireSingleSocket)
}
