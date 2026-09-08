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

// emit-refvals renders and signs the reference value set the image build
// emits (ticket 07): one reference value whose launch measurement is the
// offline prediction, with the TCB floor and guest policy the author chose.
//
// It is the author-side half of attest/refvalsfile.go and uses that package's
// own MarshalReferenceValueSet and SignReferenceValueSet, so the document the
// build ships and the document tunneld loads agree by construction rather
// than by two implementations of one format. After writing both files it
// loads them back through LoadReferenceValueSetFile with the public key
// derived from the signing key — the same call tunneld makes — and fails if
// that refuses.
//
//	emit-refvals -measurement HEX -key author.key.pem -out DIR \
//	             [-tcb bootloader,tee,snp,microcode] [-policy 0x30000] \
//	             [-policy-digest HEX]
//	emit-refvals -digest-of PATH
//
// The measurement is an input. This program has no way to obtain one from a
// platform, deliberately.
//
// -policy-digest is the peer policy this reference value admits: the digest of
// the peer's own signed set, which that peer prints at startup. Left out, the
// value is unconstrained and admits a peer running the named image under any
// policy — which is what every set authored before ticket 18 says, and which
// the guest that loads it logs one line about per value.
//
// After writing the pair, this prints the emitted document's own policy digest:
//
//	policy digest: <64 hex characters>
//
// That is the number to put in a *peer's* -policy-digest, and it is SHA-256
// over the bytes the signature covers rather than over the file, so sha256sum
// of reference-values.json is a different number and the wrong one. -digest-of
// prints the same line for a set that already exists, without a key and without
// loading it, so a harness can read a digest off a document it did not emit.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/attest"
)

func main() {
	measurement := flag.String("measurement", "", "predicted launch measurement, hex")
	keyPath := flag.String("key", "", "reference value author's Ed25519 private key, PKCS#8 PEM (openssl genpkey -algorithm ed25519)")
	out := flag.String("out", "", "output directory for reference-values.json and reference-values.json.sig")
	tcb := flag.String("tcb", "", "TCB floor as bootloader,tee,snp,microcode (all four required)")
	policy := flag.String("policy", "0x30000", "SEV-SNP guest policy the guest is launched with; the emitted guest_policy permits exactly its bits")
	policyDigest := flag.String("policy-digest", "", "the peer policy this reference value admits, hex; empty leaves the value unconstrained, which admits any policy")
	digestOf := flag.String("digest-of", "", "print the policy digest of an existing reference value set and exit; emits nothing")
	flag.Parse()
	if *digestOf != "" {
		if err := printDigestOf(*digestOf); err != nil {
			fmt.Fprintln(os.Stderr, "emit-refvals:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*measurement, *keyPath, *out, *tcb, *policy, *policyDigest); err != nil {
		fmt.Fprintln(os.Stderr, "emit-refvals:", err)
		os.Exit(1)
	}
}

// printDigestOf prints the policy digest of a document already on disk.
//
// It does not load the set and does not want the author's public key: the
// digest is over bytes, and asking a harness to hold a key in order to learn
// the name of a file it can already read would buy nothing. What it reads has
// to be the document as delivered, which is the only thing a signature ever
// covered.
func printDigestOf(path string) error {
	document, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fmt.Printf("policy digest: %s\n", attest.PolicyDigestOf(document))
	return nil
}

func run(measurementHex, keyPath, out, tcbSpec, policySpec, policyDigestHex string) error {
	m, err := hex.DecodeString(measurementHex)
	if err != nil || len(m) == 0 {
		return fmt.Errorf("-measurement must be non-empty hex")
	}
	if len(m) != 48 {
		// The loader deliberately checks no width; this author-side tool
		// knows it is emitting an SEV-SNP value, which is 384 bits.
		return fmt.Errorf("-measurement is %d bytes; an SEV-SNP launch measurement is 48", len(m))
	}
	floor, err := parseTCB(tcbSpec)
	if err != nil {
		return err
	}
	gp, err := parsePolicy(policySpec)
	if err != nil {
		return err
	}
	admitted, err := parsePolicyDigest(policyDigestHex)
	if err != nil {
		return err
	}
	priv, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if out == "" {
		return fmt.Errorf("-out is required")
	}

	// The vendor is written down rather than defaulted: since format version 2
	// every reference value says whose evidence it admits, and this program
	// emits SEV-SNP values only (see the -measurement width check above).
	//
	// The egress section is not a parameter. Version 3 requires one, and the
	// only thing this build can honestly say is that unattested egress is
	// refused — nothing enforces permitting it — so the zero value is rendered
	// and there is no flag with which to write down something untrue.
	set := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: m,
		MinimumTCB:        floor,
		GuestPolicy:       gp,
		PolicyDigest:      admitted,
	}}}
	doc, err := attest.MarshalReferenceValueSet(set)
	if err != nil {
		return err
	}
	sig, err := attest.SignReferenceValueSet(doc, priv)
	if err != nil {
		return err
	}
	docPath := filepath.Join(out, "reference-values.json")
	if err := os.WriteFile(docPath, doc, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(docPath+attest.SignatureFileSuffix, sig, 0o644); err != nil {
		return err
	}

	// Ship what you signed: load the files back exactly as tunneld will.
	loaded, err := attest.LoadReferenceValueSetFile(docPath, pub)
	if err != nil {
		return fmt.Errorf("the emitted set does not load back: %w", err)
	}
	if len(loaded.Values) != 1 || !bytes.Equal(loaded.Values[0].LaunchMeasurement, m) {
		return fmt.Errorf("the emitted set loaded back with a different measurement")
	}
	if admitted == nil {
		if loaded.Values[0].PolicyDigest != nil {
			return fmt.Errorf("the emitted set loaded back constraining a policy nobody asked for")
		}
	} else if loaded.Values[0].PolicyDigest == nil || *loaded.Values[0].PolicyDigest != *admitted {
		return fmt.Errorf("the emitted set loaded back admitting a different policy")
	}
	if loaded.PolicyDigest != attest.PolicyDigestOf(doc) {
		return fmt.Errorf("the loader and this program disagree about the emitted set's policy digest")
	}

	fmt.Printf("author public key: %s\n", hex.EncodeToString(pub))
	fmt.Printf("wrote %s and %s (loads back through attest.LoadReferenceValueSetFile)\n", docPath, docPath+attest.SignatureFileSuffix)
	if admitted == nil {
		fmt.Printf("admits any peer policy (no -policy-digest given; the guest logs one line per unconstrained value)\n")
	} else {
		fmt.Printf("admits peer policy: %s\n", admitted)
	}
	// Last, and on its own line, because it is the line a harness reads: the
	// name of the document just written, for a peer's -policy-digest.
	fmt.Printf("policy digest: %s\n", loaded.PolicyDigest)
	return nil
}

// parsePolicyDigest reads -policy-digest: absent means unconstrained, and
// anything present must be exactly a digest. A short or long value is refused
// rather than padded, because it would name a policy no peer can present while
// looking like an allow-list entry that works.
func parsePolicyDigest(spec string) (*attest.PolicyDigest, error) {
	if spec == "" {
		return nil, nil
	}
	raw, err := hex.DecodeString(spec)
	if err != nil {
		return nil, fmt.Errorf("-policy-digest is not hexadecimal: %v", err)
	}
	var digest attest.PolicyDigest
	if len(raw) != len(digest) {
		return nil, fmt.Errorf("-policy-digest is %d bytes; a policy digest is %d", len(raw), len(digest))
	}
	copy(digest[:], raw)
	return &digest, nil
}

func parseTCB(spec string) (attest.TCB, error) {
	parts := strings.Split(spec, ",")
	if len(parts) != 4 {
		return attest.TCB{}, fmt.Errorf("-tcb must be bootloader,tee,snp,microcode")
	}
	var v [4]uint8
	for i, p := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
		if err != nil {
			return attest.TCB{}, fmt.Errorf("-tcb component %d: %v", i, err)
		}
		v[i] = uint8(n)
	}
	return attest.TCB{Bootloader: v[0], TEE: v[1], SNP: v[2], Microcode: v[3]}, nil
}

// parsePolicy maps the SEV-SNP GUEST_POLICY the launch uses onto what the
// reference value permits: each permission bit set in the policy is
// permitted, and nothing else is. ABI major/minor are the policy's own.
func parsePolicy(spec string) (attest.GuestPolicy, error) {
	p, err := strconv.ParseUint(spec, 0, 64)
	if err != nil {
		return attest.GuestPolicy{}, fmt.Errorf("-policy: %v", err)
	}
	if p&(1<<17) == 0 {
		return attest.GuestPolicy{}, fmt.Errorf("-policy bit 17 is reserved-must-be-one; %#x is not a valid guest policy", p)
	}
	return attest.GuestPolicy{
		ABIMinor:            uint8(p & 0xff),
		ABIMajor:            uint8(p >> 8 & 0xff),
		AllowSMT:            p&(1<<16) != 0,
		AllowMigrationAgent: p&(1<<18) != 0,
		AllowDebug:          p&(1<<19) != 0,
		RequireSingleSocket: p&(1<<20) != 0,
	}, nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("-key is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PKCS#8 PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return priv, nil
}
