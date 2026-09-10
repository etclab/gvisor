// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// emit-refvals renders and signs the two documents the image build emits: the
// reference value set (ticket 07) and, since ticket 19, the sandbox's own
// policy.
//
// It is the author-side half of attest/refvalsfile.go and attest/policyfile.go
// and uses those packages' own Marshal and Sign calls, so the documents the
// build ships and the documents tunneld loads agree by construction rather than
// by two implementations of one format. After writing each pair it loads them
// back through the same call tunneld makes and fails if that refuses.
//
//	emit-refvals -measurement HEX -key author.key.pem -out DIR \
//	             [-tcb bootloader,tee,snp,microcode] [-policy 0x30000] \
//	             [-policy-digest HEX]
//	emit-refvals -emit-policy -key author.key.pem -out DIR \
//	             [-forward-to HEX]...
//	emit-refvals -digest-of PATH
//
// The measurement is an input. This program has no way to obtain one from a
// platform, deliberately.
//
// # The set and the policy are two documents
//
// The default mode writes reference-values.json and its signature: whom this
// sandbox admits. -policy-digest is the peer policy a reference value admits —
// the digest of the peer's own signed policy, which that peer prints at
// startup. Left out, the value is unconstrained and admits a peer running the
// named image under any policy, which the guest that loads it logs one line
// about per value.
//
// -emit-policy writes policy.json and its signature: what this sandbox is. It
// carries the egress section and -forward-to, repeatable, naming each image
// this sandbox will dial. No -forward-to at all writes "forward_to": [], which
// is a sandbox that answers and never calls; that is a legitimate thing to
// write and it is written explicitly rather than left out, because a policy
// that says nothing has not said "nobody".
//
// A policy names measurements and never digests. That is the whole reason the
// two documents are separate: while a sandbox's policy was its own allow-list,
// two peers could not both pin each other, because each set would have had to
// contain the digest of the other (docs/policy-binding.md).
//
// After writing a policy, this prints its digest:
//
//	policy digest: <64 hex characters>
//
// That is the number to put in a *peer's* -policy-digest, and it is SHA-256
// over the bytes the signature covers rather than over the file, so sha256sum
// of policy.json is a different number and the wrong one. -digest-of prints the
// same line for a policy that already exists, without a key and without loading
// it, so a harness can read a digest off a document it did not emit.
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

// forwardTo collects the repeatable -forward-to flag. It is a list because a
// sandbox may dial more than one image — an old one and a new one during a
// rollout, exactly as a reference value set names two.
type forwardTo []string

func (f *forwardTo) String() string { return strings.Join(*f, ",") }
func (f *forwardTo) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func main() {
	measurement := flag.String("measurement", "", "predicted launch measurement, hex")
	keyPath := flag.String("key", "", "reference value author's Ed25519 private key, PKCS#8 PEM (openssl genpkey -algorithm ed25519)")
	out := flag.String("out", "", "output directory for the documents and their signatures")
	tcb := flag.String("tcb", "", "TCB floor as bootloader,tee,snp,microcode (all four required)")
	policy := flag.String("policy", "0x30000", "SEV-SNP guest policy the guest is launched with; the emitted guest_policy permits exactly its bits")
	policyDigest := flag.String("policy-digest", "", "the peer policy this reference value admits, hex; empty leaves the value unconstrained, which admits any policy")
	emitPolicy := flag.Bool("emit-policy", false, "write policy.json and its signature instead of a reference value set")
	var forward forwardTo
	flag.Var(&forward, "forward-to", "with -emit-policy: a launch measurement this sandbox will dial, hex; repeatable, and none at all means it dials nobody")
	digestOf := flag.String("digest-of", "", "print the policy digest of an existing policy document and exit; emits nothing")
	flag.Parse()
	if *digestOf != "" {
		if err := printDigestOf(*digestOf); err != nil {
			fmt.Fprintln(os.Stderr, "emit-refvals:", err)
			os.Exit(1)
		}
		return
	}
	var err error
	if *emitPolicy {
		err = runPolicy(*keyPath, *out, forward)
	} else {
		err = run(*measurement, *keyPath, *out, *tcb, *policy, *policyDigest)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "emit-refvals:", err)
		os.Exit(1)
	}
}

// printDigestOf prints the policy digest of a document already on disk.
//
// It does not load the policy and does not want the author's public key: the
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

// runPolicy writes the sandbox's own policy and prints its digest.
//
// The egress section is not a parameter. The only thing this build can honestly
// say is that unattested egress is refused — nothing enforces permitting it —
// so the zero value is rendered and there is no flag with which to write down
// something untrue.
func runPolicy(keyPath, out string, forward []string) error {
	measurements, err := parseForwardTo(forward)
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
	doc, err := attest.MarshalPolicy(attest.Policy{ForwardTo: measurements})
	if err != nil {
		return err
	}
	sig, err := attest.SignPolicy(doc, priv)
	if err != nil {
		return err
	}
	docPath := filepath.Join(out, "policy.json")
	if err := os.WriteFile(docPath, doc, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(docPath+attest.SignatureFileSuffix, sig, 0o644); err != nil {
		return err
	}

	// Ship what you signed: load the files back exactly as tunneld will.
	loaded, err := attest.LoadPolicyFile(docPath, pub)
	if err != nil {
		return fmt.Errorf("the emitted policy does not load back: %w", err)
	}
	if len(loaded.ForwardTo) != len(measurements) {
		return fmt.Errorf("the emitted policy loaded back forwarding to %d image(s), not %d", len(loaded.ForwardTo), len(measurements))
	}
	for i, m := range measurements {
		if !bytes.Equal(loaded.ForwardTo[i], m) {
			return fmt.Errorf("the emitted policy loaded back forwarding to a different image at position %d", i)
		}
	}
	if loaded.Digest != attest.PolicyDigestOf(doc) {
		return fmt.Errorf("the loader and this program disagree about the emitted policy's digest")
	}

	fmt.Printf("author public key: %s\n", hex.EncodeToString(pub))
	fmt.Printf("wrote %s and %s (loads back through attest.LoadPolicyFile)\n", docPath, docPath+attest.SignatureFileSuffix)
	if len(measurements) == 0 {
		fmt.Printf("forwards to nobody (no -forward-to given; the guest says so once at start)\n")
	}
	for _, m := range measurements {
		fmt.Printf("forwards to: %s\n", hex.EncodeToString(m))
	}
	// Last, and on its own line, because it is the line a harness reads: the
	// name of the document just written, for a peer's -policy-digest.
	fmt.Printf("policy digest: %s\n", loaded.Digest)
	return nil
}

// parseForwardTo reads the measurements a policy will dial. A width is not
// checked, deliberately: how wide a launch measurement is belongs to the
// hardware vendor, and a measurement that matches nothing fails closed. What is
// checked is that each is non-empty hexadecimal, because an entry that is
// neither is a typo rather than a decision.
func parseForwardTo(specs []string) ([][]byte, error) {
	out := make([][]byte, 0, len(specs))
	for i, s := range specs {
		m, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("-forward-to #%d is not hexadecimal: %v", i+1, err)
		}
		if len(m) == 0 {
			return nil, fmt.Errorf("-forward-to #%d is empty; a measurement of no bytes names no image", i+1)
		}
		out = append(out, m)
	}
	return out, nil
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
	// Nothing about egress appears here. Since format version 4 the set is the
	// guest list and only that; what this sandbox is belongs to the policy,
	// which -emit-policy writes.
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

	fmt.Printf("author public key: %s\n", hex.EncodeToString(pub))
	fmt.Printf("wrote %s and %s (loads back through attest.LoadReferenceValueSetFile)\n", docPath, docPath+attest.SignatureFileSuffix)
	if admitted == nil {
		fmt.Printf("admits any peer policy (no -policy-digest given; the guest logs one line per unconstrained value)\n")
	} else {
		fmt.Printf("admits peer policy: %s\n", admitted)
	}
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
