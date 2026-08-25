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
//	             [-tcb bootloader,tee,snp,microcode] [-policy 0x30000]
//
// The measurement is an input. This program has no way to obtain one from a
// platform, deliberately.
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
	flag.Parse()
	if err := run(*measurement, *keyPath, *out, *tcb, *policy); err != nil {
		fmt.Fprintln(os.Stderr, "emit-refvals:", err)
		os.Exit(1)
	}
}

func run(measurementHex, keyPath, out, tcbSpec, policySpec string) error {
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
	priv, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if out == "" {
		return fmt.Errorf("-out is required")
	}

	set := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		LaunchMeasurement: m,
		MinimumTCB:        floor,
		GuestPolicy:       gp,
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
	fmt.Printf("author public key: %s\n", hex.EncodeToString(pub))
	fmt.Printf("wrote %s and %s (loads back through attest.LoadReferenceValueSetFile)\n", docPath, docPath+attest.SignatureFileSuffix)
	return nil
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
