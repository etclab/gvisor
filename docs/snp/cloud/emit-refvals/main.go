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

// emit-refvals (cloud) signs a reference value set admitting MORE THAN ONE
// measurement. docs/snp/image/emit-refvals emits a set of exactly one, which
// is what a run of two guests from one image needs; the mixed run's two peers
// cannot run the same image, so each side's set has to admit the other's
// measurement, and a set is a list precisely so that it can.
//
//	emit-refvals -key AUTHOR.key -out DIR \
//	    -value M_HEX:bootloader,tee,snp,microcode:POLICY [-value ...]
//
// The values come from two different places and PROVENANCE.md beside the
// emitted set says which: one is a prediction from build inputs (ticket 07's
// tool), the other is the provider's firmware measurement, read off a booted
// VM and matched against the provider's own signed launch endorsement.
// Nothing here knows or checks the difference; the file beside it does.
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

type values []string

func (v *values) String() string     { return strings.Join(*v, " ") }
func (v *values) Set(s string) error { *v = append(*v, s); return nil }

func main() {
	var specs values
	flag.Var(&specs, "value", "M_HEX:bootloader,tee,snp,microcode:POLICY; repeatable")
	keyPath := flag.String("key", "", "reference value author's Ed25519 private key, PKCS#8 PEM")
	out := flag.String("out", "", "output directory for reference-values.json and .sig")
	flag.Parse()
	if err := run(specs, *keyPath, *out); err != nil {
		fmt.Fprintln(os.Stderr, "emit-refvals:", err)
		os.Exit(1)
	}
}

func run(specs []string, keyPath, out string) error {
	if len(specs) == 0 || out == "" {
		return fmt.Errorf("-value (at least one) and -out are required")
	}
	priv, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	var set attest.ReferenceValueSet
	for _, spec := range specs {
		parts := strings.Split(spec, ":")
		if len(parts) != 3 {
			return fmt.Errorf("-value %q is not M:tcb:policy", spec)
		}
		m, err := hex.DecodeString(parts[0])
		if err != nil || len(m) != 48 {
			return fmt.Errorf("-value %q: measurement must be 48 bytes of hex", spec)
		}
		floor, err := parseTCB(parts[1])
		if err != nil {
			return err
		}
		gp, err := parsePolicy(parts[2])
		if err != nil {
			return err
		}
		set.Values = append(set.Values, attest.ReferenceValue{LaunchMeasurement: m, MinimumTCB: floor, GuestPolicy: gp})
	}
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
	loaded, err := attest.LoadReferenceValueSetFile(docPath, pub)
	if err != nil {
		return fmt.Errorf("the emitted set does not load back: %w", err)
	}
	if len(loaded.Values) != len(set.Values) {
		return fmt.Errorf("the emitted set loaded back with %d values, not %d", len(loaded.Values), len(set.Values))
	}
	for i := range set.Values {
		if !bytes.Equal(loaded.Values[i].LaunchMeasurement, set.Values[i].LaunchMeasurement) {
			return fmt.Errorf("value %d loaded back with a different measurement", i)
		}
	}
	fmt.Printf("author public key: %s\n", hex.EncodeToString(pub))
	fmt.Printf("wrote %s and %s with %d values (loads back through attest.LoadReferenceValueSetFile)\n", docPath, docPath+attest.SignatureFileSuffix, len(set.Values))
	return nil
}

func parseTCB(spec string) (attest.TCB, error) {
	parts := strings.Split(spec, ",")
	if len(parts) != 4 {
		return attest.TCB{}, fmt.Errorf("tcb must be bootloader,tee,snp,microcode")
	}
	var v [4]uint8
	for i, p := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
		if err != nil {
			return attest.TCB{}, fmt.Errorf("tcb component %d: %v", i, err)
		}
		v[i] = uint8(n)
	}
	return attest.TCB{Bootloader: v[0], TEE: v[1], SNP: v[2], Microcode: v[3]}, nil
}

func parsePolicy(spec string) (attest.GuestPolicy, error) {
	p, err := strconv.ParseUint(spec, 0, 64)
	if err != nil {
		return attest.GuestPolicy{}, fmt.Errorf("policy: %v", err)
	}
	if p&(1<<17) == 0 {
		return attest.GuestPolicy{}, fmt.Errorf("policy bit 17 is reserved-must-be-one; %#x is not a valid guest policy", p)
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
