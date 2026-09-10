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

// emit-tdx-refvals renders and signs a reference value set for an Intel TDX
// peer on a provider-booted VM: one reference value naming the registers the
// provider fixes, the register the image decides, the TD attributes it permits
// and the Intel TCB level it will accept.
//
// It is emit-refvals' counterpart for the second vendor and works the same way:
// it uses the attest package's own MarshalReferenceValueSet and
// SignReferenceValueSet, so the document an operator ships and the document
// tunneld loads agree by construction rather than by two implementations of one
// format, and after writing both files it loads them back through
// LoadReferenceValueSetFile — the call tunneld makes — and fails if that
// refuses.
//
//	emit-tdx-refvals -rtmr2 HEX \
//	                 -mrtd HEX [-mrtd HEX …] \
//	                 -rtmr0 HEX [-rtmr0 HEX …] \
//	                 -rtmr1 HEX [-rtmr1 HEX …] \
//	                 -tcb-evaluation N [-tcb-status UpToDate|SWHardeningNeeded] \
//	                 [-policy-digest HEX] [-allow-debug] -key author.key.pem -out DIR
//
// # -policy-digest is what makes admission constrained
//
// A reference value naming no policy digest admits a peer running the named
// image under *any* policy, which is the weaker reading and the one every set
// authored before ticket 18 has. Naming one admits that image only when the
// peer presents that policy, which is the pairing docs/policy-binding.md
// describes: the digest is over the bytes the author signed over the peer's
// policy.json, and the peer's own tunneld prints it at start. It is optional
// here and not defaulted, because "any policy" has to be something an author
// wrote down rather than something a tool assumed.
//
// # -rtmr2 must be the predicted value, never one read from a quote
//
// RTMR2 is the only register here that names the image: it covers grub, the
// kernel and the command line. Its value must be the one
// docs/snp/cloud/tdx/predict-rtmr2.py computed from the disk image before
// anything booted — paste what that script printed. A value read out of a
// running guest's quote, however convenient, is not a prediction: it is the
// machine being asked what it is, and a reference value built from it admits
// whatever that machine happens to be running. Such a check cannot fail, which
// is the same as not having one.
//
// # -mrtd, -rtmr0 and -rtmr1 are observed constants, and each may repeat
//
// MRTD is the firmware the provider boots, RTMR0 its configuration and RTMR1
// its boot chain. None of them can be predicted from anything the reference
// value author holds (docs/tdx-rtmr2-prediction.md), so they are pinned as
// values observed on real hardware — which admits the provider's current boot
// stack and nothing else, and finds out when the provider changes it.
//
// Each flag may be repeated because the provider's values are not single: on
// every Google VM on record RTMR1 takes one value on the VM's first boot,
// before the root partition is grown, and another on every boot after. A set
// naming one would refuse its own peer after a reboot.
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

	"gvisor.dev/gvisor/attest"
)

func main() {
	var mrtd, rtmr0, rtmr1 hexList
	var evaluation optionalUint
	flag.Var(&mrtd, "mrtd", "observed MRTD, hex; repeat the flag to admit more than one value")
	flag.Var(&rtmr0, "rtmr0", "observed RTMR0, hex; repeatable")
	flag.Var(&rtmr1, "rtmr1", "observed RTMR1, hex; repeatable (a Google VM's first boot and its later boots differ)")
	flag.Var(&evaluation, "tcb-evaluation", "lowest tcbEvaluationDataNumber the provisioned Intel TCB info may carry (required)")
	rtmr2 := flag.String("rtmr2", "", "PREDICTED RTMR2, hex: the value predict-rtmr2.py printed, never one read from a quote")
	status := flag.String("tcb-status", string(attest.TDXTCBUpToDate), "lowest Intel TCB status admitted: UpToDate or SWHardeningNeeded")
	policyDigest := flag.String("policy-digest", "", "the peer policy this reference value admits, hex; empty leaves the value unconstrained, which admits any policy")
	allowDebug := flag.Bool("allow-debug", false, "permit a TD created with TD_ATTRIBUTES.DEBUG, which lets the host read its memory")
	keyPath := flag.String("key", "", "reference value author's Ed25519 private key, PKCS#8 PEM (openssl genpkey -algorithm ed25519)")
	out := flag.String("out", "", "output directory for reference-values.json and reference-values.json.sig")
	flag.Parse()

	if err := run(options{
		mrtd:         mrtd,
		rtmr0:        rtmr0,
		rtmr1:        rtmr1,
		rtmr2:        *rtmr2,
		status:       *status,
		evaluation:   evaluation,
		allowDebug:   *allowDebug,
		policyDigest: *policyDigest,
		keyPath:      *keyPath,
		out:          *out,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "emit-tdx-refvals:", err)
		os.Exit(1)
	}
}

type options struct {
	mrtd, rtmr0, rtmr1 hexList
	rtmr2              string
	status             string
	evaluation         optionalUint
	allowDebug         bool
	policyDigest       string
	keyPath, out       string
}

func run(o options) error {
	observed := map[string][][]byte{}
	for _, r := range []struct {
		flag   string
		values hexList
	}{
		{"-mrtd", o.mrtd},
		{"-rtmr0", o.rtmr0},
		{"-rtmr1", o.rtmr1},
	} {
		if len(r.values) == 0 {
			return fmt.Errorf("%s is required; a register with no expected value is a register not checked", r.flag)
		}
		decoded, err := decodeRegisters(r.flag, r.values)
		if err != nil {
			return err
		}
		observed[r.flag] = decoded
	}
	predicted, err := decodeRegister("-rtmr2", o.rtmr2)
	if err != nil {
		return err
	}
	floor := attest.TDXTCBStatus(o.status)
	if floor != attest.TDXTCBUpToDate && floor != attest.TDXTCBSWHardeningNeeded {
		return fmt.Errorf("-tcb-status is %q; a floor is %q or %q", o.status,
			attest.TDXTCBUpToDate, attest.TDXTCBSWHardeningNeeded)
	}
	if !o.evaluation.set {
		// Intel raises this number on every TCB recovery, and a TCB info from
		// before a recovery still verifies and still calls a since-vulnerable
		// platform UpToDate. The host provisions that collateral, so a floor
		// left unwritten is the one the host chooses.
		return fmt.Errorf("-tcb-evaluation is required; without it the set admits TCB info from before any TCB recovery")
	}
	priv, err := loadKey(o.keyPath)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if o.out == "" {
		return fmt.Errorf("-out is required")
	}

	admitted, err := parsePolicyDigest(o.policyDigest)
	if err != nil {
		return err
	}

	set := attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		Vendor:       attest.VendorIntelTDX,
		PolicyDigest: admitted,
		TDX: &attest.TDXReferenceValue{
			ObservedMRTD:   observed["-mrtd"],
			ObservedRTMR0:  observed["-rtmr0"],
			ObservedRTMR1:  observed["-rtmr1"],
			PredictedRTMR2: predicted,
			TDPolicy:       attest.TDPolicy{AllowDebug: o.allowDebug},
			MinimumTCB: attest.TDXTCBFloor{
				Status:               floor,
				EvaluationDataNumber: uint32(o.evaluation.value),
			},
		},
	}}}
	doc, err := attest.MarshalReferenceValueSet(set)
	if err != nil {
		return err
	}
	sig, err := attest.SignReferenceValueSet(doc, priv)
	if err != nil {
		return err
	}
	docPath := filepath.Join(o.out, "reference-values.json")
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
	if len(loaded.Values) != 1 || loaded.Values[0].TDX == nil ||
		!bytes.Equal(loaded.Values[0].TDX.PredictedRTMR2, predicted) {
		return fmt.Errorf("the emitted set loaded back naming a different RTMR2")
	}
	if admitted == nil {
		if loaded.Values[0].PolicyDigest != nil {
			return fmt.Errorf("the emitted set loaded back naming a policy digest nobody asked for")
		}
	} else if loaded.Values[0].PolicyDigest == nil || *loaded.Values[0].PolicyDigest != *admitted {
		return fmt.Errorf("the emitted set loaded back naming a different policy digest")
	}
	fmt.Printf("author public key: %s\n", hex.EncodeToString(pub))
	if admitted == nil {
		fmt.Printf("admits peer policy: any (this value lists no policy_digest, which is the weaker reading)\n")
	} else {
		fmt.Printf("admits peer policy: %s\n", admitted)
	}
	fmt.Printf("wrote %s and %s (loads back through attest.LoadReferenceValueSetFile)\n", docPath, docPath+attest.SignatureFileSuffix)
	return nil
}

// parsePolicyDigest reads -policy-digest: absent means unconstrained, and a
// present one has to be a whole SHA-256. There is no third state -- a partial
// digest would compare equal to nothing and refuse every peer silently.
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

// decodeRegisters decodes one repeatable register flag's values.
func decodeRegisters(flagName string, values hexList) ([][]byte, error) {
	out := make([][]byte, 0, len(values))
	for _, v := range values {
		b, err := decodeRegister(flagName, v)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// decodeRegister decodes one register value. The loader deliberately checks no
// width — that belongs to the hardware vendor — but this author-side tool knows
// it is emitting TDX values, whose registers are SHA-384 and therefore 48
// bytes. A value of another width would load and match nothing, which fails
// closed silently; here it is a typo and is worth naming.
func decodeRegister(flagName, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required, as non-empty hex", flagName)
	}
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hexadecimal: %v", flagName, err)
	}
	if len(b) != 48 {
		return nil, fmt.Errorf("%s is %d bytes; a TDX measurement register is 48", flagName, len(b))
	}
	return b, nil
}

// hexList is a flag that may be repeated, in the order given.
type hexList []string

func (l *hexList) String() string {
	if l == nil {
		return ""
	}
	return fmt.Sprint([]string(*l))
}

func (l *hexList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// optionalUint is a flag whose absence is distinguishable from zero, because
// zero is a legal floor ("impose none") and leaving the flag out is not.
type optionalUint struct {
	value uint64
	set   bool
}

func (o *optionalUint) String() string {
	if o == nil || !o.set {
		return ""
	}
	return strconv.FormatUint(o.value, 10)
}

func (o *optionalUint) Set(v string) error {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return err
	}
	o.value, o.set = n, true
	return nil
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
