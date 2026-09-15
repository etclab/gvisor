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

package main

import (
	"context"
	"crypto/ed25519"
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

// runVerify produces a verdict on one evidence bundle, outside the guest that
// produced it (ticket 05).
//
//	attest-tool verify -bundle DIR -refvals PATH -author PATH \
//	                   [-policy-digest HEX]
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
func runVerify(args []string, out *os.File) int {
	// The flag set keeps the name the program had before ticket 21 folded it
	// into attest-tool: it is what -h prints and what an error line is prefixed
	// with, and the transcripts recorded against it are the evidence for tickets
	// 05, 08 and 19.
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
	nowFlag := fs.String("now", "", "RFC 3339 instant at which certificate validity is judged and Intel collateral expiry is decided; empty means now")
	vendor := fs.String("vendor", string(attest.VendorAMDSEVSNP), "the hardware that produced the evidence: "+string(attest.VendorAMDSEVSNP)+" or "+string(attest.VendorIntelTDX)+". It is a flag rather than a guess: sniffing the format of an untrusted blob to decide which parser to hand it to is the mistake the vendor tag exists to prevent")
	tdxCollateralDir := fs.String("tdx-collateral-dir", "", "directory holding Intel's provisioned TCB info, quoting-enclave identity and revocation lists; required to verify Intel TDX evidence, and never fetched (ADR-0005)")
	tdxRoot := fs.String("tdx-root", "", "PEM file holding the Intel SGX Root CA; empty uses the Intel root embedded in the verification library, which is the production path")
	policyDigest := fs.String("policy-digest", "", "the policy digest the bundle is bound to, hex — sha256 over the bytes the author signed over the peer's policy.json, which emit-refvals -digest-of prints; empty is 32 zero bytes")
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
		vendor:       attest.Vendor(*vendor),
		tdxDir:       *tdxCollateralDir,
		tdxRoot:      *tdxRoot,
		policyDigest: *policyDigest,
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
	vendor       attest.Vendor
	tdxDir       string
	tdxRoot      string
	policyDigest string
}

func verdict(fs *flag.FlagSet, out *os.File, o options) (int, error) {
	p, err := o.present(fs)
	if err != nil {
		return exitFailed, err
	}

	fmt.Fprintf(out, "evidence            : %s, %d bytes\n", p.evidencePath, len(p.evidence))
	fmt.Fprintf(out, "vendor              : %s\n", o.vendor)
	switch {
	case o.vendor == attest.VendorIntelTDX:
		fmt.Fprintf(out, "certificate chain   : carried inside the quote\n")
	case o.withoutChain:
		fmt.Fprintf(out, "certificate chain   : none presented (-without-chain)\n")
	default:
		fmt.Fprintf(out, "certificate chain   : %s, %d bytes (provisioned, ADR-0005)\n", p.chainPath, len(p.chain))
	}
	fmt.Fprintf(out, "public key (SPKI)   : %s, %d bytes, %x\n", p.keyPath, len(p.publicKey), p.publicKey)
	printBinding(out, p.binding)
	printTrustRoots(out, o, p)

	// The trust root. A set that is missing, unsigned, or signed by another
	// key is refused here and there is nothing to fall back to.
	set, err := attest.LoadReferenceValueSetFile(o.refvals, p.authorKey)
	if err != nil {
		fmt.Fprintf(out, "reference value set : %s — REFUSED\n", o.refvals)
		fmt.Fprintf(out, "\nSET REFUSED\n  %v\n", err)
		return exitSetRefused, nil
	}
	printReferenceValues(out, o, p, set)

	verification, err := o.verifierFor(p, set)
	if err != nil {
		return exitFailed, err
	}
	ev := attest.Evidence{Vendor: o.vendor, Bytes: p.evidence, Chain: p.chain}
	attested, err := verification.Verify(context.Background(), ev, p.binding)
	if err != nil {
		printRefusal(out, err)
		return exitRefused, nil
	}
	printAccepted(out, attested)
	return exitAccepted, nil
}

// presented is what the flags resolved to: the paths a bundle was taken apart
// into, the bytes behind them, and the trust material the verdict is reached
// with. It exists so that reading the invocation and reporting it are two
// steps rather than one long one.
type presented struct {
	evidencePath string
	chainPath    string
	keyPath      string
	evidence     []byte
	publicKey    []byte
	chain        []byte
	binding      attest.Binding
	authorKey    ed25519.PublicKey
	at           time.Time
	rootPEM      []byte
	tdxRootPEM   []byte
}

// bundlePaths resolves the three paths a verdict needs, letting an explicit
// flag stand in for any of them, and refuses an invocation that has named
// neither a bundle nor enough of its parts to do without one.
func (o options) bundlePaths(fs *flag.FlagSet) (evidencePath, chainPath, keyPath string, err error) {
	if o.refvals == "" || o.author == "" {
		fs.Usage()
		return "", "", "", errors.New("-refvals and -author are both required: a verifier with no reference value set admits nobody, and one that would take an unsigned set is not this design")
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
	evidencePath = inBundle(o.evidencePath, "evidence.bin")
	chainPath = inBundle(o.chainPath, "certificate-chain.bin")
	keyPath = inBundle(o.keyPath, "public-key.der")
	if evidencePath == "" || keyPath == "" {
		fs.Usage()
		return "", "", "", errors.New("no -bundle, and no -evidence and -key to stand in for one")
	}
	return evidencePath, chainPath, keyPath, nil
}

// checkVendor refuses a vendor tag this command does not verify, and the
// SEV-SNP chain flags when the vendor is Intel's.
func (o options) checkVendor() error {
	switch o.vendor {
	case attest.VendorAMDSEVSNP, attest.VendorIntelTDX:
	default:
		return fmt.Errorf("-vendor %q: this command verifies %q and %q", o.vendor, attest.VendorAMDSEVSNP, attest.VendorIntelTDX)
	}
	if o.vendor != attest.VendorIntelTDX {
		return nil
	}
	// A TDX quote carries its own PCK certificate chain, so there is no
	// separate chain file to present or to withhold. Saying so is better
	// than silently ignoring a path the operator typed.
	if o.chainPath != "" || o.withoutChain {
		return errors.New("-chain and -without-chain are SEV-SNP's: an Intel TDX quote carries its certificate chain inside itself")
	}
	if o.tdxDir == "" {
		return errors.New("-tdx-collateral-dir is required for Intel TDX evidence: the collateral is provisioned, never fetched (ADR-0005)")
	}
	return nil
}

// present reads the invocation: the paths, the evidence, the key it claims to
// be bound to, the chain or the deliberate absence of one, and the trust
// material behind it. The order is the order the operator learns about a bad
// invocation in, so it is the order of the checks and the reads themselves.
func (o options) present(fs *flag.FlagSet) (presented, error) {
	var p presented
	var err error
	if p.evidencePath, p.chainPath, p.keyPath, err = o.bundlePaths(fs); err != nil {
		return presented{}, err
	}
	if p.evidence, err = os.ReadFile(p.evidencePath); err != nil {
		return presented{}, fmt.Errorf("reading the evidence: %w", err)
	}
	if p.publicKey, err = os.ReadFile(p.keyPath); err != nil {
		return presented{}, fmt.Errorf("reading the public key the evidence is bound to: %w", err)
	}
	if err = o.checkVendor(); err != nil {
		return presented{}, err
	}
	if o.vendor == attest.VendorIntelTDX {
		p.chainPath = ""
	}

	switch {
	case o.vendor == attest.VendorIntelTDX:
		// Nothing to load: see checkVendor.
	case o.withoutChain:
		// Deliberately none. The acquirer will not produce a bundle without
		// one — provision.LoadFor refuses first — so this is how a peer that
		// skipped that step is modelled.
	case p.chainPath == "":
		return presented{}, errors.New("no certificate chain path, and -without-chain was not asked for")
	default:
		if p.chain, err = os.ReadFile(p.chainPath); err != nil {
			return presented{}, fmt.Errorf("reading the provisioned certificate chain: %w", err)
		}
	}

	if err = o.readTrust(&p); err != nil {
		return presented{}, err
	}
	return p, nil
}

// readTrust fills in what the verdict is reached against rather than what is
// being judged: the binding the bundle claims, the author key the set must be
// signed by, the instant validity is judged at, and the two vendor roots when
// a file stands in for the embedded ones.
func (o options) readTrust(p *presented) error {
	var err error
	if p.binding, err = o.bindingFor(p.publicKey); err != nil {
		return err
	}
	if p.authorKey, err = attest.ReadAuthorKey(o.author); err != nil {
		return err
	}
	if o.now != "" {
		if p.at, err = time.Parse(time.RFC3339, o.now); err != nil {
			return fmt.Errorf("-now: %w", err)
		}
	}
	if o.vendorRoot != "" {
		if p.rootPEM, err = os.ReadFile(o.vendorRoot); err != nil {
			return fmt.Errorf("reading the vendor root: %w", err)
		}
	}
	if o.tdxRoot != "" {
		if p.tdxRootPEM, err = os.ReadFile(o.tdxRoot); err != nil {
			return fmt.Errorf("reading the Intel root: %w", err)
		}
	}
	return nil
}

// verifierFor wires one verifier per configured vendor and hands back the
// verification built over them and the set the author signed.
func (o options) verifierFor(p presented, set attest.ReferenceValueSet) (*attest.Verification, error) {
	snp, err := verify.New(verify.Options{VendorRootPEM: p.rootPEM, ProductLine: o.productLine, Now: p.at})
	if err != nil {
		return nil, err
	}
	verifiers := []attest.Verifier{snp}
	if o.tdxDir != "" {
		tdx, err := verify.NewTDX(verify.TDXOptions{CollateralDir: o.tdxDir, VendorRootPEM: p.tdxRootPEM, Now: p.at})
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, tdx)
	}
	// One verifier per vendor, routed by the evidence's own tag. Evidence from
	// a vendor that was not configured is refused as unsupported rather than
	// offered to whoever might parse it.
	verifier, err := attest.Dispatch(verifiers...)
	if err != nil {
		return nil, err
	}
	verification, err := attest.New(verifier, set)
	if err != nil {
		return nil, err
	}
	return verification, nil
}

// printBinding reports what the bundle claims to be bound to: the context its
// report data covers and the policy digest inside it.
func printBinding(out *os.File, binding attest.Binding) {
	fmt.Fprintf(out, "binding context     : v2, %x\n", binding.Context[:])
	fmt.Fprintf(out, "policy digest       : %s\n", binding.PolicyDigest)
}

// printTrustRoots reports where the vendor's root of trust came from, in the
// vocabulary of whichever vendor produced the evidence. Both vendors say the
// same thing about the production path: no fetch, no file (ADR-0005).
func printTrustRoots(out *os.File, o options, p presented) {
	if o.vendor == attest.VendorAMDSEVSNP {
		if p.rootPEM == nil {
			fmt.Fprintf(out, "vendor root         : the AMD roots embedded in the verification library — no fetch, no file\n")
		} else {
			fmt.Fprintf(out, "vendor root         : %s (%s)\n", o.vendorRoot, o.productLine)
		}
	}
	if o.vendor == attest.VendorIntelTDX {
		fmt.Fprintf(out, "intel collateral    : %s (provisioned, ADR-0005)\n", o.tdxDir)
		if p.tdxRootPEM == nil {
			fmt.Fprintf(out, "intel root          : the Intel root embedded in the verification library — no fetch, no file\n")
		} else {
			fmt.Fprintf(out, "intel root          : %s\n", o.tdxRoot)
		}
	}
}

// printReferenceValues lists what the author signed, one block per value, in
// the vocabulary of the vendor that value is about: an Intel value names
// registers and a TCB status, an AMD one a launch measurement and a guest
// policy. Nothing here is a judgement; it is what the judgement is made of.
func printReferenceValues(out *os.File, o options, p presented, set attest.ReferenceValueSet) {
	fmt.Fprintf(out, "reference value set : %s, %d value(s), author %x\n", o.refvals, len(set.Values), []byte(p.authorKey))
	for i, rv := range set.Values {
		if rv.Vendor == attest.VendorIntelTDX && rv.TDX != nil {
			fmt.Fprintf(out, "  [%d] %s predicted RTMR2 %x\n", i, rv.Vendor, rv.TDX.PredictedRTMR2)
			fmt.Fprintf(out, "      observed MRTD      %s\n", digestList(rv.TDX.ObservedMRTD))
			fmt.Fprintf(out, "      observed RTMR0     %s\n", digestList(rv.TDX.ObservedRTMR0))
			fmt.Fprintf(out, "      observed RTMR1     %s\n", digestList(rv.TDX.ObservedRTMR1))
			fmt.Fprintf(out, "      minimum TCB        status=%s evaluation_data_number=%d\n",
				rv.TDX.MinimumTCB.Status, rv.TDX.MinimumTCB.EvaluationDataNumber)
			fmt.Fprintf(out, "      TD policy          debug=%t\n", rv.TDX.TDPolicy.AllowDebug)
			fmt.Fprintf(out, "      admits policy      %s\n", admittedPolicy(rv))
			continue
		}
		fmt.Fprintf(out, "  [%d] %s launch measurement %x\n", i, rv.Vendor, rv.LaunchMeasurement)
		fmt.Fprintf(out, "      admits policy      %s\n", admittedPolicy(rv))
		fmt.Fprintf(out, "      minimum TCB        bootloader=%d tee=%d snp=%d microcode=%d\n",
			rv.MinimumTCB.Bootloader, rv.MinimumTCB.TEE, rv.MinimumTCB.SNP, rv.MinimumTCB.Microcode)
		fmt.Fprintf(out, "      guest policy       %s\n", policyString(rv.GuestPolicy))
	}
}

// printRefusal is the whole of a refused verdict: the reason a caller may
// branch on, the line an operator is meant to read, and the error itself.
func printRefusal(out *os.File, err error) {
	var refusal *attest.Refusal
	errors.As(err, &refusal)
	fmt.Fprintf(out, "\nREFUSED\n")
	fmt.Fprintf(out, "  reason            : %v\n", attest.ReasonOf(err))
	if refusal != nil {
		fmt.Fprintf(out, "  operator log      : %s\n", refusal.LogString())
	}
	fmt.Fprintf(out, "  a caller learns   : %v\n", err)
}

// printAccepted is an accepted verdict: the claims in the producing vendor's
// own vocabulary, then the two things every vendor's evidence is held to — the
// caller-supplied bytes the binding recomputes, and the reference value that
// admitted it.
func printAccepted(out *os.File, attested attest.Attested) {
	fmt.Fprintf(out, "\nACCEPTED\n")
	fmt.Fprintf(out, "  vendor            : %s\n", attested.Vendor)
	if td := attested.Claims.TDX; td != nil {
		printTDXClaims(out, td)
	} else {
		printSNPClaims(out, attested.Claims)
	}
	fmt.Fprintf(out, "  caller-supplied   : %x\n", attested.Claims.CallerSuppliedBytes[:])
	fmt.Fprintf(out, "    = SHA-512(public key ‖ binding context ‖ policy digest), recomputed from the key above (ADR-0002, v2)\n")
	if td := attested.Satisfied.TDX; td != nil {
		fmt.Fprintf(out, "  satisfied         : reference value with predicted RTMR2 %x\n", td.PredictedRTMR2)
	} else {
		fmt.Fprintf(out, "  satisfied         : reference value with launch measurement %x\n", attested.Satisfied.LaunchMeasurement)
	}
}

// printTDXClaims reports Intel's fields, in Intel's vocabulary. RTMR2 is the
// launch measurement for this vendor — the register that covers grub, the
// kernel and the command line — and MRTD, RTMR0 and RTMR1 are the provider's,
// printed so that an operator can see what was matched against the observed
// constants.
func printTDXClaims(out *os.File, td *attest.TDXClaims) {
	fmt.Fprintf(out, "  RTMR2             : %x\n", td.RTMR2)
	fmt.Fprintf(out, "  MRTD              : %x\n", td.MRTD)
	fmt.Fprintf(out, "  RTMR0             : %x\n", td.RTMR0)
	fmt.Fprintf(out, "  RTMR1             : %x\n", td.RTMR1)
	fmt.Fprintf(out, "  TD attributes     : %x (debug=%t)\n", td.TDAttributes, td.TDAttributes[0]&0x01 != 0)
	fmt.Fprintf(out, "  Intel TCB         : status=%s evaluation_data_number=%d fmspc=%s\n",
		td.TCBStatus, td.TCBEvaluationDataNumber, td.FMSPC)
}

// printSNPClaims reports AMD's fields, in AMD's vocabulary: the launch
// measurement the platform signed over, and the TCB it says it was at.
func printSNPClaims(out *os.File, claims attest.Claims) {
	fmt.Fprintf(out, "  launch measurement: %x\n", claims.LaunchMeasurement)
	fmt.Fprintf(out, "  reported TCB      : bootloader=%d tee=%d snp=%d microcode=%d\n",
		claims.TCB.Bootloader, claims.TCB.TEE, claims.TCB.SNP, claims.TCB.Microcode)
}

// bindingFor builds the binding the bundle claims to be bound to: the key it
// names, the v2 context, and the policy digest that context commits to.
func (o options) bindingFor(publicKey []byte) (attest.Binding, error) {
	binding := attest.Binding{PublicKey: publicKey, Context: attest.BindingContextV2}
	var err error
	if binding.PolicyDigest, err = parsePolicyDigest(o.policyDigest); err != nil {
		return attest.Binding{}, err
	}
	return binding, nil
}

// digestList renders an any-of list of expected register values.
func digestList(values [][]byte) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%x", v)
	}
	return strings.Join(parts, " | ")
}

// admittedPolicy renders the peer policy a reference value admits, saying so in
// words when it admits any — an entry that lists none is the weaker reading of
// an absent field, and a transcript should not leave that looking like a value
// somebody chose.
func admittedPolicy(rv attest.ReferenceValue) string {
	if rv.PolicyDigest == nil {
		return "any (this value lists no policy_digest)"
	}
	return rv.PolicyDigest.String()
}

// policyString renders what a reference value permits, naming every field, so
// that the record of a run shows the whole ceiling rather than the bits that
// happened to be set.
func policyString(p attest.GuestPolicy) string {
	return fmt.Sprintf("abi=%d.%d smt=%t migration_agent=%t debug=%t single_socket_required=%t",
		p.ABIMajor, p.ABIMinor, p.AllowSMT, p.AllowMigrationAgent, p.AllowDebug, p.RequireSingleSocket)
}
