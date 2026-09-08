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
//	verify-evidence -bundle DIR -refvals PATH -author PATH \
//	                [-policy-digest HEX] [-binding-version 1|2]
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
	nowFlag := fs.String("now", "", "RFC 3339 instant at which certificate validity is judged and Intel collateral expiry is decided; empty means now")
	vendor := fs.String("vendor", string(attest.VendorAMDSEVSNP), "the hardware that produced the evidence: "+string(attest.VendorAMDSEVSNP)+" or "+string(attest.VendorIntelTDX)+". It is a flag rather than a guess: sniffing the format of an untrusted blob to decide which parser to hand it to is the mistake the vendor tag exists to prevent")
	tdxCollateralDir := fs.String("tdx-collateral-dir", "", "directory holding Intel's provisioned TCB info, quoting-enclave identity and revocation lists; required to verify Intel TDX evidence, and never fetched (ADR-0005)")
	tdxRoot := fs.String("tdx-root", "", "PEM file holding the Intel SGX Root CA; empty uses the Intel root embedded in the verification library, which is the production path")
	bindingVersion := fs.Int("binding-version", 2, "the ADR-0002 binding version the bundle was acquired under: 2, or 1 for a bundle recorded before the policy digest existed")
	policyDigest := fs.String("policy-digest", "", "the policy digest the bundle is bound to, hex; empty is 32 zero bytes. Meaningless with -binding-version 1, which had no such field")
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
		binding:      *bindingVersion,
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
	binding      int
	policyDigest string
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
	switch o.vendor {
	case attest.VendorAMDSEVSNP, attest.VendorIntelTDX:
	default:
		return exitFailed, fmt.Errorf("-vendor %q: this command verifies %q and %q", o.vendor, attest.VendorAMDSEVSNP, attest.VendorIntelTDX)
	}
	if o.vendor == attest.VendorIntelTDX {
		// A TDX quote carries its own PCK certificate chain, so there is no
		// separate chain file to present or to withhold. Saying so is better
		// than silently ignoring a path the operator typed.
		if o.chainPath != "" || o.withoutChain {
			return exitFailed, errors.New("-chain and -without-chain are SEV-SNP's: an Intel TDX quote carries its certificate chain inside itself")
		}
		if o.tdxDir == "" {
			return exitFailed, errors.New("-tdx-collateral-dir is required for Intel TDX evidence: the collateral is provisioned, never fetched (ADR-0005)")
		}
		chainPath = ""
	}

	var chain []byte
	switch {
	case o.vendor == attest.VendorIntelTDX:
		// Nothing to load: see above.
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

	binding, err := o.bindingFor(publicKey)
	if err != nil {
		return exitFailed, err
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
	var tdxRootPEM []byte
	if o.tdxRoot != "" {
		if tdxRootPEM, err = os.ReadFile(o.tdxRoot); err != nil {
			return exitFailed, fmt.Errorf("reading the Intel root: %w", err)
		}
	}

	fmt.Fprintf(out, "evidence            : %s, %d bytes\n", evidencePath, len(evidence))
	fmt.Fprintf(out, "vendor              : %s\n", o.vendor)
	switch {
	case o.vendor == attest.VendorIntelTDX:
		fmt.Fprintf(out, "certificate chain   : carried inside the quote\n")
	case o.withoutChain:
		fmt.Fprintf(out, "certificate chain   : none presented (-without-chain)\n")
	default:
		fmt.Fprintf(out, "certificate chain   : %s, %d bytes (provisioned, ADR-0005)\n", chainPath, len(chain))
	}
	fmt.Fprintf(out, "public key (SPKI)   : %s, %d bytes, %x\n", keyPath, len(publicKey), publicKey)
	fmt.Fprintf(out, "binding context     : v%d, %x\n", o.bindingVersion(), binding.Context[:])
	if o.bindingVersion() == 1 {
		fmt.Fprintf(out, "                      a pre-v2 bundle: its report data covers the key and the context and no policy,\n")
		fmt.Fprintf(out, "                      so it is judged by the vendor's verifier plus the v1 binding rather than by\n")
		fmt.Fprintf(out, "                      attest.Verification, which admits v2 alone\n")
	} else {
		fmt.Fprintf(out, "policy digest       : %s\n", binding.PolicyDigest)
	}
	if o.vendor == attest.VendorAMDSEVSNP {
		if rootPEM == nil {
			fmt.Fprintf(out, "vendor root         : the AMD roots embedded in the verification library — no fetch, no file\n")
		} else {
			fmt.Fprintf(out, "vendor root         : %s (%s)\n", o.vendorRoot, o.productLine)
		}
	}
	if o.vendor == attest.VendorIntelTDX {
		fmt.Fprintf(out, "intel collateral    : %s (provisioned, ADR-0005)\n", o.tdxDir)
		if tdxRootPEM == nil {
			fmt.Fprintf(out, "intel root          : the Intel root embedded in the verification library — no fetch, no file\n")
		} else {
			fmt.Fprintf(out, "intel root          : %s\n", o.tdxRoot)
		}
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

	snp, err := verify.New(verify.Options{VendorRootPEM: rootPEM, ProductLine: o.productLine, Now: at})
	if err != nil {
		return exitFailed, err
	}
	verifiers := []attest.Verifier{snp}
	if o.tdxDir != "" {
		tdx, err := verify.NewTDX(verify.TDXOptions{CollateralDir: o.tdxDir, VendorRootPEM: tdxRootPEM, Now: at})
		if err != nil {
			return exitFailed, err
		}
		verifiers = append(verifiers, tdx)
	}
	// One verifier per vendor, routed by the evidence's own tag. Evidence from
	// a vendor that was not configured is refused as unsupported rather than
	// offered to whoever might parse it.
	verifier, err := attest.Dispatch(verifiers...)
	if err != nil {
		return exitFailed, err
	}
	verification, err := attest.New(verifier, set)
	if err != nil {
		return exitFailed, err
	}

	ev := attest.Evidence{Vendor: o.vendor, Bytes: evidence, Chain: chain}
	var attested attest.Attested
	if o.bindingVersion() == 1 {
		attested, err = verifyPreV2(verifier, set, ev, binding)
	} else {
		attested, err = verification.Verify(context.Background(), ev, binding)
	}
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
	if td := attested.Claims.TDX; td != nil {
		// Intel's fields, in Intel's vocabulary. RTMR2 is the launch
		// measurement for this vendor — the register that covers grub, the
		// kernel and the command line — and MRTD, RTMR0 and RTMR1 are the
		// provider's, printed so that an operator can see what was matched
		// against the observed constants.
		fmt.Fprintf(out, "  RTMR2             : %x\n", td.RTMR2)
		fmt.Fprintf(out, "  MRTD              : %x\n", td.MRTD)
		fmt.Fprintf(out, "  RTMR0             : %x\n", td.RTMR0)
		fmt.Fprintf(out, "  RTMR1             : %x\n", td.RTMR1)
		fmt.Fprintf(out, "  TD attributes     : %x (debug=%t)\n", td.TDAttributes, td.TDAttributes[0]&0x01 != 0)
		fmt.Fprintf(out, "  Intel TCB         : status=%s evaluation_data_number=%d fmspc=%s\n",
			td.TCBStatus, td.TCBEvaluationDataNumber, td.FMSPC)
	} else {
		fmt.Fprintf(out, "  launch measurement: %x\n", attested.Claims.LaunchMeasurement)
		fmt.Fprintf(out, "  reported TCB      : bootloader=%d tee=%d snp=%d microcode=%d\n",
			attested.Claims.TCB.Bootloader, attested.Claims.TCB.TEE, attested.Claims.TCB.SNP, attested.Claims.TCB.Microcode)
	}
	fmt.Fprintf(out, "  caller-supplied   : %x\n", attested.Claims.CallerSuppliedBytes[:])
	if o.bindingVersion() == 1 {
		fmt.Fprintf(out, "    = SHA-512(public key ‖ binding context), recomputed from the key above (ADR-0002, v1)\n")
	} else {
		fmt.Fprintf(out, "    = SHA-512(public key ‖ binding context ‖ policy digest), recomputed from the key above (ADR-0002, v2)\n")
	}
	if td := attested.Satisfied.TDX; td != nil {
		fmt.Fprintf(out, "  satisfied         : reference value with predicted RTMR2 %x\n", td.PredictedRTMR2)
	} else {
		fmt.Fprintf(out, "  satisfied         : reference value with launch measurement %x\n", attested.Satisfied.LaunchMeasurement)
	}
	return exitAccepted, nil
}

// bindingVersion is -binding-version, defaulted for a zero value so that a
// caller building options in code gets what the flag's default gives.
func (o options) bindingVersion() int {
	if o.binding == 0 {
		return 2
	}
	return o.binding
}

// bindingFor builds the binding the bundle claims to be bound to.
//
// Version 1 exists here and nowhere else in this tree that still produces
// evidence: bundles acquired before ticket 18 are recorded under docs/snp and
// cannot be re-acquired without booking the machines again, so the tool that
// re-checks them has to be able to speak the version they were written in.
func (o options) bindingFor(publicKey []byte) (attest.Binding, error) {
	switch o.bindingVersion() {
	case 1:
		if o.policyDigest != "" {
			return attest.Binding{}, errors.New("-policy-digest with -binding-version 1: a v1 binding covers no policy, and pretending otherwise would compute bytes no platform ever echoed")
		}
		return attest.Binding{PublicKey: publicKey, Context: attest.BindingContextV1}, nil
	case 2:
		binding := attest.Binding{PublicKey: publicKey, Context: attest.BindingContextV2}
		if o.policyDigest != "" {
			raw, err := hex.DecodeString(o.policyDigest)
			if err != nil {
				return attest.Binding{}, fmt.Errorf("-policy-digest is not hexadecimal: %v", err)
			}
			if len(raw) != len(binding.PolicyDigest) {
				return attest.Binding{}, fmt.Errorf("-policy-digest is %d bytes; a policy digest is %d", len(raw), len(binding.PolicyDigest))
			}
			copy(binding.PolicyDigest[:], raw)
		}
		return binding, nil
	default:
		return attest.Binding{}, fmt.Errorf("-binding-version %d: this command speaks 1 and 2", o.bindingVersion())
	}
}

// verifyPreV2 is what a v1 bundle is judged by, since [attest.Verification]
// refuses a v1 context before it looks at anything else — correctly, because a
// v1 peer commits to no policy and a live verifier must not admit one.
//
// It asks the two questions that are still answerable about a recording: the
// vendor's, against the same set loaded from the same signed document, and the
// binding, recomputed from the recording's own v1 context through the same
// exported [attest.Binding.CallerSuppliedBytes] the guest used when it asked
// for the report. What it does not do is check a policy digest, because there
// is none to check; that is said out loud in the output rather than left for a
// reader to infer from an unusually short transcript.
func verifyPreV2(verifier attest.Verifier, set attest.ReferenceValueSet, ev attest.Evidence, binding attest.Binding) (attest.Attested, error) {
	if !ev.Present() {
		return attest.Attested{}, attest.Refuse(attest.ReasonNoEvidence, "no evidence presented")
	}
	attested, err := verifier.Verify(context.Background(), ev, set)
	if err != nil {
		return attest.Attested{}, err
	}
	if want := binding.CallerSuppliedBytes(); want != attested.Claims.CallerSuppliedBytes {
		return attest.Attested{}, attest.Refuse(attest.ReasonBindingMismatch,
			"evidence is bound to different caller-supplied bytes than the presented public key produces under v1")
	}
	return attested, nil
}

// digestList renders an any-of list of expected register values.
func digestList(values [][]byte) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%x", v)
	}
	return strings.Join(parts, " | ")
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
