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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"gvisor.dev/gvisor/attest"
)

// watchedVerifier is this platform's verifier with a notebook beside it. It
// wraps [attest.Verifier] — the consumer half of the vendor seam — and writes
// down what each peer presented before handing the question on unchanged. It
// decides nothing: every verdict below is returned as it came back.
//
// It exists because of something package tunneld is right to make impossible.
// A tunneld's key is observable nowhere but at the peer it is presented to:
// ratls.Identity exposes no accessor and should not, and a tunneld that handed
// its key out would be the defect. So a run that has to record "these two
// guests presented distinct keys, each with its own provisioned chain" has to
// record it at the far side, and the far side's outermost seam is here. What
// it can see is enough:
//
//   - the caller-supplied bytes, which are H(peer's public key ‖ binding
//     context ‖ policy digest) (ADR-0002 and its amendment) and therefore
//     name the key without carrying it;
//   - the certificate chain, which is issued per chip and per TCB (ADR-0005),
//     so two peers with different chains are on different chips and two with
//     the same chain are on one;
//   - the launch measurement and TCB the evidence claims.
//
// It is not a test instrument bolted onto a production path. It is what a
// tunneld may reasonably say on its console about a peer it admitted, and an
// operator debugging a federation wants exactly these four fields.
type watchedVerifier struct {
	inner attest.Verifier
	logf  func(string, ...any)

	mu       sync.Mutex
	calls    int
	accepted int
	refused  int
	peers    map[string]peerSeen
	chains   map[string]bool
}

type peerSeen struct {
	key         string
	chain       string
	measurement string
	// platform is the vendor-specific half of the line an operator reads,
	// rendered when the peer was first seen. It is a string rather than a
	// struct because AMD's TCB and Intel's are different objects, and a watcher
	// that held both would be a second place the vendor seam leaks through.
	platform string
	times    int
}

func newWatchedVerifier(inner attest.Verifier, logf func(string, ...any)) *watchedVerifier {
	return &watchedVerifier{inner: inner, logf: logf, peers: map[string]peerSeen{}, chains: map[string]bool{}}
}

// Vendor implements [attest.Verifier].
func (w *watchedVerifier) Vendor() attest.Vendor { return w.inner.Vendor() }

// Verify implements [attest.Verifier] by asking the verifier below and writing
// down what it was asked about.
func (w *watchedVerifier) Verify(ctx context.Context, ev attest.Evidence, set attest.ReferenceValueSet) (attest.Attested, error) {
	attested, err := w.inner.Verify(ctx, ev, set)

	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	if err != nil {
		w.refused++
		return attested, err
	}
	w.accepted++
	key := hex.EncodeToString(attested.Claims.CallerSuppliedBytes[:])
	chain := digest(ev.Chain)
	w.chains[chain] = true
	seen, known := w.peers[key]
	if !known {
		seen = peerSeen{
			key:         key,
			chain:       chain,
			measurement: hex.EncodeToString(attested.Claims.LaunchMeasurement),
			platform:    platformLine(attested),
		}
		w.logf("PEER key=%s chain=%s measurement=%s %s",
			abbreviate(seen.key), abbreviate(seen.chain), abbreviate(seen.measurement), seen.platform)
	}
	seen.times++
	w.peers[key] = seen
	return attested, err
}

// count is how many times this verifier has been asked anything. The exercise
// reads it around an establishment to say whether a handshake happened: one
// call is one peer's evidence judged, so a warm tunnel reused costs none and a
// re-attestation after the maximum age costs one.
func (w *watchedVerifier) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls
}

// report is the summary line at the end of a run.
//
// distinct_keys and distinct_chains are the two numbers a two-guest run is
// read for. Distinct keys mean the peers are distinct tunnelds; distinct
// chains mean they are on distinct chips, which is the only thing here that
// separates two guests from two tunnelds on one guest — two reports from one
// chip differ only in the field derived from the key.
func (w *watchedVerifier) report(logf func(string, ...any)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	logf("PEERS verifier_calls=%d accepted=%d refused=%d distinct_keys=%d distinct_chains=%d",
		w.calls, w.accepted, w.refused, len(w.peers), len(w.chains))
	// In full, unlike the line written when a peer first appears. This is the
	// record: two guests are told apart by their keys, told to be on one chip
	// by their chains, and told to be running the image somebody predicted by
	// their measurement — and a reader checking any of those against another
	// document cannot do it with sixteen characters.
	for _, key := range sortedPeerKeys(w.peers) {
		p := w.peers[key]
		logf("PEER SEEN key=%s chain=%s measurement=%s times=%d", p.key, p.chain, p.measurement, p.times)
	}
}

func digest(b []byte) string {
	if len(b) == 0 {
		return "none"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sortedPeerKeys(m map[string]peerSeen) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// platformLine is the vendor-specific tail of the PEER line: the fields an
// operator needs to tell one platform from another, in the vocabulary of the
// vendor that produced them.
//
// AMD's four security patch levels and Intel's status-and-evaluation-number
// are not the same thing said twice, so neither is translated into the other.
// A vendor this does not know is named and nothing is claimed about it, which
// is the only honest thing a printer can do with evidence it cannot read.
func platformLine(attested attest.Attested) string {
	switch attested.Vendor {
	case attest.VendorAMDSEVSNP:
		t := attested.Claims.TCB
		return fmt.Sprintf("vendor=%s tcb=bootloader=%d,tee=%d,snp=%d,microcode=%d",
			attested.Vendor, t.Bootloader, t.TEE, t.SNP, t.Microcode)
	case attest.VendorIntelTDX:
		td := attested.Claims.TDX
		if td == nil {
			return fmt.Sprintf("vendor=%s (no TDX claims)", attested.Vendor)
		}
		return fmt.Sprintf("vendor=%s mrtd=%s rtmr2=%s tcb=%s,evaluation=%d",
			attested.Vendor, abbreviate(hex.EncodeToString(td.MRTD)), abbreviate(hex.EncodeToString(td.RTMR2)),
			td.TCBStatus, td.TCBEvaluationDataNumber)
	default:
		return fmt.Sprintf("vendor=%s", attested.Vendor)
	}
}
