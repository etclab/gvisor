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

// The refusal taxonomy, driven through tunneld.
//
// Every way evidence can fail has a case here, and every case asserts four
// things: the tunnel is refused at the handshake rather than established and
// then policed; the refusal carries its own typed reason in the operator log;
// the caller and the far side learn only that the attempt was refused; and the
// same wiring with the one offending thing put right still carries traffic.
//
// That last one is the point of the file. A test that only shows an attack
// blocked would also pass with the tunnel entirely broken — with the listener
// refusing everybody, or the transport dead — so every refusal here is paired
// with a control on the same wiring that completes a real exchange and checks
// the bytes that came back.
//
// Each case runs in both roles. A refusal that holds when the bad peer dials
// but not when it listens is half a control, and which side dials is not the
// attacker's constraint to respect.
//
// The seam is tunneld's public API with the fake platform injected through
// Config. Nothing here asserts on how a verdict was reached: the reason is
// read off the operator log, which is a surface the design owes an operator,
// and never off the internals that produced it.

package tunneld_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/ratls"
	"gvisor.dev/gvisor/attest/snpfake"
	"gvisor.dev/gvisor/attest/tunnel"
	"gvisor.dev/gvisor/attest/tunneld"
	"gvisor.dev/gvisor/attest/verify"
)

// The judged side runs imageA; the side judging it runs imageB. A case changes
// exactly one thing about the judged side, or about how its judge is
// configured, and nothing else.

// refusalFloor is a TCB floor platformTCB does not meet, and refusalAbove is a
// platform that clears it. Each differs from platformTCB in one component,
// because a floor that moved every component would be met by whichever
// comparison happened to be written wrong.
var (
	refusalFloor = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 73}
	refusalAbove = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 74}
)

// refusalBelow is a platform one component beneath platformTCB, which is the
// floor every default judge in this file holds.
var refusalBelow = attest.TCB{Bootloader: 9, TEE: 0, SNP: 23, Microcode: 71}

// refusalDebugging is a guest the host may decrypt. No reference value in this
// file permits it; that is the refusal that keeps a debug-enabled guest out.
var refusalDebugging = snpfake.Policy{SMT: true, Debug: true}

// refusalStaleTCB is a TCB level a platform used to be at. A chain issued for
// it does not match a report from a platform that has since moved on, which is
// how ADR-0005's stale provisioned chain reaches a verifier.
var refusalStaleTCB = attest.TCB{Bootloader: 9, TEE: 0, SNP: 22, Microcode: 72}

// refusalRecorder is a tunneld's operator log, readable by a test. A refusal is
// written on the handshake goroutine of the connection being refused, which for
// a listener finishes after the dialer's error is already back, so a test waits
// for the line rather than assuming it has been written.
type refusalRecorder struct {
	c chan *attest.Refusal

	mu   sync.Mutex
	seen []*attest.Refusal
}

func newRefusalRecorder() *refusalRecorder {
	return &refusalRecorder{c: make(chan *attest.Refusal, 32)}
}

func (r *refusalRecorder) record(x *attest.Refusal) {
	r.mu.Lock()
	r.seen = append(r.seen, x)
	r.mu.Unlock()
	select {
	case r.c <- x:
	default:
	}
}

// next returns the refusal this side logged, waiting for it to be written.
func (r *refusalRecorder) next(t *testing.T) *attest.Refusal {
	t.Helper()
	select {
	case x := <-r.c:
		return x
	case <-time.After(10 * time.Second):
		t.Fatalf("no refusal reached the operator log")
		return nil
	}
}

// none reports the refusals logged so far, for a side that should have logged
// none.
func (r *refusalRecorder) none() []*attest.Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*attest.Refusal(nil), r.seen...)
}

// refusalNode is one tunneld under test, with its operator log captured and its
// answered exchanges counted.
type refusalNode struct {
	*tunneld.Tunneld
	name     string
	refusals *refusalRecorder
	served   atomic.Int32
}

func startRefusalNode(t *testing.T, name string, acquirer attest.Acquirer, verifier attest.Verifier, admits attest.ReferenceValueSet, peers tunneld.PeerTable) *refusalNode {
	t.Helper()
	n := &refusalNode{name: name, refusals: newRefusalRecorder()}
	td, err := tunneld.New(context.Background(), tunneld.Config{
		SandboxID:             name,
		Acquirer:              acquirer,
		Verifier:              verifier,
		ReferenceValueSetPath: writeSet(t, admits, authorPriv),
		AuthorPublicKey:       authorPub,
		Peers:                 peers,
		ListenAddr:            "127.0.0.1:0", // ephemeral: the suite runs concurrently with itself
		RefusalLog:            n.refusals.record,
		Handler: func(_ context.Context, request []byte) ([]byte, error) {
			n.served.Add(1)
			return append([]byte(name+":"), request...), nil
		},
	})
	if err != nil {
		t.Fatalf("tunneld.New(%s): %v", name, err)
	}
	n.Tunneld = td
	t.Cleanup(func() { td.Close() })
	return n
}

// refusalPlatform is a fake platform running one image at one TCB under one
// guest policy, with the chain creation time fixed so that a test's outcome
// does not depend on the day it runs.
func refusalPlatform(t *testing.T, measurement []byte, tcb attest.TCB, policy snpfake.Policy) *snpfake.Platform {
	t.Helper()
	p, err := snpfake.New(snpfake.Config{
		LaunchMeasurement: measurement,
		TCB:               tcb,
		Policy:            policy,
		Now:               chainCreatedAt,
	})
	if err != nil {
		t.Fatalf("snpfake.New: %v", err)
	}
	return p
}

// refusalGenuine is the judged side's platform with nothing wrong with it: the
// image its judge admits, at a TCB the judge's floor allows, under a policy the
// judge permits.
func refusalGenuine(t *testing.T) *snpfake.Platform {
	t.Helper()
	return refusalPlatform(t, imageA, platformTCB, launched)
}

// The fake vendor root, built once. Every snpfake platform is signed under the
// same test root, so one root judges all of them and minting a platform per
// verifier would only cost time.
var (
	refusalRootOnce    sync.Once
	refusalRootPEM     []byte
	refusalProductLine string
	refusalRootErr     error
)

// refusalFakeRoot is a verifier trusting the fake vendor root, as a tunneld is
// configured with the root provisioned onto its config device.
func refusalFakeRoot(t *testing.T) attest.Verifier {
	t.Helper()
	refusalRootOnce.Do(func() {
		p, err := snpfake.New(snpfake.Config{LaunchMeasurement: imageA, TCB: platformTCB, Policy: launched, Now: chainCreatedAt})
		if err != nil {
			refusalRootErr = err
			return
		}
		refusalRootPEM, refusalProductLine = p.VendorRootPEM(), p.ProductLine()
	})
	if refusalRootErr != nil {
		t.Fatalf("snpfake.New: %v", refusalRootErr)
	}
	v, err := verify.New(verify.Options{
		VendorRootPEM: refusalRootPEM,
		ProductLine:   refusalProductLine,
		Now:           whenChainsAreValid,
	})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	return v
}

// refusalAMDRoot is a verifier trusting AMD's real roots, which no fake
// platform chains to. It is how a chain that does not root is presented to a
// verifier without inventing a broken certificate.
func refusalAMDRoot(t *testing.T) attest.Verifier {
	t.Helper()
	v, err := verify.New(verify.Options{})
	if err != nil {
		t.Fatalf("verify.New: %v", err)
	}
	return v
}

// refusalSet is a reference value set admitting one image at one floor under
// one policy — the three things a reference value says, each of which a case
// below turns into a refusal.
func refusalSet(image []byte, floor attest.TCB, policy attest.GuestPolicy) attest.ReferenceValueSet {
	return attest.ReferenceValueSet{Values: []attest.ReferenceValue{{
		LaunchMeasurement: image,
		MinimumTCB:        floor,
		GuestPolicy:       policy,
	}}}
}

// A refusalWiring is a peer presenting evidence and the tunneld judging it.
//
// Only the judge's verdict on the judged side is under test: the judged side is
// always given a verifier and a set that admit its judge, so a refusal can only
// have come from the judge's opinion of the peer in front of it.
type refusalWiring struct {
	// judged is what the judged side presents.
	judged attest.Acquirer

	// verifier and admits are how the side judging it is configured. A nil
	// verifier trusts the fake vendor root.
	verifier attest.Verifier
	admits   attest.ReferenceValueSet
}

// runRefusalWiring starts both tunnelds and has one dial the other. judgedDials
// chooses the role: the judged side as the dialer, or as the listener.
func runRefusalWiring(t *testing.T, w refusalWiring, judgedDials bool) (judge, judged *refusalNode, ch *tunneld.Channel, err error) {
	t.Helper()
	judgePlatform := refusalPlatform(t, imageB, platformTCB, launched)
	verifier := w.verifier
	if verifier == nil {
		verifier = refusalFakeRoot(t)
	}
	admits := w.admits
	if admits.Values == nil {
		admits = refusalSet(imageA, platformTCB, permitted)
	}
	// What the judged side thinks of its judge is never the variable.
	judgedVerifier := refusalFakeRoot(t)
	judgedAdmits := refusalSet(imageB, platformTCB, permitted)

	if judgedDials {
		judge = startRefusalNode(t, "judge", judgePlatform, verifier, admits, nil)
		judged = startRefusalNode(t, "judged", w.judged, judgedVerifier, judgedAdmits,
			tunneld.PeerTable{"peer": judge.Addr().String()})
		ch, err = judged.Peer(ctx(t), "peer")
		return judge, judged, ch, err
	}
	judged = startRefusalNode(t, "judged", w.judged, judgedVerifier, judgedAdmits, nil)
	judge = startRefusalNode(t, "judge", judgePlatform, verifier, admits,
		tunneld.PeerTable{"peer": judged.Addr().String()})
	ch, err = judge.Peer(ctx(t), "peer")
	return judge, judged, ch, err
}

// bothRoles runs f with the judged side dialing and with it listening.
func bothRoles(t *testing.T, f func(t *testing.T, judgedDials bool)) {
	t.Helper()
	for _, role := range []struct {
		name        string
		judgedDials bool
	}{
		{"judged side dials", true},
		{"judged side listens", false},
	} {
		t.Run(role.name, func(t *testing.T) { f(t, role.judgedDials) })
	}
}

// refusesWith requires the judge to refuse w's peer at the handshake, for
// exactly want, in both roles. detail, when given, is text the operator's log
// line must carry beyond the reason — the cases where the reason alone does not
// tell an operator what to do about it.
func refusesWith(t *testing.T, w refusalWiring, want attest.Reason, detail string) {
	t.Helper()
	bothRoles(t, func(t *testing.T, judgedDials bool) {
		judge, judged, ch, err := runRefusalWiring(t, w, judgedDials)
		if err == nil {
			ch.Close()
			t.Fatalf("the tunnel was established; want it refused with %v", want)
		}
		// Refused outright: no channel to hand a caller, and therefore no
		// connection whose exchanges are policed afterwards.
		if ch != nil {
			t.Errorf("a channel was returned alongside the refusal")
		}
		if !errors.Is(err, tunneld.ErrNotEstablished) {
			t.Errorf("the caller got %v; want ErrNotEstablished", err)
		}

		r := judge.refusals.next(t)
		if got := r.Reason(); got != want {
			t.Errorf("refused with %v; want %v (log: %s)", got, want, r.LogString())
		}
		if line := r.LogString(); !strings.Contains(line, want.String()) {
			t.Errorf("the operator log does not name the reason: %q", line)
		}
		if detail != "" && !strings.Contains(r.Detail(), detail) {
			t.Errorf("the operator log does not say %q: %s", detail, r.LogString())
		}
		if other := judged.refusals.none(); len(other) != 0 {
			t.Errorf("the judged side refused its judge too (%s); the case is not testing what it says", other[0].LogString())
		}
		if n := judge.served.Load() + judged.served.Load(); n != 0 {
			t.Errorf("%d exchanges were answered over a refused tunnel", n)
		}
		refusalLeaksNothing(t, err, r)
	})
}

// stillCarriesTraffic is the control every refusal above is paired with: the
// same wiring, the offending thing put right, and a real exchange over it.
//
// It asserts the bytes that came back and that a handler answered them, so a
// tunnel that established and then dropped everything would fail here rather
// than pass quietly and leave the refusal beside it looking like evidence.
func stillCarriesTraffic(t *testing.T, w refusalWiring) {
	t.Helper()
	bothRoles(t, func(t *testing.T, judgedDials bool) {
		judge, judged, ch, err := runRefusalWiring(t, w, judgedDials)
		if err != nil {
			t.Fatalf("control: legitimate traffic was refused: %v", err)
		}
		defer ch.Close()
		// Whichever side listened is the one that answers.
		answering := judged
		if judgedDials {
			answering = judge
		}
		got, err := ch.Exchange(ctx(t), []byte("hello"))
		if err != nil {
			t.Fatalf("control: the exchange failed: %v", err)
		}
		if want := answering.name + ":hello"; string(got) != want {
			t.Errorf("control: the exchange returned %q; want %q", got, want)
		}
		if n := answering.served.Load(); n != 1 {
			t.Errorf("control: %s answered %d exchanges; want 1", answering.name, n)
		}
		for _, n := range []*refusalNode{judge, judged} {
			if logged := n.refusals.none(); len(logged) != 0 {
				t.Errorf("control: %s refused something: %s", n.name, logged[0].LogString())
			}
		}
	})
}

// refusalReasons is the whole taxonomy, used to check that none of it reaches a
// caller.
var refusalReasons = []attest.Reason{
	attest.ReasonNoEvidence,
	attest.ReasonUnsupportedVendor,
	attest.ReasonMalformedEvidence,
	attest.ReasonChainNotRooted,
	attest.ReasonMeasurementNotInSet,
	attest.ReasonTCBBelowFloor,
	attest.ReasonPolicyMismatch,
	attest.ReasonBindingMismatch,
	attest.ReasonUnknownBindingContext,
}

// refusalLeaksNothing is the property that makes the taxonomy safe to have: an
// attacker who can provoke refusals learns which reference value to target next
// only if a refusal tells it apart from another, and none of them does.
func refusalLeaksNothing(t *testing.T, err error, logged *attest.Refusal) {
	t.Helper()
	if got := attest.ReasonOf(err); got != attest.ReasonNone {
		t.Errorf("the caller can recover the reason %v by unwrapping its error", got)
	}
	text := err.Error()
	for _, reason := range refusalReasons {
		if strings.Contains(text, reason.String()) {
			t.Errorf("the caller's error names a reason: %q", text)
		}
	}
	if d := logged.Detail(); d != "" && strings.Contains(text, d) {
		t.Errorf("the caller's error carries the operator detail %q: %q", d, text)
	}
}

// Acquirers that present defective evidence. Each wraps a genuine fake platform
// and changes one thing about what it hands over, so that the defect under test
// is the only difference between it and the control.

// chainless presents evidence with no certificate chain: the shape a peer takes
// when its provisioned chain (ADR-0005) is missing. It must fail closed rather
// than fall back to fetching one.
type chainless struct{ attest.Acquirer }

func (c chainless) Acquire(ctx context.Context, csb [attest.CallerSuppliedBytesSize]byte) (attest.Evidence, error) {
	ev, err := c.Acquirer.Acquire(ctx, csb)
	if err != nil {
		return ev, err
	}
	ev.Chain = nil
	return ev, nil
}

// garbled presents bytes that are not evidence at all. Attacker-supplied bytes
// reach the parser before anything else does.
type garbled struct{ attest.Acquirer }

func (g garbled) Acquire(ctx context.Context, csb [attest.CallerSuppliedBytesSize]byte) (attest.Evidence, error) {
	ev, err := g.Acquirer.Acquire(ctx, csb)
	if err != nil {
		return ev, err
	}
	ev.Bytes = []byte{0x01, 0x02, 0x03}
	return ev, nil
}

// staleChain presents a genuine report alongside the chain its platform was
// provisioned with before its TCB moved. ADR-0005 warns this fails at the
// peer rather than locally, which is the confusing direction, so the refusal
// has to point an operator at re-provisioning.
type staleChain struct {
	attest.Acquirer
	provisioned []byte
}

func (s staleChain) Acquire(ctx context.Context, csb [attest.CallerSuppliedBytesSize]byte) (attest.Evidence, error) {
	ev, err := s.Acquirer.Acquire(ctx, csb)
	if err != nil {
		return ev, err
	}
	ev.Chain = s.provisioned
	return ev, nil
}

// fromAnotherVendor labels genuine evidence as hardware nobody here implements.
type fromAnotherVendor struct{ attest.Acquirer }

func (f fromAnotherVendor) Acquire(ctx context.Context, csb [attest.CallerSuppliedBytesSize]byte) (attest.Evidence, error) {
	ev, err := f.Acquirer.Acquire(ctx, csb)
	if err != nil {
		return ev, err
	}
	ev.Vendor = "intel-tdx"
	return ev, nil
}

// misbound acquires genuine evidence over bytes other than the ones binding the
// key it is about to present: the shape of a replayed report, genuine in every
// respect and about somebody else's key.
type misbound struct{ attest.Acquirer }

func (m misbound) Acquire(ctx context.Context, csb [attest.CallerSuppliedBytesSize]byte) (attest.Evidence, error) {
	other := csb
	other[0] ^= 0x01
	return m.Acquirer.Acquire(ctx, other)
}

// chainOf is the certificate chain a fake platform presents with its evidence.
func chainOf(t *testing.T, p *snpfake.Platform) []byte {
	t.Helper()
	ev, err := p.Acquire(context.Background(), [attest.CallerSuppliedBytesSize]byte{})
	if err != nil {
		t.Fatalf("acquiring evidence for its chain: %v", err)
	}
	return ev.Chain
}

// A refusalCase is one way evidence can fail, the wiring that produces it, and
// the wiring that is the same but for the one thing under test.
type refusalCase struct {
	name   string
	why    string
	reason attest.Reason

	// detail is text the operator's log line must carry beyond the reason, for
	// the cases where the reason alone does not tell an operator what to do.
	detail string

	refused  func(t *testing.T) refusalWiring
	admitted func(t *testing.T) refusalWiring
}

func refusalCases() []refusalCase {
	return []refusalCase{{
		name:   "launch measurement absent from the set",
		why:    "the refusal that keeps a modified image out",
		reason: attest.ReasonMeasurementNotInSet,
		refused: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalGenuine(t), admits: refusalSet(imageNone, platformTCB, permitted)}
		},
		admitted: func(t *testing.T) refusalWiring {
			return refusalWiring{
				judged: refusalPlatform(t, imageNone, platformTCB, launched),
				admits: refusalSet(imageNone, platformTCB, permitted),
			}
		},
	}, {
		name:   "platform below the TCB floor",
		why:    "the refusal that keeps a known-vulnerable firmware level out",
		reason: attest.ReasonTCBBelowFloor,
		refused: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalGenuine(t), admits: refusalSet(imageA, refusalFloor, permitted)}
		},
		admitted: func(t *testing.T) refusalWiring {
			return refusalWiring{
				judged: refusalPlatform(t, imageA, refusalAbove, launched),
				admits: refusalSet(imageA, refusalFloor, permitted),
			}
		},
	}, {
		name:   "guest policy bits mismatched",
		why:    "the refusal that keeps a debug-enabled guest out",
		reason: attest.ReasonPolicyMismatch,
		refused: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalPlatform(t, imageA, platformTCB, refusalDebugging)}
		},
		admitted: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalGenuine(t)}
		},
	}, {
		name:   "no evidence presented",
		why:    "a non-confidential VM must be refused, not treated as unknown",
		reason: attest.ReasonNoEvidence,
		refused: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: evidenceless{refusalGenuine(t)}}
		},
		admitted: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalGenuine(t)}
		},
	}, {
		name:   "chain does not chain to the vendor root",
		why:    "authenticity is the one question a forged report has to answer",
		reason: attest.ReasonChainNotRooted,
		refused: func(t *testing.T) refusalWiring {
			// The judge is the variable here rather than the peer: no fake
			// platform chains to AMD's real root, and no genuine one fails to
			// chain to the fake one. The control below trusts the fake root
			// with the same peer, so what it isolates is the root.
			return refusalWiring{judged: refusalGenuine(t), verifier: refusalAMDRoot(t)}
		},
		admitted: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalGenuine(t), verifier: refusalFakeRoot(t)}
		},
	}, {
		name: "provisioned chain missing",
		why:  "ADR-0005 fails closed rather than falling back to fetching one",
		// The detail is the regression guard. If certificate fetching were ever
		// re-enabled, the refusal would come from the getter that refuses
		// network access rather than from the absent chain, and the reason
		// alone would not tell the difference.
		detail: "no certificate chain presented",
		reason: attest.ReasonChainNotRooted,
		refused: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: chainless{refusalGenuine(t)}}
		},
		admitted: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalGenuine(t)}
		},
	}, {
		name:   "evidence that does not parse",
		why:    "attacker-supplied bytes reach the parser first, and it is not a place to be optimistic",
		reason: attest.ReasonMalformedEvidence,
		refused: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: garbled{refusalGenuine(t)}}
		},
		admitted: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalGenuine(t)}
		},
	}, {
		name: "stale provisioned chain",
		why:  "ADR-0005: a chain issued for a TCB the platform has left surfaces as malformed evidence",
		// This failure appears at the peer rather than locally, so an operator
		// reading "malformed evidence" about a platform they know is healthy
		// has to be pointed at re-provisioning by the line itself.
		detail: "ADR-0005",
		reason: attest.ReasonMalformedEvidence,
		refused: func(t *testing.T) refusalWiring {
			before := refusalPlatform(t, imageA, refusalStaleTCB, launched)
			return refusalWiring{judged: staleChain{refusalGenuine(t), chainOf(t, before)}}
		},
		admitted: func(t *testing.T) refusalWiring {
			// Re-provisioned: the same platform with the chain its current TCB
			// was issued for.
			now := refusalGenuine(t)
			return refusalWiring{judged: staleChain{now, chainOf(t, now)}}
		},
	}, {
		name:   "evidence from an unsupported vendor",
		why:    "guessing at the format of evidence whose vendor is unknown is how a parser becomes an attack surface",
		reason: attest.ReasonUnsupportedVendor,
		refused: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: fromAnotherVendor{refusalGenuine(t)}}
		},
		admitted: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalGenuine(t)}
		},
	}, {
		name:   "caller-supplied bytes do not match the presented key",
		why:    "the refusal that stops a genuine report being replayed against a different key",
		reason: attest.ReasonBindingMismatch,
		refused: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: misbound{refusalGenuine(t)}}
		},
		admitted: func(t *testing.T) refusalWiring {
			return refusalWiring{judged: refusalGenuine(t)}
		},
	}}
}

// TestEveryWayEvidenceCanFailRefusesTheTunnel is the ticket: each way of being
// wrong refuses the connection outright, names itself in the operator log, and
// tells the caller nothing — and each is paired with a control on the same
// wiring that still carries traffic.
func TestEveryWayEvidenceCanFailRefusesTheTunnel(t *testing.T) {
	seen := map[attest.Reason]bool{}
	for _, tc := range refusalCases() {
		seen[tc.reason] = true
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("%s: %s", tc.reason, tc.why)
			t.Run("refused", func(t *testing.T) { refusesWith(t, tc.refused(t), tc.reason, tc.detail) })
			t.Run("control", func(t *testing.T) { stillCarriesTraffic(t, tc.admitted(t)) })
		})
	}
	if len(seen) < 8 {
		t.Errorf("the cases produced %d distinct reasons; the table has stopped covering the taxonomy", len(seen))
	}
}

// TestAPeerSpeakingAnUnrecognisedBindingContextIsRefused is ADR-0002's
// reservation made a test.
//
// A v1 verifier meeting a context it does not understand must refuse rather
// than ignore it: a v2 peer carrying a policy digest that a v1 verifier never
// looked at would be admitted on the strength of a field nobody read, which is
// the deployment the reservation exists to prevent.
//
// The peer here is built out of ratls directly, because nothing that speaks v1
// can present a v2 context and a peer that cannot exist cannot be refused. The
// tunneld under test is still driven through its public API; only the adversary
// reaches lower, as the hostile peers in hostile_test.go do.
func TestAPeerSpeakingAnUnrecognisedBindingContextIsRefused(t *testing.T) {
	v2 := attest.BindingContext{}
	v2[0] = 2

	listener := startRefusalNode(t, "listener", refusalGenuine(t), refusalFakeRoot(t),
		refusalSet(imageA, platformTCB, permitted), nil)

	// Control: the same construction speaking v1 completes the handshake, so a
	// failure below is the context and not the way the peer was built.
	if err := dialWithBindingContext(t, listener.Addr().String(), attest.BindingContextV1); err != nil {
		t.Fatalf("control: a v1 peer built the same way was refused: %v", err)
	}

	if err := dialWithBindingContext(t, listener.Addr().String(), v2); err == nil {
		t.Fatal("a peer claiming an unrecognised binding context completed the handshake")
	}
	r := listener.refusals.next(t)
	if got := r.Reason(); got != attest.ReasonUnknownBindingContext {
		t.Errorf("refused with %v; want %v (log: %s)", got, attest.ReasonUnknownBindingContext, r.LogString())
	}
	if line := r.LogString(); !strings.Contains(line, attest.ReasonUnknownBindingContext.String()) {
		t.Errorf("the operator log does not name the reason: %q", line)
	}
	if n := listener.served.Load(); n != 0 {
		t.Errorf("%d exchanges were answered over a refused tunnel", n)
	}

	// Control, again and end to end: an ordinary peer still gets a channel and
	// an answer from the same listener after the refusal. The listener admits
	// imageA, so the dialer runs it.
	dialer := startRefusalNode(t, "dialer", refusalGenuine(t), refusalFakeRoot(t),
		refusalSet(imageA, platformTCB, permitted), tunneld.PeerTable{"listener": listener.Addr().String()})
	ch, err := dialer.Peer(ctx(t), "listener")
	if err != nil {
		t.Fatalf("control: a legitimate peer was refused after the v2 one: %v", err)
	}
	defer ch.Close()
	got, err := ch.Exchange(ctx(t), []byte("hello"))
	if err != nil {
		t.Fatalf("control: the exchange failed: %v", err)
	}
	if want := "listener:hello"; string(got) != want {
		t.Errorf("control: the exchange returned %q; want %q", got, want)
	}
}

// dialWithBindingContext establishes a tunnel to the listener at addr as a peer
// claiming bindingContext, and reports whether the listener admitted it.
//
// It is an otherwise well-behaved peer: it goes through the transport's own
// Dial, which is what carries the establishment round trip. TLS 1.3 lets a
// client finish its handshake before the listener has judged the client's
// certificate, so a peer that stopped at the handshake would report success
// against a listener that was in the middle of refusing it.
func dialWithBindingContext(t *testing.T, addr string, bindingContext attest.BindingContext) error {
	t.Helper()
	identity, err := ratls.NewIdentityForContext(ctx(t), refusalGenuine(t), bindingContext)
	if err != nil {
		t.Fatalf("building the peer: %v", err)
	}
	verification, err := attest.New(refusalFakeRoot(t), refusalSet(imageA, platformTCB, permitted))
	if err != nil {
		t.Fatalf("building the peer's verification: %v", err)
	}
	c, err := tunnel.Dial(ctx(t), addr, identity.ClientConfig(verification))
	if err != nil {
		return err
	}
	t.Cleanup(func() { c.Close() })
	return nil
}

// TestTheFarSideLearnsOnlyThatItWasRefused is the property that makes the
// taxonomy safe to keep: a peer that can tell one refusal from another can walk
// the reference value set one field at a time and learn what to target next.
//
// The two families are separated because they are genuinely different
// positions. A peer that is refused sees whatever crossed the wire; a peer that
// refuses sees its own verdict, which it knew already. Within each family every
// reason must look identical.
func TestTheFarSideLearnsOnlyThatItWasRefused(t *testing.T) {
	refused := map[string]string{}  // what the refused peer saw, by case
	refusing := map[string]string{} // what the refusing peer saw, by case

	for _, tc := range refusalCases() {
		t.Run(tc.name, func(t *testing.T) {
			// The judged side dials: it is the one refused, and its error is
			// what the far side put on the wire.
			_, _, _, err := runRefusalWiring(t, tc.refused(t), true)
			if err == nil {
				t.Fatal("the tunnel was established")
			}
			refused[tc.name] = elideAddresses(err.Error())

			// The judged side listens: the judge refuses locally.
			_, _, _, err = runRefusalWiring(t, tc.refused(t), false)
			if err == nil {
				t.Fatal("the tunnel was established")
			}
			refusing[tc.name] = elideAddresses(err.Error())
		})
	}
	sameForEveryReason(t, "a refused peer", refused)
	sameForEveryReason(t, "a refusing peer", refusing)
}

// sameForEveryReason fails if any two cases produced different text.
func sameForEveryReason(t *testing.T, who string, byCase map[string]string) {
	t.Helper()
	var first, firstName string
	for name, text := range byCase {
		if firstName == "" {
			first, firstName = text, name
			continue
		}
		if text != first {
			t.Errorf("%s can tell two refusals apart:\n  %s: %q\n  %s: %q", who, firstName, first, name, text)
		}
	}
	if firstName == "" {
		t.Fatalf("%s: no errors were collected; the test asserted nothing", who)
	}
	t.Logf("%s always sees: %s", who, first)
}

// elideAddresses removes the ephemeral ports the peers bound, which differ per
// run and per case and are not a refusal reason.
func elideAddresses(s string) string {
	var out []string
	for _, field := range strings.Fields(s) {
		if strings.HasPrefix(field, "127.0.0.1:") {
			field = "127.0.0.1:PORT"
		}
		out = append(out, field)
	}
	return strings.Join(out, " ")
}

// TestOneListenerRefusesEveryDefectAndKeepsServing is the control in its
// strongest form: not a fresh tunneld built beside the refused one, but the
// same listener, still running, admitting the next peer to arrive.
//
// A refusal test whose control is a different process would pass just as well
// against a listener that dies on the first peer it refuses. This one would
// not: every refusal below is followed by a legitimate peer through the same
// listener, and the exchange it completes is checked.
func TestOneListenerRefusesEveryDefectAndKeepsServing(t *testing.T) {
	listener := startRefusalNode(t, "listener", refusalPlatform(t, imageB, platformTCB, launched),
		refusalFakeRoot(t), refusalSet(imageA, platformTCB, permitted), nil)

	// Before any refusal, so that a listener broken from the start is not
	// mistaken for one broken by a refusal.
	exchangeThrough(t, listener, "control-first", refusalGenuine(t))

	// Every defect here is the peer's own, so one judge configured one way
	// refuses all of them and admits the control between each.
	defects := []struct {
		name     string
		reason   attest.Reason
		acquirer attest.Acquirer
	}{
		{"launch measurement absent from the set", attest.ReasonMeasurementNotInSet, refusalPlatform(t, imageNone, platformTCB, launched)},
		{"platform below the TCB floor", attest.ReasonTCBBelowFloor, refusalPlatform(t, imageA, refusalBelow, launched)},
		{"guest policy bits mismatched", attest.ReasonPolicyMismatch, refusalPlatform(t, imageA, platformTCB, refusalDebugging)},
		{"no evidence presented", attest.ReasonNoEvidence, evidenceless{refusalGenuine(t)}},
		{"provisioned chain missing", attest.ReasonChainNotRooted, chainless{refusalGenuine(t)}},
		{"evidence that does not parse", attest.ReasonMalformedEvidence, garbled{refusalGenuine(t)}},
		{"evidence from an unsupported vendor", attest.ReasonUnsupportedVendor, fromAnotherVendor{refusalGenuine(t)}},
		{"caller-supplied bytes do not match the presented key", attest.ReasonBindingMismatch, misbound{refusalGenuine(t)}},
	}
	for i, d := range defects {
		t.Run(d.name, func(t *testing.T) {
			bad := startRefusalNode(t, fmt.Sprintf("refused-%d", i), d.acquirer, refusalFakeRoot(t),
				refusalSet(imageB, platformTCB, permitted),
				tunneld.PeerTable{"listener": listener.Addr().String()})
			ch, err := bad.Peer(ctx(t), "listener")
			if err == nil {
				ch.Close()
				t.Fatalf("the tunnel was established; want it refused with %v", d.reason)
			}
			if !errors.Is(err, tunneld.ErrNotEstablished) {
				t.Errorf("the caller got %v; want ErrNotEstablished", err)
			}
			r := listener.refusals.next(t)
			if got := r.Reason(); got != d.reason {
				t.Errorf("refused with %v; want %v (log: %s)", got, d.reason, r.LogString())
			}
			refusalLeaksNothing(t, err, r)

			exchangeThrough(t, listener, fmt.Sprintf("control-%d", i), refusalGenuine(t))
		})
	}
	if got, want := int(listener.served.Load()), len(defects)+1; got != want {
		t.Errorf("the listener answered %d exchanges; want %d, one control before the refusals and one after each", got, want)
	}
}

// exchangeThrough starts a legitimate peer, has it dial listener, and requires
// a real exchange to complete over the tunnel.
func exchangeThrough(t *testing.T, listener *refusalNode, name string, acquirer attest.Acquirer) {
	t.Helper()
	dialer := startRefusalNode(t, name, acquirer, refusalFakeRoot(t),
		refusalSet(imageB, platformTCB, permitted),
		tunneld.PeerTable{"listener": listener.Addr().String()})
	ch, err := dialer.Peer(ctx(t), "listener")
	if err != nil {
		t.Fatalf("control: legitimate traffic was refused: %v", err)
	}
	defer ch.Close()
	got, err := ch.Exchange(ctx(t), []byte("hello"))
	if err != nil {
		t.Fatalf("control: the exchange failed: %v", err)
	}
	if want := listener.name + ":hello"; string(got) != want {
		t.Errorf("control: the exchange returned %q; want %q", got, want)
	}
	if logged := dialer.refusals.none(); len(logged) != 0 {
		t.Errorf("control: the dialer refused the listener: %s", logged[0].LogString())
	}
}

// refusalCoverage names the reasons this file drives through tunneld. A reason
// added to the taxonomy with nothing here to refuse for it is a reason no
// handshake ever applies, which is the failure this guards against — and the
// one that looks like success, because every existing test still passes.
var refusalCoverage = map[attest.Reason]string{
	attest.ReasonNoEvidence:            "TestEveryWayEvidenceCanFailRefusesTheTunnel",
	attest.ReasonUnsupportedVendor:     "TestEveryWayEvidenceCanFailRefusesTheTunnel",
	attest.ReasonMalformedEvidence:     "TestEveryWayEvidenceCanFailRefusesTheTunnel",
	attest.ReasonChainNotRooted:        "TestEveryWayEvidenceCanFailRefusesTheTunnel",
	attest.ReasonMeasurementNotInSet:   "TestEveryWayEvidenceCanFailRefusesTheTunnel",
	attest.ReasonTCBBelowFloor:         "TestEveryWayEvidenceCanFailRefusesTheTunnel",
	attest.ReasonPolicyMismatch:        "TestEveryWayEvidenceCanFailRefusesTheTunnel",
	attest.ReasonBindingMismatch:       "TestEveryWayEvidenceCanFailRefusesTheTunnel",
	attest.ReasonUnknownBindingContext: "TestAPeerSpeakingAnUnrecognisedBindingContextIsRefused",
}

func TestEveryReasonInTheTaxonomyRefusesATunnel(t *testing.T) {
	// A reason the taxonomy names prints its own sentence; one it does not
	// prints Reason(n). That is how the end of the taxonomy is found without
	// this file holding a count that goes stale.
	named := 0
	for r := attest.Reason(1); !strings.HasPrefix(r.String(), "Reason("); r++ {
		named++
		if _, ok := refusalCoverage[r]; !ok {
			t.Errorf("the taxonomy names %v; no test here refuses a tunnel for it", r)
		}
	}
	if named != len(refusalCoverage) {
		t.Errorf("the taxonomy names %d reasons; this file claims to cover %d", named, len(refusalCoverage))
	}
}
