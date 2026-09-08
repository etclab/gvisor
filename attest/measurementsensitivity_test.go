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

// The offline half of milestone 2 (ticket 08).
//
// Six confidential guests were booted from six builds of the measured image:
// one as built, one rebuilt with nothing changed, and four with one byte
// changed — in the root filesystem, in the root filesystem again at a raw
// offset, in the initrd, and on the kernel command line. Each guest's report
// is in docs/snp/image/evidence/ticket08, beside the launch measurement that
// was predicted offline for that image before it booted.
//
// These tests replay the verdicts against AMD's real root with no hardware and
// no network, and check the two things the milestone turns on: that every
// mutant reported the measurement predicted for it, and that every mutant is
// refused by name against the set signed for the unmodified image, while the
// unmodified image is accepted.
//
// They are not the proof, for the same reason ticket 05's are not: what
// milestone 2 asserts is that changing a covered byte moves the measurement a
// real platform reports, and that needs the platform. The proof is the
// recorded run in docs/snp/image/evidence/ticket08/sensitivity-run.txt. What
// these do is stop the conclusion rotting quietly — a change that stopped
// refusing a guest whose measurement is not in the set would be found on the
// next `go test`.
//
// The whole procedure is docs/measurement-sensitivity.md.
package attest_test

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/verify"
)

// sensitivityDir holds one run of docs/snp/image/sensitivity-on-hardware.sh.
// The reference value set at its root is the one the BASELINE image's build
// authored and signed, from a measurement it predicted; every verdict below is
// taken against that one set, which is what makes the mutants comparable.
const sensitivityDir = "../docs/snp/image/evidence/ticket08"

// A variant is one booted image: what was changed in it, the guest it booted,
// and whether that guest's evidence should satisfy the baseline's set.
type variant struct {
	dir      string
	changed  string
	accepted bool
}

var variants = []variant{
	{"base", "nothing — the image as built", true},
	{"none", "nothing, but rootfs.img and initrd.img regenerated from the same staging trees", true},
	{"rootfs-file", "one hexadecimal character of /etc/attested-tunnel/author.pub, in the root filesystem", false},
	{"rootfs-byte", "one byte of rootfs.img, in the padding past the filesystem's own size", false},
	{"initrd", "one byte of a comment in the initrd's /init", false},
	{"cmdline", "one trailing space on the kernel command line", false},
}

// bootedGuest is one variant's captured run, loaded.
type bootedGuest struct {
	evidence  attest.Evidence
	binding   attest.Binding
	predicted string // the measurement predicted for this image before it booted
}

// loadBootedGuest reads one variant's artifacts, or skips. It skips rather
// than fails because these are the record of a run on a particular machine,
// and a checkout without them is not a broken checkout.
func loadBootedGuest(t *testing.T, v variant) bootedGuest {
	t.Helper()
	report, err := os.ReadFile(filepath.Join(sensitivityDir, v.dir, "evidence.bin"))
	if err != nil {
		t.Skipf("no evidence captured for variant %q: %v", v.dir, err)
	}
	// The chain is the provisioned one, not a per-variant artifact: the config
	// device carrying it is outside the launch measurement and was the same
	// device for every boot, so nothing about it can account for a difference
	// between these verdicts (ADR-0004, ADR-0005).
	chain, err := os.ReadFile(filepath.Join(provisionedDir, provisionedName))
	if err != nil {
		t.Fatalf("evidence was captured without the chain provisioned for it: %v", err)
	}
	publicKey, err := os.ReadFile(filepath.Join(sensitivityDir, v.dir, "public-key.der"))
	if err != nil {
		t.Fatalf("variant %q was captured without the key its evidence is bound to: %v", v.dir, err)
	}
	predicted, err := predictionFor(v.dir)
	if err != nil {
		t.Fatalf("variant %q was captured without the prediction written before it booted: %v", v.dir, err)
	}
	return bootedGuest{
		evidence:  attest.Evidence{Vendor: attest.VendorAMDSEVSNP, Bytes: report, Chain: chain},
		binding:   attest.Binding{PublicKey: publicKey, Context: attest.BindingContextV1},
		predicted: predicted,
	}
}

// predictionFor reads the launch measurement predict-measurement.sh computed
// for one variant. That file was written before the guest booted; the whole
// point of ticket 07 is that it is not a readback.
func predictionFor(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(sensitivityDir, dir, "predicted-measurement.txt"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if m, ok := strings.CutPrefix(line, "launch_measurement: "); ok {
			return strings.TrimSpace(m), nil
		}
	}
	return "", os.ErrNotExist
}

// baselineSet is the verification a peer would run against the image as built:
// the real SEV-SNP verifier with no root of its own, which means the AMD roots
// embedded in the library, and the set the baseline's build signed.
//
// It is a [preV2], for the reason that type gives: these six guests were booted
// before binding context v2 existed and their evidence is bound under v1, which
// [attest.Verification] now refuses on the version alone. What the milestone
// asserts is about measurements, and it is asked here the way Verify asks it.
func baselineSet(t *testing.T) *preV2 {
	t.Helper()
	set := baselineReferenceValues(t)
	verifier, err := verify.New(verify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attest.New(verifier, set); err != nil {
		t.Fatalf("the baseline's own set was refused at construction: %v", err)
	}
	return &preV2{verifier: verifier, set: set}
}

// TestEachGuestReportedTheMeasurementPredictedForIt is the half of milestone 2
// that is about the measurement rather than about the verdict.
//
// For every image, the launch measurement was computed offline from the files
// on disk and written down, and only then was a guest booted from it. This
// checks the two facts that follow: each guest reported exactly what had been
// predicted for it, and the four mutations produced four different
// measurements — so the digest tracks which byte changed, rather than merely
// registering that something did.
func TestEachGuestReportedTheMeasurementPredictedForIt(t *testing.T) {
	seen := map[string]string{}
	for _, v := range variants {
		t.Run(v.dir, func(t *testing.T) {
			g := loadBootedGuest(t, v)
			attested := mustAccept(t, baselineSetOrOwn(t, v), g)
			if got := hex.EncodeToString(attested); got != g.predicted {
				t.Errorf("the guest booted from %q reports %s; the prediction written before it booted was %s",
					v.dir, got, g.predicted)
			}
		})
		if g, err := predictionFor(v.dir); err == nil {
			if other, ok := seen[g]; ok && other != v.dir && v.dir != "none" && other != "none" {
				t.Errorf("%q and %q predict the same measurement %s, so this run cannot tell them apart",
					v.dir, other, g)
			}
			seen[g] = v.dir
		}
	}
}

// TestOnlyTheUnmodifiedImageSatisfiesTheSetSignedForIt is the refusal, and its
// control.
//
// One reference value set — the one the baseline's build authored and signed
// from its own offline prediction — meets six guests. The image as built is
// accepted. The image rebuilt with nothing changed is accepted, which is what
// says the refusals below are about the mutations rather than about rebuilding.
// Every image with one byte changed is refused, and the reason names the
// measurement rather than the chain, the policy or the TCB.
func TestOnlyTheUnmodifiedImageSatisfiesTheSetSignedForIt(t *testing.T) {
	v := baselineSet(t)
	for _, variant := range variants {
		t.Run(variant.dir, func(t *testing.T) {
			g := loadBootedGuest(t, variant)
			attested, err := v.Verify(context.Background(), g.evidence, g.binding)
			if variant.accepted {
				if err != nil {
					t.Fatalf("the guest booted from an image with %s was refused: %s", variant.changed, detail(err))
				}
				if got := hex.EncodeToString(attested.Claims.LaunchMeasurement); got != g.predicted {
					t.Errorf("accepted measurement %s is not the predicted %s", got, g.predicted)
				}
				return
			}
			if err == nil {
				t.Fatalf("a guest booted from an image with %s was accepted", variant.changed)
			}
			if got := attest.ReasonOf(err); got != attest.ReasonMeasurementNotInSet {
				t.Errorf("refused as %q; want %q — a refusal for another reason would pass this test "+
					"with the measurement check removed", got, attest.ReasonMeasurementNotInSet)
			}
		})
	}
}

// baselineSetOrOwn gives an accepted variant the baseline's set and a refused
// one a set naming its own predicted measurement, so that
// TestEachGuestReportedTheMeasurementPredictedForIt can read the measurement
// out of an accepted verdict — that is, out of a report whose AMD signature
// has been checked — rather than out of the raw bytes at a fixed offset. The
// question there is what the platform attested, not whether the set admits it.
func baselineSetOrOwn(t *testing.T, v variant) *preV2 {
	t.Helper()
	if v.accepted {
		return baselineSet(t)
	}
	predicted, err := predictionFor(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := hex.DecodeString(predicted)
	if err != nil {
		t.Fatal(err)
	}
	// Everything but the measurement is the baseline set's, taken from the
	// file rather than restated here.
	base := baselineReferenceValues(t)
	own := base
	own.Values = []attest.ReferenceValue{{
		Vendor:            attest.VendorAMDSEVSNP,
		LaunchMeasurement: m,
		MinimumTCB:        base.Values[0].MinimumTCB,
		GuestPolicy:       base.Values[0].GuestPolicy,
	}}
	verifier, err := verify.New(verify.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The set still goes through attest.New, which is where a set that could
	// not mean what its author intended is refused. Only the verdict is taken
	// through the stand-in, and only because the recording's binding is v1.
	if _, err := attest.New(verifier, own); err != nil {
		t.Fatalf("the set built for %q was refused at construction: %v", v.dir, err)
	}
	return &preV2{verifier: verifier, set: own}
}

// baselineReferenceValues is the set the baseline image's build authored and
// signed, re-authored in this process because the recorded document is version
// 1 and the key that signed it is not in git; reauthoredSet says what that
// preserves and what it does not. The recorded artifacts are untouched.
//
// It skips rather than fails when the run's artifacts are not in the checkout,
// for the reason loadBootedGuest does.
func baselineReferenceValues(t *testing.T) attest.ReferenceValueSet {
	t.Helper()
	path := filepath.Join(sensitivityDir, "reference-values.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no captured reference value set: %v", err)
	}
	return reauthoredSet(t, path)
}

// mustAccept verifies and returns the launch measurement of the verdict.
func mustAccept(t *testing.T, v *preV2, g bootedGuest) []byte {
	t.Helper()
	attested, err := v.Verify(context.Background(), g.evidence, g.binding)
	if err != nil {
		t.Fatalf("evidence from a live confidential guest was refused: %s", detail(err))
	}
	return attested.Claims.LaunchMeasurement
}
