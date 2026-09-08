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

package attest

import (
	"errors"
	"fmt"
)

// A ReferenceValue is an expected launch measurement plus the TCB floor and the
// guest policy a peer must satisfy to be admitted.
//
// Nothing here is a key or a name. Membership is "runs the measured image":
// anyone who launches it joins, adding a host needs no human step, and
// revocation is a TCB floor or a measurement change rather than a file edit.
type ReferenceValue struct {
	// Vendor is the hardware this value is about, and a verifier only
	// considers the values for its own vendor.
	//
	// On disk (format version 2) the tag is required: a value that does not
	// say which vendor's evidence it admits is refused by the loader. In
	// memory an empty Vendor means [VendorAMDSEVSNP] — the vendor that existed
	// before reference values named one at all — so a set built by code
	// written before version 2 keeps meaning what it always meant. Read
	// [ReferenceValue.vendor] rather than this field when the effective vendor
	// is what matters.
	Vendor Vendor

	// LaunchMeasurement is the expected SEV-SNP digest of initial guest memory.
	// It is a prediction computed offline from the image build inputs, not a
	// value read off a booted guest — a measurement learned by asking the
	// machine is not a prediction, and a check built on one cannot fail.
	//
	// For an SEV-SNP value it must not be empty. A reference value naming no
	// measurement matches every authentic platform, so both [New] and
	// [LoadReferenceValueSet] refuse a set containing one.
	//
	// Its width is deliberately checked nowhere. How wide a launch measurement
	// is belongs to the hardware vendor. A measurement of the wrong width
	// matches nothing, which fails closed.
	LaunchMeasurement []byte

	// MinimumTCB is the lowest SEV-SNP platform trusted computing base level
	// this value admits. A platform below it is refused, which is how a
	// known-vulnerable firmware level is kept out.
	MinimumTCB TCB

	// GuestPolicy is what an SEV-SNP peer's guest policy may claim.
	GuestPolicy GuestPolicy

	// TDX is the Intel TDX half of this value, set for [VendorIntelTDX] and
	// nil for every other vendor. Intel's registers, policy and TCB are
	// different objects from AMD's, not the same objects with different
	// widths, so they get their own type rather than being packed into the
	// three fields above.
	TDX *TDXReferenceValue
}

// A TDXReferenceValue is what an Intel TDX peer on a provider-booted VM must
// present to be admitted.
//
// Two kinds of register are named here and the field names say which. The
// *Observed* ones are the provider's: MRTD is the firmware Google boots, RTMR0
// its configuration, RTMR1 its boot chain, and none of them can be predicted
// from anything the reference value author holds (docs/tdx-rtmr2-prediction.md,
// "What this does not establish"). They are pinned as constants observed on
// real hardware, which admits exactly the provider's current boot stack and
// nothing else, and a verifier on new hardware will find out when the
// provider changes it. The *Predicted* one is the image's: RTMR2 is computed
// from the disk image by docs/snp/cloud/tdx/predict-rtmr2.py before anything
// boots, under the same rule as the SEV-SNP launch measurement.
type TDXReferenceValue struct {
	// ObservedMRTD, ObservedRTMR0 and ObservedRTMR1 each admit any one of the
	// listed values, and each must list at least one. A list because the
	// provider's values are not single: RTMR1 covers the GPT, and on every
	// Google VM on record it takes one value on the VM's first boot — before
	// the root partition is grown — and another on every boot after, so a
	// reference value that named one would refuse a peer after its first
	// reboot. The list says "any of these", never "ignore".
	ObservedMRTD  [][]byte
	ObservedRTMR0 [][]byte
	ObservedRTMR1 [][]byte

	// PredictedRTMR2 is the image's register, predicted offline. It must not be
	// empty, for the reason [ReferenceValue.LaunchMeasurement] gives.
	PredictedRTMR2 []byte

	// TDPolicy is what the peer's TD attributes may claim.
	TDPolicy TDPolicy

	// MinimumTCB is the floor the platform's Intel TCB level must meet.
	MinimumTCB TDXTCBFloor
}

// TDPolicy states which TD capabilities a reference value permits. Like
// [GuestPolicy] it is a ceiling named for its polarity, and its zero value
// permits nothing.
type TDPolicy struct {
	// AllowDebug permits a TD created with TD_ATTRIBUTES.DEBUG, which lets the
	// host read its memory. Leaving it false is what stops a debug-enabled TD
	// from attesting.
	AllowDebug bool
}

// TDXTCBStatus is Intel's word for a platform's TCB level, as the TCB info
// document Intel signs for the platform's FMSPC resolves it.
type TDXTCBStatus string

// The two statuses a reference value may accept as a floor. Everything Intel
// can say other than these two — ConfigurationNeeded, OutOfDate, Revoked and
// their combinations — is below either floor and is refused.
const (
	// TDXTCBUpToDate is a platform at Intel's current level.
	TDXTCBUpToDate TDXTCBStatus = "UpToDate"

	// TDXTCBSWHardeningNeeded is a platform at the current level whose
	// software must apply documented mitigations. It is the weaker floor.
	TDXTCBSWHardeningNeeded TDXTCBStatus = "SWHardeningNeeded"
)

// TDXTCBFloor is the lowest Intel TCB level a reference value admits.
//
// It is two things because Intel's level is two things. Status is the
// platform's standing under the TCB info the verifier holds, and
// EvaluationDataNumber is how recent that TCB info must be: Intel raises the
// number on every TCB recovery, and a TCB info from before a recovery still
// verifies and still calls a since-vulnerable platform UpToDate. The
// collateral is provisioned by the host, so this is the field that stops a
// host provisioning last year's.
type TDXTCBFloor struct {
	// Status is the weakest status admitted: [TDXTCBUpToDate] or
	// [TDXTCBSWHardeningNeeded]. Any other value is refused by validate, and an
	// empty one is not a floor of "anything" but a set that does not load.
	Status TDXTCBStatus

	// EvaluationDataNumber is the lowest tcbEvaluationDataNumber the
	// provisioned TCB info may carry. Zero imposes no floor.
	EvaluationDataNumber uint32
}

// clone returns a deep copy of rv, sharing no memory with it.
//
// A reference value is a trust root, and [New] holds one for the lifetime of a
// process. Copying only the outer struct would leave the caller holding the
// same backing arrays — a launch measurement, an observed register list — and
// able to rewrite them afterwards, at a distance, from code that has no idea
// what it is touching. Every slice is therefore copied, including the ones
// behind the TDX half.
func (rv ReferenceValue) clone() ReferenceValue {
	out := rv
	out.LaunchMeasurement = cloneBytes(rv.LaunchMeasurement)
	if rv.TDX != nil {
		tdx := *rv.TDX
		tdx.ObservedMRTD = cloneDigests(rv.TDX.ObservedMRTD)
		tdx.ObservedRTMR0 = cloneDigests(rv.TDX.ObservedRTMR0)
		tdx.ObservedRTMR1 = cloneDigests(rv.TDX.ObservedRTMR1)
		tdx.PredictedRTMR2 = cloneBytes(rv.TDX.PredictedRTMR2)
		out.TDX = &tdx
	}
	return out
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func cloneDigests(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	out := make([][]byte, len(values))
	for i, v := range values {
		out[i] = cloneBytes(v)
	}
	return out
}

// A ReferenceValueSet is the collection of reference values one verifier will
// accept. Evidence satisfying any one of them is accepted, which is what lets a
// new image roll out while the old one is still running.
//
// Here the set is an in-memory value. The signed document a reference value
// author writes, its detached signature and its loader are in refvalsfile.go,
// and produce exactly this type: nothing that consumes a set can tell whether
// it was read off the config device or built in a test.
type ReferenceValueSet struct {
	Values []ReferenceValue
}

// TCB is a platform trusted computing base level, expressed as four separately
// named component versions rather than the packed integer the hardware reports.
//
// The packing is the vendor's business. A reference value set is this design's
// trust root and has to be reviewable by eye, and nobody reviews a decimal
// integer for whether it means "microcode 72".
type TCB struct {
	// Bootloader is the bootloader security patch level.
	Bootloader uint8

	// TEE is the trusted execution environment security patch level.
	TEE uint8

	// SNP is the SNP firmware security patch level.
	SNP uint8

	// Microcode is the microcode security patch level.
	Microcode uint8
}

// GuestPolicy states which guest capabilities a reference value permits. It is
// a ceiling, not a description: a peer whose evidence claims a capability this
// value does not permit is refused.
//
// Every field is named for its polarity, because a trust root that a reviewer
// can misread by one negation is not reviewable. A capability this type does
// not name is not permitted — the type fails closed as it grows, and a peer
// launched with a capability nobody has considered does not slip through on the
// grounds that nobody considered it.
//
// The zero value permits nothing and requires nothing beyond that, which is the
// right default for a reference value whose author did not think about policy.
type GuestPolicy struct {
	// ABIMajor and ABIMinor are the lowest SNP ABI version the guest may have
	// demanded at launch. Zero imposes no floor.
	ABIMajor uint8
	ABIMinor uint8

	// AllowSMT permits a guest launched on a platform with symmetric
	// multithreading enabled.
	AllowSMT bool

	// AllowMigrationAgent permits a guest that may have a migration agent.
	AllowMigrationAgent bool

	// AllowDebug permits a guest the host may decrypt for debugging. Leaving it
	// false is what stops a debug-enabled guest from attesting.
	AllowDebug bool

	// RequireSingleSocket refuses a guest that may be active on more than one
	// socket. Unlike the fields above this one is a requirement rather than a
	// permission, which is why it is not named Allow.
	RequireSingleSocket bool
}

// validate reports the two ways a reference value set can be wrong in the
// direction that matters, and is the single place either is decided.
//
// An empty set admits nobody, which is a configuration mistake every time.
//
// A reference value with no launch measurement admits *everybody*: it names no
// image, so every authentic platform matches it, and a set holding one is
// strictly weaker than its author can have intended. That is the failure worth
// catching loudly, because it does not announce itself — every handshake
// succeeds and nothing looks wrong.
//
// Both [New] and the loader in refvalsfile.go call this, so a set that would
// admit everybody is refused whether it was built in memory or read off the
// config device. The width of a launch measurement is deliberately not checked:
// see [ReferenceValue.LaunchMeasurement].
func (set ReferenceValueSet) validate() error {
	if len(set.Values) == 0 {
		return errors.New("the reference value set is empty; it would admit nobody")
	}
	for i, rv := range set.Values {
		if err := rv.validate(); err != nil {
			return fmt.Errorf("reference value %d %v", i, err)
		}
	}
	return nil
}

// vendor returns the effective vendor of rv: rv.Vendor itself, except that an
// empty Vendor means [VendorAMDSEVSNP] — see [ReferenceValue.Vendor]'s doc
// comment for why an unset tag still means something rather than nothing.
func (rv ReferenceValue) vendor() Vendor {
	if rv.Vendor == "" {
		return VendorAMDSEVSNP
	}
	return rv.Vendor
}

// validate is the per-value half of [ReferenceValueSet.validate]: every way a
// single value could admit more than its author wrote down.
func (rv ReferenceValue) validate() error {
	switch rv.vendor() {
	case VendorAMDSEVSNP:
		if len(rv.LaunchMeasurement) == 0 {
			return errors.New("has no launch measurement; it would admit every authentic platform")
		}
		if rv.TDX != nil {
			return errors.New("is an SEV-SNP value carrying TDX fields; a value is about one vendor")
		}
		return nil
	case VendorIntelTDX:
		t := rv.TDX
		if t == nil {
			return errors.New("is a TDX value with no TDX fields; it names no register and would admit every authentic TD")
		}
		if len(rv.LaunchMeasurement) != 0 {
			return errors.New("is a TDX value carrying an SEV-SNP launch measurement; a value is about one vendor")
		}
		if len(t.PredictedRTMR2) == 0 {
			return errors.New("has no predicted RTMR2; it would admit every image the provider boots")
		}
		for _, r := range []struct {
			name   string
			values [][]byte
		}{{"MRTD", t.ObservedMRTD}, {"RTMR0", t.ObservedRTMR0}, {"RTMR1", t.ObservedRTMR1}} {
			if len(r.values) == 0 {
				return fmt.Errorf("lists no observed %s; a register with no expected value is a register not checked", r.name)
			}
			for _, v := range r.values {
				if len(v) == 0 {
					return fmt.Errorf("lists an empty observed %s; an empty value would match nothing, and is a mistake rather than a choice", r.name)
				}
			}
		}
		switch t.MinimumTCB.Status {
		case TDXTCBUpToDate, TDXTCBSWHardeningNeeded:
		default:
			return fmt.Errorf("names TCB status floor %q; a floor is %q or %q", t.MinimumTCB.Status, TDXTCBUpToDate, TDXTCBSWHardeningNeeded)
		}
		return nil
	default:
		return fmt.Errorf("names vendor %q, which no verifier here implements", rv.Vendor)
	}
}
