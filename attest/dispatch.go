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
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Dispatch builds a [Verifier] that routes evidence to the verifier for its
// vendor.
//
// This is where a second vendor stops being a change to anything else. A
// tunneld builds the verifiers it was configured for, hands them here, and
// [Verification] goes on calling one Verify on one Verifier — it does not learn
// that there are now two, and neither does the transport, the certificate, or
// the reference value set, which carries entries for both vendors in one signed
// document.
//
// Duplicate vendors are refused here rather than resolved. Two verifiers for
// the same vendor means two answers to one question and no rule for which
// wins, and a startup error is the cheapest place to find that out. So is no
// verifier at all: a dispatcher over nothing would refuse every peer with
// [ReasonUnsupportedVendor], which is a true statement that hides a
// configuration mistake.
func Dispatch(verifiers ...Verifier) (Verifier, error) {
	if len(verifiers) == 0 {
		return nil, errors.New("attest: Dispatch needs at least one verifier; a dispatcher over none would refuse every peer")
	}
	byVendor := make(map[Vendor]Verifier, len(verifiers))
	for i, v := range verifiers {
		if v == nil {
			return nil, fmt.Errorf("attest: Dispatch was handed a nil verifier at position %d", i)
		}
		vendor := v.Vendor()
		if vendor == "" {
			return nil, fmt.Errorf("attest: the verifier at position %d names no vendor", i)
		}
		if _, dup := byVendor[vendor]; dup {
			return nil, fmt.Errorf("attest: two verifiers were given for vendor %q; which one speaks for it is not something this can decide", vendor)
		}
		byVendor[vendor] = v
	}
	return &dispatcher{byVendor: byVendor, vendor: compositeVendor(byVendor)}, nil
}

// compositeVendor is the name a dispatcher answers [Verifier.Vendor] with: its
// members' vendors joined with "+", in a stable order.
//
// A dispatcher speaks for several vendors, and [Verifier.Vendor] was written
// for implementations that speak for one. Returning one member's vendor would
// be a lie an operator reads in a log; returning nothing would be a lie a test
// cannot see. The composite is neither: it does not match any [Evidence.Vendor]
// and is not meant to — routing is done by the map, and this string exists to
// be printed.
func compositeVendor(byVendor map[Vendor]Verifier) Vendor {
	names := make([]string, 0, len(byVendor))
	for v := range byVendor {
		names = append(names, string(v))
	}
	sort.Strings(names)
	return Vendor(strings.Join(names, "+"))
}

type dispatcher struct {
	byVendor map[Vendor]Verifier
	vendor   Vendor
}

var _ Verifier = (*dispatcher)(nil)

// Vendor implements [Verifier]. See [compositeVendor] for what it returns and
// why it is not an [Evidence.Vendor] anything will ever match.
func (d *dispatcher) Vendor() Vendor { return d.vendor }

// Verify implements [Verifier] by handing ev to the verifier for its vendor.
//
// Evidence from a vendor no member implements is refused with
// [ReasonUnsupportedVendor] and is not offered to anyone on the chance that
// they might parse it. That is the whole point of routing on a tag rather than
// sniffing a format: a parser that is reached only by evidence claiming its
// vendor is a parser an attacker cannot pick.
func (d *dispatcher) Verify(ctx context.Context, ev Evidence, set ReferenceValueSet) (Attested, error) {
	v, ok := d.byVendor[ev.Vendor]
	if !ok {
		return Attested{}, Refuse(ReasonUnsupportedVendor,
			"evidence is from vendor %q; this verifier speaks for %q", ev.Vendor, d.vendor)
	}
	return v.Verify(ctx, ev, set)
}
