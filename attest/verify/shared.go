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

package verify

import "gvisor.dev/gvisor/attest"

// refuseUnrooted turns a vendor library's verdict on authenticity into this
// package's answer to it. A nil verdict stays nil; every other one becomes the
// single refusal both vendor halves give evidence that cannot be rooted.
//
// The library's error is not inspected to say more. go-sev-guest and
// go-tdx-guest both wrap everything with %v, so the reason a caller could
// recover by matching strings would be a reason that changes when the library
// changes its wording — and authenticity in the widest sense is one question
// anyway: is any of this real.
//
// Only the two checkAuthentic methods hand a verdict here, and they hand one
// that a whole library produced. A refusal either verifier reaches on its own —
// absent collateral, collateral out of date — names the same reason but keeps
// the sentence that says which of the verifier's own questions failed.
func refuseUnrooted(err error) error {
	if err == nil {
		return nil
	}
	return attest.Refuse(attest.ReasonChainNotRooted, "%v", err)
}
