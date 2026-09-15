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

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
)

// A pushed policy is opaque, versioned JSON:
//
//	{"format":"policy","version":1,"n":[…],"f":[…],"x":[…]}
//
// Two fields of it are read here and nowhere else in this design: the format,
// which says what kind of document this is, and the version, which says who
// may read the rest of it. `n`, `f` and `x` are not read at all — not by
// tunneld, which has no opinion about a policy's contents, and not by [Null],
// which enforces nothing. Whoever eventually enforces a policy is the first
// thing in this tree that will parse them, and it will do it against a version
// it declares it understands.
//
// The envelope is checked before the sandbox is woken rather than by the
// sandbox, because "this is a policy, version 1" is the one question whose
// answer decides whether the push is addressed to this side at all. A sandbox
// that had to answer it would be a sandbox each implementation of which could
// answer it differently, and the push would then mean whatever the sandbox
// beside a particular tunneld happened to think it meant.

// PolicyFormat is the only format this design pushes, and PolicyVersion the
// only version of it. Both are matched exactly: a document that says anything
// else is refused rather than read as far as the first field that parses.
const (
	PolicyFormat  = "policy"
	PolicyVersion = 1
)

// ErrPolicyRefused is what every refusal of a pushed policy wraps, so that a
// caller can tell "the sandbox would not take this" from "the sandbox was not
// there". It is the envelope's refusal; a sandbox that refuses a policy whose
// envelope was fine returns its own error.
var ErrPolicyRefused = errors.New("sandbox: policy refused")

// An Envelope is the whole of what is read out of a pushed policy before it is
// handed on: what it claims to be, and which version of that it claims to be.
type Envelope struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
}

// ReadEnvelope reads the two fields and refuses anything that is not a version
// this side pushes.
//
// Unknown fields are ignored, which is the opposite of how this module loads
// its signed documents (attest/refvalsfile.go refuses them) and deliberately
// so. There an unknown field is a constraint the loader cannot see, and
// accepting it would be admitting a peer under a rule nobody applied. Here the
// unknown fields are the policy — `n`, `f` and `x` and whatever a later version
// adds beside them — and refusing them would mean tunneld had to understand a
// document it is only carrying. The version is what stands in for the strict
// decode: a reader that does not know the version refuses the document whole.
func ReadEnvelope(policy []byte) (Envelope, error) {
	if len(policy) == 0 {
		return Envelope{}, fmt.Errorf("%w: it is empty", ErrPolicyRefused)
	}
	var e Envelope
	if err := json.Unmarshal(policy, &e); err != nil {
		return Envelope{}, fmt.Errorf("%w: %d bytes that are not a JSON object: %v", ErrPolicyRefused, len(policy), err)
	}
	if e.Format != PolicyFormat {
		return Envelope{}, fmt.Errorf("%w: format %q is not %q", ErrPolicyRefused, e.Format, PolicyFormat)
	}
	if e.Version != PolicyVersion {
		return Envelope{}, fmt.Errorf("%w: version %d is not %d", ErrPolicyRefused, e.Version, PolicyVersion)
	}
	return e, nil
}
