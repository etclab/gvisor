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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// Null is the sandbox that enforces nothing: it passes streams through to the
// [Network] it was given and records the policies pushed at it.
//
// It is not a placeholder for a sandbox that will do more here. It is the
// honest implementation of a contract in which a sandbox is not where anything
// is enforced — the enforcement a policy names happens at tunneld's boundary,
// in the netfilter rule set the signed policy implies (docs/policy-binding.md)
// and in the reference value set that admits a peer at all. What a sandbox
// does with a pushed policy is the sandbox's business, and this one's business
// is to say it has it.
//
// It is also the measurement of the contract's cost: with the null sandbox in
// the path, Milestone 3's exercise is the first client of the local contract
// and every recorded scenario runs through it. A figure that moved would be
// the contract's doing and nothing else's.
//
// Applying is recorded rather than acted on, and recorded in full: the format,
// the version, the length and the SHA-256 of the exact bytes. That is what
// makes "B acknowledged the policy A pushed" a claim a console transcript can
// support — the digest on both sides is the same number or the push carried
// something else.
type Null struct {
	network Network
	logf    func(string, ...any)

	mu      sync.Mutex
	applied []Record
}

// A Record is one policy this sandbox was pushed, as it will be reported.
type Record struct {
	// Format and Version are the envelope tunneld already checked.
	Format  string
	Version int

	// Bytes is the length of the document and SHA256 its digest, in lowercase
	// hexadecimal, over exactly the bytes that arrived.
	Bytes  int
	SHA256 string
}

// ErrNoNetwork is what a null sandbox with no tunneld behind it returns rather
// than dereferencing one. A sandbox is constructed around a [Network]; one
// without is a programming error, and an error is how it says so rather than a
// panic in whatever goroutine first asked it for a stream.
var ErrNoNetwork = errors.New("sandbox: no network")

var _ Sandbox = (*Null)(nil)

// NewNull returns a null sandbox over n. logf may be nil, which records
// policies without saying so.
func NewNull(n Network, logf func(string, ...any)) *Null {
	return &Null{network: n, logf: logf}
}

// Open asks tunneld for a stream to the named peer.
func (s *Null) Open(ctx context.Context, peer string) (Stream, error) {
	if s.network == nil {
		return nil, ErrNoNetwork
	}
	return s.network.Open(ctx, peer)
}

// Accept takes the next stream a peer opened, with the identity it was
// admitted under.
func (s *Null) Accept(ctx context.Context) (Stream, Attested, error) {
	if s.network == nil {
		return nil, Attested{}, ErrNoNetwork
	}
	return s.network.Accept(ctx)
}

// Apply records the policy and acknowledges it. It parses nothing beyond the
// envelope tunneld has already read, and in particular never looks at `n`, `f`
// or `x`.
func (s *Null) Apply(_ context.Context, policy []byte) error {
	e, err := ReadEnvelope(policy)
	if err != nil {
		// Tunneld checks this before the push reaches a sandbox, so reaching
		// here means the contract was driven directly. Refusing anyway is what
		// keeps "the null sandbox acks a version 1 policy" a statement about
		// version 1 rather than about anything at all.
		return err
	}
	sum := sha256.Sum256(policy)
	r := Record{Format: e.Format, Version: e.Version, Bytes: len(policy), SHA256: hex.EncodeToString(sum[:])}
	s.mu.Lock()
	s.applied = append(s.applied, r)
	s.mu.Unlock()
	if s.logf != nil {
		s.logf("SANDBOX applied format=%s version=%d bytes=%d sha256=%s", r.Format, r.Version, r.Bytes, r.SHA256)
	}
	return nil
}

// Applied is every policy this sandbox has acknowledged, in the order they
// arrived.
func (s *Null) Applied() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.applied...)
}
