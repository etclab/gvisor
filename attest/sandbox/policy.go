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
	"slices"
	"strings"
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

// The subset check, contract version 3.
//
// A delegation narrows. A node that was pushed P0 and pushes P1 onward may hand
// on no more than it was given, and nothing in this tree checked that until now
// (the finding is recorded at attest/cmd/agent-probe/twohops_test.go:35). The
// check is component-wise — `n`, `f` and `x` each on their own — over sorted,
// deduplicated atoms, which is the shape ticket 23's Deno sandbox already
// judged a widening by and the shape a widening refusal already names.
//
// The atoms are Deno's grammar, and they are here rather than there because the
// rule is the contract's and not one sandbox's:
//
//	net:<host>:<port>     one port of one host
//	net:<host>            every port of one host — a wider grant than it looks
//	read:<path>           one mode of one path, one atom per mode
//	write:<path>
//	run:<path>            an exec identity by the path it is at
//	run:sha256:<hex>      an exec identity by what it contains
//
// The set and not the document is what is compared, for the reason Deno's
// sandbox compares the set: two documents that name the same hosts in a
// different order are the same grant, and a check on the bytes would call one
// of them a widening.
//
// What is deliberately absent is `e`. The Deno sandbox invented that letter for
// the key its agent could not otherwise read (spike E4, docs/agent-on-the-
// contract.md); it is not in the provisional policy bytes and this ticket does
// not add it. The Deno sandbox keeps its own atomiser for that reason and for
// two others: it refuses a digest it has nowhere to put, and it refuses a host
// its flag parser would refuse after the exec rather than before it. Both are
// facts about Deno.

// refusePolicy is every refusal this file makes: [ErrPolicyRefused] and a
// sentence, so that a caller can tell "this policy is not one this side takes"
// from "there was nobody to take it" without reading the sentence.
func refusePolicy(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicyRefused, fmt.Sprintf(format, a...))
}

// A policyDocument is the three components of a version 1 policy. They are
// unknown fields of the envelope, which is what lets a reader that wants them
// have them without the envelope's reader growing an opinion about them.
type policyDocument struct {
	N []netGrant  `json:"n"`
	F []fileGrant `json:"f"`
	X []execGrant `json:"x"`
}

type netGrant struct {
	Host  string `json:"host"`
	CIDR  string `json:"cidr"`
	Ports []int  `json:"ports"`
}

type fileGrant struct {
	Path  string   `json:"path"`
	Modes []string `json:"modes"`
}

type execGrant struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Atoms is the whole of the parse: a policy in, the capability set it grants
// out, sorted and deduplicated, or the reason it is not a policy that can be
// compared with another one.
//
// The envelope is read here although tunneld has already read it, for the
// reason [Null] reads it: reaching this with something else means the contract
// was driven directly, and refusing anyway keeps "these are the atoms of a
// version 1 policy" a statement about version 1 rather than about anything at
// all.
func Atoms(policy []byte) ([]string, error) {
	if _, err := ReadEnvelope(policy); err != nil {
		return nil, err
	}
	var d policyDocument
	if err := json.Unmarshal(policy, &d); err != nil {
		return nil, refusePolicy("it is not a policy whose components can be read: %v", err)
	}
	var atoms []string
	for _, component := range []func(*policyDocument) ([]string, error){netAtoms, fileAtoms, execAtoms} {
		got, err := component(&d)
		if err != nil {
			return nil, err
		}
		atoms = append(atoms, got...)
	}
	slices.Sort(atoms)
	return slices.Compact(atoms), nil
}

// netAtoms reads `n`. An entry names a host and the ports of it, and an empty
// port list is the bare host, which grants every port.
//
// A CIDR is refused, and refused here rather than in one sandbox, because the
// reason is the format's and not Deno's: every check this design makes on a
// destination is against the name that was asked for — the connect hook and the
// DNS responder both see a name — and a name is in no CIDR. An entry that
// grants exactly the destinations nobody names is not a grant that can be
// enforced, and accepting it would be accepting a document whose meaning
// depends on who reads it.
func netAtoms(d *policyDocument) ([]string, error) {
	var atoms []string
	for _, n := range d.N {
		switch {
		case n.CIDR != "":
			return nil, refusePolicy("the n entry for %q is a CIDR, and every check made on a destination here is against the name that was asked for, which is in no CIDR", n.CIDR)
		case n.Host == "":
			return nil, refusePolicy("an n entry names no host")
		}
		if len(n.Ports) == 0 {
			atoms = append(atoms, "net:"+n.Host)
			continue
		}
		for _, port := range n.Ports {
			if port < 1 || port > 65535 {
				return nil, refusePolicy("the n entry for %q names port %d, which is not a port", n.Host, port)
			}
			atoms = append(atoms, fmt.Sprintf("net:%s:%d", n.Host, port))
		}
	}
	return atoms, nil
}

// fileAtoms reads `f`, one atom per mode: a set of modes is a set, and the two
// modes of one path are two grants that narrow separately.
func fileAtoms(d *policyDocument) ([]string, error) {
	var atoms []string
	for _, f := range d.F {
		if f.Path == "" {
			return nil, refusePolicy("an f entry names no path")
		}
		if len(f.Modes) == 0 {
			return nil, refusePolicy("the f entry for %q names no mode", f.Path)
		}
		for _, mode := range f.Modes {
			switch mode {
			case "r":
				atoms = append(atoms, "read:"+f.Path)
			case "w":
				atoms = append(atoms, "write:"+f.Path)
			default:
				return nil, refusePolicy("the f entry for %q names the mode %q, which is not a mode a policy grants", f.Path, mode)
			}
		}
	}
	return atoms, nil
}

// execAtoms reads `x`. An entry names an exec identity by where it is, by what
// it contains, or by both — and both is two atoms, because either of them
// admitting an exec makes it two grants and not one.
//
// An absent x key returns nil, indicating unconstrained exec.
// An empty x list returns a non-nil empty slice, indicating a grant of nothing.
func execAtoms(d *policyDocument) ([]string, error) {
	if d.X == nil {
		return nil, nil
	}
	atoms := []string{}
	for _, x := range d.X {
		if x.Path == "" && x.SHA256 == "" {
			return nil, refusePolicy("an x entry names neither a path nor a digest")
		}
		if x.Path != "" {
			atoms = append(atoms, "run:"+x.Path)
		}
		if x.SHA256 != "" {
			if !isSHA256Hex(x.SHA256) {
				return nil, refusePolicy("the x entry with digest %q is not 64 lowercase hexadecimal digits", x.SHA256)
			}
			atoms = append(atoms, "run:sha256:"+x.SHA256)
		}
	}
	return atoms, nil
}

// isSHA256Hex is the one spelling of a digest this design uses, everywhere:
// lowercase hexadecimal, 64 digits. Two spellings of one digest would be two
// atoms that grant the same exec, and the subset check would call the second
// one a widening.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// Widening is the check itself: the atoms of next that prev does not grant,
// grouped by the component they belong to.
//
// It has no notion of a first push. A nil prev is the empty grant and not "no
// grant has been fixed yet", because the two are indistinguishable once a
// policy that grants nothing has been through [Atoms], and a checker that
// guessed would wave through exactly the push that widens from nothing. A
// caller that has not yet fixed a set does not call this.
func Widening(prev, next []string) map[string][]string {
	have := make(map[string]bool, len(prev))
	for _, a := range prev {
		have[a] = true
	}
	var extra map[string][]string
	for _, a := range next {
		if have[a] {
			continue
		}
		if extra == nil {
			extra = map[string][]string{}
		}
		c := componentOf(a)
		extra[c] = append(extra[c], a)
	}
	return extra
}

// componentOf names the component an atom belongs to. An atom outside the
// grammar is grouped under its own kind, so that a caller comparing atoms this
// package did not produce — a boot table, say — still reads which of its own
// grants widened.
func componentOf(atom string) string {
	switch kind, _, _ := strings.Cut(atom, ":"); kind {
	case "net":
		return "n"
	case "read", "write":
		return "f"
	case "run":
		return "x"
	default:
		return kind
	}
}

// CheckNarrows is the document-level form: it refuses next unless every atom of
// it is one prev already granted, and says which component widened.
//
// The refusal wraps [ErrPolicyRefused], so a sandbox that makes this check is
// refusing a push the way every other refusal of a push is made, and the
// sentence reaches the pushing peer as the contract's refusal.
func CheckNarrows(prev, next []byte) error {
	before, err := Atoms(prev)
	if err != nil {
		return err
	}
	after, err := Atoms(next)
	if err != nil {
		return err
	}
	if extra := Widening(before, after); len(extra) > 0 {
		return refusePolicy("%s", widenedBy(extra))
	}
	return nil
}

// widenedBy is the sentence a widening is refused with: the components in the
// order the format names them, each with the atoms it gained.
func widenedBy(extra map[string][]string) string {
	named := map[string]bool{"n": true, "f": true, "x": true}
	order := []string{"n", "f", "x"}
	for c := range extra {
		if !named[c] {
			order = append(order, c)
		}
	}
	slices.Sort(order[3:])
	var parts []string
	for _, c := range order {
		if atoms := extra[c]; len(atoms) > 0 {
			parts = append(parts, fmt.Sprintf("%s by %v", c, atoms))
		}
	}
	return "it widens " + strings.Join(parts, ", ")
}
