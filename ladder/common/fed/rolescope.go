// rolescope.go - the receiving side's ceiling, and the honest note about duplicating it.
//
// Rung 5a, spec section 4.4: "The receiving proxy enforces rung-4 chain checks
// (accumulated taint, capability subset checks) against the standing service's role
// scope BEFORE delivery to the agent."
//
// # Why this arithmetic exists twice
//
// It is chaind.subset (common/chaind/chaind.py:90) reimplemented in Go, and that is a
// real cost that the README names rather than hides. Two reasons it is here anyway:
//
//  1. "Before delivery to the agent" is the acceptance criterion, and the proxy is the
//     only component that sits before delivery. Asking the local capability authority
//     first would work, but it would put a host-side daemon on the path of every
//     inbound message and would mean the substrate's own admission check depended on a
//     process the substrate does not own.
//  2. The two checks answer different questions with different lifetimes. chaind asks
//     "is this delegation contained in what the DELEGATOR holds", per goal, per chain.
//     This asks "is this claim contained in what this SERVICE may ever do", fixed at
//     deploy time, with no goal in sight. A standing service has a role and no task --
//     that is what the 5a model means -- and the role is the only ceiling available on
//     the receiving side.
//
// The second point is also the rung's regression, stated where the code is: rung 1
// replaced role scope with task scope, and the far side of a federation boundary gets
// role scope back. Rung 5b is the variant that does not.
//
// # The subtlety, carried over verbatim from chaind
//
// A grant that OMITS a key constraint the holder carries is a WIDENING, not a default.
// Getting that backwards is the entire bug class the check exists to prevent, so it is
// written the same way in both languages and tested in both.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Capability is the shape chaind speaks: a map of tool name to optional constraints.
type Capability struct {
	Tools map[string]*ToolConstraint `json:"tools"`
}

// ToolConstraint is the per-tool narrowing. Only `keys` exists, deliberately: rung 4's
// README records that there is no policy language and every new tool needs its
// constraint hand-coded, and rung 5a does not fix that.
type ToolConstraint struct {
	Keys []string `json:"keys,omitempty"`
}

// RoleScope is a standing service's deploy-time ceiling.
type RoleScope struct {
	Service string                     `json:"service"`
	Tools   map[string]*ToolConstraint `json:"tools"`
}

// LoadRoleScope reads a role file. Comment keys beginning with "_" are ignored, which is
// how the scenario files carry their explanations.
func LoadRoleScope(path string) (*RoleScope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rs := &RoleScope{}
	if err := json.Unmarshal(raw, rs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(rs.Tools) == 0 {
		// An empty role is a legitimate configuration -- a service that may receive
		// messages and call nothing -- but it must be written as an explicit empty map
		// rather than arrived at by a typo, so refuse the ambiguous case.
		return nil, fmt.Errorf("%s: role scope names no tools; write \"tools\": {} if that is deliberate", path)
	}
	return rs, nil
}

// Subset reports whether `granted` is no wider than `holder`.
//
// Line for line, chaind.subset. Two axes:
//
//	tools  every tool in granted must be a tool holder has
//	keys   a constraint the holder carries must be carried, and narrowed, by the grant.
//	       Omitting it is a widening.
func Subset(granted, holder map[string]*ToolConstraint) (bool, string) {
	names := make([]string, 0, len(granted))
	for name := range granted {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, tool := range names {
		held, ok := holder[tool]
		if !ok {
			return false, fmt.Sprintf("tool %q is not in the role (role holds: %s)",
				tool, joinTools(holder))
		}
		if held == nil || len(held.Keys) == 0 {
			continue // the role carries no constraint on this tool
		}
		grant := granted[tool]
		if grant == nil || len(grant.Keys) == 0 {
			return false, fmt.Sprintf("tool %q is claimed with no key constraint, but the role "+
				"holds it constrained to %s -- omitting the constraint is a widening",
				tool, joinKeys(held.Keys))
		}
		allowed := map[string]bool{}
		for _, k := range held.Keys {
			allowed[k] = true
		}
		var extra []string
		for _, k := range grant.Keys {
			if !allowed[k] {
				extra = append(extra, k)
			}
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			return false, fmt.Sprintf("tool %q: key(s) %s are outside the role (role allows: %s)",
				tool, joinKeys(extra), joinKeys(held.Keys))
		}
	}
	return true, "claim is contained in the service's role scope"
}

// ClaimTools pulls the tool map out of a capability authority's view, which is what
// travels in the envelope. The view is chaind's JSON and this package deliberately does
// not model the rest of it: the proxy has no business reading a goal id or a chain, and
// a struct that could would invite it to.
func ClaimTools(claim json.RawMessage) (map[string]*ToolConstraint, error) {
	if len(claim) == 0 {
		return nil, nil
	}
	var view struct {
		Tools map[string]*ToolConstraint `json:"tools"`
	}
	if err := json.Unmarshal(claim, &view); err != nil {
		return nil, err
	}
	return view.Tools, nil
}

func joinTools(m map[string]*ToolConstraint) string {
	if len(m) == 0 {
		return "nothing"
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return joinKeys(names)
}

func joinKeys(keys []string) string {
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += k
	}
	if out == "" {
		return "nothing"
	}
	return out
}
