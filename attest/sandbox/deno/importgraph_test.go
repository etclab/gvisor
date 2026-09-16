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

package deno_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The import-graph form of the contract's invariant, on the first sandbox that
// enforces anything.
//
// Package sandbox depends on nothing under gvisor.dev/gvisor/attest, which is
// how "a sandbox sees no evidence, no key and no trust decision" is checked
// rather than asserted (sandbox.go, "The two halves"). An implementation of
// that contract that could reach the verifier, the tunnel or the policy files
// would be one somebody eventually asks to look at a peer's evidence, and the
// argument that it must not would be an argument and not a fact about the
// build. So this package is held to the same rule, with room for exactly what
// starting a process needs: the standard library and x/sys/unix for the
// signal.
//
// The guard is modelled on attest/cmd/tunneld/importgraph_test.go, and it
// cannot share that one's helper: the two are different test binaries in
// different packages, and the thing being guarded is precisely that this
// package imports nothing it could have shared code through.
func TestThePackageImportsOnlyTheStandardLibraryAndTheContract(t *testing.T) {
	allowed := map[string]bool{
		"golang.org/x/sys/unix":                 true,
		"gvisor.dev/gvisor/attest/sandbox":      true,
		"gvisor.dev/gvisor/attest/sandbox/deno": true, // go list -deps ends with the package itself
	}
	deps := listDeps(t, "gvisor.dev/gvisor/attest/sandbox/deno")
	for _, dep := range deps {
		domain, _, _ := strings.Cut(dep, "/")
		if !strings.Contains(domain, ".") || allowed[dep] {
			// No dot in the first element is the standard library's shape.
			continue
		}
		t.Errorf("this package reaches %q; a sandbox is the standard library, x/sys/unix and the contract it implements", dep)
	}
	// The guard is worth something only if the list it read is the real one.
	for _, want := range []string{"os/exec", "encoding/json", "gvisor.dev/gvisor/attest/sandbox"} {
		if !slices.Contains(deps, want) {
			t.Fatalf("go list output does not look like this package's dependency graph: %q is missing from %d packages", want, len(deps))
		}
	}
}

func listDeps(t *testing.T, pkg string) []string {
	t.Helper()
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	out, err := exec.Command(goBin, "list", "-deps", pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	return strings.Fields(string(out))
}
