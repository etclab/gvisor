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

package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The fake platform imports go-sev-guest's test helpers, which import
// "testing" and register flags at init. Ticket 14 builds this command into the
// measured image as /usr/bin/tunneld, so everything reachable from here is in
// the launch measurement — and a measurement over a binary nobody checked is a
// measurement of whatever was there.
//
// This guard lived in package tunneld until ticket 14 and had to move, because
// the package is not what is measured. A command can import what the package
// it is built on does not, and this one is a composition root: it reaches for
// a real acquirer and a real verifier by name, which is exactly the kind of
// code where a fake platform gets wired in by accident. Package tunneld's
// graph is contained in this one — the command imports the package — so a
// guard here is strictly stronger than the guard that was there, and there is
// one guard rather than two that could disagree.
//
// It must run before the measurement is computed, which is a property of the
// packaging step and not of this file: docs/snp/image/package-tunneld.sh runs
// `go test ./cmd/tunneld` first, builds the binary second, and only then calls
// build-image.sh. TestPackagedBinaryHasNoTestSupportSymbols checks the same
// property on the artifact rather than on a graph computed beside it.
func TestPackagedImportGraphExcludesTestSupport(t *testing.T) {
	deps := listDeps(t, "gvisor.dev/gvisor/attest/cmd/tunneld")
	forbidden := []string{
		"gvisor.dev/gvisor/attest/snpfake",
		"github.com/google/go-sev-guest/testing",
		"testing",
	}
	for _, f := range forbidden {
		if contains(deps, f) {
			t.Errorf("the packaged tunneld reaches %q; it must not be linked into the binary the image measures", f)
		}
	}
	// The guard is only worth anything if the list it read is the real one.
	for _, want := range []string{
		"gvisor.dev/gvisor/attest",
		"gvisor.dev/gvisor/attest/tunneld",
		"gvisor.dev/gvisor/attest/tsm",
		"gvisor.dev/gvisor/attest/verify",
		"github.com/quic-go/quic-go",
	} {
		if !contains(deps, want) {
			t.Fatalf("go list output does not look like the packaged tunneld's dependency graph: %q is missing from %d packages", want, len(deps))
		}
	}
}

// Package tunneld's own graph is guarded here too, and not because the check
// above leaves it out — it cannot, since this command imports it. It is here
// so that a failure names which of the two grew the dependency, and so that
// somebody moving the command elsewhere does not take the package's guard with
// it by accident.
func TestPackageImportGraphExcludesTestSupport(t *testing.T) {
	deps := listDeps(t, "gvisor.dev/gvisor/attest/tunneld")
	for _, f := range []string{
		"gvisor.dev/gvisor/attest/snpfake",
		"github.com/google/go-sev-guest/testing",
		"testing",
	} {
		if contains(deps, f) {
			t.Errorf("package tunneld reaches %q; the fake platform is injected through Config, from test code, and nowhere else", f)
		}
	}
	if !contains(deps, "gvisor.dev/gvisor/attest") || !contains(deps, "github.com/quic-go/quic-go") {
		t.Fatalf("go list output does not look like package tunneld's dependency graph (%d packages)", len(deps))
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

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
