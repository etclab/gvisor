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

package tunneld_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The fake platform imports go-sev-guest's test helpers, which import
// "testing" and register flags at init. Ticket 14 puts the tunneld binary
// inside the launch measurement, so anything reachable from package tunneld
// is measured with it. This guards the production import graph rather than
// relying on a comment: it lists the non-test dependencies of package tunneld
// and fails if the fake, the vendor's test helpers, or "testing" itself
// appear.
func TestProductionImportGraphExcludesTestSupport(t *testing.T) {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	out, err := exec.Command(goBin, "list", "-deps", "gvisor.dev/gvisor/attest/tunneld").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	deps := strings.Fields(string(out))
	forbidden := []string{
		"gvisor.dev/gvisor/attest/snpfake",
		"github.com/google/go-sev-guest/testing",
		"testing",
	}
	for _, f := range forbidden {
		for _, d := range deps {
			if d == f {
				t.Errorf("package tunneld reaches %q; it must not be linked into the production binary", f)
			}
		}
	}
	// The guard is only worth anything if the list it read is the real one.
	if !contains(deps, "gvisor.dev/gvisor/attest") || !contains(deps, "github.com/quic-go/quic-go") {
		t.Fatalf("go list output does not look like tunneld's dependency graph:\n%s", out)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
