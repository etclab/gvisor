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

package tsm_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// acquisition must never reach AMD's key distribution service: a fallback
// fetch would reinstate exactly the dependency ADR-0005 removes, and would do
// it invisibly, on the critical path of every tunnel.
//
// This guards that structurally rather than by comment, but it has to guard it
// on this package's own imports rather than on its transitive graph, and that
// is worth saying plainly. gvisor.dev/gvisor/attest/provision holds both
// halves of provisioning: the operator's Fetch, which does reach the service
// and therefore reaches net/http, and the consumer's Load and CheckFor, which
// are all this package calls and which cannot be handed a getter at all. So
// net/http is in the transitive graph by construction and a check on the
// graph would prove nothing. What can be checked, and what actually matters,
// is that this package imports nothing of its own through which a fetch could
// be written: an allowlist that a new dependency fails until somebody justifies
// it here.
func TestAcquisitionImportsNoWayToReachTheKeyDistributionService(t *testing.T) {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	out, err := exec.Command(goBin, "list", "-f", `{{join .Imports "\n"}}`, "gvisor.dev/gvisor/attest/tsm").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	imports := strings.Fields(string(out))

	allowed := map[string]bool{
		// The standard library this package drives the kernel with.
		"bytes": true, "context": true, "encoding/hex": true, "errors": true,
		"fmt": true, "io/fs": true, "os": true, "path/filepath": true,
		"strconv": true, "strings": true, "sync": true, "syscall": true,

		// The vendor seam and each vendor's own report format, which is what
		// reading the caller-supplied bytes back needs (ADR-0003). Intel's
		// takes two: the parser, and the generated structures it parses into.
		// Neither reaches a network of its own — the fetching half of
		// go-tdx-guest is its verify and pcs packages, which are the
		// verifier's and are not here.
		"gvisor.dev/gvisor/attest":                 true,
		"github.com/google/go-sev-guest/abi":       true,
		"github.com/google/go-tdx-guest/abi":       true,
		"github.com/google/go-tdx-guest/proto/tdx": true,

		// The consumer half of provisioning: load the chain from the config
		// device, refuse a missing or stale one, never fetch (ADR-0005).
		"gvisor.dev/gvisor/attest/provision": true,
	}
	for _, imp := range imports {
		if !allowed[imp] {
			t.Errorf("package tsm imports %q, which is not on the acquisition allowlist; "+
				"if it belongs there, add it here and say why — acquisition reaching the network is the failure this list exists to prevent", imp)
		}
	}
	// The guard is only worth anything if the list it read is the real one.
	if !contains(imports, "gvisor.dev/gvisor/attest") || !contains(imports, "gvisor.dev/gvisor/attest/provision") {
		t.Fatalf("go list output does not look like this package's imports:\n%s", out)
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
