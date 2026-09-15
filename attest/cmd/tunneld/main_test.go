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
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config device carrying policy.json is refused, and so is one carrying only
// the orphaned signature beside where the document used to be.
//
// Ticket 22 took that document off the device: the egress ceiling it carried is
// compiled into this binary, and what a sandbox may delegate to whom is pushed
// over the tunnel after attestation. Nothing here reads it any more — which is
// exactly why its presence has to stop the guest. A device built by a script
// that is still correct for the old world would otherwise come up looking
// healthy while the file on it decided nothing, and the console would say
// nothing about the difference. That is a worse failure than a refusal, because
// the operator holding it has no way to see it.
//
// The signature is checked for by name because a half-updated device is what a
// partial rebuild leaves behind, and the orphan is the harder of the two to
// notice: before ticket 22 a lone policy.json.sig produced a refusal that named
// the *document* as missing, so nobody ever saw the signature at all.
func TestAConfigDeviceCarryingAPolicyIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
		names string
	}{
		{"the document", []string{"policy.json"}, "policy.json"},
		{"the orphaned signature", []string{"policy.json.sig"}, "policy.json.sig"},
		{"both halves", []string{"policy.json", "policy.json.sig"}, "policy.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			if code := run([]string{"-config", dir}, &out); code != exitRefusedToStart {
				t.Fatalf("a device carrying %v started: exit %d\n%s", tc.files, code, out.String())
			}
			got := out.String()
			for _, want := range []string{tc.names, "ticket 22", "pushed over the tunnel"} {
				if !strings.Contains(got, want) {
					t.Errorf("the refusal does not say %q; it is:\n%s", want, got)
				}
			}
		})
	}
}

// The refusal is before the mode split, so one check covers all three of the
// invocations a guest makes per boot (docs/snp/cloud/tdx/init.tdx): the ceiling
// install, the probe, and the serving tunneld. Checked inside serve the egress
// modes would still run against a stale device; checked inside the egress modes
// the serving tunneld would.
//
// The control is the other half of the claim: a device carrying no policy gets
// past this check and is refused, if at all, for whatever is actually wrong with
// it. A refusal that named ticket 22 for every unreadable device would be worth
// nothing to the operator holding one.
func TestThePolicyRefusalCoversEveryModeAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"print", "install", "probe"} {
		var out bytes.Buffer
		if code := run([]string{"-config", dir, "-egress", mode}, &out); code != exitRefusedToStart {
			t.Errorf("-egress %s ran against a device carrying a policy: exit %d\n%s", mode, code, out.String())
		}
	}

	var out bytes.Buffer
	if code := run([]string{"-config", t.TempDir()}, &out); code != exitRefusedToStart {
		t.Fatalf("a device with no documents at all started: exit %d\n%s", code, out.String())
	}
	if got := out.String(); strings.Contains(got, "ticket 22") || !strings.Contains(got, runConfigName) {
		t.Errorf("a device carrying no policy was refused for the wrong reason:\n%s", got)
	}
}
