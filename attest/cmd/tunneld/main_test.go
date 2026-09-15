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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// TestThePolicyToPushIsReadAndSaidOutLoud: -push-policy is the operator's half
// of the push (docs/policy-push.md), and what it puts on the console is what
// makes a two-guest transcript a claim — the digest here is the digest on the
// peer's SANDBOX applied line, or the push carried something else.
//
// What is refused here is a document that is not a policy at all. What is not
// refused is a version this build would not itself apply: which versions may be
// applied is the receiving peer's question, and its tunneld answers it.
func TestThePolicyToPushIsReadAndSaidOutLoud(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const version1 = `{"format":"policy","version":1,"n":["one"],"f":["two"],"x":["three"]}`

	for name, path := range map[string]string{
		"absent":            filepath.Join(dir, "nothing-here.json"),
		"not a JSON object": write("list.json", `["policy"]`),
		"another format":    write("other.json", `{"format":"reference-values","version":1}`),
	} {
		if _, err := loadPushPolicy(path, func(string, ...any) {}); err == nil {
			t.Errorf("a %s document was accepted as a policy to push", name)
		}
	}

	// A version this build does not apply is still one a peer may: the push
	// carries it and the peer decides.
	var lines linesf
	if _, err := loadPushPolicy(write("v2.json", `{"format":"policy","version":2}`), lines.logf); err != nil {
		t.Errorf("a version 2 policy was refused by the delegator: %v", err)
	}

	pushed, err := loadPushPolicy(write("v1.json", version1), lines.logf)
	if err != nil {
		t.Fatalf("a version 1 policy was refused: %v", err)
	}
	if string(pushed) != version1 {
		t.Errorf("the bytes to push are %q; want exactly the file", pushed)
	}
	sum := sha256.Sum256([]byte(version1))
	want := fmt.Sprintf("format=policy version=1 bytes=%d sha256=%s", len(version1), hex.EncodeToString(sum[:]))
	if !strings.Contains(lines.String(), want) {
		t.Errorf("the console does not say %q; it says:\n%s", want, lines.String())
	}
	// And no path is no policy and no push, which is what every recorded
	// scenario runs.
	if pushed, err := loadPushPolicy("", lines.logf); pushed != nil || err != nil {
		t.Errorf(`loadPushPolicy("") = %q, %v; want no policy and no error`, pushed, err)
	}
}
