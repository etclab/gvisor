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
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The run configuration is the one document on the config device that this
// command defines, and a guest gets exactly one chance to read it: the image
// has no shell, so a file this command misreads is a boot that ends in a
// console line and a power-off. These are cheap enough to keep the format
// honest and they double as the format's only worked example.

func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const goodRun = `{
  "format": "gvisor.dev/gvisor/attest/tunneld-run",
  "version": 1,
  "sandbox_id": "guest-a",
  "listen": "10.14.0.2:4433",
  "link": {"interface": "eth0", "address": "10.14.0.2", "prefix_length": 24},
  "limits": {"idle_timeout": "60s", "max_age": "15m"},
  "exercise": {"dial": ["guest-b"], "wait": "90s", "payload": "marker", "exchanges": 4, "concurrency": 2, "rounds": 1},
  "hold": "30s"
}`

func TestRunConfigLoads(t *testing.T) {
	cfg, err := loadRunConfig(write(t, "tunneld.json", goodRun))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.SandboxID != "guest-a" || cfg.Listen != "10.14.0.2:4433" {
		t.Errorf("sandbox %q listening on %q; want guest-a on 10.14.0.2:4433", cfg.SandboxID, cfg.Listen)
	}
	if got := cfg.limits(); got.IdleTimeout != time.Minute || got.MaxAge != 15*time.Minute {
		t.Errorf("limits %v; want 60s idle and 15m of age", got)
	}
	if cfg.Link == nil || cfg.Link.Interface != "eth0" || cfg.Link.PrefixLength != 24 {
		t.Errorf("link %+v; want eth0 at /24", cfg.Link)
	}
	if cfg.Exercise == nil || len(cfg.Exercise.Dial) != 1 || cfg.Exercise.Dial[0] != "guest-b" {
		t.Errorf("exercise %+v; want one peer, guest-b", cfg.Exercise)
	}
	if cfg.Hold.Duration != 30*time.Second {
		t.Errorf("hold %s; want 30s", cfg.Hold.Duration)
	}
}

func TestRunConfigRefusals(t *testing.T) {
	for _, c := range []struct{ name, document string }{
		{"an unknown field, which is a run that did something other than what was written down",
			`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a", "exercises": 4}`},
		{"a document written for something else",
			`{"format": "some-other-thing", "version": 1, "sandbox_id": "a"}`},
		{"a version this command does not read",
			`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 2, "sandbox_id": "a"}`},
		{"no sandbox identifier, which is a tunneld with no identity to be",
			`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1}`},
		{"a link with no address",
			`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a", "link": {"interface": "eth0"}}`},
		{"an exercise with nobody to dial",
			`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a", "exercise": {"exchanges": 4}}`},
		{"a duration written as a number",
			`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a", "hold": 30}`},
	} {
		if _, err := loadRunConfig(write(t, "tunneld.json", c.document)); err == nil {
			t.Errorf("loaded a configuration with %s; want a refusal", c.name)
		}
	}
}

func TestPeerTableLoads(t *testing.T) {
	table, err := loadPeerTable(write(t, "peers.json", `{"peers": {"guest-b": "10.14.0.3:4433"}}`))
	if err != nil || table["guest-b"] != "10.14.0.3:4433" {
		t.Fatalf("loaded %v, %v; want guest-b at 10.14.0.3:4433", table, err)
	}
	// The shape ticket 08's harness already wrote onto a config device, before
	// this command existed: no format line, no peers.
	empty, err := loadPeerTable(write(t, "peers.json", `{"peers":{}}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("loaded %v, %v; want an empty table and no error", empty, err)
	}
	if _, err := loadPeerTable(write(t, "peers.json", `{"peer": {"a": "b"}}`)); err == nil {
		t.Error("loaded a peer table whose field is misspelt; want a refusal")
	}
}
