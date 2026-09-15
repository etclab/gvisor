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
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest/tunnel"
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
	if got, clamped := cfg.limits(); got.IdleTimeout != time.Minute || got.MaxAge != 15*time.Minute || clamped != "" {
		t.Errorf("limits %v (clamped: %q); want 60s idle and 15m of age, unclamped", got, clamped)
	}
	// An unstated limit is the transport's default, and the console has to say
	// so: a guest whose peer advertises a smaller idle timeout runs on that
	// one, and the number it printed is where anybody would look for it.
	bare, err := loadRunConfig(write(t, "tunneld.json",
		`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a"}`))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if got, _ := bare.limits(); got.IdleTimeout != tunnel.DefaultIdleTimeout || got.MaxAge != tunnel.DefaultMaxAge {
		t.Errorf("limits %v with none configured; want the transport's defaults, stated rather than zero", got)
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
		{"a listen port the compiled-in egress ceiling does not grant",
			`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a", "listen": "10.14.0.2:5555"}`},
		{"a listen address that is not host:port",
			`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a", "listen": "10.14.0.2"}`},
	} {
		if _, err := loadRunConfig(write(t, "tunneld.json", c.document)); err == nil {
			t.Errorf("loaded a configuration with %s; want a refusal", c.name)
		}
	}
}

// The tunnel port became an image constant in ticket 22: the egress ceiling is
// compiled in and grants one UDP port, so tunneld.json may agree with it and
// may not choose. A configuration asking for another port is refused at load
// rather than honoured, because a listener the kernel silently drops looks like
// a network fault and is diagnosed as one.
func TestTheListenPortMayOnlyAgreeWithTheCeiling(t *testing.T) {
	document := func(listen string) string {
		return `{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a", "listen": "` + listen + `"}`
	}
	cfg, err := loadRunConfig(write(t, "tunneld.json", document("10.14.0.2:4433")))
	if err != nil {
		t.Fatalf("the ceiling's own port was refused: %v", err)
	}
	if cfg.Listen != "10.14.0.2:4433" {
		t.Errorf("listen %q; want the address the document named", cfg.Listen)
	}
	// A port one away from it, which is the mistake a copied configuration
	// makes and the one that is hardest to read off a console.
	_, err = loadRunConfig(write(t, "tunneld.json", document("10.14.0.2:4434")))
	if err == nil {
		t.Fatal("a listen port the ceiling does not grant was accepted")
	}
	if !strings.Contains(err.Error(), "4433") {
		t.Errorf("the refusal is %q; it has to name the port the ceiling does grant", err)
	}
	// And an address with no port at all is refused here rather than reaching
	// the listener, where it would be a different sentence about a later thing.
	if _, err := loadRunConfig(write(t, "tunneld.json", document("10.14.0.2"))); err == nil {
		t.Error("a listen address with no port was accepted")
	}
	// An absent listen is a dress rehearsal on a workstation and is left alone:
	// package tunneld takes an ephemeral port on loopback for it.
	if _, err := loadRunConfig(write(t, "tunneld.json",
		`{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a"}`)); err != nil {
		t.Errorf("a configuration naming no listen address was refused: %v", err)
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

// The config device is outside the launch measurement and delivered by a host
// this design does not trust, and the maximum age is the only bound on how
// long a verdict about a peer is relied on while traffic still flows. A host
// that could raise it could delete re-attestation without forging anything, so
// the ceiling lives in the measured binary. A shorter one is still honoured:
// the ceiling is a ceiling, not a value.
func TestMaximumAgeIsClampedButMayBeShortened(t *testing.T) {
	document := func(maxAge string) string {
		return `{"format": "gvisor.dev/gvisor/attest/tunneld-run", "version": 1, "sandbox_id": "a",
		         "limits": {"idle_timeout": "600s", "max_age": "` + maxAge + `"}}`
	}
	// A year, which is what a host would write to stop re-attestation ever
	// happening again.
	cfg, err := loadRunConfig(write(t, "tunneld.json", document("8760h")))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	got, clamped := cfg.limits()
	if got.MaxAge != tunnel.DefaultMaxAge {
		t.Errorf("maximum age %s from the config device; want it clamped to %s", got.MaxAge, tunnel.DefaultMaxAge)
	}
	if clamped == "" {
		t.Error("the clamp said nothing; a configuration silently overruled is worse than one refused")
	}
	// The idle timeout is deliberately not clamped: an idle tunnel is still
	// torn down at the maximum age, so a long one buys an attacker nothing.
	if got.IdleTimeout != 10*time.Minute {
		t.Errorf("idle timeout %s; want the configured 600s, which is not clamped", got.IdleTimeout)
	}

	shorter, err := loadRunConfig(write(t, "tunneld.json", document("90s")))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if got, clamped := shorter.limits(); got.MaxAge != 90*time.Second || clamped != "" {
		t.Errorf("maximum age %s (clamped: %q); a shorter one is the operator's to choose", got.MaxAge, clamped)
	}
}
