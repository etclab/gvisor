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

package config

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/runsc/flag"
)

// tunnelConfig builds a Config from the flag set, so that the test goes
// through the same path `runsc run` does — NewFromFlags validates, which is
// what makes this a refusal at the command line and not at boot.
func tunnelConfig(t *testing.T, set map[string]string) (*Config, error) {
	t.Helper()
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(testFlags)
	for name, value := range set {
		if err := testFlags.Lookup(name).Value.Set(value); err != nil {
			t.Fatalf("setting --%s=%s: %v", name, value, err)
		}
	}
	return NewFromFlags(testFlags)
}

func TestTunnelFlagsValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  map[string]string
		want string // a substring of the error, or "" for a config that validates
	}{
		{
			name: "neither, which is every sandbox that came before",
			set:  map[string]string{"network": "none"},
		},
		{
			name: "both, with --network=none",
			set:  map[string]string{"network": "none", "tunnel-socket": "/run/t.sock", "tunnel-table": "/run/table.json"},
		},
		{
			name: "the socket without the table",
			set:  map[string]string{"network": "none", "tunnel-socket": "/run/t.sock"},
			want: "must be given together",
		},
		{
			name: "the table without the socket",
			set:  map[string]string{"network": "none", "tunnel-table": "/run/table.json"},
			want: "must be given together",
		},
		{
			name: "both, with sandbox networking",
			set:  map[string]string{"network": "sandbox", "tunnel-socket": "/run/t.sock", "tunnel-table": "/run/table.json"},
			want: "require --network=none",
		},
		{
			name: "both, with host networking",
			set:  map[string]string{"network": "host", "tunnel-socket": "/run/t.sock", "tunnel-table": "/run/table.json"},
			want: "require --network=none",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tunnelConfig(t, tc.set)
			if err == nil {
				err = c.Validate()
			}
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("the flags were refused with %v, wanted them accepted", err)
			case tc.want == "":
			case err == nil:
				t.Fatalf("the flags were accepted, wanted a refusal mentioning %q", tc.want)
			case !strings.Contains(err.Error(), tc.want):
				t.Fatalf("the flags were refused with %v, wanted a refusal mentioning %q", err, tc.want)
			}
		})
	}
}

func TestTunnelFlagsRoundTrip(t *testing.T) {
	c, err := tunnelConfig(t, map[string]string{
		"network":       "none",
		"tunnel-socket": "/run/t.sock",
		"tunnel-table":  "/run/table.json",
	})
	if err != nil {
		t.Fatalf("NewFromFlags: %v", err)
	}
	var socket, table bool
	for _, f := range c.ToFlags() {
		switch f {
		case "--tunnel-socket=/run/t.sock":
			socket = true
		case "--tunnel-table=/run/table.json":
			table = true
		}
	}
	if !socket || !table {
		t.Errorf("ToFlags() = %v, wanted it to carry both tunnel flags to the sandbox's children", c.ToFlags())
	}
}
