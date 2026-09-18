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

package netstack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// installTestAdapter publishes a test adapter as the installed one and takes it
// back down again afterwards. There is no stack and no responder: NarrowTunnel
// touches neither.
func installTestAdapter(t *testing.T, text string) *adapter {
	t.Helper()
	a := testAdapter(t, text)
	tunnelMu.Lock()
	if tunnel != nil {
		tunnelMu.Unlock()
		t.Fatalf("a tunnel adapter is already installed")
	}
	tunnel = a
	tunnelMu.Unlock()
	t.Cleanup(func() {
		tunnelMu.Lock()
		tunnel = nil
		tunnelMu.Unlock()
	})
	return a
}

const threeNames = `{"default_exit":"b","names":{
	"api.anthropic.com":{"port":443},
	"web.peer-a":{"port":8080},
	"www.rfc-editor.org":{"port":443}}}`

// TestNarrowTunnelKeepsTheAddressesOfSurvivingNames is the property the whole
// design rests on: a workload that resolved a name before a narrowing and
// connects to it after one must reach the same place. If addresses were
// reallocated, a surviving name would silently become a different destination.
func TestNarrowTunnelKeepsTheAddressesOfSurvivingNames(t *testing.T) {
	before := installTestAdapter(t, threeNames)
	was := map[string]tcpip.Address{}
	for name, b := range before.byName {
		was[name] = b.addr
	}
	table, err := NarrowTunnel(map[string]bool{"api.anthropic.com": true, "www.rfc-editor.org": true})
	if err != nil {
		t.Fatalf("NarrowTunnel: %v", err)
	}
	after := currentTunnel()
	if after == before {
		t.Fatalf("NarrowTunnel edited the adapter in place; it must replace it")
	}
	for _, name := range []string{"api.anthropic.com", "www.rfc-editor.org"} {
		b, ok := after.lookupName(name)
		if !ok {
			t.Fatalf("%s did not survive the narrowing", name)
		}
		if b.addr != was[name] {
			t.Errorf("%s moved from %s to %s", name, was[name].String(), b.addr.String())
		}
		if _, ok := after.lookupAddr(b.addr); !ok {
			t.Errorf("%s is in byName at %s and not in byAddr", name, b.addr.String())
		}
	}
	if _, ok := table.Names["www.rfc-editor.org"]; !ok {
		t.Errorf("the table NarrowTunnel returned does not carry www.rfc-editor.org")
	}
	if got, want := len(table.Names), 2; got != want {
		t.Errorf("the table NarrowTunnel returned has %d names, wanted %d", got, want)
	}
	if got, want := table.DefaultExit, "b"; got != want {
		t.Errorf("the default exit became %q, wanted %q", got, want)
	}
}

// TestNarrowTunnelRemovesANameFromBothMaps is the other half: a name that is
// gone must be gone as a name (so the resolver says NXDOMAIN) and gone as an
// address (so a connect to the address it used to have is not in the table).
func TestNarrowTunnelRemovesANameFromBothMaps(t *testing.T) {
	before := installTestAdapter(t, threeNames)
	gone := before.byName["web.peer-a"]
	if gone == nil {
		t.Fatalf("web.peer-a is not in the adapter to begin with")
	}
	if _, err := NarrowTunnel(map[string]bool{"api.anthropic.com": true, "www.rfc-editor.org": true}); err != nil {
		t.Fatalf("NarrowTunnel: %v", err)
	}
	after := currentTunnel()
	if _, ok := after.lookupName("web.peer-a"); ok {
		t.Errorf("web.peer-a still resolves after the narrowing")
	}
	if _, ok := after.lookupAddr(gone.addr); ok {
		t.Errorf("the address %s web.peer-a used to have is still in the table", gone.addr.String())
	}
	if _, ok := after.table.Names["web.peer-a"]; ok {
		t.Errorf("web.peer-a is still in the adapter's table")
	}
}

// TestNarrowTunnelDoesNotRewindTheLocalPorts: the local port is one per
// connection so that no two live sockets agree on both ends. A replaced adapter
// that started its counter again would hand out a port a live socket already
// has.
func TestNarrowTunnelDoesNotRewindTheLocalPorts(t *testing.T) {
	before := installTestAdapter(t, threeNames)
	var last uint16
	for i := 0; i < 5; i++ {
		last = before.nextLocal().Port
	}
	if _, err := NarrowTunnel(map[string]bool{"api.anthropic.com": true}); err != nil {
		t.Fatalf("NarrowTunnel: %v", err)
	}
	after := currentTunnel()
	next := after.nextLocal().Port
	if next <= last {
		t.Errorf("the first local port after a narrowing is %d and the last before it was %d", next, last)
	}
}

// TestNarrowTunnelRefusesANameItDoesNotCarry guards the caller: the subset
// check is runsc/boot's, and this is the second place that would notice a name
// arriving from nowhere.
func TestNarrowTunnelRefusesANameItDoesNotCarry(t *testing.T) {
	installTestAdapter(t, threeNames)
	if _, err := NarrowTunnel(map[string]bool{"example.com": true}); err == nil {
		t.Fatalf("NarrowTunnel kept a name the adapter never carried")
	}
	if got := len(currentTunnel().byName); got != 3 {
		t.Errorf("a refused narrowing changed the adapter: %d names, wanted 3", got)
	}
}

// TestNarrowTunnelToNothing: a policy may name no destination at all, and that
// is a sandbox that can no longer reach anything rather than an error.
func TestNarrowTunnelToNothing(t *testing.T) {
	installTestAdapter(t, threeNames)
	table, err := NarrowTunnel(map[string]bool{})
	if err != nil {
		t.Fatalf("NarrowTunnel: %v", err)
	}
	if got := len(table.Names); got != 0 {
		t.Errorf("the table has %d names, wanted none", got)
	}
	if got := len(currentTunnel().byName); got != 0 {
		t.Errorf("the adapter has %d names, wanted none", got)
	}
}

// TestNarrowTunnelTwiceNarrowsFromWhatIsInForce: a second narrowing works on
// the adapter the first one left, not on the boot table.
func TestNarrowTunnelTwiceNarrowsFromWhatIsInForce(t *testing.T) {
	installTestAdapter(t, threeNames)
	if _, err := NarrowTunnel(map[string]bool{"api.anthropic.com": true, "web.peer-a": true}); err != nil {
		t.Fatalf("the first NarrowTunnel: %v", err)
	}
	if _, err := NarrowTunnel(map[string]bool{"www.rfc-editor.org": true}); err == nil {
		t.Fatalf("the second narrowing kept a name the first one removed")
	}
	if _, err := NarrowTunnel(map[string]bool{"web.peer-a": true}); err != nil {
		t.Fatalf("the second NarrowTunnel: %v", err)
	}
	if got := len(currentTunnel().byName); got != 1 {
		t.Errorf("the adapter has %d names, wanted 1", got)
	}
}

// TestNarrowTunnelWithNoAdapterInstalled: the sentry answers rather than
// crashing when a policy arrives at a sandbox with no tunnel.
func TestNarrowTunnelWithNoAdapterInstalled(t *testing.T) {
	if _, err := NarrowTunnel(map[string]bool{}); err == nil {
		t.Fatalf("NarrowTunnel succeeded with no adapter installed")
	}
}
