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
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

// The struct handed to SIOCADDRT has to be the kernel's, byte for byte, and
// the only architecture this command is built for is the one the guest runs.
func TestRtentryLayoutMatchesTheKernel(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("struct rtentry is laid out for x86-64; this is %s", runtime.GOARCH)
	}
	var r rtentry
	if got := unsafe.Sizeof(r); got != rtentrySize {
		t.Fatalf("sizeof(rtentry) = %d, want %d", got, rtentrySize)
	}
	for name, o := range map[string][2]uintptr{
		"dst":     {unsafe.Offsetof(r.dst), 8},
		"gateway": {unsafe.Offsetof(r.gateway), 24},
		"genmask": {unsafe.Offsetof(r.genmask), 40},
		"flags":   {unsafe.Offsetof(r.flags), 56},
		"metric":  {unsafe.Offsetof(r.metric), 80},
		"dev":     {unsafe.Offsetof(r.dev), 88},
	} {
		if o[0] != o[1] {
			t.Errorf("offsetof(rtentry.%s) = %d, want %d", name, o[0], o[1])
		}
	}
}

// The four ioctls against a real kernel, in a network namespace of the
// caller's making. It is gated on an environment variable rather than on
// being root, because as root outside a namespace it would put an address on
// the machine's loopback and a default route through it — so it runs only
// when somebody has said, in so many words, that this is a namespace to do
// that in:
//
//	unshare -rn sh -c 'TUNNELD_LINK_TEST=1 go test -run Configure ./cmd/tunneld'
//
// attest/README.md already runs the whole suite under unshare -rn, and this is
// the same invocation with one variable set.
func TestConfigureBringsUpLinkAndDefaultRoute(t *testing.T) {
	if os.Getenv("TUNNELD_LINK_TEST") != "1" {
		t.Skip("set TUNNELD_LINK_TEST=1 inside a network namespace (unshare -rn) to run this")
	}
	l := &link{Interface: "lo", Address: "10.213.0.15", PrefixLength: 24, Gateway: "10.213.0.2"}
	if err := l.validate(); err != nil {
		t.Fatal(err)
	}
	if err := l.configure(); err != nil {
		t.Fatalf("configure: %v", err)
	}
	// Read the routing table back from the kernel rather than trusting the
	// ioctl's silence: /proc/net/route is destination, gateway and mask in
	// little-endian hex, and a default route via 10.213.0.2 is the line with a
	// zero destination and 0200D50A as its gateway.
	table, err := os.ReadFile("/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, line := range strings.Split(string(table), "\n") {
		f := strings.Fields(line)
		if len(f) > 7 && f[0] == "lo" && f[1] == "00000000" && strings.EqualFold(f[2], "0200D50A") && f[7] == "00000000" {
			found = true
		}
	}
	if !found {
		t.Errorf("no default route via 10.213.0.2 on lo in /proc/net/route:\n%s", table)
	}
	// It prints as "scope link" on lo and would print without a scope on a
	// real interface: the kernel files a loopback's subnet as local, so a
	// gateway on it is not a unicast address and the route is scoped to the
	// link. That is an artefact of the only interface a namespace has for
	// free, not of the ioctl.
	if out, err := exec.Command("ip", "route").CombinedOutput(); err == nil {
		t.Logf("ip route:\n%s", out)
	}
}
