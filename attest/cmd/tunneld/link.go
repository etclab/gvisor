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
	"fmt"
	"net"
)

// link is the guest's network interface and the address to put on it.
//
// This command configures its own link, which is unusual enough to say why.
// The measured image's init mounts the kernel filesystems, loads the report
// interface driver, proves no writable path is executable and runs this binary
// (docs/snp/image/init.rootfs). It does not configure networking, and it
// cannot be asked to: init is inside the launch measurement, so a guest whose
// address was set there would be a different image per address, and the claim
// this whole design rests on is that two guests ran the *same* image. The
// address therefore arrives from outside the measurement like everything else
// that differs between two guests, and something inside has to apply it.
//
// A host that rewrites the address gets a guest that cannot be reached or that
// answers at the wrong place, which is the peer table's failure mode and has
// the same answer: attestation authenticates and naming does not.
type link struct {
	// Interface is the kernel's name for it. "eth0" in the measured image,
	// which runs no udev and so gets the kernel's own names.
	Interface string `json:"interface"`

	// Address is the IPv4 address to set, in dotted quad.
	Address string `json:"address"`

	// PrefixLength is the network's prefix length. In a ticket-14 run every
	// guest sits on one subnet with no gateway and no resolver, which is what
	// makes egress to the vendor structurally impossible rather than merely
	// blocked.
	PrefixLength int `json:"prefix_length"`

	// Gateway, if set, is the IPv4 address a default route is added through.
	// It is what a guest dialing a peer off its own segment needs — the cloud
	// run, where the peer is behind QEMU's user-mode NAT and a real network —
	// and it is what a ticket-14 guest must not have, because a guest with a
	// route off its segment has a path to the vendor and "no egress" stops
	// being a property of the wiring. Leave it out and no route is added; the
	// guest can reach its own subnet and nothing else. It must be on that
	// subnet: a gateway the guest cannot reach on-link is a route the kernel
	// refuses, and it is refused here first, with a sentence rather than
	// ENETUNREACH.
	Gateway string `json:"gateway"`
}

func (l *link) validate() error {
	if l.Interface == "" {
		return fmt.Errorf("no interface")
	}
	if l.ip() == nil {
		return fmt.Errorf("address %q is not an IPv4 address", l.Address)
	}
	if l.PrefixLength < 1 || l.PrefixLength > 32 {
		return fmt.Errorf("prefix_length %d is not between 1 and 32", l.PrefixLength)
	}
	if l.Gateway != "" {
		gw := l.gatewayIP()
		if gw == nil {
			return fmt.Errorf("gateway %q is not an IPv4 address", l.Gateway)
		}
		subnet := net.IPNet{IP: l.ip().Mask(net.IPMask(l.mask())), Mask: net.IPMask(l.mask())}
		if !subnet.Contains(gw) {
			return fmt.Errorf("gateway %s is not on %s, so no route could reach it", gw, subnet.String())
		}
		if gw.Equal(l.ip()) {
			return fmt.Errorf("gateway %s is this guest's own address", gw)
		}
	}
	return nil
}

func (l *link) gatewayIP() net.IP {
	ip := net.ParseIP(l.Gateway)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func (l *link) ip() net.IP {
	ip := net.ParseIP(l.Address)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func (l *link) mask() net.IP {
	return net.IP(net.CIDRMask(l.PrefixLength, 32))
}
