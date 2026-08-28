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
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// configure sets the address, sets the netmask, and brings the interface up:
// the three ioctls ifconfig(8) would issue, on a guest that has no ifconfig.
// With a gateway configured it adds a fourth, the SIOCADDRT route(8) would
// issue for a default route; without one there is no route but the on-link
// one the kernel adds with the address, and a guest with no default route
// cannot reach anything off its segment. The route goes last, because the
// kernel will not add a route through a gateway it has no on-link route to
// yet, and that route appears only once the interface is up.
func (l *link) configure() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("opening a socket to configure with: %w", err)
	}
	defer syscall.Close(fd)

	if err := l.ioctlAddr(fd, syscall.SIOCSIFADDR, l.ip()); err != nil {
		return fmt.Errorf("setting the address: %w", err)
	}
	if err := l.ioctlAddr(fd, syscall.SIOCSIFNETMASK, l.mask()); err != nil {
		return fmt.Errorf("setting the netmask: %w", err)
	}
	flags, err := l.flags(fd)
	if err != nil {
		return fmt.Errorf("reading the flags: %w", err)
	}
	if err := l.setFlags(fd, flags|syscall.IFF_UP|syscall.IFF_RUNNING); err != nil {
		return fmt.Errorf("bringing it up: %w", err)
	}
	if l.Gateway != "" {
		if err := l.addDefaultRoute(fd); err != nil {
			return fmt.Errorf("adding the default route via %s: %w", l.Gateway, err)
		}
	}
	return nil
}

// rtentry is the kernel's struct rtentry (linux/route.h), the argument to
// SIOCADDRT. The sockaddr members are opaque here for the same reason ifreq's
// union is: three of them are written and each holds a sockaddr_in. Go's
// alignment rules produce the same layout as the C compiler's on the one
// architecture this runs on, and rtentrySize is asserted against it below
// rather than trusted.
type rtentry struct {
	pad1    uint64
	dst     [16]byte
	gateway [16]byte
	genmask [16]byte
	flags   uint16
	pad2    int16
	pad3    uint64
	pad4    uintptr
	metric  int16
	dev     uintptr
	mtu     uint64
	window  uint64
	irtt    uint16
}

const (
	rtentrySize = 120 // sizeof(struct rtentry) on x86-64
	rtfUp       = 0x0001
	rtfGateway  = 0x0002
)

// addDefaultRoute adds 0.0.0.0/0 via the gateway: dst and genmask both zero,
// RTF_UP|RTF_GATEWAY, no device named, so the kernel picks the interface it
// already reaches the gateway on, which is the one just brought up.
func (l *link) addDefaultRoute(fd int) error {
	var r rtentry
	if unsafe.Sizeof(r) != rtentrySize {
		return fmt.Errorf("struct rtentry is %d bytes here, not %d; this architecture's layout was not accounted for", unsafe.Sizeof(r), rtentrySize)
	}
	sockaddrIn := func(into []byte, ip net.IP) {
		binary.NativeEndian.PutUint16(into[0:2], uint16(syscall.AF_INET))
		if ip != nil {
			copy(into[4:8], ip.To4())
		}
	}
	sockaddrIn(r.dst[:], nil)
	sockaddrIn(r.genmask[:], nil)
	sockaddrIn(r.gateway[:], l.gatewayIP())
	r.flags = rtfUp | rtfGateway
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCADDRT, uintptr(unsafe.Pointer(&r))); errno != 0 {
		return errno
	}
	return nil
}

// ifreq is the kernel's struct ifreq: a name and a union. The union is written
// here as opaque bytes because this file only ever puts two things in it — a
// sockaddr_in and a flags word — and naming the other forty members would be
// describing an interface this command does not use.
type ifreq struct {
	name  [syscall.IFNAMSIZ]byte
	union [24]byte
}

func (l *link) request() (*ifreq, error) {
	if len(l.Interface) >= syscall.IFNAMSIZ {
		return nil, fmt.Errorf("interface name %q is too long", l.Interface)
	}
	var r ifreq
	copy(r.name[:], l.Interface)
	return &r, nil
}

func (l *link) ioctlAddr(fd int, request uintptr, ip net.IP) error {
	r, err := l.request()
	if err != nil {
		return err
	}
	// struct sockaddr_in: family in native order, port, then the address.
	binary.NativeEndian.PutUint16(r.union[0:2], uint16(syscall.AF_INET))
	copy(r.union[4:8], ip.To4())
	return ioctl(fd, request, r)
}

func (l *link) flags(fd int) (uint16, error) {
	r, err := l.request()
	if err != nil {
		return 0, err
	}
	if err := ioctl(fd, syscall.SIOCGIFFLAGS, r); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint16(r.union[0:2]), nil
}

func (l *link) setFlags(fd int, flags uint16) error {
	r, err := l.request()
	if err != nil {
		return err
	}
	binary.NativeEndian.PutUint16(r.union[0:2], flags)
	return ioctl(fd, syscall.SIOCSIFFLAGS, r)
}

func ioctl(fd int, request uintptr, r *ifreq) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(r))); errno != 0 {
		return errno
	}
	return nil
}
