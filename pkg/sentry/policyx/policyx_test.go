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

package policyx

import (
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// seccheckFields is the empty field set: these tests exercise the decision and
// not what a sink records about it.
func seccheckFields() seccheck.FieldSet { return seccheck.FieldSet{} }

func TestAllowPermits(t *testing.T) {
	const good = "8b6a1f6ef1e5d1d6a2b0b1b25a5d2a63a3d0a7b52b9f5ee6a0c3e7d9f1a2b3c4"
	for _, tc := range []struct {
		name    string
		allow   *Allow
		path    string
		digest  string
		permits bool
	}{
		{
			name:    "no x in force permits everything",
			allow:   nil,
			path:    "/bin/busybox",
			permits: true,
		},
		{
			name:    "an empty x permits nothing",
			allow:   NewAllow(nil, nil),
			path:    "/bin/busybox",
			permits: false,
		},
		{
			name:    "a path that is named",
			allow:   NewAllow([]string{"/bin/busybox"}, nil),
			path:    "/bin/busybox",
			permits: true,
		},
		{
			name:    "a path that is not named",
			allow:   NewAllow([]string{"/bin/busybox"}, nil),
			path:    "/bin/sh",
			permits: false,
		},
		{
			name:    "a digest that is named, under any path",
			allow:   NewAllow(nil, []string{good}),
			path:    "/tmp/copied-here",
			digest:  good,
			permits: true,
		},
		{
			name:    "a digest given in upper case is the same digest",
			allow:   NewAllow(nil, []string{"8B6A1F6EF1E5D1D6A2B0B1B25A5D2A63A3D0A7B52B9F5EE6A0C3E7D9F1A2B3C4"}),
			digest:  good,
			path:    "/tmp/copied-here",
			permits: true,
		},
		{
			name:    "no digest at all never matches a digest entry",
			allow:   NewAllow(nil, []string{good}),
			path:    "/bin/busybox",
			digest:  "",
			permits: false,
		},
		{
			name:    "either half is enough",
			allow:   NewAllow([]string{"/bin/sh"}, []string{good}),
			path:    "/bin/sh",
			digest:  "0000000000000000000000000000000000000000000000000000000000000000",
			permits: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.allow.Permits(tc.path, tc.digest); got != tc.permits {
				t.Errorf("Permits(%q, %q) = %v, wanted %v", tc.path, tc.digest, got, tc.permits)
			}
		})
	}
}

// TestSinkRefusesWithEACCES is the whole contract between this package and
// pkg/sentry/kernel: the error the sink returns is the errno the execve fails
// with, so it has to be that one and no other.
func TestSinkRefusesWithEACCES(t *testing.T) {
	s := NewSink()
	info := &pb.ExecveInfo{BinaryPath: "/bin/busybox"}
	if err := s.Execve(context.Background(), seccheckFields(), info); err != nil {
		t.Fatalf("before a policy carries an x, exec is unrestricted, got %v", err)
	}
	s.Narrow(NewAllow([]string{"/bin/sh"}, nil))
	if err := s.Execve(context.Background(), seccheckFields(), info); !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Errorf("an exec outside x gave %v, wanted EACCES", err)
	}
	if err := s.Execve(context.Background(), seccheckFields(), &pb.ExecveInfo{BinaryPath: "/bin/sh"}); err != nil {
		t.Errorf("an exec inside x gave %v, wanted nil", err)
	}
	checked, refused := s.Counts()
	if checked != 2 || refused != 1 {
		t.Errorf("counted %d checked and %d refused, wanted 2 and 1", checked, refused)
	}
}

// TestSinkMatchesOnTheHashItIsGiven checks the other half of the identity: the
// digest arrives as raw bytes on the point and is matched as lowercase hex.
func TestSinkMatchesOnTheHashItIsGiven(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	sum := "deadbeef"
	s := NewSink()
	s.Narrow(&Allow{paths: map[string]struct{}{}, digests: map[string]struct{}{sum: {}}})
	if err := s.Execve(context.Background(), seccheckFields(), &pb.ExecveInfo{BinaryPath: "/anything", BinarySha256: raw}); err != nil {
		t.Errorf("a binary whose digest is in x gave %v, wanted nil", err)
	}
	if err := s.Execve(context.Background(), seccheckFields(), &pb.ExecveInfo{BinaryPath: "/anything", BinarySha256: []byte{0x00}}); !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Errorf("a binary whose digest is not in x gave %v, wanted EACCES", err)
	}
}

func TestPrintableScrubsAPathAWorkloadChose(t *testing.T) {
	if got, want := Printable("/bin/\nsh"), "/bin/?sh"; got != want {
		t.Errorf("Printable = %q, wanted %q", got, want)
	}
	long := make([]byte, maxPath+10)
	for i := range long {
		long[i] = 'a'
	}
	if got := Printable(string(long)); len(got) != maxPath {
		t.Errorf("Printable kept %d bytes, wanted %d", len(got), maxPath)
	}
}

func TestAllowListsAreSorted(t *testing.T) {
	a := NewAllow([]string{"/b", "/a"}, []string{"ff", "00"})
	if got, want := a.Paths(), []string{"/a", "/b"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Paths = %v, wanted %v", got, want)
	}
	if got, want := a.Digests(), []string{"00", "ff"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Digests = %v, wanted %v", got, want)
	}
}
