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

package tsm

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"

	"gvisor.dev/gvisor/attest"
)

// A stand-in for the kernel, so that the acquisition sequence can be driven
// with no confidential VM.
//
// Every other package in this module is tested through its public surface,
// with the substitution happening at the vendor seam. This one cannot be:
// what sits below it is not a vendor but the kernel, and the only way to stand
// in for the kernel offline is at the boundary this package talks to it
// across. That boundary stays unexported — nothing outside these tests has any
// business substituting the kernel — and the fake is declared here, in a file
// that is only compiled into the test binary, so that the tests themselves
// stay in gvisor.dev/gvisor/attest/tsm_test and drive [Acquirer] and nothing
// else.
//
// What the fake models is the ABI, not the hardware: attributes that generate
// their contents on read, a generation counter that advances on every write
// (Documentation/ABI/testing/configfs-tsm), an inblob that takes exactly the
// caller-supplied field's width, and an auxblob that is empty. The bytes it
// answers outblob with come from whatever the test supplies — the fake SEV-SNP
// platform in gvisor.dev/gvisor/attest/snpfake, or the report ticket 01 read
// out of real silicon.

// A FakeReportInterface is the kernel's report interface, faked. See the
// comment above.
type FakeReportInterface struct {
	// Provider is what the provider attribute reads.
	Provider string

	// Evidence answers a request. It is handed exactly the bytes that were
	// written to inblob.
	Evidence func(callerSupplied []byte) ([]byte, error)

	// CertificateTable is what auxblob reads. Empty is what this host's
	// platform returns and what the tests expect.
	CertificateTable []byte

	// CertificateTableErr, if set, is what reading auxblob fails with — a
	// kernel that does not expose the attribute at all.
	CertificateTableErr error

	// RacingWriter makes another writer advance the generation counter
	// between this acquisition's write and its read.
	RacingWriter bool

	// Taken are request names that already exist, so that the name a fresh
	// acquisition picks can be made to collide.
	Taken map[string]bool

	// Opened and Removed record the request names created and removed.
	Opened  []string
	Removed []string

	// Writes records every write made to a request, in order. One write of
	// the caller-supplied field's width to inblob is the whole of a correct
	// acquisition.
	Writes []FakeWrite
}

// A FakeWrite is one write to one attribute.
type FakeWrite struct {
	Attr string
	Data []byte
}

// NewOnFake builds an [Acquirer] that drives f instead of configfs.
func NewOnFake(opts Options, f *FakeReportInterface) (*Acquirer, error) {
	if err := opts.prepare(); err != nil {
		return nil, err
	}
	return newOn(opts, f)
}

func (f *FakeReportInterface) open(name string) (request, error) {
	if f.Taken[name] {
		return nil, fmt.Errorf("fake: %s: %w", name, fs.ErrExist)
	}
	if f.Taken == nil {
		f.Taken = map[string]bool{}
	}
	f.Taken[name] = true
	f.Opened = append(f.Opened, name)
	return &fakeRequest{iface: f, name: name}, nil
}

type fakeRequest struct {
	iface      *FakeReportInterface
	name       string
	generation uint64
	inblob     []byte
}

func (r *fakeRequest) read(attr string) ([]byte, error) {
	switch attr {
	case attrProvider:
		return []byte(r.iface.Provider + "\n"), nil
	case attrGeneration:
		return []byte(strconv.FormatUint(r.generation, 10) + "\n"), nil
	case attrOutblob:
		if r.inblob == nil {
			return nil, errors.New("fake: outblob read before inblob was written")
		}
		if r.iface.RacingWriter {
			r.generation++
		}
		return r.iface.Evidence(r.inblob)
	case attrAuxblob:
		if r.iface.CertificateTableErr != nil {
			return nil, r.iface.CertificateTableErr
		}
		return append([]byte(nil), r.iface.CertificateTable...), nil
	}
	return nil, fmt.Errorf("fake: %s: %w", attr, fs.ErrNotExist)
}

func (r *fakeRequest) write(attr string, data []byte) error {
	r.iface.Writes = append(r.iface.Writes, FakeWrite{Attr: attr, Data: append([]byte(nil), data...)})
	r.generation++
	if attr != attrInblob {
		return nil
	}
	if len(data) != attest.CallerSuppliedBytesSize {
		return fmt.Errorf("fake: inblob took %d bytes, not the field's %d; a partial write is a different request", len(data), attest.CallerSuppliedBytesSize)
	}
	r.inblob = append([]byte(nil), data...)
	return nil
}

func (r *fakeRequest) close() error {
	delete(r.iface.Taken, r.name)
	r.iface.Removed = append(r.iface.Removed, r.name)
	return nil
}
