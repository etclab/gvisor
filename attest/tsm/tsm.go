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

// Package tsm acquires evidence from the confidential platform this process is
// running on, through the kernel's vendor-neutral report interface. It is the
// producer half of the vendor seam, and the implementation of
// [attest.Acquirer] that talks to real hardware.
//
// # The interface is the kernel's, not this design's
//
// Linux exposes every confidential-computing platform's report interface the
// same way, at /sys/kernel/config/tsm/report: create a directory, write the
// caller-supplied bytes to inblob in one write, read the evidence back from
// outblob, remove the directory. The same four steps yield an SEV-SNP report
// on AMD and TDX evidence on Intel. Only the bytes that come back are the
// vendor's, which is why this package is named for the interface rather than
// for AMD.
//
// Three things here are vendor-specific and all three stay behind
// [attest.Acquirer]: the provider name the kernel reports for each platform's
// guest driver, the knowledge of what the bytes that come back are, and
// reading the caller-supplied field back out of them to confirm the platform
// returned what it was handed. Nothing above this package learns what a report
// is.
//
// # The certificate chain does not come from the platform
//
// The report interface exposes auxblob, which is where a host that provisioned
// a certificate chain would put it. On this host it is empty and no operator
// action fills it: upstream KVM ships a stub that always returns an empty
// certificate table, and neither a newer kernel nor a newer hypervisor changes
// that (docs/snp-host-stack.md). auxblob is therefore read on every
// acquisition and its size recorded in an [Observation] — an empty table is
// the expected state on this platform and is not an error — and the chain that
// is actually bundled with the evidence comes from the config device, through
// gvisor.dev/gvisor/attest/provision (ADR-0005).
//
// Nothing here fetches. A chain that is missing, that does not describe
// itself, or that was issued for a TCB this platform has since moved off is a
// refusal to acquire, not a reason to reach AMD's key distribution service: a
// silent fallback would reinstate exactly the dependency ADR-0005 removes, and
// would do it invisibly.
//
// All of that is AMD's half. On Intel TDX there is no chain to bundle: a
// version-4 quote carries the PCK certificate chain that roots it inside its
// own signed data, so [attest.Evidence.Chain] stays empty and a verifier reads
// the chain out of the quote instead (attest/verify/tdx.go). The chain step is
// the one place this package's sequence differs by vendor, and the certificate
// directory is required only of the vendor that has something to read from it.
package tsm

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/go-sev-guest/abi"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/provision"
)

// DefaultReportDir is where Linux exposes the report interface. A guest with
// no directory here is not a confidential guest, or has neither configfs
// mounted nor its platform's guest driver loaded.
const DefaultReportDir = "/sys/kernel/config/tsm/report"

// The attribute names. Every one of them is the kernel's ABI
// (Documentation/ABI/testing/configfs-tsm), not this package's invention.
const (
	attrProvider       = "provider"
	attrGeneration     = "generation"
	attrInblob         = "inblob"
	attrOutblob        = "outblob"
	attrAuxblob        = "auxblob"
	attrPrivlevelFloor = "privlevel_floor"
)

// The provider names the kernel reports for the guest drivers this acquirer
// implements; see [vendorOf]. Each driver names its tsm_ops after its own
// module — drivers/virt/coco/sev-guest/sev-guest.c and
// drivers/virt/coco/tdx-guest/tdx-guest.c both set .name = KBUILD_MODNAME — so
// the attribute reads with the module's underscore and not the directory's
// dash. Every TDX quote recorded under docs/snp/evidence/tdx was read from a
// request whose provider said "tdx_guest".
const (
	providerSEVGuest = "sev_guest"
	providerTDXGuest = "tdx_guest"
)

// Options configures an [Acquirer].
type Options struct {
	// ChainDir is the directory on the config device holding the certificate
	// chain provisioned for this platform — certificate-chain.bin and
	// certificate-chain.json, written by cmd/provision-chain (ADR-0005). It is
	// required on AMD SEV-SNP: an acquirer with nowhere to read a chain from
	// could only fail at its first acquisition or fetch one, and neither is
	// acceptable. On Intel TDX it is unused and may be empty, because the
	// quote carries its own chain and there is nothing to provision.
	//
	// Which of those applies is not the caller's to declare. [New] probes the
	// platform first and asks for a chain directory only if the vendor that
	// answered needs one, so the requirement still lands at startup.
	ChainDir string

	// ReportDir is the kernel's report interface. Empty means
	// [DefaultReportDir]; a test or an unusual mount point may name another.
	ReportDir string

	// RequestName is the prefix of the request directory each acquisition
	// creates under ReportDir. Empty means "tunneld". The process identifier
	// and a counter are appended, because two acquisitions must never share a
	// request: the second one's inblob would be the first one's evidence.
	RequestName string
}

// An Observation is what the platform's report interface said the last time
// evidence was acquired. It exists so that the two facts an operator needs
// about this platform — that the report interface answered, and that its
// certificate table is empty — are recorded rather than inferred, and so that
// the empty table is visible as an expected state rather than as silence.
//
// It is not part of [attest.Acquirer]: a verifier learns nothing from it and
// nothing above the seam reads it. It is for the log.
type Observation struct {
	// Provider is the platform driver the kernel named, verbatim.
	Provider string

	// Vendor is the hardware that provider speaks for.
	Vendor attest.Vendor

	// EvidenceBytes is the size of the evidence read back from outblob. 1184
	// for an SEV-SNP report on this host.
	EvidenceBytes int

	// Writes is how many writes the kernel counted against this request while
	// it was acquiring: the generation counter's advance. One is the whole
	// story — the caller-supplied bytes, in a single write.
	Writes uint64

	// CertificateTableBytes is the size of auxblob, the platform's own
	// certificate table. Zero on this host and on every host running upstream
	// KVM, which is the expected state and not a failure.
	CertificateTableBytes int

	// CertificateTableError is why auxblob could not be read at all, if it
	// could not. A kernel that does not expose the attribute is the same kind
	// of fact as a kernel that exposes an empty one: recorded, and not a
	// reason to refuse, because nothing here would have used it.
	CertificateTableError string

	// ChainDir, ChainBytes, ChainChipID and ChainTCB describe the provisioned
	// chain that was bundled with the evidence. They stay empty on Intel TDX,
	// where nothing is bundled because the quote carries its own chain.
	ChainDir    string
	ChainBytes  int
	ChainChipID string
	ChainTCB    attest.TCB
}

// String is the line an operator reads. It says the certificate table was
// empty out loud, because a reader who does not already know ADR-0005 will
// otherwise go looking for the chain the platform was supposed to supply.
func (o Observation) String() string {
	table := fmt.Sprintf("its own certificate table is empty (auxblob, %d bytes)", o.CertificateTableBytes)
	if o.CertificateTableError != "" {
		table = fmt.Sprintf("its own certificate table could not be read (auxblob: %s)", o.CertificateTableError)
	}
	chain := fmt.Sprintf("bundled the %d-byte chain provisioned in %s for chip %s at %s (ADR-0005)",
		o.ChainBytes, o.ChainDir, abbreviate(o.ChainChipID), tcbString(o.ChainTCB))
	if o.Vendor == attest.VendorIntelTDX {
		chain = "bundled no certificate chain, because the quote carries the one that roots it"
	}
	return fmt.Sprintf("tsm: provider %q (%s) returned %d bytes of evidence over %d write(s); %s, "+
		"which is the expected state on this host and not an error; %s",
		o.Provider, o.Vendor, o.EvidenceBytes, o.Writes, table, chain)
}

// An Acquirer obtains evidence from this platform. It implements
// [attest.Acquirer]; construct one with [New].
type Acquirer struct {
	opts   Options
	iface  reportInterface
	vendor attest.Vendor

	mu   sync.Mutex
	seq  uint64
	last *Observation
}

var _ attest.Acquirer = (*Acquirer)(nil)

// New builds an acquirer for this platform, and refuses to build one where
// evidence could not be acquired.
//
// It probes the report interface: it creates a request, reads which platform
// driver is behind it, maps that to a vendor and removes the request again. A
// guest with no report interface, or one whose driver this acquirer does not
// implement, fails here rather than at the first handshake — a tunneld that
// cannot produce evidence has nothing to offer a peer and should not start.
func New(opts Options) (*Acquirer, error) {
	if err := opts.prepare(); err != nil {
		return nil, err
	}
	return newOn(opts, configfs{root: opts.ReportDir})
}

// prepare fills in the defaults. The one option with no default — ChainDir —
// is checked in [newOn] instead, once the platform has said which vendor it is
// and therefore whether a chain is wanted at all.
func (o *Options) prepare() error {
	if o.ReportDir == "" {
		o.ReportDir = DefaultReportDir
	}
	if o.RequestName == "" {
		o.RequestName = "tunneld"
	}
	return nil
}

// newOn is [New] against a given report interface. The interface is a seam one
// layer below the vendor seam — it stands for the kernel, not for a vendor —
// and it is unexported because nothing outside this package's own tests has
// any business substituting the kernel.
func newOn(opts Options, iface reportInterface) (*Acquirer, error) {
	a := &Acquirer{opts: opts, iface: iface}
	req, name, err := a.open()
	if err != nil {
		return nil, err
	}
	provider, err := readProvider(req, name)
	if err != nil {
		req.close()
		return nil, err
	}
	if err := closeRequest(req, name); err != nil {
		return nil, err
	}
	vendor, err := vendorOf(provider)
	if err != nil {
		return nil, err
	}
	if vendor == attest.VendorAMDSEVSNP && opts.ChainDir == "" {
		return nil, errors.New("tsm: no certificate chain directory: evidence is bundled with the chain provisioned on the config device and this acquirer never fetches one (ADR-0005)")
	}
	a.vendor = vendor
	return a, nil
}

// closeRequest removes a request directory and says so if it could not. A
// request left behind is not a wrong answer — every acquisition creates its
// own — but it is a configfs entry this acquirer will never reclaim, and only
// sixteen names are tried before it refuses outright, so a leak is an error
// rather than a shrug.
func closeRequest(req request, name string) error {
	if err := req.close(); err != nil {
		return fmt.Errorf("tsm: removing the request %s after use: %w", name, err)
	}
	return nil
}

// Vendor implements [attest.Acquirer]. It is the vendor whose driver answered
// when this acquirer was built.
func (a *Acquirer) Vendor() attest.Vendor { return a.vendor }

// LastObservation returns what the report interface said on the most recent
// successful acquisition, and whether there has been one.
func (a *Acquirer) LastObservation() (Observation, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil {
		return Observation{}, false
	}
	return *a.last, true
}

// Acquire implements [attest.Acquirer]: it hands the platform the
// caller-supplied bytes, reads the evidence back, and bundles it with the
// certificate chain provisioned for this platform.
//
// The caller-supplied bytes are written verbatim and in a single write. They
// are not computed here and not checked here: they are whatever
// [attest.Binding.CallerSuppliedBytes] produced, which is what makes producer
// and consumer agree on ADR-0002's binding by construction. This package's
// only interest in them is that the platform gave them back — a report over
// bytes other than the ones it was handed binds nothing, and a peer would
// refuse it for a reason that points at the peer rather than at this host.
//
// The sequence is the kernel's, in the kernel's order:
//
//  1. Create a request directory of this acquirer's own, so that no other
//     process's inblob can become this acquisition's report.
//  2. Read the provider, and refuse a platform whose evidence format this
//     acquirer would only be guessing at.
//  3. Write the caller-supplied bytes to inblob, once, whole.
//  4. Read outblob, which is where the platform's answer appears.
//  5. Read auxblob, which is empty here, and record that.
//  6. Confirm the generation counter advanced by exactly the one write this
//     acquisition made, so that a racing writer is detected rather than
//     silently answered.
//  7. On AMD, load the chain the config device holds for this platform's
//     current report, refusing a missing or stale one (ADR-0005). On Intel
//     there is no seventh step: the quote carries its own chain.
func (a *Acquirer) Acquire(ctx context.Context, callerSupplied [attest.CallerSuppliedBytesSize]byte) (ev attest.Evidence, err error) {
	if err := ctx.Err(); err != nil {
		return attest.Evidence{}, fmt.Errorf("tsm: %w", err)
	}
	req, name, err := a.open()
	if err != nil {
		return attest.Evidence{}, err
	}
	// The request is removed whichever way this returns, and a removal that
	// fails is reported when nothing else already went wrong.
	defer func() {
		if cerr := closeRequest(req, name); cerr != nil && err == nil {
			ev, err = attest.Evidence{}, cerr
		}
	}()

	provider, err := readProvider(req, name)
	if err != nil {
		return attest.Evidence{}, err
	}
	if provider != a.vendorProvider() {
		return attest.Evidence{}, fmt.Errorf("tsm: %s is now provided by %q, but this acquirer was built for %q and has told its callers so", name, provider, a.vendorProvider())
	}

	before, err := readGeneration(req, name)
	if err != nil {
		return attest.Evidence{}, err
	}
	if err := req.write(attrInblob, callerSupplied[:]); err != nil {
		// privlevel is left at the kernel's default and the platform
		// rejects a request below the floor at close, so a rejection here
		// on a guest above VMPL0 would otherwise be undiagnosable.
		if floor, ferr := req.read(attrPrivlevelFloor); ferr == nil {
			err = fmt.Errorf("%w (privlevel_floor is %s and privlevel was not set)", err, strings.TrimSpace(string(floor)))
		}
		return attest.Evidence{}, err
	}
	evidence, err := req.read(attrOutblob)
	if err != nil {
		return attest.Evidence{}, fmt.Errorf("tsm: reading %s/%s: %w", name, attrOutblob, err)
	}

	// auxblob, read and recorded rather than used. See the package comment:
	// it is empty on this host, no operator action fills it, and the chain
	// comes from the config device instead.
	table, tableErr := req.read(attrAuxblob)
	observation := Observation{
		Provider:              provider,
		Vendor:                a.vendor,
		EvidenceBytes:         len(evidence),
		CertificateTableBytes: len(table),
	}
	if tableErr != nil {
		observation.CertificateTableError = tableErr.Error()
	}

	after, err := readGeneration(req, name)
	if err != nil {
		return attest.Evidence{}, err
	}
	if after != before+1 {
		return attest.Evidence{}, fmt.Errorf("tsm: the generation counter on %s went from %d to %d where this acquisition made one write; "+
			"another writer is using this request and the evidence read back may be over its caller-supplied bytes rather than these",
			name, before, after)
	}
	observation.Writes = after - before

	if err := a.confirmEcho(evidence, callerSupplied); err != nil {
		return attest.Evidence{}, err
	}

	chain, err := a.bundleChain(evidence, &observation)
	if err != nil {
		return attest.Evidence{}, err
	}

	a.mu.Lock()
	a.last = &observation
	a.mu.Unlock()

	return attest.Evidence{Vendor: a.vendor, Bytes: evidence, Chain: chain}, nil
}

// bundleChain is the chain to carry with this platform's evidence, and it is
// the one step of the acquisition sequence that differs by vendor.
//
// On AMD SEV-SNP it comes from the config device and from nowhere else.
// LoadFor refuses a chain that is missing, that does not describe itself, that
// belongs to another chip, or that was issued for a TCB this platform has
// moved off.
//
// On Intel TDX there is nothing to bundle and nothing to refuse: the PCK chain
// that roots a version-4 quote is inside the quote, so a verifier reads it out
// of [attest.Evidence.Bytes] and never looks at Chain. An acquirer that filled
// Chain here would be describing something no consumer reads. The Intel
// collateral the quote is judged against is provisioned for the verifier
// (ADR-0007), not carried by the producer.
func (a *Acquirer) bundleChain(evidence []byte, o *Observation) ([]byte, error) {
	switch a.vendor {
	case attest.VendorAMDSEVSNP:
		chain, err := provision.LoadFor(a.opts.ChainDir, evidence)
		if err != nil {
			return nil, err
		}
		o.ChainDir = a.opts.ChainDir
		o.ChainBytes = len(chain.Bytes)
		o.ChainChipID = hex.EncodeToString(chain.ChipID)
		o.ChainTCB = chain.TCB
		return chain.Bytes, nil
	case attest.VendorIntelTDX:
		return nil, nil
	default:
		return nil, fmt.Errorf("tsm: no way to tell what certificate chain %s evidence is bundled with", a.vendor)
	}
}

// vendorProvider is the provider name this acquirer's vendor is behind. It is
// the inverse of [vendorOf] and exists only so that a provider that changes
// underneath a running acquirer is caught.
func (a *Acquirer) vendorProvider() string {
	switch a.vendor {
	case attest.VendorAMDSEVSNP:
		return providerSEVGuest
	case attest.VendorIntelTDX:
		return providerTDXGuest
	default:
		return ""
	}
}

// confirmEcho checks that the platform copied the caller-supplied bytes into
// the evidence verbatim, which is the mechanism the whole binding rides on
// (ADR-0002). It reads one field out of the evidence and is therefore
// vendor-specific, which is why it lives behind the seam.
//
// This is not verification. Nothing here checks a signature, and a platform
// that lied about everything else would still pass: the question is only
// whether this host's own report interface answered the request that was made,
// so that a mismatch is reported here, by the host that caused it, rather than
// at a peer as an unexplained binding refusal.
func (a *Acquirer) confirmEcho(evidence []byte, callerSupplied [attest.CallerSuppliedBytesSize]byte) error {
	switch a.vendor {
	case attest.VendorAMDSEVSNP:
		report, err := abi.ReportToProto(evidence)
		if err != nil {
			return fmt.Errorf("tsm: the platform returned %d bytes that do not parse as an SEV-SNP report: %w", len(evidence), err)
		}
		if !bytes.Equal(report.GetReportData(), callerSupplied[:]) {
			return fmt.Errorf("tsm: the platform returned evidence over %x, not over the %x it was handed; "+
				"evidence that does not carry the caller-supplied bytes binds nothing",
				report.GetReportData(), callerSupplied[:])
		}
		return nil
	case attest.VendorIntelTDX:
		parsed, err := tdxabi.QuoteToProto(evidence)
		if err != nil {
			return fmt.Errorf("tsm: the platform returned %d bytes that do not parse as a TDX quote: %w", len(evidence), err)
		}
		quote, ok := parsed.(*tdxpb.QuoteV4)
		if !ok {
			return fmt.Errorf("tsm: the platform returned a %T, and this acquirer reads version 4 quotes", parsed)
		}
		// The TD report's REPORTDATA: the field the caller-supplied bytes are
		// written into, and the one a verifier reads them back out of
		// (attest/verify/tdx.go's claimsOf).
		if data := quote.GetTdQuoteBody().GetReportData(); !bytes.Equal(data, callerSupplied[:]) {
			return fmt.Errorf("tsm: the platform returned evidence over %x, not over the %x it was handed; "+
				"evidence that does not carry the caller-supplied bytes binds nothing",
				data, callerSupplied[:])
		}
		return nil
	default:
		return fmt.Errorf("tsm: no way to read the caller-supplied bytes out of %s evidence", a.vendor)
	}
}

// open creates this acquisition's request directory. A name left behind by a
// crashed process with the same process identifier is stepped over rather than
// reused: reusing one would mean inheriting whatever was written to its
// inblob.
func (a *Acquirer) open() (request, string, error) {
	var firstErr error
	for attempt := 0; attempt < 16; attempt++ {
		a.mu.Lock()
		seq := a.seq
		a.seq++
		a.mu.Unlock()
		name := fmt.Sprintf("%s-%d-%d", a.opts.RequestName, os.Getpid(), seq)
		req, err := a.iface.open(name)
		if err == nil {
			return req, name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", err
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, "", fmt.Errorf("tsm: every request name this acquirer tried under %s already exists: %w", a.opts.ReportDir, firstErr)
}

func readProvider(req request, name string) (string, error) {
	b, err := req.read(attrProvider)
	if err != nil {
		return "", fmt.Errorf("tsm: reading %s/%s: %w", name, attrProvider, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func readGeneration(req request, name string) (uint64, error) {
	b, err := req.read(attrGeneration)
	if err != nil {
		return 0, fmt.Errorf("tsm: reading %s/%s: %w", name, attrGeneration, err)
	}
	g, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("tsm: %s/%s is %q, which is not a write counter: %w", name, attrGeneration, b, err)
	}
	return g, nil
}

// vendorOf maps the kernel's provider name to the vendor whose evidence that
// driver produces. It is the only place in this module where a platform driver
// becomes a vendor, and an unknown driver is refused rather than guessed at:
// evidence whose format is a guess is not evidence.
func vendorOf(provider string) (attest.Vendor, error) {
	switch provider {
	case providerSEVGuest:
		return attest.VendorAMDSEVSNP, nil
	case providerTDXGuest:
		return attest.VendorIntelTDX, nil
	default:
		return "", fmt.Errorf("tsm: the report interface is provided by %q, which this acquirer does not implement; "+
			"a second vendor adds a case here and an implementation of attest.Verifier, and touches nothing else", provider)
	}
}

func tcbString(t attest.TCB) string {
	return fmt.Sprintf("bootloader=%d tee=%d snp=%d microcode=%d", t.Bootloader, t.TEE, t.SNP, t.Microcode)
}

// abbreviate shortens a chip identity for a log line. The full value is 64
// bytes and nobody reads the middle of it.
func abbreviate(hexID string) string {
	if len(hexID) <= 16 {
		return hexID
	}
	return hexID[:6] + "…" + hexID[len(hexID)-4:]
}

// A reportInterface is the kernel's report interface as this package drives
// it. See [newOn] for why it exists and why it is unexported.
type reportInterface interface {
	// open creates the request named name and returns it.
	open(name string) (request, error)
}

// A request is one entry under the report interface: the unit the kernel
// gives evidence out in.
type request interface {
	// read returns an attribute's contents.
	read(attr string) ([]byte, error)

	// write writes data to an attribute in exactly one write. Splitting it
	// would make a partial request rather than part of a request.
	write(attr string, data []byte) error

	// close removes the request.
	close() error
}

// configfs is the real report interface: directories under
// /sys/kernel/config/tsm/report.
type configfs struct{ root string }

func (c configfs) open(name string) (request, error) {
	dir := filepath.Join(c.root, name)
	// configfs assigns its own mode; the one here says what was intended.
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("tsm: no report interface at %s: this is not a confidential guest, or configfs is not mounted and the platform's guest driver is not loaded (docs/snp-host-stack.md): %w", c.root, err)
		}
		return nil, fmt.Errorf("tsm: creating the request %s: %w", dir, err)
	}
	return &configfsRequest{dir: dir}, nil
}

type configfsRequest struct{ dir string }

func (r *configfsRequest) read(attr string) ([]byte, error) {
	// The attributes report a size of zero and are generated on read, so this
	// is a growing read rather than a sized one; os.ReadFile already does
	// that.
	return os.ReadFile(filepath.Join(r.dir, attr))
}

func (r *configfsRequest) write(attr string, data []byte) error {
	path := filepath.Join(r.dir, attr)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("tsm: opening %s: %w", path, err)
	}
	n, werr := writeOnce(f, data)
	// The platform driver runs at close for a configfs binary attribute, so
	// the error that says the request was rejected arrives here and not from
	// the write.
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("tsm: writing %s: %w", path, werr)
	}
	if n != len(data) {
		return fmt.Errorf("tsm: %s took %d of %d bytes; the rest would be a second request rather than the rest of this one", path, n, len(data))
	}
	if cerr != nil {
		return fmt.Errorf("tsm: the platform rejected the request written to %s: %w", path, cerr)
	}
	return nil
}

func (r *configfsRequest) close() error {
	return os.Remove(r.dir)
}

// writeOnce performs exactly one write syscall. os.File.Write is not that: it
// retries a short write, which would turn one request into two, and a partial
// inblob is a different request rather than half of this one
// (docs/snp-host-stack.md).
func writeOnce(f *os.File, data []byte) (int, error) {
	conn, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var werr error
	if err := conn.Write(func(fd uintptr) bool {
		n, werr = syscall.Write(int(fd), data)
		return true // one attempt, never retried
	}); err != nil {
		return 0, err
	}
	return n, werr
}
