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

// tunneld is the process the measured image embeds at /usr/bin/tunneld.
//
// It is the outermost layer of the composition root: it reads what the image
// gave it, builds one [tunneld.Tunneld] out of it, and serves. Every decision
// worth making was made below it — this command chooses no reference value,
// judges no peer, and holds no key.
//
// # The paths are the image's, not this command's
//
// They were pinned by ticket 06, before this command existed, in
// docs/snp/image/tunneld-placeholder.c and docs/snp/image/mkconfigdev.sh:
//
//	/etc/attested-tunnel/author.pub    the reference value author's public key,
//	                                   INSIDE the launch measurement (ADR-0004)
//	/config/reference-values.json      the reference value set, outside it
//	/config/reference-values.json.sig  its detached signature (ADR-0006)
//	/config/policy.json                this sandbox's own signed policy: what
//	                                   leaves it, and whom it will dial
//	/config/policy.json.sig            its detached signature, under the same
//	                                   author key and its own domain
//	/config/peers.json                 the peer table
//	/config/certificate-chain.bin      the chain provisioned for this chip and
//	                                   TCB (ADR-0005)
//	/config/certificate-chain.json     the chip and TCB it was fetched for
//	/config/tunneld.json               this run: the sandbox identifier, the
//	                                   address to listen on, the link to bring
//	                                   up, the limits, and what to exercise
//
// One file on that list is new here, and the reason it is safe to add is the
// reason the others are safe to deliver on an untrusted device. Nothing on the
// config device can admit a peer. The trust root is the author key inside the
// measurement; the set is refused unless that key signed it; the chain is
// public and self-validating; the peer table resolves names to addresses and a
// wrong address is a failed handshake rather than a compromised one. A run
// configuration is the same kind of thing: it says which peers this tunneld
// asks for and how hard it exercises them, and a host that rewrites it can
// make this guest talk to nobody, or to a peer that refuses it. It cannot make
// it talk to an unattested one.
//
// # The exercise is Milestone 3's stand-in for the agent
//
// In deployment the sentry asks tunneld for a named peer and the agent's
// traffic flows (spec, user story 46); that path is Milestone 4. The measured
// image has no agent and no shell — its init runs this binary and powers off
// when it exits (docs/snp/image/init.rootfs) — so a tunneld that only listened
// would establish nothing and measure nothing. The exercise in this command is
// that missing caller: it asks for the peers the run configuration names,
// exchanges with them, and prints the figures user story 50 asks for. It lives
// here rather than in package tunneld because it is a caller of tunneld's API,
// not part of it, and because the package's seam is where every other test in
// this module already stands.
//
// # Bringing up the link
//
// The guest's init does not configure networking and cannot be asked to: it is
// inside the launch measurement, and every byte in there is a byte in M. This
// command therefore sets the address on its interface itself, from the run
// configuration, before it does anything else. It is three ioctls (link.go);
// on a host that already has an address, leave "link" out and nothing happens.
//
// # What it prints
//
// Everything, to standard output, which in the guest is the serial console
// (spec, user story 48; Error surface). The lines a harness reads are prefixed
// LATENCY, PEER, REFUSED and EXIT, and are documented where they are written.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/tsm"
	"gvisor.dev/gvisor/attest/tunneld"
	"gvisor.dev/gvisor/attest/verify"
)

// The paths inside the image. They are defaults rather than constants in the
// code's flow so that the same binary runs on a host during a dress rehearsal,
// but the image never passes a flag: init runs "/usr/bin/tunneld" with no
// arguments.
const (
	defaultConfigDir = "/config"
	defaultAuthorKey = "/etc/attested-tunnel/author.pub"
	peerTableName    = "peers.json"
	runConfigName    = "tunneld.json"

	// The reference value set's name on the device. Its detached signature is
	// beside it under attest.SignatureFileSuffix, and the loader finds it
	// there rather than being told (ADR-0006).
	referenceValueSetName = "reference-values.json"

	// This sandbox's own policy, beside the set and signed the same way under
	// its own domain. Two documents since ticket 19: the set says whom this
	// sandbox admits, and this says what it is.
	policyName = "policy.json"
)

// Exit statuses. A refusal to start and a failed exercise are different
// answers and a console transcript should not have to guess which it saw.
const (
	exitOK             = 0
	exitRefusedToStart = 1
	exitExerciseFailed = 2
)

func main() {
	out := os.Stdout
	code := run(os.Args[1:], out)
	fmt.Fprintf(out, "tunneld: EXIT status=%d\n", code)
	os.Exit(code)
}

func run(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("tunneld", flag.ContinueOnError)
	fs.SetOutput(out)
	configDir := fs.String("config", defaultConfigDir, "the read-only config device: reference value set, policy, peer table, provisioned chain, run configuration")
	authorPath := fs.String("author", defaultAuthorKey, "the reference value author's public key, which is inside the launch measurement (ADR-0004)")
	reportDir := fs.String("report-dir", tsm.DefaultReportDir, "the kernel's vendor-neutral report interface")
	runPath := fs.String("run", "", "the run configuration; empty means <config>/"+runConfigName)
	tdxCollateralDir := fs.String("tdx-collateral-dir", "", "directory holding Intel's provisioned TCB info, quoting-enclave identity and revocation lists; empty means this tunneld admits no Intel TDX peers. Never fetched (ADR-0005)")
	if err := fs.Parse(args); err != nil {
		return exitRefusedToStart
	}
	logf := func(format string, a ...any) { fmt.Fprintf(out, "tunneld: "+format+"\n", a...) }

	if *runPath == "" {
		*runPath = filepath.Join(*configDir, runConfigName)
	}
	cfg, err := loadRunConfig(*runPath)
	if err != nil {
		logf("refusing to start: %v", err)
		return exitRefusedToStart
	}
	peers, err := loadPeerTable(filepath.Join(*configDir, peerTableName))
	if err != nil {
		logf("refusing to start: %v", err)
		return exitRefusedToStart
	}
	author, err := readAuthorKey(*authorPath)
	if err != nil {
		logf("refusing to start: %v", err)
		return exitRefusedToStart
	}

	logf("sandbox %q", cfg.SandboxID)
	logf("author key %s (%s, inside the launch measurement)", abbreviate(hex.EncodeToString(author)), *authorPath)
	for _, name := range sortedKeys(peers) {
		logf("peer table: %s = %s", name, peers[name])
	}

	if cfg.Link != nil {
		if err := cfg.Link.configure(); err != nil {
			logf("refusing to start: bringing up %s: %v", cfg.Link.Interface, err)
			return exitRefusedToStart
		}
		logf("link %s up with %s/%d", cfg.Link.Interface, cfg.Link.Address, cfg.Link.PrefixLength)
	}

	limits, clamped := cfg.limits()
	if clamped != "" {
		logf("CLAMPED %s", clamped)
	}

	// The two halves of the vendor seam, both real: this platform's report
	// interface for our own evidence, and go-sev-guest under attest/verify for
	// peers'. Neither reaches the network — the chain is the one the config
	// device holds (ADR-0005) and the vendor root is the one embedded in the
	// verification library.
	logf("report interface %s: %s", *reportDir, reportInterface(*reportDir))
	acquirer, err := tsm.New(tsm.Options{ChainDir: *configDir, ReportDir: *reportDir, RequestName: "tunneld"})
	if err != nil {
		logf("refusing to start: %v", err)
		return exitRefusedToStart
	}
	snp, err := verify.New(verify.Options{})
	if err != nil {
		logf("refusing to start: %v", err)
		return exitRefusedToStart
	}
	verifiers := []attest.Verifier{snp}

	// The second vendor is opt in, and it is opt in because it needs something
	// the config device may not carry: Intel's collateral, provisioned ahead of
	// use like the AMD chain beside it. A tunneld without it admits no Intel
	// peer, which is the honest state — it holds nothing that could judge one —
	// rather than a tunneld that would try and then reach the network.
	if *tdxCollateralDir != "" {
		tdx, err := verify.NewTDX(verify.TDXOptions{CollateralDir: *tdxCollateralDir})
		if err != nil {
			logf("refusing to start: %v", err)
			return exitRefusedToStart
		}
		verifiers = append(verifiers, tdx)
		logf("intel tdx collateral %s (provisioned, never fetched — ADR-0005)", *tdxCollateralDir)
	}
	routed, err := attest.Dispatch(verifiers...)
	if err != nil {
		logf("refusing to start: %v", err)
		return exitRefusedToStart
	}
	logf("verifying evidence from %s", routed.Vendor())
	watched := newWatchedVerifier(routed, logf)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startCtx, cancel := context.WithTimeout(ctx, cfg.startTimeout())
	defer cancel()
	td, err := tunneld.New(startCtx, tunneld.Config{
		SandboxID:             cfg.SandboxID,
		Acquirer:              acquirer,
		Verifier:              watched,
		ReferenceValueSetPath: filepath.Join(*configDir, referenceValueSetName),
		PolicyPath:            filepath.Join(*configDir, policyName),
		AuthorPublicKey:       author,
		Peers:                 tunneld.PeerTable(peers),
		ListenAddr:            cfg.Listen,
		Handler:               echo(cfg.SandboxID),
		Limits:                limits,
		RefusalLog: func(r *attest.Refusal) {
			// The one place a reason surfaces (spec, Error surface): the peer
			// sees an aborted handshake and a caller sees ErrNotEstablished.
			logf("REFUSED %s", r.LogString())
		},
	})
	if err != nil {
		logf("refusing to start: %s", withoutPackagePrefix(err))
		if observation, ok := acquirer.LastObservation(); ok {
			logf("%s", observation)
		}
		return exitRefusedToStart
	}
	defer td.Close()

	if observation, ok := acquirer.LastObservation(); ok {
		logf("%s", observation)
	}
	// The number a peer's operator needs, printed where the only diagnostic
	// surface a measured guest has can carry it (spec, user story 48). It is
	// SHA-256 over the bytes the reference value author signed over the policy,
	// so it is not what sha256sum of policy.json prints; emit-refvals prints the
	// same number when it writes the document and this prints it at run time,
	// from the file the guest actually loaded.
	logf("policy digest %s (sha256 over the signed policy; put it in a peer's policy_digest)",
		td.PolicyDigest())

	// And whom this sandbox's own policy says it will dial. An empty list is a
	// sandbox that answers and never calls, which is a legitimate thing to
	// deploy and an expensive thing to diagnose from a failed dial alone.
	forward := td.ForwardTo()
	if len(forward) == 0 {
		logf("policy forward_to is empty: this sandbox dials nobody")
	}
	for _, m := range forward {
		logf("policy forward_to: measurement %s", abbreviate(hex.EncodeToString(m)))
	}

	// And the entries that will admit any policy at all. This is the one place
	// this design reads an absent field the weaker way, so it says so out loud,
	// once per entry, every start — rather than leaving an operator to notice
	// by reading a file they did not write.
	for _, u := range td.Unconstrained() {
		logf("reference value %d (%s, measurement %s) is unconstrained: it admits any policy",
			u.Index, u.Vendor, abbreviate(hex.EncodeToString(u.Measurement)))
	}

	logf("listening on %s as %q; idle %s, maximum age %s",
		td.Addr(), td.SandboxID(), limits.IdleTimeout, limits.MaxAge)

	code := exitOK
	if cfg.Exercise != nil {
		if err := cfg.Exercise.perform(ctx, td, watched, logf); err != nil {
			logf("exercise failed: %v", err)
			code = exitExerciseFailed
		}
	}
	if hold := cfg.Hold.Duration; hold > 0 {
		logf("holding for %s so that peers still dialing can finish", hold)
		select {
		case <-time.After(hold):
		case <-ctx.Done():
			logf("interrupted")
		}
	}
	watched.report(logf)
	return code
}

// echo is the handler this command answers peers with: the sandbox identifier,
// a colon, and the request. It is the same shape package tunneld's own tests
// use, and for the same reason — a response that names its answerer is how a
// caller can tell which of two peers served it.
func echo(sandboxID string) tunneld.Handler {
	prefix := []byte(sandboxID + ":")
	return func(_ context.Context, request []byte) ([]byte, error) {
		return append(append([]byte(nil), prefix...), request...), nil
	}
}

// readAuthorKey reads the reference value author's public key from the file
// the image baked into the measurement: 32 raw bytes or their hexadecimal,
// which is what build-image.sh writes (one line of 64 lowercase hex).
func readAuthorKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the reference value author's public key: %w", err)
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is neither %d raw bytes nor their hexadecimal", path, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

// reportInterface says what is at the kernel's report interface, and it is
// printed on every start rather than only on a failure. A guest that cannot
// acquire evidence fails at ratls.NewIdentity with whatever errno the kernel
// gave — "no such device or address" from a mkdir, on a guest whose sev-guest
// driver did not load — and that is a true sentence about a syscall rather
// than a legible one about a machine. The console is the only diagnostic
// surface a measured guest has (spec, user story 48), so the fact a reader
// needs is put there before the failure that depends on it.
func reportInterface(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Sprintf("absent (%v) — this kernel exposes no report interface, or configfs is not mounted; "+
			"a platform with nothing to ask has no evidence to present", err)
	}
	return fmt.Sprintf("present, %d request(s) outstanding; a platform driver that does not answer it "+
		"is what a non-confidential VM looks like from inside", len(entries))
}

// withoutPackagePrefix trims the lead-in [tunneld.New]'s errors already carry,
// because this command's own log lines add the name again and a console line
// reading "tunneld: refusing to start: tunneld: refusing to start: …" spends
// its first half saying nothing twice. Only the prefix goes; the sentence
// underneath is the one an operator needs and it is untouched.
func withoutPackagePrefix(err error) string {
	return strings.TrimPrefix(err.Error(), "tunneld: refusing to start: ")
}

func abbreviate(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}

func sortedKeys(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}
