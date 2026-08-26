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

// Package ratls carries attestation evidence in a TLS certificate and verifies
// it during the handshake.
//
// The certificate is a serialization envelope, not a trust object. It exists
// because TLS 1.3 authenticates a peer by proving possession of the private key
// matching a presented certificate, and that certificate is the one place the
// handshake gives a peer to put bytes. Nothing else about it is consulted: no
// chain is built, no subject or SAN is read, no validity date is a control.
// Authentication is the evidence, bound to the presented public key through
// the caller-supplied bytes of ADR-0002, and only the evidence.
//
// # The payload
//
// A single extension under a private arc carries a versioned payload: the
// version, the vendor, the evidence, the certificate chain the evidence needs
// (per chip, so each side presents its own — ADR-0005), and the binding
// context. The freshness challenge of Milestone 5 is a later payload version,
// not a new protocol.
//
// # Refusals
//
// Every way a peer can fail aborts the handshake, so a peer that fails is never
// a connection — there is no state in which it is connected and its exchanges
// are refused afterwards. Every refusal this package reports is an
// [attest.Refusal] carrying the [attest.Reason] that names it, and every one of
// them has the same Error text, so the reason reaches an operator through
// [WithRefusalLog] and reaches the peer through nothing at all.
package ratls

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"gvisor.dev/gvisor/attest"
)

// PayloadOID identifies the certificate extension carrying the attestation
// payload. It sits under the private enterprise arc, using the enterprise
// number IANA reserves for documentation (32473, RFC 5612): it is nobody's
// identifier, so no verifier can be led to guess another party's format, and
// it is visibly a placeholder. If a private enterprise number is assigned for
// this work, this constant is the only thing that changes.
var PayloadOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1, 1}

// PayloadVersion is the version of the payload this package writes and reads.
const PayloadVersion = 1

// payload is the ASN.1 form of the extension. Every field is present in v1; a
// later version adds fields after these and bumps the version, and a reader of
// v1 refuses it rather than guessing.
type payload struct {
	Version        int
	Vendor         string
	Evidence       []byte
	Chain          []byte
	BindingContext []byte
}

// Identity is the key a tunneld holds for the life of the process and the
// certificate that carries its evidence. It is built once at startup and never
// written anywhere.
type Identity struct {
	cert tls.Certificate
}

// NewIdentity generates a fresh key, binds it to evidence acquired from the
// platform, and wraps both in a certificate. The key never leaves the process:
// it is generated here and held only in the returned Identity.
//
// The binding context is [attest.BindingContextV1], which is what this version
// of the protocol speaks. [NewIdentityForContext] is the seam a later one grows
// through.
func NewIdentity(ctx context.Context, acquirer attest.Acquirer) (*Identity, error) {
	return NewIdentityForContext(ctx, acquirer, attest.BindingContextV1)
}

// NewIdentityForContext is [NewIdentity] with the binding context stated rather
// than assumed.
//
// ADR-0002 reserves that field so that a later version can bind runsc's
// configuration into the evidence without re-attesting every deployed platform,
// and the reservation is worth nothing unless a verifier meeting a context it
// does not understand refuses it. A v2 of this protocol is one caller: it
// passes its own constant here and changes nothing else in this package. The
// other is a test that needs a peer speaking a version this verifier does not,
// which cannot otherwise exist while v1 is the only context anything mints.
func NewIdentityForContext(ctx context.Context, acquirer attest.Acquirer, bindingContext attest.BindingContext) (*Identity, error) {
	if acquirer == nil {
		return nil, errors.New("ratls: no acquirer")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ratls: generating the key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ratls: encoding the public key: %w", err)
	}
	binding := attest.Binding{PublicKey: spki, Context: bindingContext}
	ev, err := acquirer.Acquire(ctx, binding.CallerSuppliedBytes())
	if err != nil {
		return nil, fmt.Errorf("ratls: acquiring evidence: %w", err)
	}
	ext, err := asn1.Marshal(payload{
		Version:        PayloadVersion,
		Vendor:         string(ev.Vendor),
		Evidence:       ev.Bytes,
		Chain:          ev.Chain,
		BindingContext: binding.Context[:],
	})
	if err != nil {
		return nil, fmt.Errorf("ratls: encoding the payload: %w", err)
	}
	// Every field below other than the extension is filler the x509 encoder
	// requires. The subject is a constant, the serial is random only so two
	// certificates are not byte-identical, and the validity window is wide
	// because no verifier reads it.
	tmpl := &x509.Certificate{
		SerialNumber:    randomSerial(),
		Subject:         pkix.Name{CommonName: "tunneld"},
		NotBefore:       time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:        time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC),
		ExtraExtensions: []pkix.Extension{{Id: PayloadOID, Critical: false, Value: ext}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("ratls: creating the certificate: %w", err)
	}
	return &Identity{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}}, nil
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		// rand.Reader failing is not a condition this process continues from.
		panic(fmt.Sprintf("ratls: reading random serial: %v", err))
	}
	return n
}

// Both roles use one configuration shape: present our envelope, demand the
// peer's, and decide on the evidence inside it. Go's own chain building is
// switched off on both sides (InsecureSkipVerify for the client, RequireAnyClientCert
// for the server) because there is no hierarchy to build against; the
// decision is VerifyPeerCertificate's alone.

// A RefusalLog is handed every peer this side refuses, with the typed reason
// that refused it. It is the only way the reason leaves this package: a peer
// learns nothing from it, and a caller reads an error whose text is the same
// for every reason.
//
// It runs on the handshake goroutine of the connection being refused, and one
// log may be shared by every connection a tunneld has, so an implementation
// must be safe to call concurrently and must not block.
type RefusalLog func(*attest.Refusal)

// An Option adjusts a configuration this package builds. There is one today.
type Option func(*options)

type options struct {
	log RefusalLog
}

// WithRefusalLog sends every refusal to log. Without it a refusal still aborts
// the handshake; it is simply not written down anywhere, which is the wrong
// default for an operator and the right one for a package that must not choose
// a destination for somebody else's logs.
func WithRefusalLog(log RefusalLog) Option {
	return func(o *options) { o.log = log }
}

func collect(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// ClientConfig is the TLS configuration for dialing a peer.
func (id *Identity) ClientConfig(v *attest.Verification, opts ...Option) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{id.cert},
		InsecureSkipVerify:    true, // the envelope has no chain to verify; see VerifyPeerCertificate.
		VerifyPeerCertificate: PeerVerifier(v, opts...),
		NextProtos:            []string{ALPN},
	}
}

// ServerConfig is the TLS configuration for accepting peers.
func (id *Identity) ServerConfig(v *attest.Verification, opts ...Option) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{id.cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: PeerVerifier(v, opts...),
		NextProtos:            []string{ALPN},
		// Session tickets are what would let a returning client send early
		// data; the transport also refuses 0-RTT, and this is the second lock.
		SessionTicketsDisabled: true,
	}
}

// ALPN names the protocol both sides must agree on.
const ALPN = "gvisor-attested-tunnel/1"

// ErrNoEnvelope is returned when the peer presented no certificate carrying
// the payload. Like every other failure here it aborts the handshake, and like
// every other it is a refusal carrying its reason: a peer with nothing to say
// is refused for having said nothing, not for some failure to parse what it
// did not send.
var ErrNoEnvelope = attest.Refuse(attest.ReasonNoEvidence, "peer presented no certificate at all")

// PeerVerifier returns the handshake callback that decides whether a peer is
// admitted. Returning an error aborts the handshake, so a connection to a
// peer that fails verification never exists — there is no state in which it
// is connected but its exchanges are refused.
//
// Every error it returns is an [attest.Refusal], so the reason is typed on
// every path and the text the peer sees is undifferentiated on every path.
// [WithRefusalLog] is where the reason goes.
//
// The leaf is the first raw certificate and it is the only one read. Anything
// after it is ignored, not rejected, because a peer's chain is carried in the
// payload and never as TLS certificates. The verified chains argument is
// always empty since chain building is disabled, and it is not consulted.
func PeerVerifier(v *attest.Verification, opts ...Option) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	o := collect(opts)
	refuse := func(err error) error {
		r := refusal(err)
		if o.log != nil {
			o.log(r)
		}
		return r
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return refuse(ErrNoEnvelope)
		}
		ev, binding, err := Open(rawCerts[0])
		if err != nil {
			return refuse(err)
		}
		if _, err := v.Verify(context.Background(), ev, binding); err != nil {
			return refuse(err)
		}
		return nil
	}
}

// refusal is what makes "every refusal is typed" a property of this package
// rather than a habit of the packages below it. Everything reachable from here
// already returns an [attest.Refusal]; an untyped error would be a bug in a
// verifier, and it must not become an acceptance, must not reach a peer with
// its text intact, and must not be silently filed under a reason that claims
// more than is known.
func refusal(err error) *attest.Refusal {
	var r *attest.Refusal
	if errors.As(err, &r) {
		return r
	}
	return attest.Refuse(attest.ReasonMalformedEvidence, "peer refused by an untyped error, which is a bug in this verifier: %v", err)
}

// Open reads the evidence and the binding out of a presented certificate. It
// is the whole of what this package reads from the envelope: the public key,
// so that the binding can be checked against the key TLS proved possession
// of, and the payload extension.
func Open(der []byte) (attest.Evidence, attest.Binding, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonMalformedEvidence, "peer's envelope does not parse as a certificate: %v", err)
	}
	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(PayloadOID) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonNoEvidence, "peer's envelope carries no attestation payload")
	}
	var p payload
	rest, err := asn1.Unmarshal(raw, &p)
	if err != nil {
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonMalformedEvidence, "peer's attestation payload does not parse: %v", err)
	}
	if len(rest) != 0 {
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonMalformedEvidence, "peer's attestation payload carries %d trailing bytes", len(rest))
	}
	if p.Version != PayloadVersion {
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonMalformedEvidence, "peer's attestation payload is version %d; this tunneld reads version %d", p.Version, PayloadVersion)
	}
	if len(p.BindingContext) != attest.BindingContextSize {
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonMalformedEvidence, "peer's binding context is %d bytes, want %d", len(p.BindingContext), attest.BindingContextSize)
	}
	// RawSubjectPublicKeyInfo is the DER exactly as presented, which is what
	// NewIdentity hashed into the caller-supplied bytes on the other side.
	binding := attest.Binding{PublicKey: cert.RawSubjectPublicKeyInfo}
	copy(binding.Context[:], p.BindingContext)
	return attest.Evidence{Vendor: attest.Vendor(p.Vendor), Bytes: p.Evidence, Chain: p.Chain}, binding, nil
}
