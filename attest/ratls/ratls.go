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
// (per chip, so each side presents its own — ADR-0005), the binding context and
// the digest of the policy the peer presents. The last of those arrived with
// payload version 2 and ADR-0002's binding version 2, and it travels beside the
// context rather than inside it because a 16-byte context has no room for a
// 32-byte digest. The freshness challenge of Milestone 5 is a later payload
// version, not a new protocol.
//
// # One more question, on the side that dials
//
// [WithAdmission] adds a check after verification, and only the client
// configuration is built with one. It is where a sandbox's own `forward_to`
// list is enforced: a peer may be perfectly authentic, running an image this
// side admits, under a policy this side lists — and still be one this sandbox's
// policy does not say it will dial. That is a fact about the dialer and not
// about the peer, so it cannot live in the reference value set and it does not
// live in [attest.Verification].
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
const PayloadVersion = 2

// payload is the ASN.1 form of the extension. A later version adds fields after
// these and bumps the version, and a reader refuses a version it does not write
// rather than guessing.
//
// PolicyDigest is the field version 2 added, and it is marked optional for one
// reason: a version 1 payload is five fields long, and a reader whose struct
// demands six would refuse it as unparseable. It parses, and is then refused on
// its version — which is a sentence an operator can act on rather than a
// complaint about DER. Every other field stays required, so a peer cannot omit
// one and have the digest slide into its place.
type payload struct {
	Version        int
	Vendor         string
	Evidence       []byte
	Chain          []byte
	BindingContext []byte
	PolicyDigest   []byte `asn1:"optional"`
}

// Identity is the key a tunneld holds for the life of the process and the
// certificate that carries its evidence. It is built once at startup and never
// written anywhere.
type Identity struct {
	cert tls.Certificate
}

// NewIdentity generates a fresh key, binds it to evidence acquired from the
// platform and to the policy this sandbox presents, and wraps all of it in a
// certificate. The key never leaves the process: it is generated here and held
// only in the returned Identity.
//
// policy is the digest of this sandbox's own signed policy document
// ([attest.Policy.Digest]). It is a parameter rather than something this package
// computes because the policy is loaded above it, and it is not optional: a
// peer's allow-list is a list of measurement and policy pairs, and a sandbox
// that presented no policy would be asking to be admitted on the measurement
// alone.
//
// The binding context is [attest.BindingContextV2], which is what this version
// of the protocol speaks. [NewIdentityForContext] is the seam versions grow
// through.
func NewIdentity(ctx context.Context, acquirer attest.Acquirer, policy attest.PolicyDigest) (*Identity, error) {
	return NewIdentityForContext(ctx, acquirer, attest.BindingContextV2, policy)
}

// NewIdentityForContext is [NewIdentity] with the binding context stated rather
// than assumed.
//
// ADR-0002 reserved that field so that a later version could bind a sandbox's
// configuration into the evidence without re-attesting every deployed platform,
// and the reservation was worth nothing unless a verifier meeting a context it
// does not understand refuses it. Ticket 18 spent the reservation, and this is
// still the seam: the next version passes its own constant here and changes
// nothing else in this package. The other caller is a test that needs a peer
// speaking a version this verifier does not — a v1 peer, now — which cannot
// otherwise exist while v2 is the only context anything mints.
func NewIdentityForContext(ctx context.Context, acquirer attest.Acquirer, bindingContext attest.BindingContext, policy attest.PolicyDigest) (*Identity, error) {
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
	binding := attest.Binding{PublicKey: spki, Context: bindingContext, PolicyDigest: policy}
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
		PolicyDigest:   binding.PolicyDigest[:],
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

// An Admission is asked about a peer this side has already found authentic:
// evidence that verified, over a policy digest this side's reference value set
// lists, bound to the key the handshake proved possession of. It returns a
// refusal to abort the handshake anyway, or nil.
//
// It exists for the one question the reference value set cannot answer, because
// the answer is not about the peer at all. `forward_to` in this sandbox's own
// signed policy says which images it will dial; whether a peer is on that list
// is a fact about the dialer's policy, and no allow-list entry of the peer's
// could carry it. It is therefore a hook rather than a check inside
// [attest.Verification]: the verification is the same on both sides, and the
// side that dials asks one more thing.
//
// It runs after [attest.Verification.Verify] and never instead of it, so
// whatever it reads has already been vouched for. A refusal it returns should
// be an [attest.Refusal] carrying its own reason; anything else is filed the way
// an untyped verifier error is.
type Admission func(attest.Attested) error

// An Option adjusts a configuration this package builds.
type Option func(*options)

type options struct {
	log   RefusalLog
	admit Admission
}

// WithRefusalLog sends every refusal to log. Without it a refusal still aborts
// the handshake; it is simply not written down anywhere, which is the wrong
// default for an operator and the right one for a package that must not choose
// a destination for somebody else's logs.
func WithRefusalLog(log RefusalLog) Option {
	return func(o *options) { o.log = log }
}

// WithAdmission asks a of every peer whose evidence has already been accepted,
// and refuses the peer if it says so. Without it nothing is asked, which is what
// a listening side wants: whom this sandbox will *dial* is its own policy's
// business, and holds no opinion about who dials it.
func WithAdmission(a Admission) Option {
	return func(o *options) { o.admit = a }
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
		attested, err := v.Verify(context.Background(), ev, binding)
		if err != nil {
			return refuse(err)
		}
		if o.admit != nil {
			if err := o.admit(attested); err != nil {
				return refuse(err)
			}
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
//
// It reads the policy digest the peer presents and does not judge it. Whether
// that digest is one this side admits, and whether the peer's evidence was
// actually acquired over it, are [attest.Verification.Verify]'s questions.
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
	if p.Version == 1 {
		// A version 1 peer is not malformed and is not a stranger: it is this
		// protocol, one version back, carrying no policy digest. It gets the
		// reason that says so, which is the same reason its binding context
		// would earn a moment later — and it gets it here, before anything
		// reads a field the older payload never had.
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonUnknownBindingContext,
			"peer speaks attestation payload version 1, which carried no policy digest; this tunneld reads version %d", PayloadVersion)
	}
	if p.Version != PayloadVersion {
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonMalformedEvidence, "peer's attestation payload is version %d; this tunneld reads version %d", p.Version, PayloadVersion)
	}
	if len(p.BindingContext) != attest.BindingContextSize {
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonMalformedEvidence, "peer's binding context is %d bytes, want %d", len(p.BindingContext), attest.BindingContextSize)
	}
	if len(p.PolicyDigest) != len(attest.PolicyDigest{}) {
		return attest.Evidence{}, attest.Binding{}, attest.Refuse(attest.ReasonMalformedEvidence, "peer's policy digest is %d bytes, want %d", len(p.PolicyDigest), len(attest.PolicyDigest{}))
	}
	// RawSubjectPublicKeyInfo is the DER exactly as presented, which is what
	// NewIdentity hashed into the caller-supplied bytes on the other side.
	binding := attest.Binding{PublicKey: cert.RawSubjectPublicKeyInfo}
	copy(binding.Context[:], p.BindingContext)
	copy(binding.PolicyDigest[:], p.PolicyDigest)
	return attest.Evidence{Vendor: attest.Vendor(p.Vendor), Bytes: p.Evidence, Chain: p.Chain}, binding, nil
}
