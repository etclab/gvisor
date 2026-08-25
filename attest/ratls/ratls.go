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
func NewIdentity(ctx context.Context, acquirer attest.Acquirer) (*Identity, error) {
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
	binding := attest.Binding{PublicKey: spki, Context: attest.BindingContextV1}
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

// ClientConfig is the TLS configuration for dialing a peer.
func (id *Identity) ClientConfig(v *attest.Verification) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{id.cert},
		InsecureSkipVerify:    true, // the envelope has no chain to verify; see VerifyPeerCertificate.
		VerifyPeerCertificate: PeerVerifier(v),
		NextProtos:            []string{ALPN},
	}
}

// ServerConfig is the TLS configuration for accepting peers.
func (id *Identity) ServerConfig(v *attest.Verification) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{id.cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: PeerVerifier(v),
		NextProtos:            []string{ALPN},
		// Session tickets are what would let a returning client send early
		// data; the transport also refuses 0-RTT, and this is the second lock.
		SessionTicketsDisabled: true,
	}
}

// ALPN names the protocol both sides must agree on.
const ALPN = "gvisor-attested-tunnel/1"

// ErrNoEnvelope is returned when the peer presented no certificate carrying
// the payload. Like every other failure here it aborts the handshake.
var ErrNoEnvelope = errors.New("ratls: peer presented no attestation envelope")

// PeerVerifier returns the handshake callback that decides whether a peer is
// admitted. Returning an error aborts the handshake, so a connection to a
// peer that fails verification never exists — there is no state in which it
// is connected but its exchanges are refused.
//
// The leaf is the first raw certificate and it is the only one read. Anything
// after it is ignored, not rejected, because a peer's chain is carried in the
// payload and never as TLS certificates. The verified chains argument is
// always empty since chain building is disabled, and it is not consulted.
func PeerVerifier(v *attest.Verification) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrNoEnvelope
		}
		ev, binding, err := Open(rawCerts[0])
		if err != nil {
			return err
		}
		_, err = v.Verify(context.Background(), ev, binding)
		return err
	}
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
