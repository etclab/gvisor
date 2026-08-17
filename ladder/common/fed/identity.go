// identity.go - a host's long-term key, and the pin that is the whole authentication policy.
//
// Rung 5a, spec section 2 ("Connect"): "TLS 1.3 with raw public keys (RFC 7250 -- no
// X.509, no CA), mutual auth, peer key checked against the registry, connection refused
// otherwise."
//
// # Spec correction: Go has no RFC 7250
//
// crypto/tls does not implement raw public keys. There is no client_certificate_type or
// server_certificate_type extension in the standard library, at any Go version available
// here -- checked, not remembered. So the long-term Ed25519 key is wrapped in a
// self-signed X.509 certificate that exists for exactly one reason: it is the only
// container TLS 1.3 will carry a public key in.
//
// It is not a trust object, and every line below is written to make that unfalsifiable:
//
//   - no CA, no intermediate, nothing to build a chain from
//   - InsecureSkipVerify on the client and RequireAnyClientCert on the server, so
//     crypto/tls builds no chain and VerifiedChains is empty on both sides
//   - the subject, the SANs and the validity dates are never consulted. The dates are
//     set a century wide precisely so that nobody can mistake certificate expiry for a
//     security control; expiry lives on the ENVELOPE (minutes), and revocation lives in
//     the registry, by hand.
//   - authentication is one question: is this exact Ed25519 public key a key an operator
//     enrolled? It is a map lookup. See registry.go.
//
// This is section 2's "Keep Noise's worldview: strict static-key pinning, no certificate
// hierarchy -- TLS used as if it were Noise KK", implemented literally.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// ALPN is the application protocol name. A dedicated ALPN is also where the attestation
// rung's per-connection evidence exchange would go (SEAT-style over its own ALPN or its
// own stream), which is one of the two slots section 8 asks this rung to leave open.
const ALPN = "ladder-fed/1"

// Identity is this host's long-term key plus the TLS envelope that carries it.
type Identity struct {
	Host string
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
	Cert tls.Certificate
}

// keyFile is the on-disk form. 0600, and the demo never puts it anywhere a sandbox can
// reach: an agent that could read this file could impersonate its own runtime, which is
// the one thing the whole substrate rests on.
type keyFile struct {
	Host           string `json:"host"`
	Priv           string `json:"private_key"`
	Pub            string `json:"public_key"`
	RuntimeVersion string `json:"runtime_version,omitempty"`
	PolicyEpoch    int    `json:"policy_epoch,omitempty"`
}

// GenerateIdentity mints a fresh long-term key for a host.
func GenerateIdentity(host string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return newIdentity(host, priv, pub)
}

func newIdentity(host string, priv ed25519.PrivateKey, pub ed25519.PublicKey) (*Identity, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ladder-fed:" + host},
		// A century wide, on purpose. See the package comment: certificate expiry is
		// not a control here, and a short-lived envelope would imply it was.
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("self-signing the key envelope: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Host: host,
		Priv: priv,
		Pub:  pub,
		Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf},
	}, nil
}

// SaveIdentity writes the keyfile, 0600.
func SaveIdentity(id *Identity, path, runtimeVersion string, epoch int) error {
	blob, err := json.MarshalIndent(keyFile{
		Host:           id.Host,
		Priv:           base64.StdEncoding.EncodeToString(id.Priv),
		Pub:            base64.StdEncoding.EncodeToString(id.Pub),
		RuntimeVersion: runtimeVersion,
		PolicyEpoch:    epoch,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(blob, '\n'), 0o600)
}

// LoadIdentity reads a keyfile back.
func LoadIdentity(path string) (*Identity, string, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", 0, err
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, "", 0, fmt.Errorf("%s: %w", path, err)
	}
	priv, err := base64.StdEncoding.DecodeString(kf.Priv)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, "", 0, fmt.Errorf("%s: private key is not a %d-byte ed25519 key", path, ed25519.PrivateKeySize)
	}
	pub, err := base64.StdEncoding.DecodeString(kf.Pub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, "", 0, fmt.Errorf("%s: public key is not a %d-byte ed25519 key", path, ed25519.PublicKeySize)
	}
	id, err := newIdentity(kf.Host, ed25519.PrivateKey(priv), ed25519.PublicKey(pub))
	return id, kf.RuntimeVersion, kf.PolicyEpoch, err
}

// PubB64 is the registry's encoding of a public key.
func PubB64(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

// peerAuth carries what the pin check concluded out of the TLS callback.
//
// It exists because of a real asymmetry in TLS 1.3, documented here rather than
// discovered twice: the side that REJECTS knows exactly why, and the side that is
// rejected sees only a generic alert. Without this, host B's "not in the registry"
// sentence -- the evidence line the demo prints -- would never leave the callback.
type peerAuth struct {
	mu   sync.Mutex
	host string
	pub  ed25519.PublicKey
	err  error
	// onReject is called the moment the pin check refuses. It exists because a refused
	// handshake never becomes a connection, so the accept loop has nothing to report --
	// the only place that knows an impostor was turned away is inside the callback, and
	// "the impostor was refused at the handshake" is an evidence line the demo needs.
	onReject func(error)
}

func (p *peerAuth) set(host string, pub ed25519.PublicKey, err error) {
	p.mu.Lock()
	p.host, p.pub, p.err = host, pub, err
	hook := p.onReject
	p.mu.Unlock()
	if err != nil && hook != nil {
		hook(err)
	}
}

func (p *peerAuth) get() (string, ed25519.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.host, p.pub, p.err
}

// pinVerifier is the entire authentication policy of the federation.
//
// verifiedChains is always nil when this runs -- the client sets InsecureSkipVerify and
// the server sets RequireAnyClientCert, so crypto/tls has built no path. That is not a
// weakening to work around; it is the point. There is no CA to build a path to.
func pinVerifier(side string, reg *Registry, out *peerAuth) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		fail := func(format string, a ...any) error {
			err := fmt.Errorf(side+": "+format, a...)
			out.set("", nil, err)
			return err
		}
		if len(rawCerts) != 1 {
			return fail("expected exactly one peer certificate, got %d", len(rawCerts))
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fail("peer certificate is not parseable DER: %v", err)
		}
		pub, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			// Pin the algorithm as well as the bytes. A registry hit means nothing if
			// the peer chooses which kind of key the hit was on.
			return fail("peer key is %T, this federation enrolls ed25519 keys only", leaf.PublicKey)
		}
		entry, known := reg.ByKey(pub)
		if !known {
			return fail("peer public key %s is not in the enrollment registry (enrolled: %v)",
				Fingerprint(pub), reg.Hosts())
		}
		out.set(entry.Host, pub, nil)
		return nil
	}
}

// serverTLS authenticates the CALLER by pinned key and nothing else.
func serverTLS(me *Identity, reg *Registry, seen *peerAuth) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{me.Cert},
		// Demand a certificate but build no chain: pinVerifier is the whole policy.
		// Both halves are load-bearing -- with only the callback, a peer that sends no
		// certificate at all is never checked, because the callback is not invoked.
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinVerifier("server", reg, seen),
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		NextProtos:            []string{ALPN},
	}
}

// clientTLS authenticates the CALLEE by pinned key and nothing else.
func clientTLS(me *Identity, reg *Registry, seen *peerAuth) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{me.Cert},
		// Disables hostname and chain validation. It does NOT disable
		// VerifyPeerCertificate, which still runs on every handshake.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinVerifier("client", reg, seen),
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		NextProtos:            []string{ALPN},
	}
}
