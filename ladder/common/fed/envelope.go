// envelope.go - the federation envelope: what one exchange looks like on the wire.
//
// Rung 5a, spec section 2 ("Converse") and 2a ("stamp integration point").
//
// The cross-host label is TWO LAYERS and they are written by different components for
// different reasons, which is the single most important thing to get right in this file:
//
//	inner  the 256-byte sentry stamp. Written by the SENDING SANDBOX'S KERNEL below the
//	       syscall boundary (pkg/sentry/ladder/attest.go), carries identity, taint,
//	       grants, chain and origin. This file treats it as OPAQUE BYTES. It is copied
//	       into the envelope, hashed with everything else, and copied out again on the
//	       far side. Nothing here parses it, rewrites it, or could invent it -- the taint
//	       bit is the one field only the runtime knows, which is exactly why rung 3 put
//	       the stamping in the sentry and not in a host-side proxy.
//
//	outer  this envelope. Written by the runtime-owned PROXY, carries the routing, the
//	       freshness (expiry + sequence), the channel binding, and the capability claim
//	       the sending host's authority already attenuated. Signed with the host's
//	       enrolled long-term key.
//
// Moving the inner layer out here to simplify the proxy would reopen the problem rung 3
// already rejected -- a host-side stamper has to poll `runsc ladder-status` per message,
// which is root-only and live-sandbox-only -- and would shrink the runtime's role from
// "holds facts nothing else can" to "is one more participant". See the verdict in
// ladder/README.md.
//
// # Framing, and why one exchange is one stream
//
//	"LFED1"                    5 bytes
//	uint32 be | envelope JSON  canonical (encoding/json on a struct, fixed field order)
//	uint32 be | signature      Ed25519 over the envelope bytes, 64 bytes
//	uint32 be | body           the message the agent wrote
//	<EOF>                      the sender CloseWrite()s here
//
// The receiver reads to EOF and rejects ANY byte after the body. That check is not
// hygiene, it is rung 3's forgery attack re-tested across the network. Rung 3 needed
// SOCK_SEQPACKET on the local peer channel because on a byte stream an agent can put a
// second, fully-formed, "stamped" message inside its own payload and hand the receiver
// two messages where the kernel saw one. QUIC streams are byte streams, so the same
// attack is available again the moment a receiver is willing to parse more than one
// message out of one stream. One exchange per stream, trailing bytes rejected, is how
// that boundary is restored -- and the demo runs the attack rather than asserting it.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Magic marks a rung-5a frame. Five bytes, so a receiver that has been pointed at the
// wrong port says so instead of failing somewhere deep in a JSON parser.
var Magic = []byte("LFED1")

// EnvelopeVersion is bumped when a field's MEANING changes, never when one is added:
// fields are keyed by name, so an older peer reading a newer envelope ignores what it
// does not know, exactly as parseStamp does for the sentry stamp (attest.go:244).
const EnvelopeVersion = 1

// MaxFrame bounds every length prefix. A research prototype's messages are a few
// kilobytes; the bound exists so a hostile length prefix cannot make the receiver
// allocate its way out of memory before a single check has run.
const MaxFrame = 1 << 20

// ExporterLabel is the RFC 5705/8446 exporter label the channel binding is derived
// under. Both ends compute it from their own TLS state; neither takes the other's word.
const ExporterLabel = "EXPORTER-ladder-fed"

// ExporterLen is how many bytes of exported keying material the binding carries.
const ExporterLen = 32

// Envelope is the outer layer. Field order here is the canonical serialization order:
// encoding/json emits struct fields in declaration order, so signing the marshalled
// bytes is deterministic without a separate canonicalizer.
type Envelope struct {
	V        int    `json:"v"`
	FromHost string `json:"from_host"`
	FromPeer string `json:"from_peer"`
	ToHost   string `json:"to_host"`
	ToPeer   string `json:"to_peer"`

	// Seq is monotonic per (FromHost, FromPeer) and is what makes a replay detectable
	// on the connection it was captured from. Exp is what bounds how long a captured
	// envelope is worth anything at all. Binding is what makes it worthless on any
	// OTHER connection, which is the check that actually does the work -- see replay.go.
	Seq int64 `json:"seq"`
	Exp int64 `json:"exp"`

	// Binding is the TLS exporter output for THIS connection, base64. The receiver
	// derives the same value from its own half of the handshake and compares; it never
	// uses the value it was sent for anything but the comparison.
	Binding string `json:"binding"`

	// Stamp is the sending sentry's 256 bytes, base64, verbatim. Opaque here.
	Stamp string `json:"stamp"`

	// Claim is the sending host's capability authority's view of what the destination
	// hop should hold -- already attenuated by rung 4's check on the sending host,
	// never touched by any agent. nil when the sending host runs no authority, which
	// is the rung-3 configuration and is a legitimate deployment.
	Claim json.RawMessage `json:"claim,omitempty"`

	// BodySHA256 covers the payload, so the signature over this struct covers the
	// payload too without the signer having to buffer it twice.
	BodySHA256 string `json:"body_sha256"`
}

// SigningBytes is what gets signed and what the signature is verified against. It is
// the marshalled envelope and nothing else: no length prefix, no magic, no connection
// state. The connection is bound in through Binding, which is a field, so a signature
// lifted onto another connection fails the binding check rather than the signature one
// -- and the demo asserts both, because they are different failures.
func (e *Envelope) SigningBytes() ([]byte, error) {
	return json.Marshal(e)
}

// Sign returns the detached Ed25519 signature over the envelope.
func (e *Envelope) Sign(key ed25519.PrivateKey) ([]byte, error) {
	raw, err := e.SigningBytes()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, raw), nil
}

// BodyDigest is the hex sha256 the envelope carries for a payload.
func BodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// WriteFrame serializes one exchange onto a stream. The caller closes the write side
// immediately afterwards; see ReadFrame for why that is load-bearing.
func WriteFrame(w io.Writer, env *Envelope, sig, body []byte) error {
	raw, err := env.SigningBytes()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.Write(Magic)
	for _, part := range [][]byte{raw, sig, body} {
		if len(part) > MaxFrame {
			return fmt.Errorf("frame part is %d bytes, limit is %d", len(part), MaxFrame)
		}
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		buf.Write(n[:])
		buf.Write(part)
	}
	_, err = w.Write(buf.Bytes())
	return err
}

// Frame is one exchange as it came off the wire, before any check has run.
type Frame struct {
	Envelope    *Envelope
	EnvelopeRaw []byte
	Sig         []byte
	Body        []byte
}

// Rejection codes. Each one is a separate line of demo evidence, which is why they are
// constants rather than formatted strings: a check that cannot be named cannot be
// asserted on.
const (
	CodeBadFrame       = "bad-frame"
	CodeTrailingBytes  = "trailing-bytes"
	CodeSigInvalid     = "signature-invalid"
	CodeNotBound       = "not-exporter-bound"
	CodeExpired        = "expired"
	CodeReplayed       = "replayed"
	CodeBodyTampered   = "body-tampered"
	CodeUnknownService = "unknown-service"
	CodeOutsideRole    = "outside-role-scope"
	CodeWrongHost      = "wrong-host"
)

// RejectError carries the code alongside the human sentence, so the proxy can log one
// and the demo can grep the other.
type RejectError struct {
	Code   string
	Detail string
}

func (e *RejectError) Error() string { return e.Code + ": " + e.Detail }

func reject(code, format string, args ...any) error {
	return &RejectError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf returns the rejection code of an error, or "" if it is not a rejection.
func CodeOf(err error) string {
	var re *RejectError
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

// ReadFrame reads exactly one exchange and then requires EOF.
//
// "Then requires EOF" is the whole security content of this function. A stream is a
// byte stream; a receiver willing to read a second frame from it is a receiver an
// enrolled-but-misbehaving sender can hand two messages while the exporter binding,
// the sequence number and the signature all cover only the first. The rung-3 lesson
// (postbox.py's module docstring, on why the local channel is SOCK_SEQPACKET) is that
// message boundaries have to be a fact rather than a convention. Here the fact is
// enforced by refusing anything after the body rather than by the kernel, so it is
// checked in one place and tested by ladder-fed attack --case trailing.
func ReadFrame(r io.Reader) (*Frame, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 4*MaxFrame+64))
	if err != nil {
		return nil, reject(CodeBadFrame, "reading the stream: %v", err)
	}
	return ParseFrame(raw)
}

// ParseFrame is ReadFrame once the stream has already been drained. Split out because
// the receiving proxy has to look at the raw bytes first -- the post-handshake
// confirmation exchange is not a frame, and misreporting it as a malformed one would
// put a rejection in the log on every healthy connect.
func ParseFrame(raw []byte) (*Frame, error) {
	if len(raw) < len(Magic) || !bytes.Equal(raw[:len(Magic)], Magic) {
		return nil, reject(CodeBadFrame, "no LFED1 magic (%d bytes on the stream)", len(raw))
	}
	rest := raw[len(Magic):]

	parts := make([][]byte, 0, 3)
	for i := 0; i < 3; i++ {
		if len(rest) < 4 {
			return nil, reject(CodeBadFrame, "truncated length prefix for part %d", i+1)
		}
		n := binary.BigEndian.Uint32(rest[:4])
		if n > MaxFrame {
			return nil, reject(CodeBadFrame, "part %d declares %d bytes, limit is %d", i+1, n, MaxFrame)
		}
		rest = rest[4:]
		if uint32(len(rest)) < n {
			return nil, reject(CodeBadFrame, "part %d declares %d bytes, %d present", i+1, n, len(rest))
		}
		parts = append(parts, rest[:n])
		rest = rest[n:]
	}
	if len(rest) != 0 {
		// One exchange per stream, and this is where that is enforced.
		return nil, reject(CodeTrailingBytes,
			"%d byte(s) after the payload; one exchange per stream, trailing bytes are a second message", len(rest))
	}

	env := &Envelope{}
	if err := json.Unmarshal(parts[0], env); err != nil {
		return nil, reject(CodeBadFrame, "envelope is not JSON: %v", err)
	}
	return &Frame{Envelope: env, EnvelopeRaw: parts[0], Sig: parts[1], Body: parts[2]}, nil
}

// VerifyOpts is everything the receiver knows independently of the message.
type VerifyOpts struct {
	// PeerKey is the key that authenticated THIS connection, taken from the TLS
	// handshake and checked against the registry before any stream existed. The
	// signature is verified against it and not against a key looked up from
	// env.FromHost -- otherwise an enrolled host C could relay host A's envelope and
	// have it verify.
	PeerKey ed25519.PublicKey
	// PeerHost is the registry name of that key.
	PeerHost string
	// Binding is this receiver's own exporter output for this connection.
	Binding []byte
	// SelfHost is the name this proxy is enrolled under.
	SelfHost string
	// Now is injected so the expiry check is testable.
	Now time.Time
}

// Verify runs every per-message check, in the order the README documents, and returns
// the first failure with its code. The order matters for the evidence more than for the
// security: a message that fails several checks should be reported as failing the most
// specific one a reader would name.
func (f *Frame) Verify(o VerifyOpts) error {
	env := f.Envelope

	if env.V != EnvelopeVersion {
		return reject(CodeBadFrame, "envelope version %d, this proxy speaks %d", env.V, EnvelopeVersion)
	}
	if len(o.PeerKey) != ed25519.PublicKeySize {
		return reject(CodeSigInvalid, "no authenticated peer key for this connection")
	}
	if !ed25519.Verify(o.PeerKey, f.EnvelopeRaw, f.Sig) {
		return reject(CodeSigInvalid,
			"envelope is not signed by the key that authenticated this connection (%s)", o.PeerHost)
	}
	// The signature proves the CONNECTION'S peer wrote this envelope. That the envelope
	// also claims to be from that peer is a separate statement and has to be checked:
	// an enrolled host must not be able to sign an envelope claiming to originate on a
	// different enrolled host.
	if env.FromHost != o.PeerHost {
		return reject(CodeSigInvalid,
			"envelope claims from_host=%q on a connection authenticated as %q", env.FromHost, o.PeerHost)
	}
	if env.ToHost != "" && env.ToHost != o.SelfHost {
		return reject(CodeWrongHost, "envelope is addressed to host %q; this is %q", env.ToHost, o.SelfHost)
	}

	bind, err := base64.StdEncoding.DecodeString(env.Binding)
	if err != nil {
		return reject(CodeNotBound, "binding is not base64: %v", err)
	}
	if len(o.Binding) == 0 {
		return reject(CodeNotBound, "this connection exported no keying material")
	}
	if !bytes.Equal(bind, o.Binding) {
		// A captured envelope replayed onto a fresh connection dies here, before the
		// sequence check ever runs -- the exporter output is per-connection, so the
		// attacker would have to have the receiver's handshake secrets to forge it.
		return reject(CodeNotBound,
			"envelope is bound to a different channel; exporter %q output does not match this connection", ExporterLabel)
	}

	if env.Exp == 0 {
		return reject(CodeExpired, "envelope carries no expiry")
	}
	if o.Now.After(time.Unix(env.Exp, 0)) {
		return reject(CodeExpired, "envelope expired at %s (now %s)",
			time.Unix(env.Exp, 0).UTC().Format(time.RFC3339), o.Now.UTC().Format(time.RFC3339))
	}

	if got := BodyDigest(f.Body); got != env.BodySHA256 {
		return reject(CodeBodyTampered, "body sha256 is %s, envelope says %s", got[:16], safePrefix(env.BodySHA256, 16))
	}
	return nil
}

// StampBytes is the inner sentry stamp, decoded. Opaque to this package.
func (f *Frame) StampBytes() ([]byte, error) {
	if f.Envelope.Stamp == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(f.Envelope.Stamp)
}

func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
