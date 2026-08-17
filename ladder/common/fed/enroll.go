// enroll.go - the one human touchpoint, and the only place trust enters the system.
//
// Rung 5a, spec section 2 ("Enroll"). A Magic-Wormhole-style SPAKE2 ceremony between a
// new runtime proxy and the registry holder, over a SELF-HOSTED mailbox, exchanging the
// runtime's long-term Ed25519 public key plus its metadata. Human-pace, once per host,
// and never on the per-exchange path -- which is the acceptance criterion CONTROL's
// unattended burst demonstrates.
//
// # Why a PAKE and not "paste the key"
//
// The operator transcribes a short code between two terminals. A short code is a
// low-entropy secret, and low-entropy secrets are exactly what a PAKE exists for: the
// SPAKE2 exchange turns 24 bits of typed code into a channel an offline attacker cannot
// grind, and holds an online attacker to one guess per ceremony. Pasting a public key
// over the same channel would be no worse cryptographically and much worse
// operationally -- 44 base64 characters transcribed by hand is where the typos and the
// copy-paste-from-the-wrong-window mistakes live.
//
// # What it does NOT prove, stated here because it is the rung's crack
//
// A completed ceremony proves an operator was present at both ends at the same moment.
// It proves nothing about what the peer RUNS. An enrolled host that is hostile, or that
// was compromised after enrolment, passes every check in envelope.go and can assert
// anything within the receiving service's role. Section 8: "Keys are trusted by
// ceremony, not by attestation." The next rung's job is to put attestation evidence
// where the self-asserted runtime_version string sits today.
//
// # Implementation note
//
// The mailbox is wormhole-william's own rendezvous server
// (rendezvous/rendezvousservertest), run locally. It is not a _test.go file, so it is
// importable, and using the upstream project's own server is both smaller and more
// trustworthy than reimplementing the rendezvous protocol -- which was the alternative
// considered and rejected. Nothing in the ceremony reaches the public relay: the client
// only uses SendText/Receive, which never touch the transit relay at all.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/psanford/wormhole-william/rendezvous/rendezvousservertest"
	"github.com/psanford/wormhole-william/wormhole"
)

// CodeWords is how many words follow the nameplate in the transcribed code.
//
// wormhole-william's default is 2, which is 16 bits from a 256-word list. This ceremony
// mints a long-term trust anchor rather than sending a file, so it uses 3 (24 bits).
// That is the difference between an online attacker who gets one guess in 65 thousand
// and one who gets one guess in 16 million, for one extra word the operator types once
// per host, ever.
const CodeWords = 3

// enrollRecord is what crosses the PAKE channel. It is what ends up in the registry.
type enrollRecord struct {
	Host           string `json:"host"`
	Key            string `json:"key"`
	Address        string `json:"address"`
	RuntimeVersion string `json:"runtime_version"`
	PolicyEpoch    int    `json:"policy_epoch"`
	// SelfSig is the new runtime signing its own record with the key the record
	// carries. It proves the sender holds the private half, which the PAKE alone does
	// not -- the PAKE proves who you are talking to, not what they can do. Cheap, and
	// it turns "somebody typed the code and sent me a key" into "somebody typed the
	// code and can use this key".
	SelfSig string `json:"self_sig"`
}

func (r *enrollRecord) signingBytes() []byte {
	return []byte(strings.Join([]string{
		r.Host, r.Key, r.Address, r.RuntimeVersion, fmt.Sprint(r.PolicyEpoch),
	}, "\x00"))
}

// RunMailbox starts the self-hosted rendezvous server and blocks. It writes the URL to
// urlPath so the two ceremony halves can find it without a well-known port.
func RunMailbox(ctx context.Context, urlPath string) error {
	srv := rendezvousservertest.NewServer()
	defer srv.Close()
	url := srv.WebSocketURL()
	if urlPath != "" {
		if err := os.WriteFile(urlPath, []byte(url+"\n"), 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("MAILBOX url=%s (self-hosted; no public relay is contacted)\n", url)
	os.Stdout.Sync()
	<-ctx.Done()
	return nil
}

func mailboxURL(explicit, urlPath string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	raw, err := os.ReadFile(urlPath)
	if err != nil {
		return "", fmt.Errorf("no mailbox URL: pass --mailbox or start `ladder-fed mailbox` first (%w)", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func wormholeClient(url string) *wormhole.Client {
	return &wormhole.Client{
		AppID:                     "gvisor.dev/ladder/fed/enroll",
		RendezvousURL:             url,
		PassPhraseComponentLength: CodeWords,
	}
}

// EnrollOffer is the NEW RUNTIME's half: prints a code, waits for the registry holder.
func EnrollOffer(ctx context.Context, keyPath, addr, url string, timeout time.Duration) error {
	id, runtimeVersion, epoch, err := LoadIdentity(keyPath)
	if err != nil {
		return err
	}
	rec := enrollRecord{
		Host:           id.Host,
		Key:            PubB64(id.Pub),
		Address:        addr,
		RuntimeVersion: runtimeVersion,
		PolicyEpoch:    epoch,
	}
	rec.SelfSig = base64.StdEncoding.EncodeToString(ed25519.Sign(id.Priv, rec.signingBytes()))
	blob, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	// A timeout is NOT optional. wormhole-william's rendezvous client never consumes
	// server error frames, so every server-side rejection -- including the crowded
	// nameplate that holds a guesser to one attempt -- presents to the caller as a hang
	// rather than an error. Without a deadline the ceremony's failure mode is "it
	// stopped", which is the worst thing an enrolment tool can do.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c := wormholeClient(url)
	code, status, err := c.SendText(ctx, string(blob))
	if err != nil {
		return fmt.Errorf("starting the ceremony: %w", err)
	}
	fmt.Printf("ENROLL-CODE %s\n", code)
	fmt.Printf("ENROLL-OFFER host=%s key=%s runtime=%s epoch=%d addr=%s\n",
		rec.Host, Fingerprint(id.Pub), rec.RuntimeVersion, rec.PolicyEpoch, rec.Address)
	fmt.Println("ENROLL-WAIT read that code to the registry holder; it is the only human step, ever")
	os.Stdout.Sync()

	select {
	case s := <-status:
		if !s.OK {
			return fmt.Errorf("ceremony failed: %v", s.Error)
		}
	case <-ctx.Done():
		return fmt.Errorf("ceremony timed out after %s", timeout)
	}
	fmt.Println("ENROLL-DONE the registry holder has this runtime's key")
	return nil
}

// EnrollAccept is the REGISTRY HOLDER's half: takes the code, appends to the registry.
func EnrollAccept(ctx context.Context, code, registryPath, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c := wormholeClient(url)
	msg, err := c.Receive(ctx, code)
	if err != nil {
		return fmt.Errorf("completing the ceremony: %w", err)
	}
	var sb strings.Builder
	if _, err := io.Copy(&sb, msg); err != nil {
		return err
	}
	var rec enrollRecord
	if err := json.Unmarshal([]byte(sb.String()), &rec); err != nil {
		return fmt.Errorf("the peer sent something that is not an enrolment record: %w", err)
	}

	pub, err := base64.StdEncoding.DecodeString(rec.Key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("the peer sent a key that is not ed25519")
	}
	sig, err := base64.StdEncoding.DecodeString(rec.SelfSig)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), rec.signingBytes(), sig) {
		// The PAKE says who you are talking to. This says they hold the private half of
		// what they just handed you. Both, or the registry records a key its owner
		// cannot use and every later handshake fails for a reason nobody can find.
		return fmt.Errorf("the record is not signed by the key it carries")
	}

	reg, err := LoadRegistry(registryPath)
	if err != nil {
		return err
	}
	entry := Entry{
		Host:           rec.Host,
		Key:            rec.Key,
		Address:        rec.Address,
		RuntimeVersion: rec.RuntimeVersion,
		PolicyEpoch:    rec.PolicyEpoch,
		EnrolledAt:     time.Now().UTC().Format(time.RFC3339),
		Ceremony:       fmt.Sprintf("spake2/magic-wormhole, %d-word code", CodeWords),
	}
	if err := reg.Append(entry); err != nil {
		return err
	}
	fmt.Printf("ENROLL-ACCEPTED host=%s key=%s runtime=%s epoch=%d addr=%s registry=%s\n",
		entry.Host, Fingerprint(ed25519.PublicKey(pub)), entry.RuntimeVersion,
		entry.PolicyEpoch, entry.Address, registryPath)
	fmt.Println("ENROLL-BASIS an operator vouched once. Nothing here attested that this host " +
		"runs the enforcement; that is the next rung.")
	return nil
}
