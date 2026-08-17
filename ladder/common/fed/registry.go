// registry.go - the enrollment registry: the list of runtime keys this host will talk to.
//
// Rung 5a, spec section 2 ("Enroll"). This file is the entire trust root of the
// federation, and it is a text file. That is not an accident of prototyping -- it is
// the rung's crack, stated as a data structure:
//
//	Keys are trusted by CEREMONY, not by ATTESTATION. A line in this file means an
//	operator once stood at a keyboard and completed a PAKE with whoever was on the other
//	end. It does not mean the peer runs the patched runtime, that it enforces anything,
//	or that it has not been compromised since. A hostile-but-enrolled host can stamp
//	lies, and every check in envelope.go will pass.
//
// Distribution and revocation are manual, deliberately: automating either would need
// exactly the thing the next rung is about (attestation evidence, admission-time or
// per-connection), and faking it here would make the crack invisible.
//
// # Format
//
// One JSON object per line, comments allowed on lines beginning with '#'. Append-only in
// practice; the demo rewrites it between blocks because it stands up a fresh federation
// each time.
//
//	{"host":"hosta","key":"<base64 ed25519 public key>","runtime_version":"...",
//	 "policy_epoch":1,"enrolled_at":"2026-08-17T11:04:22Z","ceremony":"spake2"}
//
// runtime_version and policy_epoch are carried because section 2 asks the ceremony to
// exchange them. Nothing in rung 5a ENFORCES them -- and the README says so rather than
// letting two unused fields imply a check that is not there. They are the slot the
// attestation rung fills: a measured runtime identity belongs exactly where a
// self-asserted version string sits today.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// Entry is one enrolled runtime.
type Entry struct {
	Host string `json:"host"`
	Key  string `json:"key"`
	// Address is where to reach that host's proxy. It is here rather than in a separate
	// config because "who I trust" and "where they are" are learned in the same
	// ceremony; note that it is NOT security-relevant -- a wrong address fails to
	// connect, and a right address to the wrong key fails the handshake.
	Address        string `json:"address,omitempty"`
	RuntimeVersion string `json:"runtime_version,omitempty"`
	PolicyEpoch    int    `json:"policy_epoch,omitempty"`
	EnrolledAt     string `json:"enrolled_at,omitempty"`
	Ceremony       string `json:"ceremony,omitempty"`
}

// PublicKey decodes the entry's key.
func (e Entry) PublicKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(e.Key)
	if err != nil {
		return nil, fmt.Errorf("host %q: key is not base64: %w", e.Host, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("host %q: key is %d bytes, ed25519 public keys are %d",
			e.Host, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Fingerprint is the short name for a key in logs. sha256 of the raw key, hex, first 16.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

// Registry is an immutable snapshot plus the lookups the transport needs. Both lookups
// are by KEY as well as by name, because the handshake learns a key and has to decide
// whether to continue before any name has been exchanged.
type Registry struct {
	mu      sync.RWMutex
	path    string
	byHost  map[string]Entry
	byKeyID map[string]Entry // raw key bytes as a map key
}

// LoadRegistry reads the file. A missing file is an empty registry, not an error: a host
// that has enrolled nobody should refuse everyone, which is what an empty registry does.
func LoadRegistry(path string) (*Registry, error) {
	r := &Registry{path: path, byHost: map[string]Entry{}, byKeyID: map[string]Entry{}}
	fh, err := os.Open(path)
	if os.IsNotExist(err) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	scan := bufio.NewScanner(fh)
	scan.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for scan.Scan() {
		line++
		text := strings.TrimSpace(scan.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if e.Host == "" {
			return nil, fmt.Errorf("%s:%d: entry has no host", path, line)
		}
		pub, err := e.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		r.byHost[e.Host] = e
		r.byKeyID[string(pub)] = e
	}
	return r, scan.Err()
}

// Append adds an entry and rewrites the file. Used only by the enrollment ceremony.
func (r *Registry) Append(e Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	pub, err := e.PublicKey()
	if err != nil {
		return err
	}
	r.byHost[e.Host] = e
	r.byKeyID[string(pub)] = e

	fh, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	blob, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = fh.Write(append(blob, '\n'))
	return err
}

// ByHost looks an entry up by its enrolled name.
func (r *Registry) ByHost(host string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byHost[host]
	return e, ok
}

// ByKey is the handshake's question, and the only one that decides whether a connection
// lives: "is the key on the other end one an operator enrolled?" No name, no chain, no
// expiry, no CA. The answer is a map lookup, and the demo's impostor fails it.
func (r *Registry) ByKey(pub ed25519.PublicKey) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byKeyID[string(pub)]
	return e, ok
}

// Hosts lists enrolled names, sorted, for logging.
func (r *Registry) Hosts() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byHost))
	for h := range r.byHost {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Len is how many runtimes this host has enrolled.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byHost)
}
