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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"gvisor.dev/gvisor/attest/tunnel"
	"gvisor.dev/gvisor/attest/tunneld"
)

// The two documents this command reads off the config device that no other
// package defines: the peer table, and the run configuration.
//
// Neither is security-critical and both say so here rather than leaving a
// reader to work it out. The peer table maps names to addresses, and a wrong
// address is a failed handshake and never a compromised one (CONTEXT.md, Peer
// Table). The run configuration says what this tunneld asks for; a host that
// rewrites it can stop this guest from talking to anybody, which a host that
// declines to launch it could do anyway, and cannot make it talk to a peer its
// reference value set does not admit.
//
// Both are refused on an unknown field, which is *not* the argument
// attest/refvalsfile.go makes about the trust root — an unknown field there is
// a constraint the loader cannot see. Here it is only that a misspelt field is
// a run that silently did something other than what was written down, and a
// harness whose configuration is quietly ignored records the wrong thing.

// peerTableFile is /config/peers.json.
type peerTableFile struct {
	Format  string            `json:"format"`
	Version int               `json:"version"`
	Peers   map[string]string `json:"peers"`
}

// PeerTableFormat and PeerTableVersion name what this command reads, so a file
// written for something else is refused rather than half-understood.
const (
	PeerTableFormat  = "gvisor.dev/gvisor/attest/peer-table"
	PeerTableVersion = 1
)

func loadPeerTable(path string) (map[string]string, error) {
	var f peerTableFile
	if err := readJSON(path, &f); err != nil {
		return nil, err
	}
	// The format line is optional here and required nowhere else: ticket 08's
	// harness already wrote {"peers":{}} onto a config device before this
	// command existed, and a file that names no format is that one.
	if f.Format != "" && f.Format != PeerTableFormat {
		return nil, fmt.Errorf("%s: format %q is not %q", path, f.Format, PeerTableFormat)
	}
	if f.Version != 0 && f.Version != PeerTableVersion {
		return nil, fmt.Errorf("%s: version %d is not %d", path, f.Version, PeerTableVersion)
	}
	if f.Peers == nil {
		f.Peers = map[string]string{}
	}
	return f.Peers, nil
}

// runConfig is /config/tunneld.json: everything about this run that differs
// between two guests booted from the same image. It has to be outside the
// measurement for exactly the reason the reference value set is — two guests
// that differed in a measured byte would be two images, and the whole claim
// is that both ran the same one.
type runConfig struct {
	Format  string `json:"format"`
	Version int    `json:"version"`

	// SandboxID is the unit of identity: one tunneld, one sandbox, one key.
	// Milestone 3 passes a synthetic one (CONTEXT.md, Sandbox).
	SandboxID string `json:"sandbox_id"`

	// Listen is the UDP address to accept peers on.
	Listen string `json:"listen"`

	// Link is the interface to bring up first, or absent on a host that
	// already has an address.
	Link *link `json:"link"`

	// Limits bound every tunnel's life. Two guests must be configured alike:
	// QUIC's idle timeout is the minimum of what the two peers advertise, so
	// the larger of two different values is fiction (tunnel.Limits).
	Limits *limits `json:"limits"`

	// StartTimeout bounds startup — reference value set, key, evidence,
	// listener. Zero takes a minute, which is two orders of magnitude more
	// than acquisition costs and still finite.
	StartTimeout duration `json:"start_timeout"`

	// Exercise is the stand-in agent, or absent for a tunneld that only
	// answers.
	Exercise *exercise `json:"exercise"`

	// Hold keeps this tunneld listening after the exercise, so that a peer
	// still dialing it does not lose its answerer.
	Hold duration `json:"hold"`
}

// RunConfigFormat and RunConfigVersion name what this command reads.
const (
	RunConfigFormat  = "gvisor.dev/gvisor/attest/tunneld-run"
	RunConfigVersion = 1
)

type limits struct {
	IdleTimeout duration `json:"idle_timeout"`
	MaxAge      duration `json:"max_age"`
}

func loadRunConfig(path string) (*runConfig, error) {
	var c runConfig
	if err := readJSON(path, &c); err != nil {
		return nil, err
	}
	if c.Format != RunConfigFormat {
		return nil, fmt.Errorf("%s: format %q is not %q", path, c.Format, RunConfigFormat)
	}
	if c.Version != RunConfigVersion {
		return nil, fmt.Errorf("%s: version %d is not %d", path, c.Version, RunConfigVersion)
	}
	if c.SandboxID == "" {
		return nil, fmt.Errorf("%s: no sandbox_id; a tunneld is one sandbox's identity and has to be told which", path)
	}
	if c.Link != nil {
		if err := c.Link.validate(); err != nil {
			return nil, fmt.Errorf("%s: link: %w", path, err)
		}
	}
	if c.Exercise != nil {
		if err := c.Exercise.validate(); err != nil {
			return nil, fmt.Errorf("%s: exercise: %w", path, err)
		}
	}
	return &c, nil
}

func (c *runConfig) limits() tunnel.Limits {
	if c.Limits == nil {
		return tunnel.Limits{}
	}
	return tunnel.Limits{IdleTimeout: c.Limits.IdleTimeout.Duration, MaxAge: c.Limits.MaxAge.Duration}
}

func (c *runConfig) startTimeout() time.Duration {
	if c.StartTimeout.Duration > 0 {
		return c.StartTimeout.Duration
	}
	return time.Minute
}

var _ tunneld.Handler = echo("")

// duration is a time.Duration written the way a human writes one — "60s",
// "15m" — because this file is read and edited by whoever runs the harness,
// and a count of nanoseconds is not.
type duration struct{ time.Duration }

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("a duration is a string like \"60s\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

// readJSON reads path and decodes it, refusing an unknown field and trailing
// content. Both are a file that says something this command did not read.
func readJSON(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if dec.More() {
		return fmt.Errorf("reading %s: trailing content after the document", path)
	}
	return nil
}
