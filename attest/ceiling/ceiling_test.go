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

package ceiling_test

import (
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/attest/ceiling"
)

// recordedCeiling is the file spike E3 installed into a namespace of its own and
// ran the unmodified ticket 19 egress probe against, and whose SHA-256 the
// record published. The text this package compiles in is that file, so the
// evidence and the binary name the same rule set.
const recordedCeiling = "../../docs/snp/evidence/ticket22/spikes/E3/ceiling.nft"

// recordedDigest is what that record published
// (docs/snp/evidence/ticket22/spikes/E3/out/ceiling.nft.sha256).
const recordedDigest = "197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973"

// The whole point of a compiled-in ceiling is that a verifier who has read the
// image knows which rule set the guest came up with. That holds only while the
// text in the binary and the text in the record are the same bytes — not the
// same rules, the same bytes, because the digest covers the commentary too and
// the commentary is the justification.
func TestTheCompiledInCeilingIsTheRecordedOne(t *testing.T) {
	recorded, err := os.ReadFile(recordedCeiling)
	if err != nil {
		t.Fatalf("reading the recorded ceiling: %v", err)
	}
	if got := ceiling.Text(); got != string(recorded) {
		t.Errorf("the compiled-in ceiling is not the recorded one.\ncompiled in (%d bytes):\n%s\nrecorded (%d bytes):\n%s",
			len(got), got, len(recorded), recorded)
	}
}

// The digest is the number a peer's policy_digest names and the number the
// guest prints at boot, so it is written down here as digits rather than
// recomputed: a test that hashes the same bytes the code hashes would agree
// with any edit at all.
func TestTheDigestIsTheNameTheRecordPublished(t *testing.T) {
	if got := ceiling.DigestHex(); got != recordedDigest {
		t.Errorf("the ceiling's digest is %s, and the record published %s", got, recordedDigest)
	}
	d := ceiling.Digest()
	if len(d) != 32 {
		t.Errorf("a digest of %d bytes is not a SHA-256", len(d))
	}
}

// The two values that vary per image build have to appear in the text, because
// the text is what a reader checks them against: a constant nobody can see in
// the description is a constant nobody audits.
func TestTheTwoCompiledInValuesAreInTheText(t *testing.T) {
	for _, want := range []string{
		`iifname "` + ceiling.Interface + `"`,
		`oifname "` + ceiling.Interface + `"`,
		"udp dport 4433",
		"udp sport 4433",
	} {
		if !strings.Contains(ceiling.Text(), want) {
			t.Errorf("the ceiling's text does not contain %q", want)
		}
	}
	if ceiling.Port != 4433 {
		t.Errorf("the port constant is %d and the text says 4433", ceiling.Port)
	}
	// And no rule may name anything that would have had to come off the config
	// device. The rules are read apart from the commentary here, because the
	// commentary's whole job is to discuss the things the rules may not name.
	// The metadata block is the one address among them and it is there to be
	// refused.
	for _, line := range strings.Split(ceiling.Text(), "\n") {
		rule := strings.TrimSpace(line)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}
		for _, forbidden := range []string{"10.128.0.", "peers.json", "policy.json", "sandbox"} {
			if strings.Contains(rule, forbidden) {
				t.Errorf("the ceiling's rule %q names %q, which nothing inside the launch measurement can know", rule, forbidden)
			}
		}
	}
}
