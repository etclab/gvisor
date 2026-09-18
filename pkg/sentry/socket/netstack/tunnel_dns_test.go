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

package netstack

import (
	"bytes"
	"strings"
	"testing"
)

// query builds one DNS question, the way a resolver on the wire does.
func query(id uint16, name string, qtype, qclass uint16, extra ...byte) []byte {
	b := []byte{
		byte(id >> 8), byte(id),
		0x01, 0x00, // RD
		0x00, 0x01, // one question
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0x00, byte(qtype>>8), byte(qtype), byte(qclass>>8), byte(qclass))
	if len(extra) > 0 {
		b[11] = 1 // one additional record
		b = append(b, extra...)
	}
	return b
}

// optRecord is a bare EDNS OPT record, which this responder ignores.
var optRecord = []byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

func counts(t *testing.T, b []byte) (qd, an, ns, ar uint16, rcode byte) {
	t.Helper()
	if len(b) < dnsHeaderLen {
		t.Fatalf("a %d byte answer is not a DNS message", len(b))
	}
	return uint16(b[4])<<8 | uint16(b[5]),
		uint16(b[6])<<8 | uint16(b[7]),
		uint16(b[8])<<8 | uint16(b[9]),
		uint16(b[10])<<8 | uint16(b[11]),
		b[3] & 0x0f
}

func testResolver(t *testing.T) *adapter {
	t.Helper()
	return testAdapter(t, `{"default_exit":"b","names":{"api.anthropic.com":{"port":443},"www.rfc-editor.org":{"port":443}}}`)
}

func TestDNSAnswersAForANameInTheTable(t *testing.T) {
	a := testResolver(t)
	q := query(0x1234, "www.rfc-editor.org", dnsTypeA, dnsClassIN)
	ans := a.answerDNS(q)
	if ans == nil {
		t.Fatal("no answer at all")
	}
	if ans[0] != 0x12 || ans[1] != 0x34 {
		t.Errorf("the answer's id is %02x%02x, wanted the query's 1234", ans[0], ans[1])
	}
	if ans[2]&0x80 == 0 {
		t.Errorf("QR is not set on the answer")
	}
	if ans[2]&0x01 == 0 {
		t.Errorf("RD was not copied from the query")
	}
	if ans[3]&0x80 == 0 {
		t.Errorf("RA is not set, so a stub resolver is told recursion is unavailable")
	}
	qd, an, ns, ar, rcode := counts(t, ans)
	if qd != 1 || an != 1 || ns != 0 || ar != 0 || rcode != dnsRcodeNoError {
		t.Fatalf("counts are qd=%d an=%d ns=%d ar=%d rcode=%d, wanted 1/1/0/0/0", qd, an, ns, ar, rcode)
	}
	// The record: a pointer to the question's name, A, IN, a TTL and the
	// address the adapter allocated for the name.
	want := []byte{
		0xc0, 0x0c,
		0x00, dnsTypeA,
		0x00, dnsClassIN,
		0x00, 0x00, 0x00, dnsTTL,
		0x00, 0x04,
		100, 64, 1, 1, // www.rfc-editor.org sorts after api.anthropic.com
	}
	if got := ans[len(ans)-len(want):]; !bytes.Equal(got, want) {
		t.Errorf("the record is % x, wanted % x", got, want)
	}
	// And the address is the one a connect must then be intercepted on.
	b, ok := a.lookupAddr(tunnelSyntheticAddr(1))
	if !ok || b.name != "www.rfc-editor.org" {
		t.Errorf("the address the answer carries is bound to %v, %t", b, ok)
	}
}

func TestDNSAnswersAAAAWithNoRecords(t *testing.T) {
	// An agent runtime asks AAAA first, every time, for every name (spike E4,
	// surprise 3). NOERROR with no records says the name exists and has no v6
	// address; NXDOMAIN would deny the name and make the A query pointless.
	a := testResolver(t)
	ans := a.answerDNS(query(1, "api.anthropic.com", dnsTypeAAAA, dnsClassIN))
	qd, an, _, _, rcode := counts(t, ans)
	if qd != 1 || an != 0 || rcode != dnsRcodeNoError {
		t.Fatalf("counts are qd=%d an=%d rcode=%d, wanted 1/0/NOERROR", qd, an, rcode)
	}
}

func TestDNSRefusesEverythingElse(t *testing.T) {
	a := testResolver(t)
	for _, tc := range []struct {
		name string
		q    []byte
	}{
		{"a name the table does not carry", query(1, "evil.example", dnsTypeA, dnsClassIN)},
		{"the same name asked for as AAAA", query(1, "evil.example", dnsTypeAAAA, dnsClassIN)},
		{"a known name asked for as MX", query(1, "api.anthropic.com", 15, dnsClassIN)},
		{"a known name in the CHAOS class", query(1, "api.anthropic.com", dnsTypeA, 3)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ans := a.answerDNS(tc.q)
			qd, an, _, _, rcode := counts(t, ans)
			if rcode != dnsRcodeNXDomain || an != 0 || qd != 1 {
				t.Fatalf("counts are qd=%d an=%d rcode=%d, wanted 1/0/NXDOMAIN", qd, an, rcode)
			}
		})
	}
}

func TestDNSIsCaseInsensitive(t *testing.T) {
	a := testResolver(t)
	ans := a.answerDNS(query(1, "API.Anthropic.COM", dnsTypeA, dnsClassIN))
	_, an, _, _, rcode := counts(t, ans)
	if an != 1 || rcode != dnsRcodeNoError {
		t.Fatalf("an=%d rcode=%d, wanted one answer and NOERROR", an, rcode)
	}
	if got := ans[len(ans)-4:]; !bytes.Equal(got, []byte{100, 64, 1, 0}) {
		t.Errorf("the address is % x, wanted 100.64.1.0", got)
	}
}

func TestDNSDropsAnOPTRecord(t *testing.T) {
	// This responder speaks no EDNS. Dropping the OPT record rather than
	// echoing it is what says so, and the answer must still be well formed.
	a := testResolver(t)
	ans := a.answerDNS(query(1, "api.anthropic.com", dnsTypeA, dnsClassIN, optRecord...))
	qd, an, ns, ar, rcode := counts(t, ans)
	if qd != 1 || an != 1 || ns != 0 || ar != 0 || rcode != dnsRcodeNoError {
		t.Fatalf("counts are qd=%d an=%d ns=%d ar=%d rcode=%d, wanted 1/1/0/0/0", qd, an, ns, ar, rcode)
	}
}

func TestDNSRejectsWhatIsNotAQuery(t *testing.T) {
	a := testResolver(t)
	if got := a.answerDNS([]byte{1, 2, 3}); got != nil {
		t.Errorf("a 3 byte datagram was answered with % x, wanted silence", got)
	}
	// A response, not a query: QR set.
	resp := query(1, "api.anthropic.com", dnsTypeA, dnsClassIN)
	resp[2] |= 0x80
	if got := a.answerDNS(resp); got != nil {
		t.Errorf("a response was answered with % x, wanted silence", got)
	}
	// Two questions: this responder reads one.
	two := query(1, "api.anthropic.com", dnsTypeA, dnsClassIN)
	two[5] = 2
	_, _, _, _, rcode := counts(t, a.answerDNS(two))
	if rcode != dnsRcodeFormErr {
		t.Errorf("a two-question query got rcode %d, wanted FORMERR", rcode)
	}
	// A compression pointer where a label belongs.
	bad := query(1, "api.anthropic.com", dnsTypeA, dnsClassIN)
	bad[dnsHeaderLen] = 0xc0
	_, _, _, _, rcode = counts(t, a.answerDNS(bad))
	if rcode != dnsRcodeFormErr {
		t.Errorf("a compressed question got rcode %d, wanted FORMERR", rcode)
	}
	// A label that runs off the end.
	short := query(1, "api.anthropic.com", dnsTypeA, dnsClassIN)
	short = short[:len(short)-6]
	_, _, _, _, rcode = counts(t, a.answerDNS(short))
	if rcode != dnsRcodeFormErr {
		t.Errorf("a truncated question got rcode %d, wanted FORMERR", rcode)
	}
}

func TestDNSQuestionName(t *testing.T) {
	q := query(1, "WWW.Example.COM", dnsTypeA, dnsClassIN)
	name, end, ok := dnsQuestionName(q)
	if !ok {
		t.Fatal("dnsQuestionName refused a well formed question")
	}
	if name != "www.example.com" {
		t.Errorf("dnsQuestionName = %q, wanted the folded spelling", name)
	}
	if end != len(q)-4 {
		t.Errorf("dnsQuestionName ended at %d, wanted %d", end, len(q)-4)
	}
}
