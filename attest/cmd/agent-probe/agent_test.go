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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

// The loop is tested against a model that is a canned script and never against
// the API: a test that needed a key would be a test that ran on one machine,
// and the whole of what this loop has to get right — the order of the tool
// calls, what travels in one message, the arithmetic, where it stops — is
// decided by bytes that a script can produce.

// script is the fake model. It answers each request with the next canned reply
// and keeps the request bodies, because what this loop must get right is as
// much what it sends as what it does with what comes back.
type script struct {
	// host is where the fake model listens, which is what the CONNECT line
	// carries when the loop runs behind the contract.
	host string

	// turns counts the requests as they arrive, so that a test can say how
	// many the loop made without taking the lock the bodies are under.
	turns atomic.Int64

	mu      sync.Mutex
	replies []string
	bodies  [][]byte
}

func (s *script) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.turns.Add(1)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bodies = append(s.bodies, body)
	if len(s.replies) == 0 {
		http.Error(w, `{"error":"the script has no reply for this request"}`, http.StatusInternalServerError)
		return
	}
	reply := s.replies[0]
	s.replies = s.replies[1:]
	w.Header().Set("content-type", "application/json")
	io.WriteString(w, reply)
}

// sent is the nth request the loop made, decoded far enough to see the
// conversation it carried.
func (s *script) sent(t *testing.T, n int) []message {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if n >= len(s.bodies) {
		t.Fatalf("the loop made %d requests; there is no request %d", len(s.bodies), n+1)
	}
	var req struct {
		Messages []message `json:"messages"`
	}
	if err := json.Unmarshal(s.bodies[n], &req); err != nil {
		t.Fatalf("request %d is not JSON: %v", n+1, err)
	}
	return req.Messages
}

// canned starts the fake model and points the loop at it for this test only.
func canned(t *testing.T, replies ...string) *script {
	t.Helper()
	t.Setenv("ANTHROPIC_API_KEY", "this-is-not-a-key")
	s := &script{replies: replies}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.host = srv.Listener.Addr().String()
	was := modelEndpoint
	modelEndpoint = srv.URL + "/v1/messages"
	t.Cleanup(func() { modelEndpoint = was })
	return s
}

// The canned turns, in the shapes the API sends them.

func turn(stop string, in, out int, blocks ...string) string {
	return fmt.Sprintf(`{"stop_reason":%q,"content":[%s],"usage":{"input_tokens":%d,"output_tokens":%d}}`,
		stop, strings.Join(blocks, ","), in, out)
}

func turnUsing(in, out int, blocks ...string) string {
	return turn("tool_use", in, out, blocks...)
}

func use(id, name, input string) string {
	return fmt.Sprintf(`{"type":"tool_use","id":%q,"name":%q,"input":%s}`, id, name, input)
}

func endTurn(in, out int, text string) string {
	return turn("end_turn", in, out, fmt.Sprintf(`{"type":"text","text":%q}`, text))
}

// document is something for fetch_url to fetch that is not the model: its URL,
// and the host and port an exit would be asked to dial for it.
func document(t *testing.T, text string) (string, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, text)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, srv.Listener.Addr().String()
}

func TestTheLoopRunsTheToolCallsTheModelAsksForInOrderAndPricesTheRun(t *testing.T) {
	doc, _ := document(t, "RFC 8446 defines TLS 1.3.")
	work := t.TempDir()
	s := canned(t,
		turnUsing(100, 20, use("tu_1", "fetch_url", `{"url":"`+doc+`/rfc8446.txt"}`)),
		turnUsing(200, 30, use("tu_2", "write_file", `{"path":"summary.txt","content":"TLS 1.3, in one sentence."}`)),
		endTurn(300, 40, "DONE"))

	var out bytes.Buffer
	res, err := Run(context.Background(), http.DefaultClient, Summarize(), Tools{FetchURL: true, WriteDir: work}, &out)
	if err != nil {
		t.Fatalf("the loop: %v", err)
	}

	want := []string{"fetch_url(" + doc + "/rfc8446.txt)", "write_file(summary.txt)"}
	if got := res.Calls; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("the tool calls were %q; want %q", got, want)
	}
	if s.turns.Load() != 3 {
		t.Errorf("the loop made %d requests; want 3", s.turns.Load())
	}
	if res.InputTokens != 600 || res.OutputTokens != 90 {
		t.Errorf("the totals are input=%d output=%d; want 600 and 90", res.InputTokens, res.OutputTokens)
	}
	// 600 input at $2/M and 90 output at $10/M, which is the arithmetic the
	// record quotes and the only reason the rates are in the source.
	if wantCost := 0.0012 + 0.0009; math.Abs(res.Cost-wantCost) > 1e-9 {
		t.Errorf("the run cost $%.6f; want $%.6f", res.Cost, wantCost)
	}
	if res.Final != "DONE" {
		t.Errorf("the final text is %q; want DONE", res.Final)
	}
	if res.ToolError {
		t.Error("a tool reported an error; none of them failed")
	}
	summary, err := os.ReadFile(filepath.Join(work, "summary.txt"))
	if err != nil {
		t.Fatalf("write_file wrote nothing into -dir: %v", err)
	}
	if got := string(summary); got != "TLS 1.3, in one sentence." {
		t.Errorf("summary.txt holds %q", got)
	}
	// The transcript is the record: one line per request and one per tool
	// call, and the run above had three and two.
	if len(res.Transcript) != 5 {
		t.Errorf("the transcript is %d lines; want 5:\n%s", len(res.Transcript), strings.Join(res.Transcript, "\n"))
	}
}

func TestEveryToolResultOfOneTurnGoesBackInOneUserMessage(t *testing.T) {
	doc, _ := document(t, "RFC 8446 defines TLS 1.3.")
	work := t.TempDir()
	s := canned(t,
		turnUsing(10, 5,
			use("tu_1", "fetch_url", `{"url":"`+doc+`/rfc8446.txt"}`),
			use("tu_2", "write_file", `{"path":"summary.txt","content":"one"}`)),
		endTurn(20, 6, "DONE"))

	if _, err := Run(context.Background(), http.DefaultClient, Summarize(), Tools{FetchURL: true, WriteDir: work}, io.Discard); err != nil {
		t.Fatalf("the loop: %v", err)
	}

	messages := s.sent(t, 1)
	if len(messages) != 3 {
		t.Fatalf("the second request carried %d messages; want the task, the assistant turn and one user message", len(messages))
	}
	if messages[2].Role != "user" {
		t.Fatalf("the third message is a %q; want a user message", messages[2].Role)
	}
	blocks := resultsIn(t, messages[2])
	if len(blocks) != 2 {
		t.Fatalf("the user message carried %d tool_result blocks; want both of the turn's", len(blocks))
	}
	for i, b := range blocks {
		if b.Type != "tool_result" {
			t.Errorf("block %d is a %q", i+1, b.Type)
		}
	}
	if blocks[0].ToolUseID != "tu_1" || blocks[1].ToolUseID != "tu_2" {
		t.Errorf("the results answer %q and %q; want tu_1 and tu_2", blocks[0].ToolUseID, blocks[1].ToolUseID)
	}
}

func TestARefusalStopsTheLoopWithAnErrorThatNamesIt(t *testing.T) {
	s := canned(t, `{"stop_reason":"refusal","stop_details":{"type":"refusal"},"content":[],"usage":{"input_tokens":7,"output_tokens":1}}`)

	var out bytes.Buffer
	res, err := Run(context.Background(), http.DefaultClient, Summarize(), Tools{FetchURL: true, WriteDir: t.TempDir()}, &out)
	if !errors.Is(err, ErrModelRefused) {
		t.Fatalf("the loop returned %v; want ErrModelRefused", err)
	}
	if s.turns.Load() != 1 {
		t.Errorf("the loop made %d requests after a refusal; want 1", s.turns.Load())
	}
	// A run that stopped still says what it spent.
	if res.InputTokens != 7 || res.Cost == 0 {
		t.Errorf("the refused run reports input=%d cost=$%f; want the one turn it paid for", res.InputTokens, res.Cost)
	}
}

func TestADelegateResultWithAToolErrorInTheFarTranscriptIsAnError(t *testing.T) {
	// What the far side said: it ran, it was denied one destination, and its
	// model worked around the denial and finished. Exactly E4's case (ii).
	transcript := "RUN accepted\n" +
		"request 1: stop_reason=tool_use input_tokens=1000 output_tokens=60 in 2100ms\n" +
		"  tool_use fetch_url {\"url\":\"https://www.rfc-editor.org/rfc/rfc8446.txt\"} -> 84 bytes, is_error=true\n" +
		"TOOL_ERROR fetch_url: NotCapable: Requires net access to \"www.rfc-editor.org\"\n" +
		"final text: DONE\n"

	s := canned(t,
		turnUsing(50, 10, use("tu_1", "delegate", `{"peer":"b"}`)),
		endTurn(60, 12, "DONE"))

	res, err := Run(context.Background(), http.DefaultClient, Delegate("b"),
		Tools{Delegate: farSide(t, transcript)}, io.Discard)
	if err != nil {
		t.Fatalf("the loop: %v", err)
	}
	if !res.ToolError {
		t.Error("the delegate result was not an error; a TOOL_ERROR line in the far transcript is one")
	}
	blocks := resultsIn(t, s.sent(t, 1)[2])
	if len(blocks) != 1 {
		t.Fatalf("the second request carried %d tool_result blocks; want one", len(blocks))
	}
	if !blocks[0].IsError {
		t.Error("the tool_result went back with is_error false; the model must be told its request failed")
	}
	if !strings.Contains(blocks[0].Content, "TOOL_ERROR fetch_url") {
		t.Errorf("the model was told %q; it must be the far side's own transcript", clip(blocks[0].Content, 200))
	}
	// And nothing else travelled: no peer, no measurement, no reason.
	for _, word := range []string{"measurement", "policy_digest", "vendor", "refus"} {
		if strings.Contains(strings.ToLower(blocks[0].Content), word) {
			t.Errorf("the tool result mentions %q; the near model sees a tool error and nothing about trust", word)
		}
	}
}

// farSide is a delegate that answers RUN with a fixed transcript, over one end
// of a socketpair: the far agent's process is not what this test is about, and
// the stream is the only thing the tool touches.
func farSide(t *testing.T, transcript string) func(context.Context, string) (sandbox.Stream, error) {
	t.Helper()
	return func(context.Context, string) (sandbox.Stream, error) {
		near, far, err := streamPair()
		if err != nil {
			return nil, err
		}
		go func() {
			defer far.Close()
			request := make([]byte, len("RUN\n"))
			if _, err := io.ReadFull(far, request); err != nil {
				return
			}
			io.WriteString(far, transcript)
			far.CloseWrite()
		}()
		return near, nil
	}
}

// resultsIn is the tool_result blocks of one user message.
func resultsIn(t *testing.T, m message) []toolResult {
	t.Helper()
	raw, err := json.Marshal(m.Content)
	if err != nil {
		t.Fatalf("the message content: %v", err)
	}
	var blocks []toolResult
	if err := json.Unmarshal(raw, &blocks); err != nil {
		t.Fatalf("the message content is not tool_result blocks: %v", err)
	}
	return blocks
}

// deadline is how long a test waits for something that should be immediate.
const deadline = 10 * time.Second
