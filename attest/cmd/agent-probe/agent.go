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
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
)

// The loop is spike E1's, promoted. Nothing about how it talks to the model
// changed on the way here: the same model id, the same task, the same manual
// tool loop, the same arithmetic. What is new is that the tools it may be
// given are three rather than two, that the transcript is a value a caller can
// read rather than only lines on a terminal, and that the *http.Client is
// somebody else's business (see network.go) — which is the whole of what this
// study is measuring.

// What the model is, fixed here so that two runs of this binary are two runs
// of the same thing. The ticket asks for the model id, the prompts and the
// cost in the record; a constant is the only way a record of one run says
// anything about the next.
const (
	model      = "claude-sonnet-5"
	maxTokens  = 4096
	apiVersion = "2023-06-01"

	// fetchCap is how much of a fetched document the model is shown before it
	// is truncated: enough of RFC 8446 to summarise, and a bound on what one
	// tool call can put in the next request.
	fetchCap = 20 << 10

	// Dollars per million tokens for claude-sonnet-5, which is what the run's
	// cost line is computed from and why the rates are printed beside it.
	inputPerM  = 2.00
	outputPerM = 10.00
)

// There is no system prompt. The task is the whole of what the model is told,
// so the prompt in the record is the prompt that ran; if one is ever needed it
// belongs here, beside the task strings, and not at the command line.

// summarizePrompt is E1's task, verbatim — byte-identical to spikeTask in
// docs/snp/evidence/ticket23/spikes/E1/agent.go, so that this binary's runs
// are comparable with the four spikes' runs.
const summarizePrompt = "Fetch the document at https://www.rfc-editor.org/rfc/rfc8446.txt, write a summary of it in at most five sentences, and save the summary to the file summary.txt in the current directory using write_file. Then reply with the word DONE."

// delegatePrompt is the second task and the only one that needs a peer: the
// agent's own work is to ask another agent to do the work and to hand back
// what it said. "Verbatim, and nothing else" is not politeness — the far
// side's transcript is the evidence, and a model that summarised it would have
// thrown the evidence away.
const delegatePrompt = "Ask peer %s to run its task by calling delegate exactly once, then reply with the complete text it returned, verbatim, and nothing else."

// modelEndpoint is the one destination this agent has of its own. It is a var
// and not a const for one reason: the tests point the loop at an httptest
// server playing a canned script, and a loop that could only be exercised
// against the real API would be a loop with no tests at all.
var modelEndpoint = "https://api.anthropic.com/v1/messages"

// The three tools, as the JSON the API takes. fetch_url and write_file are
// E1's, unchanged. delegate is ticket 23's, and it is the hop: it is the only
// tool whose work happens in another process behind another sandbox.
const (
	fetchURLTool = `{"name":"fetch_url",
   "description":"HTTP GET a URL and return the response body as text, truncated to about 20 KB.",
   "input_schema":{"type":"object","properties":{"url":{"type":"string","description":"An absolute http or https URL."}},"required":["url"]}}`

	writeFileTool = `{"name":"write_file",
   "description":"Write text to a file, creating or truncating it.",
   "input_schema":{"type":"object","properties":{"path":{"type":"string","description":"The file to write."},"content":{"type":"string","description":"What to write."}},"required":["path","content"]}}`

	delegateTool = `{"name":"delegate",
   "description":"Ask a named peer to run its own task and return everything it says.",
   "input_schema":{"type":"object","properties":{"peer":{"type":"string","description":"The name of the peer to ask."}},"required":["peer"]}}`
)

// The errors this loop stops on that are not a failure of the machinery. Both
// are guarded because E1 guarded them: a refusal and a truncated turn each
// leave the conversation in a state where sending it back would be asking the
// model to continue something it did not finish.
var (
	// ErrModelRefused is stop_reason "refusal".
	ErrModelRefused = errors.New("agent-probe: the model refused, stop_reason refusal")

	// ErrMaxTokens is stop_reason "max_tokens": the turn is cut off mid-word.
	ErrMaxTokens = errors.New("agent-probe: the turn hit max_tokens and is truncated")

	// ErrNoKey is the key this agent never holds a copy of. It comes from the
	// environment on every run and is written down nowhere.
	ErrNoKey = errors.New("agent-probe: ANTHROPIC_API_KEY is not set")
)

// A Task is one of the two things this agent is ever asked to do. Both are
// fixed in this file; -task picks one and nothing at the command line can
// change the words.
type Task struct {
	// Name is what -task takes and what the record calls the run.
	Name string

	// Prompt is the user message the conversation starts from.
	Prompt string
}

// Summarize is E1's three-step task: fetch a document, summarise it, write the
// summary to a file.
func Summarize() Task {
	return Task{Name: "summarize", Prompt: summarizePrompt}
}

// Delegate is the task that makes this agent a hop: ask the named peer for its
// task and repeat what came back.
func Delegate(peer string) Task {
	return Task{Name: "delegate", Prompt: fmt.Sprintf(delegatePrompt, peer)}
}

// Tools is what the at most three tools need, and which of them the model is
// offered at all: an unconfigured tool is not in the request, so a task cannot
// be answered with a tool this process could not have run.
type Tools struct {
	// FetchURL offers fetch_url, over the same *http.Client the model requests
	// go over. Sharing the client is not a convenience: -network is only worth
	// measuring if a tool's fetch takes the same path as the request that
	// asked for it, which is what E2 measured and E1 did not have to.
	FetchURL bool

	// WriteDir offers write_file and is what a relative path is resolved
	// against; an absolute one is used as given, as E1's was. An empty WriteDir
	// leaves write_file out.
	WriteDir string

	// Delegate offers delegate: one stream to the peer the model names. It is
	// a function and not a sandbox.Network because what the contract gives
	// this binary differs per -network, and because a test can hand it a
	// stream that came from nowhere.
	Delegate func(ctx context.Context, peer string) (sandbox.Stream, error)
}

// Result is what one run of the loop leaves behind.
type Result struct {
	// Transcript is one line per model request and one per tool call, in the
	// style E1 printed and for E1's reason: the record of a run is the
	// evidence, and a line written for a human is a line that can be pasted
	// into one. The same lines go to Run's io.Writer as they are made.
	Transcript []string

	// Calls names the tool calls in order — the tool, and the argument that
	// decides what it reaches.
	Calls []string

	// InputTokens and OutputTokens are the totals over every request.
	InputTokens, OutputTokens int

	// Cost is those totals in dollars at the rates above. It is kept current
	// after every request, so a run that ends in an error still says what it
	// spent.
	Cost float64

	// Final is the model's last text block.
	Final string

	// ToolError is true when any tool_result went back is_error. It is not an
	// error of the run: a tool that failed is something the model reads and
	// answers, which is the whole of how a far side's denied resource reaches
	// this side.
	ToolError bool
}

// Run runs one task to completion over client, printing the transcript to out
// as it goes.
//
// The client is the only thing that differs between -network direct, plain,
// null and socket, and the loop cannot tell which it was given. That is deliberate and
// it is what E2 established: an agent behind the contract is an agent with a
// different DialContext and no other change at all.
func Run(ctx context.Context, client *http.Client, task Task, tools Tools, out io.Writer) (Result, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return Result{}, ErrNoKey
	}
	defs, err := tools.defs()
	if err != nil {
		return Result{}, err
	}
	r := &run{client: client, tools: tools, out: out, key: key}
	messages := []message{{Role: "user", Content: task.Prompt}}
	began := time.Now()
	fmt.Fprintf(out, "model=%s max_tokens=%d endpoint=%s\n", model, maxTokens, modelEndpoint)
	fmt.Fprintf(out, "task=%s\nprompt=%q\n\n", task.Name, task.Prompt)

	for turn := 1; ; turn++ {
		rep, err := r.ask(ctx, turn, defs, messages)
		if err != nil {
			return r.res, err
		}
		if err := r.guard(rep); err != nil {
			return r.res, err
		}
		// The assistant turn goes back as the raw blocks it arrived as, so a
		// block this agent does not understand survives the round trip.
		messages = append(messages, message{Role: "assistant", Content: rep.Content})
		if rep.StopReason != "tool_use" {
			r.finish(rep)
			break
		}
		results := r.callAll(ctx, rep)
		if len(results) == 0 {
			return r.res, fmt.Errorf("agent-probe: request %d: stop_reason tool_use with no tool_use block", turn)
		}
		// Every tool_result for one assistant turn goes back in one user
		// message. Anthropic's API requires it, and a loop that sent one
		// message per result would be a different conversation.
		messages = append(messages, message{Role: "user", Content: results})
	}
	r.summary(began)
	return r.res, nil
}

// The words a run made without the model is read by, and the gap it leaves
// where the model's first answer would have been.
const (
	// withoutModelMarker is the last line such a run writes. It is the marker
	// the loopback harness asserts on, and it is not the model's "DONE": a
	// transcript that never reached a model must not end in the word a
	// transcript that did ends in.
	withoutModelMarker = "NO-MODEL DONE"

	// withoutModelPause is how long this mode waits between the request to the
	// model endpoint and the document fetch. A model's first answer takes
	// seconds, and two of the governed runs are built on that: the narrowed run
	// pushes a policy that removes the document host after the first stream has
	// been accepted, and needs a second stream opened afterwards for the
	// refusal to be observable at all. Five seconds is the push's round trip
	// with room over it, and it is printed so that a reader of the transcript
	// knows the gap is this constant and not a model thinking.
	withoutModelPause = 5 * time.Second
)

// summarizeDoc is the document summarizePrompt names. The two are written twice
// because the prompt is byte-identical to spike E1's and must stay so, and a run
// made without the model has to fetch what the prompt asked for rather than what
// a model chose: a change to one is a change to both.
const summarizeDoc = "https://www.rfc-editor.org/rfc/rfc8446.txt"

// RunWithoutModel runs the task with the one step that needs a key left out, and
// reports what every other step really did.
//
// It is explicit and never a fallback. [Run] with no key in the environment
// still stops at [ErrNoKey]; this is reached only because a caller asked for it
// (agent-probe's -without-model), so a transcript made this way cannot be
// mistaken for one made with a model by anybody reading how it was started.
//
// What it proves is each leg of the path, measured:
//
//   - The model endpoint is requested for real, over the same client and
//     therefore over the same tunnel, with the request body the loop builds and
//     with no key header. What comes back is the API's own answer to an
//     unauthenticated request, and the status printed is the status received —
//     which is what says the stream crossed the tunnel and the exit dialled the
//     model's host and port.
//   - The document is fetched the way fetch_url fetches it, over the same
//     client, and the status and the byte count printed are the ones measured.
//   - write_file writes a file that says what it is.
//
// Nothing here is presented as something a model said. There is no token count,
// no cost, no summary and no final text, because no model was asked; the run's
// last line is [withoutModelMarker] and every number on it was measured.
func RunWithoutModel(ctx context.Context, client *http.Client, task Task, tools Tools, out io.Writer) (Result, error) {
	defs, err := tools.defs()
	if err != nil {
		return Result{}, err
	}
	r := &run{client: client, tools: tools, out: out}
	began := time.Now()
	fmt.Fprintf(out, "WITHOUT-MODEL no model is called in this run and no key is read: the request to %s carries "+
		"the body the loop builds and no x-api-key header, so the status it answers with is an authentication "+
		"error and what that status proves is the reach of the path and not the model's work. There are no "+
		"tokens, no cost and no summary below, and the gap before the document fetch is a fixed %s.\n",
		modelEndpoint, withoutModelPause)
	fmt.Fprintf(out, "task=%s\nprompt=%q\nendpoint=%s tools=%d\n\n", task.Name, task.Prompt, modelEndpoint, len(defs))

	body, err := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"tools":      defs,
		"messages":   []message{{Role: "user", Content: task.Prompt}},
	})
	if err != nil {
		return r.res, err
	}
	got, err := r.reach(ctx, http.MethodPost, modelEndpoint, body)
	if err != nil {
		// The refusal a governed run is looking for arrives here, as the
		// resolver's or the connect's own sentence, and it ends the run the way
		// a failed model request ends Run's loop.
		r.say("model endpoint %s: %v", modelEndpoint, err)
		return r.res, fmt.Errorf("agent-probe: requesting %s without a key: %w", modelEndpoint, err)
	}
	r.say("model endpoint: POST %s -> HTTP %d proto=%s %d bytes in %s; what it answered: %s",
		modelEndpoint, got.status, got.proto, got.read, got.took.Round(time.Millisecond), clip(got.body, 200))

	select {
	case <-ctx.Done():
		return r.res, ctx.Err()
	case <-time.After(withoutModelPause):
	}

	line := fmt.Sprintf("%s model_status=%d model_bytes=%d", withoutModelMarker, got.status, got.read)
	if tools.FetchURL {
		doc, err := r.reach(ctx, http.MethodGet, summarizeDoc, nil)
		switch {
		case err != nil:
			// A tool that could not reach something is what the model would
			// have been told and worked with, so it is not the end of the run.
			r.say("  tool fetch_url %s: %v", summarizeDoc, err)
			line += " doc_status=none doc_bytes=0"
		default:
			at := ""
			if doc.read == fetchCap {
				// The same bound fetch_url reads to, said out loud so that the
				// count is not read as the size of the document.
				at = fmt.Sprintf(" (the %d KiB cap fetch_url reads to)", fetchCap>>10)
			}
			r.say("  tool fetch_url %s -> HTTP %d proto=%s %d bytes%s in %s",
				summarizeDoc, doc.status, doc.proto, doc.read, at, doc.took.Round(time.Millisecond))
			line += fmt.Sprintf(" doc_status=%d doc_bytes=%d", doc.status, doc.read)
		}
	}
	if tools.WriteDir != "" {
		said, failed := r.writeFile(json.RawMessage(`{"path":"summary.txt","content":` +
			strconv.Quote("This file was written by agent-probe -without-model. No model was called in this run, "+
				"so it holds no summary of anything.\n") + `}`))
		r.say("  tool write_file summary.txt -> %s, is_error=%v", said, failed)
		r.res.ToolError = r.res.ToolError || failed
	}
	r.say("%s in %s", line, time.Since(began).Round(time.Millisecond))
	r.res.Final = line
	return r.res, nil
}

// A fetched is one request this mode made: what came back, and how much of it.
type fetched struct {
	status int
	proto  string
	read   int
	body   string
	took   time.Duration
}

// reach makes one request over the client the caller was given and measures it.
// The body is read to the same cap fetch_url reads to, and the count reported is
// the count of bytes read.
func (r *run) reach(ctx context.Context, method, url string, body []byte) (fetched, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return fetched{}, err
	}
	if body != nil {
		req.Header.Set("anthropic-version", apiVersion)
		req.Header.Set("content-type", "application/json")
	}
	started := time.Now()
	resp, err := r.client.Do(req)
	if err != nil {
		return fetched{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, fetchCap))
	if err != nil {
		return fetched{}, err
	}
	return fetched{status: resp.StatusCode, proto: resp.Proto, read: len(raw), body: string(raw), took: time.Since(started)}, nil
}

// defs is the tool definitions this Tools offers, as the API takes them.
func (t Tools) defs() ([]json.RawMessage, error) {
	var offered []string
	if t.FetchURL {
		offered = append(offered, fetchURLTool)
	}
	if t.WriteDir != "" {
		offered = append(offered, writeFileTool)
	}
	if t.Delegate != nil {
		offered = append(offered, delegateTool)
	}
	if len(offered) == 0 {
		return nil, errors.New("agent-probe: no tools are configured, so there is nothing for the model to do")
	}
	var defs []json.RawMessage
	if err := json.Unmarshal([]byte("["+strings.Join(offered, ",")+"]"), &defs); err != nil {
		return nil, fmt.Errorf("agent-probe: the tool definitions: %w", err)
	}
	return defs, nil
}

// run is one conversation: what it needs to make a request, and what it has
// recorded so far.
type run struct {
	client *http.Client
	tools  Tools
	out    io.Writer
	key    string
	res    Result
}

// say writes one transcript line, to the record and to the terminal both.
func (r *run) say(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	r.res.Transcript = append(r.res.Transcript, line)
	fmt.Fprintln(r.out, line)
}

// ask sends one request and returns the model's reply, accounting for what it
// cost on the way past.
func (r *run) ask(ctx context.Context, turn int, defs []json.RawMessage, messages []message) (reply, error) {
	body, err := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"tools":      defs,
		"messages":   messages,
	})
	if err != nil {
		return reply{}, fmt.Errorf("agent-probe: request %d: %w", turn, err)
	}
	started := time.Now()
	proto, raw, err := r.post(ctx, body)
	if err != nil {
		return reply{}, fmt.Errorf("agent-probe: request %d: %w", turn, err)
	}
	var rep reply
	if err := json.Unmarshal(raw, &rep); err != nil {
		return reply{}, fmt.Errorf("agent-probe: request %d: the response is not JSON: %w", turn, err)
	}
	r.res.InputTokens += rep.Usage.Input
	r.res.OutputTokens += rep.Usage.Output
	r.res.Cost = costOf(r.res.InputTokens, r.res.OutputTokens)
	r.say("request %d: proto=%s stop_reason=%s input_tokens=%d output_tokens=%d in %s",
		turn, proto, rep.StopReason, rep.Usage.Input, rep.Usage.Output, time.Since(started).Round(time.Millisecond))
	return rep, nil
}

// post is the one HTTP request this agent makes on its own behalf. The key
// goes in a header and nowhere else: it is read from the environment once per
// run and never written to the transcript, which is what makes the transcript
// something that can be committed.
func (r *run) post(ctx context.Context, body []byte) (string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, modelEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("x-api-key", r.key)
	req.Header.Set("anthropic-version", apiVersion)
	req.Header.Set("content-type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("reading the response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, clip(string(raw), 400))
	}
	return resp.Proto, raw, nil
}

// guard stops the loop on the two stop reasons that are answers rather than
// turns, as E1 did.
func (r *run) guard(rep reply) error {
	switch rep.StopReason {
	case "refusal":
		r.say("the model refused: %s", string(rep.StopDetails))
		return ErrModelRefused
	case "max_tokens":
		r.say("the model hit max_tokens=%d and the turn is truncated", maxTokens)
		return ErrMaxTokens
	}
	return nil
}

// finish records the model's last word.
func (r *run) finish(rep reply) {
	for _, rb := range rep.Content {
		var b block
		if json.Unmarshal(rb, &b) == nil && b.Type == "text" {
			r.res.Final = b.Text
			fmt.Fprintf(r.out, "\nfinal text: %s\n", b.Text)
		}
	}
}

// callAll runs every tool_use block of one assistant turn and returns the
// results in the order the model asked for them.
func (r *run) callAll(ctx context.Context, rep reply) []any {
	var results []any
	for _, rb := range rep.Content {
		var b block
		if err := json.Unmarshal(rb, &b); err != nil || b.Type != "tool_use" {
			continue
		}
		text, failed := r.call(ctx, b.Name, b.Input)
		r.res.Calls = append(r.res.Calls, callOf(b.Name, b.Input))
		r.res.ToolError = r.res.ToolError || failed
		r.say("  tool_use %s %s -> %d bytes, is_error=%v", b.Name, clip(string(b.Input), 120), len(text), failed)
		results = append(results, toolResult{
			Type: "tool_result", ToolUseID: b.ID, Content: text, IsError: failed,
		})
	}
	return results
}

// call executes one tool and returns what the model is told, and whether that
// is an error. Every failure comes back this way and never as a Go error: a
// tool that cannot reach something is a fact the model has to work with.
func (r *run) call(ctx context.Context, name string, input json.RawMessage) (string, bool) {
	switch {
	case name == "fetch_url" && r.tools.FetchURL:
		return r.fetchURL(ctx, input)
	case name == "write_file" && r.tools.WriteDir != "":
		return r.writeFile(input)
	case name == "delegate" && r.tools.Delegate != nil:
		return r.delegate(ctx, input)
	}
	return "no such tool: " + name, true
}

// fetchURL is E1's fetch, over whatever client -network built.
func (r *run) fetchURL(ctx context.Context, input json.RawMessage) (string, bool) {
	var in struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "fetch_url: " + err.Error(), true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, in.URL, nil)
	if err != nil {
		return "fetch_url: " + err.Error(), true
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "fetch_url: " + err.Error(), true
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, fetchCap))
	if err != nil {
		return "fetch_url: " + err.Error(), true
	}
	text := string(body)
	if len(body) == fetchCap {
		text += "\n\n[truncated at 20 KB]"
	}
	return text, resp.StatusCode != http.StatusOK
}

// writeFile is E1's write, with a directory the caller chose rather than
// whatever the process happened to be started in: -dir is what the file lands
// under, so a run leaves nothing in the tree.
func (r *run) writeFile(input json.RawMessage) (string, bool) {
	var in struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "write_file: " + err.Error(), true
	}
	path := in.Path
	if !filepath.IsAbs(path) {
		path = filepath.Join(r.tools.WriteDir, path)
	}
	if err := os.WriteFile(path, []byte(in.Content), 0o644); err != nil {
		return "write_file: " + err.Error(), true
	}
	return fmt.Sprintf("wrote %d bytes to %s", len(in.Content), in.Path), false
}

// delegate is the hop: one stream to the peer the model named, "RUN", this
// side's half closed, and everything the far side says read back as the
// tool_result.
//
// What comes back is the far agent's transcript, and this side reads it as
// text and nothing else. A resource the far side's sandbox denied appears in
// it as a TOOL_ERROR line or a non-zero exit, and that is what makes this
// tool_result an error. The model on this side is told its request failed and
// is told nothing about trust: it never sees a peer, a measurement or a
// refusal reason, because a refusal does not travel on a stream at all.
func (r *run) delegate(ctx context.Context, input json.RawMessage) (string, bool) {
	var in struct {
		Peer string `json:"peer"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "delegate: " + err.Error(), true
	}
	if in.Peer == "" {
		return "delegate: no peer was named", true
	}
	s, err := r.tools.Delegate(ctx, in.Peer)
	if err != nil {
		return "delegate: " + err.Error(), true
	}
	defer s.Close()
	if _, err := io.WriteString(s, "RUN\n"); err != nil {
		return "delegate: " + err.Error(), true
	}
	if err := s.CloseWrite(); err != nil {
		return "delegate: " + err.Error(), true
	}
	body, err := io.ReadAll(s)
	text := string(body)
	if err != nil {
		text += "\nTOOL_ERROR delegate: " + err.Error()
	}
	return text, delegateFailed(text)
}

// delegateFailed reads the far side's transcript the only way this side is
// allowed to: as text, for the markers the far side writes when a tool of its
// own failed. TOOL_ERROR is what the Deno agent in deno/agent.ts prints,
// is_error= is what this loop prints, and exit= is what a harness that waited
// for a process prints. None of the three says anything about the far side's
// policy, and this side neither has one nor asks.
func delegateFailed(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.Contains(line, "TOOL_ERROR"), strings.Contains(line, "is_error=true"):
			return true
		case strings.HasPrefix(line, "exit="):
			// "exit=0 first_tool_call=…" is the only shape that is not a
			// failure, including the shape that is not a number at all.
			status, _, _ := strings.Cut(strings.TrimPrefix(line, "exit="), " ")
			if code, err := strconv.Atoi(status); err != nil || code != 0 {
				return true
			}
		}
	}
	return false
}

// summary is the last thing a run prints: what it did, what it cost and how
// long it took, which is the record the ticket asks for.
func (r *run) summary(began time.Time) {
	fmt.Fprintf(r.out, "\ntool calls, in order:\n")
	for i, c := range r.res.Calls {
		fmt.Fprintf(r.out, "  %d. %s\n", i+1, c)
	}
	fmt.Fprintf(r.out, "\ntotals: input_tokens=%d output_tokens=%d\n", r.res.InputTokens, r.res.OutputTokens)
	fmt.Fprintf(r.out, "cost: $%.6f  (input $%.2f/M, output $%.2f/M for %s)\n",
		r.res.Cost, inputPerM, outputPerM, model)
	fmt.Fprintf(r.out, "wall time: %s\n", time.Since(began).Round(time.Millisecond))
}

// costOf prices a run at the rates above.
func costOf(in, out int) float64 {
	return float64(in)/1e6*inputPerM + float64(out)/1e6*outputPerM
}

// callOf names one tool call for the record: the tool and the argument that
// decides what it reaches.
func callOf(name string, input json.RawMessage) string {
	var in struct {
		URL  string `json:"url"`
		Path string `json:"path"`
		Peer string `json:"peer"`
	}
	json.Unmarshal(input, &in)
	for _, what := range []string{in.URL, in.Path, in.Peer} {
		if what != "" {
			return name + "(" + what + ")"
		}
	}
	return name + "()"
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// The wire types, which are as much of the API as this agent reads.

type message struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// block is as much of a content block as this agent understands. Blocks are
// sent back as the raw JSON they arrived as, so one this agent cannot read —
// a thinking block, say — survives the round trip.
type block struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type toolResult struct {
	Type      string `json:"type"`
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

type reply struct {
	StopReason  string            `json:"stop_reason"`
	StopDetails json.RawMessage   `json:"stop_details"`
	Content     []json.RawMessage `json:"content"`
	Usage       struct {
		Input  int `json:"input_tokens"`
		Output int `json:"output_tokens"`
	} `json:"usage"`
}
