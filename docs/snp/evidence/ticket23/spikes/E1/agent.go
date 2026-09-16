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

// Command agent is ticket 23's spike E1: the smallest tool-calling agent that
// does the fixed three-step task, with no sandbox and no contract anywhere
// near it, so that strace can say what a trivial agent needs from the network,
// the filesystem and exec.
//
// It is a throwaway. The agent this study ends with is attest/cmd/agent-probe;
// nothing here is imported by anything.
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
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// E1's client: the default transport, no sandbox, direct dials.
	if err := spikeRunAgent(ctx, &http.Client{}, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "agent: %v\n", err)
		os.Exit(1)
	}
}

// ===== the agent, shared verbatim by E1 and E2 =====
//
// Everything below this line is byte-identical in E1's agent.go and in E2's
// harness. The only thing that differs between the two experiments is the
// *http.Client handed to spikeRunAgent: E1 gives it one over the default
// transport, E2 gives it one whose DialContext is the sandbox contract's Open.

const (
	spikeModel     = "claude-sonnet-5"
	spikeMaxTokens = 4096
	spikeEndpoint  = "https://api.anthropic.com/v1/messages"
	spikeAPIVer    = "2023-06-01"
	spikeFetchCap  = 20 << 10 // ~20 KB of a fetched document, then truncate

	// The task, fixed here verbatim so that runs replay.
	spikeTask = "Fetch the document at https://www.rfc-editor.org/rfc/rfc8446.txt, write a summary of it in at most five sentences, and save the summary to the file summary.txt in the current directory using write_file. Then reply with the word DONE."

	// claude-sonnet-5, dollars per million tokens.
	spikeInputPerM  = 2.00
	spikeOutputPerM = 10.00
)

// spikeToolDefs are the two tools, as the JSON the API takes.
const spikeToolDefs = `[
  {"name":"fetch_url",
   "description":"HTTP GET a URL and return the response body as text, truncated to about 20 KB.",
   "input_schema":{"type":"object","properties":{"url":{"type":"string","description":"An absolute http or https URL."}},"required":["url"]}},
  {"name":"write_file",
   "description":"Write text to a file, creating or truncating it.",
   "input_schema":{"type":"object","properties":{"path":{"type":"string","description":"The file to write."},"content":{"type":"string","description":"What to write."}},"required":["path","content"]}}
]`

type spikeMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// spikeBlock is as much of a content block as this agent reads. The blocks are
// sent back to the model as the raw JSON they arrived as, so a block this
// agent does not understand — a thinking block, say — survives the round trip.
type spikeBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type spikeToolResult struct {
	Type      string `json:"type"`
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

type spikeReply struct {
	StopReason  string            `json:"stop_reason"`
	StopDetails json.RawMessage   `json:"stop_details"`
	Content     []json.RawMessage `json:"content"`
	Usage       struct {
		Input  int `json:"input_tokens"`
		Output int `json:"output_tokens"`
	} `json:"usage"`
}

// spikeRunAgent runs the fixed task to completion over hc, printing to out.
func spikeRunAgent(ctx context.Context, hc *http.Client, out io.Writer) error {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return errors.New("ANTHROPIC_API_KEY is not set")
	}
	var tools []json.RawMessage
	if err := json.Unmarshal([]byte(spikeToolDefs), &tools); err != nil {
		return fmt.Errorf("the tool definitions: %w", err)
	}

	messages := []spikeMessage{{Role: "user", Content: spikeTask}}
	var totalIn, totalOut int
	var calls []string
	began := time.Now()

	fmt.Fprintf(out, "model=%s max_tokens=%d endpoint=%s\n", spikeModel, spikeMaxTokens, spikeEndpoint)
	fmt.Fprintf(out, "task=%q\n\n", spikeTask)

	for turn := 1; ; turn++ {
		body, err := json.Marshal(map[string]any{
			"model":      spikeModel,
			"max_tokens": spikeMaxTokens,
			"tools":      tools,
			"messages":   messages,
		})
		if err != nil {
			return fmt.Errorf("request %d: %w", turn, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, spikeEndpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("request %d: %w", turn, err)
		}
		req.Header.Set("x-api-key", key)
		req.Header.Set("anthropic-version", spikeAPIVer)
		req.Header.Set("content-type", "application/json")

		started := time.Now()
		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("request %d: %w", turn, err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("request %d: reading the response: %w", turn, err)
		}
		took := time.Since(started).Round(time.Millisecond)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("request %d: HTTP %d: %s", turn, resp.StatusCode, spikeClip(string(raw), 400))
		}
		var reply spikeReply
		if err := json.Unmarshal(raw, &reply); err != nil {
			return fmt.Errorf("request %d: the response is not JSON: %w", turn, err)
		}
		totalIn += reply.Usage.Input
		totalOut += reply.Usage.Output
		fmt.Fprintf(out, "request %d: proto=%s stop_reason=%s input_tokens=%d output_tokens=%d in %s\n",
			turn, resp.Proto, reply.StopReason, reply.Usage.Input, reply.Usage.Output, took)

		switch reply.StopReason {
		case "refusal":
			fmt.Fprintf(out, "the model refused: %s\n", string(reply.StopDetails))
			return errors.New("stop_reason refusal")
		case "max_tokens":
			fmt.Fprintf(out, "the model hit max_tokens=%d and the turn is truncated\n", spikeMaxTokens)
			return errors.New("stop_reason max_tokens")
		}

		// The assistant turn goes back as the raw blocks it arrived as.
		messages = append(messages, spikeMessage{Role: "assistant", Content: reply.Content})

		if reply.StopReason != "tool_use" {
			for _, rb := range reply.Content {
				var b spikeBlock
				if json.Unmarshal(rb, &b) == nil && b.Type == "text" {
					fmt.Fprintf(out, "\nfinal text: %s\n", b.Text)
				}
			}
			break
		}

		var results []any
		for _, rb := range reply.Content {
			var b spikeBlock
			if err := json.Unmarshal(rb, &b); err != nil || b.Type != "tool_use" {
				continue
			}
			text, failed := spikeRunTool(ctx, hc, b.Name, b.Input)
			calls = append(calls, spikeCallOf(b.Name, b.Input))
			fmt.Fprintf(out, "  tool_use %s %s -> %d bytes, is_error=%v\n",
				b.Name, spikeClip(string(b.Input), 120), len(text), failed)
			results = append(results, spikeToolResult{
				Type: "tool_result", ToolUseID: b.ID, Content: text, IsError: failed,
			})
		}
		if len(results) == 0 {
			return fmt.Errorf("request %d: stop_reason tool_use with no tool_use block", turn)
		}
		// Every tool_result for one assistant turn goes back in one user message.
		messages = append(messages, spikeMessage{Role: "user", Content: results})
	}

	cost := float64(totalIn)/1e6*spikeInputPerM + float64(totalOut)/1e6*spikeOutputPerM
	fmt.Fprintf(out, "\ntool calls, in order:\n")
	for i, c := range calls {
		fmt.Fprintf(out, "  %d. %s\n", i+1, c)
	}
	fmt.Fprintf(out, "\ntotals: input_tokens=%d output_tokens=%d\n", totalIn, totalOut)
	fmt.Fprintf(out, "cost: $%.6f  (input $%.2f/M, output $%.2f/M for %s)\n",
		cost, spikeInputPerM, spikeOutputPerM, spikeModel)
	fmt.Fprintf(out, "wall time: %s\n", time.Since(began).Round(time.Millisecond))
	return nil
}

// spikeRunTool executes one tool call and returns what the model is told, and
// whether that is an error.
func spikeRunTool(ctx context.Context, hc *http.Client, name string, input json.RawMessage) (string, bool) {
	switch name {
	case "fetch_url":
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
		resp, err := hc.Do(req)
		if err != nil {
			return "fetch_url: " + err.Error(), true
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, spikeFetchCap))
		if err != nil {
			return "fetch_url: " + err.Error(), true
		}
		text := string(body)
		if len(body) == spikeFetchCap {
			text += "\n\n[truncated at 20 KB]"
		}
		return text, resp.StatusCode != http.StatusOK

	case "write_file":
		var in struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return "write_file: " + err.Error(), true
		}
		if err := os.WriteFile(in.Path, []byte(in.Content), 0o644); err != nil {
			return "write_file: " + err.Error(), true
		}
		return fmt.Sprintf("wrote %d bytes to %s", len(in.Content), in.Path), false
	}
	return "no such tool: " + name, true
}

// spikeCallOf names one tool call for the record: the tool and the argument
// that decides what it reaches.
func spikeCallOf(name string, input json.RawMessage) string {
	var in struct {
		URL  string `json:"url"`
		Path string `json:"path"`
	}
	json.Unmarshal(input, &in)
	switch {
	case in.URL != "":
		return name + "(" + in.URL + ")"
	case in.Path != "":
		return name + "(" + in.Path + ")"
	}
	return name + "()"
}

func spikeClip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
