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

// The far side of the hop: the same agent as the Go loop beside this file,
// written for the one sandbox in this tree that enforces anything.
//
// It is spike E3's agent.ts promoted (docs/snp/evidence/ticket23/spikes/E3),
// with the arrangement spike E4 settled on: this process does not start
// working when it starts. attest/sandbox/deno starts it when a policy is
// pushed — the permission flags it is running under ARE that policy — and the
// delegating agent then opens a stream and says RUN. So the gate below is the
// hop: the flags were set before this process existed, and the request arrives
// afterwards.
//
// What this side may reach is Deno's business and not this file's. A denied
// destination arrives here as a NotCapable error from fetch, which is printed
// as a TOOL_ERROR line and handed to the model as a failed tool_result. The
// transcript is what carries it back: E4 measured that the model says DONE
// anyway once it has worked around the failure, so the exit status says the
// agent ran and the transcript says what it could not reach. The two are
// different questions and this file answers both separately.
//
// Same model id, same task string, same two tools, same arithmetic as the Go
// loop and as E1. No import of any kind, no npm package: plain fetch, plain
// Deno.writeTextFile. Run it with `deno run --no-prompt <flags> agent.ts`,
// never `deno eval`, which ignores permission flags entirely.

const MODEL = "claude-sonnet-5";
const MAX_TOKENS = 4096;
const ENDPOINT = "https://api.anthropic.com/v1/messages";
const API_VER = "2023-06-01";
const FETCH_CAP = 20 << 10; // ~20 KB of a fetched document, then truncate

// The task, byte-identical to summarizePrompt in agent.go and to spikeTask in
// E1's, so that a run here and a run there are runs of the same thing.
const TASK =
  "Fetch the document at https://www.rfc-editor.org/rfc/rfc8446.txt, write a summary of it in at most five sentences, and save the summary to the file summary.txt in the current directory using write_file. Then reply with the word DONE.";

// claude-sonnet-5, dollars per million tokens.
const IN_PER_M = 2.00;
const OUT_PER_M = 10.00;

// The two tools. There is no delegate here: this is the end of the chain, and
// an agent that could delegate onwards would be a second hop nobody pushed a
// policy for.
const TOOL_DEFS = `[
  {"name":"fetch_url",
   "description":"HTTP GET a URL and return the response body as text, truncated to about 20 KB.",
   "input_schema":{"type":"object","properties":{"url":{"type":"string","description":"An absolute http or https URL."}},"required":["url"]}},
  {"name":"write_file",
   "description":"Write text to a file, creating or truncating it.",
   "input_schema":{"type":"object","properties":{"path":{"type":"string","description":"The file to write."},"content":{"type":"string","description":"What to write."}},"required":["path","content"]}}
]`;

type Block = {
  type: string;
  text?: string;
  id?: string;
  name?: string;
  input?: Record<string, unknown>;
};

type Reply = {
  stop_reason: string;
  stop_details?: unknown;
  content: Block[];
  usage: { input_tokens: number; output_tokens: number };
};

function clip(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n) + "…";
}

// how names the error the way the model is told it: Deno's own sentence, not a
// paraphrase, because which sentence a denied resource produces is the whole
// of what this side is measuring.
function how(e: unknown): string {
  return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
}

// waitForRun is the gate. The delegating agent opens a stream, writes RUN and
// ends its half; whatever carries that to this process — a harness pumping the
// stream into this stdin — closes it, and either the line or the end of the
// input starts the run.
//
// End of input runs the task too, and that is deliberate: the sandbox that
// starts this process gives it no stdin at all, so a script that insisted on
// the word would be a script that never ran under the sandbox it was written
// for. Which of the two happened is the first line of the transcript.
async function waitForRun(): Promise<string> {
  const buf = new Uint8Array(64);
  const decoder = new TextDecoder();
  let seen = "";
  while (!seen.includes("\n")) {
    let n: number | null;
    try {
      n = await Deno.stdin.read(buf);
    } catch (e) {
      return "stdin: " + how(e);
    }
    // End of input with nothing on it is the sandbox's arrangement; end of
    // input with a partial line is a harness that stopped mid-sentence, and
    // the caller below tells the two apart.
    if (n === null) return seen.trim();
    seen += decoder.decode(buf.subarray(0, n));
  }
  return seen.slice(0, seen.indexOf("\n")).trim();
}

// runTool executes one tool call and returns what the model is told, and
// whether that is an error. Every failure comes back as a tool_result the
// model reads, never as a throw.
async function runTool(
  name: string,
  input: Record<string, unknown>,
): Promise<[string, boolean]> {
  switch (name) {
    case "fetch_url": {
      const url = String(input?.url ?? "");
      let resp: Response;
      try {
        resp = await fetch(url);
      } catch (e) {
        return ["fetch_url: " + how(e), true];
      }
      let body: Uint8Array;
      try {
        body = new Uint8Array(await resp.arrayBuffer());
      } catch (e) {
        return ["fetch_url: " + how(e), true];
      }
      const truncated = body.length > FETCH_CAP;
      const bytes = truncated ? body.subarray(0, FETCH_CAP) : body;
      let text = new TextDecoder().decode(bytes);
      if (truncated) text += "\n\n[truncated at 20 KB]";
      return [text, resp.status !== 200];
    }
    case "write_file": {
      const path = String(input?.path ?? "");
      const content = String(input?.content ?? "");
      try {
        await Deno.writeTextFile(path, content);
      } catch (e) {
        return ["write_file: " + how(e), true];
      }
      return [`wrote ${content.length} bytes to ${path}`, false];
    }
  }
  return ["no such tool: " + name, true];
}

// callOf names one tool call for the record: the tool and the argument that
// decides what it reaches.
function callOf(name: string, input: Record<string, unknown>): string {
  const url = input?.url as string | undefined;
  const path = input?.path as string | undefined;
  if (url) return `${name}(${url})`;
  if (path) return `${name}(${path})`;
  return `${name}()`;
}

// readKey is the one secret this process holds, and only because the sandbox
// that started it granted --allow-env for exactly this name. A policy without
// that grant ends the run here, which is the shape of a denial and not a bug.
function readKey(): string | null {
  try {
    const key = Deno.env.get("ANTHROPIC_API_KEY");
    if (key) return key;
    console.log("TOOL_ERROR agent: ANTHROPIC_API_KEY is not set");
  } catch (e) {
    console.log("TOOL_ERROR agent: reading ANTHROPIC_API_KEY: " + how(e));
  }
  return null;
}

// askModel sends one request and returns the model's reply, or null when the
// run cannot go on — which it says in the transcript before it says it here.
// The model endpoint is a destination like any other and a policy that left it
// out denies it, so this is the one denial the agent cannot work around.
async function askModel(key: string, body: string, turn: number): Promise<Reply | null> {
  const started = performance.now();
  let resp: Response;
  try {
    resp = await fetch(ENDPOINT, {
      method: "POST",
      headers: {
        "x-api-key": key,
        "anthropic-version": API_VER,
        "content-type": "application/json",
      },
      body,
    });
  } catch (e) {
    console.log(`TOOL_ERROR agent: request ${turn}: ` + how(e));
    return null;
  }
  const raw = await resp.text();
  const took = Math.round(performance.now() - started);
  if (resp.status !== 200) {
    console.log(`TOOL_ERROR agent: request ${turn}: HTTP ${resp.status}: ${clip(raw, 400)}`);
    return null;
  }
  let reply: Reply;
  try {
    reply = JSON.parse(raw);
  } catch (e) {
    console.log(`TOOL_ERROR agent: request ${turn}: the response is not JSON: ` + how(e));
    return null;
  }
  console.log(
    `request ${turn}: stop_reason=${reply.stop_reason} input_tokens=${reply.usage.input_tokens} output_tokens=${reply.usage.output_tokens} in ${took}ms`,
  );
  return reply;
}

// toolPass runs every tool_use block of one assistant turn and returns the
// results, appending what each call reached to calls. One line per call, and
// one TOOL_ERROR line for each that failed, in the shape the delegating side
// reads: it scans this transcript as text for TOOL_ERROR and for nothing else,
// because a tool error is all it is entitled to know.
// deno-lint-ignore no-explicit-any
async function toolPass(reply: Reply, calls: string[]): Promise<any[]> {
  // deno-lint-ignore no-explicit-any
  const results: any[] = [];
  for (const b of reply.content) {
    if (b.type !== "tool_use") continue;
    const input = (b.input ?? {}) as Record<string, unknown>;
    const [text, failed] = await runTool(b.name!, input);
    calls.push(callOf(b.name!, input));
    console.log(
      `  tool_use ${b.name} ${clip(JSON.stringify(input), 120)} -> ${text.length} bytes, is_error=${failed}`,
    );
    if (failed) console.log(`TOOL_ERROR ${b.name}: ${clip(text, 400)}`);
    results.push({
      type: "tool_result",
      tool_use_id: b.id,
      content: text,
      is_error: failed,
    });
  }
  return results;
}

// report is the last thing a run prints: what it did, what it cost and how
// long it took, in the same shape and the same arithmetic as the Go loop's.
function report(calls: string[], totalIn: number, totalOut: number, began: number) {
  const cost = totalIn / 1e6 * IN_PER_M + totalOut / 1e6 * OUT_PER_M;
  console.log("\ntool calls, in order:");
  calls.forEach((c, i) => console.log(`  ${i + 1}. ${c}`));
  console.log(`\ntotals: input_tokens=${totalIn} output_tokens=${totalOut}`);
  console.log(
    `cost: $${cost.toFixed(6)}  (input $${IN_PER_M.toFixed(2)}/M, output $${OUT_PER_M.toFixed(2)}/M for ${MODEL})`,
  );
  console.log(`wall time: ${((performance.now() - began) / 1000).toFixed(3)}s`);
}

// accepted reads the gate's answer and says whether this process should work.
// Which of the two ways it was started is the first line of the transcript,
// because the two are different arrangements and a record that did not say
// which would be a record of neither.
function accepted(request: string): boolean {
  if (request === "") {
    console.log(
      "RUN assumed: stdin ended without a request, which is how the sandbox starts this process",
    );
    return true;
  }
  if (request === "RUN") {
    console.log("RUN accepted");
    return true;
  }
  console.log(`agent: ${JSON.stringify(request)} is not a request`);
  return false;
}

// stopped is the two stop reasons that are answers rather than turns: a
// refusal and a truncated turn each leave the conversation in a state where
// sending it back would be asking the model to continue what it did not
// finish.
function stopped(reply: Reply): boolean {
  if (reply.stop_reason === "refusal") {
    console.log(
      "TOOL_ERROR agent: the model refused: " + JSON.stringify(reply.stop_details),
    );
    return true;
  }
  if (reply.stop_reason === "max_tokens") {
    console.log(
      `TOOL_ERROR agent: the model hit max_tokens=${MAX_TOKENS} and the turn is truncated`,
    );
    return true;
  }
  return false;
}

// finalText is the model's last word, which for a run that was denied
// something is the word it says anyway.
function finalText(reply: Reply) {
  for (const b of reply.content) {
    if (b.type === "text") console.log(`\nfinal text: ${b.text}`);
  }
}

async function main(): Promise<number> {
  if (!accepted(await waitForRun())) return 2;

  const key = readKey();
  if (key === null) return 1;

  const tools = JSON.parse(TOOL_DEFS);
  // deno-lint-ignore no-explicit-any
  const messages: any[] = [{ role: "user", content: TASK }];
  let totalIn = 0, totalOut = 0;
  const calls: string[] = [];
  const began = performance.now();

  console.log(`model=${MODEL} max_tokens=${MAX_TOKENS} endpoint=${ENDPOINT}`);
  console.log(`runtime=deno ${Deno.version.deno}`);
  console.log(`task=${JSON.stringify(TASK)}\n`);

  for (let turn = 1;; turn++) {
    const body = JSON.stringify({
      model: MODEL,
      max_tokens: MAX_TOKENS,
      tools,
      messages,
    });
    const reply = await askModel(key, body, turn);
    if (reply === null) return 1;
    totalIn += reply.usage.input_tokens;
    totalOut += reply.usage.output_tokens;

    if (stopped(reply)) return 1;

    // The assistant turn goes back as the raw blocks it arrived as.
    messages.push({ role: "assistant", content: reply.content });

    if (reply.stop_reason !== "tool_use") {
      finalText(reply);
      break;
    }

    const results = await toolPass(reply, calls);
    if (results.length === 0) {
      console.log(`TOOL_ERROR agent: request ${turn}: stop_reason tool_use with no tool_use block`);
      return 1;
    }
    // Every tool_result for one assistant turn goes back in one user message.
    messages.push({ role: "user", content: results });
  }

  report(calls, totalIn, totalOut, began);
  // end_turn is exit 0 even when a tool failed. The model works around a
  // denied resource and says DONE (E4, case ii), so the exit status says
  // whether the agent ran and the TOOL_ERROR lines say what it could not
  // reach. Collapsing the two would lose the finding.
  return 0;
}

Deno.exit(await main());
