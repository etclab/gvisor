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

// Ticket 23's spike E3: E1's agent, ported to Deno, so that Deno's permission
// flags are the thing standing between it and the resources E1 measured.
//
// It is a throwaway. Same task string, same two tools, same model, same loop,
// same arithmetic as docs/snp/evidence/ticket23/spikes/E1/agent.go. No npm
// package and no import of any kind: plain fetch, plain Deno.writeTextFile.
//
// Run it with `deno run --no-prompt <flags> agent.ts`. Never `deno eval`,
// which ignores permission flags entirely.

const MODEL = "claude-sonnet-5";
const MAX_TOKENS = 4096;
const ENDPOINT = "https://api.anthropic.com/v1/messages";
const API_VER = "2023-06-01";
const FETCH_CAP = 20 << 10; // ~20 KB of a fetched document, then truncate

// The task, fixed here verbatim so that runs replay. Byte-identical to
// spikeTask in E1's agent.go.
const TASK =
  "Fetch the document at https://www.rfc-editor.org/rfc/rfc8446.txt, write a summary of it in at most five sentences, and save the summary to the file summary.txt in the current directory using write_file. Then reply with the word DONE.";

// claude-sonnet-5, dollars per million tokens.
const IN_PER_M = 2.00;
const OUT_PER_M = 10.00;

// The two tools, as the JSON the API takes. Byte-identical to spikeToolDefs.
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

// how names the error the way the model is told it: Deno's own sentence, not
// a paraphrase, because the whole of E3 is which sentence arrives.
function how(e: unknown): string {
  return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
}

// runTool executes one tool call and returns what the model is told, and
// whether that is an error. It mirrors spikeRunTool in E1's agent.go: every
// failure comes back as a tool_result the model reads, never as a throw.
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

async function main(): Promise<number> {
  let key: string | undefined;
  try {
    key = Deno.env.get("ANTHROPIC_API_KEY");
  } catch (e) {
    console.error("agent: reading ANTHROPIC_API_KEY: " + how(e));
    return 1;
  }
  if (!key) {
    console.error("agent: ANTHROPIC_API_KEY is not set");
    return 1;
  }

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
      console.error(`agent: request ${turn}: ` + how(e));
      return 1;
    }
    const raw = await resp.text();
    const took = Math.round(performance.now() - started);
    if (resp.status !== 200) {
      console.error(`agent: request ${turn}: HTTP ${resp.status}: ${clip(raw, 400)}`);
      return 1;
    }
    let reply: Reply;
    try {
      reply = JSON.parse(raw);
    } catch (e) {
      console.error(`agent: request ${turn}: the response is not JSON: ` + how(e));
      return 1;
    }
    totalIn += reply.usage.input_tokens;
    totalOut += reply.usage.output_tokens;
    console.log(
      `request ${turn}: stop_reason=${reply.stop_reason} input_tokens=${reply.usage.input_tokens} output_tokens=${reply.usage.output_tokens} in ${took}ms`,
    );

    if (reply.stop_reason === "refusal") {
      console.log("the model refused: " + JSON.stringify(reply.stop_details));
      return 1;
    }
    if (reply.stop_reason === "max_tokens") {
      console.log(`the model hit max_tokens=${MAX_TOKENS} and the turn is truncated`);
      return 1;
    }

    // The assistant turn goes back as the raw blocks it arrived as.
    messages.push({ role: "assistant", content: reply.content });

    if (reply.stop_reason !== "tool_use") {
      for (const b of reply.content) {
        if (b.type === "text") console.log(`\nfinal text: ${b.text}`);
      }
      break;
    }

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
      if (failed) console.log(`    the model is told: ${clip(text, 400)}`);
      results.push({
        type: "tool_result",
        tool_use_id: b.id,
        content: text,
        is_error: failed,
      });
    }
    if (results.length === 0) {
      console.error(`agent: request ${turn}: stop_reason tool_use with no tool_use block`);
      return 1;
    }
    // Every tool_result for one assistant turn goes back in one user message.
    messages.push({ role: "user", content: results });
  }

  const cost = totalIn / 1e6 * IN_PER_M + totalOut / 1e6 * OUT_PER_M;
  console.log("\ntool calls, in order:");
  calls.forEach((c, i) => console.log(`  ${i + 1}. ${c}`));
  console.log(`\ntotals: input_tokens=${totalIn} output_tokens=${totalOut}`);
  console.log(
    `cost: $${cost.toFixed(6)}  (input $${IN_PER_M.toFixed(2)}/M, output $${OUT_PER_M.toFixed(2)}/M for ${MODEL})`,
  );
  console.log(`wall time: ${((performance.now() - began) / 1000).toFixed(3)}s`);
  return 0;
}

Deno.exit(await main());
