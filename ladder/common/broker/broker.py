#!/usr/bin/env python3
"""broker - the tool broker: the only sanctioned path to a world-effect.

Runs on the HOST, outside every sandbox. Holds the only credentials in the system and
listens on a unix socket that is bind-mounted into the sandbox. The agent can ask it to
do things; it never hands the agent a credential.

Rung 0's authorization was deliberately trivial -- "is this a known tool name" and
nothing else. Rung 1 adds the second question: "is this tool in the scope of the task
this socket belongs to". Rung 4 adds the third, and it is a different KIND of
question: "is this call inside what the user's goal authorized, given the whole chain
that reached this hop". With --chaind set, the broker asks the capability authority
before it runs anything, and a deny there is a deny in fact -- the credential is here,
so there is nothing left for the agent to route around.

The two questions come apart exactly where rung 4 lives. `write_config` is in ops's
rung-1 scope and the credential below would set any key at all; `auth_disabled` is
outside the goal's key allowlist. Rung 1 says yes and rung 4 says no.

The task binding is established OUTSIDE the sandbox and cannot be named from inside
it. The launcher starts one broker per task, hands it that task's tool set on the
command line, and bind-mounts only that broker's socket into that task's sandbox. The
agent never sends a task id, so it has nothing to lie about -- the socket it can reach
IS its identity. That is the first appearance of the unforgeability idea rung 3
generalizes; see rung1/README.md.

Protocol: one JSON object per connection.
    -> {"tool": "read_metrics", "args": []}
    <- {"decision": "allow", "result": "..."}   or   {"decision": "deny", "reason": "..."}

Every request is logged with its task, decision and reason.

Usage: broker.py --socket PATH [--task-id ID] [--tools a,b] [--chaind SOCKET]
                 [--log PATH] [--state-dir PATH]

With no --tools the broker allows every known tool, which is exactly rung 0's
behaviour and is what rung 0's demo still runs against.
"""

import argparse
import json
import os
import socket
import socketserver
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "chaind"))
import chaind  # noqa: E402  (for its client half; the daemon runs as its own process)

# The credential the sandbox never sees. A real deployment would read this from the
# host keyring or an instance role; the demo hardcodes an obvious fake so that a
# grep for it inside the sandbox is a meaningful check.
SERVICE_CREDENTIAL = "svc-agent-key-DEADBEEF-c123"

LOG_LOCK = threading.Lock()
# "scope" is the set of tools this broker will serve. It is set once at startup from
# the launcher's command line and never changes -- there is no protocol message that
# can widen it, because there is no protocol message that can reach it.
STATE = {"log_path": None, "state_dir": "/tmp", "task_id": "-", "scope": None, "chaind": None}


def log(line):
    stamped = "BROKER %.3f task=%s %s" % (time.time(), STATE["task_id"], line)
    with LOG_LOCK:
        print(stamped, flush=True)
        if STATE["log_path"]:
            with open(STATE["log_path"], "a") as fh:
                fh.write(stamped + "\n")


# ---------------------------------------------------------------- tools
# The complete set of world-effects a rung-0 agent can cause. The rung-0 claim is that
# this dict IS the reachable damage surface -- everything else is denied by the sandbox
# config rather than by the broker.


def tool_read_metrics(_args):
    return "cpu=12%% mem=41%% (fetched with %s)" % redact(SERVICE_CREDENTIAL)


def tool_read_wiki(args):
    page = args[0] if args else "index"
    return "wiki[%s]: deploys happen on fridays (fetched with %s)" % (page, redact(SERVICE_CREDENTIAL))


def tool_write_config(args):
    if len(args) < 2:
        raise ValueError("write_config needs <key> <value>")
    key, value = args[0], " ".join(args[1:])
    path = os.path.join(STATE["state_dir"], "broker-config.txt")
    with open(path, "a") as fh:
        fh.write("%s=%s\n" % (key, value))
    return "wrote %s=%s to %s" % (key, value, path)


TOOLS = {
    "read_metrics": tool_read_metrics,
    "read_wiki": tool_read_wiki,
    "write_config": tool_write_config,
}


def redact(secret):
    return "cred:***" + secret[-4:]


def handle(request):
    tool = request.get("tool")
    args = request.get("args") or []
    if tool not in TOOLS:
        reason = "unknown tool %r (known: %s)" % (tool, ", ".join(sorted(TOOLS)))
        log("tool=%s args=%s decision=deny reason=%s" % (tool, args, reason))
        return {"decision": "deny", "reason": reason}
    # Rung 1. The tool exists and rung 0 would have run it; this task may not have it.
    # Checked after the unknown-tool case so that rung 0's denial wording is untouched.
    if tool not in STATE["scope"]:
        reason = "tool %r out of scope for task %s (scope: %s)" % (
            tool,
            STATE["task_id"],
            ", ".join(sorted(STATE["scope"])) or "none",
        )
        log("tool=%s args=%s decision=deny reason=%s" % (tool, args, reason))
        return {"decision": "deny", "reason": reason}
    # Rung 4. Last check before the credential is spent, and the only one that looks
    # at the ARGUMENTS. The hop name is this broker's --task-id, set by the launcher:
    # one broker per task, so there is nothing here the agent could claim to be.
    if STATE["chaind"]:
        request = {"op": "authorize", "hop": STATE["task_id"], "tool": tool, "args": args}
        try:
            verdict = chaind.call(STATE["chaind"], request)
        except (OSError, ValueError) as e:
            reason = "capability authority unreachable: %s" % e
            log("tool=%s args=%s decision=deny reason=%s" % (tool, args, reason))
            return {"decision": "deny", "reason": reason}
        if verdict.get("decision") != "allow":
            reason = verdict.get("reason", "outside the goal's capability")
            log("tool=%s args=%s decision=deny reason=chain:%s" % (tool, args, reason))
            return {"decision": "deny", "reason": reason,
                    "code": verdict.get("code", "chain-denied")}
    try:
        result = TOOLS[tool](args)
    except Exception as e:  # a broken tool is a deny, not a crash
        reason = "%s: %s" % (type(e).__name__, e)
        log("tool=%s args=%s decision=deny reason=%s" % (tool, args, reason))
        return {"decision": "deny", "reason": reason}
    log("tool=%s args=%s decision=allow reason=known-tool" % (tool, args))
    return {"decision": "allow", "result": result}


class Handler(socketserver.StreamRequestHandler):
    timeout = 5

    def handle(self):
        raw = self.rfile.readline(65536).decode("utf-8", "replace").strip()
        if not raw:
            return
        try:
            request = json.loads(raw)
        except ValueError:
            log("raw=%r decision=deny reason=malformed-json" % raw[:80])
            reply = {"decision": "deny", "reason": "malformed json"}
        else:
            reply = handle(request)
        self.wfile.write((json.dumps(reply) + "\n").encode())


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    # Rung 5a. socketserver's default backlog is 5, which is fine for one agent making
    # one tool call at a time and is not fine for a 32-way burst across a federation:
    # the excess connections are refused by the kernel and surface as "capability
    # authority unreachable", which reads like a policy denial and is a listen queue.
    request_queue_size = 128


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--task-id", default="-")
    ap.add_argument("--tools", default=None, help="comma-separated tool scope; default is every tool")
    ap.add_argument("--chaind", default=None, metavar="SOCKET",
                    help="rung 4: authorize every call against the capability authority "
                         "on this socket, using --task-id as the hop name")
    ap.add_argument("--log", default=None)
    ap.add_argument("--state-dir", default="/tmp")
    args = ap.parse_args()

    scope = set(TOOLS) if args.tools is None else {t.strip() for t in args.tools.split(",") if t.strip()}
    # A manifest naming a tool that does not exist is a launcher-side bug, and the
    # honest failure is to refuse to start rather than to serve a scope that quietly
    # means less than it says.
    unknown = scope - set(TOOLS)
    if unknown:
        sys.exit("broker: task %s asks for unknown tools: %s" % (args.task_id, ", ".join(sorted(unknown))))

    # AF_UNIX paths are capped at 108 bytes; a deep scratch directory silently blows
    # past that and the failure ("path too long") reads like a permissions problem.
    if len(args.socket.encode()) >= 108:
        sys.exit("broker: socket path is %d bytes, AF_UNIX limit is 107" % len(args.socket.encode()))

    STATE["log_path"] = args.log
    STATE["state_dir"] = args.state_dir
    STATE["task_id"] = args.task_id
    STATE["scope"] = scope
    STATE["chaind"] = args.chaind
    os.makedirs(os.path.dirname(args.socket), exist_ok=True)
    if os.path.exists(args.socket):
        os.unlink(args.socket)

    server = Server(args.socket, Handler)
    # The sandboxed agent runs as a different uid than the broker; the socket must be
    # connectable by it. This is a demo fixture, not a permissions lesson.
    os.chmod(args.socket, 0o777)
    log("listening socket=%s scope=%s chaind=%s" % (
        args.socket, ",".join(sorted(scope)), args.chaind or "none"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if os.path.exists(args.socket):
            os.unlink(args.socket)


if __name__ == "__main__":
    main()
