#!/usr/bin/env python3
"""broker - the tool broker: the only sanctioned path to a world-effect.

Runs on the HOST, outside every sandbox. Holds the only credentials in the system and
listens on a unix socket that is bind-mounted into the sandbox. The agent can ask it to
do things; it never hands the agent a credential.

Rung 0's authorization is deliberately trivial -- "is this a known tool name" and
nothing else. Per the rung-0 spec this is not where policy goes yet; rung 1 narrows the
tool set per task and rung 3 gives the broker labels to check. Keeping it dumb here is
what makes the rung-1 diff legible.

Protocol: one JSON object per connection.
    -> {"tool": "read_metrics", "args": []}
    <- {"decision": "allow", "result": "..."}   or   {"decision": "deny", "reason": "..."}

Every request is logged with its decision and reason.

Usage: broker.py --socket PATH [--log PATH] [--state-dir PATH]
"""

import argparse
import json
import os
import socket
import socketserver
import sys
import threading
import time

# The credential the sandbox never sees. A real deployment would read this from the
# host keyring or an instance role; the demo hardcodes an obvious fake so that a
# grep for it inside the sandbox is a meaningful check.
SERVICE_CREDENTIAL = "svc-agent-key-DEADBEEF-c123"

LOG_LOCK = threading.Lock()
STATE = {"log_path": None, "state_dir": "/tmp"}


def log(line):
    stamped = "BROKER %.3f %s" % (time.time(), line)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--log", default=None)
    ap.add_argument("--state-dir", default="/tmp")
    args = ap.parse_args()

    # AF_UNIX paths are capped at 108 bytes; a deep scratch directory silently blows
    # past that and the failure ("path too long") reads like a permissions problem.
    if len(args.socket.encode()) >= 108:
        sys.exit("broker: socket path is %d bytes, AF_UNIX limit is 107" % len(args.socket.encode()))

    STATE["log_path"] = args.log
    STATE["state_dir"] = args.state_dir
    os.makedirs(os.path.dirname(args.socket), exist_ok=True)
    if os.path.exists(args.socket):
        os.unlink(args.socket)

    server = Server(args.socket, Handler)
    # The sandboxed agent runs as a different uid than the broker; the socket must be
    # connectable by it. This is a demo fixture, not a permissions lesson.
    os.chmod(args.socket, 0o777)
    log("listening socket=%s tools=%s" % (args.socket, ",".join(sorted(TOOLS))))
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
