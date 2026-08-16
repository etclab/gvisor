#!/usr/bin/env python3
"""proxy - the egress allowlist, enforced outside the sandbox.

The rung-0 spec asks for deny-by-default egress with an explicit host allowlist. The
checked-out runsc has no native host or CIDR filtering (--network takes only
sandbox|host|none|plugin), so the filter has to live outside the runtime. It is split
in two here:

  1. topology  - the enforced agent sits alone on an internal docker network with only
                 this proxy for company, so every other address is ENETUNREACH. That
                 is the deny-by-default half.
  2. this file - the proxy is dual-homed onto the world network and forwards only to
                 allowlisted hosts. That is the allowlist half; without it "reachable"
                 and "allowed" would be the same set and the allowlist would be a
                 property of the wiring rather than a policy.

Rung 2 may want this enforcement point inside the runtime instead. Whether that is
possible is exactly what rung 0 was asked to find out; see rung0/README.md.

Rung 1 adds two things. An allowlist entry may now be "host" (any port) or
"host:port". And the allowlist can be NARROWED at runtime through a control socket --
attenuation only, never widening, enforced in the handler below. The control socket is
a unix socket in a directory bind-mounted into this container and into nothing else;
no sandbox mounts it and it is not reachable over any network this proxy serves. See
rung1/README.md for why that asymmetry is the whole point.

Usage: proxy.py --allow 169.254.0.10 --allow wiki.corp:9101 [--port 3128]
                [--task-id ID] [--control SOCKET]
"""

import argparse
import http.server
import json
import os
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request

ALLOW = set()
# The allowlist is mutated by the control thread and read by every request thread.
ALLOW_LOCK = threading.Lock()
TASK_ID = None


def task_tag():
    """' task=<id>' when this proxy belongs to a task, empty otherwise.

    Empty by default so that rung 0's transcripts, which have no task, keep their
    exact wording.
    """
    return " task=%s" % TASK_ID if TASK_ID else ""


def allows(host, port):
    """True if host is allowlisted, by bare name (any port) or as host:port."""
    with ALLOW_LOCK:
        return host in ALLOW or ("%s:%d" % (host, port)) in ALLOW


def snapshot():
    with ALLOW_LOCK:
        return ",".join(sorted(ALLOW))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _decide(self, target):
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or 80
        allowed = allows(host, port)
        print(
            "PROXY host=%s decision=%s allowlist=%s" % (host, "allow" if allowed else "deny", snapshot()),
            flush=True,
        )
        return host, allowed

    def do_GET(self):
        host, allowed = self._decide(self.path)
        if not allowed:
            body = ("PROXY_DENY%s host=%s not in egress allowlist" % (task_tag(), host)).encode()
            self.send_response(403)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            upstream = urllib.request.urlopen(self.path, timeout=4).read()
        except Exception as e:
            body = ("PROXY_UPSTREAM_ERROR %s" % e).encode()
            self.send_response(502)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"PROXY_ALLOW " + upstream
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_CONNECT(self):
        # The demo is plaintext HTTP end to end, so tunnelling is refused outright
        # rather than half-implemented -- a CONNECT that worked would be an egress
        # path this proxy could not inspect.
        host = self.path.split(":")[0]
        print("PROXY host=%s decision=deny reason=connect-not-supported" % host, flush=True)
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b"PROXY_DENY CONNECT tunnelling is not offered")

    def log_message(self, fmt, *a):
        pass


# ------------------------------------------------- rung 1: narrowing, and only that


def control_apply(request):
    """Apply one control request. Returns the reply dict.

    The monotonicity check is here rather than in the caller on purpose: an
    attenuation API whose only guarantee is that callers are polite is not a
    guarantee. The new set must be a subset of the current one -- dropping hosts is
    allowed, adding one back is not, and neither is naming a host that was never in
    scope. Rungs 3 and 4 depend on this property holding mechanically.
    """
    op = request.get("op")
    want = set(request.get("allow") or [])
    if op != "narrow":
        reason = "unknown op %r (only 'narrow' exists; widening has no opcode)" % op
        print("PROXY control op=%s decision=rejected reason=%s" % (op, reason), flush=True)
        return {"decision": "rejected", "reason": reason}
    with ALLOW_LOCK:
        added = want - ALLOW
        if added:
            reason = "widening rejected: %s not in current scope (%s)" % (
                ", ".join(sorted(added)),
                ",".join(sorted(ALLOW)) or "empty",
            )
            print("PROXY control op=narrow decision=rejected reason=%s" % reason, flush=True)
            return {"decision": "rejected", "reason": reason}
        dropped = ALLOW - want
        ALLOW.clear()
        ALLOW.update(want)
        now = ",".join(sorted(ALLOW)) or "empty"
    print(
        "PROXY control op=narrow decision=applied dropped=%s allowlist=%s"
        % (",".join(sorted(dropped)) or "none", now),
        flush=True,
    )
    return {"decision": "applied", "allow": sorted(want), "dropped": sorted(dropped)}


class ControlHandler(socketserver.StreamRequestHandler):
    timeout = 5

    def handle(self):
        raw = self.rfile.readline(65536).decode("utf-8", "replace").strip()
        if not raw:
            return
        try:
            request = json.loads(raw)
        except ValueError:
            reply = {"decision": "rejected", "reason": "malformed json"}
        else:
            reply = control_apply(request)
        self.wfile.write((json.dumps(reply) + "\n").encode())


class ControlServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_control(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.unlink(path)
    server = ControlServer(path, ControlHandler)
    # This proxy runs as root inside its container; the launcher that narrows it is an
    # unprivileged user on the host sharing the directory through a bind mount.
    os.chmod(path, 0o777)
    print("proxy control socket=%s (host side only)" % path, flush=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def main():
    global TASK_ID
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow", action="append", default=[])
    ap.add_argument("--port", type=int, default=3128)
    ap.add_argument("--task-id", default=None)
    ap.add_argument("--control", default=None, help="unix socket for narrow-only control requests")
    args = ap.parse_args()
    ALLOW.update(args.allow)
    TASK_ID = args.task_id
    if args.control:
        serve_control(args.control)

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", args.port), Handler) as srv:
        print("proxy listening on :%d%s allowlist=%s" % (args.port, task_tag(), snapshot()), flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
