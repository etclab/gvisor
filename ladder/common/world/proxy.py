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

Usage: proxy.py --allow 169.254.0.10 --allow wiki.corp [--port 3128]
"""

import argparse
import http.server
import socketserver
import urllib.error
import urllib.parse
import urllib.request

ALLOW = set()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _decide(self, target):
        host = urllib.parse.urlparse(target).hostname or ""
        allowed = host in ALLOW
        print(
            "PROXY host=%s decision=%s allowlist=%s" % (host, "allow" if allowed else "deny", ",".join(sorted(ALLOW))),
            flush=True,
        )
        return host, allowed

    def do_GET(self):
        host, allowed = self._decide(self.path)
        if not allowed:
            body = ("PROXY_DENY host=%s not in egress allowlist" % host).encode()
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow", action="append", default=[])
    ap.add_argument("--port", type=int, default=3128)
    args = ap.parse_args()
    ALLOW.update(args.allow)

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", args.port), Handler) as srv:
        print("proxy listening on :%d allowlist=%s" % (args.port, ",".join(sorted(ALLOW))), flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
