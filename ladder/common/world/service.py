#!/usr/bin/env python3
"""service - a local stand-in for one host in "the outside world".

Conventions section 4 requires the demos to be offline and self-contained, so every
host the agent might reach is a container running this program: the wiki, the
non-allowlisted host the agent should never talk to, and the cloud metadata endpoint.

Being real listeners matters most for the metadata case. "Blocked" and "nothing was
listening" look identical from inside the sandbox, so the BASELINE check has to show
the probe genuinely succeeding against a listener bound at 169.254.169.254 before the
ENFORCED failure means anything.

From rung 4 the body may come from a file instead. Rung 4's untrusted source is a web
PAGE -- the deck's actual scenario -- so it is a multi-line fixture with an injected
paragraph in the middle of it, and passing that on a command line would make the
fixture unreadable and unreviewable.

Usage: service.py --name wiki --body 'content' [--port 80]
       service.py --name wiki --body-file /ladder/pages/injected-page.txt
"""

import argparse
import http.server
import socketserver


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--body", default=None)
    ap.add_argument("--body-file", default=None,
                    help="serve this file's contents instead of --body (rung 4)")
    ap.add_argument("--port", type=int, default=80)
    args = ap.parse_args()

    if args.body_file:
        with open(args.body_file) as fh:
            body = fh.read()
    elif args.body is not None:
        body = args.body
    else:
        ap.error("one of --body or --body-file is required")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(("%s %s" % (args.name.upper(), body)).encode())

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(("%s RECEIVED" % args.name.upper()).encode())

        def log_message(self, fmt, *a):
            print("%s %s" % (args.name, fmt % a), flush=True)

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", args.port), Handler) as srv:
        print("service %s listening on :%d" % (args.name, args.port), flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
