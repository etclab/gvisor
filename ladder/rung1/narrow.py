#!/usr/bin/env python3
"""narrow - ask a running task's proxy to give up part of its egress allowlist.

The host side of rung 1's mid-task attenuation. Connects to the control socket of one
task's proxy and sends the new, smaller allowlist. The proxy refuses anything that is
not a subset of what it currently has, so this program cannot widen a scope no matter
what it sends -- which is the point of running the check over there rather than here.

The socket lives in a directory bind-mounted into the proxy container and into no
sandbox. A task cannot reach it: it is not a TCP port on the proxy, and the task mounts
neither the directory nor anything above it.

    narrow.py <control-socket>                       drop everything
    narrow.py <control-socket> wiki.corp             keep only wiki.corp

Exits 0 if applied, 1 if the proxy rejected it.
"""

import json
import socket
import sys


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path, allow = sys.argv[1], sys.argv[2:]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect(path)
        sock.sendall((json.dumps({"op": "narrow", "allow": allow}) + "\n").encode())
        reply = json.loads(sock.recv(8192).decode("utf-8", "replace").strip())
    except (OSError, ValueError) as e:
        print("NARROW decision=error reason=%s" % e)
        return 1
    finally:
        sock.close()
    if reply.get("decision") == "applied":
        print("NARROW decision=applied allow=%s dropped=%s"
              % (",".join(reply.get("allow") or []) or "empty", ",".join(reply.get("dropped") or []) or "none"))
        return 0
    print("NARROW decision=rejected reason=%s" % reply.get("reason", ""))
    return 1


if __name__ == "__main__":
    sys.exit(main())
