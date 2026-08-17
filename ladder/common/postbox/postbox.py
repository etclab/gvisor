#!/usr/bin/env python3
"""postbox - the mediated agent-to-agent channel. Rung 3.

Runs on the HOST, outside every sandbox, like the broker. It is a store-and-forward
relay and nothing more: it moves messages between sandboxes and it logs what it moved.

    reader sandbox  --/peer/peer.sock-->  <tasks>/reader/peer/peer.sock  \
                                                                         postbox
    ops    sandbox  --/peer/peer.sock-->  <tasks>/ops/peer/peer.sock     /

Two properties make it worth having, and neither is "it stamps messages" -- it does
not stamp anything and could not:

1. **One listening socket per sandbox.** Each sandbox gets exactly one of these
   bind-mounted at the same in-sandbox path, /peer/peer.sock. The postbox therefore
   knows which sandbox a connection came from without asking, the same way rung 1's
   broker knows which task it serves: the socket you can reach IS your identity.
   That is an identity source independent of anything in the message, which is what
   lets --require-stamp check the runtime's stamp against it.
2. **It is the only route.** Rung 0's topology puts each task on its own --internal
   docker network whose only other occupant is that task's own proxy, so there is no
   IP path from one sandbox to another and no shared writable mount. Rung 3's claim 5
   rests on that, not on the runtime.

The stamp itself is written by the SENDER'S SENTRY, before the bytes leave the guest
kernel (--ladder-attest). The postbox never writes one and cannot: it has no way to
know a sandbox's taint bit. If it invented the label the whole rung would be circular.

SOCK_SEQPACKET, not SOCK_STREAM. The stamp is a fixed prefix on each message, so the
demo's security argument needs "one send is one message" to be a fact rather than a
convention -- otherwise an agent could put a newline in its payload and hand the
receiver a second, wholly fabricated, "stamped" line. Message boundaries are enforced
by the kernel on both sides of the gofer, and SEQPACKET is connection-oriented, so
the connect(2) that rung 2's labeling hooks is mandatory (an unconnected SOCK_DGRAM
sendto would have no connect to hook).

Wire format, one message per connection:

    <256-byte stamp><verb and body>

    stamp:  "LADDER-STAMP v=1 sender=<id> taint=<0|1> grants=<a,b>" space-padded
            "LADDER-STAMP v=2 sender=<id> taint=<0|1> grants=<a,b> chain=<a>b> origin=<path>"
    verb:   "SEND to=<peer> <body>"   ->  queue <stamp><body> for <peer>
            "RECV"                    ->  reply with one queued <stamp><body>

v=2 is rung 4: the stamp additionally names every hop the message has passed through
and the first untrusted source anywhere upstream. Both fields are written by the
sending sentry, which is why this file only reads them.

With --ladder-attest off there is no stamp, the message is just "<verb and body>",
and the postbox relays it unstamped. That is rung 3's BASELINE and it is the whole
attack: the message crosses the boundary carrying nothing about where it came from.

Rung 4 adds one job, and only one: a relay is where a DELEGATION physically happens,
so with --chaind set the postbox asks the capability authority whether the delegation
carried in the message body is contained in what the sender itself holds. It makes no
decision of its own -- it forwards two facts it is uniquely placed to know (which
socket the message arrived on, and what the runtime stamped on it) and relays or drops
according to the answer. The capability arithmetic is in common/chaind/chaind.py.

    body:   "LADDER-CAP <compact json> LADDER-CAP-END <payload>"

The delegation is in the part of the message the AGENT controls, and that is correct:
a delegation is a claim, and a claim is only ever checked against the delegator's own
set. An agent that writes itself a wider capability has written a request that will be
refused. Rung 4's ENFORCED block does exactly that.

Usage:
    postbox.py --peer reader=/path/to/reader/peer/peer.sock \\
               --peer ops=/path/to/ops/peer/peer.sock \\
               [--require-stamp] [--chaind SOCKET] [--log PATH]
"""

import argparse
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "chaind"))
import chaind  # noqa: E402  (for its client half; the daemon runs as its own process)

# Must match pkg/sentry/ladder/attest.go (StampLen) and
# common/fake_agent/fake_agent.py (STAMP_LEN). Widened from 128 by rung 4; nothing
# detects a disagreement at runtime, so all three move together or none do.
STAMP_PREFIX = b"LADDER-STAMP "
STAMP_LEN = 256

# Rung 4's delegation markers, inside the message body. See the module docstring.
CAP_OPEN = "LADDER-CAP "
CAP_CLOSE = " LADDER-CAP-END"

MAX_MESSAGE = 65536

LOG_LOCK = threading.Lock()
STATE = {
    "log_path": None,
    "require_stamp": False,
    "chaind": None,
    "peers": set(),
    # peer -> list of pending raw messages (stamp bytes + body bytes)
    "queues": {},
    "queue_lock": threading.Lock(),
}


def log(line):
    stamped = "POSTBOX %.3f %s" % (time.time(), line)
    with LOG_LOCK:
        print(stamped, flush=True)
        if STATE["log_path"]:
            with open(STATE["log_path"], "a") as fh:
                fh.write(stamped + "\n")


def split_stamp(raw):
    """Split a message into (stamp, rest). stamp is b'' when there is none.

    Fixed width, not delimiter-scanned, deliberately: the sentry has to write this on
    a send path and read it on a receive path, and "the first 128 bytes" is a rule
    with no parser state. On SEQPACKET the message boundary does the rest.
    """
    if raw.startswith(STAMP_PREFIX) and len(raw) >= STAMP_LEN:
        return raw[:STAMP_LEN].rstrip(), raw[STAMP_LEN:]
    return b"", raw


def stamp_field(stamp, name):
    """Pull one field out of a stamp. Returns '' if absent."""
    for token in stamp.decode("utf-8", "replace").split():
        key, _, value = token.partition("=")
        if key == name:
            return value
    return ""


def stamp_dict(stamp):
    """The stamp as the fields chaind is given. Rung 4.

    Everything here was written by the SENDING sentry below the syscall boundary. The
    postbox passes it through verbatim and adds nothing: if it invented a field the
    whole chain would be circular.
    """
    chain = stamp_field(stamp, "chain")
    return {
        "sender": stamp_field(stamp, "sender"),
        "taint": stamp_field(stamp, "taint"),
        "chain": [h for h in chain.split(">") if h] if chain else [],
        "origin": stamp_field(stamp, "origin"),
    }


def split_delegation(body):
    """Pull rung 4's delegation out of a message body. Returns (cap_or_None, shown).

    The delegation is left IN the body when the message is relayed, deliberately: the
    receiving agent should be able to see what it was granted, and its transcript is
    where a reader looks for that.
    """
    if CAP_OPEN not in body or CAP_CLOSE not in body:
        return None, ""
    blob = body.split(CAP_OPEN, 1)[1].split(CAP_CLOSE, 1)[0].strip()
    try:
        return json.loads(blob), blob
    except ValueError:
        # A malformed delegation is not a free pass. chaind is never asked, so the
        # relay falls through to "no delegation" and the receiver inherits nothing
        # wider than the sender held.
        log("warn reason=malformed-delegation blob=%r" % blob[:80])
        return None, blob


def handle_message(sock_peer, raw):
    """Process one message that arrived on sock_peer's listening socket.

    sock_peer is the postbox's own knowledge of who is talking -- which socket file
    the connection landed on -- and is never taken from the message.
    """
    stamp, rest = split_stamp(raw)
    body = rest.decode("utf-8", "replace").strip()
    shown = stamp.decode("utf-8", "replace") if stamp else "(none)"

    if STATE["require_stamp"]:
        if not stamp:
            log("drop from=%s reason=unstamped body=%r" % (sock_peer, body[:60]))
            return b'{"delivered": false, "reason": "unstamped"}'
        claimed = stamp_field(stamp, "sender")
        if claimed != sock_peer:
            # Cannot happen while the runtime writes the stamp; checked because the
            # postbox is the one component that can tell, and a silent mismatch would
            # mean the identity in the stamp had stopped meaning anything.
            log("drop from=%s reason=sender-mismatch claimed=%s" % (sock_peer, claimed))
            return b'{"delivered": false, "reason": "sender-mismatch"}'

    if body == "RECV":
        with STATE["queue_lock"]:
            queue = STATE["queues"].setdefault(sock_peer, [])
            message = queue.pop(0) if queue else None
        if message is None:
            log("recv from=%s stamp=%r result=empty" % (sock_peer, shown))
            return b"LADDER-POSTBOX empty"
        out_stamp, out_body = split_stamp(message)
        log("deliver to=%s stamp=%r body=%r" % (
            sock_peer,
            out_stamp.decode("utf-8", "replace") if out_stamp else "(none)",
            out_body.decode("utf-8", "replace").strip()[:80],
        ))
        return message

    if body.startswith("SEND "):
        rest_body = body[len("SEND "):].strip()
        if not rest_body.startswith("to="):
            log("drop from=%s reason=no-destination body=%r" % (sock_peer, body[:60]))
            return b'{"delivered": false, "reason": "no destination"}'
        dest, _, message_body = rest_body[len("to="):].partition(" ")
        if dest not in STATE["peers"]:
            log("drop from=%s to=%s reason=unknown-peer" % (sock_peer, dest))
            return b'{"delivered": false, "reason": "unknown peer"}'

        # Rung 4. Before anything is queued, ask the capability authority whether this
        # hop may hand the next hop what it is trying to hand it. A widening is refused
        # HERE, at the relay, because that is where the delegation happens -- and the
        # message is not relayed at all, so the widened capability never exists.
        if STATE["chaind"]:
            cap, shown_cap = split_delegation(message_body)
            request = {"op": "delegate", "from": sock_peer, "to": dest,
                       "stamp": stamp_dict(stamp)}
            if cap is not None:
                request["cap"] = cap
            try:
                verdict = chaind.call(STATE["chaind"], request)
            except (OSError, ValueError) as e:
                log("drop from=%s to=%s reason=chaind-unreachable %s" % (sock_peer, dest, e))
                return b'{"delivered": false, "reason": "capability authority unreachable"}'
            if verdict.get("decision") != "allow":
                log("drop from=%s to=%s reason=%s cap=%r" % (
                    sock_peer, dest, verdict.get("code") or "delegation-denied", shown_cap[:120]))
                return json.dumps({"delivered": False,
                                   "reason": verdict.get("reason", "delegation denied"),
                                   "code": verdict.get("code", "delegation-denied")}).encode()
            log("delegate from=%s to=%s decision=allow cap=%r" % (
                sock_peer, dest, shown_cap[:120] or "(inherited unchanged)"))

        # The stamp travels verbatim. The postbox neither writes nor rewrites it; if
        # there is none, none is delivered, and the receiver's runtime has nothing to
        # inherit. That is the BASELINE.
        queued = (stamp.ljust(STAMP_LEN) if stamp else b"") + message_body.encode()
        with STATE["queue_lock"]:
            STATE["queues"].setdefault(dest, []).append(queued)
        log("relay from=%s to=%s stamp=%r body=%r" % (sock_peer, dest, shown, message_body[:80]))
        return b'{"delivered": true, "to": "%s"}' % dest.encode()

    log("drop from=%s reason=unknown-verb body=%r" % (sock_peer, body[:60]))
    return b'{"delivered": false, "reason": "unknown verb"}'


def serve(name, path):
    """Accept loop for one peer's mailbox. One connection, one message, one reply.

    Hand-rolled rather than socketserver, which has no SOCK_SEQPACKET server.
    """
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.bind(path)
    # The sandboxed agent runs as a different uid than the postbox; the socket has to
    # be connectable by it. Demo fixture, not a permissions lesson.
    os.chmod(path, 0o777)
    listener.listen(16)

    def handle_conn(conn):
        try:
            conn.settimeout(5)
            raw = conn.recv(MAX_MESSAGE)
            if raw:
                conn.send(handle_message(name, raw))
        except OSError as e:
            log("error from=%s %s" % (name, e))
        finally:
            conn.close()

    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--peer", action="append", default=[], metavar="NAME=SOCKET_PATH",
                    help="repeatable; one listening socket per sandbox")
    ap.add_argument("--require-stamp", action="store_true",
                    help="drop messages with no runtime stamp, or whose stamp disagrees "
                         "with the socket they arrived on")
    ap.add_argument("--chaind", default=None, metavar="SOCKET",
                    help="rung 4: verify every delegation against the capability "
                         "authority on this socket before relaying")
    ap.add_argument("--log", default=None)
    args = ap.parse_args()

    if not args.peer:
        sys.exit("postbox: at least one --peer is required")

    wiring = []
    for entry in args.peer:
        name, sep, path = entry.partition("=")
        if not sep or not name or not path:
            sys.exit("postbox: --peer wants NAME=SOCKET_PATH, got %r" % entry)
        wiring.append((name, path))

    STATE["log_path"] = args.log
    STATE["require_stamp"] = args.require_stamp
    STATE["chaind"] = args.chaind
    STATE["peers"] = {name for name, _ in wiring}

    paths = []
    for name, path in wiring:
        # AF_UNIX paths cap at 108 bytes and the failure reads like a permission
        # problem; the broker learned this the same way.
        if len(path.encode()) >= 108:
            sys.exit("postbox: socket path is %d bytes, AF_UNIX limit is 107" % len(path.encode()))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            os.unlink(path)
        threading.Thread(target=serve, args=(name, path), daemon=True).start()
        paths.append(path)

    for path in paths:
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.02)

    log("listening peers=%s require_stamp=%s chaind=%s" % (
        ",".join("%s@%s" % (n, p) for n, p in wiring), args.require_stamp,
        args.chaind or "none"))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for path in paths:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    main()
