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

Rung 5a adds a destination that is not on this host. A SEND whose destination names a
peer AND a host -- "to=ops@hostb" -- is handed to the federation proxy over --fed-gateway
instead of being queued locally, and messages arriving from another host reach this
postbox over --fed-ingest. The postbox does none of the federation work: it does not
speak QUIC, hold a transport key, verify an envelope or consult the registry. All of
that is ladder-fed's, on this host, outside every sandbox. What the postbox keeps is
what it has had since rung 3 -- the identity of a LOCAL sender is which socket the
connection landed on -- and what it gains is the one thing it cannot get that way: the
identity of a REMOTE sender, which arrives already verified from the proxy.

Rung 4's delegation check runs on the SENDING host for a federated message, exactly as
it does for a local one, so a hop cannot widen a capability by aiming it off-host. The
receiving host then imports the (already attenuated) capability into its own authority
and delegates from there. See common/chaind/chaind.py, op "import".

    fed gateway (out):  {"op":"send","from":..,"to_host":..,"to_peer":..,
                         "stamp":<b64>,"body":..,"cap":{..}|null}
    fed ingest  (in):   {"op":"deliver","from_host":..,"from_peer":..,"to_peer":..,
                         "stamp":<b64>,"body":..,"envelope":{..}}

Usage:
    postbox.py --peer reader=/path/to/reader/peer/peer.sock \\
               --peer ops=/path/to/ops/peer/peer.sock \\
               [--require-stamp] [--chaind SOCKET] [--log PATH]
               [--host NAME] [--fed-gateway SOCKET] [--fed-ingest SOCKET]
"""

import argparse
import base64
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
    # Rung 5a. All three are None/"" unless the demo asks for federation, and every
    # code path below that reads them is skipped when they are, so rungs 0-4 behave
    # byte for byte as they did.
    "host": "",
    "fed_gateway": None,
    "fed_ingest": None,
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


# ---------------------------------------------------------------- rung 5a: federation


def fed_call(request, timeout=10):
    """One request to this host's federation proxy, one reply. Newline-delimited JSON.

    The postbox is a CLIENT of the proxy and holds nothing the proxy holds: no transport
    key, no registry, no connection. It hands over a message and is told whether it left.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(STATE["fed_gateway"])
        sock.sendall((json.dumps(request) + "\n").encode())
        reply = sock.recv(1 << 16).decode("utf-8", "replace").strip()
    finally:
        sock.close()
    return json.loads(reply) if reply else {"delivered": False, "reason": "empty reply"}


def split_destination(dest):
    """"ops" -> ("ops", ""); "ops@hostb" -> ("ops", "hostb").

    The host half is written by the SENDING AGENT, and that is fine for the same reason
    the delegation is: naming a host is a request, not an authority. The proxy will only
    reach a host that is in the registry, and the receiving proxy decides what may be
    delivered to the service the agent named.
    """
    peer, _, host = dest.partition("@")
    return peer, host


def federated_send(sock_peer, dest_peer, dest_host, stamp, message_body):
    """Hand one message to the federation proxy for a peer on another host. Rung 5a.

    Rung 4's attenuation check runs HERE, on the sending host, before the message is
    handed over -- a hop must not be able to widen a capability by aiming it off-box.
    What crosses the network is the capability authority's own view of what the
    destination hop should hold, which is already narrowed and which the agent never
    touched.
    """
    claim = None
    if STATE["chaind"]:
        cap, shown_cap = split_delegation(message_body)
        remote_hop = "%s@%s" % (dest_peer, dest_host)
        request = {"op": "delegate", "from": sock_peer, "to": remote_hop,
                   "stamp": stamp_dict(stamp)}
        if cap is not None:
            request["cap"] = cap
        try:
            verdict = chaind.call(STATE["chaind"], request)
        except (OSError, ValueError) as e:
            log("drop from=%s to=%s reason=chaind-unreachable %s" % (sock_peer, remote_hop, e))
            return b'{"delivered": false, "reason": "capability authority unreachable"}'
        if verdict.get("decision") != "allow":
            log("drop from=%s to=%s reason=%s cap=%r" % (
                sock_peer, remote_hop, verdict.get("code") or "delegation-denied",
                shown_cap[:120]))
            return json.dumps({"delivered": False,
                               "reason": verdict.get("reason", "delegation denied"),
                               "code": verdict.get("code", "delegation-denied")}).encode()
        claim = verdict.get("view")
        log("delegate from=%s to=%s decision=allow cap=%r" % (
            sock_peer, remote_hop, shown_cap[:120] or "(inherited unchanged)"))

    request = {
        "op": "send",
        "from": sock_peer,
        "to_host": dest_host,
        "to_peer": dest_peer,
        # Verbatim, base64 only because JSON is not a byte transport. The proxy wraps
        # these bytes; it never parses, rewrites or invents them. That is the two-layer
        # stamp of the rung-5a spec, section 2a.
        "stamp": base64.b64encode(stamp.ljust(STAMP_LEN) if stamp else b"").decode(),
        "body": message_body,
        "claim": claim,
    }
    try:
        reply = fed_call(request)
    except (OSError, ValueError) as e:
        log("drop from=%s to=%s@%s reason=fed-unreachable %s" % (
            sock_peer, dest_peer, dest_host, e))
        return b'{"delivered": false, "reason": "federation proxy unreachable"}'
    ok = bool(reply.get("delivered"))
    log("fed-send from=%s to=%s@%s delivered=%s reason=%s body=%r" % (
        sock_peer, dest_peer, dest_host, ok, reply.get("code") or reply.get("reason", ""),
        message_body[:80]))
    return json.dumps(reply).encode()


def ingest_deliver(request):
    """A message the federation proxy has already verified, arriving from another host.

    Everything the substrate checks -- the peer's key against the registry, the
    envelope signature, the channel binding, expiry, replay, the framing, and the
    service's role scope -- happened in the proxy before this function was called. What
    is left here is what the postbox has always done: decide whether this host's
    capability authority accepts the sender's claim, and queue the message with the
    SENDING SENTRY'S STAMP UNTOUCHED, so the receiving sentry inherits taint and chain
    exactly as it does for a message that never left the box.
    """
    from_host = request.get("from_host") or ""
    from_peer = request.get("from_peer") or ""
    to_peer = request.get("to_peer") or ""
    body = request.get("body") or ""
    envelope = request.get("envelope") or {}
    remote = "%s@%s" % (from_peer, from_host)
    try:
        stamp_raw = base64.b64decode(request.get("stamp") or "")
    except (ValueError, TypeError):
        stamp_raw = b""
    stamp, _ = split_stamp(stamp_raw)

    if to_peer not in STATE["peers"]:
        log("drop from=%s reason=unknown-peer to=%s" % (remote, to_peer))
        return {"delivered": False, "reason": "unknown peer", "code": "unknown-peer"}

    if STATE["require_stamp"]:
        if not stamp:
            log("drop from=%s reason=unstamped body=%r" % (remote, body[:60]))
            return {"delivered": False, "reason": "unstamped", "code": "unstamped"}
        claimed = stamp_field(stamp, "sender")
        # The local half of the hop name. The stamp names a sandbox on ITS OWN host and
        # knows nothing about hosts; the envelope names the host, and the proxy verified
        # it against the enrolled key before this ran. Disagreement means one of the two
        # mechanisms is off.
        if claimed != from_peer:
            log("drop from=%s reason=sender-mismatch claimed=%s" % (remote, claimed))
            return {"delivered": False, "reason": "sender-mismatch", "code": "sender-mismatch"}

    if STATE["chaind"]:
        # Cross-host delegation, and the one place where this host's authority takes
        # another host's word for something. It is taking it because the host is
        # ENROLLED, not because anything attested that it runs the enforcement -- which
        # is the crack rung 5a leaves open, logged here where it happens.
        imp = {"op": "import", "hop": to_peer, "from": remote,
               "claim": envelope.get("claim"),
               "stamp": stamp_dict(stamp),
               "attested_by": {"host": from_host, "key": envelope.get("peer_key", "")}}
        try:
            verdict = chaind.call(STATE["chaind"], imp)
        except (OSError, ValueError) as e:
            log("drop from=%s to=%s reason=chaind-unreachable %s" % (remote, to_peer, e))
            return {"delivered": False, "reason": "capability authority unreachable",
                    "code": "chaind-unreachable"}
        if verdict.get("decision") != "allow":
            log("drop from=%s to=%s reason=%s" % (
                remote, to_peer, verdict.get("code") or "import-denied"))
            return {"delivered": False, "reason": verdict.get("reason", "import denied"),
                    "code": verdict.get("code", "import-denied")}

    queued = (stamp.ljust(STAMP_LEN) if stamp else b"") + body.encode()
    with STATE["queue_lock"]:
        STATE["queues"].setdefault(to_peer, []).append(queued)
    log("deliver to=%s via=fed from=%s stamp=%r body=%r" % (
        to_peer, remote, stamp.decode("utf-8", "replace") if stamp else "(none)", body[:80]))
    return {"delivered": True, "to": to_peer}


def serve_ingest(path):
    """Accept loop for the federation proxy's deliveries. SOCK_STREAM, one JSON line."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o600)  # the proxy runs as this user; no sandbox mounts this
    listener.listen(64)

    def handle_conn(conn):
        try:
            conn.settimeout(10)
            raw = b""
            while b"\n" not in raw:
                chunk = conn.recv(MAX_MESSAGE)
                if not chunk:
                    break
                raw += chunk
            if not raw.strip():
                return
            try:
                request = json.loads(raw.decode("utf-8", "replace").strip())
            except ValueError:
                reply = {"delivered": False, "reason": "malformed json"}
            else:
                reply = ingest_deliver(request)
            conn.sendall((json.dumps(reply) + "\n").encode())
        except OSError as e:
            log("error ingest %s" % e)
        finally:
            conn.close()

    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()


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

        # Rung 5a. A destination that names another host leaves this box through the
        # federation proxy and never touches the local queues. A destination that names
        # THIS host, or no host at all, is rung 3's local relay, unchanged.
        dest_peer, dest_host = split_destination(dest)
        if dest_host and dest_host != STATE["host"]:
            if not STATE["fed_gateway"]:
                log("drop from=%s to=%s reason=no-federation" % (sock_peer, dest))
                return b'{"delivered": false, "reason": "this host has no federation proxy"}'
            return federated_send(sock_peer, dest_peer, dest_host, stamp, message_body)
        dest = dest_peer

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
    ap.add_argument("--host", default="", metavar="NAME",
                    help="rung 5a: this host's federation name; a destination naming "
                         "this host is relayed locally")
    ap.add_argument("--fed-gateway", default=None, metavar="SOCKET",
                    help="rung 5a: hand messages for another host to the federation "
                         "proxy on this socket")
    ap.add_argument("--fed-ingest", default=None, metavar="SOCKET",
                    help="rung 5a: listen here for messages the federation proxy has "
                         "already verified")
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
    STATE["host"] = args.host
    STATE["fed_gateway"] = args.fed_gateway
    STATE["fed_ingest"] = args.fed_ingest

    paths = []
    if args.fed_ingest:
        if len(args.fed_ingest.encode()) >= 108:
            sys.exit("postbox: ingest socket path is %d bytes, AF_UNIX limit is 107"
                     % len(args.fed_ingest.encode()))
        os.makedirs(os.path.dirname(args.fed_ingest), exist_ok=True)
        if os.path.exists(args.fed_ingest):
            os.unlink(args.fed_ingest)
        threading.Thread(target=serve_ingest, args=(args.fed_ingest,), daemon=True).start()
        paths.append(args.fed_ingest)

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

    log("listening host=%s peers=%s require_stamp=%s chaind=%s fed=%s" % (
        args.host or "-", ",".join("%s@%s" % (n, p) for n, p in wiring), args.require_stamp,
        args.chaind or "none",
        ("gateway=%s ingest=%s" % (args.fed_gateway, args.fed_ingest))
        if args.fed_gateway or args.fed_ingest else "none"))
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
