#!/usr/bin/env python3
"""chaind - the capability authority. Rung 4.

Runs on the HOST, outside every sandbox, like the broker and the postbox. It owns
exactly one thing: the capability record minted for the user's goal, and the
per-hop attenuations derived from it by delegation.

    user's trigger                 mint      -> hop "reader" holds the root capability
    reader  --message--> orch      delegate  -> hop "orch" holds reader's, or narrower
    orch    --message--> ops       delegate  -> hop "ops"  holds orch's, or narrower
    ops     --write_config-->      authorize -> against OPS'S CHAIN, not ops's identity

Three components talk to it and none of them is inside a sandbox:

  * demo.sh   mints the goal. This stands in for the user's trigger, and the record
              it mints is HAND-WRITTEN. See "the largest assumption" below.
  * postbox   calls delegate when it relays a message, because the relay is where a
              delegation physically happens. It passes the runtime's stamp verbatim.
  * broker    calls authorize before running a tool, because the broker is the
              enforcement point -- it holds the credential, so a denial there is a
              denial in fact and not a request the agent could route around.

The socket lives in the demo's runtime directory and is bind-mounted into NOTHING.
An agent cannot mint, cannot delegate, and cannot authorize; it can only ask its own
broker for a tool and be told no.

    THE LARGEST ASSUMPTION IN THE ENTIRE LADDER, stated where it cannot be missed:
    the root capability is hand-written. Nobody translates "investigate why service
    X is slow and fix its config" into {write_config: {keys: [cache_size, pool_max,
    timeout_ms]}}. Over-scope that record -- add auth_disabled to the key list, or
    grant write_config with no key constraint at all -- and every check below still
    passes while the attack succeeds. Attenuation is only as good as the thing being
    attenuated, and who writes it is a backlog item, not a solved problem.

Deliberately NOT Macaroons, Biscuit, or SPIFFE; see rung4/README.md. The
unforgeability here comes from centralization plus the runtime's stamp, not from
cryptography: there is one process, it holds all the state, and the only reason an
agent cannot forge a delegation is that it cannot reach this socket.

Protocol: one JSON object per connection, one JSON object back.

    -> {"op": "mint", "goal": {...}, "to": "reader"}
    -> {"op": "delegate", "from": "reader", "to": "orch", "cap": {...}, "stamp": {...}}
    -> {"op": "authorize", "hop": "ops", "tool": "write_config", "args": ["k", "v"]}
    -> {"op": "view", "hop": "ops"}
    <- {"decision": "allow"|"deny", "reason": "...", "view": {...}}

Usage:
    chaind.py serve --socket PATH --goal FILE --assign HOP [--log PATH]
    chaind.py call  --socket PATH --op view --hop ops
"""

import argparse
import json
import os
import socket
import socketserver
import sys
import threading
import time

LOG_LOCK = threading.Lock()

STATE = {
    "log_path": None,
    "goal": None,
    # hop name -> record. A record is the hop's effective capability plus the chain
    # state that produced it. Written by mint and delegate, read by authorize.
    "hops": {},
    "lock": threading.Lock(),
}


def log(line):
    stamped = "CHAIND %.3f %s" % (time.time(), line)
    with LOG_LOCK:
        print(stamped, flush=True)
        if STATE["log_path"]:
            with open(STATE["log_path"], "a") as fh:
                fh.write(stamped + "\n")


# ---------------------------------------------------------------- capability arithmetic


def tools_of(cap):
    return (cap or {}).get("tools") or {}


def subset(granted, holder):
    """Is `granted` no wider than `holder`? Returns (ok, reason).

    This is the whole of rung 4's claim 2 and it is twelve lines, which is itself a
    finding: see rung4/README.md on whether this wanted a real capability library.

    Two axes, and the second is the one that matters:

      tools  every tool in granted must be a tool holder has.
      keys   a constraint the holder carries must be carried, and narrowed, by the
             grant. A grant that simply OMITS the key list is unconstrained, which
             is WIDER than a holder that has one -- so omission is a widening, not
             a default. Getting that backwards is the whole bug class this check
             exists to prevent.
    """
    g, h = tools_of(granted), tools_of(holder)
    for tool, constraint in sorted(g.items()):
        if tool not in h:
            return False, "tool %r is not held by the delegator (holds: %s)" % (
                tool, ", ".join(sorted(h)) or "nothing")
        held = h[tool] or {}
        if "keys" in held:
            if "keys" not in (constraint or {}):
                return False, ("tool %r is delegated with no key constraint, but the "
                               "delegator holds it constrained to %s -- omitting the "
                               "constraint is a widening" % (tool, ",".join(held["keys"])))
            extra = sorted(set(constraint["keys"]) - set(held["keys"]))
            if extra:
                return False, "tool %r: key(s) %s not held by the delegator (holds: %s)" % (
                    tool, ",".join(extra), ",".join(held["keys"]))
    return True, "granted is contained in the delegator's own set"


def merge_chain(existing, incoming):
    """Append hops from incoming that are not already in existing, preserving order."""
    out = list(existing)
    for hop in incoming or []:
        hop = (hop or "").strip()
        if hop and hop not in out:
            out.append(hop)
    return out


# ---------------------------------------------------------------- operations


def op_mint(request):
    """The user's trigger. Assign the root capability to the first hop of the chain."""
    goal = request.get("goal") or STATE["goal"]
    if not goal:
        return {"decision": "deny", "reason": "no goal record to mint"}
    to = request.get("to")
    if not to:
        return {"decision": "deny", "reason": "mint needs a hop to assign to"}
    with STATE["lock"]:
        STATE["goal"] = goal
        STATE["hops"] = {
            to: {
                "goal_id": goal["goal_id"],
                "cap": {"tools": tools_of(goal)},
                "chain": list(goal.get("chain") or ["user"]),
                "taint": 0,
                "origin": "-",
                # Whether the runtime attested the chain of the message that
                # produced this record. False for the root: no message produced it.
                "chain_attested": False,
            }
        }
    log("mint goal=%s to=%s tools=%s chain=%s" % (
        goal["goal_id"], to, json.dumps(tools_of(goal), sort_keys=True),
        ">".join(goal.get("chain") or ["user"])))
    return {"decision": "allow", "reason": "minted", "view": view_of(to)}


def op_delegate(request):
    """One hop hands another a capability. Attenuation only.

    The delegator's own set is looked up here, from state no agent can reach. The
    grant is read out of the message, which the agent DOES control -- and that is
    fine, because a grant is only ever checked against the delegator's set. An agent
    writing itself a wider capability is writing a request that will be refused.
    """
    frm, to = request.get("from"), request.get("to")
    granted = request.get("cap") or {}
    stamp = request.get("stamp") or {}

    with STATE["lock"]:
        holder = STATE["hops"].get(frm)
    if holder is None:
        reason = ("hop %r holds no capability for any goal, so it has nothing to "
                  "delegate" % frm)
        log("delegate from=%s to=%s decision=deny reason=%s" % (frm, to, reason))
        return {"decision": "deny", "reason": reason}

    # The stamp's sender is the runtime's word for who sent this; `from` is the
    # postbox's word, taken from which socket the connection landed on. They cannot
    # disagree unless one of the two mechanisms is off, and a silent disagreement
    # would mean the identity in the record had stopped meaning anything.
    claimed = stamp.get("sender", "")
    if claimed and claimed != frm:
        reason = "stamp claims sender=%r but the message arrived on %r's socket" % (claimed, frm)
        log("delegate from=%s to=%s decision=deny reason=%s" % (frm, to, reason))
        return {"decision": "deny", "reason": reason}

    if not granted:
        # No delegation in the message: the receiver inherits the sender's set
        # unchanged. Convenient, and honest -- it is the identity attenuation.
        granted = holder["cap"]

    ok, why = subset(granted, holder["cap"])
    if not ok:
        reason = "granted is not contained in the caller's own set: %s" % why
        log("delegate from=%s to=%s decision=deny reason=%s granted=%s held=%s" % (
            frm, to, reason, json.dumps(tools_of(granted), sort_keys=True),
            json.dumps(tools_of(holder["cap"]), sort_keys=True)))
        return {"decision": "deny", "reason": reason, "code": "capability-widening"}

    # Chain state. The hop list is merged from the runtime's stamp when there is
    # one and from this daemon's own bookkeeping regardless, so the record is
    # complete either way. The ORIGIN is different: it is the path the first hop
    # actually read, which only that hop's sentry ever knew. Nothing host-side can
    # reconstruct it, so with --ladder-chain off it stays unknown. That asymmetry is
    # rung 4's honest answer to "what does the runtime uniquely provide".
    attested = bool(stamp.get("chain"))
    chain = merge_chain(holder["chain"], [frm])
    chain = merge_chain(chain, stamp.get("chain"))
    chain = merge_chain(chain, [to])
    taint = max(int(holder["taint"]), 1 if str(stamp.get("taint")) == "1" else 0)
    origin = holder["origin"]
    if origin in ("", "-", "unknown"):
        origin = stamp.get("origin") or "-"
    if origin in ("", "-") and taint:
        origin = "unknown"

    record = {
        "goal_id": holder["goal_id"],
        "cap": {"tools": tools_of(granted)},
        "chain": chain,
        "taint": taint,
        "origin": origin,
        "chain_attested": attested or holder.get("chain_attested", False),
    }
    with STATE["lock"]:
        STATE["hops"][to] = record
    log("delegate from=%s to=%s decision=allow tools=%s chain=%s taint=%d origin=%s attested=%s" % (
        frm, to, json.dumps(tools_of(granted), sort_keys=True),
        ">".join(chain), taint, origin, record["chain_attested"]))
    return {"decision": "allow", "reason": why, "view": view_of(to)}


def op_authorize(request):
    """The sink. Authorize a tool call against the CHAIN, not against the caller.

    Rung 1 asked "is this tool in this task's scope". This asks a different question
    -- "is this call inside what the user's goal authorized, given everything that
    reached this hop" -- and the answers differ exactly where rung 4 lives: ops holds
    write_config in its own manifest, and its credentials would happily set
    auth_disabled.
    """
    hop = request.get("hop")
    tool = request.get("tool")
    args = request.get("args") or []

    with STATE["lock"]:
        record = STATE["hops"].get(hop)

    if record is None:
        # Fail closed. A hop that is not in a chain has no goal to be acting on
        # behalf of, and "it has valid credentials" is precisely the reasoning rung 4
        # exists to reject.
        reason = ("hop %r is not in any chain for this goal, so there is nothing to "
                  "authorize this call against" % hop)
        log("authorize hop=%s tool=%s decision=deny reason=%s" % (hop, tool, reason))
        return {"decision": "deny", "reason": reason, "code": "no-chain"}

    tools = tools_of(record["cap"])
    chain = ">".join(record["chain"])
    if tool not in tools:
        reason = ("tool %r is outside the capability for goal %s (chain %s holds: %s)" % (
            tool, record["goal_id"], chain, ", ".join(sorted(tools)) or "nothing"))
        log("authorize hop=%s tool=%s args=%s decision=deny reason=%s" % (hop, tool, args, reason))
        return {"decision": "deny", "reason": reason, "code": "tool-out-of-scope",
                "view": view_of(hop)}

    constraint = tools[tool] or {}
    if "keys" in constraint:
        key = args[0] if args else ""
        if key not in constraint["keys"]:
            # Claim 4, and the line the demo greps for. It names the key AND the
            # goal, because "denied" without either is an operator's dead end.
            reason = ("key %r is outside the capability allowlist for goal %s "
                      "(allowed: %s; chain %s; origin %s)" % (
                          key, record["goal_id"], ",".join(constraint["keys"]),
                          chain, record["origin"]))
            log("authorize hop=%s tool=%s args=%s decision=deny reason=%s" % (
                hop, tool, args, reason))
            return {"decision": "deny", "reason": reason, "code": "key-out-of-scope",
                    "view": view_of(hop)}
        if record["taint"]:
            # Claim 5, and the place where taint tracking and usefulness collide.
            # The parameter came through a chain something untrusted entered, and it
            # is being allowed because it passed the allowlist -- the allowlist is
            # standing in for a validator, and it is doing so at message granularity
            # with no idea WHICH bytes were tainted. Logged loudly rather than
            # silently allowed; discussed at length in rung4/README.md.
            log("authorize hop=%s tool=%s args=%s taint=1 origin=%s decision=allow "
                "reason=parameter-passed-allowlist-despite-tainted-chain" % (
                    hop, tool, args, record["origin"]))

    reason = "in scope for goal %s via chain %s" % (record["goal_id"], chain)
    log("authorize hop=%s tool=%s args=%s decision=allow reason=%s" % (hop, tool, args, reason))
    return {"decision": "allow", "reason": reason, "view": view_of(hop)}


def view_of(hop):
    """What the sink knows about the chain that reached it. Acceptance criterion 2."""
    with STATE["lock"]:
        record = STATE["hops"].get(hop)
    if record is None:
        return {"hop": hop, "known": False}
    return {
        "hop": hop,
        "known": True,
        "goal_id": record["goal_id"],
        "chain": record["chain"],
        "origin": record["origin"],
        "taint": record["taint"],
        "tools": tools_of(record["cap"]),
        "chain_attested": record["chain_attested"],
    }


def op_view(request):
    v = view_of(request.get("hop"))
    return {"decision": "allow" if v.get("known") else "deny",
            "reason": "chain view", "view": v}


OPS = {"mint": op_mint, "delegate": op_delegate, "authorize": op_authorize, "view": op_view}


def handle(request):
    fn = OPS.get(request.get("op"))
    if fn is None:
        reason = "unknown op %r (known: %s)" % (request.get("op"), ", ".join(sorted(OPS)))
        log("decision=deny reason=%s" % reason)
        return {"decision": "deny", "reason": reason}
    return fn(request)


class Handler(socketserver.StreamRequestHandler):
    timeout = 5

    def handle(self):
        raw = self.rfile.readline(1 << 20).decode("utf-8", "replace").strip()
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


# ---------------------------------------------------------------- client


def call(socket_path, request, timeout=5):
    """Send one request, return the reply. Used by the broker, the postbox and demo.sh."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(socket_path)
        sock.sendall((json.dumps(request) + "\n").encode())
        reply = sock.recv(1 << 16).decode("utf-8", "replace").strip()
    finally:
        sock.close()
    return json.loads(reply) if reply else {"decision": "deny", "reason": "empty reply"}


def cmd_serve(args):
    goal = None
    if args.goal:
        with open(args.goal) as fh:
            goal = json.load(fh)
        for field in ("goal_id", "tools"):
            if field not in goal:
                sys.exit("chaind: goal record %s is missing %r" % (args.goal, field))

    if len(args.socket.encode()) >= 108:
        sys.exit("chaind: socket path is %d bytes, AF_UNIX limit is 107" % len(args.socket.encode()))

    STATE["log_path"] = args.log
    STATE["goal"] = goal
    os.makedirs(os.path.dirname(args.socket), exist_ok=True)
    if os.path.exists(args.socket):
        os.unlink(args.socket)

    server = Server(args.socket, Handler)
    # 0600 on purpose, and worth saying out loud: the broker and the postbox run as
    # this user, and no sandbox mounts this directory. Compare the broker's socket,
    # which is 0777 because a sandboxed agent has to reach it.
    os.chmod(args.socket, 0o600)
    log("listening socket=%s goal=%s" % (args.socket, goal["goal_id"] if goal else "none"))
    if goal and args.assign:
        handle({"op": "mint", "goal": goal, "to": args.assign})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if os.path.exists(args.socket):
            os.unlink(args.socket)
    return 0


def cmd_call(args):
    request = {"op": args.op}
    for field in ("hop", "tool"):
        if getattr(args, field):
            request[field] = getattr(args, field)
    if args.arg:
        request["args"] = args.arg
    reply = call(args.socket, request)
    print(json.dumps(reply, sort_keys=True))
    return 0 if reply.get("decision") == "allow" else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--socket", required=True)
    s.add_argument("--goal", default=None, help="the root capability record, as JSON")
    s.add_argument("--assign", default=None, help="mint the goal to this hop at startup")
    s.add_argument("--log", default=None)
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("call")
    s.add_argument("--socket", required=True)
    s.add_argument("--op", required=True, choices=sorted(OPS))
    s.add_argument("--hop", default=None)
    s.add_argument("--tool", default=None)
    s.add_argument("--arg", action="append", default=[])
    s.set_defaults(fn=cmd_call)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
