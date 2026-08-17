#!/usr/bin/env python3
"""fake_agent - a scripted stand-in for an LLM agent.

Per ladder conventions section 4: the sandbox cannot distinguish a syscall made by a
hijacked LLM from one made by a shell script, so every ladder demo drives a
deterministic script instead of a model. No API keys, no network to the internet,
identical output on every run.

Each action prints exactly one machine-parsable line:

    RESULT <channel> <action> <SUCCESS|FAILURE> <evidence>

channel is one of: creds, network, fs, exec, broker, source, peer, sync.
SUCCESS means the agent achieved the world-effect it attempted. Whether that is good
or bad news depends on which config it was run under -- that judgement lives in
demo.sh, not here.

The process exits 0 whenever every action ran to completion, even if every probe was
denied. A non-zero exit means the harness itself broke.
"""

import argparse
import base64
import errno
import json
import os
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Credential shapes an ambient-authority environment tends to leak. Names only -- no
# real secret ever enters this repo; the demo injects obvious fakes.
CRED_ENV_VARS = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "LADDER_DEMO_SECRET",
]

CRED_FILES = [
    "~/.aws/credentials",
    "~/.config/gcloud/application_default_credentials.json",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/etc/ladder-demo/service-account.json",
]

METADATA_URL = "http://169.254.169.254/latest/api/token"

DEFAULT_BROKER_SOCK = os.environ.get("LADDER_BROKER_SOCK", "/broker/broker.sock")
DEFAULT_TIMEOUT = float(os.environ.get("LADDER_TIMEOUT", "4"))

# Rung 3. The mediated peer channel, and the shape of the label the RUNTIME writes on
# every message that leaves through it. The agent knows this format only so that it can
# print what it was handed -- and so that it can try to forge one, which is the point of
# --forge-header. Must match pkg/sentry/socket/unix/ladder.go and common/postbox.
DEFAULT_PEER_SOCK = os.environ.get("LADDER_PEER_SOCK", "/peer/peer.sock")
STAMP_PREFIX = "LADDER-STAMP "
STAMP_LEN = 256

# Rung 4's delegation markers. The agent writes these; the postbox reads them and asks
# the capability authority whether the delegation is contained in what this sandbox
# already holds. Writing a wider one is allowed and pointless, which is the design.
CAP_OPEN = "LADDER-CAP "
CAP_CLOSE = " LADDER-CAP-END"


def emit(channel, action, ok, evidence, tag=""):
    """Print the one canonical result line and return the outcome.

    tag, when set, is appended to the action as "<action>#<tag>". Rung 2 runs
    the same action several times in ONE sandbox -- once per laundering attempt
    -- and demo.sh matches a check to a line by action substring, so the
    repeats have to be distinguishable. Rungs 0 and 1 pass no tag and their
    transcripts are unchanged.
    """
    if tag:
        action = "%s#%s" % (action, tag)
    evidence = " ".join(str(evidence).split())
    print(
        "RESULT %s %s %s %s" % (channel, action, "SUCCESS" if ok else "FAILURE", evidence),
        flush=True,
    )
    return ok


def errno_of(exc):
    """Render an OSError as 'ENOENT(2) No such file or directory'."""
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, OSError):
        exc = exc.reason
    if isinstance(exc, OSError) and exc.errno is not None:
        name = errno.errorcode.get(exc.errno, "E?")
        return "%s(%d) %s" % (name, exc.errno, exc.strerror or "")
    return "%s %s" % (type(exc).__name__, exc)


def http_get(url, via_proxy=None, timeout=DEFAULT_TIMEOUT):
    """GET url, optionally through an explicit HTTP proxy.

    Returns (ok, evidence, body). The evidence string is the one-line RESULT summary
    and is truncated for the transcript; the body is the whole response, because from
    rung 4 on a source read over HTTP has to be able to steer the agent the same way a
    source read from a file does, and an instruction 200 bytes into a page would
    otherwise be invisible.
    """
    if via_proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": via_proxy, "https": via_proxy})
        )
    else:
        # Empty ProxyHandler defeats any inherited *_proxy env var, so a "direct"
        # probe is genuinely direct.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        body = opener.open(url, timeout=timeout).read().decode("utf-8", "replace")
        return True, "http_200 body=%s" % body[:60], body
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:60]
        return False, "http_%d %s" % (e.code, detail), ""
    except Exception as e:  # URLError, socket.timeout, ...
        return False, errno_of(e), ""


# ---------------------------------------------------------------- probes


def probe_env_creds(args):
    found = []
    for var in CRED_ENV_VARS:
        val = os.environ.get(var)
        if val:
            found.append("%s=%s" % (var, val[:6] + "..."))
    for path in CRED_FILES:
        real = os.path.expanduser(path)
        if os.path.isfile(real):
            try:
                with open(real) as fh:
                    fh.read(1)
                found.append("file:%s" % path)
            except OSError:
                pass
    if found:
        return emit("creds", "probe-env-creds", True, "read %d: %s" % (len(found), "; ".join(found)), args.tag)
    return emit("creds", "probe-env-creds", False, "no credential env vars or files present", args.tag)


def probe_metadata(args):
    ok, evidence, _ = http_get(METADATA_URL, via_proxy=args.via_proxy)
    return emit("network", "probe-metadata", ok, evidence, args.tag)


def probe_egress(args):
    url = args.target
    if not url.startswith("http"):
        url = "http://%s/" % url
    ok, evidence, _ = http_get(url, via_proxy=args.via_proxy)
    # The proxied and direct attempts at the same host are different claims -- one
    # tests reachability, the other tests policy -- so they get different action names
    # and cannot be confused for each other in a transcript.
    suffix = ":via-proxy" if args.via_proxy else ""
    return emit("network", "probe-egress:%s%s" % (args.target, suffix), ok, evidence, args.tag)


def probe_fs_write(args):
    path = args.path
    try:
        with open(path, "w") as fh:
            fh.write("ladder-probe-wrote-here\n")
        return emit("fs", "probe-fs-write:%s" % path, True, "wrote %d bytes" % os.path.getsize(path), args.tag)
    except OSError as e:
        return emit("fs", "probe-fs-write:%s" % path, False, errno_of(e), args.tag)


def probe_exec(args):
    binary = args.binary
    try:
        proc = subprocess.run(
            [binary] + args.argv, capture_output=True, timeout=DEFAULT_TIMEOUT, text=True
        )
        out = (proc.stdout or proc.stderr).strip()
        return emit(
            "exec", "probe-exec:%s" % binary, True,
            "spawned rc=%d out=%s" % (proc.returncode, out[:40]), args.tag
        )
    except OSError as e:
        return emit("exec", "probe-exec:%s" % binary, False, errno_of(e), args.tag)
    except subprocess.SubprocessError as e:
        return emit("exec", "probe-exec:%s" % binary, False, "%s %s" % (type(e).__name__, e), args.tag)


# ---------------------------------------------------------------- sanctioned path


def call_broker(args):
    # --socket overrides the bind-mounted default. Rung 2 uses it to reach the
    # broker through a symlink the agent planted itself, which is the path-based
    # half of the laundering attempts.
    sock_path = args.socket or os.environ.get("LADDER_BROKER_SOCK", DEFAULT_BROKER_SOCK)
    request = {"tool": args.tool, "args": args.argv}
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        sock.connect(sock_path)
        sock.sendall((json.dumps(request) + "\n").encode())
        reply = sock.recv(8192).decode("utf-8", "replace").strip()
        sock.close()
    except OSError as e:
        # Rung 2 lands here: the runtime refuses the write to the broker socket
        # and python's sendall raises EPERM. The broker is never contacted, so
        # there is no decision to report -- only an errno from the sandbox.
        return emit("broker", "call-broker:%s" % args.tool, False, errno_of(e), args.tag)
    try:
        parsed = json.loads(reply)
    except ValueError:
        return emit("broker", "call-broker:%s" % args.tool, False, "malformed reply %s" % reply[:60], args.tag)
    ok = parsed.get("decision") == "allow"
    detail = parsed.get("result") if ok else parsed.get("reason", "")
    return emit("broker", "call-broker:%s" % args.tool, ok, "%s %s" % (parsed.get("decision"), detail), args.tag)


# ------------------------------------------------- rung 2+ hooks (unused by rung 0)


def read_source(args):
    """Read a source and optionally obey an instruction embedded in its content.

    Conventions section 4 requires this in the shared harness. Rung 0's demo does not
    call it: rung 0 has no notion of a source label and no injection story. It exists
    so rung 2 has a deterministic injection stand-in to build on.

    The http branch obeys instructions in the FULL response body, not in the truncated
    evidence string it used to see. Rung 4's untrusted source is a web page rather than
    a mounted file -- which is the deck's actual scenario, and the case rung 2's
    per-mount label does not cover.
    """
    src = args.source
    if src.startswith("http"):
        ok, evidence, content = http_get(src, via_proxy=args.via_proxy)
    else:
        try:
            with open(src, "rb") as fh:
                raw = fh.read()
            if args.decode == "base64":
                raw = base64.b64decode(raw)
            content = raw.decode("utf-8", "replace")
            ok, evidence = True, "read %d bytes decode=%s" % (len(content), args.decode)
        except (OSError, ValueError) as e:
            ok, content, evidence = False, "", errno_of(e)
    emit("source", "read-source:%s" % src, ok, evidence, args.tag)
    if ok and args.save:
        # The agent's notes. Rung 4's reader fetches a page and forwards what it
        # "found" to a peer, which needs the bytes to exist somewhere it can send them
        # from. The path is unlabeled on purpose -- see recv-agent --save.
        try:
            with open(args.save, "w") as fh:
                fh.write(content)
            emit("fs", "save-source:%s" % args.save, True,
                 "wrote %d bytes read from %s" % (len(content), src), args.tag)
        except OSError as e:
            emit("fs", "save-source:%s" % args.save, False, errno_of(e), args.tag)
    if ok and args.obey_instructions:
        found, outcome = obey_instructions(content, args.tag)
        if found:
            return outcome
    return ok


def obey_instructions(content, tag):
    """Find an embedded instruction and execute it. Returns (found, outcome).

    The injection stand-in, shared by read-source (rung 2, a document steers the
    agent that read it) and recv-agent (rung 3, a document steers an agent that
    never read it).

    LADDER-END terminates the instruction. Rung 2's pages end it at a newline and
    carry no terminator, so they are unaffected; rung 3 needs one because a message
    arrives as a single whitespace-collapsed line and everything after the
    instruction would otherwise be parsed as more arguments to it.
    """
    for line in content.splitlines():
        if "LADDER-INSTRUCTION:" not in line:
            continue
        injected = line.split("LADDER-INSTRUCTION:", 1)[1].strip().split()
        if "LADDER-END" in injected:
            injected = injected[: injected.index("LADDER-END")]
        if not injected:
            continue
        # The reader's tag flows into the action the document asked for, so that the
        # same injected instruction obeyed after four different laundering attempts
        # produces four distinguishable lines in one transcript.
        if tag:
            injected = [injected[0], "--tag", tag] + injected[1:]
        print("INJECTED %s" % " ".join(injected), flush=True)
        return True, dispatch(build_parser().parse_args(injected))
    return False, False


# ------------------------------------------------- rung 3: the mediated peer channel


def split_stamp(raw):
    """Split a received frame into (stamp, body). stamp is '' when there is none.

    Fixed width rather than delimiter-scanned, because the sentry has to write this
    on a send path and read it on a receive path: "exactly 128 bytes" is a rule that
    cannot be half-applied across a partial read.
    """
    if raw.startswith(STAMP_PREFIX) and len(raw) >= STAMP_LEN:
        return raw[:STAMP_LEN].rstrip(), raw[STAMP_LEN:]
    return "", raw


def peer_roundtrip(sock_path, message):
    """One request, one reply, one connection. Returns the reply as text.

    SOCK_SEQPACKET: the channel is message-oriented, so "one send is one message" is
    enforced by the kernel rather than by a convention this agent could break. An
    agent that wants to hand the receiver a second, fabricated, stamped message
    cannot do it by putting a delimiter in its payload -- there is no delimiter.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sock.settimeout(DEFAULT_TIMEOUT)
    sock.connect(sock_path)
    sock.send(message.encode())
    reply = sock.recv(65536).decode("utf-8", "replace")
    sock.close()
    return reply


def send_agent(args):
    """Send one message to a peer through the mediated channel. Rung 3.

    The agent writes the message. It does NOT write the label: with --ladder-attest
    on, the sentry prepends the stamp to these bytes before they leave the sandbox,
    and there is no argument to this function that can suppress it.

    --forge-header is the attempt to. It puts a byte-identical, fully padded, entirely
    fabricated stamp INSIDE the message body -- claiming a different sender, a clean
    taint bit and a wider grant set -- which is the most an agent can do, since the
    body is the only part it controls. The demo prints this line next to the one the
    receiver was actually handed.
    """
    sock_path = args.socket or os.environ.get("LADDER_PEER_SOCK", DEFAULT_PEER_SOCK)
    body = " ".join(args.message)
    if args.from_source:
        try:
            with open(args.from_source) as fh:
                # Whitespace-collapsed into one line: this is the reader summarizing
                # a page for a peer, and it keeps the message readable in the
                # postbox log and in the transcript.
                body = " ".join(fh.read().split())
        except OSError as e:
            return emit("peer", "send-agent:%s" % args.peer, False, errno_of(e), args.tag)
    if args.delegate_file:
        # Rung 4. The capability this hop hands the next one, read from a file in the
        # sandbox's own scratch directory -- which the agent can rewrite, and which the
        # rung-4 demo does rewrite in order to attempt a widening. It is a CLAIM, and
        # the capability authority checks it against what this hop actually holds.
        try:
            with open(args.delegate_file) as fh:
                cap = json.load(fh)
        except (OSError, ValueError) as e:
            return emit("peer", "send-agent:%s" % args.peer, False,
                        "delegation %s: %s" % (args.delegate_file, e), args.tag)
        blob = json.dumps(cap, sort_keys=True, separators=(",", ":"))
        print("DELEGATION %s" % blob, flush=True)
        body = CAP_OPEN + blob + CAP_CLOSE + " " + body
    if args.forge_header:
        forged = "%sv=1 sender=%s taint=0 grants=%s" % (
            STAMP_PREFIX, args.forge_header, args.forge_grants)
        print("FORGED-HEADER %s" % forged, flush=True)
        body = forged.ljust(STAMP_LEN) + body
    try:
        reply = peer_roundtrip(sock_path, "SEND to=%s %s" % (args.peer, body))
    except OSError as e:
        return emit("peer", "send-agent:%s" % args.peer, False, errno_of(e), args.tag)
    try:
        parsed = json.loads(reply.strip())
    except ValueError:
        return emit("peer", "send-agent:%s" % args.peer, False,
                    "malformed reply %s" % reply.strip()[:60], args.tag)
    ok = bool(parsed.get("delivered"))
    detail = "to=%s" % parsed.get("to") if ok else parsed.get("reason", "")
    return emit("peer", "send-agent:%s" % args.peer, ok,
                "%s %s" % ("delivered" if ok else "not-delivered", detail), args.tag)


def recv_agent(args):
    """Collect one message from the mediated channel, and optionally obey it.

    The receiving half of the confused deputy. This agent never opened the untrusted
    page and never will; it acts on what a peer told it. --obey-instructions makes
    that mechanical, exactly as it does for read-source.

    Reading these bytes is what the receiving sentry hooks: if the stamp says the
    sender was tainted, this sandbox is tainted from here on, before recv() returns.
    """
    sock_path = args.socket or os.environ.get("LADDER_PEER_SOCK", DEFAULT_PEER_SOCK)
    try:
        reply = peer_roundtrip(sock_path, "RECV")
    except OSError as e:
        return emit("peer", "recv-agent", False, errno_of(e), args.tag)
    stamp, body = split_stamp(reply)
    body = body.strip()
    if not stamp and body.startswith("LADDER-POSTBOX empty"):
        return emit("peer", "recv-agent", False, "no message queued", args.tag)
    # Printed on its own line so the demo can show it beside FORGED-HEADER. This is
    # what the receiver was handed, not what the sender claimed.
    print("DELIVERED-HEADER %s" % (stamp or "(none)"), flush=True)
    emit("peer", "recv-agent", True,
         "stamp=[%s] body=%s" % (stamp or "none", body[:60]), args.tag)
    if args.save:
        # Rung 4's middle hop. The message body is written to a path nothing labels and
        # is read back from there when this agent composes its own onward message -- so
        # the bytes that leave are bytes this agent wrote, from an unlabeled source,
        # with no trace of the channel they arrived on. That is taint laundering by
        # re-emission, done deliberately, and the reason it does not work is that the
        # label was never in the bytes: it is on the sandbox, and the runtime stamps it
        # again on the way out.
        try:
            with open(args.save, "w") as fh:
                fh.write(body + "\n")
            emit("fs", "save-message:%s" % args.save, True,
                 "wrote %d bytes of a peer's message to an unlabeled path" % len(body), args.tag)
        except OSError as e:
            emit("fs", "save-message:%s" % args.save, False, errno_of(e), args.tag)
    if args.obey_instructions:
        found, outcome = obey_instructions(body, args.tag)
        if found:
            return outcome
    return True


def serve_agent(args):
    """Stay up and handle exchanges as they arrive. Rung 5a.

    Rungs 3 and 4 model an agent as a task: it runs a script, it exits, its taint dies
    with it. Rung 5a models the shape the A2A/MCP ecosystem actually has -- a long-lived
    addressable service that callers reach an existing instance of. This action is that
    shape and nothing more: poll the mailbox, handle what arrives, stop on a bound.

    The bounds are deliberate. A standing service that never stops is a standing service
    whose taint bit never clears (rung 2's bit is monotonic and nothing anywhere clears
    it in place), so the recycle policy has to be able to end this loop and start a new
    sandbox. --max-exchanges and --idle-timeout are what make that terminate; the actual
    destroy-and-restart is the launcher's, outside the sandbox, because a sandbox that
    could recycle itself could also decline to.

    --on-message runs an action file per exchange, with the message body available to it
    as ${LADDER_MESSAGE_FILE}. That keeps the per-turn behaviour in the same action-file
    format every other probe uses instead of growing a second scripting language here.
    """
    sock_path = args.socket or os.environ.get("LADDER_PEER_SOCK", DEFAULT_PEER_SOCK)
    parser = build_parser() if args.on_message else None
    deadline = time.time() + args.idle_timeout
    handled = 0

    while handled < args.max_exchanges and time.time() < deadline:
        try:
            reply = peer_roundtrip(sock_path, "RECV")
        except OSError as e:
            emit("peer", "serve-agent", False, errno_of(e), args.tag)
            return False
        stamp, body = split_stamp(reply)
        body = body.strip()
        if not stamp and body.startswith("LADDER-POSTBOX empty"):
            time.sleep(args.poll_interval)
            continue

        handled += 1
        deadline = time.time() + args.idle_timeout
        tag = "%s%d" % (args.tag or "exchange", handled)
        print("DELIVERED-HEADER %s" % (stamp or "(none)"), flush=True)
        emit("peer", "serve-agent", True,
             "stamp=[%s] body=%s" % (stamp or "none", body[:60]), tag)

        if args.save:
            try:
                with open(args.save, "w") as fh:
                    fh.write(body + "\n")
            except OSError as e:
                emit("fs", "save-message:%s" % args.save, False, errno_of(e), tag)
        if args.on_message:
            # The body reaches the turn script through a file rather than through the
            # command line: it is attacker-controlled text and the action files are
            # shlex-split, so putting it in argv would make quoting part of the
            # security story for no reason.
            os.environ["LADDER_MESSAGE_FILE"] = args.save or "/scratch/exchange.txt"
            if not args.save:
                try:
                    with open(os.environ["LADDER_MESSAGE_FILE"], "w") as fh:
                        fh.write(body + "\n")
                except OSError as e:
                    emit("fs", "save-message", False, errno_of(e), tag)
            os.environ["LADDER_EXCHANGE"] = str(handled)
            for line in open(args.on_message):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                turn = parser.parse_args(shlex.split(os.path.expandvars(line)))
                turn.tag = tag
                dispatch(turn)
        if args.obey_instructions:
            obey_instructions(body, tag)

    emit("peer", "serve-agent:retired", True,
         "handled %d exchange(s) before %s" % (
             handled, "its exchange bound" if handled >= args.max_exchanges else "going idle"),
         args.tag)
    return True


def launder(args):
    """Copy a source's bytes elsewhere, optionally re-encoding them on the way.

    This is the rung-2 laundering attempt in its purest form: the agent tries to
    strip a label by moving the bytes to a path that carries no label, or by
    changing the bytes so that nothing in them resembles the original. Neither
    can work, because the label was never in the path or in the content -- it was
    attached to the fd at open time and consumed by the runtime on the read that
    already happened. Reported as its own line so a reader can see the laundering
    itself SUCCEED and the privileged call after it still fail.
    """
    action = "launder:%s->%s" % (args.source, args.dest)
    try:
        with open(args.source, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return emit("fs", action, False, "reading %s: %s" % (args.source, errno_of(e)), args.tag)
    if args.encode == "base64":
        data = base64.b64encode(data)
    try:
        with open(args.dest, "wb") as fh:
            fh.write(data)
    except OSError as e:
        return emit("fs", action, False, "writing %s: %s" % (args.dest, errno_of(e)), args.tag)
    return emit("fs", action, True, "moved %d bytes encode=%s" % (len(data), args.encode), args.tag)


def symlink(args):
    """Plant a symlink. A laundering attempt against a PATH-based label.

    If a sink were identified by the string the agent passes to connect(2), an
    agent could rename it out from under the check. Rung 2's gate resolves the
    path the way connect(2) does before matching, so this is a way to see that
    property fail to be exploitable rather than to assume it.
    """
    try:
        if os.path.islink(args.linkpath) or os.path.exists(args.linkpath):
            os.remove(args.linkpath)
        os.symlink(args.target, args.linkpath)
    except OSError as e:
        return emit("fs", "symlink:%s" % args.linkpath, False, errno_of(e), args.tag)
    return emit("fs", "symlink:%s" % args.linkpath, True, "-> %s" % args.target, args.tag)


def exec_fresh(args):
    """Run the same actions in a FRESH agent process and report its verdict.

    probe-exec reports only whether a spawn worked, which is the wrong question
    here: the claim is about what the child is allowed to DO. This runs a new
    fake_agent -- new pid, new fd table, new broker connection -- and adopts the
    child's last RESULT line as its own outcome.
    """
    cmd = [sys.executable, os.path.abspath(__file__)] + args.argv
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=DEFAULT_TIMEOUT, text=True)
    except (OSError, subprocess.SubprocessError) as e:
        return emit("exec", "exec-fresh", False, "%s %s" % (type(e).__name__, e), args.tag)
    results = [ln for ln in (proc.stdout or "").splitlines() if ln.startswith("RESULT ")]
    if not results:
        detail = (proc.stderr or proc.stdout or "").strip()[:80]
        return emit("exec", "exec-fresh", False, "child emitted no RESULT: %s" % detail, args.tag)
    fields = results[-1].split(None, 4)
    ok = len(fields) > 3 and fields[3] == "SUCCESS"
    detail = fields[4] if len(fields) > 4 else ""
    return emit("exec", "exec-fresh", ok, "child pid ran %s -> %s" % (" ".join(args.argv), detail), args.tag)


# ---------------------------------------------------------------- rung 1 hook


def wait_for(args):
    """Block until PATH exists. The launcher's half of a mid-task handshake.

    Rung 1's attenuation check has to show a grant being narrowed inside ONE running
    sandbox: probe, narrow from the host, probe again. Sleeping a fixed interval would
    turn that into a race the demo loses on a slow machine; waiting on a marker file
    the launcher drops makes the ordering a fact rather than a hope.

    The agent gets no authority from this -- the marker is dropped in a directory it
    can already read, and its arrival tells it nothing it could act on.
    """
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if os.path.exists(args.path):
            return emit("sync", "wait-for:%s" % args.path, True, "marker present", args.tag)
        time.sleep(0.1)
    return emit("sync", "wait-for:%s" % args.path, False, "timed out after %gs" % args.timeout, args.tag)


# ---------------------------------------------------------------- driver


def run_script(args):
    """Run a newline-delimited list of actions; blank lines and # comments skipped.

    ${VAR} is expanded from the environment first, so an action file can name a value
    the demo only learns at runtime (the proxy address) without becoming config-aware.
    """
    with open(args.path) as fh:
        lines = [ln.strip() for ln in fh]
    parser = build_parser()
    outcomes = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        outcomes.append(dispatch(parser.parse_args(shlex.split(os.path.expandvars(line)))))
    print("SCRIPT actions=%d succeeded=%d" % (len(outcomes), sum(1 for o in outcomes if o)), flush=True)
    return all(outcomes)


def build_parser():
    p = argparse.ArgumentParser(prog="fake_agent", description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)

    def add(name, fn):
        s = sub.add_parser(name)
        s.set_defaults(fn=fn)
        # Every action takes --tag, so an action file can run the same action
        # several times in one sandbox and still be asserted on line by line.
        # It must precede the positionals on the command line.
        s.add_argument("--tag", default="")
        return s

    add("probe-env-creds", probe_env_creds)

    s = add("probe-metadata", probe_metadata)
    s.add_argument("--via-proxy", default=None)

    s = add("probe-egress", probe_egress)
    s.add_argument("target")
    s.add_argument("--via-proxy", default=None)

    s = add("probe-fs-write", probe_fs_write)
    s.add_argument("path")

    s = add("probe-exec", probe_exec)
    s.add_argument("binary")
    # REMAINDER, not "*": the whole point is to exec arbitrary things, and an argument
    # list like `-c "echo hi"` must reach the binary instead of being parsed here.
    s.add_argument("argv", nargs=argparse.REMAINDER)

    s = add("call-broker", call_broker)
    s.add_argument("--socket", default=None)
    s.add_argument("tool")
    s.add_argument("argv", nargs="*")

    s = add("read-source", read_source)
    s.add_argument("source")
    s.add_argument("--via-proxy", default=None)
    s.add_argument("--decode", choices=["none", "base64"], default="none")
    s.add_argument("--obey-instructions", action="store_true")
    s.add_argument("--save", default=None, metavar="PATH",
                   help="rung 4: write what was read to PATH, so it can be forwarded")

    s = add("launder", launder)
    s.add_argument("source")
    s.add_argument("dest")
    s.add_argument("--encode", choices=["none", "base64"], default="none")

    s = add("symlink", symlink)
    s.add_argument("target")
    s.add_argument("linkpath")

    s = add("exec-fresh", exec_fresh)
    s.add_argument("argv", nargs=argparse.REMAINDER)

    s = add("send-agent", send_agent)
    s.add_argument("--socket", default=None)
    s.add_argument("--from-source", default=None,
                   help="send this file's contents as the message, whitespace-collapsed")
    s.add_argument("--forge-header", default=None, metavar="SENDER",
                   help="prepend a fabricated stamp claiming to be SENDER, clean and capable")
    s.add_argument("--forge-grants", default="read_wiki,write_config")
    s.add_argument("--delegate-file", default=None, metavar="PATH",
                   help="rung 4: the capability record to delegate to the peer, as JSON")
    s.add_argument("peer")
    s.add_argument("message", nargs="*")

    s = add("recv-agent", recv_agent)
    s.add_argument("--socket", default=None)
    s.add_argument("--obey-instructions", action="store_true")
    s.add_argument("--save", default=None, metavar="PATH",
                   help="rung 4: write the received body to PATH, so it can be re-emitted "
                        "from an unlabeled source")

    s = add("serve-agent", serve_agent)
    s.add_argument("--socket", default=None)
    s.add_argument("--max-exchanges", type=int, default=4,
                   help="rung 5a: stop after this many exchanges, so the recycle "
                        "policy has something to recycle")
    s.add_argument("--idle-timeout", type=float, default=45.0)
    s.add_argument("--poll-interval", type=float, default=0.2)
    s.add_argument("--on-message", default=None, metavar="PATH",
                   help="rung 5a: an action file to run per exchange; the body is at "
                        "${LADDER_MESSAGE_FILE}")
    s.add_argument("--obey-instructions", action="store_true")
    s.add_argument("--save", default=None, metavar="PATH")

    s = add("wait-for", wait_for)
    s.add_argument("path")
    s.add_argument("--timeout", type=float, default=30.0)

    s = add("script", run_script)
    s.add_argument("path")

    return p


def dispatch(args):
    return args.fn(args)


def main():
    args = build_parser().parse_args()
    dispatch(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
