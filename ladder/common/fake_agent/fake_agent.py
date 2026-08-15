#!/usr/bin/env python3
"""fake_agent - a scripted stand-in for an LLM agent.

Per ladder conventions section 4: the sandbox cannot distinguish a syscall made by a
hijacked LLM from one made by a shell script, so every ladder demo drives a
deterministic script instead of a model. No API keys, no network to the internet,
identical output on every run.

Each action prints exactly one machine-parsable line:

    RESULT <channel> <action> <SUCCESS|FAILURE> <evidence>

channel is one of: creds, network, fs, exec, broker, source, peer.
SUCCESS means the agent achieved the world-effect it attempted. Whether that is good
or bad news depends on which config it was run under -- that judgement lives in
demo.sh, not here.

The process exits 0 whenever every action ran to completion, even if every probe was
denied. A non-zero exit means the harness itself broke.
"""

import argparse
import errno
import json
import os
import shlex
import socket
import subprocess
import sys
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


def emit(channel, action, ok, evidence):
    """Print the one canonical result line and return the outcome."""
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
    """GET url, optionally through an explicit HTTP proxy. Returns (ok, evidence)."""
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
        return True, "http_200 body=%s" % body[:60]
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:60]
        return False, "http_%d %s" % (e.code, detail)
    except Exception as e:  # URLError, socket.timeout, ...
        return False, errno_of(e)


# ---------------------------------------------------------------- probes


def probe_env_creds(_args):
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
        return emit("creds", "probe-env-creds", True, "read %d: %s" % (len(found), "; ".join(found)))
    return emit("creds", "probe-env-creds", False, "no credential env vars or files present")


def probe_metadata(args):
    ok, evidence = http_get(METADATA_URL, via_proxy=args.via_proxy)
    return emit("network", "probe-metadata", ok, evidence)


def probe_egress(args):
    url = args.target
    if not url.startswith("http"):
        url = "http://%s/" % url
    ok, evidence = http_get(url, via_proxy=args.via_proxy)
    # The proxied and direct attempts at the same host are different claims -- one
    # tests reachability, the other tests policy -- so they get different action names
    # and cannot be confused for each other in a transcript.
    suffix = ":via-proxy" if args.via_proxy else ""
    return emit("network", "probe-egress:%s%s" % (args.target, suffix), ok, evidence)


def probe_fs_write(args):
    path = args.path
    try:
        with open(path, "w") as fh:
            fh.write("ladder-probe-wrote-here\n")
        return emit("fs", "probe-fs-write:%s" % path, True, "wrote %d bytes" % os.path.getsize(path))
    except OSError as e:
        return emit("fs", "probe-fs-write:%s" % path, False, errno_of(e))


def probe_exec(args):
    binary = args.binary
    try:
        proc = subprocess.run(
            [binary] + args.argv, capture_output=True, timeout=DEFAULT_TIMEOUT, text=True
        )
        out = (proc.stdout or proc.stderr).strip()
        return emit(
            "exec", "probe-exec:%s" % binary, True, "spawned rc=%d out=%s" % (proc.returncode, out[:40])
        )
    except OSError as e:
        return emit("exec", "probe-exec:%s" % binary, False, errno_of(e))
    except subprocess.SubprocessError as e:
        return emit("exec", "probe-exec:%s" % binary, False, "%s %s" % (type(e).__name__, e))


# ---------------------------------------------------------------- sanctioned path


def call_broker(args):
    sock_path = os.environ.get("LADDER_BROKER_SOCK", DEFAULT_BROKER_SOCK)
    request = {"tool": args.tool, "args": args.argv}
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        sock.connect(sock_path)
        sock.sendall((json.dumps(request) + "\n").encode())
        reply = sock.recv(8192).decode("utf-8", "replace").strip()
        sock.close()
    except OSError as e:
        return emit("broker", "call-broker:%s" % args.tool, False, errno_of(e))
    try:
        parsed = json.loads(reply)
    except ValueError:
        return emit("broker", "call-broker:%s" % args.tool, False, "malformed reply %s" % reply[:60])
    ok = parsed.get("decision") == "allow"
    detail = parsed.get("result") if ok else parsed.get("reason", "")
    return emit("broker", "call-broker:%s" % args.tool, ok, "%s %s" % (parsed.get("decision"), detail))


# ------------------------------------------------- rung 2+ hooks (unused by rung 0)


def read_source(args):
    """Read a source and optionally obey an instruction embedded in its content.

    Conventions section 4 requires this in the shared harness. Rung 0's demo does not
    call it: rung 0 has no notion of a source label and no injection story. It exists
    so rung 2 has a deterministic injection stand-in to build on.
    """
    src = args.source
    if src.startswith("http"):
        ok, evidence = http_get(src, via_proxy=args.via_proxy)
        content = evidence
    else:
        try:
            with open(src) as fh:
                content = fh.read()
            ok, evidence = True, "read %d bytes" % len(content)
        except OSError as e:
            ok, content, evidence = False, "", errno_of(e)
    emit("source", "read-source:%s" % src, ok, evidence)
    if ok and args.obey_instructions:
        for line in content.splitlines():
            if "LADDER-INSTRUCTION:" in line:
                injected = line.split("LADDER-INSTRUCTION:", 1)[1].strip().split()
                print("INJECTED %s" % " ".join(injected), flush=True)
                return dispatch(build_parser().parse_args(injected))
    return ok


def send_agent(args):
    """Peer messaging stand-in. Rung 3 gives messages labels; rung 0 does not."""
    return emit("peer", "send-agent:%s" % args.peer, False, "not implemented before rung 3")


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
    s.add_argument("tool")
    s.add_argument("argv", nargs="*")

    s = add("read-source", read_source)
    s.add_argument("source")
    s.add_argument("--via-proxy", default=None)
    s.add_argument("--obey-instructions", action="store_true")

    s = add("send-agent", send_agent)
    s.add_argument("peer")
    s.add_argument("message", nargs="*")

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
