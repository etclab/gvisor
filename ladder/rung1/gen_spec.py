#!/usr/bin/env python3
"""gen_spec - turn a task manifest into the sandbox that task gets, and nothing more.

Rung 0 wrote its sandbox by hand, in config/rung0/agent.args. That file is the agent's
ROLE: the union of everything the agent might ever need, fixed at deploy time. Rung 1
deletes that file and derives the sandbox from the task instead, so the reviewer's
question changes from "who wrote this list" to "which manifest field produced this
restriction".

    gen_spec.py show <manifest>            print the manifest -> restriction table
    gen_spec.py emit <manifest> <outdir>   write the generated spec into outdir

emit writes four files, and between them they are the whole sandbox:

    agent.args    docker run arguments, in the rung-0 one-per-line format
    proxy.args    the task's egress allowlist, for its own proxy
    broker.args   the task's tool scope and task id, for its own broker
    meta.env      values demo.sh needs as shell variables (network name, ttl, image)

Deterministic by construction: the output is a pure function of the manifest text.
Nothing here reads the clock, the environment, or the docker state, and runtime values
the manifest cannot know -- the task's directory and its proxy's address -- are emitted
as ${VAR} placeholders for lib.sh's ladder_load_args to expand at launch. demo.sh
diffs two independent emits as a check.

Manifest format is a deliberately small subset of YAML; see parse_manifest.
"""

import argparse
import os
import sys

# The world the demo stands up. This is fixture, not policy: every task resolves every
# name identically, so a denial is always the allowlist talking and never a name that
# failed to resolve. (Docker's embedded DNS does not work under runsc -- rung 0's
# spec-correction 5 -- so resolution is static /etc/hosts entries either way.)
WORLD_HOSTS = [
    ("wiki.corp", "169.254.0.10"),
    ("evil.example.com", "169.254.0.20"),
    ("metrics.local", "169.254.0.30"),
]

REQUIRED_FIELDS = ["task_id", "agent_image", "network_allow", "mounts", "broker_tools", "ttl_seconds"]

TASK_ID_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def parse_manifest(path):
    """Parse the manifest subset: scalars, one-level lists, one-level maps.

        key: value
        key:
          - item
          - item
        key:
          sub: value

    python3 ships no YAML parser and the ladder installs nothing, so this reads exactly
    the shape the manifests use and refuses everything else. Refusing is the point: a
    line that silently fails to parse is a grant that silently fails to apply, and the
    sandbox would be wrong in the safe-looking direction only by luck.
    """
    data = {}
    current = None  # key whose nested block we are inside
    with open(path) as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            body = line.strip()
            if indent == 0:
                if ":" not in body:
                    raise ValueError("%s:%d: expected 'key: value' or 'key:'" % (path, lineno))
                key, _, value = body.partition(":")
                key, value = key.strip(), value.strip()
                if value:
                    data[key] = value
                    current = None
                else:
                    data[key] = None  # filled in by the nested block below
                    current = key
                continue
            if current is None:
                raise ValueError("%s:%d: indented line outside any block" % (path, lineno))
            if body.startswith("- "):
                item = body[2:].strip()
                if data[current] is None:
                    data[current] = []
                if not isinstance(data[current], list):
                    raise ValueError("%s:%d: mixed list and map under %r" % (path, lineno, current))
                data[current].append(item)
            elif ":" in body:
                sub, _, value = body.partition(":")
                if data[current] is None:
                    data[current] = {}
                if not isinstance(data[current], dict):
                    raise ValueError("%s:%d: mixed map and list under %r" % (path, lineno, current))
                data[current][sub.strip()] = value.strip()
            else:
                raise ValueError("%s:%d: expected '- item' or 'key: value'" % (path, lineno))
    return data


def validate(manifest, path):
    """Reject anything we would not act on. An unenforced field is a lie in a config."""
    missing = [f for f in REQUIRED_FIELDS if manifest.get(f) is None]
    if missing:
        raise ValueError("%s: missing required field(s): %s" % (path, ", ".join(missing)))
    unknown = sorted(set(manifest) - set(REQUIRED_FIELDS))
    if unknown:
        raise ValueError("%s: unknown field(s): %s (this generator would ignore them)" % (path, ", ".join(unknown)))

    task_id = manifest["task_id"]
    if not set(task_id) <= TASK_ID_CHARS:
        raise ValueError("%s: task_id %r must be [a-z0-9-]; it becomes a docker object name" % (path, task_id))
    if not isinstance(manifest["network_allow"], list):
        raise ValueError("%s: network_allow must be a list" % path)
    if not isinstance(manifest["broker_tools"], list):
        raise ValueError("%s: broker_tools must be a list" % path)
    if not isinstance(manifest["mounts"], dict):
        raise ValueError("%s: mounts must be a map" % path)
    unknown_mounts = sorted(set(manifest["mounts"]) - {"scratch"})
    if unknown_mounts:
        raise ValueError("%s: unknown mount(s): %s (only 'scratch' exists)" % (path, ", ".join(unknown_mounts)))
    if manifest["mounts"].get("scratch") not in (None, "rw", "none"):
        raise ValueError("%s: mounts.scratch must be rw or none" % path)
    try:
        int(manifest["ttl_seconds"])
    except ValueError:
        raise ValueError("%s: ttl_seconds must be an integer" % path)
    return manifest


def load(path):
    return validate(parse_manifest(path), path)


def network_name(manifest):
    return "ladder-net-%s" % manifest["task_id"]


def agent_args(manifest):
    """The docker run arguments. Every line traces to a manifest field or is hygiene."""
    task_id = manifest["task_id"]
    out = [
        "# GENERATED by rung1/gen_spec.py from manifests/%s -- do not edit." % task_id,
        "# Every restriction below is derived from that manifest. Regenerate, do not patch.",
        "",
        "# The task runs under gVisor, and reaches its broker over a host unix socket.",
        "--runtime=${LADDER_TASK_RUNTIME}",
        "--annotation=dev.gvisor.flag.host-uds=open",
        "",
        "# network_allow -> a network private to this task, whose only other occupant is",
        "# this task's proxy. Deny-by-default is the topology; the allowlist is proxy.args.",
        "--network=%s" % network_name(manifest),
        "--env=LADDER_PROXY=http://${LADDER_PROXY_IP}:3128",
        "",
        "# Fixture, identical for every task: a denial must be the allowlist talking and",
        "# never a name that failed to resolve.",
    ]
    out += ["--add-host=%s:%s" % (host, ip) for host, ip in WORLD_HOSTS]
    out += [
        "",
        "# mounts -> the only writable host path, and it belongs to this task alone.",
        "--read-only",
    ]
    if manifest["mounts"].get("scratch") == "rw":
        out.append("--volume=${LADDER_TASK_DIR}/scratch:/scratch")
    else:
        out.append("# mounts.scratch is not rw: this task gets no writable host path at all.")
    out += [
        "",
        "# broker_tools -> this task's own broker socket. Which socket the sandbox can",
        "# reach IS its task identity, so there is nothing for the agent to forge.",
        "--volume=${LADDER_TASK_DIR}/sock:/broker",
        "",
        "# Hygiene, identical to rung 0. Not load-bearing for any rung-1 claim.",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--label=ladder-task=%s" % task_id,
    ]
    return "\n".join(out) + "\n"


def proxy_args(manifest):
    lines = [
        "# GENERATED from manifests/%s -- the egress allowlist for this task only." % manifest["task_id"],
        "--task-id",
        manifest["task_id"],
        "--control",
        "/ctl/proxy.sock",
    ]
    for entry in manifest["network_allow"]:
        lines += ["--allow", entry]
    return "\n".join(lines) + "\n"


def broker_args(manifest):
    return "\n".join(
        [
            "# GENERATED from manifests/%s -- the tool scope for this task only." % manifest["task_id"],
            "--task-id",
            manifest["task_id"],
            "--tools",
            ",".join(manifest["broker_tools"]),
        ]
    ) + "\n"


def meta_env(manifest):
    return "".join(
        [
            "# GENERATED from manifests/%s -- values demo.sh needs as shell variables.\n" % manifest["task_id"],
            "LADDER_TASK_ID=%s\n" % manifest["task_id"],
            "LADDER_TASK_NET=%s\n" % network_name(manifest),
            "LADDER_TASK_IMAGE=%s\n" % manifest["agent_image"],
            "LADDER_TASK_TTL=%d\n" % int(manifest["ttl_seconds"]),
        ]
    )


def cmd_emit(args):
    manifest = load(args.manifest)
    os.makedirs(args.outdir, exist_ok=True)
    for name, text in [
        ("agent.args", agent_args(manifest)),
        ("proxy.args", proxy_args(manifest)),
        ("broker.args", broker_args(manifest)),
        ("meta.env", meta_env(manifest)),
    ]:
        with open(os.path.join(args.outdir, name), "w") as fh:
            fh.write(text)
    return 0


def cmd_show(args):
    manifest = load(args.manifest)
    scratch = manifest["mounts"].get("scratch", "none")
    rows = [
        ("task_id", manifest["task_id"], "names the network, the proxy, the broker and the scratch dir"),
        ("agent_image", manifest["agent_image"], "the same image every task uses"),
        ("network_allow", ", ".join(manifest["network_allow"]), "--allow on this task's own proxy"),
        ("broker_tools", ", ".join(manifest["broker_tools"]), "--tools on this task's own broker"),
        ("mounts.scratch", scratch, "/scratch, under this task's directory only"),
        ("ttl_seconds", manifest["ttl_seconds"], "hard timeout around the sandbox"),
    ]
    print("%-16s %-34s %s" % ("MANIFEST FIELD", "VALUE", "BECOMES"))
    print("-" * 108)
    for field, value, becomes in rows:
        print("%-16s %-34s %s" % (field, value, becomes))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("emit")
    s.add_argument("manifest")
    s.add_argument("outdir")
    s.set_defaults(fn=cmd_emit)

    s = sub.add_parser("show")
    s.add_argument("manifest")
    s.set_defaults(fn=cmd_show)

    args = ap.parse_args()
    try:
        return args.fn(args)
    except (ValueError, OSError) as e:
        sys.exit("gen_spec: %s" % e)


if __name__ == "__main__":
    sys.exit(main())
