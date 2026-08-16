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

# The mounts a task may ask for, and the modes each accepts. The first entry of
# each list is the default when the manifest omits the mount, so a rung-1
# manifest that names only scratch still gets its broker socket and still gets
# no untrusted source.
#
#   scratch    the task's own writable host directory
#   broker     the task's own broker socket -- its tools. Rung 2's read/act
#              split is a task with this set to none.
#   untrusted  a read-only mount whose contents the RUNTIME labels untrusted
#              (rung 2). The mount alone does nothing; --ladder-taint and
#              --ladder-untrusted-paths on the runtime are what give it meaning.
MOUNT_MODES = {
    "scratch": ["none", "rw"],
    "broker": ["rw", "none"],
    "untrusted": ["none", "ro"],
}


def mount_mode(manifest, name):
    return manifest["mounts"].get(name) or MOUNT_MODES[name][0]

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
                if value == "[]":
                    # The one literal the block form cannot express. Rung 2's
                    # reader task holds no tools and needs no egress, and
                    # "broker_tools:" with nothing under it is indistinguishable
                    # from a field someone forgot to fill in.
                    data[key] = []
                    current = None
                elif value:
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
    unknown_mounts = sorted(set(manifest["mounts"]) - set(MOUNT_MODES))
    if unknown_mounts:
        raise ValueError("%s: unknown mount(s): %s (known: %s)" % (
            path, ", ".join(unknown_mounts), ", ".join(sorted(MOUNT_MODES))))
    for name, allowed in MOUNT_MODES.items():
        value = manifest["mounts"].get(name)
        if value is not None and value not in allowed:
            raise ValueError("%s: mounts.%s must be one of: %s" % (path, name, ", ".join(allowed)))
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
    if mount_mode(manifest, "broker") == "rw":
        out += [
            "",
            "# broker_tools -> this task's own broker socket. Which socket the sandbox can",
            "# reach IS its task identity, so there is nothing for the agent to forge.",
            "--volume=${LADDER_TASK_DIR}/sock:/broker",
        ]
    else:
        out += [
            "",
            "# mounts.broker is none: this task has no broker socket in its filesystem at",
            "# all, so it holds no tools and can cause no world-effect through one.",
        ]
    if mount_mode(manifest, "untrusted") == "ro":
        out += [
            "",
            "# mounts.untrusted -> the labeled source (rung 2). This line only puts bytes",
            "# in the sandbox; what makes reading them taint it is --ladder-taint plus",
            "# --ladder-untrusted-paths=/untrusted on the runtime.",
            "--volume=${LADDER_TASK_DIR}/untrusted:/untrusted:ro",
        ]
    out += [
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
    lines = [
        "# GENERATED from manifests/%s -- the tool scope for this task only." % manifest["task_id"],
        "--task-id",
        manifest["task_id"],
    ]
    if manifest["broker_tools"]:
        lines += ["--tools", ",".join(manifest["broker_tools"])]
    else:
        # An empty scope has to be written as one token: lib.sh's ladder_load_args
        # drops blank lines, so "--tools" on its own line followed by an empty one
        # would reach the broker as a flag with no value and it would refuse to
        # start. A task with no tools is a real configuration -- rung 2's reader --
        # not a mistake, and it has to survive the round trip.
        lines += ["--tools="]
    return "\n".join(lines) + "\n"


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
    rows = [
        ("task_id", manifest["task_id"], "names the network, the proxy, the broker and the scratch dir"),
        ("agent_image", manifest["agent_image"], "the same image every task uses"),
        ("network_allow", ", ".join(manifest["network_allow"]), "--allow on this task's own proxy"),
        ("broker_tools", ", ".join(manifest["broker_tools"]), "--tools on this task's own broker"),
        ("mounts.scratch", mount_mode(manifest, "scratch"), "/scratch, under this task's directory only"),
        ("ttl_seconds", manifest["ttl_seconds"], "hard timeout around the sandbox"),
    ]
    # Printed only when the manifest sets them, so a rung-1 manifest's table is
    # exactly what it was.
    if manifest["mounts"].get("broker") is not None:
        rows.insert(-1, ("mounts.broker", mount_mode(manifest, "broker"),
                         "/broker, this task's own socket -- 'none' means no tools at all"))
    if manifest["mounts"].get("untrusted") is not None:
        rows.insert(-1, ("mounts.untrusted", mount_mode(manifest, "untrusted"),
                         "/untrusted, labeled untrusted by the runtime (rung 2)"))
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
