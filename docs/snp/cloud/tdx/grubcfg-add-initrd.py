#!/usr/bin/env python3
# Put an `initrd` line into the default menu entry of an Ubuntu GCP image's
# grub.cfg, and change nothing else.
#
#   grubcfg-add-initrd.py IN.cfg OUT.cfg [--boot-dir /boot]
#
# Ticket 19's step zero needs one boot that loads an initrd, so that the initrd
# path of docs/snp/cloud/tdx/predict-rtmr2.py -- which has never been exercised,
# because on this image's default path grub loads no initrd at all -- can be
# compared against a real quote. The smaller the difference between that boot
# and the boots already on record, the more a mismatch means, so this makes the
# smallest one there is: exactly one inserted line.
#
# # What the default entry looks like, and where the line goes
#
# The image sets GRUB_FORCE_PARTUUID, so 10_linux writes an entry that boots
# without an initrd and keeps one in reserve for the boot after a panic:
#
#     if [ "${initrdfail}" = 1 ]; then
#             echo    'GRUB_FORCE_PARTUUID set, initrdless boot failed. Attempting with initrd.'
#             linux   /vmlinuz-6.17.0-1022-gcp root=PARTUUID=... ro  console=ttyS0,115200
#             initrd  /initrd.img-6.17.0-1022-gcp
#     else
#             echo    'GRUB_FORCE_PARTUUID set, attempting initrdless boot.'
#             linux   /vmlinuz-6.17.0-1022-gcp root=PARTUUID=... ro  console=ttyS0,115200 panic=-1
#     fi
#
# grubenv carries no initrdfail on a healthy boot, so the else branch is the one
# taken, and it is the one an initrd has to be added to. The `then` branch's
# initrd line is left where it is: reaching it needs a failed boot, and a probe
# that arranged one would be measuring two changes at once.
#
# The two branches are told apart by their kernel command lines -- only the
# initrdless one carries `panic=-1`, which is what GRUB_FORCE_PARTUUID's
# fallback is armed by -- and the insertion is refused unless exactly one line
# in the default entry matches. Everything else in the file, including the
# `then` branch, the `initrdfail` function and the submenu, is copied byte for
# byte.
#
# # What is deliberately not changed
#
# `root=PARTUUID=...` stays. It is a root specification Ubuntu's initramfs
# resolves as happily as the kernel does (scripts/functions' resolve_device
# handles PARTUUID= alongside UUID= and LABEL=), so a boot with an initrd needs
# no other root=, and rewriting it would move the two records that carry the
# kernel command line -- exactly the ones that must not move if the initrd is to
# be the only thing under test.
#
# The `initrdfail` call at the end of the entry stays too. It writes to grubenv,
# not to this file, and grub measures grubenv before the entry runs.
import argparse
import os
import re
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", help="the grub.cfg to read")
    ap.add_argument("dst", help="the grub.cfg to write")
    ap.add_argument("--boot-dir", default="/boot",
                    help="where the initrd named by the new line lives on this "
                         "machine, so its presence can be checked (grub's own "
                         "path is relative to the /boot filesystem and is not "
                         "this)")
    args = ap.parse_args()

    with open(args.src, "r", encoding="latin-1", newline="") as f:
        text = f.read()
    lines = text.split("\n")

    start, end = default_entry(lines)

    # The initrdless branch's kernel: the one line of the default entry whose
    # command is `linux` and whose command line arms the panic fallback.
    hits = [i for i in range(start + 1, end)
            if re.match(r"^\s*linux\s", lines[i]) and lines[i].rstrip().endswith("panic=-1")]
    if len(hits) != 1:
        die("the default entry has %d initrdless `linux` lines (want exactly one ending in "
            "panic=-1); this image is not the one this rewrite was written for" % len(hits))
    at = hits[0]

    version = re.search(r"/vmlinuz-(\S+)", lines[at])
    if not version:
        die("cannot read a kernel version out of %r" % lines[at])
    version = version.group(1)

    # grub's paths in this entry are relative to the filesystem `search` set as
    # root, which on this image is the /boot partition -- so the line reads
    # `/initrd.img-VERSION` and not `/boot/initrd.img-VERSION`, exactly as the
    # `then` branch already writes it.
    initrd = "/initrd.img-%s" % version
    on_disk = os.path.join(args.boot_dir, "initrd.img-%s" % version)
    if not os.path.exists(on_disk):
        die("%s does not exist, so the line would name a file grub cannot open" % on_disk)

    # The indentation and the separator of the line above it, so the new line is
    # shaped like its neighbours rather than like this script.
    indent = re.match(r"^\s*", lines[at]).group(0)
    sep = "\t" if re.match(r"^\s*linux\t", lines[at]) else " "
    new = "%sinitrd%s%s" % (indent, sep, initrd)

    # The rest of the branch that kernel line sits in, which ends at the `else`
    # or the `fi`. An initrd already there means this ran twice, or the image
    # changed shape; either way the answer is not a second line.
    tail = at + 1
    while tail < end and not re.match(r"^\s*(else|fi)\s*$", lines[tail]):
        tail += 1
    if any(re.match(r"^\s*initrd\s", lines[i]) for i in range(at + 1, tail)):
        die("the branch already carries an initrd line; nothing to do")

    out = lines[:at + 1] + [new] + lines[at + 1:]
    with open(args.dst, "w", encoding="latin-1", newline="") as f:
        f.write("\n".join(out))

    sys.stderr.write("inserted after line %d of %s:\n  %s\n" % (at + 1, args.src, new.expandtabs(8)))
    sys.stderr.write("one line added; %d bytes -> %d bytes\n" % (len(text), len("\n".join(out))))


def default_entry(lines):
    """The line range of the entry grub boots with nobody at the console.

    The image's grub.cfg sets `default=0` and every top-level menuentry is
    written by 10_linux in the order it generates them, so the first one that
    starts in column zero is the default. A submenu is not it: descending into
    one takes a keystroke, and predict-rtmr2.py refuses to model that.
    """
    for i, line in enumerate(lines):
        if not line.startswith("menuentry "):
            continue
        for j in range(i + 1, len(lines)):
            if lines[j] == "}":
                return i, j
        die("the default menuentry that starts at line %d never closes" % (i + 1))
    die("no top-level menuentry: this is not a generated Ubuntu grub.cfg")


def die(msg):
    sys.stderr.write("grubcfg-add-initrd: %s\n" % msg)
    sys.exit(1)


if __name__ == "__main__":
    main()
