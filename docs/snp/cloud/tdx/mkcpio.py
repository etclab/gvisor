#!/usr/bin/env python3
"""Write a deterministic newc cpio archive from a description, without root.

    mkcpio.py LIST > initrd.cpio

LIST is the format Linux's own usr/gen_init_cpio takes, one entry per line,
comments and blank lines ignored:

    dir   NAME MODE UID GID
    file  NAME LOCATION MODE UID GID
    slink NAME TARGET   MODE UID GID
    nod   NAME MODE UID GID {b|c} MAJ MIN

Why this exists rather than gen_init_cpio(1) or cpio(1). gen_init_cpio is in
the kernel tree, and ticket 14's image build reached into the SEV-SNP host
stack for a copy of it; this ticket's build has no host stack and should not
grow one for ninety lines of archive format. cpio(1) archives files that
already exist, so a /dev/console device node and root-owned files would need
root, or a fakeroot, on the machine doing the build.

Everything about the output is fixed by the description: inode numbers are
assigned in order, every mtime is zero, and nothing is read from the build
machine's clock, umask or user. The same list and the same file contents give
the same bytes, which matters because those bytes are hashed into RTMR2 and a
verifier has to be able to produce them again.
"""
import io
import sys

TRAILER = "TRAILER!!!"


def field(value):
    return b"%08X" % (value & 0xFFFFFFFF)


def pad4(stream, written):
    if written % 4:
        stream.write(b"\0" * (4 - written % 4))


def entry(stream, ino, name, mode, uid, gid, nlink, data, rdevmaj=0, rdevmin=0):
    name_bytes = name.encode("utf-8") + b"\0"
    header = b"070701"
    for v in (ino, mode, uid, gid, nlink, 0, len(data), 0, 0, rdevmaj, rdevmin,
              len(name_bytes), 0):
        header += field(v)
    stream.write(header)
    stream.write(name_bytes)
    pad4(stream, len(header) + len(name_bytes))
    if data:
        stream.write(data)
        pad4(stream, len(data))


def main(argv):
    if len(argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    out = io.BytesIO()
    ino = 1
    with open(argv[1]) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            kind = parts[0]
            try:
                if kind == "dir":
                    _, name, mode, uid, gid = parts
                    entry(out, ino, name, 0o040000 | int(mode, 8), int(uid), int(gid), 2, b"")
                elif kind == "file":
                    _, name, location, mode, uid, gid = parts
                    with open(location, "rb") as src:
                        data = src.read()
                    entry(out, ino, name, 0o100000 | int(mode, 8), int(uid), int(gid), 1, data)
                elif kind == "slink":
                    _, name, target, mode, uid, gid = parts
                    entry(out, ino, name, 0o120000 | int(mode, 8), int(uid), int(gid), 1,
                          target.encode("utf-8"))
                elif kind == "nod":
                    _, name, mode, uid, gid, dev, maj, minor = parts
                    kindbit = 0o060000 if dev == "b" else 0o020000
                    entry(out, ino, name, kindbit | int(mode, 8), int(uid), int(gid), 1, b"",
                          int(maj), int(minor))
                else:
                    raise ValueError("unknown entry kind %r" % kind)
            except Exception as exc:                       # noqa: BLE001 - the line is the context
                sys.stderr.write("mkcpio: %s line %d: %s\n  %s\n" % (argv[1], lineno, exc, line))
                return 1
            ino += 1
    entry(out, 0, TRAILER, 0, 0, 0, 1, b"")
    # The kernel's parser reads the archive in 512-byte blocks; padding to one
    # is what every other producer does and costs at most 511 bytes.
    if out.tell() % 512:
        out.write(b"\0" * (512 - out.tell() % 512))
    sys.stdout.buffer.write(out.getvalue())
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
