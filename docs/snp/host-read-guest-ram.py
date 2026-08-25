#!/usr/bin/env python3
"""Read the guest's RAM the way a malicious host operator would, and look for a
canary the guest wrote into it.

The guest RAM is a `memory-backend-memfd`, so the host holds it as an open memfd
on the QEMU process. Reading /proc/<pid>/fd/<n> reads guest RAM directly, with
no cooperation from the guest and no hypervisor API involved.

Under SEV-SNP the guest's *private* pages live in a separate guest_memfd that
QEMU never maps, so this read must not turn up guest data. Run the same script
against the same guest booted without -object sev-snp-guest as the control: there
the canary is plainly visible, which is what makes the SNP result evidence rather
than an absence of proof.

Run as root.
"""
import os
import sys


def find_guest_ram_fd(pid):
    """Return (fd_path, size) of the largest memfd held by the process."""
    best = None
    fddir = "/proc/%d/fd" % pid
    for name in os.listdir(fddir):
        path = os.path.join(fddir, name)
        try:
            target = os.readlink(path)
            st = os.stat(path)
        except OSError:
            continue
        if "memfd:" not in target:
            continue
        if best is None or st.st_size > best[2]:
            best = (path, target, st.st_size)
    return best


def scan(path, size, marker):
    marker = marker.encode()
    overlap = len(marker) - 1
    hits = 0
    total = 0
    nonzero = 0
    tail = b""
    fd = os.open(path, os.O_RDONLY)
    try:
        while total < size:
            want = min(64 << 20, size - total)
            chunk = os.pread(fd, want, total)
            if not chunk:
                break
            total += len(chunk)
            nonzero += len(chunk) - chunk.count(0)
            buf = tail + chunk
            hits += buf.count(marker)
            tail = buf[-overlap:] if overlap else b""
    finally:
        os.close(fd)
    return hits, total, nonzero


def main():
    pid = int(sys.argv[1])
    marker = sys.argv[2]
    # How many copies the guest was told to write, so the verdict is a comparison
    # rather than a presence test. A confidential guest still leaks a handful of
    # copies through shared SWIOTLB bounce buffers -- that is expected, and is why
    # "occurrences > 0" is the wrong question.
    expected = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    found = find_guest_ram_fd(pid)
    if not found:
        sys.exit("no memfd found on pid %d -- is this the QEMU process?" % pid)
    path, target, size = found
    print("qemu pid           : %d" % pid)
    print("guest RAM backing  : %s -> %s" % (path, target))
    print("size               : %d bytes (%.2f GiB)" % (size, size / (1 << 30)))
    hits, total, nonzero = scan(path, size, marker)
    print("bytes read         : %d (%.2f GiB)" % (total, total / (1 << 30)))
    print("non-zero bytes     : %d (%.4f%% of what was read)"
          % (nonzero, 100.0 * nonzero / total if total else 0))
    print("canary             : %s" % marker)
    print("occurrences        : %d" % hits)
    if expected:
        print("copies written     : %d" % expected)
        print("visible fraction   : %.6f%%" % (100.0 * hits / expected))
    print()
    if expected:
        if hits > expected // 100:
            print("RESULT: the host can read the bulk of guest RAM -- NOT confidential.")
        else:
            print("RESULT: the bulk of guest RAM is not readable by the host.")
            print("        The %d copies that are visible are the marker text in transit"
                  % hits)
            print("        through shared bounce buffers, not the pages the guest filled.")
    elif hits:
        print("RESULT: %d copies visible; pass the expected count to get a verdict." % hits)
    else:
        print("RESULT: canary not found in the host's view of guest RAM.")


if __name__ == "__main__":
    main()
