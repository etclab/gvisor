#!/usr/bin/env python3
"""Count occurrences of a marker in a large file, chunked so it cannot OOM.

Used to test whether a canary written into guest RAM is readable from the
host's view of that RAM.
"""
import sys

def main():
    path, marker = sys.argv[1], sys.argv[2].encode()
    n, total, nonzero = 0, 0, 0
    overlap = len(marker) - 1
    tail = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(64 << 20)
            if not chunk:
                break
            total += len(chunk)
            nonzero += len(chunk) - chunk.count(0)
            buf = tail + chunk
            n += buf.count(marker)
            tail = buf[-overlap:] if overlap else b""
    print("file            : %s" % path)
    print("bytes scanned   : %d (%.2f GiB)" % (total, total / (1 << 30)))
    print("non-zero bytes  : %d (%.4f%%)" % (nonzero, 100.0 * nonzero / total if total else 0))
    print("marker          : %s" % marker.decode())
    print("occurrences     : %d" % n)

if __name__ == "__main__":
    main()
