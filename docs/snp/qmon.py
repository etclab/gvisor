#!/usr/bin/env python3
"""Send commands to a QEMU human monitor over its unix socket.

Run as root: the socket is created by the QEMU process, which runs as root
because it must open /dev/sev.

  qmon.py <monitor.sock> "info sev" "info sev-capability"
"""
import socket
import sys
import time

def main():
    path, cmds = sys.argv[1], sys.argv[2:]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(120)
    s.connect(path)
    time.sleep(0.4)
    try:
        banner = s.recv(65536).decode(errors="replace")
        print(banner, end="")
    except socket.timeout:
        pass
    for c in cmds:
        s.sendall((c + "\n").encode())
        # Read until the monitor prompt comes back.
        buf = b""
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if buf.rstrip().endswith(b"(qemu)"):
                break
        print("\n===== %s =====" % c)
        print(buf.decode(errors="replace"))
    s.close()

if __name__ == "__main__":
    main()
