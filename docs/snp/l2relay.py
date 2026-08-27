#!/usr/bin/env python3
"""Relay the ethernet frames between two guests, and read them (ticket 14).

The two guests in a ticket-14 run have no other path to each other. Each one's
QEMU is given

    -netdev socket,id=net0,connect=127.0.0.1:<port>

and this process is what is at the other end of both connections: it reads
every frame one guest sends and writes it to the other, in both directions,
for as long as the run lasts. Nothing else is on the segment. There is no
gateway, no resolver and no route off it, which is what makes egress to the
hardware vendor structurally impossible during the run rather than merely
blocked by a rule somebody could have got wrong.

That makes it the attacker of the memo's verification list at the same time as
the wire: an on-path adversary who sees every byte between the two peers and
can copy, count, delay or corrupt them. What it cannot do is read them, and
the point of running the legitimate exchange *through* it is that the same
process which carried the traffic is the one that failed to understand it.

    l2relay.py --listen 127.0.0.1:15001 --listen 127.0.0.1:15002
               [--pcap FILE] [--marker STRING] [--summary FILE]
               [--seconds N] [--tamper N]

--marker is the plaintext an exchange carries inside the tunnel. Every frame is
searched for it and a hit is reported loudly, because a run in which the marker
was never sent would make its absence prove nothing.

--pcap writes an ordinary libpcap file, so the claim can be re-checked with
tcpdump by anyone who does not want to take this script's word for it.

--tamper flips one bit in every Nth frame carrying a UDP payload, which is the
active half: QUIC authenticates every packet, so a tampered one is discarded by
the peer and the tunnel carries on. Off by default — the recording relay is the
control, and an attacker who breaks the connection has not read anything either.

QEMU's socket netdev frames each ethernet frame with a four-byte big-endian
length (net/socket.c); this speaks exactly that.
"""

import argparse
import selectors
import signal
import socket
import struct
import sys
import time

LINKTYPE_ETHERNET = 1


class Pcap:
    """An ordinary libpcap file, microsecond resolution."""

    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("=IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))

    def write(self, frame, when):
        self.f.write(struct.pack("=IIII", int(when), int((when % 1) * 1e6), len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.flush()
        self.f.close()


class Census:
    """What was on the segment, so that "no egress" is a reading and not a claim.

    A guest that tried to reach the vendor would have to send a packet
    addressed off the subnet, and would have to ARP for a gateway to do it.
    Both would appear here.
    """

    def __init__(self):
        self.ethertypes = {}
        self.protocols = {}
        self.pairs = {}
        self.arp_targets = set()

    def look(self, frame):
        if len(frame) < 14:
            return
        ethertype = struct.unpack("!H", frame[12:14])[0]
        self.ethertypes[ethertype] = self.ethertypes.get(ethertype, 0) + 1
        if ethertype == 0x0806 and len(frame) >= 42:                 # ARP
            self.arp_targets.add(".".join(str(b) for b in frame[38:42]))
        elif ethertype == 0x0800 and len(frame) >= 34:               # IPv4
            proto = frame[23]
            self.protocols[proto] = self.protocols.get(proto, 0) + 1
            src = ".".join(str(b) for b in frame[26:30])
            dst = ".".join(str(b) for b in frame[30:34])
            key = (src, dst, proto)
            self.pairs[key] = self.pairs.get(key, 0) + 1

    def report(self, out):
        names = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}
        print("  ethertypes : " + ", ".join(
            f"{names.get(t, hex(t))}={n}" for t, n in sorted(self.ethertypes.items())), file=out)
        protos = {1: "ICMP", 6: "TCP", 17: "UDP"}
        print("  ip protocols: " + (", ".join(
            f"{protos.get(p, p)}={n}" for p, n in sorted(self.protocols.items())) or "none"), file=out)
        print("  arp targets : " + (", ".join(sorted(self.arp_targets)) or "none"), file=out)
        for (src, dst, proto), n in sorted(self.pairs.items(), key=lambda kv: -kv[1]):
            print(f"  {src} -> {dst} proto={protos.get(proto, proto)} frames={n}", file=out)


def accept_two(addresses, deadline):
    """Wait for both guests to attach. Neither exists yet when this starts."""
    listeners = []
    for host, port in addresses:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        listeners.append(s)
        print(f"l2relay: listening on {host}:{port}", flush=True)
    conns = []
    for s in listeners:
        s.settimeout(max(1.0, deadline - time.time()))
        try:
            conn, peer = s.accept()
        except socket.timeout:
            print("l2relay: FATAL: a guest never attached to the segment", file=sys.stderr)
            sys.exit(2)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conns.append(conn)
        print(f"l2relay: {peer[0]}:{peer[1]} attached", flush=True)
        s.close()
    return conns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", action="append", required=True, metavar="HOST:PORT")
    ap.add_argument("--pcap")
    ap.add_argument("--marker")
    ap.add_argument("--summary")
    ap.add_argument("--seconds", type=float, default=900)
    ap.add_argument("--attach-timeout", type=float, default=180)
    ap.add_argument("--tamper", type=int, default=0, metavar="N")
    args = ap.parse_args()
    if len(args.listen) != 2:
        ap.error("--listen twice: one port per guest")

    addresses = []
    for spec in args.listen:
        host, _, port = spec.rpartition(":")
        addresses.append((host or "127.0.0.1", int(port)))

    running = [True]
    signal.signal(signal.SIGTERM, lambda *_: running.__setitem__(0, False))
    signal.signal(signal.SIGINT, lambda *_: running.__setitem__(0, False))

    conns = accept_two(addresses, time.time() + args.attach_timeout)
    pcap = Pcap(args.pcap) if args.pcap else None
    census = Census()
    marker = args.marker.encode() if args.marker else None
    frames = [0, 0]
    octets = [0, 0]
    hits = 0
    tampered = 0
    seen = 0

    sel = selectors.DefaultSelector()
    for i, c in enumerate(conns):
        c.setblocking(False)
        sel.register(c, selectors.EVENT_READ, i)
    buffers = [bytearray(), bytearray()]

    attached = [True, True]
    started = time.time()
    print(f"l2relay: relaying for up to {args.seconds:.0f}s", flush=True)
    while running[0] and time.time() - started < args.seconds:
        for key, _ in sel.select(timeout=0.5):
            i = key.data
            try:
                chunk = conns[i].recv(65536)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                chunk = b""
            if not chunk:
                # One guest leaving is not the end of the run. A scenario in
                # which one of the two refuses to start is a scenario whose
                # other guest is still trying to reach it, and a relay that
                # tore the segment down on the first exit would hide what the
                # survivor did next.
                print(f"l2relay: guest {i} detached", flush=True)
                sel.unregister(conns[i])
                attached[i] = False
                if not any(attached):
                    running[0] = False
                break
            buffers[i] += chunk
            while len(buffers[i]) >= 4:
                (length,) = struct.unpack("!I", buffers[i][:4])
                if len(buffers[i]) < 4 + length:
                    break
                frame = bytes(buffers[i][4:4 + length])
                del buffers[i][:4 + length]
                seen += 1
                frames[i] += 1
                octets[i] += length
                census.look(frame)
                if pcap:
                    pcap.write(frame, time.time())
                if marker and marker in frame:
                    hits += 1
                    print(f"l2relay: PLAINTEXT MARKER ON THE WIRE in frame {seen}", flush=True)
                out = frame
                if args.tamper and seen % args.tamper == 0 and is_udp_with_payload(frame):
                    out = bytearray(frame)
                    out[-1] ^= 0x01
                    out = bytes(out)
                    tampered += 1
                if not attached[1 - i]:
                    continue
                try:
                    conns[1 - i].sendall(struct.pack("!I", len(out)) + out)
                except OSError:
                    attached[1 - i] = False

    for c in conns:
        try:
            c.close()
        except OSError:
            pass
    if pcap:
        pcap.close()

    out = open(args.summary, "w") if args.summary else sys.stdout
    print(f"l2relay: RELAYED a_to_b_frames={frames[0]} b_to_a_frames={frames[1]} "
          f"a_to_b_bytes={octets[0]} b_to_a_bytes={octets[1]} tampered={tampered}", file=out)
    if marker:
        verdict = "FOUND" if hits else "not found"
        print(f"l2relay: MARKER {verdict} hits={hits} marker={args.marker!r} "
              f"in {seen} frames carrying {octets[0] + octets[1]} bytes", file=out)
    print("l2relay: what was on the segment:", file=out)
    census.report(out)
    if args.summary:
        out.close()
        print(open(args.summary).read(), end="")
    return 1 if (marker and hits) else 0


def is_udp_with_payload(frame):
    return (len(frame) > 42 and struct.unpack("!H", frame[12:14])[0] == 0x0800
            and frame[23] == 17)


if __name__ == "__main__":
    sys.exit(main())
