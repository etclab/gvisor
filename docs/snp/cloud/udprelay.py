#!/usr/bin/env python3
"""Relay the datagrams between the dialing guest and the listener, and read them.

docs/snp/l2relay.py one layer up. In a ticket-14 run the attacker copied
ethernet frames between two QEMUs on one host. Here it runs on an ordinary
(non-confidential) VM in the cloud with a public address, the dialing guest's
peer table names *this* address rather than the listener's, and every datagram
of the tunnel crosses a real network to get here and another to get to the
listener. It is what the peer table is for: a wrong address is a failed
handshake, never a compromised one, so pointing the dialer at an attacker is
nothing more than what a hostile network already does.

    udprelay.py --listen 0.0.0.0:4433 --forward 10.142.0.3:4433
                [--pcap FILE] [--marker STRING] [--summary FILE]
                [--seconds N] [--tamper N]

Each source address:port that sends to --listen gets its own socket towards
--forward, so replies find their way back to the right dialer; a mapping that
carries nothing for ten minutes is dropped, which is also roughly how a NAT
behaves, and is not the NAT this run is interested in (that one is QEMU's, on
the dialing side).

--marker is the plaintext an exchange carries inside the tunnel. Every
datagram is searched for it and a hit is reported loudly.

--pcap writes a libpcap file with a raw-IP link type — an IPv4 header with
the addresses as this relay saw them, then UDP, then the datagram — so the
claim can be re-checked with tcpdump.

--tamper flips one bit in every Nth datagram, the active half. Off by default.
"""

import argparse
import selectors
import signal
import socket
import struct
import sys
import time

LINKTYPE_RAW = 101      # raw IPv4/IPv6, no link-layer header
MAPPING_IDLE = 600.0


class Pcap:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("=IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW))

    def write(self, src, dst, payload, when):
        sip, sport = src
        dip, dport = dst
        udp_len = 8 + len(payload)
        udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
        total = 20 + len(udp)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                         socket.inet_aton(sip), socket.inet_aton(dip))
        pkt = ip + udp
        self.f.write(struct.pack("=IIII", int(when), int((when % 1) * 1e6), len(pkt), len(pkt)))
        self.f.write(pkt)

    def close(self):
        self.f.flush()
        self.f.close()


def addr(spec):
    host, _, port = spec.rpartition(":")
    return (host or "0.0.0.0", int(port))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, metavar="HOST:PORT")
    ap.add_argument("--forward", required=True, metavar="HOST:PORT")
    ap.add_argument("--pcap")
    ap.add_argument("--marker")
    ap.add_argument("--summary")
    ap.add_argument("--seconds", type=float, default=1800)
    ap.add_argument("--tamper", type=int, default=0, metavar="N")
    args = ap.parse_args()

    listen = addr(args.listen)
    forward = addr(args.forward)
    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    front.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    front.bind(listen)
    front.setblocking(False)
    my_ip = front.getsockname()[0]

    running = [True]
    signal.signal(signal.SIGTERM, lambda *_: running.__setitem__(0, False))
    signal.signal(signal.SIGINT, lambda *_: running.__setitem__(0, False))

    pcap = Pcap(args.pcap) if args.pcap else None
    marker = args.marker.encode() if args.marker else None
    sel = selectors.DefaultSelector()
    sel.register(front, selectors.EVENT_READ, ("front", None))
    mappings = {}           # dialer addr -> (socket towards the listener, last seen)
    counts = {"in_dgrams": 0, "in_bytes": 0, "out_dgrams": 0, "out_bytes": 0}
    dialers = set()
    hits = 0
    tampered = 0
    seen = 0

    def maybe_tamper(data):
        nonlocal tampered
        if args.tamper and seen % args.tamper == 0 and len(data) > 0:
            out = bytearray(data)
            out[-1] ^= 0x01
            tampered += 1
            return bytes(out)
        return data

    print(f"udprelay: listening on {listen[0]}:{listen[1]}, forwarding to {forward[0]}:{forward[1]}"
          f"{' with tamper every %d' % args.tamper if args.tamper else ''}", flush=True)
    started = time.time()
    last_sweep = started
    while running[0] and time.time() - started < args.seconds:
        for key, _ in sel.select(timeout=0.5):
            kind, dialer = key.data
            try:
                data, src = key.fileobj.recvfrom(65535)
            except (BlockingIOError, InterruptedError, ConnectionResetError):
                continue
            now = time.time()
            seen += 1
            if marker and marker in data:
                hits += 1
                print(f"udprelay: PLAINTEXT MARKER ON THE WIRE in datagram {seen}", flush=True)
            if kind == "front":
                if src not in mappings:
                    back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    back.connect(forward)
                    back.setblocking(False)
                    sel.register(back, selectors.EVENT_READ, ("back", src))
                    mappings[src] = [back, now]
                    dialers.add(src[0])
                    print(f"udprelay: new dialer {src[0]}:{src[1]} -> mapping {back.getsockname()[1]}", flush=True)
                back, _ = mappings[src]
                mappings[src][1] = now
                counts["in_dgrams"] += 1
                counts["in_bytes"] += len(data)
                if pcap:
                    pcap.write(src, (my_ip, listen[1]), data, now)
                try:
                    back.send(maybe_tamper(data))
                except OSError:
                    pass
            else:
                if dialer not in mappings:
                    continue
                mappings[dialer][1] = now
                counts["out_dgrams"] += 1
                counts["out_bytes"] += len(data)
                if pcap:
                    pcap.write(forward, dialer, data, now)
                try:
                    front.sendto(maybe_tamper(data), dialer)
                except OSError:
                    pass
        now = time.time()
        if now - last_sweep > 30:
            last_sweep = now
            for d in [d for d, (_, last) in mappings.items() if now - last > MAPPING_IDLE]:
                sel.unregister(mappings[d][0])
                mappings[d][0].close()
                del mappings[d]
                print(f"udprelay: dropped idle mapping for {d[0]}:{d[1]}", flush=True)

    for back, _ in mappings.values():
        back.close()
    front.close()
    if pcap:
        pcap.close()

    out = open(args.summary, "w") if args.summary else sys.stdout
    total = counts["in_bytes"] + counts["out_bytes"]
    print(f"udprelay: RELAYED dialer_to_listener_dgrams={counts['in_dgrams']} listener_to_dialer_dgrams={counts['out_dgrams']} "
          f"dialer_to_listener_bytes={counts['in_bytes']} listener_to_dialer_bytes={counts['out_bytes']} tampered={tampered}", file=out)
    if marker:
        verdict = "FOUND" if hits else "not found"
        print(f"udprelay: MARKER {verdict} hits={hits} marker={args.marker!r} in {seen} datagrams carrying {total} bytes", file=out)
    print(f"udprelay: dialers seen: {', '.join(sorted(dialers)) or 'none'}", file=out)
    if args.summary:
        out.close()
        print(open(args.summary).read(), end="")
    return 1 if (marker and hits) else 0


if __name__ == "__main__":
    sys.exit(main())
