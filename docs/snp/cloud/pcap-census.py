#!/usr/bin/env python3
"""What was on the guest's link, from a filter-dump pcap, so that "it sent to
the relay and nowhere else" is a reading and not a claim.

    pcap-census.py guest.pcap

Prints the ethertypes, every ARP target, and every (src -> dst, protocol)
pair with a frame count. A guest reaching for the vendor would show up as a
pair with a destination that is not the relay."""
import struct
import sys

names = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}
protos = {1: "ICMP", 6: "TCP", 17: "UDP"}


def main(path):
    f = open(path, "rb")
    hdr = f.read(24)
    if len(hdr) < 24:
        print("empty pcap")
        return
    ethertypes, arp, pairs, ports = {}, set(), {}, {}
    n = 0
    while True:
        h = f.read(16)
        if len(h) < 16:
            break
        _, _, caplen, _ = struct.unpack("=IIII", h)
        fr = f.read(caplen)
        n += 1
        if len(fr) < 14:
            continue
        et = struct.unpack("!H", fr[12:14])[0]
        ethertypes[et] = ethertypes.get(et, 0) + 1
        if et == 0x0806 and len(fr) >= 42:
            arp.add(".".join(str(b) for b in fr[38:42]))
        elif et == 0x0800 and len(fr) >= 34:
            proto = fr[23]
            src = ".".join(str(b) for b in fr[26:30])
            dst = ".".join(str(b) for b in fr[30:34])
            key = (src, dst, proto)
            pairs[key] = pairs.get(key, 0) + 1
            if proto == 17 and len(fr) >= 42:
                ihl = (fr[14] & 0xF) * 4
                dport = struct.unpack("!H", fr[14 + ihl + 2:14 + ihl + 4])[0]
                ports[(dst, dport)] = ports.get((dst, dport), 0) + 1
    print(f"frames: {n}")
    print("ethertypes: " + ", ".join(f"{names.get(t, hex(t))}={c}" for t, c in sorted(ethertypes.items())))
    print("arp targets: " + (", ".join(sorted(arp)) or "none"))
    for (src, dst, proto), c in sorted(pairs.items(), key=lambda kv: -kv[1]):
        print(f"  {src} -> {dst} proto={protos.get(proto, proto)} frames={c}")
    for (dst, port), c in sorted(ports.items(), key=lambda kv: -kv[1]):
        print(f"  udp to {dst}:{port} datagrams={c}")


if __name__ == "__main__":
    main(sys.argv[1])
