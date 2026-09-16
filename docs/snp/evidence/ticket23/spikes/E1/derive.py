#!/usr/bin/env python3
"""Derive E1's resource list from strace output.

Usage: derive.py LABEL=FILE [LABEL=FILE ...] [--host NAME ...]

One markdown table: one row per distinct destination, per binary execve'd and
per distinct path opened. /proc, /sys and the dynamic loader's own files are
collapsed into single rows with a note, and so is the certificate directory's
per-root walk; everything a policy would have to name is kept as its own row.

Hostnames are attached by resolving the --host names at derive time and
matching the addresses. That is recorded rather than trusted: the strace itself
carries addresses and never a name.

strace -f prints a thread id per line, and a call a thread was descheduled
inside is split across an '<unfinished ...>' line and a '<... resumed>' line.
Both halves are joined here, because a connect() that is counted from its
first half only has no result and a socket() that is counted from its first
half only never says which descriptor it became.
"""

import collections
import re
import socket
import sys

SOCKET = re.compile(r'^(\d+)\s+socket\((AF_\w+), (SOCK_\w+)[^)]*\)\s*=\s*(\d+)')
SOCKET_UNF = re.compile(r'^(\d+)\s+socket\((AF_\w+), (SOCK_\w+)[^)]*<unfinished')
RESUMED = re.compile(r'^(\d+)\s+<\.\.\. (\w+) resumed>.*?=\s*(.*)$')
CONNECT4 = re.compile(r'^(\d+)\s+connect\((\d+), \{sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([\d.]+)"\)\}(.*)$')
CONNECT6 = re.compile(r'^(\d+)\s+connect\((\d+), \{sa_family=AF_INET6, sin6_port=htons\((\d+)\),.*inet_pton\(AF_INET6, "([^"]+)"(.*)$')
CONNECTU = re.compile(r'^(\d+)\s+connect\((\d+), \{sa_family=AF_UNIX, sun_path="([^"]*)"\}(.*)$')
SENDTO = re.compile(r'^(\d+)\s+(sendto|sendmmsg)\((\d+),')
EXECVE = re.compile(r'^(\d+)\s+execve\("([^"]+)"')
OPENAT = re.compile(r'^(\d+)\s+(openat|readlinkat|newfstatat)\(\w+, "((?:[^"\\]|\\.)*)".*=\s*(.*)$')
ACCESS = re.compile(r'^(\d+)\s+(access)\("((?:[^"\\]|\\.)*)".*=\s*(.*)$')

COLLAPSE = [
    (re.compile(r'^/proc/'), '/proc/* (Go runtime: maps, cgroup, mountinfo)'),
    (re.compile(r'^/sys/'), '/sys/* (Go runtime: hugepage size, cpu.max, cpu/online)'),
    (re.compile(r'^/etc/ssl/certs/.*\.pem$'), '/etc/ssl/certs/*.pem (the per-root walk)'),
    (re.compile(r'^/etc/ssl/certs/java$'), '/etc/ssl/certs/*.pem (the per-root walk)'),
    (re.compile(r'^/etc/ssl/certs/[0-9a-f]+\.\d+$'), '/etc/ssl/certs/<hash>.N (the hashed-symlink walk)'),
]


def collapse(path):
    for rx, into in COLLAPSE:
        if rx.match(path):
            return into, True
    return path, False


def parse(path):
    """Return (destinations, binaries, opens) for one strace file."""
    # fd -> "AF_INET/SOCK_STREAM". Keyed by the descriptor alone and not by the
    # thread, because the threads of one process share a descriptor table: the
    # socket a connect() is on is the last one opened on that number by any of
    # them.
    kind = {}
    pending_socket = {}   # tid -> kind, for a socket() split in two
    pending_connect = {}  # tid -> (addr, port, proto), for a connect() split in two
    dests = collections.Counter()
    bins = collections.Counter()
    opens = collections.Counter()

    def connected(addr, port, proto, tail, tid):
        if '<unfinished' in tail:
            pending_connect[tid] = (addr, port, proto)
            return
        _, _, res = tail.rpartition('=')
        dests[(addr, port, proto, res.strip())] += 1

    for line in open(path, encoding='utf-8', errors='replace').read().splitlines():
        m = RESUMED.match(line)
        if m:
            tid, call, res = m.groups()
            if call == 'socket' and tid in pending_socket:
                kind[res.strip()] = pending_socket.pop(tid)
            elif call == 'connect' and tid in pending_connect:
                addr, port, proto = pending_connect.pop(tid)
                dests[(addr, port, proto, res.strip())] += 1
            continue
        m = SOCKET.match(line)
        if m:
            _, fam, typ, fd = m.groups()
            kind[fd] = f'{fam}/{typ.split("|")[0]}'
            continue
        m = SOCKET_UNF.match(line)
        if m:
            tid, fam, typ = m.groups()
            pending_socket[tid] = f'{fam}/{typ.split("|")[0]}'
            continue
        m = SENDTO.match(line)
        if m:
            if kind.get(m.group(3), '').startswith('AF_NETLINK'):
                dests[('netlink:RTM_GETADDR', 0, kind[m.group(3)], '0')] += 1
            continue
        m = EXECVE.match(line)
        if m:
            bins[m.group(2)] += 1
            continue
        m = OPENAT.match(line) or ACCESS.match(line)
        if m:
            call, p, res = m.group(2), m.group(3), m.group(4)
            p, col = collapse(p)
            opens[(p, call, 'ok' if not res.startswith('-1') else res, col)] += 1
            continue
        for rx in (CONNECT4, CONNECT6):
            m = rx.match(line)
            if m:
                tid, fd, port, addr, tail = m.groups()
                connected(addr, int(port), kind.get(fd, 'unknown'), tail, tid)
                break
        else:
            m = CONNECTU.match(line)
            if m:
                tid, fd, sun, tail = m.groups()
                connected(f'unix:{sun}', 0, kind.get(fd, 'unknown'), tail, tid)
    return dests, bins, opens


def main():
    files, hosts = [], []
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--host':
            hosts.append(args[i + 1])
            i += 2
        else:
            label, _, path = args[i].partition('=')
            files.append((label, path))
            i += 1

    names = {}
    for h in hosts:
        for info in socket.getaddrinfo(h, None):
            names.setdefault(info[4][0], set()).add(h)

    runs = [(label, parse(path)) for label, path in files]
    labels = [label for label, _ in runs]

    def counts(which, key):
        return '/'.join(str(r[which][key]) for _, r in runs)

    print('| kind | resource | protocol | seen (%s) | note |' % ', '.join(labels))
    print('| --- | --- | --- | --- | --- |')

    for k in sorted({k for _, r in runs for k in r[0]}, key=lambda k: (k[1] == 0, -k[1], k[0])):
        addr, port, proto, res = k
        who = ', '.join(sorted(names.get(addr, [])))
        if addr.startswith(('unix:', 'netlink:')):
            where, who = addr, ''
        else:
            where = f'{addr}:{port}'
        note = res if res not in ('0', 'ok') else ''
        if port == 0 and not addr.startswith(('unix:', 'netlink:')):
            note = (note + '; ' if note else '') + 'port 0: source-address selection, no bytes'
        said = ' — '.join(x for x in (who, note) if x) or '—'
        print(f'| destination | `{where}` | {proto} | {counts(0, k)} | {said} |')

    for k in sorted({k for _, r in runs for k in r[1]}):
        print(f'| binary | `{k}` | execve | {counts(1, k)} | the only one |')

    for k in sorted({k for _, r in runs for k in r[2]}, key=lambda k: (k[3], k[0], k[1])):
        p, call, res, col = k
        note = 'collapsed' if col else ''
        if res != 'ok':
            note = (note + '; ' if note else '') + res
        print(f'| path | `{p}` | {call} | {counts(2, k)} | {note or "—"} |')


if __name__ == '__main__':
    main()
