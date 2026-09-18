#!/usr/bin/env python3
"""Derive E4's ordered host list from strace output.

Usage: derive.py LABEL=FILE [LABEL=FILE ...] [--home LABEL=PATH ...]

E1's derive.py answered "which destinations exist"; ticket 25 needs "which
names, in which order", so this one is a timeline rather than a counter.

Three things E1's version did not do are done here.

  * DNS is read off the wire. Every sendto/sendmmsg on a descriptor that was
    connect()ed to port 53 is decoded as a DNS query (QNAME + QTYPE), and every
    recvfrom on that descriptor is decoded as the answer. The A and AAAA
    records in those answers are what maps an address back to a name, so the
    name column is derived from the trace itself and not from a resolution
    done at derive time, which could differ.

  * The TLS ClientHello is parsed for its SNI. That is the second, independent
    witness for the name behind a connect(): the address says where the packet
    went, the SNI says what the client thinks it is talking to. They agree in
    every run here, and an in-sentry name table has to satisfy both.

  * Order is kept. The rows come out in the order strace wrote them, which for
    a run this small is the order the syscalls returned in.

strace -f prints a thread id per line and splits a call a thread was
descheduled inside across an '<unfinished ...>' line and a '<... resumed>'
line; both halves are joined, as in E1.
"""

import collections
import re
import sys

SOCKET      = re.compile(r'^(\d+)\s+socket\((AF_\w+), (SOCK_\w+)[^)]*\)\s*=\s*(\d+)')
SOCKET_UNF  = re.compile(r'^(\d+)\s+socket\((AF_\w+), (SOCK_\w+)[^)]*<unfinished')
RESUMED     = re.compile(r'^(\d+)\s+<\.\.\. (\w+) resumed>(.*?)(?:=\s*(.*))?$')
CONNECT4    = re.compile(r'^(\d+)\s+connect\((\d+), \{sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([\d.]+)"\)\}, \d+(.*)$')
CONNECT6    = re.compile(r'^(\d+)\s+connect\((\d+), \{sa_family=AF_INET6, sin6_port=htons\((\d+)\),.*?inet_pton\(AF_INET6, "([^"]+)".*?\}, \d+(.*)$')
CONNECTU    = re.compile(r'^(\d+)\s+connect\((\d+), \{sa_family=AF_UNIX, sun_path="([^"]*)"\}, \d+(.*)$')
SEND        = re.compile(r'^(\d+)\s+(sendto|sendmsg|sendmmsg|write)\((\d+), ')
RECVFROM    = re.compile(r'^(\d+)\s+recvfrom\((\d+), "((?:[^"\\]|\\.)*)"')
RECV_UNF    = re.compile(r'^(\d+)\s+(recvfrom)\((\d+),\s+<unfinished')
FIRSTSTR    = re.compile(r'"((?:[^"\\]|\\.)*)"')
IOVBASE     = re.compile(r'iov_base="((?:[^"\\]|\\.)*)"')
BUF         = re.compile(r'^\d+\s+\w+\(\d+, "((?:[^"\\]|\\.)*)"')
NETLINK     = re.compile(r'^(\d+)\s+(sendto|sendmsg)\((\d+), \[\{nlmsg_len=\d+, nlmsg_type=(\w+)')
EXECVE      = re.compile(r'^(\d+)\s+execve\("([^"]+)", \[(.*?)\], ')
PATHCALL    = re.compile(r'^(\d+)\s+(openat|readlinkat|newfstatat|statx)\([^,]+, "((?:[^"\\]|\\.)*)".*?=\s*(.*)$')
PATHCALL1   = re.compile(r'^(\d+)\s+(access|stat|readlink|open|unlink|mkdir|chdir)\("((?:[^"\\]|\\.)*)".*?=\s*(.*)$')

ESCAPE = re.compile(r'\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)')
SIMPLE = {'n': 10, 't': 9, 'r': 13, 'a': 7, 'b': 8, 'f': 12, 'v': 11,
          '\\': 92, '"': 34, "'": 39, '0': 0}
QTYPE = {1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 16: 'TXT', 28: 'AAAA',
         33: 'SRV', 64: 'SVCB', 65: 'HTTPS'}


def unescape(s):
    """strace's C-string form back to bytes."""
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            m = ESCAPE.match(s, i)
            g = m.group(1)
            if g[0] == 'x':
                out.append(int(g[1:], 16))
            elif g[0] in '01234567':
                out.append(int(g, 8) & 0xFF)
            else:
                out.append(SIMPLE.get(g, ord(g) & 0xFF))
            i = m.end()
        else:
            out.append(ord(s[i]) & 0xFF)
            i += 1
    return bytes(out)


def dns_name(b, i):
    """Read a (possibly compressed) name at offset i. Returns (name, next_i)."""
    parts, jumped, next_i, guard = [], False, None, 0
    while i < len(b) and guard < 128:
        guard += 1
        n = b[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            if i + 1 >= len(b):
                return None, None
            ptr = ((n & 0x3F) << 8) | b[i + 1]
            if not jumped:
                next_i = i + 2
            jumped, i = True, ptr
            continue
        if i + 1 + n > len(b):
            return None, None
        parts.append(b[i + 1:i + 1 + n].decode('ascii', 'replace'))
        i += 1 + n
    return '.'.join(parts), (next_i if jumped else i)


def dns_message(b):
    """Decode a DNS message. Returns (qname, qtype, [(name, type, rdata)])."""
    if len(b) < 12:
        return None
    qd, an = int.from_bytes(b[4:6], 'big'), int.from_bytes(b[6:8], 'big')
    if qd != 1 or int.from_bytes(b[2:4], 'big') & 0x7800 not in (0, 0x0000):
        pass
    name, i = dns_name(b, 12)
    if name is None or i is None or i + 4 > len(b):
        return None
    qtype = int.from_bytes(b[i:i + 2], 'big')
    if qtype not in QTYPE:
        return None
    i += 4
    answers = []
    for _ in range(an):
        rn, i = dns_name(b, i)
        if rn is None or i is None or i + 10 > len(b):
            break
        rt = int.from_bytes(b[i:i + 2], 'big')
        rdlen = int.from_bytes(b[i + 8:i + 10], 'big')
        rd = b[i + 10:i + 10 + rdlen]
        i += 10 + rdlen
        if rt == 1 and len(rd) == 4:
            answers.append((rn, 'A', '.'.join(str(x) for x in rd)))
        elif rt == 28 and len(rd) == 16:
            g = [rd[j:j + 2].hex() for j in range(0, 16, 2)]
            answers.append((rn, 'AAAA', compress6(g)))
        elif rt == 5:
            cn, _ = dns_name(b, i - rdlen)
            answers.append((rn, 'CNAME', cn or '?'))
        else:
            answers.append((rn, QTYPE.get(rt, str(rt)), ''))
    return name, QTYPE[qtype], answers


def compress6(groups):
    g = [x.lstrip('0') or '0' for x in groups]
    best_i = best_n = cur_i = cur_n = -1
    for i, x in enumerate(g + ['stop']):
        if x == '0':
            if cur_i < 0:
                cur_i, cur_n = i, 0
            cur_n += 1
        else:
            if cur_n > best_n:
                best_i, best_n = cur_i, cur_n
            cur_i = cur_n = -1
    if best_n > 1:
        return ':'.join(g[:best_i]) + '::' + ':'.join(g[best_i + best_n:])
    return ':'.join(g)


def sni(b):
    """The server_name of a TLS ClientHello, or None."""
    if len(b) < 6 or b[0] != 0x16 or b[1] != 0x03 or b[5] != 0x01:
        return None
    for i in range(43, len(b) - 9):
        if b[i] or b[i + 1]:
            continue
        ext = int.from_bytes(b[i + 2:i + 4], 'big')
        lst = int.from_bytes(b[i + 4:i + 6], 'big')
        if b[i + 6] != 0:
            continue
        nl = int.from_bytes(b[i + 7:i + 9], 'big')
        if ext != lst + 2 or lst != nl + 3 or not 1 <= nl <= 253:
            continue
        name = b[i + 9:i + 9 + nl]
        if len(name) == nl and re.fullmatch(rb'[A-Za-z0-9.\-]+', name) and b'.' in name:
            return name.decode()
    return None


# Which paths a policy has to name, and which are noise to be collapsed.
def collapse_home(rel):
    # An atomic rewrite leaves a pid/nonce-suffixed sibling; one row for all.
    rel = re.sub(r'\.tmp\.[0-9a-f]+(\.[0-9a-f]+)?$', '.tmp.<pid>.<nonce>', rel)
    # Everything one level below a $HOME/.claude subdirectory is that
    # subdirectory's own bookkeeping, not something a policy names one by one.
    m = re.match(r'^(\$HOME/\.claude/[^/]+)/.+', rel)
    if m:
        return m.group(1) + '/** (collapsed)'
    if rel.startswith('$HOME/.local/share/claude/'):
        return '$HOME/.local/share/claude/** (collapsed: the install itself)'
    if rel.startswith('$HOME/.cache/'):
        return '$HOME/.cache/** (collapsed)'
    # run3 only: the operator's HOME holds a working tree. Not part of the
    # question, so it is collapsed at the first component.
    m = re.match(r'^\$HOME/([^./][^/]*)/.+', rel)
    if m:
        return '$HOME/%s/** (collapsed)' % m.group(1)
    return rel


def classify(p, home):
    if home and p.startswith(home + '/') or p == home:
        rel = '$HOME' + p[len(home):]
        shown = collapse_home(rel)
        return 'HOME', shown
    if p.startswith('/proc/'):
        return 'collapse', '/proc/* (runtime: self/stat, maps, cgroup, meminfo, cpuinfo)'
    if p.startswith('/sys/'):
        return 'collapse', '/sys/* (runtime: cgroup limits, cpu online, hugepages)'
    if re.fullmatch(r'/etc/ssl/certs/[0-9a-f]{8}\.\d+', p):
        return 'collapse', '/etc/ssl/certs/<hash>.N (the hashed-symlink walk)'
    if p.startswith('/etc/ssl/certs/') and p.endswith('.pem'):
        return 'collapse', '/etc/ssl/certs/*.pem (the per-root walk)'
    if p.startswith('/etc/ssl'):
        return 'TLS', p
    if p in ('/etc/resolv.conf', '/etc/nsswitch.conf', '/etc/hosts',
             '/etc/host.conf', '/etc/gai.conf', '/etc/services'):
        return 'RESOLVER', p
    if p.startswith('/etc/pki') or p.startswith('/usr/share/ca-certificates'):
        return 'TLS', p
    if p.startswith('/lib/') or p.startswith('/usr/lib/') or p == '/etc/ld.so.cache' \
            or p == '/etc/ld.so.preload':
        return 'collapse', 'the dynamic loader (ld.so.cache, ld.so.preload, /usr/lib/*)'
    return None, p


def parse(path, home):
    kind = {}                    # fd -> "AF_INET/SOCK_STREAM"
    dns_fd = set()               # fds connect()ed to :53
    pend_sock, pend_conn, pend_io = {}, {}, {}
    addr2name = {}               # address -> name, from the DNS answers
    events = []                  # (n, tid, kind, detail, result)
    paths = collections.Counter()
    execs = []

    def emit(tid, k, detail, result=''):
        events.append([len(events) + 1, tid, k, detail, result])

    def sent(tid, fd, bufs):
        for b in bufs:
            if fd in dns_fd:
                d = dns_message(b)
                if d:
                    emit(tid, 'dns-query', (d[0], d[1], fd))
                    continue
            s_ = sni(b)
            if s_:
                emit(tid, 'tls-sni', (s_, fd))

    def received(tid, fd, b):
        if fd not in dns_fd:
            return
        d = dns_message(b)
        if not d:
            return
        for rn, rt, rd in d[2]:
            if rt in ('A', 'AAAA') and rd:
                addr2name.setdefault(rd, d[0])
        emit(tid, 'dns-answer', (d[0], d[1], [(rt, rd) for _, rt, rd in d[2]]))

    def did_connect(tid, fd, addr, port, fam, res):
        if port == 53:
            dns_fd.add(fd)
        proto = kind.get(fd, '?')
        events.append([len(events) + 1, tid, 'connect',
                       (fam, addr, port, proto, fd), res])

    for line in open(path, encoding='utf-8', errors='replace'):
        line = line.rstrip('\n')
        m = RESUMED.match(line)
        if m:
            tid, call, _, res = m.groups()
            res = (res or '').strip()
            if call == 'socket' and tid in pend_sock:
                kind[res] = pend_sock.pop(tid)
            elif call == 'connect' and tid in pend_conn:
                fd, addr, port, fam = pend_conn.pop(tid)
                did_connect(tid, fd, addr, port, fam, res)
            elif call in ('sendto', 'sendmsg', 'sendmmsg') and tid in pend_io:
                fd = pend_io.pop(tid)[1]
                bufs = [unescape(x) for x in IOVBASE.findall(line)]
                if not bufs:
                    mb = FIRSTSTR.search(line.split('resumed>', 1)[-1])
                    if mb:
                        bufs = [unescape(mb.group(1))]
                sent(tid, fd, bufs)
            elif call == 'recvfrom' and tid in pend_io:
                fd = pend_io.pop(tid)[1]
                mb = FIRSTSTR.search(line.split('resumed>', 1)[-1])
                if mb:
                    received(tid, fd, unescape(mb.group(1)))
            continue
        m = SOCKET.match(line)
        if m:
            _, fam, typ, fd = m.groups()
            kind[fd] = '%s/%s' % (fam, typ.split('|')[0])
            dns_fd.discard(fd)
            continue
        m = SOCKET_UNF.match(line)
        if m:
            tid, fam, typ = m.groups()
            pend_sock[tid] = '%s/%s' % (fam, typ.split('|')[0])
            continue
        m = EXECVE.match(line)
        if m:
            tid, binary, argv = m.groups()
            args = re.findall(r'"((?:[^"\\]|\\.)*)"', argv)
            execs.append((binary, args))
            emit(tid, 'execve', (binary, args))
            continue
        m = NETLINK.match(line)
        if m:
            emit(m.group(1), 'netlink', m.group(4))
            continue
        m = SEND.match(line)
        if m:
            tid, call, fd = m.group(1), m.group(2), m.group(3)
            if '<unfinished' in line:
                pend_io[tid] = (call, fd)
                continue
            bufs = [unescape(x) for x in IOVBASE.findall(line)]
            if not bufs:
                mb = BUF.match(line)
                if mb:
                    bufs = [unescape(mb.group(1))]
            sent(tid, fd, bufs)
            continue
        m = RECV_UNF.match(line)
        if m:
            pend_io[m.group(1)] = (m.group(2), m.group(3))
            continue
        m = RECVFROM.match(line)
        if m:
            tid, fd, buf = m.groups()
            received(tid, fd, unescape(buf))
            continue
        m = CONNECT4.match(line) or CONNECT6.match(line)
        if m:
            tid, fd, port, addr, tail = m.groups()
            fam = 'AF_INET6' if ':' in addr else 'AF_INET'
            if '<unfinished' in tail:
                pend_conn[tid] = (fd, addr, int(port), fam)
            else:
                did_connect(tid, fd, addr, int(port), fam,
                            tail.rpartition('=')[2].strip())
            continue
        m = CONNECTU.match(line)
        if m:
            tid, fd, sun, tail = m.groups()
            if '<unfinished' in tail:
                pend_conn[tid] = (fd, 'unix:' + sun, -1, 'AF_UNIX')
            else:
                did_connect(tid, fd, 'unix:' + sun, -1, 'AF_UNIX',
                            tail.rpartition('=')[2].strip())
            continue
        m = PATHCALL.match(line) or PATHCALL1.match(line)
        if m:
            _, call, p, res = m.groups()
            cat, shown = classify(p, home)
            if cat:
                paths[(cat, shown, call,
                       'ok' if not res.startswith('-1') else res.split('(')[0].strip())] += 1
    return events, paths, execs, addr2name


def fmt_events(events, addr2name):
    sni_by_fd = {}
    for _, _, k, d, _ in events:
        if k == 'tls-sni':
            sni_by_fd.setdefault(d[1], d[0])
    out = []
    for n, tid, k, d, res in events:
        if k == 'connect':
            fam, addr, port, proto, fd = d
            if addr.startswith('unix:'):
                out.append((n, tid, 'connect AF_UNIX', addr[5:], '—', proto,
                            res or '(no result: thread never resumed in trace)', ''))
            else:
                who = addr2name.get(addr, '')
                out.append((n, tid, 'connect', addr, str(port), proto,
                            res or '(unfinished)', who))
        elif k == 'dns-query':
            out.append((n, tid, 'DNS query', d[0], '53 (127.0.0.53)',
                        'AF_INET/SOCK_DGRAM', 'QTYPE ' + d[1], d[0]))
        elif k == 'dns-answer':
            rr = ', '.join('%s %s' % (t, v) for t, v in d[2]) or '(no answer)'
            out.append((n, tid, 'DNS answer', d[0], '53 (127.0.0.53)',
                        'AF_INET/SOCK_DGRAM', '%s: %s' % (d[1], rr), d[0]))
        elif k == 'tls-sni':
            out.append((n, tid, 'TLS ClientHello SNI', d[0], '443',
                        'AF_INET/SOCK_STREAM', 'fd %s' % d[1], d[0]))
        elif k == 'netlink':
            out.append((n, tid, 'netlink', d, '—', 'AF_NETLINK/SOCK_RAW', '', ''))
        elif k == 'execve':
            binary, args = d
            out.append((n, tid, 'execve', binary, '—', '—',
                        ' '.join(args[1:])[:110], ''))
    return out


def main():
    files, homes = [], {}
    args, i = sys.argv[1:], 0
    while i < len(args):
        if args[i] == '--home':
            lbl, _, p = args[i + 1].partition('=')
            homes[lbl] = p.rstrip('/')
            i += 2
        else:
            lbl, _, p = args[i].partition('=')
            files.append((lbl, p))
            i += 1

    runs = [(lbl, parse(p, homes.get(lbl))) for lbl, p in files]
    labels = [l for l, _ in runs]

    print('# E4 — what `claude -p` resolves, connects to, and opens\n')
    print('Derived from the untrimmed traces in this directory by `derive.py`; '
          'nothing here is hand-edited.\n')
    print('Runs: ' + ', '.join(
        '`%s`' % l for l in labels) + '. `run1` is a HOME that has never been '
        'used, `run2` is the same HOME warm, `run3` is the operator\'s own '
        'configured HOME.\n')

    print('## How to read the connect rows\n')
    print('A `connect()` on a **SOCK_DGRAM** socket to a destination port sends no '
          'bytes. It is glibc\'s `getaddrinfo` asking the kernel which source '
          'address it would pick for that destination, so that RFC 3484 can sort '
          'the candidate list. Those rows are there because a sandbox has to '
          'answer them, not because traffic left. The port on such a row is 0 when '
          '`getaddrinfo` was called without a service and 443 when it was called '
          'with one; both are address selection, not a session.\n')
    print('A `connect()` on a **SOCK_STREAM** socket that returns `EINPROGRESS` is '
          'the real thing: a non-blocking TCP connect that then completes. '
          '`ENETUNREACH` on the AF_INET6 rows is this workstation having no IPv6 '
          'route; the client tries v6 first every time and would use it if it '
          'were there.\n')
    print('The name in the last column comes from the DNS answers in the same '
          'trace. The `TLS ClientHello SNI` rows are the independent witness: what '
          'the client itself puts on the wire as the name it means to reach.\n')

    print('## The ordered host list\n')
    print('| run | order of first contact | ports | refused or failed |')
    print('| --- | --- | --- | --- |')
    for lbl, (events, _, _, addr2name) in runs:
        seen, ports, bad = [], collections.defaultdict(set), collections.Counter()
        for _n, _t, k, d, res in events:
            if k == 'dns-query' and d[0] not in seen:
                seen.append(d[0])
            if k == 'connect' and not d[1].startswith('unix:'):
                who = addr2name.get(d[1])
                if who:
                    if who not in seen:
                        seen.append(who)
                    if d[3].endswith('SOCK_STREAM'):
                        ports[who].add(d[2])
                        if res.startswith('-1') and 'EINPROGRESS' not in res:
                            bad[(who, res.split('(')[0].strip())] += 1
            if k == 'connect' and d[1].startswith('unix:') and res.startswith('-1'):
                bad[(d[1], res.split('(')[0].strip())] += 1
        print('| %s | %s | %s | %s |'
              % (lbl,
                 ' → '.join('`%s`' % h for h in seen),
                 '; '.join('%s: %s' % (h, ','.join(str(x) for x in sorted(ports[h])))
                           for h in seen if h in ports),
                 '; '.join('%s %s ×%d' % (a, b, c) for (a, b), c in sorted(bad.items()))))
    print()

    for lbl, (events, _, _, addr2name) in runs:
        print('## %s — every network event, in the order strace wrote it\n' % lbl)
        print('| # | tid | event | name / address | port | socket | result / detail | host |')
        print('| --- | --- | --- | --- | --- | --- | --- | --- |')
        for row in fmt_events(events, addr2name):
            n, tid, k, a, port, proto, res, who = row
            print('| %d | %s | %s | `%s` | %s | %s | %s | %s |'
                  % (n, tid, k, a, port, proto, res or '—', who or '—'))
        print()
        print('Address → name, read off the DNS answers in this same trace: '
              + ('; '.join('`%s` → `%s`' % (a, n) for a, n in sorted(addr2name.items()))
                 or '(none)') + '\n')

    print('## Paths, all runs\n')
    print('Everything under the run\'s `HOME`, everything under `/etc/ssl`, and '
          '`/etc/resolv.conf`, `/etc/nsswitch.conf`, `/etc/hosts`, `/etc/host.conf`, '
          '`/etc/gai.conf`. `/proc`, `/sys`, the loader\'s own files and the '
          'certificate-directory walk are collapsed into one row each; every other '
          'row is a single path.\n')
    print('| class | path | call | result | seen (%s) |' % ', '.join(labels))
    print('| --- | --- | --- | --- | --- |')
    keys = sorted({k for _, r in runs for k in r[1]},
                  key=lambda k: ({'RESOLVER': 0, 'TLS': 1, 'HOME': 2,
                                  'collapse': 3}[k[0]], k[1], k[2]))
    for k in keys:
        cat, p, call, res = k
        print('| %s | `%s` | %s | %s | %s |'
              % (cat, p, call, res,
                 '/'.join(str(r[1][k]) for _, r in runs)))

    print('\n## Binaries executed\n')
    print('| binary | argv (after argv[0]) | seen (%s) |' % ', '.join(labels))
    print('| --- | --- | --- |')
    allex = collections.Counter()
    per = []
    for _, r in runs:
        c = collections.Counter((b, ' '.join(a[1:])[:150]) for b, a in r[2])
        per.append(c)
        allex.update(c)
    for k in sorted(allex):
        print('| `%s` | `%s` | %s |'
              % (k[0], k[1] or '(none)', '/'.join(str(c[k]) for c in per)))


if __name__ == '__main__':
    main()
