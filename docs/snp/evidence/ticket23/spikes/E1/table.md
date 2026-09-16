| kind | resource | protocol | seen (run1, run2, run3) | note |
| --- | --- | --- | --- | --- |
| destination | `104.18.20.81:443` | AF_INET/SOCK_STREAM | 1/1/1 | www.rfc-editor.org — -1 EINPROGRESS (Operation now in progress) |
| destination | `160.79.104.10:443` | AF_INET/SOCK_STREAM | 1/1/1 | api.anthropic.com — -1 EINPROGRESS (Operation now in progress) |
| destination | `127.0.0.53:53` | AF_INET/SOCK_DGRAM | 2/2/2 | — |
| destination | `104.18.20.81:0` | AF_INET/SOCK_DGRAM | 1/1/1 | www.rfc-editor.org — port 0: source-address selection, no bytes |
| destination | `104.18.21.81:0` | AF_INET/SOCK_DGRAM | 1/1/1 | www.rfc-editor.org — port 0: source-address selection, no bytes |
| destination | `160.79.104.10:0` | AF_INET/SOCK_DGRAM | 1/1/1 | api.anthropic.com — port 0: source-address selection, no bytes |
| destination | `2606:4700::6812:1451:0` | AF_INET6/SOCK_DGRAM | 1/1/1 | www.rfc-editor.org — -1 ENETUNREACH (Network is unreachable); port 0: source-address selection, no bytes |
| destination | `2606:4700::6812:1551:0` | AF_INET6/SOCK_DGRAM | 1/1/1 | www.rfc-editor.org — -1 ENETUNREACH (Network is unreachable); port 0: source-address selection, no bytes |
| destination | `2607:6bc0::10:0` | AF_INET6/SOCK_DGRAM | 1/1/1 | api.anthropic.com — -1 ENETUNREACH (Network is unreachable); port 0: source-address selection, no bytes |
| destination | `netlink:RTM_GETADDR` | AF_NETLINK/SOCK_RAW | 2/2/2 | — |
| destination | `unix:/var/run/nscd/socket` | AF_UNIX/SOCK_STREAM | 2/2/2 | -1 ENOENT (No such file or directory) |
| binary | `./agent` | execve | 1/1/1 | the only one |
| path | `/` | newfstatat | 0/0/1 | — |
| path | `/etc/gai.conf` | openat | 1/1/1 | — |
| path | `/etc/host.conf` | openat | 1/1/1 | — |
| path | `/etc/hosts` | openat | 2/2/2 | — |
| path | `/etc/ld.so.cache` | openat | 1/1/1 | — |
| path | `/etc/ld.so.preload` | access | 0/0/1 | -1 ENOENT (No such file or directory) |
| path | `/etc/nsswitch.conf` | newfstatat | 0/0/2 | — |
| path | `/etc/nsswitch.conf` | openat | 2/2/2 | — |
| path | `/etc/pki/tls/certs` | openat | 1/1/1 | -1 ENOENT (No such file or directory) |
| path | `/etc/resolv.conf` | newfstatat | 0/0/2 | — |
| path | `/etc/resolv.conf` | openat | 2/2/2 | — |
| path | `/etc/ssl/certs` | openat | 1/1/1 | — |
| path | `/etc/ssl/certs/ca-certificates.crt` | openat | 2/2/2 | — |
| path | `/lib/x86_64-linux-gnu/libc.so.6` | openat | 1/1/1 | — |
| path | `summary.txt` | openat | 1/1/1 | — |
| path | `/etc/ssl/certs/*.pem (the per-root walk)` | openat | 123/124/122 | collapsed |
| path | `/etc/ssl/certs/*.pem (the per-root walk)` | readlinkat | 0/0/121 | collapsed |
| path | `/etc/ssl/certs/<hash>.N (the hashed-symlink walk)` | readlinkat | 0/0/123 | collapsed |
| path | `/proc/* (Go runtime: maps, cgroup, mountinfo)` | openat | 3/3/3 | collapsed |
| path | `/sys/* (Go runtime: hugepage size, cpu.max, cpu/online)` | openat | 4/2/2 | collapsed |
