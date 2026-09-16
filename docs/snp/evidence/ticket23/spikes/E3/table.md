# E3 — E1's resource list, row by row, against Deno's permission flags

`express` is the flag that says this row and nothing wider. `unpoliced` means
the resource is still used and Deno's permission model never sees it: the
capability query says `prompt` and the syscall happens anyway. `absent` means
Deno does not touch the row at all.

| E1 row | Deno | the flag, or what happens instead |
| --- | --- | --- |
| `104.18.20.81:443` (www.rfc-editor.org) | **express** | `--allow-net=www.rfc-editor.org:443`. The check is against the **name** in the URL, before resolution, so the address never enters it — which is why a CDN's two A records cost nothing here and cost everything to a CIDR. |
| `160.79.104.10:443` (api.anthropic.com) | **express** | `--allow-net=api.anthropic.com:443`. |
| `127.0.0.53:53` (the resolver, UDP) | **unpoliced** | `fetch` resolves inside Rust and glibc; the query `net 127.0.0.53:53` is `prompt` on a run whose fetches all succeed. The same address through `Deno.connect` **is** checked (`NotCapable: Requires net access to "127.0.0.53:53"`), so the resolver is unpoliced exactly when it is the runtime's and policed when it is the script's. |
| `104.18.20.81:0`, `104.18.21.81:0`, `160.79.104.10:0` (source-address selection, UDP) | **unpoliced** | glibc's, inside `getaddrinfo`; present in Deno's strace exactly as in Go's. |
| `2606:4700::6812:1451:0`, `…:1551:0`, `2607:6bc0::10:0` (AAAA, ENETUNREACH) | **unpoliced** | same. |
| `netlink:RTM_GETADDR` | **unpoliced** | same. Deno has no netlink capability at all. |
| `unix:/var/run/nscd/socket` (ENOENT) | **unpoliced** | two `connect` calls a run, as in E1. `--allow-net` does not cover AF_UNIX, and there is no flag for this socket. |
| binary `./agent` (`execve`) | **cannot** | the binary is now `deno` itself, and Deno does not police its own exec. `--allow-run` governs children only; `X` for the agent process is whoever started `deno`. |
| `/etc/gai.conf`, `/etc/host.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, `/etc/resolv.conf` | **unpoliced** | Deno opens all five (`run-strace.raw`); `read /etc/resolv.conf` and `read /etc/nsswitch.conf` both query `prompt` on the same run. |
| `/etc/ld.so.cache`, `/etc/ld.so.preload`, `/lib/x86_64-linux-gnu/libc.so.6` | **unpoliced** | the dynamic loader's, before any Deno code runs. Deno adds `libm`, `libdl`, `libgcc_s`, `libpthread`, `librt`. |
| `/etc/pki/tls/certs` (ENOENT), `/etc/ssl/certs`, `/etc/ssl/certs/ca-certificates.crt`, the 122-openat `*.pem` walk, the 244 `readlinkat` hashed-symlink walk | **absent** | **zero** cert files opened on a straced run that completed three TLS handshakes. Deno's roots are compiled into the binary, so the whole trust-store half of `F` disappears — and with it any way to say *which* roots this agent trusts. `read /etc/ssl/certs` queries `prompt` throughout. |
| `summary.txt` (`openat O_WRONLY\|O_CREAT\|O_TRUNC`) | **express** | `--allow-write=./summary.txt`. Exact path, resolved against the cwd at process start, and it works for a file that does not exist yet. A sibling (`./other.txt`) and an absolute elsewhere are both refused. |
| `/proc/*`, `/sys/*` (the Go runtime's maps, cgroup, hugepage, cpu.max) | **unpoliced** | Deno's equivalents: `/proc/self/maps`, `/proc/self/cgroup`, four `cpu.max` up the cgroup tree, `/proc/meminfo`, `/proc/sys/kernel/osrelease`, `/sys/devices/system/cpu/online`, `tsc_freq_khz`, six `/dev/urandom`. |
| — (not in E1) | **unpoliced** | **33** probes for `deno.json`, `deno.jsonc` and `package.json`, one triple per directory from the script's own up to `/`, plus `~/.npmrc`. Deno reads above the working directory as a matter of startup, and no `--allow-read` is involved. |
| — (not in E1) | **unpoliced** | `~/.cache/deno`: 11 opens — three SQLite databases (`dep_analysis_cache_v2`, `node_analysis_cache_v2`, `v8_code_cache_v2`) with their `-wal` and `-shm`, `latest.txt`, and the transpiled `gen/…/agent.ts.js`. These are **written** on every run under a flag set whose only write grant is `./summary.txt`. |
| — (not in E1) | **express** | `ANTHROPIC_API_KEY` is `--allow-env=ANTHROPIC_API_KEY`. E1 never listed it because `environ` is not a syscall; Deno makes the key a named resource, which is the one thing its model has that `(N, F, X)` has not. |
