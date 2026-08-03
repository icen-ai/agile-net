# Network Tools (anet tool)

`anet tool` is a local network diagnostics toolset built into the anet binary, aimed at **operations
sites where packages cannot be installed online**: trimmed-down domestic systems such as Kylin /
UnionTech UOS often lack telnet / nc / curl / ping, and may even strip ICMP permissions. anet itself is
a single-file static binary — copy it over and you have the full set of replacements.

- All subcommands except bandwidth **run locally**: no session validation (no `anet login` needed), no database reads, no audit-log writes; bandwidth executes on the server via the management API and requires login (see its dedicated section below)
- Probe failures (timeout / refused / no permission) are **normal output**, not process errors — combined with exit codes they are scriptable
- Human-readable output by default; add `--json` for structured results (`{success, exit_code, ...}`)
- Privileged commands ship with built-in fallback paths and always mark the active probe mode explicitly in the output

Not sure where to start? Run this first:

```bash
anet tool selfcheck    # 巡检 PATH 常见命令，输出缺失清单 + 对应 anet tool 替代方案
```

## Command Reference

### Connectivity and Requests

| Command | Replaces | Description |
| --- | --- | --- |
| `anet tool tcping <host> <port>` | telnet / nc / Test-NetConnection | TCP connect probe with timing; `-c N` repeats and prints min/avg/max, `-t` sets the per-attempt timeout |
| `anet tool curl <url>` | curl / wget | Status code / response headers / response body (truncated) / elapsed time; supports `-X` `-H` `-d` `-k` (skip certificate verification) `--max-time` |
| `anet tool ping <host>` | ping | ICMP echo is the primary path; falls back to TCP ping automatically without privileges (see "Fallback Chains") |
| `anet tool traceroute <host>` | tracert / traceroute | ICMP hop-by-hop TTL probing; `--max-hops` and `-t` are tunable |
| `anet tool scan <host> <range>` | nc batch scan / basic nmap | Connect scan (e.g. `1-1024`) with bounded concurrency (`--concurrency`, default 256); reports open ports only, with common service-name guesses |
| `anet tool diag <host> [port]` | ping+tcping+traceroute+DNS combo | Layered orchestration diagnosis (DNS → ping → traceroute → tcping) concluding "which layer is stuck" |

### DNS

| Command | Replaces | Description |
| --- | --- | --- |
| `anet tool dns <domain> [@server] [type]` | nslookup / dig | A / AAAA / CNAME / MX / PTR; UDP queries with automatic TCP retry on 512-byte truncation |
| `anet tool dnsconf` | cat /etc/resolv.conf | Linux: parses resolv.conf (nameserver/search/options); Windows: reads per-adapter DNS |

### Ports and Processes

| Command | Replaces | Description |
| --- | --- | --- |
| `anet tool listen [--proto tcp\|udp]` | netstat -tunlp / ss -tulnp | All listening / connected sockets + PID + process name |
| `anet tool portof <port>` | lsof -i:\<port\> | Find the process by port |
| `anet tool portsof <pid>` | lsof -i \| grep pid | Find ports by process |
| `anet tool psinfo <pid>` | ps -p pid | Command line / user / exe path / CPU / memory |
| `anet tool killport <port>` | kill $(lsof -t -i:port) | Terminate the process holding a port; SIGTERM by default, SIGKILL only with `--force`, and `-y` confirmation is mandatory (prevents accidents) |

### Interfaces and Routes

| Command | Replaces | Description |
| --- | --- | --- |
| `anet tool ifconfig` | ipconfig / ifconfig / ip a | Interface list, IP, MAC, gateway, MTU |
| `anet tool route` | route print / ip route | Default gateway + routing table |
| `anet tool mtu [iface]` | ip link | Interface MTU (lists all by default) |

### Firewall and Others

| Command | Replaces | Description |
| --- | --- | --- |
| `anet tool fwstatus` | firewall-cmd / iptables / nft / netsh | Probes system firewall tools in order and uses whichever exists; rule parsing is not reimplemented |
| `anet tool fwcheck <port>` | manual investigation | Probes whether the firewall allows a given port (heuristic hints) |
| `anet tool bandwidth [peer]` | iperf (differentiated) | Actual throughput / RTT to a given peer across the anet tunnel (requires the server online + login + a connected peer; see the dedicated section below) |

## Tunnel Bandwidth Test (bandwidth)

`anet tool bandwidth [peer]` directly answers "how fast can this tunnel actually go": it sends
protocol-level diagnostic streams (echo / sink / source) to the peer through the anet tunnel and
reports RTT plus up/down throughput. This is not an iperf-style raw-network test — it measures **the
tunnel's real capability including TLS encryption and mux overhead**, a differentiator generic tools
cannot offer.

- `peer`: the name of a fan-out connector or an upstream address; defaults to the first connected connector
- Prerequisites: the server is online + you are logged in (`anet login` — the only command in the toolset that needs a session) + the peer connector is connected
- Limitation: currently only **upstream peers** (initiated via fan-out connectors); downstream fan-in peers are not yet supported
- Peers with Peer ACL attached are equally testable: the diagnostic stream is answered locally by the peer before the ACL check, has no routing capability, and does not constitute an ACL bypass; bandwidth streams are normal diagnostic traffic and are not recorded in audit details

```bash
anet tool bandwidth            # 测第一个已连接的上游对端
anet tool bandwidth hk-relay   # 按 connector 名称指定
anet tool bandwidth --json     # 结构化输出（peer / rtt / up / down）
```

Sample output:

```text
穿透链路带宽测试（经 anet 隧道）
  对端:   hk-relay
  RTT:    min 0.421ms · avg 0.613ms · max 1.037ms
  上行:   8.0 MiB / 812 ms — 82.76 Mbps
  下行:   8.0 MiB / 790 ms — 85.03 Mbps
```

## Aliases (muscle-memory compatible)

High-frequency commands have equivalent aliases — type them the way your fingers remember:

- `anet tool telnet` / `anet tool nc` → `tcping`
- `anet tool nslookup` → `dns`
- `anet tool netstat` / `anet tool ports` → `listen`
- `anet tool lsof -i:<port>` → `portof` (only the `-i:` form)
- `anet tool ip` → `ifconfig`
- `anet tool tracert` → `traceroute`

## Exit Codes

| Exit Code | Meaning | Examples |
| --- | --- | --- |
| `0` | Target reachable / probe succeeded | tcping connected, dns resolved records |
| `1` | Target unreachable / probe failed | Connection refused, query timed out (normal output, not a program error) |
| `2` | Usage or environment error | Invalid arguments, malformed port range |

Scripting usage:

```bash
anet tool tcping db.internal 5432 -c 1 --json && echo reachable
```

## Permission Requirements

| Command | Privilege Needed | Behavior Without It |
| --- | --- | --- |
| tcping / curl / dns / dnsconf / scan / selfcheck / diag | None | — |
| ping | ICMP needs root / `CAP_NET_RAW` or a kernel-opened `net.ipv4.ping_group_range` (no administrator needed on Windows) | Automatically falls back to TCP ping, output marked `mode=tcp` |
| traceroute | Raw socket (root / `CAP_NET_RAW`) | Prints explicit privilege guidance |
| listen / portof / portsof | Reading all processes' sockets needs root or `CAP_NET_ADMIN` | Shows only the current user's processes, with the note "limited privileges; the list may be incomplete" |
| psinfo / killport | Reading / terminating other users' processes needs the corresponding privileges | Fails honestly (exit 1 or 2) |
| ifconfig / route / mtu | None (netlink / system APIs are read-only) | — |
| fwstatus / fwcheck | Depends on the detected firewall tool (e.g. `iptables -L` needs root) | With no tool available, honestly reports "no supported firewall tool detected" plus manual-investigation advice |

Granting the binary privileges on Linux (run ping / traceroute without sudo):

```bash
sudo setcap cap_net_raw+ep anet-svc
```

## Fallback Chains

When privileges or the environment fall short, tools degrade along fixed chains and **always mark the
active mode explicitly in the output** — paths are never switched silently:

1. **ping**: ICMP echo → TCP ping (`--port` selects the target port, default 443), output marked `mode=icmp|tcp`
2. **traceroute**: ICMP hop-by-hop → without privileges, prints guidance (root / `CAP_NET_RAW` needed; `sudo setcap cap_net_raw+ep anet-svc` works)
3. **listen / portof / portsof**: all processes' sockets → with limited privileges, only the current user's processes plus an incompleteness note
4. **fwstatus / fwcheck**: `firewall-cmd` → `iptables` → `nft` → `netsh advfirewall` (Windows) → when none exists, reports honestly and suggests manual investigation; no firewall rule parsing is reimplemented

## Scenario: Trimmed-Down Domestic Linux Environments

A typical intranet-penetration operations site: in Kylin / UOS trimmed images, `telnet`, `nc`, `curl`,
and `ping` are all missing, outbound restrictions block package installation, and ICMP may even be
disabled by kernel policy. The playbook:

1. Copy the anet single-file static binary (x86_64 / aarch64 musl artifacts; LoongArch support under evaluation — see the release notes) to the target machine
2. Run `anet tool selfcheck` to confirm what's missing and the replacement commands
3. Diagnose as needed: `tcping` for connectivity, `dns` for resolution, `listen`/`portof` for port occupancy, `diag` to locate the stuck layer in one shot
4. When ICMP is stripped, `ping` automatically degrades to TCP mode; for full ICMP capability, grant privileges with `setcap` (see Permission Requirements)
