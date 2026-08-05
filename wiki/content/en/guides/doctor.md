# Self-Diagnosis

Self-diagnosis answers one question: **is the AgileNet environment on this machine healthy?** It
inspects the seven most common sources of trouble one by one — ports, system proxy, TUN, subscription
kernel, network connectivity, configuration data, and rules — and produces a status report. Items that
can be safely auto-fixed are fixed on the spot; the rest come with clear manual instructions.

Two entry points, one report:

- **CLI**: `anet doctor` (runs locally; no `anet login` required, no database reads, no audit-log writes)
- **anet-gui**: Settings → Self-Diagnosis; click "Start Diagnosis" to generate the report. Abnormal items come with action buttons and explanations

```bash
anet doctor            # 人类可读报告
anet doctor --json     # 结构化输出（{section, status, detail, fixed} 列表）
```

## Reading the Report

The report is organized into sections, one per category of checks. Every check within a section carries a status:

| Status | Meaning | What to Do |
| --- | --- | --- |
| Pass | The check is normal | Nothing |
| Info | Information that does not affect operation (e.g. an optional capability is not enabled) | Review as needed |
| Warning | Currently functional but with latent risks (e.g. a port was once occupied by an unexpected process, redundant rules exist) | Follow the guidance |
| Error | Functionality is already affected (e.g. system proxy residue, missing kernel) | Must be resolved |
| Fixed | A problem was found and automatically repaired during diagnosis | Just confirm the fix note |

### Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | No errors (Info, Warning, and Fixed do not affect the exit code) |
| `1` | Error items exist; scripts can alert on this |
| `2` | Usage or runtime environment error (invalid arguments, insufficient permission to read required information, etc.) |

```bash
anet doctor --json || echo "环境存在异常，请查看报告"
```

---

## Ports and Occupancy (ports)

**What it checks**: whether the local ports required by each AgileNet role are occupied by unexpected
processes — client proxy `57890`, embedded-node API / Relay `59293` / `54431`; when the server role is
enabled, admin API `59090` and Relay listener `54430` are added.

**Healthy state**: ports are free, or listened on by AgileNet's own processes (`anet-gui` / `anet-svc`).

**Common anomalies and causes**:

- The port is taken by other proxy software (Clash-family tools favor the 7890/9090 range; AgileNet defaults all sit in the 50000 range precisely to avoid them, but third-party software can still collide).
- A previous abnormal exit of AgileNet left a residual process still holding the port.

**Auto-fix**: none. Port ownership may involve third-party processes; diagnosis only reports the occupant (PID + process name) and never terminates it for you.

**Manual resolution**:

```bash
# 任意平台（推荐，无需系统自带工具）
anet tool portof 57890

# Windows
netstat -ano | findstr 57890
tasklist | findstr <PID>

# macOS
lsof -i :57890

# 国产 Linux（麒麟 / UOS 裁剪镜像常缺 lsof）
ss -tlnp | grep 57890
```

Once the occupant is identified: if it is a residual AgileNet process, terminate it and start again;
if it is third-party software, change the corresponding AgileNet port to a free one in Settings
(keeping the 50000 range is recommended).

---

## System Proxy (sysproxy)

**What it checks**: whether the system proxy switch state and its target are consistent — when enabled
it should point to the local AgileNet proxy (`127.0.0.1:57890`); when disabled the system proxy should
be fully restored with no residue.

**Healthy state**: switch on → system proxy points to AgileNet; switch off → system proxy is empty or
restored to its original value from before it was enabled.

**Common anomalies and causes**:

- **Residue**: the AgileNet process was force-killed (ended via Task Manager, power loss) and had no chance to restore the system proxy, leaving it pointing at a local port that no longer exists — symptom: "the entire Internet is down".
- **Preemption**: another proxy tool (Clash / FlClash / V2rayN) rewrote the system proxy after AgileNet did, hijacking AgileNet's traffic entry point — symptom: "no rules take effect".

**Auto-fix**: when **residue** is detected, the system proxy is restored to the original state backed up
before AgileNet enabled it, and the item is marked "Fixed". When **preemption** is detected, nothing is
changed (that is the other software's legitimate setting); only the current owner is reported.

**Manual resolution**:

- Windows: Settings → Network & Internet → Proxy; check the "Use a proxy server" switch and address.
- macOS: System Settings → Network → Details → Proxies; check Web Proxy, Secure Web Proxy, and SOCKS Proxy.
- Linux: the proxy page in your desktop environment's network settings, or check the `http_proxy` / `https_proxy` environment variables.

**Coexistence advice**: when multiple proxy tools manage the system proxy at once they will inevitably
overwrite each other — keep only one "writer of the system proxy". To run them side by side, see
[Clash / FlClash Coexistence](#/guides/clash): let AgileNet take the system proxy and the other tool
use rule subscriptions, or vice versa. If AgileNet is confirmed to be the only writer, enable "System
Proxy Lock" in Settings; it automatically takes the setting back and alerts you when something external rewrites it.

---

## TUN Support (tun)

**What it checks**: whether the system capabilities required by TUN mode are ready — a virtual NIC
driver is available and the process has permission to create TUN devices.

**Healthy state**: on Windows a loadable `wintun.dll` is found; on macOS the `utun` device can be
opened; on Linux `/dev/net/tun` exists and is writable by the current process.

**Common anomalies and causes**:

- Windows: `wintun.dll` is missing, quarantined by antivirus software, or too old.
- macOS / Linux: insufficient privileges (not running as root / administrator); trimmed-down kernels on some domestic Linux distributions may not have the `tun` module compiled in, so `/dev/net/tun` does not exist.

**Auto-fix**: none. Driver installation and privilege escalation must be the user's decision.

**Manual resolution**:

- Windows: download the `wintun.dll` for your architecture from [wintun.net](https://www.wintun.net), place it next to `anet-gui.exe` (or under `resources` in the installation directory), then re-run the diagnosis.
- macOS: make sure the app is launched with authorization (no action needed if the installer already handled permissions).
- Linux: check `ls -l /dev/net/tun`; if missing, run `sudo modprobe tun` — machines with modular trimmed kernels need a kernel package that includes tun; if permissions are insufficient, run as root or configure capabilities.

An unavailable TUN does not affect other modes — fall back to system proxy / manual proxy and everything
works normally; this section shows as "Info" rather than "Error" in the report.

---

## Subscription Kernel (kernel)

**What it checks**: whether the subscription proxy kernel (mihomo sidecar) binary exists, whether its
version matches, whether its process is healthy, and whether any orphaned kernel processes remain from
a previous abnormal exit.

**Healthy state**: the kernel file is present, executable, and a supported version; when the
subscription proxy is on, exactly one kernel child process exists, parented to AgileNet.

**Common anomalies and causes**:

- **Orphaned kernel**: after AgileNet was force-killed, the kernel child process was not reaped and keeps holding the mixed port and API port; the next subscription-proxy start reports port conflicts.
- **Missing or corrupted kernel**: the download was intercepted, the disk write went bad, or antivirus software quarantined it.
- **Version mismatch**: the kernel file was replaced manually.

**Auto-fix**: when an orphaned kernel is detected, it is terminated (only kernel processes matching
AgileNet's launch-parameter signature are touched — a mihomo / Clash instance installed by the user is
never harmed) and the item is marked "Fixed".

**Manual resolution**:

- Missing kernel: re-download the kernel on the Subscription Proxy page in Settings; download failures are usually network issues — resolve the network section first.
- Manual orphan cleanup: on Windows find it with `tasklist | findstr mihomo` then `taskkill /PID <PID> /F`; on macOS / Linux use `pkill -f mihomo`. Verify the process path before killing — do not kill other proxy software by mistake.

---

## Network Connectivity (network)

**What it checks**: outbound capability verified layer by layer — DNS resolution, TCP connectivity to
the subscription update address, and egress connectivity through the local proxy — reporting "which
layer is stuck".

**Healthy state**: all three layers connect, with latency within a reasonable range.

**Common anomalies and causes**:

- DNS layer failure: system DNS is hijacked or misconfigured, or the intranet DNS does not resolve the subscription domain.
- TCP layer failure: blocked by the local firewall / gateway, or the subscription address itself is unreachable.
- Proxy egress failure: the local proxy is not running (the client role is off), or the upstream node is offline.

**Auto-fix**: none. The cause of network problems lies outside AgileNet; diagnosis only locates the failing layer.

**Manual resolution**:

```bash
anet tool diag example.com 443     # 一键分层定位（DNS → ping → traceroute → tcping）
anet tool dns example.com          # 单独验证解析
anet tool tcping example.com 443   # 单独验证 TCP
```

Treat by layer: for DNS failure, switch the system DNS or check hosts first; for TCP failure, check the
firewall (`anet tool fwstatus`); for proxy egress failure, go back to the GUI and check node connection status.

---

## Configuration and Data (config)

**What it checks**: readability and integrity of AgileNet's configuration files and local data —
whether the TOML parses, whether the SQLite database opens and passes integrity checks, whether key
fields are within valid ranges.

**Healthy state**: all files parse, and the database integrity check passes.

**Common anomalies and causes**:

- The configuration file gained syntax errors from manual edits, or fields became invalid after an upgrade from an old version.
- The database file was corrupted by power loss / force-killing.

**Auto-fix**: when an **unparseable configuration file** is detected, the original file is renamed to
`<filename>.bak-<timestamp>` as a backup, a fresh startable default configuration is rebuilt, and the
item is marked "Fixed". A corrupted database is **not** rebuilt automatically (credentials and audit
data are involved); it is only reported, with recovery guidance.

**Manual resolution**:

- Configuration and data live in `~/.anet/gui/` by default (`%USERPROFILE%\.anet\gui\` on Windows).
- After an automatic reset, manually merge still-valid custom sections (such as ports and subscription links) from the `.bak` file back into the new configuration.
- Corrupted database: stop AgileNet and restore from the backup directory; with no backup, delete the database file, re-initialize, then log in to the server again to pull the configuration.

---

## Rule Conflicts (rules)

**What it checks**: the health of the currently effective rule set — whether user rules and subscription
rules shadow each other, whether redundant rules exist that can never match, and whether any rules were
paused and forgotten.

**Healthy state**: rules take effect in the expected order, with no large-scale mutual shadowing.

**Common anomalies and causes**:

- The same domain / segment is matched by multiple rules, and the earlier one wins (for example, a user-added `direct` rule shadows a subscription proxy rule).
- Stale rules left behind by a subscription update conflict semantically with the new ones.
- Rules were paused during an earlier troubleshooting session and never resumed.

**Auto-fix**: none. Choosing between rules is user intent; diagnosis only lists conflicting pairs and paused rules.

**Manual resolution**: on the GUI's "Hit Tracking" page, enter the target domain to see exactly which
rule matched and which rules rank ahead of it; then reorder, remove redundancies, or resume paused rules
on the rules page. For full hit-tracking usage, see [anet-gui Graphical Client](#/guides/gui).

---

## FAQ: The Report Is All Green, but I Still Can't Get Online

An all-green report means the local environment is healthy; the problem lies outside the report's scope. Troubleshoot in this order:

1. **GUI Logs page → Live Connections**: initiate a request and see whether the connection appears in the list.
   - No connection at all → traffic never entered AgileNet. Go back to the sysproxy section to confirm the system proxy target, or check whether the application bypasses the system proxy (some applications need their proxy manually set to `127.0.0.1:57890`).
   - Connection appears but closes immediately (red) → read the error message; it is usually an upstream node or TLS problem. See [Troubleshooting and Diagnosis](#/guides/troubleshooting).
2. **Hit Tracking**: enter the target domain and confirm the matched rule and path are as expected (is the egress node correct?). If `direct` or a wrong path matched, go back to the rules section to resolve conflicts.
3. **The network section of the doctor report**: confirm that "egress via local proxy" among the three layers genuinely passes; if that item shows Info, measure actual tunnel throughput to the upstream with `anet tool bandwidth` to rule out link degradation — "connects but can't move traffic".
4. Everything above checks out but it still fails → the problem lies with the target site or the peer network. Use `anet tool diag <target-domain> 443` for the final layer of localization.
