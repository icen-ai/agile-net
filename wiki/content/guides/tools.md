# 网络工具（anet tool）

`anet tool` 是内置在 anet 二进制里的本机网络诊断工具集，面向**无法联网装包的运维现场**：麒麟 / 统信 UOS 等国产化裁剪系统常未安装 telnet / nc / curl / ping，甚至阉割 ICMP 权限。anet 本身是单文件静态二进制，拷过去即自带整套替代品。

- 除 bandwidth 外全部子命令**本机执行**：不走会话校验（无需 `anet login`）、不读数据库、不写审计日志；bandwidth 经管理 API 在服务端执行，需登录（见下文专节）
- 探测失败（超时 / 拒绝 / 无权限）是**正常输出**而非进程错误，配合退出码可脚本化
- 默认人类可读输出，加 `--json` 输出结构化结果（`{success, exit_code, ...}`）
- 需特权的命令自带降级路径，并在输出中显式标注当前探测方式

不知道从哪下手时先跑：

```bash
anet tool selfcheck    # 巡检 PATH 常见命令，输出缺失清单 + 对应 anet tool 替代方案
```

## 命令清单

### 连通性与请求

| 命令 | 替代 | 说明 |
| --- | --- | --- |
| `anet tool tcping <host> <port>` | telnet / nc / Test-NetConnection | TCP 连接探测并计时；`-c N` 多次输出 min/avg/max，`-t` 单次超时 |
| `anet tool curl <url>` | curl / wget | 状态码 / 响应头 / 响应体（截断）/ 耗时；支持 `-X` `-H` `-d` `-k`（跳过证书校验）`--max-time` |
| `anet tool ping <host>` | ping | ICMP echo 主路径，无权限自动降级 TCP ping（见「降级链」） |
| `anet tool traceroute <host>` | tracert / traceroute | ICMP 逐跳 TTL 探测；`--max-hops`、`-t` 可调 |
| `anet tool scan <host> <range>` | nc 批量扫 / nmap 基础 | connect 扫描（如 `1-1024`），并发受限（`--concurrency`，默认 256），只报开放端口 + 常见服务名猜测 |
| `anet tool diag <host> [port]` | ping+tcping+traceroute+DNS 组合 | 分层编排诊断（DNS → ping → traceroute → tcping），输出「卡在哪一层」的结论 |

### DNS

| 命令 | 替代 | 说明 |
| --- | --- | --- |
| `anet tool dns <domain> [@server] [type]` | nslookup / dig | A / AAAA / CNAME / MX / PTR；UDP 查询，512 截断自动重试 TCP |
| `anet tool dnsconf` | cat /etc/resolv.conf | Linux 解析 resolv.conf（nameserver/search/options）；Windows 读各网卡 DNS |

### 端口与进程

| 命令 | 替代 | 说明 |
| --- | --- | --- |
| `anet tool listen [--proto tcp\|udp]` | netstat -tunlp / ss -tulnp | 全部监听 / 已连接 socket + PID + 进程名 |
| `anet tool portof <port>` | lsof -i:\<port\> | 按端口查进程 |
| `anet tool portsof <pid>` | lsof -i \| grep pid | 按进程查端口 |
| `anet tool psinfo <pid>` | ps -p pid | 命令行 / 用户 / exe 路径 / CPU / 内存 |
| `anet tool killport <port>` | kill $(lsof -t -i:port) | 终止占用端口的进程；默认 SIGTERM，`--force` 才 SIGKILL，必须 `-y` 确认（防误杀） |

### 网卡与路由

| 命令 | 替代 | 说明 |
| --- | --- | --- |
| `anet tool ifconfig` | ipconfig / ifconfig / ip a | 网卡列表、IP、MAC、网关、MTU |
| `anet tool route` | route print / ip route | 默认网关 + 路由表 |
| `anet tool mtu [iface]` | ip link | 网卡 MTU（缺省列出全部） |

### 防火墙与其它

| 命令 | 替代 | 说明 |
| --- | --- | --- |
| `anet tool fwstatus` | firewall-cmd / iptables / nft / netsh | 依次探测系统防火墙工具，哪个在用哪个；不重实现规则解析 |
| `anet tool fwcheck <port>` | 人工排查 | 探测指定端口的防火墙放行状态（探测提示） |
| `anet tool bandwidth [peer]` | iperf（差异化） | 经 anet 穿透链路到指定对端的实际吞吐 / RTT（需服务端在线 + 登录 + 对端已连接，见下文专节） |

## 穿透链路带宽测试（bandwidth）

`anet tool bandwidth [peer]` 直接回答「这条穿透链路实际能跑多快」：经 anet 隧道向对端发协议级诊断流（echo / sink / source），输出 RTT 与上下行吞吐。不是 iperf 式裸网测试——测的是**含 TLS 加密与 mux 复用开销的隧道实际能力**，是通用工具给不了的差异化能力。

- `peer`：扇出 connector 的名称或上游地址；缺省 = 第一个已连接（connected）的 connector
- 前提：服务端在线 + 已登录（`anet login`，tool 集中唯一需要会话的命令）+ 对端 connector 处于 connected
- 限制：当前仅支持**上游对端**（经扇出 connector 发起）；对下游扇入对端暂不支持
- 对端挂了对端收敛（Peer ACL）同样可测：诊断流在收敛检查之前由对端本地应答，无路由能力，不构成收敛旁路；带宽流属正常诊断流量，不落审计明细

```bash
anet tool bandwidth            # 测第一个已连接的上游对端
anet tool bandwidth hk-relay   # 按 connector 名称指定
anet tool bandwidth --json     # 结构化输出（peer / rtt / up / down）
```

输出示例：

```text
穿透链路带宽测试（经 anet 隧道）
  对端:   hk-relay
  RTT:    min 0.421ms · avg 0.613ms · max 1.037ms
  上行:   8.0 MiB / 812 ms — 82.76 Mbps
  下行:   8.0 MiB / 790 ms — 85.03 Mbps
```

## 别名（肌肉记忆兼容）

高频命令注册了等价别名，老命令怎么敲就怎么敲：

- `anet tool telnet` / `anet tool nc` → `tcping`
- `anet tool nslookup` → `dns`
- `anet tool netstat` / `anet tool ports` → `listen`
- `anet tool lsof -i:<port>` → `portof`（仅 `-i:` 一种形式）
- `anet tool ip` → `ifconfig`
- `anet tool tracert` → `traceroute`

## 退出码

| 退出码 | 含义 | 示例 |
| --- | --- | --- |
| `0` | 目标可达 / 探测成功 | tcping 连上、dns 解析到记录 |
| `1` | 目标不可达 / 探测失败 | 连接被拒、查询超时（属正常输出，不是程序错误） |
| `2` | 用法或环境错误 | 参数非法、端口范围写错 |

脚本化用法：

```bash
anet tool tcping db.internal 5432 -c 1 --json && echo reachable
```

## 权限需求表

| 命令 | 权限需求 | 无权限时的行为 |
| --- | --- | --- |
| tcping / curl / dns / dnsconf / scan / selfcheck / diag | 无 | — |
| ping | ICMP 需 root / `CAP_NET_RAW` 或内核开放 `net.ipv4.ping_group_range`（Windows 无需管理员） | 自动降级 TCP ping，输出标注 `mode=tcp` |
| traceroute | raw socket（root / `CAP_NET_RAW`） | 输出明确权限指引 |
| listen / portof / portsof | 读全量进程 socket 需 root 或 `CAP_NET_ADMIN` | 只显示本用户进程，输出标注「权限受限，列表可能不完整」 |
| psinfo / killport | 跨用户进程信息读取 / 终止需相应权限 | 如实报错（exit 1 或 2） |
| ifconfig / route / mtu | 无（netlink / 系统 API 只读） | — |
| fwstatus / fwcheck | 取决于探测到的防火墙工具（如 `iptables -L` 需 root） | 全无工具时如实输出「未检测到支持的防火墙工具」+ 人工排查建议 |

Linux 下给二进制授权（免 sudo 跑 ping / traceroute）：

```bash
sudo setcap cap_net_raw+ep anet-svc
```

## 降级链

权限或环境不满足时，工具按固定链路降级，且**输出中始终显式标注当前模式**，绝不静默换路径：

1. **ping**：ICMP echo → TCP ping（`--port` 指定目标端口，默认 443），输出标注 `mode=icmp|tcp`
2. **traceroute**：ICMP 逐跳 → 无权限时输出指引（需 root / `CAP_NET_RAW`，可 `sudo setcap cap_net_raw+ep anet-svc`）
3. **listen / portof / portsof**：全量进程 socket → 权限受限时仅本用户进程 + 不完整提示
4. **fwstatus / fwcheck**：`firewall-cmd` → `iptables` → `nft` → `netsh advfirewall`（Windows）→ 全部不存在时如实报告并建议人工排查，不重实现任何防火墙规则解析

## 国产化裁剪环境场景

典型的内网穿透运维现场：麒麟 / UOS 裁剪镜像里 `telnet`、`nc`、`curl`、`ping` 全缺，出网受限装不了包，甚至 ICMP 被内核策略禁用。应对流程：

1. 拷贝 anet 单文件静态二进制（x86_64 / aarch64 musl 产物，LoongArch 支持评估中，见发布文档）到目标机器
2. `anet tool selfcheck` 确认环境缺失清单与替代命令
3. 按需诊断：`tcping` 验连通、`dns` 验解析、`listen`/`portof` 查端口占用、`diag` 一键定位卡在哪一层
4. ICMP 被阉割时 `ping` 自动退化 TCP 模式；需要完整 ICMP 能力时 `setcap` 授权（见权限需求表）
