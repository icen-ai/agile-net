# `anet tool` 内置网络诊断工具集实施计划

> 状态：全部已实施（2026-08-01）
> 来源：运维场景 CSV 调研（麒麟/UOS 等国产化裁剪环境常缺 telnet/nc/curl/ping 等基础工具且无法联网装包）
> 前置：无（全部为本机诊断能力，不依赖服务端已部署）

## 1. 背景与动机

anet 的目标部署环境（内网穿透运维现场）恰恰是基础网络工具最匮乏的环境：麒麟/UOS
等国产化裁剪系统常未安装 telnet/nc/curl/ping，甚至阉割 ICMP 权限；出网受限的机器
连"装个工具"都做不到。anet 本身是静态二进制（目标形态：单文件拷过去就能跑），
在二进制内自带一套诊断工具，边际成本极低（现有依赖树已覆盖大半），且与产品定位
（内网穿透运维工具）同赛道，不算跑题。

**立项原则**：

- **边际成本优先**：只做边际成本接近零（现有依赖薄封装）或只净增**纯 Rust、
  无 C 依赖、musl 可静态编译**的小 crate 的条目。需要引入 C 库、平台专有 SDK 或
  跨发行版体系差异过大的，不做或降级为探测提示。
- **诊断不需要登录**：`anet tool` 子命令**不走会话校验**——诊断的典型场景
  就是端点尚未配好的时候（唯一例外：`bandwidth` 的测量必须在服务端执行，
  经管理 API 触发，需 `anet login`，见 §2 P3）。
- **权限语义显式化**：凡需特权（raw socket / 读 `/proc`）的命令，必须有无权限
  降级路径，并在输出和 `--help` 中明说当前用的是哪种探测方式。

## 2. 命令分层与实现方案

命令统一挂在 `anet tool <sub>` 子树下（`crates/node/src/cli.rs` 新增 `Tool(ToolArgs)`
变体，实现模块 `crates/node/src/tool/`）。输出沿用现有 CLI 约定：默认人类可读
表格/报告，`--json` 机器可读。

### P0 — 零新增依赖，纯现有依赖薄封装（第一批）

现有依赖已含 tokio(full)、reqwest(rustls)、sysinfo、clap，以下条目均为薄封装。

| 命令 | 覆盖传统命令 | 实现要点 |
| --- | --- | --- |
| `anet tool tcping <host> <port>` | telnet / nc -v / Test-NetConnection | tokio `TcpStream::connect` + 计时；支持 `-c N` 多次探测输出 min/avg/max；别名 `telnet`、`nc`（见 §4） |
| `anet tool curl <url>` | curl / wget | reqwest 封装：状态码、响应头、响应体（截断）、耗时；支持 `-X`、`-H`、`-d`、`-k`（跳过证书校验）、`--max-time` |
| `anet tool dns <domain> [@server] [type]` | nslookup / dig | 手写最小 UDP DNS 查询（A/AAAA/PTR/CNAME/MX，约百余行，含 512 截断重试 TCP）；若复杂度失控再升级 `hickory-proto`（纯 Rust，安全依赖） |
| `anet tool dnsconf` | cat /etc/resolv.conf 等 | Linux 解析 `/etc/resolv.conf`（nameserver/search/options）；Windows 读各网卡 DNS（注册表 `Tcpip\Parameters\Interfaces` 或 iphlpapi） |
| `anet tool scan <host> <port-range>` | nc 批量扫 / nmap 基础 | 并发受限（默认 256）的 tcping 循环，只输出开放端口 + 常见服务名猜测 |
| `anet tool diag <host> [port]` | ping+tcping+traceroute+DNS 组合 | 纯编排：DNS 解析 → ping（§P2 降级链）→ traceroute → tcping，分层输出报告并给出"卡在哪一层"的结论 |
| `anet tool selfcheck` | 无对应 | 扫 PATH 检查常见命令（telnet/nc/curl/ping/traceroute/nslookup/netstat/lsof/ifconfig/ss）是否存在，输出缺失清单 + 对应 `anet tool` 替代方案；兼作整套工具的入口引导 |
| `anet tool psinfo <pid>` | ps -p pid | sysinfo 薄封装：命令行、用户、exe 路径、CPU/内存 |
| `anet tool killport <port>` | kill -9 $(lsof -t -i:port) | `portof` 找 PID + sysinfo kill；默认 SIGTERM，`--force` 才 SIGKILL；执行前打印将终止的进程信息并要求 `-y` 确认（非交互终端必须显式确认，防误杀） |

### P1 — 净增 1-2 个纯 Rust 安全小依赖（第二批）

| 命令 | 覆盖传统命令 | 实现要点 | 新增依赖 |
| --- | --- | --- | --- |
| `anet tool listen` / `anet tool ports` | netstat -tunlp / ss -tulnp | 列出全部监听/已连接 socket + PID + 进程名 | `netstat2`（Linux 读 `/proc/net/*`，Windows 走 `GetExtendedTcpTable`，纯 Rust 无 C 依赖，musl 兼容） |
| `anet tool portof <port>` | lsof -i:port | 同上数据源过滤端口 | 同上 |
| `anet tool portsof <pid>` | lsof -i \| grep pid | 同上数据源过滤 PID | 同上 |
| `anet tool ifconfig` / `anet tool ip` | ipconfig / ifconfig / ip a | 网卡列表、IP、MAC、网关、MTU | `default-net`（Linux 走 netlink，纯 Rust，musl 兼容；同时覆盖 DNS 服务器列表，可反哺 dnsconf） |
| `anet tool route` | route print / ip route | 默认网关 + 路由表 | 同上（default-net 已含） |
| `anet tool mtu [iface]` | ip link | 网卡 MTU | 同上（零增量） |

### P2 — 能做但有权限坑，必须带降级链（第三批）

| 命令 | 覆盖传统命令 | 实现与降级策略 |
| --- | --- | --- |
| `anet tool ping <host>` | ping | 主路径：ICMP echo。Linux 需 root / `CAP_NET_RAW` / 内核开放 `net.ipv4.ping_group_range`；Windows 走 `IcmpSendEcho`（无需管理员）。**降级**：ICMP 不可用时自动退化为 TCP ping（默认 443，可 `--port` 指定），输出中显式标注 `mode=icmp|tcp`。依赖：`surge-ping`（tokio 原生，socket2 raw socket，纯 Rust） |
| `anet tool traceroute <host>` | tracert / traceroute | 主路径：ICMP/UDP 逐跳 TTL 探测（同需 raw socket 权限，参考纯 Rust 实现 `ftr`）。**降级**：无权限时退化为 TCP traceroute（逐 TTL 建连）或明确输出"需要 root/CAP_NET_RAW，可 `setcap cap_net_raw+ep`"的指引。若 TCP traceroute 跨平台实现代价过大，允许只保留 ICMP 主路径 + 权限提示 |

### P3 — 改设计后纳入（第四批，可与 P2 并行）

| 命令 | 说明 |
| --- | --- |
| `anet tool bandwidth [peer]` | **不做** iperf 式裸网吞吐测试，改做产品差异化能力：**经 anet 穿透链路到指定对端的实际吞吐/RTT 测试**（复用现有隧道/mux 发测速流）。这直接回答运维最关心的问题"这条穿透链路实际能跑多快"，是通用工具给不了的。前提：服务端在线 + 已登录 + 对端已连接，属本计划唯一依赖服务端角色与登录会话的命令。**已实施**：协议级诊断流（保留地址 `anet.bandwidth`，首字节定 echo/sink/source 模式，ACL 之前拦截、无路由能力、非收敛旁路）；CLI 经 `POST /api/v1/admin/tool/bandwidth` 在服务端执行（RTT 10×64B + 上下行各 8MiB）；当前仅支持上游（扇出 connector）对端 |
| `anet tool fwstatus` / `anet tool fwcheck <port>` | **降级为探测提示**：shell out 依次探测 `firewall-cmd` / `iptables` / `nft` / Windows `netsh advfirewall`，哪个存在用哪个，全部不存在时如实输出"未检测到支持的防火墙工具"并建议人工排查。**不重实现**任何防火墙规则解析——iptables/nftables/firewalld 三套体系差异过大，超出边际成本原则。优先级最低，允许砍 |

### 明确的非目标

- nmap 级指纹识别、操作系统探测、脚本引擎——`scan` 只做 connect 扫描。
- 防火墙规则解析/重实现（见上）。
- GUI/TUI 内嵌诊断面板——本期只做 CLI；`tool` 模块设计为纯函数库形态（输入参数 → 结构化结果），未来 GUI 可直接复用，但不在本期范围。
- 身份/服务端联动的远端诊断（如对端代查）——与 `bandwidth` 一起另行评估。

## 3. 架构落点

```
crates/node/src/
├── cli.rs              # 新增 Commands::Tool(ToolArgs)；tool 子命令在会话校验之前分流
└── tool/
    ├── mod.rs          # 子命令分发 + 输出格式化（表格/--json）
    ├── tcping.rs       # tcping / scan 共用 connect 探测核心
    ├── http.rs         # curl
    ├── dns.rs          # dns / dnsconf（resolv.conf 解析 + 最小 DNS 协议）
    ├── netstat.rs      # listen / portof / portsof（netstat2 + sysinfo 富化进程信息）
    ├── sysinfo.rs      # psinfo / killport
    ├── netif.rs        # ifconfig / route / mtu（default-net）
    ├── ping.rs         # ping（surge-ping + TCP 降级）
    ├── traceroute.rs   # traceroute + 降级
    ├── fw.rs           # fwstatus / fwcheck（shell out 探测）
    ├── bandwidth.rs    # 链路吞吐测试（P3）
    ├── diag.rs         # diag 编排（组合以上模块）
    └── selfcheck.rs    # PATH 巡检
```

- `tool` 模块全部是**本机操作**（除 bandwidth），不依赖 API server 运行、不读数据库、
  不写审计日志——与 cli.rs 现有管理命令（需 login）在执行入口即分流。
- 结构化结果类型（serde Serialize）为唯一内部接口，`--json` 直接序列化，
  人类可读输出由 mod.rs 统一渲染，保证未来 GUI 复用时零改动。
- 错误语义：探测失败（超时/拒绝/无权限）是**正常输出**而非进程错误——
  退出码约定：`0` 目标可达/探测成功，`1` 目标不可达/探测失败，`2` 用法或环境错误，
  与 `--json` 的 `{success, ...}` 字段一致，方便脚本化。

## 4. 别名策略（肌肉记忆兼容）

目标用户是顺手敲老命令的工程师，给高频命令注册等价别名，学习成本归零：

- `anet tool telnet <host> <port>` → `tcping`
- `anet tool nc <host> <port>` → `tcping`
- `anet tool nslookup <domain>` → `dns`
- `anet tool netstat` → `listen`
- `anet tool lsof -i:<port>` → `portof`（解析 `-i:` 形式即可，不做完整 lsof 语法）

别名在 `--help` 中标注，文档中只维护主命令名。

## 5. 依赖新增清单（全部需过 musl 静态编译验证）

| crate | 用途 | 风险点 |
| --- | --- | --- |
| `netstat2` | listen/portof/portsof | Linux 路径读 `/proc`，musl 无虞；Windows 走 iphlpapi |
| `default-net` | ifconfig/route/mtu | Linux 走 netlink，无 C 依赖；macOS/Windows 走系统 API |
| `surge-ping` | ping | 依赖 socket2 raw socket；musl OK；权限问题由降级链兜底 |
| （备选）`hickory-proto` | dns | 仅当手写 DNS 查询失控时引入，纯 Rust |

引入任何新依赖时同步更新本文件与 `AGENTS.md` 常用命令节（如涉及新构建注意点）。

## 6. 发布矩阵与国产化适配

"拷过去就能跑"是本计划的灵魂，发布侧必须跟上（现状见 `docs/release.md`）：

- **x86_64 / aarch64 的 musl 静态产物**为必须项（麒麟/UOS 主流架构）。
- **LoongArch（龙芯）**：Rust 为 tier-2 目标，musl 工具链有坑；本期只在
  `docs/release.md` 登记为"评估中"，不阻塞 tool 功能落地，但需尽早验证
  `cargo build --target loongarch64-unknown-linux-musl` 的可行性，否则
  "国产化无网环境"卖点打折。
- 控制二进制体积：新依赖一律 `default-features = false` 起步，按需开特性。

## 7. 实施批次与验收

每批完成后运行 `rtk cargo test --workspace` 全绿并提交（遵循 AGENTS.md 流程）。

1. **批次一（P0）**：tcping(+别名) / curl / dns / dnsconf / scan / selfcheck /
   psinfo / killport / diag 骨架。
   - 验收：本机起临时 listener 测 tcping/scan；dns 对 `127.0.0.53`/`114.114.114.114`
     可注入测试；selfcheck 在 `PATH` 受控环境下断言缺失报告。
2. **批次二（P1）**：listen / portof / portsof / ifconfig / route / mtu。
   - 验收：起已知端口的测试进程，断言 portof/portsof/killport 链路；
     killport 误杀保护（无 `-y` 拒绝执行）有测试。
3. **批次三（P2 + P3-fw）**：ping / traceroute / fwstatus / fwcheck。
   - 验收：降级链有测试（模拟无 raw socket 权限环境，断言退化为 TCP 模式且
     输出标注 mode）；fw 在无防火墙工具的容器中如实输出"未检测到"。
4. **批次四（P3）**：bandwidth 链路吞吐（依赖对端，接入 `.docker` 四级链
   编排做断言）。**已实施（2026-08-01）**。
   - 验收：docker-compose 链上跑 bandwidth，输出 RTT/吞吐且数量级合理；
     core 集成测试（`crates/core/tests/bandwidth_test.rs`）覆盖两侧应答、
     收敛节点可测、未知模式关闭；node API 测试（`crates/node/tests/tool_api_test.rs`）
     覆盖缺省/指定 peer、未知 peer 40400、无可用对端 40401。

测试约定：网络探测类单测一律打本机回环或测试内临时 listener，不依赖外网；
权限相关路径用依赖注入/特性开关模拟，CI 不申请特权。

## 8. 文档与权限指引

- `docs/api/overview.md` 不动（tool 仅 bandwidth 经 API，端点为
  `POST /api/v1/admin/tool/bandwidth`，文档见 wiki「网络工具 anet tool」）；
  新增 `docs/crate/cli-tool.md` 或在 CLI 用户文档中登记命令清单、退出码、权限需求表。
- Linux 权限指引写入文档（也进 `--help` 长描述）：
  `ping`/`traceroute` 推荐 `sudo setcap cap_net_raw+ep anet-svc`；
  `listen`/`portof` 读全量进程 socket 需 root 或 `CAP_NET_ADMIN`（无权限时
  只显示本用户进程，输出中标注"权限受限，列表可能不完整"）。
- `AGENTS.md` 端口规范/常用命令节在本功能落地后同步更新。
