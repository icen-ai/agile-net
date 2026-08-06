# 连接记录（全收录连接日志）设计与实施记录

状态：设计定稿（2026-08，讨论结论见 §2 决策），实施分期见 §6。

## 1. 背景与问题

日志页四页签（实时连接/实时日志/命中追踪/事件中心）数据源**全部来自 mihomo 内核**（`sub_connections` WS / 内核日志）。两个系统性盲区：

1. **放行流量无记录**：`*.icen.ai` 这类放行（Direct）在 anet 本地代理入站层（`crates/core/src/proxy/inbound.rs`）`decide_inbound` 后直接拨号，**流量根本不转发给 mihomo**，内核连接追踪自然没有；anet 侧此前只做全局字节累计（`stats.bytes_up/down` + `record_transit`），无逐连接记录。
2. **隧道连接不可见**：anet 穿透隧道（Tunnel 出站）连接同样不过 mihomo，日志页完全看不到。

数据链路：`系统代理 → anet 本地代理(57890) → decide_inbound → Direct / Tunnel / Forward(订阅内核)`。**anet 入站层是全量数据面前门**（SOCKS5 + HTTP 两个入口，三条出站臂结束处 `copy_bidirectional` 均返回 `(up, down)`），记录钩子现成。

TUN 模式链路不同：mihomo TUN 收编全部流量 → 规则 → `MATCH,ANET-IN`（socks 回转 127.0.0.1:57890）→ **照常过 anet 入站钩子**；但 mihomo 侧 DIRECT 的（UDP 等）不过 anet。因此 TUN 下需要内核源补充（见 §5）。

## 2. 讨论决策（用户拍板）

| 议题 | 决策 |
| --- | --- |
| 记录实现位置 | **写 Rust**（anet 数据面前门自带域名/规则/字节语义），不用系统能力（ETW/NEFilter/conntrack 拿不到域名与规则命中，跨平台三套高权限） |
| 落盘 | **内存为主 + 智能动态落盘**（不逐条写，防性能损耗） |
| 命中层信息 | **要**——记录「被哪条规则/哪一层放行或路由」 |
| TUN 模式 | **一期一起设计**（模型带 `source` 字段），避免后续冲突 |
| 隐私 | **默认关闭**；连接记录页内开关；一键清空；时间范围查询；搜索 |
| 分页 | 连接类列表 50 条/页；四个页签一起重设计 |

## 3. 记录模型与命中层

```rust
ConnRec {
    id: u64,              // 原子递增
    start_ms: i64, end_ms: i64, // epoch 毫秒（active 时 end=0）
    host: String,         // 域名或 IP（hosts 映射改写前的原始目标另注 mapped_to）
    port: u16,
    proto: Socks5 | Http, // 入站协议
    source: Proxy | TunRelay,   // TUN 回转标记（tun_mode 开启时入站记录打 TunRelay）
    outbound: Direct | Tunnel{node} | Forward,  // Forward = 订阅内核
    hit: UserBypass | ExplicitRoute | PresetBypass | Default,  // 命中层
    up: u64, down: u64,   // active 实时累计 / closed 终值
    state: Active | Closed | Failed(String),
}
```

命中层由 `ProxyRouter` 带出：`decide_inbound` 现行四档优先级（用户 bypass > 更窄显式路由 > 预置 bypass > 默认出口）改为返回 `(Outbound, HitLayer)` 元组（新增 `decide_inbound_hit`，旧签名保留委托调用，零破坏）；hosts 映射改写命中时另记 `mapped_to`。UI 文案：用户放行 / 显式路由 / 预置放行 / 默认兜底。

## 4. 记录器（core：`proxy::conlog` 模块）

- `ConnLog`：`enabled: AtomicBool`（**默认 false，关闭时全路径短路零开销**）；closed 记录 `VecDeque` 容量 5000（挤最旧）；active 表 `DashMap<u64, Arc<ActiveCounters>>`。
- 实时字节：入站流与目标流各包一层 CountingIo（read/write 累计到共享原子计数器），active 期间前端轮询读增量；`copy_bidirectional` 结束写终值、状态转 Closed（握手/拨号失败记 Failed）。
- 查询：`query(filter, offset, limit)`——filter = 关键词（host 包含）/ 出站类型 / 状态 / 时间范围 `[from_ms, to_ms]`；分页 50/页由调用方传 offset/limit；`totals()` 返回本会话累计 up/down/连接数/active 数。
- **智能落盘**：批量触发——①未落盘记录满 200 条 ②30s 空闲定时 ③开关关闭/应用退出；JSONL 追加写 `conn-log.jsonl`（桌面数据目录，与 roles 同目录），异步 task 持快照写、不阻塞数据面；启动回放最近 5000 条重建内存。开关关闭 = 不记录也不落盘；**一键清空 = 内存 + 文件一起删**。
- 隐私：连接记录 = 浏览历史。页面明示；默认关；清空彻底。

## 5. TUN 模式

- 入站钩子照常记录，打 `source = TunRelay`（桌面侧开启 TUN 时把标志位注入 ConnLog）。
- mihomo 侧 DIRECT（UDP 等不过 anet 的流量）由内核 `/connections` 补充采集（desktop kernel manager 已有 WS 通道），打 `source = Kernel`。
- 展示去重：TUN 下同一 TCP 流会出现 Kernel(TUN 入站) + TunRelay(回转) 两条——`tun-relay` 行默认折叠（过滤器可选显示），以内核源为主视图。
- 系统代理/本地代理模式下无 Kernel 源，anet 记录即全收录。

## 6. 实施分期

- **P1 core**：`proxy::conlog` 记录器 + CountingIo + `decide_inbound_hit` 命中层 + inbound 三臂钩子（SOCKS5/HTTP）+ 单测。
- **P2 client/desktop 接线**：client 引擎持有 `Arc<ConnLog>` 并注入 ProxyInbound；roles 持久化开关（`conn_log_enabled`，默认 false）；智能落盘 task；tauri 命令 `conlog_status / conlog_query / conlog_set_enabled / conlog_clear`。
- **P3 GUI 日志页重设计**：
  - 「实时连接」改「**连接记录**」：顶行（启用开关 / 本会话累计↑↓与连接数 / 搜索 / 出站类型过滤 / 状态过滤 / 时间范围：全部·近1h·近24h·自定义起止 / 一键清空 askConfirm）；active 区置顶（1s 实时速率）；记录区 50/页分页；行右键保留强制打断（active）与一键加规则（含 closed——按 host 生成放行/路由规则）。
  - 命中追踪、事件中心：同步加 50/页分页。实时日志（内核流）保持流式 + 已有级别过滤。
- **P4 TUN 补充**：内核源采集合并与 TunRelay 折叠视图。

## 7. 实施记录

2026-08 全部四期落地：

- **P1 core**（`crates/core/src/proxy/`）：`conlog.rs` 记录器（ConnRec 模型 / enabled+tun_relay 原子开关 / ring 5000 / active DashMap 实时计数 / `CountingIo` 客户端流包装 / kill oneshot 开关 / unflushed 快照 / restore 回放）；`router.rs` 新增 `decide_inbound_hit`（旧 `decide_inbound` 委托，零破坏）；`inbound.rs` 两入口三臂全挂钩（`ConnRecGuard` drop 定稿 Closed、`.fail` 标 Failed；kill 开关经 select 竞速，**sender 未注册时 kill 分支 pending 化**——否则 oneshot 关闭会误杀连接，socks5_auth_enforced 抓出）；SOCKS5 Forward 臂改 connect+手动泵（拨号失败标 Failed、中途重置仍 Closed）。测试 8 新（conlog 7 + 计数流 1），core 133 全过。
- **P2 client/desktop**：`client.rs` 引擎持有 `Arc<ConnLog>` 并随 `start_proxy_with_auth` 注入（`conn_log()` 访问器）；desktop `cmd/conlog.rs`（`conlog_status/query/set_enabled/clear/kill` 五命令）+ `roles.conn_log_enabled`（serde 默认 false）+ 智能落盘（5s tick：≥200 立即 / 30s 空闲扫 / 关闭先冲后停，JSONL `~/.anet/gui/conn-log.jsonl`，启动回放截断 5000）+ `set_tun_mode` 打 TunRelay 标。
- **P3 GUI**：日志页「实时连接」改「**连接记录**」（工具行：记录开关+隐私 ahelp+会话累计统计+TUN 提示+清空 askConfirm；过滤行：搜索/出口/状态/时间范围含自定义起止/含 TUN 回转；50 条/页分页；行 = 时间/目标:端口(→映射)/出口徽标/命中层/↓↑累计/耗时/状态徽标；右键 active 强制打断（conlog_kill）+ 加规则）；命中追踪、事件中心 50 条/页分页（事件取最新 200 条客户端分页）。i18n 键 `logs.cl.*`/`logs.out.*`/`logs.hit.*` 双语。
- **P4 TUN**：`source` 字段从模型第一天就位（Proxy/TunRelay）；回转行默认隐藏，「含 TUN 回转」勾选调 source=all 查询并打 TUN 徽标；TUN 模式工具行提示「UDP 与内核直连流量不入库」。内核源持久合并不做（避免双源双写冲突，见 §5）。
- 偏差：内核时代的「连接详情展开（链路迷你拓扑）」随数据源切换下线（anet 记录无内核链信息）；`recent_events` 上限 200 故事件分页在 200 条内进行；HTTP_MODE（Web 远程面）连接记录不可用（local-only 语义，与原有一致）。

### 2026-08 修订：按目标聚合视图 + 去 mihomo 依赖 + 子进程静默

用户验收反馈驱动的大修：

1. **连接记录改按目标聚合**（原逐连接流水被批「变成日志了」）：`HostAgg` 映射（key=host:port 小写）——一行一目标，行内实时速率（前端 1s 累计差分）、连接数、最近活动、状态；点击展开详情（历史累计/本次累计/首见/最近/失败数 + ring 层最近 5 条连接）。持久化由 JSONL 追加改为 **conn-stats.json 快照**（tmp+rename 原子写；脏标记 5s tick / 30s 活跃扫描 / 关前冲盘），顺带解决 JSONL 无限增长；历史累计 = 快照基线，本次累计 = 会话内 live 计数。`conlog_kill_target` 按目标全断。ring 层保留（详情/agent 工具用），回放仅恢复 id 序列。
2. **去 mihomo 依赖**（「内核未运行就失明」修复）：速率 = `proxy_traffic`（anet `ProxyStats` 累计差分，SubTraffic 双源）；活跃连接数同源托底；出口探测 = 内核在→内核出口，不在→anet 本地代理（57890）出口，双无才直连；实时日志 = 内核在→内核日志，不在→**anet 应用日志环**（node `LogBuffer` 复用为桌面 tracing Layer，`app_logs`/`app_logs_clear` 命令）；清空按钮按源路由。侧栏底部速率同步双源。
3. **子进程静默**：GUI 场景 spawn 控制台程序（netif 的 netsh×2/route、dns 的 reg、init、内核孤儿扫描 powershell 等）闪黑窗 + netsh 0xc0000142 报错——`core::util::silent_command`（CREATE_NO_WINDOW）全仓唯一来源并全部替换（fw/svc/doctor-kernel 原本已处理）。启动时两下闪窗 = 内网 IP 探测的两次 netsh，已灭。
4. **配套 UI 修正**：折叠栏图标盒 = 标题栏 34×26（半径 7，中心线 23px 不动）；输入框聚焦去除旧版四边 outline（硬边底缘即聚焦指示，agsel 同步）；扇入页「手动添加扇入」折叠卡 → 快捷条「手动连接」弹窗（「导入并连接」更名「导入链接」）。

偏差：聚合行的命中层/出口/来源取该目标**最后一次连接**的值；连接详情不再含内核链拓扑（数据源不在内核）。
