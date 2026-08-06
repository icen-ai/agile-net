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

（待实施批次填写）
