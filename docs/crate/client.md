# agile-net-client 客户端（与实现一致）

## 职责

用户端引擎（lib crate）。**委托-only**：无账号、无 API 往返——持签发端统一签发的委托
链接（`anet://connect?...`）直连 relay 数据面，令牌即唯一身份（纯数据面密钥，兼作
E2E 密钥材料）。建立数据面隧道，启动本地代理，按词表路由流量。

## 形态

| 形态 | 说明 |
|------|------|
| `anet-svc client`（daemon） | 读取 `agile-net-client.toml`（`nodes = ["anet://..."]` 链接式），无界面常驻运行 |
| `anet-svc` `[client]` 段 | 进程内嵌客户端角色，与节点角色共存 |
| `apps/desktop`（Tauri 2） | Windows / macOS / Android GUI，IPC 复用同一引擎 |
| `agile-net-client`（lib crate） | 供 GUI/测试嵌入的 Rust API |

## 引擎结构（crates/client）

`lib.rs` 只做模块声明与再导出，实现按域拆分：`client` / `credential` / `config_cache` /
`connect_url` / `custom_rules` / `hosts` / `api`（管理面 Web API）/ `daemon`。

```
AgileNetClient (Arc<ClientInner>)
├── nodes: DashMap<node_id, NodeHandle>
│   └── NodeHandle { state, opener, tasks }
│       ├── 主入口同步首连（fail fast）
│       └── 监督循环：容灾切换（断开按 entry 序换入、逐入口指纹钉值、
│           指数回退 full jitter、流量跨隧道累计）
├── shared_router: ArcSwap<ProxyRouter>     — 多节点合并路由（RCU）
├── openers: DashMap<node_id, ChannelOpener>— DelegatedOpener（E2E 包装对消费方透明）
├── ProxyInbound (127.0.0.1:port)           — SOCKS5/HTTP（可选认证）
└── HostsManager                            — BEGIN/END AGILE-NET 标记块
```

## 连接流程（`AgileNetClient::connect()` 唯一入口）

```
connect(ConnectParams)
├── 1. 解析 anet://connect 链接 → Credential{addr,label,token,name?,insecure,
│      pinned_fingerprint?,entries,entry_fps,en?,emode?,eadmin,pad}
├── 2. ClientTunnel 直连主入口（TLS 信任策略：pinned_fingerprint > insecure）
│      AuthFrame { kind: "client", token: psk_... }（委托令牌，无登录/无配置拉取）
├── 3. DelegatedOpener：en 存在时全 Open E2E 包装（entrust 路由词寻址）
│      委托节点注册全量路由 0.0.0.0/0 + 通配域名（dedicated 专线默认）
├── 4. emode=split：经 E2E 配置通道（__anet_delegation_config__）拉取词表
│      改选择性路由，失败回退专线行为
├── 5. eadmin=1：经同一配置通道取管理引导票据
│      （delegated_console_ticket / delegated_upstream_ticket）
└── 6. resolve 规则 → HostsManager.apply（manage_hosts=true 时）
```

## 凭据存储

`~/.anet/credentials.json`（Unix 0600）。`Credential` 字段：`addr / label / token /
name? / insecure / pinned_fingerprint? / entries / entry_fps / en? / emode? / eadmin / padding`。
桌面平台令牌优先存 OS keyring（Windows 凭据管理器 / macOS 钥匙串），文件只留元数据；
keyring 不可用回退 0600 文件。

`NodeState.label` 为节点显示名（用户自命名优先，缺省取链接 `d:` 标签）。

## 离线缓存与断网降级

- 分流词表离线缓存：节点不可达时沿用缓存词表组网（状态 Reconnecting），监督循环按
  容灾集合换入口重连；恢复后重拉词表刷新
- 专线档无词表依赖，断线即按容灾集合故障切换

## hosts 管理

`manage_hosts=true` 的节点，其 `resolve=true` 的 host 规则写入系统 hosts
（`127.0.0.1 <host>`，BEGIN/END AGILE-NET 标记块内），断开/退出时清理。
修改 hosts 需要管理员/root 权限，失败仅告警不中断。
