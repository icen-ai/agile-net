# agile-net-client 客户端（与实现一致）

## 职责

用户端引擎与守护进程。连接一个或多个 Node，拉取路由配置，建立数据面隧道，启动本地代理，按规则路由流量。

## 形态

| 形态 | 说明 |
|------|------|
| `agile-net-client`（daemon） | 读取 `agile-net-client.toml`，无界面常驻运行 |
| `apps/desktop`（Tauri 2） | Windows / Android GUI，IPC 复用同一引擎 |
| `agile-net-client`（lib crate） | 供 GUI/测试嵌入的 Rust API |

## 引擎结构（crates/client）

```
AgileNetClient (Arc<ClientInner>)
├── nodes: DashMap<node_id, NodeHandle>
│   └── NodeHandle { state, tunnel: Arc<ClientTunnel>, tasks[3], manage_hosts }
│       ├── task1: ClientTunnel::run()      — 数据面自动重连
│       ├── task2: heartbeat 60s            — 真实流量增量 + force_disconnect
│       └── task3: config watcher           — 长轮询热更新 + token 刷新
├── shared_router: ArcSwap<ProxyRouter>     — 多节点合并路由（RCU）
├── openers: DashMap<node_id, ChannelOpener>— 与 ProxyInbound 共用注册表
├── ProxyInbound (127.0.0.1:port)           — SOCKS5/HTTP（可选认证）
└── HostsManager                            — BEGIN/END AGILE-NET 标记块
```

## 连接流程

```
connect(params)
├── 1. POST /api/v1/auth/login → access + refresh + tunnel_token
├── 2. GET /api/v1/client/config → version/node_name/rules/tunnel{server,port}
├── 3. ClientTunnel::connect(tunnel.server:port, tunnel_token)
│      TLS 信任策略：pinned_cert_path > insecure > 系统根
├── 4. openers.insert(node_id, tunnel)；合并规则进 shared_router
├── 5. 后台三任务（重连 / 心跳 / 长轮询）
└── 6. resolve 规则 → HostsManager.apply（manage_hosts=true 时）
```

## Tauri Commands（apps/desktop/src/lib.rs）

| Command | 说明 |
|---------|------|
| `connect_node(input)` | 连接节点（可选保存凭据） |
| `disconnect_node(node_id)` | 断开并清除凭据 |
| `list_nodes()` | 节点列表（实时状态） |
| `list_credentials()` | 已保存凭据 |
| `start_proxy(port)` / `stop_proxy()` / `proxy_status()` | 本地代理控制 |
| `parse_connect_url(url)` | 解析 `anet://connect?...` 接入链接（兼容旧 `agilenet://`） |

## 凭据存储

`~/.agile-net/credentials.json`（Unix 0600）。内容为 addr/username/password/insecure，
由管理员下发的 sk- 强密码——本机文件权限是防线，与系统 keychain 同级风险的简化方案。

## 心跳与流量统计

- 间隔 60s；`bytes_tx/rx` 为**自上次上报以来的增量**（来源：ProxyInbound 全局计数）
- 服务端按小时聚合到 `traffic_log`（stats API / 控制台图表数据源）
- 响应 `force_disconnect: true`（账号被禁用/删除）时客户端主动断开该节点

## 离线缓存与断网降级

- 每次成功拉取配置后写入 `~/.agile-net/cache/<节点>.json`（0600）：规则、版本、隧道端点、tunnel_token、refresh_token
- 节点网络不可达时自动降级：**沿用缓存规则组网**（状态 Reconnecting），隧道自动重连，
  后台每 30s(+抖动) 重试登录；恢复后无缝升级为完整连接并刷新缓存
- token 刷新时同步轮换缓存与隧道的 tunnel_token（修复刷新后重连失同步）

## hosts 管理

`manage_hosts=true` 的节点，其 `resolve=true` 的 host 规则写入系统 hosts
（`127.0.0.1 <host>`，BEGIN/END AGILE-NET 标记块内），断开/退出时清理。
修改 hosts 需要管理员/root 权限，失败仅告警不中断。
