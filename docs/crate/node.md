# agile-net-node 节点服务（与实现一致）

## 职责

AgileNet 的服务端 binary（**`anet-svc` / `anet` 同一实现双入口，按 argv[0] 分人格**）。
每个 Node 同时具备：

- **Listener 角色**：扇入——接受对端 Node 与消费者（委托令牌）连入（TLS 1.3）
- **Connector 角色**：扇出——主动连出对端（入库一等资源，多目标扇出/容灾，自动重连）
- **统一签发**：delegated_token 签发/吊销 + DelegationEngine 数据面执法
- **API Server**：单端口统一 Web（`/` 管理端 SPA、`/client` 客户端 SPA、
  `/api/v1/client/*` 走 AdminAuth 共享登录）
- **客户端角色（可选）**：`[client]` 配置段进程内嵌客户端引擎（anet:// 链接式 nodes）
- **Proxy（可选）**：本地 SOCKS5/HTTP 入站，供节点本机应用使用

子命令：`start`（默认）/ `stop` / `restart` / `status` / `init` / `client` / `tui` /
`doctor` + 管理命令 `login` / `node` / `rule` / `group` / `token` / `connector` /
`admin` / `audit`。

## 启动流程

```
main()
├── 0. init_crypto_provider()（rustls ring，必须最先）
├── 1. 加载 agile-net.toml（缺失则用默认值）
├── 2. 初始化 SQLite（基线 v1）+ 清理过期 refresh token
├── 3. env 种子：AGILE_ADMIN_PASSWORD（admin）、AGILE_RELAY_TOKENS（扇入令牌）
├── 4. JwtService::load_or_create（密钥持久化于 node_config.jwt_secret）
├── 5. RelayListener（证书加载或生成自签并持久化到 certs/，输出 SHA-256 指纹）
├── 6. ConnectorManager（DB 为唯一事实来源；advertise 有效集 = 手工 ∪ 上送组规则；
│      TLS 策略：pinned_fingerprint > pinned_cert_path > ca > insecure）
├── 7. ProxyInbound（可选，默认仅 loopback，支持认证）
├── 8. [client] 段 → 进程内嵌客户端引擎（可选）
├── 9. axum HTTP Server（统一 Web，ConnectInfo 提供审计来源 IP）
└── 10. Ctrl-C / stop → RelayListener::shutdown_all 优雅关闭
```

## 模块结构

```
crates/node/src/
├── main.rs / app.rs  # 启动编排与 CLI 分发（无业务逻辑）
├── service/          # 装配根 NodeServer + connectors（ConnectorManager）
│                     # + delegation（统一签发 + DelegationEngine）+ acl（PeerAclRegistry）
├── db/               # r2d2_sqlite 连接池：基线 v1 schema + 全部 CRUD（按域 8 文件）
├── auth/jwt.rs       # JwtService：access+refresh 签发/验证/轮换/吊销
├── api/              # 路由、ApiState、NodeRuntime、统一信封、登录限流
│   ├── extractors.rs # AdminAuth / ClientIp（阻塞活一律 db_call offload）
│   └── handlers/     # auth rules groups relay_tokens node delegation connectors audit
├── relay_auth.rs     # DbTokenValidator：relay_token / delegated_token 哈希校验 → AuthIdentity
├── logs.rs           # 内存日志环形缓冲（tracing Layer）
├── ui/mod.rs         # 内嵌管理端 SPA（路由与 include_str!，含安全响应头）
├── cli/              # 管理 CLI（按域 10 文件）
├── tui/              # ratatui 终端控制台（API 优先 + DB 只读兜底）
├── svc.rs            # 服务管理（PID 文件）
├── init.rs           # 首装向导
├── qr.rs             # 二维码图片解码（rqrr）
└── tool/             # anet tool 网络诊断 + doctor/ 自我诊断（按域 10 文件）
```

## 关键数据结构

```rust
pub struct ApiState {
    db: Database,
    jwt: Arc<JwtService>,
    runtime: Arc<NodeRuntime>,      // 数据面句柄（listener/connector/proxy 状态）
    login_limiter: LoginRateLimiter,// 5 次/分钟 + 连续失败 5 次锁 15 分钟（core::util 唯一实现）
    public_host / api_port / relay_port,
}

pub struct NodeRuntime {
    started_at: Instant,
    listener: Option<Arc<RelayListener>>,
    connector_manager: Arc<ConnectorManager>,  // 扇出管理（DB 为唯一事实来源，热操作）
    proxy_stats: Option<Arc<ProxyStats>>,
    proxy_listen: Option<String>,
    client_proxy_slot: ClientProxySlot,     // 内嵌客户端角色的代理槽位
    log_buffer: LogBuffer,
    transit_meter: Arc<TransitMeter>,       // 中继途径核算（listener/connector/proxy 三处打点）
}
```

## 热更新机制

- **配置版本号**：规则/权限组变更时 `config_version` 递增（node_config），watcher
  驱动 DelegationEngine 缓存与采纳组漂移写刷新
- **DelegationEngine**：kid→key+组名集 与 组名→规则/e2e标记 双 ArcSwap 缓存，热路径零 DB
- **节点本地代理**：进程启动时从全部规则构建路由表（命中 → PeerAutoOpener 自动选下游）

## 数据面认证与 ACL

```
AuthFrame { kind: "node"|"client", token, advertise, groups, version: 4 }
  ├── kind=node   → relay_token 表 SHA-256 比对 → AuthIdentity::Node{advertise}
  └── kind=client → delegated_token 表 SHA-256 比对 → AuthIdentity::Delegated{组规则并集}
```

- Listener 为消费者会话处理 Open：ACL 校验（e2e_required 组明文 fail-close）→
  E2E 信封签发端解包/中间跳盲转 → 命中通告路由链式向下游 Open，否则本机直连
- 并发执法：single 档同令牌踢旧留新；multi 档并存上限 max_sessions（签发时
  node_config `delegation_max_sessions` 快照，默认 8）
- 消费者在线状态来自 Listener 的内存会话表（WS 事件 `consumer.online/offline`，
  data.session_key），不落库
