# agile-net-node 节点服务（与实现一致）

## 职责

AgileNet 的服务端 binary。每个 Node 同时具备：
- **Listener 角色**：接受下游 Node / Client 连入（relay listener，TLS 1.3）
- **Connector 角色**：主动连接上游 Node（relay connector，自动重连）
- **API Server**：HTTP API + 内嵌 Web Admin UI（axum，SPA 单文件）
- **Proxy（可选）**：本地 SOCKS5/HTTP 入站，供节点本机应用使用

## 启动流程

```
main()
├── 0. init_crypto_provider()（rustls ring，必须最先）
├── 1. 加载 agile-net.toml（缺失则用默认值）
├── 2. 初始化 SQLite（版本化迁移）+ 清理过期 refresh token
├── 3. env 种子：AGILE_ADMIN_PASSWORD（admin）、AGILE_RELAY_TOKENS（下游令牌）
├── 4. JwtService::load_or_create（密钥持久化于 node_config.jwt_secret）
├── 5. RelayListener（证书加载或生成自签并持久化到 certs/，输出 SHA-256 指纹）
├── 6. RelayConnector（advertise 通告 + TLS 策略：pinning > CA > insecure）
├── 7. ProxyInbound（可选，默认仅 loopback，支持认证）
├── 8. axum HTTP Server（API + Web UI，ConnectInfo 提供审计来源 IP）
└── 9. Ctrl-C → connector.disconnect() 优雅关闭
```

## 模块结构

```
crates/node/src/
├── main.rs          # 启动编排（无业务逻辑）
├── db/              # rusqlite：MIGRATIONS 版本化迁移 + 全部 CRUD + argon2id/令牌生成
├── auth/jwt.rs      # JwtService：access+refresh 签发/验证/轮换/吊销
├── api/             # 路由、ApiState、NodeRuntime、统一信封、登录限流
│   ├── extractors.rs# AdminAuth / ClientAuth / AnyAuth / ClientIp
│   └── handlers/    # auth rules groups accounts relay_tokens node client audit
├── relay_auth.rs    # DbTokenValidator：relay_token / tunnel_token 哈希校验 → AuthIdentity(含 ACL)
├── logs.rs          # 内存日志环形缓冲（tracing Layer）
├── ui/mod.rs        # 内嵌 Web 管理后台（单文件 SPA，含安全响应头）
└── tui/mod.rs       # ratatui 终端控制台（六页签 + 行操作）
```

## 关键数据结构

```rust
pub struct ApiState {
    db: Database,
    jwt: Arc<JwtService>,
    runtime: Arc<NodeRuntime>,      // 数据面句柄（listener/connector/proxy 状态）
    login_limiter: LoginRateLimiter,// 5 次/分钟 + 连续失败 5 次锁 15 分钟
    connect_url_cache: …,           // 创建/重置后 10 分钟内可取二维码
    public_host / api_port / relay_port,
}

pub struct NodeRuntime {
    started_at: Instant,
    listener: Option<Arc<RelayListener>>,
    connectors: Vec<Arc<RelayConnector>>,  // 扇出连接（多目标扇出/容灾）
    proxy_stats: Option<Arc<ProxyStats>>,
    proxy_listen: Option<String>,
    log_buffer: LogBuffer,
}
```

## 热更新机制

- **配置版本号**：规则/权限组/账号组变更时 `config_version` 递增（node_config）
- **客户端长轮询**：`GET /client/config?wait=true&version=N` 挂起至版本变化或 30s 超时 304
- **节点本地代理**：进程启动时从全部规则构建路由表（命中 → PeerAutoOpener 自动选下游）

## 数据面认证与 ACL

```
AuthFrame { kind: "node"|"client", token, advertise, version }
  ├── kind=node   → relay_token 表 SHA-256 比对 → AuthIdentity::Node{advertise}
  └── kind=client → account.tunnel_token_hash 比对 → AuthIdentity::Client{acl=组规则}
```

- Listener 为 client 会话处理 Open：ACL 校验 → 命中通告路由则链式向下游 Open，否则本机直连
- 在线状态（账号 online）来自 Listener 的内存会话表，不落库；`last_seen_at` 由认证/心跳更新
