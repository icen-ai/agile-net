# Cargo Workspace 结构

```
agile-net/
├── Cargo.toml              # workspace root
├── crates/
│   ├── core/               # agile-net-core — 核心库
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── relay/      # 穿透隧道
│   │       │   ├── mod.rs
│   │       │   ├── listener.rs   # 上游角色：接受连入
│   │       │   ├── connector.rs  # 下游角色：主动连接
│   │       │   ├── frame.rs      # 帧编解码
│   │       │   └── bridge.rs     # 双向数据桥接
│   │       ├── proxy/      # 本地代理
│   │       │   ├── mod.rs
│   │       │   ├── inbound.rs    # SOCKS5/HTTP 入站监听
│   │       │   ├── router.rs     # CIDR/HOST 路由表
│   │       │   └── outbound.rs   # 出站（DIRECT / Tunnel）
│   │       ├── tunnel/     # TLS 隧道连接
│   │       │   ├── mod.rs
│   │       │   ├── pool.rs       # 连接池管理
│   │       │   └── tls.rs        # TLS 配置
│   │       ├── proto/      # 共享协议定义
│   │       │   ├── mod.rs
│   │       │   ├── auth.rs       # 认证帧
│   │       │   └── message.rs    # 控制消息
│   │       ├── config/     # 配置模型
│   │       │   ├── mod.rs
│   │       │   ├── node.rs       # 节点配置
│   │       │   └── client.rs     # 客户端配置
│   │       └── error.rs    # 统一错误类型
│   │
│   ├── node/               # agile-net-node — 节点二进制
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── api/        # axum HTTP API
│   │       │   ├── mod.rs
│   │       │   ├── auth.rs
│   │       │   ├── rules.rs
│   │       │   ├── groups.rs
│   │       │   ├── accounts.rs
│   │       │   ├── config.rs     # 客户端拉配置
│   │       │   ├── node.rs       # 节点状态
│   │       │   └── middleware.rs # JWT 验证中间件
│   │       ├── db/         # 数据库层
│   │       │   ├── mod.rs
│   │       │   ├── migration.rs  # 迁移
│   │       │   ├── repo.rs       # 通用 CRUD trait
│   │       │   ├── account.rs
│   │       │   ├── group.rs
│   │       │   ├── rule.rs
│   │       │   └── audit.rs
│   │       ├── service/    # 业务逻辑层
│   │       │   ├── mod.rs
│   │       │   ├── auth.rs
│   │       │   ├── account.rs
│   │       │   ├── group.rs
│   │       │   ├── rule.rs
│   │       │   └── relay.rs
│   │       ├── state.rs    # 全局状态（AppState）
│   │       └── web/        # 内嵌 Admin UI 静态文件
│   │
│   └── client/             # agile-net-client — Tauri 客户端
│       ├── Cargo.toml      # Tauri Rust 端
│       ├── src/
│       │   ├── main.rs
│       │   ├── commands/   # Tauri IPC commands
│       │   │   ├── mod.rs
│       │   │   ├── connection.rs # 节点连接管理
│       │   │   ├── status.rs     # 状态查询
│       │   │   └── hosts.rs      # hosts 文件操作
│       │   ├── runtime/    # 后台运行时
│       │   │   ├── mod.rs
│       │   │   ├── manager.rs    # 多节点连接管理
│       │   │   └── merger.rs     # 路由表合并
│       │   ├── store.rs    # 配置持久化
│       │   └── tray.rs     # 系统托盘
│       └── ui/             # React 前端
│           ├── package.json
│           ├── src/
│           │   ├── App.tsx
│           │   ├── pages/
│           │   │   ├── Connect.tsx
│           │   │   ├── Status.tsx
│           │   │   └── Settings.tsx
│           │   └── components/
│           └── index.html
│
├── docs/                   # 设计文档
├── tests/                  # 集成测试
│   ├── relay_test.rs
│   ├── proxy_test.rs
│   └── e2e_test.rs
└── .github/
    └── workflows/
        └── ci.yml
```

## Workspace Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "crates/core",
    "crates/node",
    "crates/client",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
repository = "https://github.com/user/agile-net"

[workspace.dependencies]
# 异步
tokio = { version = "1", features = ["full"] }
# 网络
fast-socks5 = "0.9"
rustls = "0.23"
tokio-rustls = "0.26"
# 路由
ip_network = "0.4"
ip_network_table = "0.2"
# HTTP
axum = { version = "0.8", features = ["ws"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["cors", "fs"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
# 数据库
rusqlite = { version = "0.32", features = ["bundled"] }
# 序列化
serde = { version = "1", features = ["derive"] }
serde_json = "1"
# 认证
jsonwebtoken = "9"
argon2 = "0.5"
# 工具
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
thiserror = "2"
anyhow = "1"
rand = "0.8"
```

## 依赖关系

```
agile-net-core ← 无外部 crate 依赖（仅 workspace deps）
     ↑
     ├── agile-net-node  (core + axum + rusqlite)
     └── agile-net-client (core + tauri)
```

core 不依赖 node 或 client，保持纯净。
