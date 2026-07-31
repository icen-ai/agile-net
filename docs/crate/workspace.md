# Cargo Workspace 结构（与实现一致）

```
agile-net/
├── Cargo.toml              # workspace root（4 crates + 共享依赖）
├── crates/
│   ├── core/               # agile-net-core — 核心网络库
│   │   └── src/
│   │       ├── lib.rs      # init_crypto_provider()
│   │       ├── proto/      # 帧编解码(frame) + 控制消息(message)
│   │       ├── relay/      # 穿透隧道
│   │       │   ├── listener.rs   # 上游角色：TLS+认证+限流+ACL+通告路由+事件
│   │       │   ├── connector.rs  # 下游角色：重连/心跳抖动/链式转发
│   │       │   ├── mux.rs        # 多路复用会话（背压/分片/上限/shutdown）
│   │       │   └── bridge.rs     # 双向数据桥接
│   │       ├── proxy/      # 本地代理
│   │       │   ├── inbound.rs    # SOCKS5/HTTP 入站（认证/超时/上限/统计/自连环防护）
│   │       │   ├── router.rs     # CIDR/HOST 路由表（最长前缀/后缀/匹配判定）
│   │       │   └── outbound.rs   # 出站（DIRECT / Tunnel）
│   │       ├── tunnel/     # TLS 隧道
│   │       │   ├── tls.rs        # TLS 配置（pinning/CA/自签持久化/指纹）
│   │       │   ├── client_tunnel.rs # 客户端数据面隧道（重连/心跳）
│   │       │   ├── opener.rs     # ChannelOpener 抽象（Listener/PeerAuto/ClientTunnel）
│   │       │   └── pool.rs       # 通道获取（不缓存通道，防错目标）
│   │       ├── config/     # 配置模型（node/client）
│   │       └── error.rs    # 统一错误类型
│   │
│   ├── node/               # agile-net-node — 节点二进制
│   │   └── src/
│   │       ├── main.rs     # 启动编排（env 种子/证书/数据面/API）
│   │       ├── db/         # rusqlite 版本化迁移 + CRUD + argon2id/令牌
│   │       ├── auth/jwt.rs # access+refresh 签发/轮换/吊销
│   │       ├── api/        # axum：统一信封/限流/角色提取器/ handlers
│   │       ├── relay_auth.rs # 数据面 Token 校验器（DB 桥接）
│   │       ├── logs.rs     # 内存日志环缓冲（tracing Layer）
│   │       ├── ui/mod.rs   # 内嵌 Web 管理后台（单文件 SPA）
│   │       └── tui/mod.rs  # ratatui 终端控制台
│   │
│   ├── client/             # agile-net-client — 客户端引擎 + daemon
│   │   └── src/
│   │       ├── lib.rs      # AgileNetClient 引擎（连接/合并路由/心跳/长轮询/hosts）
│   │       └── main.rs     # daemon（agile-net-client.toml）
│   │
│   └── cli/                # anet — 命令行工具
│       └── src/lib.rs      # 全命令树/会话持久化/ID 前缀解析/表格输出
│
├── apps/
│   └── desktop/            # Tauri 2 桌面/Android 客户端（独立 workspace）
│       ├── src/            # IPC commands（复用 agile-net-client 引擎）
│       └── ui/             # 原生 HTML/JS 前端（无 Node 构建链）
│
├── .docker/                # 部署测试
│   ├── Dockerfile          # 多阶段构建（node+client 双二进制）
│   ├── docker-compose.test.yaml # 四层嵌套网络四级节点链
│   ├── configs/            # 各节点 TOML
│   └── tests/              # 链路断言脚本（T1-T6）
│
├── docs/                   # 全部设计文档（与实现对齐）
└── tests/                  # （预留）跨 crate 端到端测试
```
