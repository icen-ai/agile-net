# Cargo Workspace 结构（与实现一致）

```
agile-net/
├── Cargo.toml              # workspace root（3 crates + 共享依赖）
├── crates/
│   ├── core/               # agile-net-core — 核心网络库
│   │   └── src/
│   │       ├── lib.rs      # init_crypto_provider()
│   │       ├── proto/      # 帧编解码(frame) + 控制消息(message)（协议 v4）
│   │       ├── relay/      # 穿透隧道
│   │       │   ├── listener.rs   # 扇入：TLS+认证+限流+ACL+委托注册表+并发执法+事件
│   │       │   ├── connector.rs  # 扇出：重连/心跳抖动/链式转发/DelegationHooks 三角色
│   │       │   ├── mux.rs        # 多路复用会话（背压/分片/上限/Ctrl channel 0）
│   │       │   ├── e2e.rs        # 联邦 E2E（HKDF 密钥层次/ChannelCipher/E2eStream）
│   │       │   ├── limit.rs      # 会话带宽限速（TokenBucket）
│   │       │   └── bridge.rs     # 双向数据桥接
│   │       ├── proxy/      # 本地代理
│   │       │   ├── inbound.rs    # SOCKS5/HTTP 入站（认证/超时/上限/统计/decide_inbound）
│   │       │   ├── router.rs     # CIDR/HOST 路由表（最长前缀/后缀/匹配判定）
│   │       │   ├── conlog.rs     # 连接记录（ConnLog 全收录，默认关闭）
│   │       │   └── outbound.rs   # 出站（DIRECT / Tunnel）
│   │       ├── tunnel/     # TLS 隧道
│   │       │   ├── tls.rs        # TLS 配置（指纹钉值/CA/自签持久化）
│   │       │   ├── client_tunnel.rs # 消费者数据面隧道（重连/心跳/open_channel_raw）
│   │       │   └── opener.rs     # ChannelOpener 抽象（BoxedChannel/PeerAuto/ClientTunnel）
│   │       ├── link.rs     # anet:// 统一链接底座（connect/fanout 双角色解析+生成）
│   │       ├── util.rs     # sha256_hex / base64 / LoginRateLimiter（全仓唯一来源）
│   │       ├── config/     # 配置模型（node）
│   │       └── error.rs    # 统一错误类型
│   │
│   ├── node/               # agile-net-node — anet-svc / anet 双入口
│   │   └── src/
│   │       ├── main.rs / app.rs # 启动编排与 CLI 分发
│   │       ├── service/    # NodeServer 装配根 + connectors + delegation + acl
│   │       ├── db/         # r2d2_sqlite 连接池：基线 v1 + CRUD（按域 8 文件）
│   │       ├── auth/jwt.rs # access+refresh 签发/轮换/吊销
│   │       ├── api/        # axum：统一信封/限流/AdminAuth/handlers
│   │       ├── relay_auth.rs # 数据面 Token 校验器（DB 桥接）
│   │       ├── ui/         # 内嵌管理端 SPA（index/app/style + mod.rs 内嵌）
│   │       ├── cli/        # 管理 CLI（按域 10 文件）
│   │       ├── tui/        # ratatui 终端控制台
│   │       ├── svc.rs / init.rs / qr.rs / logs.rs
│   │       └── tool/       # anet tool 诊断 + doctor/ 自我诊断（按域 10 文件）
│   │
│   └── client/             # agile-net-client — 客户端引擎（委托-only lib crate）
│       └── src/
│           ├── lib.rs      # 模块声明与再导出（pub API 路径不变）
│           ├── client.rs   # AgileNetClient 引擎（connect 唯一入口/监督循环容灾）
│           ├── credential.rs # 凭据存储（OS keyring 优先，0600 文件回退）
│           ├── config_cache.rs / connect_url.rs / custom_rules.rs / hosts.rs
│           ├── api.rs      # 管理面 Web API（/api/v1/client/*，AdminAuth）
│           └── daemon.rs   # anet-svc client（nodes = ["anet://..."] 链接式）
│
├── apps/
│   └── desktop/            # anet-gui（Tauri 2 桌面/Android，独立 workspace）
│       ├── src/            # cmd/ 命令按域 + kernel/ mihomo sidecar + lib.rs 装配根
│       └── ui/             # 原生 HTML/JS 前端（无 Node 构建链）
│
├── .docker/                # 四级节点链编排测试与常驻演示
│   ├── Dockerfile          # 多阶段构建
│   ├── docker-compose.test.yaml # 四级节点链断言
│   └── docker-compose.chain.yaml # 常驻演示
│
├── docs/                   # 全部设计文档（与实现对齐）
└── tests/                  # （预留）跨 crate 端到端测试
```
