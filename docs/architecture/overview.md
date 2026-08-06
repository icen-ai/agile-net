# AgileNet 架构总览

## 定位

私有化部署的内网穿透与代理链路由系统。用户自建公网会合点 + 内网端点，通过 TLS 1.3
加密隧道安全穿透内网；消费者持委托令牌接入，按 CIDR/HOST 规则精确路由流量。

## 核心原则

1. **节点无固定角色** — 同一程序既可扇入（接受对端连入）也可扇出（主动连出），角色由配置决定
2. **单二进制** — 所有功能编译进一个 Rust 二进制（relay / proxy / tunnel / api），无子进程
3. **令牌即身份** — 数据面无账号层：节点间扇入与消费者接入统一为 relay PSK / 委托令牌，
  每个节点独立管理自己的令牌、权限组、规则
4. **全程 TLS 1.3** — 节点间通信、消费者到节点、全部走 TLS，流量特征等同 HTTPS
5. **精确路由** — 客户端只代理命中规则的流量（IP-CIDR / HOST），其余走 DIRECT

## 两种部署形态

| 产物 | 说明 | 技术 |
|------|------|------|
| `anet-svc` / `anet` | 服务器二进制（双入口同实现），跑在公网机/内网端点 | Rust binary + 内嵌管理端/客户端 SPA |
| `anet-gui` | 全功能图形客户端（Windows / macOS / Android） | Tauri 2 + 原生 HTML/JS + agile-net-core |

`anet-svc` 单端口统一 Web：`/` 管理端 SPA、`/client` 客户端 SPA、`/api/v1/client/*`
走 AdminAuth 共享登录；`[client]` 配置段可在进程内嵌客户端角色。

共享底层核心库：

```
agile-net-core (Rust lib crate)
├── relay   — TCP + TLS 穿透（listener/connector、委托注册表、E2E、对端收敛）
├── proxy   — SOCKS5/HTTP 入站 + CIDR 路由（替代 mihomo）
├── tunnel  — 客户端隧道（替代 gost）
├── proto   — 控制协议、帧编码、握手（协议 v4 唯一行为）
├── link    — anet:// 统一链接底座（connect/fanout 双角色）
└── config  — 统一配置模型
```

## 全局数据流

```
用户机 (Client / anet-gui)
│  本地 SOCKS5/HTTP 127.0.0.1:57890
│  路由表：IP-CIDR 10.12.0.0/16 → Node-B
│          HOST  git.internal  → Node-B
│          *                   → DIRECT
▼
公网机 Node-A (relay listener)
│  TLS 1.3 on :54430
│  认证：delegated token（psk_，委托注册表会话级注册）
│  转发到 Node-B 的控制隧道（E2E 令牌盲转不透明路由词）
▼
内网机 Node-B (relay connector → Node-A)
│  DelegationHooks 终点解包 E2E 信封
│  路由：10.12.0.0/16 → DIRECT（走 B 本机网卡）
▼
内网目标 10.12.186.133:8080
```

## 进程内架构

### anet-svc 进程

```
anet-svc
├── API Server (axum，单端口统一 Web)
│   ├── /api/v1/admin/*   — 管理面（AdminAuth JWT）
│   ├── /api/v1/client/*  — 客户端 SPA 管理面（同 AdminAuth 共享登录）
│   ├── /                 — 管理端 SPA
│   └── /client           — 客户端 SPA
├── Relay Module
│   ├── Listener  — 扇入：接受对端节点与消费者连入（委托注册表 + 并发执法）
│   └── Connector — 扇出：主动连出（入库一等资源，多目标扇出/容灾）
├── Proxy Module
│   ├── Inbound   — SOCKS5/HTTP 本地监听
│   └── Router    — CIDR/HOST trie 路由表
├── Delegation    — 统一签发引擎（issue_token / DelegationEngine 数据面执法）
├── Auth Module   — Admin JWT 签发/验证（argon2id 口令）
├── Database (SQLite) — 单文件 agile-net.db，基线 v1
└── [client] 段（可选）— 进程内嵌客户端角色（anet:// 链接式 nodes）
```

### anet-gui 进程

```
anet-gui (Tauri 2)
├── Tauri Core
│   ├── Commands (IPC，cmd/ 按域)
│   └── System Tray + 悬浮球
├── Core Runtime (tokio)
│   ├── Proxy Inbound (127.0.0.1:57890)
│   ├── Router (多节点合并路由表)
│   ├── Delegated Tunnels (anet:// 委托链接，容灾集合故障切换)
│   └── Hosts Manager (写系统 hosts)
├── 三路独立开关 — 客户端角色 / 服务端角色（内嵌 anet-svc）/ Web 远程面
└── 原生 HTML/JS UI（无构建链）
    ├── 连接 / 节点 / 路由 / 日志 / 设置
    └── 扇出管理（监听 | 连接 | 签发 三页签）
```

## 安全模型

```
传输安全：
  Client ←→ Node : TLS 1.3 (rustls)
  Node   ←→ Node : TLS 1.3 (rustls)

认证安全：
  Admin  → Node : username + password (argon2id) → JWT
  Client → Node : delegated token (psk_，SHA-256 落库)
  Node   → Node : relay token (psk_，pre-shared)

隧道特征：
  ALPN 恒 h2,http/1.1 + 自签拟态证书
  心跳指数分布、重连 full jitter、分片长度扰动
  无自定义魔数，DPI 不可区分于普通 HTTPS
```

## 技术选型

| 层 | 选型 | 理由 |
|----|------|------|
| 异步运行时 | tokio | Rust 事实标准 |
| TLS | rustls (ring) | 纯 Rust，无 OpenSSL 依赖 |
| HTTP 框架 | axum | tokio 生态，性能好 |
| 数据库 | SQLite (r2d2_sqlite) | 零运维，单文件，嵌入式 |
| 序列化 | serde + serde_json | 标准 |
| SOCKS5/HTTP 入站 | 自实现 | 认证 + 连接记录钩子 |
| CIDR 路由 | ip_network_table | trie 实现，O(prefix_len) |
| JWT | jsonwebtoken | 成熟 |
| 口令哈希 | argon2id | 抗 GPU/ASIC，OWASP 推荐 |
| 桌面 UI | Tauri 2.x + 原生 HTML/JS | 轻量，WebView2，无构建链 |
| 构建 | cargo workspace | 多 crate 管理 |
