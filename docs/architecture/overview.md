# AgileNet 架构总览

## 定位

私有化部署的内网访问管理平台。用户自建公网中继节点 + 内网跳板节点，通过 TLS 1.3 加密隧道安全穿透内网，客户端按 CIDR/HOST 规则精确路由流量。

## 核心原则

1. **节点无固定角色** — 同一程序既可作为上游（接受下游连入）也可作为下游（连接上游），角色由配置决定
2. **单二进制** — 所有功能编译进一个 Rust 二进制（relay / proxy / tunnel / api），无子进程
3. **账号分布式** — 每个节点独立管理自己的账号、权限组、规则，节点之间不通信
4. **全程 TLS 1.3** — 节点间通信、客户端到节点、全部走 TLS，流量特征等同 HTTPS
5. **精确路由** — 客户端只代理命中规则的流量（IP-CIDR / HOST），其余走 DIRECT

## 两种部署形态

| 产物 | 说明 | 技术 |
|------|------|------|
| `agile-net-node` | 节点程序，跑在公网机/内网跳板机 | Rust binary + 内嵌 Web Admin UI |
| `agile-net-client` | 客户端程序，跑在用户桌面 | Tauri + React + agile-net-core |

共享底层核心库：

```
agile-net-core (Rust lib crate)
├── relay   — TCP + TLS 穿透（替代 frp）
├── proxy   — SOCKS5/HTTP 入站 + CIDR 路由（替代 mihomo）
├── tunnel  — 出站 SOCKS5-over-TLS 连接（替代 gost）
├── proto   — 控制协议、帧编码、握手
└── config  — 统一配置模型
```

## 全局数据流

```
用户机 (Client)
│  本地 SOCKS5/HTTP 127.0.0.1:7890
│  路由表：IP-CIDR 10.12.0.0/16 → Node-B
│          HOST  git.internal  → Node-B
│          *                   → DIRECT
▼
公网机 Node-A (relay listener)
│  TLS 1.3 on :443
│  认证：client token
│  转发到 Node-B 的控制隧道
▼
内网机 Node-B (relay connector → Node-A)
│  proxy 模块收到请求
│  路由：10.12.0.0/16 → DIRECT（走 B 本机网卡）
▼
内网目标 10.12.186.133:8080
```

## 进程内架构

### Node 进程

```
agile-net-node
├── API Server (axum)
│   ├── /api/v1/admin/*   — 管理面（需 admin 认证）
│   └── /api/v1/client/*  — 客户端面（需 client 认证）
├── Relay Module
│   ├── Listener  — 接受下游连入 + 客户端连入
│   └── Connector — 主动连接上游节点
├── Proxy Module
│   ├── Inbound   — SOCKS5/HTTP 本地监听
│   └── Router    — CIDR/HOST trie 路由表
├── Tunnel Module
│   └── Outbound  — SOCKS5-over-TLS 出站
├── Auth Module
│   ├── JWT 签发/验证
│   └── 账号/密码/权限组 管理
├── Database (SQLite via rusqlite)
│   └── 单文件 agile-net.db
└── Web Admin UI (内嵌静态文件)
```

### Client 进程

```
agile-net-client (Tauri)
├── Tauri Core
│   ├── Commands (IPC)
│   └── System Tray
├── Core Runtime (tokio)
│   ├── Proxy Inbound (127.0.0.1:7890)
│   ├── Router (多节点合并路由表)
│   ├── Tunnel Pool (N 条到不同节点的 TLS 连接)
│   └── Hosts Manager (写 /etc/hosts 或 Windows hosts)
├── Config Store
│   ├── 节点连接信息（公网IP、端口、token）
│   └── 缓存的路由规则（离线可用）
└── React UI
    ├── 连接管理（添加/删除节点）
    ├── 状态面板（连接状态、流量统计）
    └── 日志查看
```

## 安全模型

```
传输安全：
  Client ←→ Node : TLS 1.3 (rustls)
  Node   ←→ Node : TLS 1.3 (rustls)

认证安全：
  Admin  → Node : username + password → JWT
  Client → Node : account_id + password → JWT
  Node   → Node : pre-shared token (relay auth)

隧道特征：
  端口 443 + 标准 TLS 1.3 握手
  心跳间隔随机化（30s ± 5s）
  无自定义魔数，DPI 不可区分于普通 HTTPS
```

## 技术选型

| 层 | 选型 | 理由 |
|----|------|------|
| 异步运行时 | tokio | Rust 事实标准 |
| TLS | rustls | 纯 Rust，无 OpenSSL 依赖 |
| HTTP 框架 | axum | tokio 生态，性能好 |
| 数据库 | SQLite (rusqlite) | 零运维，单文件，嵌入式 |
| 序列化 | serde + serde_json | 标准 |
| SOCKS5 | fast-socks5 | 入站+出站 |
| CIDR 路由 | ip_network_table | trie 实现，O(prefix_len) |
| JWT | jsonwebtoken | 成熟 |
| 桌面 UI | Tauri 2.x + React | 轻量，WebView2 |
| 构建 | cargo workspace | 多 crate 管理 |
