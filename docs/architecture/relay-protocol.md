# Relay 协议设计（v1，与实现一致）

节点间穿透通信与客户端数据面的核心协议，替代 frp。
单条 TLS 1.3 连接上多路复用多个逻辑通道。

## 连接模型

```
Connector (下游节点/客户端)              Listener (上游节点)
      │                                       │
      ├── TCP connect ──────────────────────> │
      ├── TLS 1.3 handshake ────────────────> │  ← 全程 10s 超时
      ├── AuthFrame { kind, token, ... } ───> │
      │ <──────────────── AuthOk / AuthFail ──┤  ← 失败随机延迟 150~400ms
      │                                       │
      │   ══ Mux Session Established ══       │
      │                                       │
      │ <──── Open { channel_id, target } ────┤  ← 节点会话：上游发起（奇数 id）
      ├──── OpenOk / OpenFail ──────────────> │
      ├──── Open { channel_id, target } ─────> │  ← 客户端会话：客户端发起（偶数 id）
      │ <──────────────── OpenOk / OpenFail ──┤
      │ <═══════ Data 帧双向转发 ════════════> │
      │                                       │
      ├── Ping ─────────────────────────────> │  ← 25s + 0~10s 随机抖动
      │ <──────────────────────────── Pong ───┤
```

## 帧格式

所有帧在 TLS 内部传输，外部只看到 TLS 密文。

```
┌──────────────┬──────────────┬──────────────┬──────────┐
│ Length (u32) │ Type (u8)    │ Channel (u32)│ Payload  │
│ 4 bytes      │ 1 byte       │ 4 bytes      │ N bytes  │
└──────────────┴──────────────┴──────────────┴──────────┘
```

Length = 1 (type) + 4 (channel) + N (payload)，不含自身 4 字节。

### 帧类型

| Type | 名称 | 方向 | payload |
|------|------|------|---------|
| 0x01 | Auth | C→L | AuthRequest JSON |
| 0x02 | AuthOk | L→C | 空 |
| 0x03 | AuthFail | L→C | 空 |
| 0x10 | Open | 双向 | `{ "target_addr": "...", "target_port": 8080 }` |
| 0x11 | OpenOk | 双向 | 空 |
| 0x12 | OpenFail | 双向 | 空 |
| 0x20 | Data | 双向 | 原始数据（≤16KB 分片） |
| 0x21 | DataFin | 双向 | 空（半关闭） |
| 0x22 | WindowUpdate | 双向 | u32 BE：对端已消费字节数（v2 流控） |
| 0x30 | Ping | 双向 | 空 |
| 0x31 | Pong | 双向 | 空 |
| 0x40 | Close | 双向 | 空 |

## Per-channel 窗口流控（协议 v2）

- 每条通道写方持有额度信号量（初始窗口 **1 MiB**），写数据即扣减
- 读方每消费 **≥512 KiB** 回发 `WindowUpdate` 补充额度
- 额度耗尽的通道仅自身挂起——**大流量通道不再队头阻塞同会话其他通道**
- 会话级 mpsc 背压仍保留为最后防线
- **版本协商**：`AuthRequest.version` 与 `AuthOk {"version":2}` 双向声明；
  对端为 v1 时自动降级为无流控模式（行为与旧版一致）

### 帧大小安全限制

| 类别 | 上限 | 说明 |
|------|------|------|
| 控制帧 payload | 64 KB | Auth/Open 等，超限断开 |
| 数据帧 payload | 256 KB | 正常路径由 MuxChannel 按 16 KB 分片 |

对端声明超大长度不会导致内存预分配耗尽——读端按类型校验后再分配。

## AuthRequest

```json
{
  "node_id": "node-b 或 account-id",
  "token": "psk_... 或 tun_...",
  "kind": "node | client",
  "advertise": ["10.12.0.0/16", "*.corp.internal"],
  "version": 1
}
```

| 字段 | 说明 |
|------|------|
| `kind` | `node`（PSK 认证，relay_token 表 SHA-256 比对）/ `client`（tunnel_token 认证） |
| `advertise` | 仅 node：向上游通告本节点可服务的网段/域名，用于多级路由 |
| `version` | 协议版本，当前恒为 1 |

- token 比较使用**常数时间比较**，防时序侧信道。
- 同一 IP 60s 内认证尝试超过 20 次直接丢弃连接。
- 节点 ID 长度限制 1~128 字符。

## 多路复用

- channel_id 奇偶分配：Listener 侧会话从 1 开始（奇），Connector/Client 侧从 2 开始（偶），互不冲突。
- 单会话最大并发通道数 1024（防 Open 洪泛）。
- Data 帧写入按 16 KB 分片；会话写缓冲满时发送方挂起（正确背压）。
- 单通道读缓冲 128 帧。

## 客户端会话与 ACL

`kind=client` 的会话由 Listener 处理 Open 请求：

1. 按账号权限组规则做目标 ACL 校验（CIDR / 精确域名 / 通配后缀），拒绝 → OpenFail。
2. 命中下游节点通告路由 → 向下游继续 Open（链式转发，桥接两个 MuxChannel）。
3. 否则本机直连（TcpStream::connect）→ 桥接。

## 多级串联

```
Node-C (叶子)  →  Node-B (中间)  →  Node-A (根/公网)  ←  Client

Node-C 向 Node-B 通告 172.16.0.0/12
Node-B 向 Node-A 通告 172.16.0.0/12（自身路由表 = 本机 + C 的通告）
```

Open 请求在每一级做同样的解析：命中通告路由 → 向对应下游 Open；否则直连。
上游无需知道下游有多少级。

## 心跳与超时

| 参数 | 值 | 说明 |
|------|-----|------|
| 心跳间隔 | 25s + 0~10s 随机 | 模拟自然 HTTPS 行为 |
| 空闲超时 | 90s | 未收到对端任何帧判定断线 |
| 握手+认证超时 | 10s | 防 Slowloris 半开连接 |
| Open 等待超时 | 10s | OpenOk/OpenFail 等待 |

## 连接与速率限制（Listener）

| 限制 | 值 |
|------|-----|
| 最大并发连接 | 1024 |
| 最大待认证连接 | 256 |
| 认证尝试 | 20 次/分钟/IP |

## 重连策略

```rust
// 指数退避 + 抖动（Connector 与 ClientTunnel 一致）
let backoff = min(1s * 2^attempt, 60s);
let delay = backoff + random(0..3s);
```

重连后重新认证；客户端 tunnel_token 轮换后使用最新值。

## TLS 配置

- 仅 TLS 1.3（rustls + ring），禁用 0-RTT。
- Listener 证书：优先外部 PEM；缺省时生成自签证书并**持久化**到 `certs/`（重启不变，便于固定）。
- Connector/Client 信任策略优先级：**证书固定 (pinning)** > 自定义 CA > 跳过验证（仅开发）> webpki 系统根。
- 证书指纹（SHA-256 hex）在节点启动日志中输出，用于带外分发固定配置。
