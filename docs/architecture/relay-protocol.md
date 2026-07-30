# Relay 协议设计

节点间穿透通信的核心协议，替代 frp。

## 连接模型

```
Connector (下游节点)                    Listener (上游节点)
      │                                       │
      ├── TCP connect ──────────────────────> │
      ├── TLS 1.3 handshake ────────────────> │
      ├── AuthFrame { token } ──────────────> │
      │ <──────────────── AuthResult { ok } ──┤
      │                                       │
      │   ══ Control Channel Established ══   │
      │                                       │
      │ <──── NewConnection { conn_id } ──────┤  ← 有客户端访问时
      ├── DataChannel { conn_id } ──────────> │
      │ <════════ 双向数据转发 ════════════════│
      │                                       │
      ├── Ping ─────────────────────────────> │  ← 每 30s ± 5s
      │ <──────────────────────────── Pong ───┤
```

## 帧格式

所有帧在 TLS 内部传输，外部只看到 TLS 密文。

```
┌──────────┬──────────┬──────────────┐
│ type: u8 │ len: u32 │ payload: [u8]│
└──────────┴──────────┴──────────────┘
```

| type | 名称 | 方向 | payload |
|------|------|------|---------|
| 0x01 | Auth | C→L | `{ "token": "xxx" }` |
| 0x02 | AuthResult | L→C | `{ "ok": true }` 或 `{ "ok": false, "reason": "..." }` |
| 0x03 | NewConnection | L→C | `{ "conn_id": "uuid" }` |
| 0x04 | DataChannel | C→L | `{ "conn_id": "uuid" }` — 然后帧结束，后续此 TCP 流变为透明数据 |
| 0x05 | Ping | C→L | 空 |
| 0x06 | Pong | L→C | 空 |
| 0x07 | Shutdown | 双向 | `{ "reason": "..." }` |

payload 使用 JSON 编码，简单、可调试、长度可忽略（控制帧很少）。

## 数据通道建立流程

```
1. Client 连到 Listener:443，请求访问 10.12.186.133:8080
2. Listener 查路由表，目标属于 Connector-B 注册的网段
3. Listener 通过 Control Channel 发 NewConnection { conn_id: "abc" }
4. Connector-B 收到通知，新建 TCP 连接到 Listener:443
5. Connector-B 发 TLS 握手 → DataChannel { conn_id: "abc" }
6. Listener 确认 conn_id，将 Client 连接和 DataChannel 连接桥接
7. 双向数据透明转发：Client ←→ Listener ←→ Connector-B ←→ 内网目标
```

## 多级串联

```
Node-C (叶子)  →  Node-B (中间)  →  Node-A (根/公网)  ←  Client

Node-C 注册网段 172.16.0.0/12 到 Node-B
Node-B 注册网段 10.12.0.0/16 + 172.16.0.0/12 到 Node-A
Node-A 路由表：
  10.12.0.0/16   → Node-B
  172.16.0.0/12  → Node-B (Node-B 再路由到 Node-C)
```

上游节点不需要知道下游有多少级，每级只负责转发到下一跳。

## 重连策略

```rust
// 指数退避 + 抖动
let base_delay = Duration::from_secs(1);
let max_delay = Duration::from_secs(60);
let delay = min(base_delay * 2^attempt, max_delay) + random(0..3s);
```

重连时复用同一 token，Listener 端通过 token 识别是同一个 Connector 重连，更新会话。

## 心跳与超时

| 参数 | 值 | 说明 |
|------|-----|------|
| 心跳间隔 | 30s ± 5s 随机 | 模拟自然 HTTPS 行为 |
| 心跳超时 | 90s | 连续 3 次无响应断开 |
| 数据通道空闲超时 | 300s | 5 分钟无数据关闭 |
| 握手超时 | 10s | 认证必须在 10s 内完成 |

## TLS 配置

```rust
// rustls 配置要点
ServerConfig::builder()
    .with_no_client_auth()           // 应用层 token 认证，不用 mTLS
    .with_single_cert(cert, key)?;

// 客户端
ClientConfig::builder()
    .with_root_certificates(roots)   // 支持自签证书（开发）和 CA 证书
    .with_no_client_auth();

// 强制 TLS 1.3
config.max_early_data_size = 0;      // 禁用 0-RTT
// rustls 默认只启用 TLS 1.3 cipher suites
```
