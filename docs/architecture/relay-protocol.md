# Relay 协议设计（v4，与实现一致）

节点间穿透通信与消费者数据面的核心协议，替代 frp。
单条 TLS 1.3 连接上多路复用多个逻辑通道。**协议 v4 为唯一行为**——无版本门槛、
无降级分支（`PROTOCOL_VERSION = 4` 仅为握手声明常量）。

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
| 0x02 | AuthOk | L→C | `{ "version": 4, ... }` |
| 0x03 | AuthFail | L→C | 空 |
| 0x04 | Ctrl | 双向 | 会话控制面（channel 0：委托 token_register/revoke、TokenAck 等） |
| 0x10 | Open | 双向 | `{ "target_addr": "...", "target_port": 8080 }` |
| 0x11 | OpenOk | 双向 | 空 |
| 0x12 | OpenFail | 双向 | 空 |
| 0x20 | Data | 双向 | 原始数据（≤16KB 分片） |
| 0x21 | DataFin | 双向 | 空（半关闭） |
| 0x22 | WindowUpdate | 双向 | u32 BE：对端已消费字节数（v2 流控） |
| 0x30 | Ping | 双向 | 空 |
| 0x31 | Pong | 双向 | 空 |
| 0x40 | Close | 双向 | 空 |

## Per-channel 窗口流控

- 每条通道写方持有额度信号量（初始窗口 **1 MiB**），写数据即扣减
- 读方每消费 **≥512 KiB** 回发 `WindowUpdate` 补充额度
- 额度耗尽的通道仅自身挂起——**大流量通道不再队头阻塞同会话其他通道**
- 会话级 mpsc 背压仍保留为最后防线

### 帧大小安全限制

| 类别 | 上限 | 说明 |
|------|------|------|
| 控制帧 payload | 64 KB | Auth/Open 等，超限断开 |
| 数据帧 payload | 256 KB | 正常路径由 MuxChannel 按 16 KB 分片 |

对端声明超大长度不会导致内存预分配耗尽——读端按类型校验后再分配。

## AuthRequest

```json
{
  "node_id": "node-b 或消费者标签",
  "token": "psk_...",
  "kind": "node | client",
  "advertise": ["10.12.0.0/16", "*.corp.internal"],
  "groups": [{ "name": "git", "remark": "...", "rules": ["git.internal"] }],
  "version": 4,
  "my_name": "小明的 MacBook",
  "device_pubkey": "base64(ed25519 pubkey)",
  "device_sig": "base64(ed25519 sig)"
}
```

| 字段 | 说明 |
|------|------|
| `kind` | `node`（relay_token 表 SHA-256 比对）/ `client`（委托令牌，delegated_token 表 SHA-256 比对，`AuthIdentity::Delegated`） |
| `advertise` | 仅 node：向上游通告本节点可服务的网段/域名，用于多级路由（有效集 = 手工 ∪ 上送组规则） |
| `groups` | 仅 node：策略上送的权限组（可授权池，经上限清洗） |
| `version` | 协议版本，当前恒为 4 |
| `my_name` | 自声明显示名（"我的名称"；装饰性，不参与认证/路由） |
| `device_pubkey` / `device_sig` | **设备身份证明（强制）**：对 TLS exporter secret（RFC 5705，label `anet device proof v1`）的 ed25519 签名——零额外 RTT、防重放、绑定会话；验签失败按 `device_proof_invalid` 拒连 |

- token 比较使用**常数时间比较**，防时序侧信道。
- 同一 IP 60s 内认证尝试超过 20 次直接丢弃连接。
- 节点 ID 长度限制 1~128 字符。
- `device_fp = sha256(device_pubkey)` 由 listener 本地派生（**线路上声明的指纹不可信**）；
  设备吊销（`device_registry.state=revoked`）→ 拒连 `device_revoked` + 红色告警事件。
- AuthOk 载荷：`{version, node_id, device_state, control?}`；`device_state=pending` 表示设备
  待认证（数据面门控生效中），relay 入口经 E2E 配置通道的 `device_state` 叠加传达。
- AuthFail 载荷为结构化 `FailReason{reason_code, message}`（吊销/拒绝可带一次性附言）。

### reason_code 标准表（SessionNotice / AuthFail / OpenFail 共用）

`revoked_by_admin`（管理员吊销）/ `device_revoked`（设备吊销，终态）/ `device_replaced`
（换机迁移）/ `token_expired`（过期/用尽）/ `kicked`（管理员踢下线）/ `session_takeover`
（single 档新会话接管）/ `issuer_offline`（签发者会话掉线）/ `server_shutdown`（服务关闭）/
`bad_credentials`（凭据无效）/ `device_proof_invalid`（设备证明失败）/ `pending_approval`
（等待认证）。

### Ctrl 会话控制面（channel 0，JSON）

- `token_register` / `token_revoke`（吊销带 reason_code + 一次性附言）/ `token_ack`
- `session_notice`：踢断/吊销前置通知（reason_code + 附言，随帧推送 + 握手拒绝双通道）
- `pending_note`：pending 会话附言上行（≤3 条）；relay 中转时补 `device_fp`/`session_key`
  转发签发者会话（消费者只发 body）
- M6 预留码位：`cert_push` / `cert_revoke` / `grant_receipt`（传递认证与拓扑回执，schema 后定）

## 多路复用

- channel_id 奇偶分配：Listener 侧会话从 1 开始（奇），Connector/Client 侧从 2 开始（偶），互不冲突。
- 单会话最大并发通道数 1024（防 Open 洪泛）。
- Data 帧写入按 16 KB 分片；会话写缓冲满时发送方挂起（正确背压）。
- 单通道读缓冲 128 帧。

## 消费者会话与 ACL

`kind=client` 的会话（委托令牌）由 Listener 处理 Open 请求：

1. 按令牌引用权限组的规则并集做目标 ACL 校验（CIDR / 精确域名 / 通配后缀），拒绝 → OpenFail；
   命中 `e2e_required` 组的明文 Open **fail-close**。
2. E2E 信封（entrust 路由词 `en_xxx` 寻址）验 kid/hint 后由签发端解包，中间跳逐字透传盲转；
   伪造/重放（严格序列校验）硬拒即断。
3. 命中下游节点通告路由 → 向下游继续 Open（链式转发，桥接两个 MuxChannel）。
4. 否则本机直连（TcpStream::connect）→ 桥接。

并发执法（listener 落地）：`single` 档同令牌新会话踢旧留新；`multi` 档多会话并存，
上限为签发时快照的 `max_sessions`（node_config `delegation_max_sessions`，默认 8），超限拒开。
会话级 Open 洪泛防护 `MAX_INBOUND_OPENS_PER_SESSION = 256`，超限回 OpenFail。

**设备认证门控（M3-T2）**：委托 Open 转发时 listener 盖上该会话已实证的 `device_fp` 戳
（消费者自报无效）。direct 入口由签发者本端 listener 执法（pending 拒开
`pending_approval`，revoked 拒连 `device_revoked`）；relay 入口由签发者 connector 的
`DelegationHooks.device_open_gate` 执法（E2E 配置通道豁免——pending 设备须能拉状态）。
策略 `device_pending_policy`：block（默认）/ allow（放行插灰旗）。

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

重连后重新认证；委托会话断开即清注册（随会话清空/吊销即断）。

## TLS 配置

- 仅 TLS 1.3（rustls + ring），禁用 0-RTT。
- Listener 证书：优先外部 PEM；缺省时生成自签证书并**持久化**到 `certs/`（重启不变，便于固定）。
- Connector/Client 信任策略优先级：**证书固定 (pinning)** > 自定义 CA > 跳过验证（仅开发）> webpki 系统根。
- 证书指纹（SHA-256 hex）在节点启动日志中输出，用于带外分发固定配置。
