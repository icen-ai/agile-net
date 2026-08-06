# Mux 帧协议

AgileNet 节点间及消费者与节点间运行于 TLS 1.3 之上的自定义二进制多路复用（Mux）协议。
**协议 v4 为唯一行为**（`PROTOCOL_VERSION = 4` 仅为握手声明常量，无版本门槛、无降级分支）。

## 帧头格式

每个 Mux 帧由 9 字节固定帧头与变长 Payload 组成：

```text
┌─────────────────┬──────────────────┬──────────────────────┬──────────────────────┐
│  Length (u32BE) │ FrameType (u8)   │ Channel ID (u32BE)   │ Payload (0..N bytes) │
│     4 字节      │     1 字节       │       4 字节         │       N 字节         │
└─────────────────┴──────────────────┴──────────────────────┴──────────────────────┘
```

- **Length**：大端序 32 位无符号整数，表示 Payload 及 Header 内部偏移之和（即 `1 + 4 + PayloadLen`）。
- **FrameType**：8 位无符号整数，指定帧类型。
- **Channel ID**：大端序 32 位无符号整数，标识该帧所属的虚拟多路复用通道（`0` 通常用于全局控制帧）。
- **Payload**：变长二进制数据。

### 负载长度限制

- **控制帧**（Auth/Open/Ping/Close 等）：最大 Payload 64 KB（`65536` 字节）。超限即断开连接。
- **数据帧**（Data/DataFin）：最大 Payload 256 KB（`262144` 字节）。写路径默认按 `16 KB`（`16384` 字节）切片分包。

---

## 帧类型定义 (FrameType)

| 值 (Hex) | 帧类型 | 作用 | Payload 格式 |
| --- | --- | --- | --- |
| `0x01` | `Auth` | 客户端 / 下游节点发起认证 | JSON 格式 `AuthRequest` |
| `0x02` | `AuthOk` | 认证成功响应 | 可选 JSON 格式 `ControlOffer`（握手 v2） |
| `0x03` | `AuthFail` | 认证失败响应 | 字符串原因说明 |
| `0x04` | `Ctrl` | 会话控制面（channel 0：委托注册/吊销等） | JSON 格式 `CtrlMessage` |
| `0x10` | `Open` | 请求打开一条到目标的虚拟通道 | JSON 格式 `OpenChannel`（可携带组标/E2E 信封） |
| `0x11` | `OpenOk` | 目标通道打开成功 | 空 |
| `0x12` | `OpenFail` | 目标通道打开失败 | JSON 格式 `OpenFailed` |
| `0x20` | `Data` | 通道数据传输 | 原始二进制 Payload（E2E 信道为 AEAD 记录流） |
| `0x21` | `DataFin` | 通道数据半关闭 (FIN) | 原始二进制 Payload（可选） |
| `0x22` | `WindowUpdate` | per-channel 窗口流控更新 | u32BE 已消费字节数 |
| `0x30` | `Ping` | 心跳维持 | 空 |
| `0x31` | `Pong` | 心跳响应 | 空 |
| `0x40` | `Close` | 通道或会话关闭 | 空或字符串原因 |

---

## 会话控制面（Ctrl 帧）

Ctrl 帧固定走 channel 0，JSON Payload，控制面与数据面分离。首个用途是**委托令牌注册**
（签发者 → 中继，relay 入口）：

### CtrlMessage Payload (0x04)

```json
{ "op": "token_register", "token_hash": "<sha256-hex>", "label": "alice", "groups": ["git"],
  "hint_map": [{ "hint": "en_ab12cd34ef56", "groups": ["db-prod"] }] }
{ "op": "token_revoke", "token_hash": "<sha256-hex>" }
{ "op": "token_ack", "token_hash": "<sha256-hex>", "ok": true, "error": "" }
```

- 注册校验：组名 ∩ 签发者上送组（entrust 词 `en_` 前缀免路由校验直进不透明表，
  一哈希一签发者）；透明档每个 hint 必须能经路由表解析回签发者本身。
- 生命周期随会话：签发者断线即全部失效（吊销即断），重连后签发者自动重注册。

### OpenChannel 扩展

```json
{ "target_addr": "10.0.0.5", "target_port": 5432,
  "groups": ["git"],                                   // 可选：委托会话组标（中继盖章，签发端按本地同名组执法）
  "e2e": { "kid": "<hash前12hex>", "hint": "en_ab12cd34ef56", "blob": "<base64(nonce‖ct)>" } }
```

携带 `e2e` 时 `target_addr` 为不透明路由词（中继盲转），真实目标密封在 blob 内：
`AES-256-GCM(e2e_key, 随机nonce, json{target_addr, target_port, groups, chan_salt})`，
`e2e_key = HKDF-SHA256(ikm=token, salt="anet/e2e/v1")`；该信道后续 Data 为逐块 AEAD 记录
（`[u32 长度][密文]`，子密钥 = HKDF(e2e_key, chan_salt)，nonce = 方向(1B)‖序号(8B)，
收端严格序列校验，重放/乱序即断）。

---

## 握手与控制面下发

在 Auth 帧成功通过鉴权后，服务端返回 `AuthOk` 帧，可附带 `ControlOffer` 负载：

### AuthRequest Payload (0x01)
```json
{
  "node_id": "node-b 或消费者标签",
  "token": "psk_...",
  "kind": "client|node",
  "advertise": ["10.12.0.0/16", "git.internal"],
  "groups": [{ "name": "git", "remark": "...", "rules": ["git.internal"] }],
  "version": 4
}
```

- `kind=node`：relay_token 表 SHA-256 比对（扇入对端）；`advertise` 通告可服务网段，
  `groups` 为策略上送组（可授权池）。
- `kind=client`：委托令牌（delegated_token 表 SHA-256 比对，`AuthIdentity::Delegated`）。

### ControlOffer Payload (0x02 AuthOk)
当上游 Relay Token 开启了「允许暴露控制面」时，`AuthOk` 帧附带 `ControlOffer`：
```json
{
  "exposed": true,
  "api_host": "relay.example.com",
  "api_port": 59090,
  "node_name": "Beijing-Relay-01",
  "ticket": "adt_...",
  "scope": "full"
}
```

下游节点解析此扩展后，会自动感知上游可管理状态，并供客户端做**可管理节点自动发现**。

---

## 通道流控 (WindowUpdate)

基于 per-channel 窗口的滑动流控：
- 初始接收窗口为 1 MiB。
- 当对端消费读取数据后，发送 `0x22 WindowUpdate` 帧，Payload 为 4 字节大端序 `u32`，告知已释放的窗口增量。
- 防止高速写入方撑爆低速接收方的缓冲池。
