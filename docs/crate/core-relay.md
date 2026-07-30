# agile-net-core::relay 穿透模块

## 职责

Node 之间建立 TLS 1.3 加密隧道，双向透传任意 TCP 流量。替代 frp 的核心穿透能力。

## 模块结构

```
core/src/relay/
├── mod.rs          # pub use + RelayConfig
├── listener.rs     # 上游角色：监听并接受连入
├── connector.rs    # 下游角色：主动连接上游
├── frame.rs        # 帧编解码
└── bridge.rs       # 双向数据桥接
```

## 帧协议

所有通信在 TLS 之上使用自定义帧格式：

```
┌──────────────┬──────────────┬──────────────┬──────────┐
│ Length (u32)  │ Type (u8)    │ Channel (u32)│ Payload  │
│ 4 bytes      │ 1 byte       │ 4 bytes      │ N bytes  │
└──────────────┴──────────────┴──────────────┴──────────┘
```

### 帧类型

| Type | 名称 | 方向 | 描述 |
|------|------|------|------|
| 0x01 | Auth | connector → listener | 认证请求（node_id + token） |
| 0x02 | AuthOk | listener → connector | 认证成功 |
| 0x03 | AuthFail | listener → connector | 认证失败 |
| 0x10 | Open | listener → connector | 请求打开数据通道（channel_id） |
| 0x11 | OpenOk | connector → listener | 通道就绪 |
| 0x12 | OpenFail | connector → listener | 通道打开失败 |
| 0x20 | Data | 双向 | 数据帧（channel_id + payload） |
| 0x21 | DataFin | 双向 | 数据结束（半关闭） |
| 0x30 | Ping | 双向 | 心跳请求 |
| 0x31 | Pong | 双向 | 心跳响应 |
| 0x40 | Close | 双向 | 关闭通道 |

### 多路复用

单条 TLS 连接上复用多个逻辑通道（channel_id），每个通道代表一条端到端的 TCP 连接。

```
TLS Connection
├── channel 1: Client-A 的请求 → 内网 10.12.0.1:80
├── channel 2: Client-A 的请求 → 内网 10.12.0.2:3306
├── channel 3: Client-B 的请求 → 内网 10.12.0.1:22
└── ...
```

## Listener（上游角色）

```rust
pub struct RelayListener {
    /// TLS 监听地址
    listen_addr: SocketAddr,
    /// TLS 配置
    tls_config: Arc<ServerConfig>,
    /// 已认证的下游节点
    peers: DashMap<NodeId, PeerConnection>,
    /// 数据通道路由表：target_addr → peer_node_id
    route_table: Arc<RwLock<RouteTable>>,
}

impl RelayListener {
    pub async fn start(&self) -> Result<()>;
    pub async fn open_channel(&self, peer_id: &NodeId, target: SocketAddr) -> Result<Channel>;
    pub fn peer_count(&self) -> usize;
    pub fn channel_count(&self) -> usize;
}
```

## Connector（下游角色）

```rust
pub struct RelayConnector {
    /// 上游地址
    upstream_addr: SocketAddr,
    /// TLS 配置
    tls_config: Arc<ClientConfig>,
    /// 认证信息
    auth: AuthCredential,
    /// 连接状态
    state: Arc<AtomicU8>,
}

impl RelayConnector {
    pub async fn connect(&self) -> Result<()>;
    pub async fn disconnect(&self);
    pub fn state(&self) -> ConnectionState;
    /// 当收到 Open 帧时，连接本地目标并桥接
    async fn handle_open(&self, channel_id: u32, target: SocketAddr) -> Result<()>;
}
```

## Bridge（双向桥接）

```rust
/// 将两个 AsyncRead+AsyncWrite 流双向桥接
pub async fn bridge<A, B>(a: A, b: B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin;
```

使用 `tokio::io::copy_bidirectional` 的零拷贝优化版本。返回两个方向的传输字节数。

## 心跳与重连

- Ping 间隔：30s ± 随机抖动（0~5s），模拟自然 HTTPS 行为
- Pong 超时：10s 未收到 Pong → 标记连接断开
- 重连策略：指数退避 1s → 2s → 4s → ... → 60s（上限）
- 重连时自动重新认证

## 流量控制

初版不做流控，依赖 TCP 自身的流控机制。后续可在 Data 帧级别加 window-based flow control。

## 错误处理

| 场景 | 行为 |
|------|------|
| TLS 握手失败 | 日志记录，关闭连接 |
| 认证失败 | 返回 AuthFail，关闭连接 |
| 帧解码错误 | 日志记录，关闭连接 |
| 通道目标不可达 | 返回 OpenFail，只关闭该通道 |
| Ping 超时 | 关闭连接，触发重连 |
