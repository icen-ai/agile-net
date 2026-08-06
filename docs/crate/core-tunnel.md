# agile-net-core::tunnel 隧道连接模块

## 职责

管理 Client / Node 到上游 Node 的 TLS 连接池。这是 relay 和 proxy 的胶水层——proxy 的 TunnelOutbound 通过 tunnel pool 获取连接，relay 的帧协议在 pool 管理的 TLS 流上运行。

## 模块结构

```
core/src/tunnel/
├── mod.rs      # pub use + TunnelConfig
├── pool.rs     # 连接池管理
└── tls.rs      # TLS 1.3 配置
```

## TLS 配置

```rust
/// 统一的 TLS 配置构建器
pub struct TlsConfigBuilder {
    /// 服务端证书路径（listener 模式）
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    /// 客户端 CA 根证书（connector 模式，可选，默认信任系统 CA）
    ca_path: Option<PathBuf>,
    /// SNI 域名（connector 模式，伪装用）
    sni_hostname: String,
}

impl TlsConfigBuilder {
    /// 构建 rustls ServerConfig（listener 用）
    pub fn build_server(&self) -> Result<Arc<ServerConfig>>;
    /// 构建 rustls ClientConfig（connector 用）
    pub fn build_client(&self) -> Result<Arc<ClientConfig>>;
}
```

### TLS 伪装

- `sni_hostname`：TLS ClientHello 的 SNI 字段设为普通域名（如 `cdn.cloudflare.com`），DPI 看到的是访问 Cloudflare
- 端口使用 443，与 HTTPS 流量完全一致
- 只启用 TLS 1.3（rustls 默认），无降级

## 通道获取（TunnelPool，已修正设计）

> 设计修正：MuxChannel 与目标地址一一绑定，**复用通道会把流量发往错误目标**。
> 因此 `TunnelPool` 不再缓存通道——每次 `acquire` 都在既有 MuxSession 上新建通道。
> 复用发生在会话层：单条 TLS 连接的多路复用天然承载全部通道，新建通道代价极低。

```rust
pub struct TunnelPool {
    listener: Arc<RelayListener>,
    node_id: String,
}

impl TunnelPool {
    pub fn new(listener: Arc<RelayListener>, node_id: impl Into<String>, config: TunnelPoolConfig) -> Self;
    /// 向目标打开一条新通道
    pub async fn acquire(&self, target_host: &str, target_port: u16) -> Result<MuxChannel>;
    /// 通道绑定目标不可复用，release 即丢弃
    pub async fn release(&self, channel: MuxChannel);
    pub async fn available(&self) -> usize; // 恒 0（无缓存）
    pub async fn evict_expired(&self);      // 空操作（保留 API 兼容）
}
```

## 客户端隧道（ClientTunnel）

消费者到节点的数据面连接（委托令牌即身份，`kind=client`）：

```rust
pub struct ClientTunnel { ... }

impl ClientTunnel {
    /// 生产推荐：TlsConfigBuilder::pinned_fingerprint(...)
    pub fn with_tls_builder(addr: SocketAddr, node_id: impl Into<String>,
                            token: impl Into<String>, builder: TlsConfigBuilder) -> Result<Self>;
    /// 开发模式（不校验证书）
    pub fn new_insecure(addr: SocketAddr, node_id: impl Into<String>,
                        token: impl Into<String>) -> Result<Self>;

    pub async fn connect(&self) -> Result<()>;                       // TLS + Auth(kind=client)
    pub async fn open_channel(&self, host: &str, port: u16) -> Result<MuxChannel>;
    pub async fn run(&self);                                          // 自动重连（指数退避+抖动）
    pub async fn disconnect(&self);
    pub fn is_connected(&self) -> bool;
}
```

- 心跳 25s + 0~10s 抖动，90s 无帧判定断线
- 断线指数退避重连（1s → 60s + 0~3s 抖动）
- `open_channel_raw` 支持自定义 Open payload（E2E 信封由 DelegatedOpener 包装，
  对消费方透明：`ChannelOpener` 返回 `BoxedChannel`）

## ChannelOpener（通道开启抽象）

Proxy 入站把 `Outbound::Tunnel { node_id }` 解析到具体通道来源：

```rust
pub trait ChannelOpener: Send + Sync {
    fn open<'a>(&'a self, node_id: &'a str, host: &'a str, port: u16)
        -> Pin<Box<dyn Future<Output = Result<MuxChannel>> + Send + 'a>>;
}
```

| 实现 | 场景 |
|------|------|
| `RelayListener` | 节点上向指定下游 peer 开通道 |
| `PeerAutoOpener` | 节点本地代理：按通告路由自动选 peer |
| `ClientTunnel` | 客户端到节点的隧道（忽略 node_id） |

## Channel（逻辑通道）

```rust
/// 一条逻辑通道，实现 AsyncRead + AsyncWrite
pub struct Channel {
    channel_id: u32,
    /// 读端：从帧解码器中接收该 channel 的 Data 帧
    reader: mpsc::Receiver<Bytes>,
    /// 写端：编码为 Data 帧发送
    writer: mpsc::Sender<Frame>,
}

impl AsyncRead for Channel { ... }
impl AsyncWrite for Channel { ... }
```

Channel 对 proxy 层完全透明——proxy 拿到 Channel 就像拿到普通 TcpStream 一样 bridge。

## 与其他模块的关系

```
proxy::outbound::TunnelOutbound
    │
    ├── 持有 TunnelPool
    │
    └── open_channel(target)
            │
            ├── pool.acquire() → TLS 连接
            │
            └── 在 TLS 连接上发 relay::frame::Open
                    │
                    └── 对端 relay::connector 收到 Open
                            │
                            └── 连接 target → bridge
```
