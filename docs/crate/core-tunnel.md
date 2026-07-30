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

## 连接池

```rust
pub struct TunnelPool {
    /// 上游地址
    upstream: SocketAddr,
    /// TLS 配置
    tls_config: Arc<ClientConfig>,
    /// 认证信息
    auth: AuthCredential,
    /// 连接池大小
    pool_size: usize,
    /// 可用连接
    connections: Mutex<VecDeque<PooledConnection>>,
    /// 空闲超时
    idle_timeout: Duration,
}

struct PooledConnection {
    stream: TlsStream<TcpStream>,
    created_at: Instant,
    last_used: Instant,
}

impl TunnelPool {
    /// 创建连接池并预建连接
    pub async fn new(config: TunnelConfig, pool_size: usize) -> Result<Self>;

    /// 获取一条连接（优先复用，不够则新建）
    pub async fn acquire(&self) -> Result<TlsStream<TcpStream>>;

    /// 归还连接（用完后自动归还）
    pub fn release(&self, conn: TlsStream<TcpStream>);

    /// 在连接上打开一个逻辑通道（发送 Open 帧）
    pub async fn open_channel(&self, target: SocketAddr) -> Result<Channel>;

    /// 当前可用连接数
    pub fn available(&self) -> usize;

    /// 关闭所有连接
    pub async fn shutdown(&self);
}
```

### 连接池策略

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `pool_size` | 5 | 预建连接数 |
| `idle_timeout` | 5min | 空闲超时后断开 |
| `max_lifetime` | 30min | 连接最大存活时间 |
| `acquire_timeout` | 10s | 获取连接超时 |

### 后台维护

连接池启动后台 task：

```rust
async fn maintenance_loop(&self) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;

        // 1. 清理空闲超时连接
        self.evict_idle().await;

        // 2. 清理超过 max_lifetime 的连接
        self.evict_expired().await;

        // 3. 补充到 pool_size
        self.refill().await;
    }
}
```

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
