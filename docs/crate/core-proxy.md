# agile-net-core::proxy 代理路由模块

## 职责

本地代理入站（SOCKS5 / HTTP CONNECT）+ 目标路由（CIDR / HOST 匹配）+ 出站（DIRECT / Tunnel）。替代 mihomo 的核心代理能力。

## 模块结构

```
core/src/proxy/
├── mod.rs          # pub use + ProxyConfig
├── inbound.rs      # SOCKS5/HTTP 入站监听
├── router.rs       # CIDR/HOST 路由表
└── outbound.rs     # 出站策略（DIRECT / Tunnel）
```

## Inbound（入站监听）

支持两种协议，同端口同时监听：

### SOCKS5

```rust
pub struct Socks5Inbound {
    listen_addr: SocketAddr,
    auth: Option<(String, String)>, // 可选的用户名密码
}

// 处理流程：
// 1. 握手 → 协商认证方式
// 2. 收到 CONNECT 请求 → 提取 target_addr
// 3. 查路由表 → 选择出站
// 4. 桥接 inbound ↔ outbound
```

### HTTP CONNECT

```rust
pub struct HttpInbound {
    listen_addr: SocketAddr,
}

// 处理流程：
// 1. 读取 CONNECT host:port
// 2. 查路由表 → 选择出站
// 3. 回复 200 Connection Established
// 4. 桥接 inbound ↔ outbound
```

### 协议自动检测

监听同一个端口，根据首字节判断协议：

```rust
async fn detect_protocol(stream: &TcpStream) -> Protocol {
    let mut peek = [0u8; 1];
    stream.peek(&mut peek).await?;
    match peek[0] {
        0x05 => Protocol::Socks5,  // SOCKS5 握手固定 0x05
        _    => Protocol::Http,     // HTTP CONNECT 以 ASCII 开头
    }
}
```

## Router（路由表）

```rust
pub struct ProxyRouter {
    /// CIDR 路由表：IpNetwork → OutboundType
    cidr_table: IpNetworkTable<Outbound>,
    /// HOST 路由表：域名 → OutboundType
    host_table: HashMap<String, Outbound>,
    /// 默认出站（DIRECT）
    default: Outbound,
}

#[derive(Clone)]
pub enum Outbound {
    /// 直连
    Direct,
    /// 通过隧道转发到指定节点
    Tunnel { node_id: NodeId },
}

impl ProxyRouter {
    /// 根据目标地址选择出站
    pub fn route(&self, target: &TargetAddr) -> &Outbound;
    /// 热更新路由表
    pub fn update(&mut self, rules: Vec<Rule>);
    /// 路由条目数
    pub fn route_count(&self) -> usize;
    /// 检查地址是否匹配
    pub fn matches(&self, addr: &str) -> bool;
}
```

### 路由匹配优先级

1. HOST 精确匹配（`git.internal.com`）
2. CIDR 最长前缀匹配（`10.12.186.0/24` 优先于 `10.12.0.0/16`）
3. 默认 → DIRECT

### 多节点路由合并

Client 连接多个 Node 时，每个 Node 下发各自的规则。合并策略：

```rust
pub fn merge_routes(node_routes: &[(NodeId, Vec<Rule>)]) -> ProxyRouter {
    let mut router = ProxyRouter::new();
    for (node_id, rules) in node_routes {
        for rule in rules {
            // 每条规则绑定到对应的 node_id
            router.insert(rule, Outbound::Tunnel { node_id: *node_id });
        }
    }
    router
}
```

冲突处理：如果两个 Node 下发重叠的 CIDR，后连接的 Node 覆盖先前的（用户可以在 Client UI 调整优先级，未来功能）。

## Outbound（出站）

### DirectOutbound

```rust
pub struct DirectOutbound;

impl DirectOutbound {
    pub async fn connect(target: SocketAddr) -> Result<TcpStream> {
        TcpStream::connect(target).await.map_err(Into::into)
    }
}
```

### TunnelOutbound

```rust
pub struct TunnelOutbound {
    pool: Arc<TunnelPool>,
}

impl TunnelOutbound {
    pub async fn connect(&self, target: SocketAddr) -> Result<Channel> {
        let channel = self.pool.open_channel(target).await?;
        Ok(channel)
    }
}
```

## 性能考量

| 项目 | 设计 |
|------|------|
| 连接处理 | tokio::spawn per connection，无锁 |
| 路由查找 | CIDR: O(prefix_len)，HOST: O(1) HashMap |
| 数据转发 | tokio::io::copy_bidirectional，零拷贝 |
| 路由表更新 | RwLock，写入时短暂阻塞查询 |
| 内存占用 | 1000 条 CIDR 规则 < 100KB |

## 代理引擎生命周期

```rust
pub struct ProxyEngine {
    inbound: JoinHandle<()>,
    router: Arc<RwLock<ProxyRouter>>,
}

impl ProxyEngine {
    pub async fn start(config: ProxyConfig) -> Result<Self>;
    pub async fn stop(&self);
    pub fn port(&self) -> u16;
    pub fn router(&self) -> Arc<RwLock<ProxyRouter>>;
    pub fn stats(&self) -> ProxyStats;
}

pub struct ProxyStats {
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
```
