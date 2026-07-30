# Proxy 与路由设计

本地代理入站 + CIDR/HOST 路由表，替代 mihomo。

## 入站监听

Node 和 Client 都运行 proxy 模块，监听本地端口：

```
127.0.0.1:7890
├── SOCKS5 协议
└── HTTP CONNECT 协议（自动探测）
```

探测逻辑：读取首字节，`0x05` → SOCKS5，`C`/`G`/`P` → HTTP。

## 路由表结构

```rust
pub struct Router {
    /// CIDR 路由，trie 结构，O(prefix_len) 查询
    cidr_table: IpLookupTable<Ipv4Addr, OutboundId>,

    /// HOST 精确匹配，HashMap O(1)
    host_exact: HashMap<String, OutboundId>,

    /// HOST 后缀匹配（*.example.com），倒序 trie
    host_suffix: SuffixTrie<OutboundId>,

    /// 默认出站
    fallback: OutboundId,
}
```

### 路由匹配优先级

```
1. HOST 精确匹配 → host_exact
2. HOST 后缀匹配 → host_suffix
3. IP-CIDR 匹配  → cidr_table（最长前缀优先）
4. 兜底          → fallback (DIRECT)
```

### 出站类型

```rust
pub enum Outbound {
    /// 直连，走本机网卡
    Direct,

    /// 通过 TLS 隧道连到指定节点
    Tunnel {
        node_id: String,
        server: String,
        port: u16,
        tls: bool,
    },
}
```

## Node 端路由

Node 作为下游时，proxy 模块接收从上游转发来的请求：

```
请求: CONNECT 10.12.186.133:8080
Router 查表: 10.12.0.0/16 → DIRECT
→ 从 Node 本机网卡直连 10.12.186.133:8080
```

Node 的路由规则由 Admin 在管理面配置，存在数据库。

## Client 端路由

Client 同时连接多个节点，合并路由表：

```
Node-B 下发规则:
  IP-CIDR 10.12.0.0/16
  HOST git.internal

Node-C 下发规则:
  IP-CIDR 172.16.0.0/12

Client 合并路由表:
  10.12.0.0/16   → Tunnel(Node-B)
  172.16.0.0/12  → Tunnel(Node-C)
  git.internal   → Tunnel(Node-B) + hosts 写入
  *              → DIRECT
```

### 冲突处理

两个节点声明了重叠的 CIDR，按**最长前缀优先**（标准路由规则）。如果完全相同，按节点连接顺序（先连优先），Client UI 可手动调整优先级。

## hosts 管理

HOST 类型的规则需要写入系统 hosts 文件：

```
# AgileNet managed — do not edit manually
# BEGIN AGILE-NET
10.12.186.133  git.internal
10.12.186.134  wiki.internal
# END AGILE-NET
```

操作规则：
1. 只操作 `BEGIN/END AGILE-NET` 之间的内容
2. HOST 规则的 IP 填 `127.0.0.1`（让 DNS 解析到本地，流量走 proxy）
3. 断开节点时清理对应条目
4. Client 退出时清理全部

**等等，HOST 类型应该怎么工作？** 两种模式：

### 模式 A：hosts + 代理（当前方案）

```
hosts: git.internal → 127.0.0.1
proxy 入站收到: CONNECT git.internal:443
Router: git.internal → Tunnel(Node-B)
Node-B: git.internal → DIRECT → 真实 IP（Node-B 的 DNS 解析）
```

需要应用走系统代理，否则解析到 127.0.0.1 就直连了。

### 模式 B：hosts 直接写目标 IP

```
hosts: git.internal → 10.12.186.133
proxy CIDR 规则: 10.12.0.0/16 → Tunnel(Node-B)
```

更简洁，但需要管理员知道 HOST 对应的 IP。

**采用模式 A**，因为：
- Admin 只需要配 HOST 名，不需要知道 IP
- Node-B 本地可以解析内网 DNS
- 对用户透明

## 热更新

路由表更新采用 RCU（Read-Copy-Update）：

```rust
// 路由表持有方
let router: Arc<ArcSwap<Router>> = ...;

// 更新：构建新表，原子替换
let new_router = Router::new(new_rules);
router.store(Arc::new(new_router));

// 读取：无锁
let current = router.load();
let outbound = current.resolve(&target);
```

已建立的连接不受路由表更新影响，只有新连接走新表。
