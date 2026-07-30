# M3：代理路由 (Proxy)

## 目标

实现本地 SOCKS5/HTTP 代理入站 + CIDR/HOST 路由表 + DIRECT 出站。单独可用：任何 SOCKS5 客户端连入，按规则路由。

## 依赖

M1 完成。可与 M2 并行开发。

## 产出

1. `core::proxy::inbound` — SOCKS5 + HTTP CONNECT 入站监听（协议自动探测）
2. `core::proxy::router` — CIDR trie + HOST exact/suffix 路由表
3. `core::proxy::outbound` — DIRECT 出站（直接 TCP 连接目标）
4. `core::config::node` / `core::config::client` — 配置模型

## 任务清单

- [ ] SOCKS5 入站（基于 fast-socks5 或手写握手）
- [ ] HTTP CONNECT 入站
- [ ] 协议自动探测（首字节判断）
- [ ] Router 结构：CIDR trie (ip_network_table) + HOST HashMap + HOST suffix trie
- [ ] 路由匹配优先级：host_exact → host_suffix → cidr → fallback
- [ ] DIRECT Outbound：tokio TCP connect + copy_bidirectional
- [ ] 路由表热更新（ArcSwap 原子替换）
- [ ] 配置模型定义

## 验收测试

### AT-M3-01：SOCKS5 入站

```rust
#[tokio::test]
async fn socks5_proxy_works() {
    let proxy = start_proxy("127.0.0.1:0", default_router()).await;
    let addr = proxy.local_addr();

    // 通过 SOCKS5 代理连接 httpbin
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&format!("socks5://{addr}"))?)
        .build()?;
    let resp = client.get("http://httpbin.org/ip").send().await?;
    assert_eq!(resp.status(), 200);
}
```

### AT-M3-02：HTTP CONNECT 入站

```rust
#[tokio::test]
async fn http_connect_proxy_works() {
    let proxy = start_proxy("127.0.0.1:0", default_router()).await;
    let addr = proxy.local_addr();

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&format!("http://{addr}"))?)
        .build()?;
    let resp = client.get("http://httpbin.org/ip").send().await?;
    assert_eq!(resp.status(), 200);
}
```

### AT-M3-03：CIDR 路由匹配

```rust
#[test]
fn cidr_routing() {
    let mut router = Router::new();
    router.add_cidr("10.12.0.0/16", OutboundId::new("tunnel-b"));
    router.add_cidr("10.152.0.0/16", OutboundId::new("tunnel-c"));

    assert_eq!(router.resolve_ip("10.12.186.133"), Some("tunnel-b"));
    assert_eq!(router.resolve_ip("10.152.1.1"), Some("tunnel-c"));
    assert_eq!(router.resolve_ip("8.8.8.8"), None); // fallback
}
```

### AT-M3-04：HOST 路由匹配

```rust
#[test]
fn host_routing() {
    let mut router = Router::new();
    router.add_host_exact("git.internal", OutboundId::new("tunnel-b"));
    router.add_host_suffix("*.dev.internal", OutboundId::new("tunnel-b"));

    assert_eq!(router.resolve_host("git.internal"), Some("tunnel-b"));
    assert_eq!(router.resolve_host("app.dev.internal"), Some("tunnel-b"));
    assert_eq!(router.resolve_host("google.com"), None);
}
```

### AT-M3-05：最长前缀匹配

```rust
#[test]
fn longest_prefix_match() {
    let mut router = Router::new();
    router.add_cidr("10.0.0.0/8", OutboundId::new("wide"));
    router.add_cidr("10.12.0.0/16", OutboundId::new("narrow"));

    // 10.12.x.x 命中 /16（更精确）
    assert_eq!(router.resolve_ip("10.12.1.1"), Some("narrow"));
    // 10.13.x.x 命中 /8
    assert_eq!(router.resolve_ip("10.13.1.1"), Some("wide"));
}
```

### AT-M3-06：路由表热更新

```rust
#[tokio::test]
async fn hot_reload_router() {
    let router = Arc::new(ArcSwap::from_pointee(Router::new()));

    // 初始无规则，全部 fallback
    assert_eq!(router.load().resolve_ip("10.12.1.1"), None);

    // 热更新
    let mut new_router = Router::new();
    new_router.add_cidr("10.12.0.0/16", OutboundId::new("tunnel-b"));
    router.store(Arc::new(new_router));

    // 立即生效
    assert_eq!(router.load().resolve_ip("10.12.1.1"), Some("tunnel-b"));
}
```

### AT-M3-07：协议自动探测

```rust
#[tokio::test]
async fn auto_detect_protocol() {
    let proxy = start_proxy("127.0.0.1:0", default_router()).await;
    let addr = proxy.local_addr();

    // 同一个端口，SOCKS5 和 HTTP CONNECT 都能工作
    let socks_ok = test_socks5_connect(addr).await.is_ok();
    let http_ok = test_http_connect(addr).await.is_ok();
    assert!(socks_ok);
    assert!(http_ok);
}
```

## 回归要求

CI 必须通过：AT-M1-* + AT-M3-01 ~ AT-M3-07（M2 如已合入则也包含 AT-M2-*）
