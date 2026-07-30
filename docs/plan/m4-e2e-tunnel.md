# M4：端到端穿透 (E2E Tunnel)

## 目标

Client → Node-A(公网) → Node-B(内网) → 内网目标，全链路打通。这是 relay + proxy 的集成点，验证整条代理链。

## 依赖

M2 + M3 完成。

## 产出

1. `core::tunnel::pool` — 隧道连接池（Client 到 Node 的 TLS 长连接管理）
2. `core::proxy::outbound::TunnelOutbound` — 通过隧道转发的出站实现
3. Node 整合：relay listener + relay connector + proxy inbound + proxy router 在同一进程协同
4. Client 整合：proxy inbound + router + tunnel pool 在同一进程协同
5. 多节点路由合并（Client 连多个 Node，合并路由表）

## 任务清单

- [ ] TunnelOutbound：proxy 路由命中 Tunnel 出站 → 通过 relay DataChannel 转发
- [ ] 连接池：预建 N 条 DataChannel，用完补充，空闲回收
- [ ] Node 角色整合：listener + connector + proxy 在 main.rs 启动
- [ ] Client 角色整合：proxy + router + tunnel pool 在 main.rs 启动
- [ ] 多节点路由合并逻辑（Client 连 Node-B 和 Node-C，各自下发规则，合并到一张路由表）
- [ ] 隧道认证（account_id + tunnel_token）
- [ ] 集成测试：三进程（Node-A + Node-B + Client）端到端

## 验收测试

### AT-M4-01：Client 到内网目标全链路

```rust
#[tokio::test]
async fn e2e_client_to_internal() {
    // 启动内网 echo server（模拟内网目标 10.12.186.133:8080）
    let echo = start_echo_server("127.0.0.1:0").await;

    // 启动 Node-B（connector 角色 + proxy DIRECT）
    // 路由: echo 的 IP → DIRECT
    let node_b = start_node_b(echo.addr()).await;

    // 启动 Node-A（listener 角色）
    let node_a = start_node_a().await;

    // Node-B 连入 Node-A
    node_b.connect_upstream(node_a.addr()).await;

    // 启动 Client proxy，路由: echo 的 IP → Tunnel(Node-A)
    let client = start_client(node_a.addr(), echo.ip_range()).await;

    // 通过 Client 的 SOCKS5 入站发请求
    let resp = socks5_request(client.proxy_addr(), echo.addr(), "hello").await;
    assert_eq!(resp, "hello");
}
```

### AT-M4-02：多节点路由隔离

```rust
#[tokio::test]
async fn multi_node_routing() {
    // echo-B 模拟 10.12.x.x 网段目标
    let echo_b = start_echo_server_reply("from-B").await;
    // echo-C 模拟 172.16.x.x 网段目标
    let echo_c = start_echo_server_reply("from-C").await;

    let node_a = start_node_a().await;
    let node_b = start_node_b(echo_b.addr()).await;  // 注册 10.12.0.0/16
    let node_c = start_node_c(echo_c.addr()).await;  // 注册 172.16.0.0/12

    node_b.connect_upstream(node_a.addr()).await;
    node_c.connect_upstream(node_a.addr()).await;

    let client = start_client_multi(node_a.addr()).await;

    // 10.12.x.x 走 Node-B
    let resp = request_via_client(client.proxy_addr(), echo_b.addr()).await;
    assert_eq!(resp, "from-B");

    // 172.16.x.x 走 Node-C
    let resp = request_via_client(client.proxy_addr(), echo_c.addr()).await;
    assert_eq!(resp, "from-C");
}
```

### AT-M4-03：非匹配流量走 DIRECT

```rust
#[tokio::test]
async fn non_matching_goes_direct() {
    // 同上设置，但访问 8.8.8.8（不在任何内网段）
    let client = start_client_with_routes().await;

    // 公网目标应该直连，不走隧道
    let resp = http_request(client.proxy_addr(), "http://httpbin.org/ip").await;
    assert_eq!(resp.status(), 200);
    // 验证不走隧道：Node-A 的数据通道计数为 0
    assert_eq!(node_a.data_channel_count(), 0);
}
```

### AT-M4-04：隧道认证失败拒绝客户端

```rust
#[tokio::test]
async fn tunnel_auth_rejected() {
    let node_a = start_node_a().await;
    // 用错误的 tunnel_token 连接
    let result = start_client_with_bad_token(node_a.addr()).await;
    assert!(result.is_err());
}
```

### AT-M4-05：连接池预建和回收

```rust
#[tokio::test]
async fn connection_pool_lifecycle() {
    let pool = TunnelPool::new(config, 5 /* pool_size */).await;

    // 初始预建 5 条
    assert_eq!(pool.available(), 5);

    // 取一条用
    let conn = pool.acquire().await;
    assert_eq!(pool.available(), 4);

    // 用完归还
    drop(conn);
    // 等回收
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(pool.available(), 5);

    // 空闲超时回收（缩短到 1s 测试）
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(pool.available() <= 5); // 可能缩减
}
```

### AT-M4-06：隧道断线后流量降级

```rust
#[tokio::test]
async fn tunnel_disconnect_graceful() {
    // 全链路正常
    let resp = request_via_client(addr, target).await;
    assert!(resp.is_ok());

    // 断开 Node-B ↔ Node-A 的隧道
    node_b.disconnect().await;

    // Client 发请求到内网目标 → 应返回连接错误，不能 hang
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        request_via_client(addr, target),
    ).await;
    assert!(result.is_ok()); // 不超时
    assert!(result.unwrap().is_err()); // 连接错误
}
```

### AT-M4-07：多级串联（三跳）

```rust
#[tokio::test]
async fn three_hop_chain() {
    // Node-A (公网) ← Node-B (中间) ← Node-C (叶子)
    let echo = start_echo_server("hello-leaf").await;
    let node_a = start_listener().await;
    let node_b = start_listener_and_connector(node_a.addr()).await;
    let node_c = start_connector(node_b.addr(), echo.addr()).await;

    let client = start_client(node_a.addr()).await;
    let resp = request_via_client(client.proxy_addr(), echo.addr()).await;
    assert_eq!(resp, "hello-leaf");
}
```

## 回归要求

CI 必须通过：AT-M1-* + AT-M2-* + AT-M3-* + AT-M4-01 ~ AT-M4-07
