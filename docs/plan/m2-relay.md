# M2：核心穿透 (Relay)

## 目标

两个 Node 实例间建立 TLS 1.3 加密隧道，可以透传任意 TCP 连接。

## 依赖

M1 完成。

## 产出

1. `core::relay::frame` — 帧编解码（Auth / NewConnection / DataChannel / Ping / Pong / Shutdown）
2. `core::relay::listener` — 上游角色：TLS 监听 → 认证 → 管理控制连接 → 桥接数据通道
3. `core::relay::connector` — 下游角色：TLS 连接 → 认证 → 响应 NewConnection → 建立数据通道
4. `core::relay::bridge` — 双向零拷贝数据转发 (`tokio::io::copy_bidirectional`)
5. `core::proto::auth` — 认证帧定义
6. `core::tunnel::tls` — 共享 TLS 配置（rustls ServerConfig / ClientConfig）
7. 自签证书自动生成（开发环境）

## 任务清单

- [ ] 帧编解码 + 单元测试
- [ ] TLS 配置模块（自签证书生成 + 加载外部证书）
- [ ] Listener：接受连入 → TLS 握手 → 读 AuthFrame → 验证 token → 注册会话
- [ ] Connector：连接 → TLS 握手 → 发 AuthFrame → 等 AuthResult
- [ ] 控制通道心跳（Ping/Pong + 超时检测）
- [ ] NewConnection / DataChannel 通知 + 建立
- [ ] Bridge 双向转发
- [ ] Connector 断线重连（指数退避 + 抖动）
- [ ] 集成测试：两个进程穿透 TCP

## 验收测试

### AT-M2-01：帧编解码往返

```rust
#[test]
fn frame_roundtrip() {
    let frame = Frame::Auth { token: "test_token".into() };
    let bytes = frame.encode();
    let decoded = Frame::decode(&bytes).unwrap();
    assert_eq!(frame, decoded);
}
// 覆盖全部 7 种帧类型
```

### AT-M2-02：TLS 隧道建立

```rust
#[tokio::test]
async fn tls_tunnel_established() {
    let (listener, connector) = setup_test_pair().await;
    // Connector 成功连入 Listener
    // 双方 Control Channel 建立
    assert!(connector.is_connected());
    assert_eq!(listener.connected_count(), 1);
}
```

### AT-M2-03：TCP 穿透

```rust
#[tokio::test]
async fn tcp_passthrough() {
    // 1. 启动 Listener (端口 A) + 一个 echo TCP server (端口 B)
    // 2. Connector 连入 Listener，注册转发 localhost:B
    // 3. 外部 TCP 客户端连接 Listener:A
    // 4. 发送 "hello" → 收到 "hello"（echo）
    let response = send_through_tunnel("hello").await;
    assert_eq!(response, "hello");
}
```

### AT-M2-04：认证失败拒绝

```rust
#[tokio::test]
async fn auth_rejected_with_wrong_token() {
    let listener = start_listener("correct_token").await;
    let result = try_connect("wrong_token").await;
    assert!(result.is_err());
}
```

### AT-M2-05：心跳超时断开

```rust
#[tokio::test]
async fn heartbeat_timeout_disconnects() {
    // 建立连接后，Connector 停止发 Ping
    // 等待 > 90s（或在测试中缩短超时）
    // 验证 Listener 关闭了该 Connector 的会话
    tokio::time::pause();
    // ... 快进时间 ...
    assert_eq!(listener.connected_count(), 0);
}
```

### AT-M2-06：断线重连

```rust
#[tokio::test]
async fn reconnect_after_disconnect() {
    let listener = start_listener("token").await;
    let connector = start_connector("token").await;
    assert!(connector.is_connected());

    // 模拟 Listener 重启
    listener.restart().await;

    // 等待重连（指数退避，最多几秒）
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(connector.is_connected());
}
```

### AT-M2-07：并发数据通道

```rust
#[tokio::test]
async fn concurrent_data_channels() {
    // 同时建立 10 条数据通道，各自独立转发
    let handles: Vec<_> = (0..10).map(|i| {
        tokio::spawn(async move {
            let resp = send_through_tunnel(&format!("msg-{i}")).await;
            assert_eq!(resp, format!("msg-{i}"));
        })
    }).collect();
    for h in handles { h.await.unwrap(); }
}
```

## 回归要求

CI 必须通过：AT-M1-01 ~ AT-M1-04 + AT-M2-01 ~ AT-M2-07
