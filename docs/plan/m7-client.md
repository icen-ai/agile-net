# M7：Client 桌面端

## 目标

Tauri 客户端可连接一个或多个节点，拉取路由配置，启动本地代理，按规则路由流量。系统托盘常驻。

## 依赖

M4（端到端穿透）+ M5（API + 账号认证）完成。

## 产出

1. `agile-net-client` Tauri 应用（Windows 优先，macOS/Linux 后续）
2. 多节点连接管理
3. 本地 SOCKS5/HTTP 代理 + CIDR/HOST 路由
4. 系统托盘 + 状态指示
5. hosts 文件管理（可选）

## 技术选型

| 库 | 用途 |
|----|------|
| Tauri 2 | 桌面框架 |
| React | 前端 UI |
| TailwindCSS | 样式 |
| agile-net-core | 复用 relay + proxy 模块 |

## 页面结构

```
主窗口（从托盘打开）：
├── 节点列表页（首页）
│   ├── + 添加节点（填公网地址 + 账号密码）
│   ├── 每个节点卡片：名称 / 地址 / 状态 / 开关
│   └── 点击展开：该节点下发的规则列表（只读）
├── 流量统计页
│   └── 各节点实时流量、总连接数
└── 设置页
    ├── 代理端口配置
    ├── 开机启动
    └── hosts 管理开关

托盘右键菜单：
├── 显示主窗口
├── 快速开关（全局代理 on/off）
├── 当前状态（已连 N 个节点）
└── 退出
```

## 任务清单

- [ ] Tauri 项目初始化：`client/` 目录
- [ ] Tauri command：`connect_node(addr, username, password)` → 登录 + 拉配置 + 建隧道
- [ ] Tauri command：`disconnect_node(node_id)`
- [ ] Tauri command：`get_nodes()` → 返回所有节点状态
- [ ] Tauri command：`get_traffic_stats()` → 流量统计
- [ ] 代理引擎启停：启动/停止本地 SOCKS5+HTTP 入站
- [ ] 多节点路由合并：多个节点的规则合并到一张路由表
- [ ] 节点凭据持久化：加密存储到本地（tauri-plugin-store / 自己 AES）
- [ ] 系统托盘集成：图标 + 右键菜单 + 状态切换
- [ ] 前端节点列表页：卡片式布局 + 连接/断开
- [ ] 前端设置页：代理端口 + 开机启动
- [ ] Windows 安装包：Tauri NSIS/WiX 打包
- [ ] 自动重连：节点断线后指数退避重连

## 验收测试

### AT-M7-01：连接节点并拉取配置

```rust
#[tokio::test]
async fn client_connect_and_pull_config() {
    let node = start_test_node_with_data().await; // 已有规则+权限组+账号

    let client = AgileNetClient::new();
    let result = client.connect(ConnectParams {
        addr: node.addr(),
        username: "zhangsan".into(),
        password: "generated_pass".into(),
    }).await;

    assert!(result.is_ok());
    let node_state = client.get_node(result.unwrap().node_id).await;
    assert_eq!(node_state.status, NodeStatus::Connected);
    assert!(!node_state.rules.is_empty());
}
```

### AT-M7-02：多节点路由合并

```rust
#[tokio::test]
async fn multi_node_route_merge() {
    let node_a = start_node_with_rules(&["10.12.0.0/16"]).await;
    let node_b = start_node_with_rules(&["172.16.0.0/12"]).await;

    let client = AgileNetClient::new();
    client.connect(node_a.connect_params()).await.unwrap();
    client.connect(node_b.connect_params()).await.unwrap();

    let router = client.proxy_router();
    // 两个节点的规则都在路由表里
    assert!(router.matches("10.12.0.1"));    // → node_a
    assert!(router.matches("172.16.0.1"));   // → node_b
    assert!(!router.matches("8.8.8.8"));     // → DIRECT
}
```

### AT-M7-03：断开节点后路由移除

```rust
#[tokio::test]
async fn disconnect_removes_routes() {
    let node_a = start_node_with_rules(&["10.12.0.0/16"]).await;

    let client = AgileNetClient::new();
    let conn = client.connect(node_a.connect_params()).await.unwrap();

    assert!(client.proxy_router().matches("10.12.0.1"));

    client.disconnect(conn.node_id).await;

    assert!(!client.proxy_router().matches("10.12.0.1"));
}
```

### AT-M7-04：凭据持久化

```rust
#[tokio::test]
async fn credentials_persist() {
    let store = CredentialStore::open_temp().await;

    store.save("node-1", &Credential {
        addr: "1.2.3.4:443".into(),
        username: "zhangsan".into(),
        password: "secret".into(),
    }).await;

    // 重新打开
    let store2 = CredentialStore::open(store.path()).await;
    let cred = store2.get("node-1").await.unwrap();
    assert_eq!(cred.username, "zhangsan");
    assert_eq!(cred.password, "secret"); // 解密后
}
```

### AT-M7-05：代理引擎启停

```rust
#[tokio::test]
async fn proxy_engine_start_stop() {
    let client = AgileNetClient::new();

    // 启动代理
    client.start_proxy(ProxyConfig { port: 0 }).await.unwrap();
    let port = client.proxy_port();
    assert!(port > 0);

    // 可以通过代理发请求
    let resp = socks5_request(("127.0.0.1", port), "httpbin.org:80", "GET /ip").await;
    assert!(resp.is_ok());

    // 停止代理
    client.stop_proxy().await;

    // 端口不再监听
    let resp = TcpStream::connect(("127.0.0.1", port)).await;
    assert!(resp.is_err());
}
```

### AT-M7-06：自动重连

```rust
#[tokio::test]
async fn auto_reconnect() {
    let node = start_test_node_with_data().await;

    let client = AgileNetClient::new();
    client.connect(node.connect_params()).await.unwrap();
    assert_eq!(client.node_status(node.id()), NodeStatus::Connected);

    // 模拟断线
    node.drop_all_connections().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(client.node_status(node.id()), NodeStatus::Reconnecting);

    // 等待重连
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(client.node_status(node.id()), NodeStatus::Connected);
}
```

## 回归要求

CI 必须通过：AT-M1-* ~ AT-M5-* + AT-M7-01 ~ AT-M7-06

AT-M6-* 的 Rust 端测试也须通过（Web UI 的 E2E 除外）。
