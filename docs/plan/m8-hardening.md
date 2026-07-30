# M8：安全加固与生产化

## 目标

所有安全机制到位，可以部署到真实环境使用。产出可分发安装包。

## 依赖

M7 完成（Client 可用）。

## 产出

1. 频率限制（登录、API）
2. 审计日志（所有管理操作）
3. TLS 证书管理（自动 ACME / 手动指定）
4. 配置校验与错误提示
5. 打包脚本（Node binary + Client installer）
6. 运维文档

## 任务清单

### 安全

- [ ] 登录频率限制：IP + 账号维度，5 次/分钟，超限锁定 15 分钟
- [ ] API 频率限制：通用 middleware，100 req/min per token
- [ ] 审计日志写入 `audit_log` 表：操作人 / 操作 / 目标 / 时间 / IP
- [ ] Admin 密码强度校验：≥8 字符，混合大小写+数字
- [ ] 首次启动引导：设置 admin 密码（不使用默认密码）
- [ ] TLS 证书：支持 ACME（Let's Encrypt）自动申请 + 手动指定路径
- [ ] Relay 通信 mTLS（可选，节点间双向证书认证）

### 健壮性

- [ ] 配置文件校验：启动时检查必填项，错误时输出清晰提示并退出
- [ ] 优雅关闭：SIGTERM → 停止接受新连接 → 等待现有连接完成（超时 30s）→ 退出
- [ ] 结构化日志：tracing + JSON 格式，支持 `RUST_LOG` 分级
- [ ] 心跳超时检测：Client/Node 心跳超时后自动标记离线并清理资源

### 打包与分发

- [ ] Node：`cargo build --release` → 单 binary（含 Web UI 静态资源）
- [ ] Node：Docker 镜像（Alpine base）
- [ ] Client：Tauri NSIS 安装包（Windows）
- [ ] Client：Tauri DMG（macOS，后续）
- [ ] GitHub Release 自动化：tag → CI build → 发布

### 文档

- [ ] 部署指南：公网机 Node 部署步骤（含防火墙/端口）
- [ ] 内网机 Node 部署步骤（含上游配置）
- [ ] Client 用户手册：安装 → 添加节点 → 使用
- [ ] 配置文件参考：`agile-net.toml` 所有字段说明

## 验收测试

### AT-M8-01：登录频率限制

```rust
#[tokio::test]
async fn login_rate_limit() {
    let app = start_test_node().await;

    // 连续 5 次错误登录
    for _ in 0..5 {
        let resp = app.post("/api/v1/auth/login")
            .json(&json!({"username": "admin", "password": "wrong"}))
            .send().await;
        // 前 5 次返回 401
        assert_eq!(resp.status(), 401);
    }

    // 第 6 次被限流
    let resp = app.post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "wrong"}))
        .send().await;
    assert_eq!(resp.status(), 429);

    // 正确密码也被限流
    let resp = app.post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "admin123"}))
        .send().await;
    assert_eq!(resp.status(), 429);
}
```

### AT-M8-02：审计日志记录

```rust
#[tokio::test]
async fn audit_log_records() {
    let (app, token) = admin_login().await;

    // 创建规则
    create_rule(&app, &token, "cidr", "10.0.0.0/8").await;

    // 查审计日志
    let resp = app.get("/api/v1/admin/node/audit-log")
        .bearer_auth(&token)
        .send().await;
    let logs: Vec<AuditEntry> = resp.json().await;

    // 至少有登录 + 创建规则两条
    assert!(logs.len() >= 2);
    assert!(logs.iter().any(|e| e.action == "login"));
    assert!(logs.iter().any(|e| e.action == "rule.create"));
}
```

### AT-M8-03：优雅关闭

```rust
#[tokio::test]
async fn graceful_shutdown() {
    let node = start_test_node().await;
    let client = connect_client(&node).await;

    // 建立一个活跃连接
    let _stream = open_tunnel(&client).await;

    // 发送 shutdown 信号
    node.signal_shutdown();

    // 现有连接应正常完成
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        send_data_and_recv(&_stream, "hello"),
    ).await;
    assert!(result.is_ok());

    // 新连接被拒绝
    let new_conn = TcpStream::connect(node.addr()).await;
    assert!(new_conn.is_err());
}
```

### AT-M8-04：首次启动引导

```rust
#[tokio::test]
async fn first_run_setup() {
    let node = start_fresh_node().await; // 全新数据库

    // 首次启动，admin 密码为空，API 返回 setup_required
    let resp = reqwest::get(format!("http://{}/api/v1/admin/node/status", node.addr())).await.unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["setup_required"], true);

    // 设置密码
    let resp = reqwest::Client::new()
        .post(format!("http://{}/api/v1/setup", node.addr()))
        .json(&json!({"admin_password": "MyStr0ngP@ss"}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // 可以用新密码登录
    let resp = reqwest::Client::new()
        .post(format!("http://{}/api/v1/auth/login", node.addr()))
        .json(&json!({"username": "admin", "password": "MyStr0ngP@ss"}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
}
```

### AT-M8-05：TLS 证书加载

```rust
#[tokio::test]
async fn tls_cert_loading() {
    // 生成自签证书
    let (cert_path, key_path) = generate_self_signed_cert().await;

    let node = start_node_with_tls(&cert_path, &key_path).await;

    // HTTPS 可连接
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build().unwrap();
    let resp = client.get(format!("https://{}/api/v1/admin/node/status", node.addr()))
        .send().await.unwrap();
    assert_eq!(resp.status(), 200); // 未登录但不是连接错误
}
```

### AT-M8-06：结构化日志

```rust
#[tokio::test]
async fn structured_logging() {
    let log_output = capture_node_logs(|| async {
        let node = start_test_node().await;
        admin_login_to(&node).await;
    }).await;

    // 日志包含 JSON 格式
    let lines: Vec<&str> = log_output.lines().collect();
    assert!(!lines.is_empty());

    // 至少一行可解析为 JSON
    let parsed = lines.iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect::<Vec<_>>();
    assert!(!parsed.is_empty());

    // JSON 日志包含 level 和 message
    assert!(parsed[0].get("level").is_some());
    assert!(parsed[0].get("message").is_some() || parsed[0].get("msg").is_some());
}
```

## 回归要求

CI 必须通过：**所有里程碑的全部测试**（AT-M1-* ~ AT-M8-*）

这是最终的全量回归门禁，任何历史测试失败都阻塞发布。

## 发布检查清单

- [ ] `cargo clippy --workspace -- -D warnings` 零警告
- [ ] `cargo test --workspace` 全部通过
- [ ] `cargo audit` 无已知漏洞
- [ ] Node binary 大小 < 20MB（含 Web UI）
- [ ] Client installer 大小 < 30MB
- [ ] 部署文档可跟随操作，无遗漏步骤
- [ ] CHANGELOG 已更新
