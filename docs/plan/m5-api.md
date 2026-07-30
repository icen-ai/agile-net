# M5：数据库与 API

## 目标

Node 的 HTTP API 全部实现，SQLite 数据库就绪，Postman / curl 可完整测试所有管理功能。

## 依赖

M1 完成（workspace 骨架），M3 完成（proxy 模块提供路由表热更新接口）。

## 产出

1. `agile-net-node` binary 启动 HTTP Server（axum）
2. SQLite 数据库自动建表 + 迁移（rusqlite）
3. 全部 Admin API：auth / rules / groups / accounts / node
4. 全部 Client API：login / config / heartbeat
5. JWT 认证中间件（admin_token + tunnel_token）
6. 配置热更新：API 修改规则 → proxy 路由表实时生效

## 任务清单

- [ ] `node/src/db.rs`：SQLite 连接池 + 建表 DDL（参照 `docs/database/schema.md`）
- [ ] `node/src/auth.rs`：argon2 密码哈希 + JWT 签发/验证
- [ ] `node/src/api/mod.rs`：axum Router 注册所有路由
- [ ] `node/src/api/auth.rs`：POST `/login` + POST `/token/refresh` + POST `/logout`
- [ ] `node/src/api/rules.rs`：规则 CRUD（对应 `docs/api/rules.md`）
- [ ] `node/src/api/groups.rs`：权限组 CRUD + 规则绑定
- [ ] `node/src/api/accounts.rs`：账号 CRUD + 随机密码生成
- [ ] `node/src/api/config.rs`：Client 拉取配置（按 account 权限组 → 规则 → 生成路由配置）
- [ ] `node/src/api/node.rs`：节点状态 / 对等节点列表 / 服务重启
- [ ] JWT 中间件：admin_token 保护 Admin API，tunnel_token 保护 Client API
- [ ] 热更新桥：API 写入 DB 后通知 proxy 模块重新加载路由表

## 验收测试

### AT-M5-01：数据库建表与迁移

```rust
#[tokio::test]
async fn db_init_creates_tables() {
    let db = Database::open_in_memory().await;
    // 所有表存在
    for table in ["rules", "groups", "group_rules", "accounts", "audit_log"] {
        assert!(db.table_exists(table).await);
    }
}
```

### AT-M5-02：Admin 登录流程

```rust
#[tokio::test]
async fn admin_login_and_refresh() {
    let app = start_test_node().await;

    // 登录
    let resp = app.post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "admin123"}))
        .send().await;
    assert_eq!(resp.status(), 200);
    let body: LoginResponse = resp.json().await;
    assert_eq!(body.role, "admin");
    assert!(!body.access_token.is_empty());

    // 用 access_token 访问 Admin API
    let resp = app.get("/api/v1/admin/rules")
        .bearer_auth(&body.access_token)
        .send().await;
    assert_eq!(resp.status(), 200);

    // 刷新 token
    let resp = app.post("/api/v1/auth/token/refresh")
        .bearer_auth(&body.refresh_token)
        .send().await;
    assert_eq!(resp.status(), 200);
}
```

### AT-M5-03：规则 CRUD

```rust
#[tokio::test]
async fn rule_crud() {
    let (app, token) = admin_login().await;

    // 创建
    let resp = app.post("/api/v1/admin/rules")
        .bearer_auth(&token)
        .json(&json!({
            "name": "办公网段",
            "rule_type": "cidr",
            "value": "10.12.0.0/16",
            "action": "proxy"
        }))
        .send().await;
    assert_eq!(resp.status(), 201);
    let rule: Rule = resp.json().await;

    // 读取
    let resp = app.get(&format!("/api/v1/admin/rules/{}", rule.id))
        .bearer_auth(&token)
        .send().await;
    assert_eq!(resp.status(), 200);

    // 更新
    let resp = app.put(&format!("/api/v1/admin/rules/{}", rule.id))
        .bearer_auth(&token)
        .json(&json!({"name": "办公网段-扩展", "value": "10.0.0.0/8"}))
        .send().await;
    assert_eq!(resp.status(), 200);

    // 删除
    let resp = app.delete(&format!("/api/v1/admin/rules/{}", rule.id))
        .bearer_auth(&token)
        .send().await;
    assert_eq!(resp.status(), 204);
}
```

### AT-M5-04：权限组绑定规则

```rust
#[tokio::test]
async fn group_bind_rules() {
    let (app, token) = admin_login().await;

    // 创建规则
    let r1 = create_rule(&app, &token, "cidr", "10.12.0.0/16").await;
    let r2 = create_rule(&app, &token, "host", "git.internal.com").await;

    // 创建权限组
    let group = create_group(&app, &token, "开发组").await;

    // 绑定规则
    let resp = app.put(&format!("/api/v1/admin/groups/{}/rules", group.id))
        .bearer_auth(&token)
        .json(&json!({"rule_ids": [r1.id, r2.id]}))
        .send().await;
    assert_eq!(resp.status(), 200);

    // 查看权限组规则
    let resp = app.get(&format!("/api/v1/admin/groups/{}", group.id))
        .bearer_auth(&token)
        .send().await;
    let g: GroupDetail = resp.json().await;
    assert_eq!(g.rules.len(), 2);
}
```

### AT-M5-05：账号创建并拉取配置

```rust
#[tokio::test]
async fn account_create_and_pull_config() {
    let (app, admin_token) = admin_login().await;

    // 创建规则 + 权限组 + 账号
    let rule = create_rule(&app, &admin_token, "cidr", "10.12.0.0/16").await;
    let group = create_group(&app, &admin_token, "开发组").await;
    bind_rules(&app, &admin_token, group.id, &[rule.id]).await;
    let account = create_account(&app, &admin_token, "zhangsan", group.id).await;

    // 用账号登录（Client 登录）
    let resp = app.post("/api/v1/auth/login")
        .json(&json!({"username": account.username, "password": account.password}))
        .send().await;
    let client_auth: LoginResponse = resp.json().await;
    assert_eq!(client_auth.role, "client");

    // 拉取配置
    let resp = app.get("/api/v1/client/config")
        .bearer_auth(&client_auth.access_token)
        .send().await;
    assert_eq!(resp.status(), 200);
    let config: ClientConfig = resp.json().await;
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].value, "10.12.0.0/16");
}
```

### AT-M5-06：热更新路由表

```rust
#[tokio::test]
async fn hot_reload_routes() {
    let (app, token) = admin_login().await;
    let router = app.proxy_router();

    // 初始无规则
    assert_eq!(router.route_count(), 0);

    // 添加规则
    create_rule(&app, &token, "cidr", "10.12.0.0/16").await;

    // 路由表自动更新
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(router.route_count(), 1);
    assert!(router.matches("10.12.0.1"));
}
```

### AT-M5-07：权限隔离

```rust
#[tokio::test]
async fn permission_isolation() {
    let (app, admin_token) = admin_login().await;
    let account = create_account(&app, &admin_token, "user1", group_id).await;

    // Client token 不能访问 Admin API
    let client_token = client_login(&app, &account).await;
    let resp = app.get("/api/v1/admin/rules")
        .bearer_auth(&client_token)
        .send().await;
    assert_eq!(resp.status(), 403);

    // 无 token 不能访问任何 API
    let resp = app.get("/api/v1/admin/rules").send().await;
    assert_eq!(resp.status(), 401);
}
```

## 回归要求

CI 必须通过：AT-M1-* + AT-M2-* + AT-M3-* + AT-M4-* + AT-M5-01 ~ AT-M5-07
