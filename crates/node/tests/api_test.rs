//! Admin & Client API 集成测试（对应 docs/api/*.md 规格）

use agile_net_node::api::{ApiState, NodeRuntime, create_app};
use agile_net_node::auth::jwt::JwtService;
use agile_net_node::db::{Database, hash_password};
use agile_net_node::logs::LogBuffer;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Instant;
use tower::ServiceExt;

/// 构建测试用 App（内存数据库 + 空运行时）。
async fn test_app() -> (Router, Database) {
    let db = Database::in_memory().unwrap();
    let jwt = Arc::new(JwtService::load_or_create(db.clone()).unwrap());
    let runtime = Arc::new(NodeRuntime {
        started_at: Instant::now(),
        listener: None,
        connectors: Vec::new(),
        proxy_stats: None,
        proxy_listen: None,
        log_buffer: LogBuffer::new(),
        cert_fingerprint: None,
        manageable: Default::default(),
    });
    let state = ApiState::new(db.clone(), jwt, runtime, "127.0.0.1".into(), 59090, 54430);
    (create_app(state), db)
}

async fn req(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let body_str = match &body {
        Some(b) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            b.to_string()
        }
        None => String::new(),
    };
    let request = builder.body(Body::from(body_str)).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    (status, json)
}

/// 初始化 admin 并登录，返回 access_token。
async fn init_and_login(app: &Router) -> String {
    let (status, _) = req(
        app,
        "POST",
        "/api/v1/auth/init",
        None,
        Some(json!({
            "username": "admin",
            "password": "AdminPass123",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = req(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "admin",
            "password": "AdminPass123",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["code"], 0);
    body["data"]["access_token"].as_str().unwrap().to_string()
}

// ==================== 认证 ====================

#[tokio::test]
async fn auth_init_login_refresh_logout() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;
    assert!(!token.is_empty());

    // 重复 init 应被拒绝
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/auth/init",
        None,
        Some(json!({
            "username": "admin2",
            "password": "AdminPass456",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], 40300);

    // 错误密码
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "admin",
            "password": "WrongPass123",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], 40100);

    // me
    let (status, body) = req(&app, "GET", "/api/v1/auth/me", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["role"], "admin");

    // 刷新
    let (_, login_body) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "admin",
            "password": "AdminPass123",
        })),
    )
    .await;
    let refresh_token = login_body["data"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(json!({
            "refresh_token": refresh_token,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["access_token"].is_string());

    // 旧 refresh_token 已被轮换吊销，再次使用应失败
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(json!({
            "refresh_token": refresh_token,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 登出吊销
    let new_refresh = body["data"]["refresh_token"].as_str().unwrap().to_string();
    let new_access = body["data"]["access_token"].as_str().unwrap().to_string();
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/logout",
        Some(&new_access),
        Some(json!({
            "refresh_token": new_refresh,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(json!({
            "refresh_token": new_refresh,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rate_limited() {
    let (app, _db) = test_app().await;
    init_and_login(&app).await;

    // 连续 6 次错误登录（限制 5 次/分钟）
    let mut last_status = StatusCode::OK;
    for _ in 0..6 {
        let (status, _) = req(
            &app,
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({
                "username": "admin",
                "password": "WrongPass999",
            })),
        )
        .await;
        last_status = status;
    }
    assert_eq!(last_status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn unauthenticated_and_role_enforcement() {
    let (app, _db) = test_app().await;
    // 无 token
    let (status, body) = req(&app, "GET", "/api/v1/admin/rules", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], 40100);

    // client 角色访问 admin API → 403
    let admin_token = init_and_login(&app).await;
    let account_token = create_account_and_login(&app, &admin_token).await;
    let (status, body) = req(
        &app,
        "GET",
        "/api/v1/admin/rules",
        Some(&account_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], 40301);
}

// ==================== 规则 ====================

#[tokio::test]
async fn rules_crud_flow() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    // 创建
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/rules",
        Some(&token),
        Some(json!({
            "type": "ip-cidr",
            "value": "10.12.0.0/16",
            "remark": "办公网",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let rule_id = body["data"]["id"].as_str().unwrap().to_string();

    // 重复创建 → 409
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/rules",
        Some(&token),
        Some(json!({
            "type": "ip-cidr",
            "value": "10.12.0.0/16",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], 40900);

    // 非法 CIDR → 400
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/rules",
        Some(&token),
        Some(json!({
            "type": "ip-cidr",
            "value": "999.999.0.0/16",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // 列表 + 分页
    let (status, body) = req(
        &app,
        "GET",
        "/api/v1/admin/rules?page=1&page_size=10",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["total"], 1);

    // 更新
    let (status, body) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/rules/{rule_id}"),
        Some(&token),
        Some(json!({
            "remark": "扩大到办公全网",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["remark"], "扩大到办公全网");

    // 批量导入
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/rules/batch",
        Some(&token),
        Some(json!({
            "rules": [
                { "type": "ip-cidr", "value": "10.12.0.0/16" },
                { "type": "host", "value": "git.internal", "resolve": true },
                { "type": "host", "value": "wiki.internal" }
            ],
            "on_conflict": "skip"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "batch body: {body}");
    assert_eq!(body["data"]["created"], 2);
    assert_eq!(body["data"]["skipped"], 1);

    // 删除
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/rules/{rule_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ==================== 权限组 ====================

#[tokio::test]
async fn groups_flow() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    // 创建规则
    let (_, body) = req(
        &app,
        "POST",
        "/api/v1/admin/rules",
        Some(&token),
        Some(json!({
            "type": "ip-cidr", "value": "172.16.0.0/12",
        })),
    )
    .await;
    let rule_id = body["data"]["id"].as_str().unwrap().to_string();

    // 创建权限组（含 rule_ids）
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/groups",
        Some(&token),
        Some(json!({
            "name": "开发组",
            "remark": "前后端",
            "rule_ids": [rule_id],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let group_id = body["data"]["id"].as_str().unwrap().to_string();

    // 详情
    let (status, body) = req(
        &app,
        "GET",
        &format!("/api/v1/admin/groups/{group_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["rules"].as_array().unwrap().len(), 1);

    // 全量设置规则（清空）
    let (status, body) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/groups/{group_id}/rules"),
        Some(&token),
        Some(json!({
            "rule_ids": [],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["rule_count"], 0);

    // 重新绑定
    req(
        &app,
        "PUT",
        &format!("/api/v1/admin/groups/{group_id}/rules"),
        Some(&token),
        Some(json!({
            "rule_ids": [rule_id],
        })),
    )
    .await;

    // 删除被引用的规则 → 409 + groups 列表
    let (status, body) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/rules/{rule_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body["data"]["groups"]
            .as_array()
            .unwrap()
            .contains(&json!("开发组"))
    );

    // 强制删除
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/rules/{rule_id}?force=true"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ==================== 账号 ====================

/// 创建权限组 + 账号，返回 client 登录 token。
async fn create_account_and_login(app: &Router, admin_token: &str) -> String {
    let (_, body) = req(
        app,
        "POST",
        "/api/v1/admin/groups",
        Some(admin_token),
        Some(json!({
            "name": "默认组",
        })),
    )
    .await;
    let group_id = body["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = req(
        app,
        "POST",
        "/api/v1/admin/accounts",
        Some(admin_token),
        Some(json!({
            "username": "zhangsan",
            "group_id": group_id,
            "remark": "张三",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let password = body["data"]["password"].as_str().unwrap().to_string();

    let (status, body) = req(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "zhangsan",
            "password": password,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["role"], "client");
    assert!(body["data"]["tunnel_token"].is_string());
    body["data"]["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn accounts_strong_password_and_lifecycle() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    let (_, body) = req(
        &app,
        "POST",
        "/api/v1/admin/groups",
        Some(&token),
        Some(json!({
            "name": "运维组",
        })),
    )
    .await;
    let group_id = body["data"]["id"].as_str().unwrap().to_string();

    // 创建账号：服务端生成强密码
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/accounts",
        Some(&token),
        Some(json!({
            "username": "lisi",
            "group_id": group_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let password = body["data"]["password"].as_str().unwrap();
    // sk- 前缀 + 48 位 = 51 字符，混合大小写与数字
    assert!(password.starts_with("sk-"));
    assert_eq!(password.len(), 51);
    assert!(
        body["data"]["connect_url"]
            .as_str()
            .unwrap()
            .starts_with("agilenet://connect?")
    );
    let account_id = body["data"]["id"].as_str().unwrap().to_string();

    // 弱用户名校验
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/accounts",
        Some(&token),
        Some(json!({
            "username": "a",
            "group_id": group_id,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // 重置密码
    let (status, body) = req(
        &app,
        "POST",
        &format!("/api/v1/admin/accounts/{account_id}/reset-password"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let new_password = body["data"]["password"].as_str().unwrap();
    assert!(new_password.starts_with("sk-"));
    assert_ne!(new_password, password);

    // 旧密码失效，新密码可登录
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "lisi", "password": password,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "lisi", "password": new_password,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 禁用 → 登录被拒
    let (status, _) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/accounts/{account_id}"),
        Some(&token),
        Some(json!({
            "enabled": false,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "lisi", "password": new_password,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 组下存在账号时删组 → 409
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/groups/{group_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // 删除账号
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/accounts/{account_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ==================== 客户端配置 ====================

#[tokio::test]
async fn client_config_scoped_by_group() {
    let (app, db) = test_app().await;
    let admin_token = init_and_login(&app).await;

    // 两条规则，仅一条绑定到账号所在组
    let (_, b1) = req(
        &app,
        "POST",
        "/api/v1/admin/rules",
        Some(&admin_token),
        Some(json!({
            "type": "ip-cidr", "value": "10.12.0.0/16",
        })),
    )
    .await;
    let rule_a = b1["data"]["id"].as_str().unwrap().to_string();
    req(
        &app,
        "POST",
        "/api/v1/admin/rules",
        Some(&admin_token),
        Some(json!({
            "type": "ip-cidr", "value": "192.168.0.0/16",
        })),
    )
    .await;

    let (_, body) = req(
        &app,
        "POST",
        "/api/v1/admin/groups",
        Some(&admin_token),
        Some(json!({
            "name": "一组", "rule_ids": [rule_a],
        })),
    )
    .await;
    let group_id = body["data"]["id"].as_str().unwrap().to_string();

    let (_, body) = req(
        &app,
        "POST",
        "/api/v1/admin/accounts",
        Some(&admin_token),
        Some(json!({
            "username": "wangwu", "group_id": group_id,
        })),
    )
    .await;
    let password = body["data"]["password"].as_str().unwrap().to_string();

    let (_, body) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "wangwu", "password": password,
        })),
    )
    .await;
    let client_token = body["data"]["access_token"].as_str().unwrap().to_string();

    // 拉取配置：只应看到绑定规则
    let (status, body) = req(
        &app,
        "GET",
        "/api/v1/client/config",
        Some(&client_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rules = body["data"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["value"], "10.12.0.0/16");
    assert!(body["data"]["tunnel"]["port"].is_number());
    let version = body["data"]["version"].as_u64().unwrap();

    // 心跳
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/client/heartbeat",
        Some(&client_token),
        Some(json!({
            "uptime": 10, "bytes_tx": 100, "bytes_rx": 200, "active_connections": 1,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["force_disconnect"], false);

    // 变更规则 → 配置版本递增
    req(
        &app,
        "POST",
        "/api/v1/admin/rules",
        Some(&admin_token),
        Some(json!({
            "type": "host", "value": "git.internal",
        })),
    )
    .await;
    let new_version = db.config_version().unwrap();
    assert!(new_version > version);

    // 心跳流量计入统计
    let (rows, tx, rx) = db.traffic_by_account(1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(tx, 100);
    assert_eq!(rx, 200);
}

// ==================== Relay Token ====================

#[tokio::test]
async fn relay_tokens_lifecycle() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/node/relay-tokens",
        Some(&token),
        Some(json!({
            "remark": "分公司跳板",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let full_token = body["data"]["token"].as_str().unwrap().to_string();
    assert!(full_token.starts_with("psk_"));
    let token_id = body["data"]["id"].as_str().unwrap().to_string();

    // 列表只显示前缀
    let (status, body) = req(
        &app,
        "GET",
        "/api/v1/admin/node/relay-tokens",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0]["token_prefix"].as_str().unwrap().ends_with("****"));
    assert!(items[0].get("token").is_none());

    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/node/relay-tokens/{token_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ==================== 审计与状态 ====================

#[tokio::test]
async fn audit_logs_and_node_status() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    req(
        &app,
        "POST",
        "/api/v1/admin/groups",
        Some(&token),
        Some(json!({ "name": "审计组" })),
    )
    .await;

    let (status, body) = req(&app, "GET", "/api/v1/admin/audit-logs", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["data"]["items"].as_array().unwrap();
    assert!(items.iter().any(|i| i["action"] == "group.create"));
    assert!(items.iter().any(|i| i["action"] == "admin.login"));

    let (status, body) = req(&app, "GET", "/api/v1/admin/node/status", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["data"]["uptime"].is_number());

    // 更新节点名
    let (status, body) = req(
        &app,
        "PUT",
        "/api/v1/admin/node/settings",
        Some(&token),
        Some(json!({
            "node_name": "办公网跳板",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["data"]["applied"]
            .as_array()
            .unwrap()
            .contains(&json!("node_name"))
    );

    let (_, body) = req(&app, "GET", "/api/v1/admin/node/status", Some(&token), None).await;
    assert_eq!(body["data"]["node_name"], "办公网跳板");
}

/// 密码哈希使用 Argon2id 且可验证
#[test]
fn password_hash_uses_argon2id() {
    let hash = hash_password("TestPassword123").unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(agile_net_node::db::verify_password("TestPassword123", &hash).unwrap());
}

// ==================== 管理员管理 ====================

#[tokio::test]
async fn admins_management_flow() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    // 列表：初始 1 个
    let (status, body) = req(&app, "GET", "/api/v1/admin/admins", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 1);

    // 新建
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/admins",
        Some(&token),
        Some(json!({
            "username": "ops_admin", "password": "OpsPass12345",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let new_id = body["data"]["id"].as_str().unwrap().to_string();

    // 新管理员可登录
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "ops_admin", "password": "OpsPass12345",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 弱密码拒绝
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/admins",
        Some(&token),
        Some(json!({
            "username": "weak_admin", "password": "short",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // 删除自己 → 拒绝
    let me_id = body["data"]["id"].as_str().unwrap();
    let _ = me_id;
    let (_, me) = req(&app, "GET", "/api/v1/auth/me", Some(&token), None).await;
    let self_id = me["data"]["id"].as_str().unwrap().to_string();
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/admins/{self_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // 删除新管理员 → 成功，其会话被吊销
    let (_, login2) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "ops_admin", "password": "OpsPass12345",
        })),
    )
    .await;
    let refresh2 = login2["data"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/admins/{new_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(json!({
            "refresh_token": refresh2,
        })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "被删管理员的 refresh token 必须失效"
    );
}

#[tokio::test]
async fn change_password_flow() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    // 旧密码错误 → 401
    let (status, _) = req(
        &app,
        "PUT",
        "/api/v1/auth/password",
        Some(&token),
        Some(json!({
            "old_password": "WrongOld123", "new_password": "NewPass12345",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 正确修改
    let (status, _) = req(
        &app,
        "PUT",
        "/api/v1/auth/password",
        Some(&token),
        Some(json!({
            "old_password": "AdminPass123", "new_password": "NewPass12345",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 旧密码失效，新密码可登录
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "admin", "password": "AdminPass123",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "admin", "password": "NewPass12345",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn audit_retention_cleanup() {
    let (_app, db) = test_app().await;
    db.record_audit_log(None, "admin", "recent.action", None, None, None)
        .unwrap();
    // 刚插入的不是 90 天前，不应被清理
    let n = db.cleanup_audit_log(90).unwrap();
    assert_eq!(n, 0);
    let (_, total) = db.list_audit_logs(1, 20, None).unwrap();
    assert_eq!(total, 1);
}
