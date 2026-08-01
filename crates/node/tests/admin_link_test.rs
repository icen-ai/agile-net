//! P1.6 管理版接入链接集成测试：
//! admin_console 标记 → console-ticket 签发 → admin-bootstrap 换取管理会话 → scope 三档强制。

use agile_net_node::api::{ApiState, NodeRuntime, create_app};
use agile_net_node::auth::jwt::JwtService;
use agile_net_node::db::Database;
use agile_net_node::logs::LogBuffer;
use agile_net_node::service::connectors::ConnectorManager;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Instant;
use tower::ServiceExt;

async fn test_app() -> (Router, Database) {
    let db = Database::in_memory().unwrap();
    let jwt = Arc::new(JwtService::load_or_create(db.clone()).unwrap());
    let runtime = Arc::new(NodeRuntime {
        started_at: Instant::now(),
        listener: None,
        connector_manager: Arc::new(ConnectorManager::new(db.clone())),
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

async fn admin_token(app: &Router) -> String {
    req(
        app,
        "POST",
        "/api/v1/auth/init",
        None,
        Some(json!({
            "username": "admin", "password": "AdminPass123",
        })),
    )
    .await;
    let (_, body) = req(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "admin", "password": "AdminPass123",
        })),
    )
    .await;
    body["data"]["access_token"].as_str().unwrap().to_string()
}

/// 建组 + 建账号（可选管理权限），返回 (account_id, password, connect_url)。
async fn create_account(
    app: &Router,
    admin_token: &str,
    username: &str,
    admin_console: bool,
) -> (String, String, String) {
    let (_, body) = req(
        app,
        "POST",
        "/api/v1/admin/groups",
        Some(admin_token),
        Some(json!({
            "name": format!("g-{username}"),
        })),
    )
    .await;
    let gid = body["data"]["id"].as_str().unwrap().to_string();
    let (status, body) = req(
        app,
        "POST",
        "/api/v1/admin/accounts",
        Some(admin_token),
        Some(json!({
            "username": username, "group_id": gid, "admin_console": admin_console,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create account: {body}");
    (
        body["data"]["id"].as_str().unwrap().to_string(),
        body["data"]["password"].as_str().unwrap().to_string(),
        body["data"]["connect_url"].as_str().unwrap().to_string(),
    )
}

async fn client_login(app: &Router, username: &str, password: &str) -> String {
    let (status, body) = req(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": username, "password": password,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "client login: {body}");
    body["data"]["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn admin_link_full_flow() {
    let (app, db) = test_app().await;
    let token = admin_token(&app).await;

    // 1. 创建管理版账号 → connect_url 带 &admin=1，签发落审计
    let (_id, pw, url) = create_account(&app, &token, "alice", true).await;
    assert!(url.contains("&admin=1"), "管理版链接应带 admin 标记: {url}");
    let has_issue_audit = {
        let (s, b) = req(
            &app,
            "GET",
            "/api/v1/admin/audit-logs?action=account.issue_admin_link",
            Some(&token),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        b["data"]["items"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    };
    assert!(
        has_issue_audit,
        "签发管理链接应落 account.issue_admin_link 审计"
    );

    // 2. 客户端配置响应带 admin_console 标记
    let ctoken = client_login(&app, "alice", &pw).await;
    let (s, b) = req(&app, "GET", "/api/v1/client/config", Some(&ctoken), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["data"]["admin_console"].as_bool(), Some(true));

    // 3. 申请控制台票据 → bootstrap 换取管理会话
    let (s, b) = req(
        &app,
        "POST",
        "/api/v1/client/console-ticket",
        Some(&ctoken),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "console-ticket: {b}");
    let ticket = b["data"]["ticket"].as_str().unwrap().to_string();
    assert!(ticket.starts_with("adt_"));

    let (s, b) = req(
        &app,
        "POST",
        "/api/v1/auth/admin-bootstrap",
        None,
        Some(json!({
            "ticket": ticket,
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "bootstrap: {b}");
    assert_eq!(b["data"]["role"].as_str(), Some("admin"));
    assert_eq!(b["data"]["scope"].as_str(), Some("full"));
    let admin_jwt = b["data"]["access_token"].as_str().unwrap().to_string();

    // 4. 换得的管理会话可访问管理接口
    let (s, _) = req(
        &app,
        "GET",
        "/api/v1/admin/node/status",
        Some(&admin_jwt),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // 5. 票据一次性：再次使用被拒绝
    let (s, _) = req(
        &app,
        "POST",
        "/api/v1/auth/admin-bootstrap",
        None,
        Some(json!({
            "ticket": ticket,
        })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // 6. 换取审计归因：operator 区分链接身份
    let (_, b) = req(
        &app,
        "GET",
        "/api/v1/admin/audit-logs?action=admin.console_access",
        Some(&token),
        None,
    )
    .await;
    let items = b["data"]["items"].as_array().unwrap();
    assert!(
        items
            .iter()
            .any(|i| i["operator"].as_str() == Some("link:alice")),
        "console_access 审计应归因管理链接持有者: {items:?}"
    );

    // 7. 收回管理权限（禁用 admin_console）→ 不再签发票据
    let acc = db.get_account_by_username("alice").unwrap().unwrap().0;
    db.update_account_full(&acc.id, None, None, None, Some(false))
        .unwrap();
    let (s, _) = req(
        &app,
        "POST",
        "/api/v1/client/console-ticket",
        Some(&ctoken),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn non_admin_account_cannot_get_ticket() {
    let (app, _db) = test_app().await;
    let token = admin_token(&app).await;
    let (_id, pw, url) = create_account(&app, &token, "bob", false).await;
    assert!(!url.contains("&admin="), "普通链接不应带 admin 标记: {url}");

    let ctoken = client_login(&app, "bob", &pw).await;
    let (s, b) = req(&app, "GET", "/api/v1/client/config", Some(&ctoken), None).await;
    assert_eq!(b["data"]["admin_console"].as_bool(), Some(false));
    let _ = s;

    let (s, _) = req(
        &app,
        "POST",
        "/api/v1/client/console-ticket",
        Some(&ctoken),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // 伪造票据必然失败（哈希不落库即不存在）
    let (s, _) = req(
        &app,
        "POST",
        "/api/v1/auth/admin-bootstrap",
        None,
        Some(json!({
            "ticket": "adt_forged0000000000000000000000000000000000000000",
        })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn scope_enforcement_three_tiers() {
    let (app, db) = test_app().await;
    let token = admin_token(&app).await;

    // 构造三档票据（relay kind，subject 标识中继来源）
    let mut seq = 10u8;
    for (scope, can_read, can_rule_write, can_account_write) in [
        ("ro", true, false, false),
        ("rules", true, true, false),
        ("full", true, true, true),
    ] {
        seq += 1;
        let ticket = db
            .create_admin_ticket("relay", "psk_test@downstream", scope, 1, 600)
            .unwrap();
        let (s, b) = req(
            &app,
            "POST",
            "/api/v1/auth/admin-bootstrap",
            None,
            Some(json!({
                "ticket": ticket,
            })),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{scope} bootstrap: {b}");
        let jwt = b["data"]["access_token"].as_str().unwrap().to_string();

        let (s, _) = req(&app, "GET", "/api/v1/admin/node/status", Some(&jwt), None).await;
        assert_eq!(s == StatusCode::OK, can_read, "{scope} read");

        let (s, _) = req(
            &app,
            "POST",
            "/api/v1/admin/rules",
            Some(&jwt),
            Some(json!({
                "type": "ip-cidr", "value": format!("10.{seq}.0.0/16"),
            })),
        )
        .await;
        assert_eq!(
            s == StatusCode::CREATED,
            can_rule_write,
            "{scope} rule write: {s}"
        );

        let (s, _) = req(
            &app,
            "POST",
            "/api/v1/admin/groups",
            Some(&jwt),
            Some(json!({
                "name": format!("scope-{scope}"),
            })),
        )
        .await;
        assert_eq!(
            s == StatusCode::CREATED,
            can_account_write,
            "{scope} group write: {s}"
        );

        // relay 换取落审计 admin.session_via_relay
        let (_, b) = req(
            &app,
            "GET",
            "/api/v1/admin/audit-logs?action=admin.session_via_relay",
            Some(&token),
            None,
        )
        .await;
        let items = b["data"]["items"].as_array().unwrap();
        assert!(
            items
                .iter()
                .any(|i| i["operator"].as_str() == Some("relay:psk_test@downstream")),
            "{scope} relay 换取应落审计"
        );
    }
}

#[tokio::test]
async fn update_account_grant_and_revoke_admin() {
    let (app, _db) = test_app().await;
    let token = admin_token(&app).await;
    let (id, pw, _url) = create_account(&app, &token, "carol", false).await;

    // 授予管理权限 → 签发审计
    let (s, _) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/accounts/{id}"),
        Some(&token),
        Some(json!({
            "admin_console": true,
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let ctoken = client_login(&app, "carol", &pw).await;
    let (s, _) = req(
        &app,
        "POST",
        "/api/v1/client/console-ticket",
        Some(&ctoken),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "授予后应可签发票据");

    // 收回管理权限 → 票据签发被拒
    let (s, _) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/accounts/{id}"),
        Some(&token),
        Some(json!({
            "admin_console": false,
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = req(
        &app,
        "POST",
        "/api/v1/client/console-ticket",
        Some(&ctoken),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "收回后应拒绝签发票据");
}
