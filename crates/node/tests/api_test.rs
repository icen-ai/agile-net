//! Admin & Client API integration tests (per docs/api/*.md spec)

use agile_net_node::api::{ApiState, NodeRuntime, create_app};
use agile_net_node::auth::jwt::JwtService;
use agile_net_node::db::{Database, hash_password};
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

/// Build a test App (in-memory DB + empty runtime).
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
        client_proxy_slot: Default::default(),
        transit_meter: agile_net_core::relay::transit::TransitMeter::new(),
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

/// Init admin and log in; returns access_token.
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

// ==================== Auth ====================

#[tokio::test]
async fn auth_init_login_refresh_logout() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;
    assert!(!token.is_empty());

    // Repeat init must be rejected
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

    // Wrong password
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

    // Refresh
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

    // Old refresh_token was rotated out; reuse must fail
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

    // Logout revokes
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

    // 6 bad logins in a row (limit: 5/min)
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
    // No token
    let (status, body) = req(&app, "GET", "/api/v1/admin/rules", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], 40100);

    // client role on admin API → 403
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

// ==================== Rules ====================

#[tokio::test]
async fn rules_crud_flow() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    // Create
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

    // Duplicate create → 409
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

    // Invalid CIDR → 400
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

    // List + pagination
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

    // Update
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

    // Batch import
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

    // Delete
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

// ==================== Groups ====================

#[tokio::test]
async fn groups_flow() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    // Create rule
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

    // Create group (with rule_ids)
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

    // Detail
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

    // Replace rule set (clear)
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

    // Rebind
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

    // Delete referenced rule → 409 + groups list
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

    // Force delete
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

// ==================== Accounts ====================

/// Create group + account; returns client login token.
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

    // Create account: server generates strong password
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
    // "sk-" prefix + 48 chars = 51 total, mixed case + digits
    assert!(password.starts_with("sk-"));
    assert_eq!(password.len(), 51);
    assert!(
        body["data"]["connect_url"]
            .as_str()
            .unwrap()
            .starts_with("agilenet://connect?")
    );
    let account_id = body["data"]["id"].as_str().unwrap().to_string();

    // Weak username rejected
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

    // Reset password
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

    // Old password dead; new one logs in
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

    // Disable → login rejected
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

    // Delete group with accounts → 409
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/groups/{group_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Delete account
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

// ==================== Client config ====================

#[tokio::test]
async fn client_config_scoped_by_group() {
    let (app, db) = test_app().await;
    let admin_token = init_and_login(&app).await;

    // Two rules; only one bound to the account's group
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

    // Fetch config: only bound rules visible
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

    // Heartbeat
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

    // Rule change bumps config version
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

    // Heartbeat bytes counted in stats
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

    // List shows prefix only
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

// ==================== Audit & status ====================

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

    // Rename node
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

/// status traffic contract fields: roles.fanout_traffic / roles.transit / traffic_24h
#[tokio::test]
async fn node_status_traffic_contract() {
    let (app, db) = test_app().await;
    let token = init_and_login(&app).await;

    // Seed 24h series rows (sampler not run here; insert directly to verify aggregation output)
    db.add_node_traffic("fanin", "n1", "", 100, 200).unwrap();
    db.add_node_traffic("fanout", "up-a", "", 7, 8).unwrap();
    db.add_node_traffic("transit", "n1", "n2", 3, 4).unwrap();

    let (status, body) = req(&app, "GET", "/api/v1/admin/node/status", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let data = &body["data"];

    // roles.fanout_traffic: per-connector array (empty when no connectors)
    assert!(data["roles"]["fanout_traffic"].is_array());
    // roles.transit: totals + pairs (live meter snapshot; no data-plane traffic here → all zero/empty)
    assert_eq!(data["roles"]["transit"]["bytes_up"], 0);
    assert_eq!(data["roles"]["transit"]["bytes_down"], 0);
    assert!(data["roles"]["transit"]["pairs"].is_array());
    // traffic_24h: three hourly series (hour is local time "YYYY-MM-DD HH:00")
    let t24 = &data["traffic_24h"];
    assert_eq!(t24["fanin"][0]["up"], 100);
    assert_eq!(t24["fanin"][0]["down"], 200);
    let hour = t24["fanin"][0]["hour"].as_str().unwrap();
    assert_eq!(hour.len(), 16);
    assert!(hour.ends_with(":00"));
    assert_eq!(t24["fanout"][0]["up"], 7);
    assert_eq!(t24["fanout"][0]["down"], 8);
    assert_eq!(t24["transit"][0]["up"], 3);
    assert_eq!(t24["transit"][0]["down"], 4);
}

/// Password hash uses Argon2id and verifies
#[test]
fn password_hash_uses_argon2id() {
    let hash = hash_password("TestPassword123").unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(agile_net_node::db::verify_password("TestPassword123", &hash).unwrap());
}

// ==================== Admin management ====================

#[tokio::test]
async fn admins_management_flow() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;

    // List: 1 initially
    let (status, body) = req(&app, "GET", "/api/v1/admin/admins", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 1);

    // Create
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

    // New admin can log in
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

    // Weak password rejected
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

    // Delete self → rejected
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

    // Delete new admin → ok; its sessions revoked
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

    // Wrong old password → 401
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

    // Correct change
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

    // Old password dead; new one logs in
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
    // Freshly inserted row is not 90 days old; must not be cleaned
    let n = db.cleanup_audit_log(90).unwrap();
    assert_eq!(n, 0);
    let (_, total) = db.list_audit_logs(1, 20, None).unwrap();
    assert_eq!(total, 1);
}
