//! Peer ACL (peer scoping) integration tests:
//! ConnectorManager DB→runtime state flow, connector admin API (with audit redaction),
//! relay token group-mount API, and group detail listing all three identity kinds.

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

// ==================== ConnectorManager (DB → runtime behavior, no real tunnel) ====================

#[tokio::test]
async fn connector_manager_upsert_remove_lifecycle() {
    let db = Database::in_memory().unwrap();
    let manager = ConnectorManager::new(db.clone()).with_node_id("test-node".into());

    // Insert an enabled connector in DB (unreachable addr; failed dial just enters reconnect backoff)
    let rec = db
        .create_connector(
            "site-a",
            "127.0.0.1:1",
            "psk_test-token",
            "",
            true,
            "",
            "",
            "",
            None,
            "",
        )
        .expect("create connector");

    // upsert → handle appears, states carry addr and live status
    manager.upsert_from_db(&rec.id).await.expect("upsert");
    let states = manager.states();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].0, "127.0.0.1:1");
    assert!(matches!(
        states[0].1.as_str(),
        "connecting" | "reconnecting" | "disconnected"
    ));
    assert!(manager.state_of(&rec.id).is_some());
    assert_ne!(manager.aggregate_status(), "disabled");

    // upsert after disable → handle removed (aggregate back to disabled)
    db.set_connector_enabled(&rec.id, false).unwrap();
    manager.upsert_from_db(&rec.id).await.expect("upsert off");
    assert!(manager.states().is_empty());
    assert_eq!(manager.state_of(&rec.id), None);
    assert_eq!(manager.aggregate_status(), "disabled");

    // re-enable → handle restored
    db.set_connector_enabled(&rec.id, true).unwrap();
    manager.upsert_from_db(&rec.id).await.expect("upsert on");
    assert_eq!(manager.states().len(), 1);

    // remove → disconnect and drop
    manager.remove(&rec.id).await;
    assert!(manager.states().is_empty());
    assert_eq!(manager.aggregate_status(), "disabled");
}

#[tokio::test]
async fn connector_manager_start_all_skips_disabled() {
    let db = Database::in_memory().unwrap();
    let a = db
        .create_connector("a", "127.0.0.1:1", "psk_a", "", true, "", "", "", None, "")
        .unwrap();
    let b = db
        .create_connector("b", "127.0.0.1:2", "psk_b", "", true, "", "", "", None, "")
        .unwrap();
    db.set_connector_enabled(&b.id, false).unwrap();

    let manager = ConnectorManager::new(db.clone());
    manager.start_all().await;
    let states = manager.states();
    assert_eq!(states.len(), 1, "只装配 enabled 的 connector");
    assert_eq!(states[0].0, "127.0.0.1:1");
    assert!(manager.state_of(&a.id).is_some());
    assert_eq!(manager.state_of(&b.id), None);

    manager.shutdown().await;
    assert!(manager.states().is_empty());
}

// ==================== Admin API ====================

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
    body["data"]["access_token"].as_str().unwrap().to_string()
}

/// Create a group; returns group id.
async fn mk_group(app: &Router, token: &str, name: &str) -> String {
    let (status, body) = req(
        app,
        "POST",
        "/api/v1/admin/groups",
        Some(token),
        Some(json!({ "name": name })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    body["data"]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn connector_api_crud_and_audit_sanitized() {
    let (app, db) = test_app().await;
    let token = init_and_login(&app).await;
    let gid = mk_group(&app, &token, "peers").await;
    let secret = "psk_secret-connector-token-0123456789";

    // Create (group mount + advertise array)
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/connectors",
        Some(&token),
        Some(json!({
            "name": "site-a",
            "upstream_addr": "127.0.0.1:1",
            "token": secret,
            "advertise": ["10.0.0.0/8", "git.internal"],
            "group_id": gid,
            "remark": "站点 A",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    assert!(
        !body.to_string().contains(secret),
        "创建响应不得回显 token"
    );
    assert_eq!(body["data"]["advertise"], "10.0.0.0/8,git.internal");
    assert_eq!(body["data"]["group_name"], "peers");
    assert_eq!(body["data"]["token_prefix"], "psk_secr");
    assert!(matches!(
        body["data"]["state"].as_str().unwrap(),
        "connecting" | "reconnecting" | "disconnected"
    ));
    let cid = body["data"]["id"].as_str().unwrap().to_string();

    // duplicate name → 409
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/connectors",
        Some(&token),
        Some(json!({ "name": "site-a", "upstream_addr": "127.0.0.1:9", "token": "psk_x" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // nonexistent group → 404
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/connectors",
        Some(&token),
        Some(json!({
            "name": "site-b",
            "upstream_addr": "127.0.0.1:9",
            "token": "psk_x",
            "group_id": "no-such-group",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Update: empty token = keep old value; change addr and unmount group
    let (status, body) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/connectors/{cid}"),
        Some(&token),
        Some(json!({
            "name": "site-a",
            "upstream_addr": "127.0.0.1:2",
            "group_id": Value::Null,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update: {body}");
    assert_eq!(body["data"]["upstream_addr"], "127.0.0.1:2");
    assert_eq!(body["data"]["group_id"], Value::Null);
    assert_eq!(
        db.get_connector_secret(&cid).unwrap(),
        secret,
        "token 留空应保留原值"
    );

    // Disable → DB row kept, runtime handle removed (state falls back to disconnected)
    let (status, body) = req(
        &app,
        "POST",
        &format!("/api/v1/admin/connectors/{cid}/disable"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["enabled"], false);
    assert_eq!(body["data"]["state"], "disconnected");

    // Enable → reassemble
    let (status, body) = req(
        &app,
        "POST",
        &format!("/api/v1/admin/connectors/{cid}/enable"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["enabled"], true);

    // List carries view and state
    let (status, body) = req(&app, "GET", "/api/v1/admin/connectors", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0]["state"].is_string());
    assert!(!body.to_string().contains(secret), "列表不得含 token");

    // Audit redaction: no connector audit entry holds token plaintext/ciphertext
    let token_enc = db.get_connector(&cid).unwrap().unwrap().token_enc;
    let (status, body) = req(
        &app,
        "GET",
        "/api/v1/admin/audit-logs?page_size=100",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let audit_dump = body.to_string();
    assert!(audit_dump.contains("connector.create"));
    assert!(audit_dump.contains("connector.update"));
    assert!(audit_dump.contains("connector.disable"));
    assert!(audit_dump.contains("connector.enable"));
    assert!(!audit_dump.contains(secret), "审计不得含 token 明文");
    assert!(!audit_dump.contains(&token_enc), "审计不得含 token 密文");

    // Delete → runtime removal; further ops 404
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/v1/admin/connectors/{cid}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = req(
        &app,
        "POST",
        &format!("/api/v1/admin/connectors/{cid}/enable"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn relay_token_group_mount_via_api() {
    let (app, _) = test_app().await;
    let token = init_and_login(&app).await;
    let gid = mk_group(&app, &token, "peers").await;

    // Create grouped token
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/node/relay-tokens",
        Some(&token),
        Some(json!({ "remark": "对端甲", "group_id": gid })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    assert_eq!(body["data"]["group_id"], gid);
    let tid = body["data"]["id"].as_str().unwrap().to_string();

    // List carries group info
    let (_, body) = req(
        &app,
        "GET",
        "/api/v1/admin/node/relay-tokens",
        Some(&token),
        None,
    )
    .await;
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items[0]["group_id"], gid);
    assert_eq!(items[0]["group_name"], "peers");

    // PUT without group_id field → mount unchanged
    let (status, body) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/node/relay-tokens/{tid}"),
        Some(&token),
        Some(json!({ "expose_control": false, "control_scope": "full" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["group_id"], gid);

    // PUT group_id=null → unmount
    let (status, body) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/node/relay-tokens/{tid}"),
        Some(&token),
        Some(json!({ "expose_control": false, "control_scope": "full", "group_id": Value::Null })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["group_id"], Value::Null);

    // PUT mount to nonexistent group → 404
    let (status, _) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/node/relay-tokens/{tid}"),
        Some(&token),
        Some(json!({ "expose_control": false, "group_id": "no-such-group" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Audit contains set_group event
    let (_, body) = req(
        &app,
        "GET",
        "/api/v1/admin/audit-logs?page_size=100",
        Some(&token),
        None,
    )
    .await;
    assert!(body.to_string().contains("relay_token.set_group"));
}

#[tokio::test]
async fn group_detail_lists_three_identity_kinds() {
    let (app, _) = test_app().await;
    let token = init_and_login(&app).await;
    let gid = mk_group(&app, &token, "peers").await;

    // Mount three identity kinds: account / fan-in token / fan-out peer
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/accounts",
        Some(&token),
        Some(json!({ "username": "alice", "group_id": gid })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/node/relay-tokens",
        Some(&token),
        Some(json!({ "remark": "对端甲", "group_id": gid })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/connectors",
        Some(&token),
        Some(json!({
            "name": "site-a",
            "upstream_addr": "127.0.0.1:1",
            "token": "psk_detail-test",
            "group_id": gid,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = req(
        &app,
        "GET",
        &format!("/api/v1/admin/groups/{gid}/detail"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "detail: {body}");
    let accounts = body["data"]["accounts"].as_array().unwrap();
    let relay_tokens = body["data"]["relay_tokens"].as_array().unwrap();
    let connectors = body["data"]["connectors"].as_array().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0]["username"], "alice");
    assert_eq!(relay_tokens.len(), 1);
    assert!(relay_tokens[0]["token_prefix"].is_string());
    assert_eq!(connectors.len(), 1);
    assert_eq!(connectors[0]["name"], "site-a");

    // nonexistent group → 404
    let (status, _) = req(
        &app,
        "GET",
        "/api/v1/admin/groups/no-such-group/detail",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
