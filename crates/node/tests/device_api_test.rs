//! M3 admin-plane integration tests: device registry APIs (list/detail/certify/rebind/revoke +
//! pending policy), approval center (appeal cap, decide actions, notice single-shot), sessions
//! inventory endpoints (empty-runtime behavior).

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
        relay_sni: None,
        manageable: Default::default(),
        client_proxy_slot: Default::default(),
        transit_meter: agile_net_core::relay::transit::TransitMeter::new(),
        device: std::sync::Arc::new(agile_net_core::device::DeviceIdentity::ephemeral()),
        device_gate: None,
        admin_events: tokio::sync::broadcast::channel(4).0,
    });
    let state = ApiState::new(db.clone(), jwt, runtime, "127.0.0.1".into(), 59090, 54430);
    (create_app(state), db)
}

async fn req(app: &Router, method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
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
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(json!({})))
}

async fn init_and_login(app: &Router) -> String {
    req(
        app,
        "POST",
        "/api/v1/auth/init",
        None,
        Some(json!({ "username": "admin", "password": "AdminPass123" })),
    )
    .await;
    let (status, body) = req(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({ "username": "admin", "password": "AdminPass123" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body["data"]["access_token"].as_str().unwrap().to_string()
}

fn fp_of_pub(raw: &[u8; 32]) -> String {
    agile_net_core::device::fp_of(raw)
}

#[tokio::test]
async fn device_lifecycle_over_api() {
    let (app, db) = test_app().await;
    let token = init_and_login(&app).await;

    // two devices sighted (as the handshake hook would record)
    let id_a = agile_net_core::device::DeviceIdentity::ephemeral();
    let id_b = agile_net_core::device::DeviceIdentity::ephemeral();
    let fp_a = id_a.device_fp();
    let fp_b = id_b.device_fp();
    db.touch_device(&fp_a, &agile_net_core::util::base64_encode(id_a.pubkey()), "th1", "小明-MacBook").unwrap();
    db.touch_device(&fp_b, &agile_net_core::util::base64_encode(id_b.pubkey()), "th1", "小明-台式机").unwrap();

    // list: both pending
    let (status, body) = req(&app, "GET", "/api/v1/admin/devices?state=pending", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 2);

    // detail: OpenSSH line present
    let (status, body) = req(&app, "GET", &format!("/api/v1/admin/devices/{fp_a}"), Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["openssh"].as_str().unwrap().starts_with("ssh-ed25519 "));

    // certify A onto holder 小明
    let (status, body) = req(
        &app,
        "POST",
        &format!("/api/v1/admin/devices/{fp_a}/certify"),
        Some(&token),
        Some(json!({ "subject": "小明", "remark": "前端 MacBook" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["certified"], true);

    // rebind A -> B (换机): B inherits holder + stats, A revoked
    db.add_device_traffic(&fp_a, 111, 222).unwrap();
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/devices/rebind",
        Some(&token),
        Some(json!({ "old_fp": fp_a, "new_fp": fp_b, "message": "已换新机" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = req(&app, "GET", &format!("/api/v1/admin/devices/{fp_b}"), Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["state"], "certified");
    assert_eq!(body["data"]["subject"], "小明");
    assert_eq!(body["data"]["bytes_up"], 111);
    let (_, body) = req(&app, "GET", &format!("/api/v1/admin/devices/{fp_a}"), Some(&token), None).await;
    assert_eq!(body["data"]["state"], "revoked");

    // policy roundtrip
    let (_, body) = req(&app, "GET", "/api/v1/admin/devices/policy", Some(&token), None).await;
    assert_eq!(body["data"]["policy"], "block");
    let (status, _) = req(&app, "PUT", "/api/v1/admin/devices/policy", Some(&token), Some(json!({ "policy": "allow" }))).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = req(&app, "GET", "/api/v1/admin/devices/policy", Some(&token), None).await;
    assert_eq!(body["data"]["policy"], "allow");
}

#[tokio::test]
async fn approval_center_flow() {
    let (app, db) = test_app().await;
    let token = init_and_login(&app).await;
    let id = agile_net_core::device::DeviceIdentity::ephemeral();
    let fp = id.device_fp();
    db.touch_device(&fp, &agile_net_core::util::base64_encode(id.pubkey()), "th", "dev").unwrap();
    let approval_id = agile_net_node::service::approvals::ensure_device_certify_approval(&db, &fp).unwrap();
    // idempotent
    assert_eq!(agile_net_node::service::approvals::ensure_device_certify_approval(&db, &fp).unwrap(), approval_id);

    // appeals cap at 3
    for i in 0..3 {
        db.add_approval_message(&approval_id, "appeal", &format!("n{i}")).unwrap();
    }
    assert!(db.add_approval_message(&approval_id, "appeal", "x").is_err());

    // list shows the pending item with messages
    let (status, body) = req(&app, "GET", "/api/v1/admin/approvals?state=pending", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["messages"].as_array().unwrap().len(), 3);

    // approve with restated subject → device certified
    let (status, body) = req(
        &app,
        "POST",
        &format!("/api/v1/admin/approvals/{approval_id}/decide"),
        Some(&token),
        Some(json!({ "action": "approve", "subject": "小明", "remark": "主力机" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(db.get_device(&fp).unwrap().unwrap().state, "certified");
    assert_eq!(db.get_device(&fp).unwrap().unwrap().subject, "小明");

    // second device: reject_revoke path + notice single-shot
    let id2 = agile_net_core::device::DeviceIdentity::ephemeral();
    let fp2 = id2.device_fp();
    db.touch_device(&fp2, &agile_net_core::util::base64_encode(id2.pubkey()), "th", "dev2").unwrap();
    let a2 = agile_net_node::service::approvals::ensure_device_certify_approval(&db, &fp2).unwrap();
    let (status, body) = req(
        &app,
        "POST",
        &format!("/api/v1/admin/approvals/{a2}/decide"),
        Some(&token),
        Some(json!({ "action": "reject_revoke", "notice": "非本人设备" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(db.get_device(&fp2).unwrap().unwrap().state, "revoked");
    assert!(db.add_approval_message(&a2, "notice", "again").is_err());

    // decided items reject further decisions
    let (status, _) = req(
        &app,
        "POST",
        &format!("/api/v1/admin/approvals/{a2}/decide"),
        Some(&token),
        Some(json!({ "action": "approve", "subject": "x" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn sessions_api_empty_runtime() {
    let (app, _db) = test_app().await;
    let token = init_and_login(&app).await;
    let (status, body) = req(&app, "GET", "/api/v1/admin/sessions", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["items"].as_array().unwrap().len(), 0);
    // kick against a missing listener is a clean 400
    let (status, _) = req(&app, "POST", "/api/v1/admin/sessions/kick", Some(&token), Some(json!({ "session_key": "x" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn fp_helper_matches_device() {
    // sanity: fp_of == device_fp derivation used by the listener
    let id = agile_net_core::device::DeviceIdentity::ephemeral();
    assert_eq!(fp_of_pub(id.pubkey()), id.device_fp());
}
