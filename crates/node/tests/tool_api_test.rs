//! bandwidth diagnostics API integration tests (POST /api/v1/admin/tool/bandwidth, batch four)
//!
//! Spins up a real in-process RelayListener + ConnectorManager fan-out tunnel, verifying:
//! - default peer: picks the first connected connector, returns structured RTT/up-down results (exact byte counts)
//! - peer specified by name / upstream address both resolve; unknown peer → 40400
//! - no connected peer → 40401 (PEER_UNAVAILABLE)

use agile_net_core::relay::RelayListener;
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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::ServiceExt;

fn get_free_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// Build a test App (in-memory database + given ConnectorManager).
fn test_app_with(db: Database, manager: ConnectorManager) -> Router {
    let jwt = Arc::new(JwtService::load_or_create(db.clone()).unwrap());
    let runtime = Arc::new(NodeRuntime {
        started_at: Instant::now(),
        listener: None,
        connector_manager: Arc::new(manager),
        proxy_stats: None,
        proxy_listen: None,
        log_buffer: LogBuffer::new(),
        cert_fingerprint: None,
        manageable: Default::default(),
        client_proxy_slot: Default::default(),
        transit_meter: agile_net_core::relay::transit::TransitMeter::new(),
    });
    let state = ApiState::new(db, jwt, runtime, "127.0.0.1".into(), 59090, 54430);
    create_app(state)
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

/// Init admin and log in, returning an access_token.
async fn init_and_login(app: &Router) -> String {
    let (status, _) = req(
        app,
        "POST",
        "/api/v1/auth/init",
        None,
        Some(json!({ "username": "admin", "password": "AdminPass123" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
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

/// Start a static-token listener + DB connector + ConnectorManager, wait for the tunnel.
/// Returns (app, db, connector name, upstream address string).
async fn setup_tunnel_app() -> (Router, Database, String, String) {
    let relay_addr = get_free_addr();
    let token = "bw-api-token";
    let listener = Arc::new(RelayListener::new(relay_addr, token).unwrap());
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.start().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let db = Database::in_memory().unwrap();
    let rec = db
        .create_connector(
            "up1",
            &relay_addr.to_string(),
            token,
            "localhost",
            true,
            "",
            "",
            "",
            "",
            None,
            "",
        )
        .expect("create connector");
    let manager = ConnectorManager::new(db.clone()).with_node_id("bw-node".into());
    manager.upsert_from_db(&rec.id).await.expect("upsert");

    // wait for the tunnel (poll live state, up to 5s)
    let deadline = Instant::now() + Duration::from_secs(5);
    while manager.state_of(&rec.id) != Some("connected") {
        assert!(Instant::now() < deadline, "connector 5s 内未连通");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let app = test_app_with(db.clone(), manager);
    (app, db, "up1".to_string(), relay_addr.to_string())
}

/// Default peer + peer by name/address: complete structured results, exact byte counts, sane magnitude
#[tokio::test]
async fn bandwidth_api_default_and_named_peer() {
    let (app, _db, name, upstream) = setup_tunnel_app().await;
    let token = init_and_login(&app).await;

    // default = first connected connector
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/tool/bandwidth",
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["code"], json!(0));
    let d = &body["data"];
    assert_eq!(d["peer"], json!(name));
    let (rtt, up, down) = (&d["rtt"], &d["up"], &d["down"]);
    assert!(rtt["min_ms"].as_f64().unwrap() >= 0.0);
    assert!(rtt["min_ms"].as_f64().unwrap() <= rtt["avg_ms"].as_f64().unwrap());
    assert!(rtt["avg_ms"].as_f64().unwrap() <= rtt["max_ms"].as_f64().unwrap());
    assert_eq!(up["bytes"], json!(8 * 1024 * 1024));
    assert_eq!(down["bytes"], json!(8 * 1024 * 1024));
    // loose floor: an in-process loopback tunnel should far exceed 10 MB/s (80 Mbps); no hard cap, CI jitter safe
    assert!(up["mbps"].as_f64().unwrap() > 80.0, "up: {up}");
    assert!(down["mbps"].as_f64().unwrap() > 80.0, "down: {down}");

    // by name
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/tool/bandwidth",
        Some(&token),
        Some(json!({ "peer": "up1" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["data"]["peer"], json!("up1"));

    // by upstream address
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/tool/bandwidth",
        Some(&token),
        Some(json!({ "peer": upstream })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["data"]["peer"], json!("up1"));

    // unknown peer → 40400
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/tool/bandwidth",
        Some(&token),
        Some(json!({ "peer": "nope" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["code"], json!(40400));

    // no token → 401 (AdminAuth semantics must not degrade)
    let (status, _) = req(&app, "POST", "/api/v1/admin/tool/bandwidth", None, Some(json!({}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// No connector at all / connector not connected → 40401 (PEER_UNAVAILABLE)
#[tokio::test]
async fn bandwidth_api_no_connected_peer() {
    let db = Database::in_memory().unwrap();
    let app = test_app_with(db.clone(), ConnectorManager::new(db.clone()));
    let token = init_and_login(&app).await;

    // no connector records: default resolution fails
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/tool/bandwidth",
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["code"], json!(40401));

    // connector exists but has no runtime handle (not connected): named resolution fails
    db.create_connector(
        "down1",
        "127.0.0.1:1",
        "psk_x",
        "localhost",
        true,
        "",
        "",
        "",
        "",
        None,
        "",
    )
    .unwrap();
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/admin/tool/bandwidth",
        Some(&token),
        Some(json!({ "peer": "down1" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["code"], json!(40401));
}
