//! Admin ticket integration tests: admin-bootstrap ticket redemption → 3-tier scope enforcement.
//! (Account-based admin links are gone; tickets now mint at relay/expose_control handshakes
//! and the delegated admin config channel.)

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
        relay_sni: None,
        manageable: Default::default(),
        client_proxy_slot: Default::default(),
        transit_meter: agile_net_core::relay::transit::TransitMeter::new(),
        device: std::sync::Arc::new(agile_net_core::device::DeviceIdentity::ephemeral()),
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

#[tokio::test]
async fn scope_enforcement_three_tiers() {
    let (app, db) = test_app().await;
    let token = admin_token(&app).await;

    // Build tickets for all 3 tiers (relay kind, subject identifies relay source)
    let mut seq = 10u8;
    for (scope, can_read, can_rule_write, can_group_write) in [
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
            can_group_write,
            "{scope} group write: {s}"
        );

        // relay exchange lands in audit as admin.session_via_relay
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
