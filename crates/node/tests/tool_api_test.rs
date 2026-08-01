//! bandwidth 诊断 API 集成测试（POST /api/v1/admin/tool/bandwidth，批次四）
//!
//! 进程内起真实 RelayListener + ConnectorManager 扇出隧道，验证：
//! - 缺省 peer：取第一个 connected connector，返回 RTT/上下行结构化结果（字节数精确）
//! - 按名称 / 上游地址指定 peer 均可命中；未知 peer → 40400
//! - 无已连接对端 → 40401（PEER_UNAVAILABLE）

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

/// 构建测试用 App（内存数据库 + 指定 ConnectorManager）。
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

/// 初始化 admin 并登录，返回 access_token。
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

/// 起静态 token listener + DB connector + ConnectorManager，等隧道连通。
/// 返回 (app, db, connector 名称, 上游地址字符串)。
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
            None,
            "",
        )
        .expect("create connector");
    let manager = ConnectorManager::new(db.clone()).with_node_id("bw-node".into());
    manager.upsert_from_db(&rec.id).await.expect("upsert");

    // 等隧道连通（轮询实时状态，至多 5s）
    let deadline = Instant::now() + Duration::from_secs(5);
    while manager.state_of(&rec.id) != Some("connected") {
        assert!(Instant::now() < deadline, "connector 5s 内未连通");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let app = test_app_with(db.clone(), manager);
    (app, db, "up1".to_string(), relay_addr.to_string())
}

/// 缺省 peer + 按名称/地址指定 peer：结构化结果完整、字节数精确、量级合理
#[tokio::test]
async fn bandwidth_api_default_and_named_peer() {
    let (app, _db, name, upstream) = setup_tunnel_app().await;
    let token = init_and_login(&app).await;

    // 缺省 = 第一个 connected connector
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
    // 宽松量级下限：进程内回环隧道应远大于 10 MB/s（80 Mbps），防 CI 抖动不设硬阈值
    assert!(up["mbps"].as_f64().unwrap() > 80.0, "up: {up}");
    assert!(down["mbps"].as_f64().unwrap() > 80.0, "down: {down}");

    // 按名称指定
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

    // 按上游地址指定
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

    // 未知 peer → 40400
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

    // 未带 token → 401（AdminAuth 口径不退化）
    let (status, _) = req(&app, "POST", "/api/v1/admin/tool/bandwidth", None, Some(json!({}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// 无任何 connector / connector 未连接 → 40401（PEER_UNAVAILABLE）
#[tokio::test]
async fn bandwidth_api_no_connected_peer() {
    let db = Database::in_memory().unwrap();
    let app = test_app_with(db.clone(), ConnectorManager::new(db.clone()));
    let token = init_and_login(&app).await;

    // 无 connector 记录：缺省解析失败
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

    // connector 存在但无运行时句柄（未连接）：指定解析失败
    db.create_connector(
        "down1",
        "127.0.0.1:1",
        "psk_x",
        "localhost",
        true,
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
