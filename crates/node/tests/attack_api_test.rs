//! Attack-surface tests (API side): brute-force lockout, JWT forgery, injection, oversized body,
//! stored XSS, privilege escalation, mass assignment, audit leakage, unauthorized WS.
//!
//! Rule: attacks must be safely rejected, errors must not leak internals, audit must not leak credentials.

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

async fn test_app() -> (Router, Database, Arc<JwtService>) {
    let db = Database::in_memory().unwrap();
    db.create_admin("admin", &hash_password("AdminPass123").unwrap())
        .unwrap();
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
    let state = ApiState::new(
        db.clone(),
        jwt.clone(),
        runtime,
        "127.0.0.1".into(),
        59090,
        54430,
    );
    (create_app(state), db, jwt)
}

async fn req_raw(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    builder = builder.header(header::CONTENT_TYPE, "application/json");
    let request = builder.body(Body::from(body)).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes).to_string()})),
    )
}

async fn req(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    req_raw(app, method, uri, token, bytes).await
}

async fn login(app: &Router) -> String {
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

/// B1: repeated failed logins trigger lockout; even the correct password gets 429 during lockout
#[tokio::test]
async fn login_bruteforce_lockout() {
    let (app, _db, _jwt) = test_app().await;

    // 5 failures in a row (hits lockout threshold)
    for _ in 0..5 {
        req(
            &app,
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({
                "username": "admin", "password": "WrongPass999",
            })),
        )
        .await;
    }
    // 6th failure → 429
    let (status, body) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "admin", "password": "WrongPass999",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], 42900);

    // Correct password also rejected during lockout (anti-bruteforce window)
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
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// B2: JWT forgery — wrong-key signature / alg=none / expired token all get 401
#[tokio::test]
async fn jwt_forgery_rejected() {
    let (app, _db, _jwt) = test_app().await;

    // 1) wrong-key signature
    let fake = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &json!({"sub":"x","username":"admin","role":"admin","exp":4102444800i64,"iat":1i64,"jti":"f","typ":"access"}),
        &jsonwebtoken::EncodingKey::from_secret(b"wrong-secret"),
    )
    .unwrap();
    let (status, _) = req(&app, "GET", "/api/v1/admin/rules", Some(&fake), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 2) alg=none forgery (header.payload. with empty signature)
    let none_token = format!(
        "{}.{}.",
        base64url(br#"{"alg":"none","typ":"JWT"}"#),
        base64url(br#"{"sub":"x","username":"admin","role":"admin","exp":4102444800i64,"iat":1i64,"jti":"f","typ":"access"}"#),
    );
    let (status, _) = req(&app, "GET", "/api/v1/admin/rules", Some(&none_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 3) expired token (real key, past exp)
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &json!({"sub":"x","username":"admin","role":"admin","exp":1000000000,"iat":1,"jti":"f","typ":"access"}),
        &jsonwebtoken::EncodingKey::from_secret(read_secret(&_db).as_bytes()),
    )
    .unwrap();
    let (status, _) = req(&app, "GET", "/api/v1/admin/rules", Some(&expired), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 4) refresh token posing as access token
    let issued = _jwt.issue("admin-id", "admin", "admin").unwrap();
    let (status, _) = req(
        &app,
        "GET",
        "/api/v1/admin/rules",
        Some(&issued.refresh_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

fn base64url(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

fn read_secret(db: &Database) -> String {
    db.get_config("jwt_secret").unwrap().unwrap()
}

/// B3: SQL injection attempts — no 500, no data leak
#[tokio::test]
async fn sql_injection_safe() {
    let (app, _db, _jwt) = test_app().await;
    let token = login(&app).await;

    // login injection
    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "admin'--", "password": "x",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // search injection
    let (status, body) = req(
        &app,
        "GET",
        "/api/v1/admin/rules?q=%27%20OR%201%3D1%20--",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["total"], 0);

    // ID injection
    let (status, _) = req(
        &app,
        "DELETE",
        "/api/v1/admin/rules/1'%20OR%20'1'%3D'1",
        Some(&token),
        None,
    )
    .await;
    assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

/// B4: oversized body rejected
#[tokio::test]
async fn oversized_body_rejected() {
    let (app, _db, _jwt) = test_app().await;
    let big = format!(
        "{{\"username\":\"{}\",\"password\":\"x\"}}",
        "a".repeat(5 * 1024 * 1024)
    );
    let (status, _) = req_raw(&app, "POST", "/api/v1/auth/login", None, big.into_bytes()).await;
    assert!(
        status == StatusCode::PAYLOAD_TOO_LARGE
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::UNPROCESSABLE_ENTITY,
        "超大请求体必须被拒，实际 {status}"
    );
}

/// B5: XSS payload stored safely (stored verbatim as JSON; UI render layer escapes)
#[tokio::test]
async fn xss_payload_stored_safely() {
    let (app, _db, _jwt) = test_app().await;
    let token = login(&app).await;
    let xss = "<script>alert(document.cookie)</script>";

    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/rules",
        Some(&token),
        Some(json!({
            "type": "host", "value": "xss-test.internal", "remark": xss,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // API returns JSON (no executable HTML context); UI esc() handles render escaping (covered by ui_test)
    let (_, body) = req(&app, "GET", "/api/v1/admin/rules", Some(&token), None).await;
    let remark = body["data"]["items"][0]["remark"].as_str().unwrap();
    assert_eq!(remark, xss, "存储保持原文，渲染层负责转义");
}

/// B6: privilege escalation & resource enumeration — 404 for missing resources, 403 for client role on admin endpoints
#[tokio::test]
async fn authorization_enforced() {
    let (app, db, _jwt) = test_app().await;
    let admin_token = login(&app).await;

    // nonexistent resources
    let (status, _) = req(
        &app,
        "PUT",
        "/api/v1/admin/rules/nonexistent-id",
        Some(&admin_token),
        Some(json!({"remark":"x"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = req(
        &app,
        "DELETE",
        "/api/v1/admin/accounts/nonexistent-id",
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // client role hitting admin API
    let gid = db.create_group("g", "").unwrap().id;
    db.create_account("c1", &hash_password("x").unwrap(), &gid, "")
        .unwrap();
    let (_, g) = req(
        &app,
        "POST",
        "/api/v1/admin/groups",
        Some(&admin_token),
        Some(json!({"name":"g2"})),
    )
    .await;
    let gid2 = g["data"]["id"].as_str().unwrap().to_string();
    let (_, a) = req(
        &app,
        "POST",
        "/api/v1/admin/accounts",
        Some(&admin_token),
        Some(json!({
            "username": "c2user", "group_id": gid2,
        })),
    )
    .await;
    let pwd = a["data"]["password"].as_str().unwrap().to_string();
    let (_, l) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "c2user", "password": pwd,
        })),
    )
    .await;
    let client_token = l["data"]["access_token"].as_str().unwrap().to_string();

    let (status, body) = req(
        &app,
        "GET",
        "/api/v1/admin/accounts",
        Some(&client_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], 40301);

    // client role reading config (only its own is reachable)
    let (status, _) = req(
        &app,
        "GET",
        "/api/v1/client/config",
        Some(&client_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Unauthorized WS events (first message after upgrade authenticates: handshake 101, invalid token closes connection on first frame, no event stream)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.clone()).await;
    });
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let handshake = "GET /api/v1/admin/node/events HTTP/1.1\r\n\
                     Host: 127.0.0.1\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: websocket\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\r\n";
    stream.write_all(handshake.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("101"), "WS 升级应成功，实际: {}", &resp[..resp.len().min(120)]);

    // Send masked text frame "bad" (first message is the token; invalid → connection closed)
    let mask = [0x01u8, 0x02, 0x03, 0x04];
    let mut frame = vec![0x81u8, 0x80 | 3u8];
    frame.extend_from_slice(&mask);
    for (i, b) in b"bad".iter().enumerate() {
        frame.push(b ^ mask[i]);
    }
    stream.write_all(&frame).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    if n > 0 {
        assert_eq!(buf[0], 0x88, "无效认证后应收到 close 帧，实际收到数据帧");
    }
    // n == 0: server dropped the connection outright — also satisfies "close on unauthorized"
}

/// B7: mass assignment — unknown fields ignored, no privilege escalation
#[tokio::test]
async fn mass_assignment_ignored() {
    let (app, _db, _jwt) = test_app().await;
    let admin_token = login(&app).await;

    let (_, g) = req(
        &app,
        "POST",
        "/api/v1/admin/groups",
        Some(&admin_token),
        Some(json!({"name":"gm"})),
    )
    .await;
    let gid = g["data"]["id"].as_str().unwrap().to_string();
    let (_, a) = req(
        &app,
        "POST",
        "/api/v1/admin/accounts",
        Some(&admin_token),
        Some(json!({
            "username": "muser", "group_id": gid,
        })),
    )
    .await;
    let aid = a["data"]["id"].as_str().unwrap().to_string();
    let pwd = a["data"]["password"].as_str().unwrap().to_string();

    // Try injecting role/is_admin/password_hash fields
    let (status, _) = req(
        &app,
        "PUT",
        &format!("/api/v1/admin/accounts/{aid}"),
        Some(&admin_token),
        Some(json!({
            "remark": "x", "role": "admin", "is_admin": true, "password_hash": "plaintext",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Login still yields client role
    let (_, l) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "muser", "password": pwd,
        })),
    )
    .await;
    assert_eq!(l["data"]["role"], "client", "批量赋值不能导致提权");
}

/// B8: audit log leaks no passwords/tokens
#[tokio::test]
async fn audit_log_no_credential_leak() {
    let (app, _db, _jwt) = test_app().await;
    let token = login(&app).await;

    let (_, g) = req(
        &app,
        "POST",
        "/api/v1/admin/groups",
        Some(&token),
        Some(json!({"name":"审计组"})),
    )
    .await;
    let gid = g["data"]["id"].as_str().unwrap().to_string();
    let (_, a) = req(
        &app,
        "POST",
        "/api/v1/admin/accounts",
        Some(&token),
        Some(json!({
            "username": "audituser", "group_id": gid,
        })),
    )
    .await;
    let password = a["data"]["password"].as_str().unwrap().to_string();

    req(
        &app,
        "POST",
        "/api/v1/admin/node/relay-tokens",
        Some(&token),
        Some(json!({"remark":"t"})),
    )
    .await;

    let (_, logs) = req(
        &app,
        "GET",
        "/api/v1/admin/audit-logs?page_size=100",
        Some(&token),
        None,
    )
    .await;
    let all = serde_json::to_string(&logs).unwrap();
    assert!(!all.contains(&password), "审计日志泄露了账号密码！");
    assert!(!all.contains("sk-"), "审计日志不应包含任何 sk- 密码");
    // relay token plaintext must not appear either (only masked psk_ prefix allowed)
    let leak = all.matches("psk_").any(|_| {
        all.matches(|c: char| c.is_ascii_alphanumeric()).count() > 0
            && all.contains("psk_")
            && !all.contains("****")
            && all.matches("psk_").count() > all.matches("psk_").count()
    });
    let _ = leak; // any psk_ occurrence must be masked
    for item in logs["data"]["items"].as_array().unwrap() {
        let detail = item["detail"].as_str().unwrap_or("");
        if detail.contains("psk_") {
            assert!(detail.contains("****"), "审计中的 token 必须掩码: {detail}");
        }
    }
}

/// B9: username header injection (CRLF) rejected
#[tokio::test]
async fn header_injection_rejected() {
    let (app, _db, _jwt) = test_app().await;
    let token = login(&app).await;
    let (_, g) = req(
        &app,
        "POST",
        "/api/v1/admin/groups",
        Some(&token),
        Some(json!({"name":"inj"})),
    )
    .await;
    let gid = g["data"]["id"].as_str().unwrap().to_string();

    let (status, _) = req(
        &app,
        "POST",
        "/api/v1/admin/accounts",
        Some(&token),
        Some(json!({
            "username": "evil\r\nX-Injected: 1", "group_id": gid,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// B10: login response does not reveal user existence (uniform error message)
#[tokio::test]
async fn login_oracle_prevented() {
    let (app, _db, _jwt) = test_app().await;
    let (_, wrong_user) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "nonexistent", "password": "x",
        })),
    )
    .await;
    let (_, wrong_pass) = req(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({
            "username": "admin", "password": "WrongPass999",
        })),
    )
    .await;
    assert_eq!(wrong_user["message"], wrong_pass["message"]);
    assert_eq!(wrong_user["message"], "invalid username or password");
}
