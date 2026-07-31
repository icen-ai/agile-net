//! 攻击面测试（API 面）：暴力登录锁定、JWT 伪造、注入、超大请求体、
//! XSS 存储、越权访问、批量赋值、审计泄露、WS 未授权。
//!
//! 原则：攻击必须被安全拒绝，错误不泄露内部信息，审计不泄露凭据。

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

async fn test_app() -> (Router, Database, Arc<JwtService>) {
    let db = Database::in_memory().unwrap();
    db.create_admin("admin", &hash_password("AdminPass123").unwrap())
        .unwrap();
    let jwt = Arc::new(JwtService::load_or_create(db.clone()).unwrap());
    let runtime = Arc::new(NodeRuntime {
        started_at: Instant::now(),
        listener: None,
        connector: None,
        proxy_stats: None,
        proxy_listen: None,
        log_buffer: LogBuffer::new(),
        cert_fingerprint: None,
    });
    let state = ApiState::new(db.clone(), jwt.clone(), runtime, "127.0.0.1".into(), 59090, 54430);
    (create_app(state), db, jwt)
}

async fn req_raw(app: &Router, method: &str, uri: &str, token: Option<&str>, body: Vec<u8>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    builder = builder.header(header::CONTENT_TYPE, "application/json");
    let request = builder.body(Body::from(body)).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes).to_string()})))
}

async fn req(app: &Router, method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
    let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    req_raw(app, method, uri, token, bytes).await
}

async fn login(app: &Router) -> String {
    let (_, body) = req(app, "POST", "/api/v1/auth/login", None, Some(json!({
        "username": "admin", "password": "AdminPass123",
    }))).await;
    body["data"]["access_token"].as_str().unwrap().to_string()
}

/// B1: 连续失败登录触发锁定，锁定期间正确密码也返回 429
#[tokio::test]
async fn login_bruteforce_lockout() {
    let (app, _db, _jwt) = test_app().await;

    // 连续 5 次错误（达到锁定阈值）
    for _ in 0..5 {
        req(&app, "POST", "/api/v1/auth/login", None, Some(json!({
            "username": "admin", "password": "WrongPass999",
        }))).await;
    }
    // 第 6 次错误 → 429
    let (status, body) = req(&app, "POST", "/api/v1/auth/login", None, Some(json!({
        "username": "admin", "password": "WrongPass999",
    }))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], 42900);

    // 锁定期间正确密码也被拒（防爆破窗口）
    let (status, _) = req(&app, "POST", "/api/v1/auth/login", None, Some(json!({
        "username": "admin", "password": "AdminPass123",
    }))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// B2: JWT 伪造 —— 错误密钥签名 / alg=none / 过期 token 全部 401
#[tokio::test]
async fn jwt_forgery_rejected() {
    let (app, _db, _jwt) = test_app().await;

    // 1) 错误密钥签名
    let fake = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &json!({"sub":"x","username":"admin","role":"admin","exp":4102444800i64,"iat":1i64,"jti":"f","typ":"access"}),
        &jsonwebtoken::EncodingKey::from_secret(b"wrong-secret"),
    )
    .unwrap();
    let (status, _) = req(&app, "GET", "/api/v1/admin/rules", Some(&fake), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 2) alg=none 伪造（header.payload. 空签名）
    let none_token = format!(
        "{}.{}.",
        base64url(br#"{"alg":"none","typ":"JWT"}"#),
        base64url(br#"{"sub":"x","username":"admin","role":"admin","exp":4102444800i64,"iat":1i64,"jti":"f","typ":"access"}"#),
    );
    let (status, _) = req(&app, "GET", "/api/v1/admin/rules", Some(&none_token), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 3) 过期 token（真实密钥，已过期）
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &json!({"sub":"x","username":"admin","role":"admin","exp":1000000000,"iat":1,"jti":"f","typ":"access"}),
        &jsonwebtoken::EncodingKey::from_secret(read_secret(&_db).as_bytes()),
    )
    .unwrap();
    let (status, _) = req(&app, "GET", "/api/v1/admin/rules", Some(&expired), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 4) refresh token 冒充 access token
    let issued = _jwt.issue("admin-id", "admin", "admin").unwrap();
    let (status, _) = req(&app, "GET", "/api/v1/admin/rules", Some(&issued.refresh_token), None).await;
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

/// B3: SQL 注入尝试 —— 不产生 500，不泄露数据
#[tokio::test]
async fn sql_injection_safe() {
    let (app, _db, _jwt) = test_app().await;
    let token = login(&app).await;

    // 登录注入
    let (status, _) = req(&app, "POST", "/api/v1/auth/login", None, Some(json!({
        "username": "admin'--", "password": "x",
    }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 搜索注入
    let (status, body) = req(&app, "GET", "/api/v1/admin/rules?q=%27%20OR%201%3D1%20--", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["total"], 0);

    // ID 注入
    let (status, _) = req(&app, "DELETE", "/api/v1/admin/rules/1'%20OR%20'1'%3D'1", Some(&token), None).await;
    assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

/// B4: 超大请求体被拒绝
#[tokio::test]
async fn oversized_body_rejected() {
    let (app, _db, _jwt) = test_app().await;
    let big = format!("{{\"username\":\"{}\",\"password\":\"x\"}}", "a".repeat(5 * 1024 * 1024));
    let (status, _) = req_raw(&app, "POST", "/api/v1/auth/login", None, big.into_bytes()).await;
    assert!(
        status == StatusCode::PAYLOAD_TOO_LARGE
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::UNPROCESSABLE_ENTITY,
        "超大请求体必须被拒，实际 {status}"
    );
}

/// B5: XSS 载荷存储安全（JSON 原样存储，UI 渲染层转义）
#[tokio::test]
async fn xss_payload_stored_safely() {
    let (app, _db, _jwt) = test_app().await;
    let token = login(&app).await;
    let xss = "<script>alert(document.cookie)</script>";

    let (status, _) = req(&app, "POST", "/api/v1/admin/rules", Some(&token), Some(json!({
        "type": "host", "value": "xss-test.internal", "remark": xss,
    }))).await;
    assert_eq!(status, StatusCode::CREATED);

    // API 返回 JSON（不含可执行 HTML 上下文），UI 层 esc() 负责渲染转义（ui_test 覆盖）
    let (_, body) = req(&app, "GET", "/api/v1/admin/rules", Some(&token), None).await;
    let remark = body["data"]["items"][0]["remark"].as_str().unwrap();
    assert_eq!(remark, xss, "存储保持原文，渲染层负责转义");
}

/// B6: 越权与资源枚举 —— 不存在资源 404，client 角色访问 admin 接口 403
#[tokio::test]
async fn authorization_enforced() {
    let (app, db, _jwt) = test_app().await;
    let admin_token = login(&app).await;

    // 不存在的资源
    let (status, _) = req(&app, "PUT", "/api/v1/admin/rules/nonexistent-id", Some(&admin_token), Some(json!({"remark":"x"}))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = req(&app, "DELETE", "/api/v1/admin/accounts/nonexistent-id", Some(&admin_token), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // client 角色访问 admin API
    let gid = db.create_group("g", "").unwrap().id;
    db.create_account("c1", &hash_password("x").unwrap(), &gid, "").unwrap();
    let (_, g) = req(&app, "POST", "/api/v1/admin/groups", Some(&admin_token), Some(json!({"name":"g2"}))).await;
    let gid2 = g["data"]["id"].as_str().unwrap().to_string();
    let (_, a) = req(&app, "POST", "/api/v1/admin/accounts", Some(&admin_token), Some(json!({
        "username": "c2user", "group_id": gid2,
    }))).await;
    let pwd = a["data"]["password"].as_str().unwrap().to_string();
    let (_, l) = req(&app, "POST", "/api/v1/auth/login", None, Some(json!({
        "username": "c2user", "password": pwd,
    }))).await;
    let client_token = l["data"]["access_token"].as_str().unwrap().to_string();

    let (status, body) = req(&app, "GET", "/api/v1/admin/accounts", Some(&client_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], 40301);

    // client 角色访问他人 config（只能访问自己的）
    let (status, _) = req(&app, "GET", "/api/v1/client/config", Some(&client_token), None).await;
    assert_eq!(status, StatusCode::OK);

    // WS 事件未授权（真实服务器 + 合法升级头 + 无效 token → 401）
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.clone()).await;
    });
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let handshake = "GET /api/v1/admin/node/events?token=bad HTTP/1.1\r\n\
                     Host: 127.0.0.1\r\n\
                     Connection: Upgrade\r\n\
                     Upgrade: websocket\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\r\n";
    stream.write_all(handshake.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("401"), "无效 token 的 WS 握手必须 401，实际: {}", &resp[..resp.len().min(120)]);
}

/// B7: 批量赋值攻击 —— 未知字段被忽略，不能提权
#[tokio::test]
async fn mass_assignment_ignored() {
    let (app, _db, _jwt) = test_app().await;
    let admin_token = login(&app).await;

    let (_, g) = req(&app, "POST", "/api/v1/admin/groups", Some(&admin_token), Some(json!({"name":"gm"}))).await;
    let gid = g["data"]["id"].as_str().unwrap().to_string();
    let (_, a) = req(&app, "POST", "/api/v1/admin/accounts", Some(&admin_token), Some(json!({
        "username": "muser", "group_id": gid,
    }))).await;
    let aid = a["data"]["id"].as_str().unwrap().to_string();
    let pwd = a["data"]["password"].as_str().unwrap().to_string();

    // 尝试注入 role/is_admin/password_hash 字段
    let (status, _) = req(&app, "PUT", &format!("/api/v1/admin/accounts/{aid}"), Some(&admin_token), Some(json!({
        "remark": "x", "role": "admin", "is_admin": true, "password_hash": "plaintext",
    }))).await;
    assert_eq!(status, StatusCode::OK);

    // 登录仍是 client 角色
    let (_, l) = req(&app, "POST", "/api/v1/auth/login", None, Some(json!({
        "username": "muser", "password": pwd,
    }))).await;
    assert_eq!(l["data"]["role"], "client", "批量赋值不能导致提权");
}

/// B8: 审计日志不泄露密码/令牌
#[tokio::test]
async fn audit_log_no_credential_leak() {
    let (app, _db, _jwt) = test_app().await;
    let token = login(&app).await;

    let (_, g) = req(&app, "POST", "/api/v1/admin/groups", Some(&token), Some(json!({"name":"审计组"}))).await;
    let gid = g["data"]["id"].as_str().unwrap().to_string();
    let (_, a) = req(&app, "POST", "/api/v1/admin/accounts", Some(&token), Some(json!({
        "username": "audituser", "group_id": gid,
    }))).await;
    let password = a["data"]["password"].as_str().unwrap().to_string();

    req(&app, "POST", "/api/v1/admin/node/relay-tokens", Some(&token), Some(json!({"remark":"t"}))).await;

    let (_, logs) = req(&app, "GET", "/api/v1/admin/audit-logs?page_size=100", Some(&token), None).await;
    let all = serde_json::to_string(&logs).unwrap();
    assert!(!all.contains(&password), "审计日志泄露了账号密码！");
    assert!(!all.contains("sk-"), "审计日志不应包含任何 sk- 密码");
    // relay token 明文也不应出现（只允许 psk_ 前缀掩码）
    let leak = all.matches("psk_").any(|_| all.matches(|c: char| c.is_ascii_alphanumeric()).count() > 0 && all.contains("psk_") && !all.contains("****") && all.matches("psk_").count() > all.matches("psk_").count());
    let _ = leak; // psk_ 出现必须带掩码
    for item in logs["data"]["items"].as_array().unwrap() {
        let detail = item["detail"].as_str().unwrap_or("");
        if detail.contains("psk_") {
            assert!(detail.contains("****"), "审计中的 token 必须掩码: {detail}");
        }
    }
}

/// B9: 用户名头注入（CRLF）被拒绝
#[tokio::test]
async fn header_injection_rejected() {
    let (app, _db, _jwt) = test_app().await;
    let token = login(&app).await;
    let (_, g) = req(&app, "POST", "/api/v1/admin/groups", Some(&token), Some(json!({"name":"inj"}))).await;
    let gid = g["data"]["id"].as_str().unwrap().to_string();

    let (status, _) = req(&app, "POST", "/api/v1/admin/accounts", Some(&token), Some(json!({
        "username": "evil\r\nX-Injected: 1", "group_id": gid,
    }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// B10: 登录响应不泄露用户存在性（统一错误信息）
#[tokio::test]
async fn login_oracle_prevented() {
    let (app, _db, _jwt) = test_app().await;
    let (_, wrong_user) = req(&app, "POST", "/api/v1/auth/login", None, Some(json!({
        "username": "nonexistent", "password": "x",
    }))).await;
    let (_, wrong_pass) = req(&app, "POST", "/api/v1/auth/login", None, Some(json!({
        "username": "admin", "password": "WrongPass999",
    }))).await;
    assert_eq!(wrong_user["message"], wrong_pass["message"]);
    assert_eq!(wrong_user["message"], "invalid username or password");
}
