//! Client control-plane Web API (the server side of anet-gui switch C "Web remote panel").
//!
//! Maps the ~15 desktop management commands to REST endpoints, with unified `{code,data}` / `{code,message}`
//! envelopes and error-code ranges; admin auth matches server-side strength:
//! - Admin password stored as argon2id hash (verification injected by the host via [`ClientWebAuth`])
//! - Login issues an HS256 JWT (12h); auth failures are rate-limited per IP (5/min, locked 15 min after consecutive failures)
//! - Login outcomes and credential exports are persisted via the audit callback; never log password/token plaintext
//! - Credential export is sensitive and requires a `confirm=true` second confirmation (error code 40001 otherwise)

use crate::{AgileNetClient, ConnectParams, Credential, CredentialStore, NodeState};

use agile_net_core::util::{LoginBlockReason, LoginRateLimiter};
use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Host-injected Web admin auth (password hash storage, JWT secret, and audit persistence are host-implemented).
pub trait ClientWebAuth: Send + Sync {
    /// Whether an admin password has been set
    fn has_password(&self) -> bool;
    /// Set the admin password (the host handles argon2id hashing and persistence)
    fn set_password(&self, password: &str) -> std::result::Result<(), String>;
    /// Verify the admin password (argon2id)
    fn verify_password(&self, password: &str) -> bool;
    /// JWT signing secret (stably persisted; sessions survive restarts)
    fn jwt_secret(&self) -> String;
    /// Audit callback (action / detail; must never contain password/token plaintext)
    fn audit(&self, action: &str, detail: serde_json::Value);
}

/// SPA static assets (path → content), injected by the host via include_str!.
pub struct SpaAssets {
    pub index: &'static str,
    pub app_js: &'static str,
    pub icons_js: &'static str,
    pub style_css: &'static str,
    /// Shared design tokens (AGENTS.md §6; referenced by desktop index.html — without it all site variables break)
    pub tokens_css: &'static str,
    /// Shared component styles (ag-select/ag-tabs/agchart; without them: duplicate select UIs, unstyled chart popovers)
    pub components_css: &'static str,
    /// Shared chart component JS (referenced by desktop index.html — without it AgChart is undefined)
    pub agchart_js: &'static str,
    /// app.js domain-split six files (desktop index.html references them in dependency order; missing files = 404 blank panel)
    pub app_core_js: &'static str,
    pub app_views_js: &'static str,
    pub app_subscription_js: &'static str,
    pub app_hero_js: &'static str,
    pub app_logs_js: &'static str,
    pub app_settings_js: &'static str,
}

#[derive(Clone)]
struct ApiState {
    client: AgileNetClient,
    creds: Option<Arc<CredentialStore>>,
    auth: Arc<dyn ClientWebAuth>,
    limiter: LoginRateLimiter,
}

/// Handle of a running Web API (`stop` is idempotent).
pub struct ClientApiHandle {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ClientApiHandle {
    /// Actual listen address (read-back value when port 0 was dynamically allocated).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}

/// Start the client control-plane Web API.
pub async fn start_client_api(
    client: AgileNetClient,
    creds: Option<Arc<CredentialStore>>,
    auth: Arc<dyn ClientWebAuth>,
    listen: SocketAddr,
    spa: Option<SpaAssets>,
) -> Result<ClientApiHandle> {
    let state = ApiState {
        client,
        creds,
        auth,
        limiter: LoginRateLimiter::new(),
    };

    let mut app = Router::new()
        // ---- Auth (Public) ----
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/init", post(init_password))
        // ---- Nodes ----
        .route("/api/v1/nodes", get(list_nodes).post(connect_node))
        .route("/api/v1/nodes/disconnect", post(disconnect_node))
        .route(
            "/api/v1/nodes/paused-rules",
            get(get_paused_rules).put(set_paused_rules),
        )
        .route(
            "/api/v1/nodes/paused-rules/toggle",
            post(toggle_rule_paused),
        )
        // ---- Credentials ----
        .route("/api/v1/credentials", get(list_credentials))
        .route("/api/v1/credentials", delete(delete_credential))
        .route("/api/v1/credentials/export", get(export_credential))
        // ---- Proxy ----
        .route("/api/v1/proxy/start", post(start_proxy))
        .route("/api/v1/proxy/stop", post(stop_proxy))
        .route("/api/v1/proxy/status", get(proxy_status))
        // ---- Util ----
        .route("/api/v1/parse-connect-url", post(parse_connect_url))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);

    if let Some(spa) = spa {
        app = app.merge(spa_router(spa));
    }

    let listener = tokio::net::TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = rx.await;
        })
        .await;
    });
    tracing::info!(addr = %addr, "client web api started");
    Ok(ClientApiHandle {
        addr,
        shutdown: Some(tx),
        task: Some(task),
    })
}

fn spa_router(spa: SpaAssets) -> Router {
    async fn serve(asset: &'static str, content_type: &'static str) -> Response {
        (
            [
                (header::CONTENT_TYPE, content_type),
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
                ),
                (header::X_FRAME_OPTIONS, "DENY"),
                (header::REFERRER_POLICY, "no-referrer"),
            ],
            asset,
        )
            .into_response()
    }
    let index = spa.index;
    let app_js = spa.app_js;
    let icons_js = spa.icons_js;
    let style_css = spa.style_css;
    let tokens_css = spa.tokens_css;
    let components_css = spa.components_css;
    let agchart_js = spa.agchart_js;
    let app_core_js = spa.app_core_js;
    let app_views_js = spa.app_views_js;
    let app_subscription_js = spa.app_subscription_js;
    let app_hero_js = spa.app_hero_js;
    let app_logs_js = spa.app_logs_js;
    let app_settings_js = spa.app_settings_js;
    Router::new()
        .route("/", get(move || serve(index, "text/html; charset=utf-8")))
        .route(
            "/index.html",
            get(move || serve(index, "text/html; charset=utf-8")),
        )
        .route(
            "/app.js",
            get(move || serve(app_js, "text/javascript; charset=utf-8")),
        )
        .route(
            "/icons.js",
            get(move || serve(icons_js, "text/javascript; charset=utf-8")),
        )
        .route(
            "/agchart.js",
            get(move || serve(agchart_js, "text/javascript; charset=utf-8")),
        )
        .route(
            "/app-core.js",
            get(move || serve(app_core_js, "text/javascript; charset=utf-8")),
        )
        .route(
            "/app-views.js",
            get(move || serve(app_views_js, "text/javascript; charset=utf-8")),
        )
        .route(
            "/app-subscription.js",
            get(move || serve(app_subscription_js, "text/javascript; charset=utf-8")),
        )
        .route(
            "/app-hero.js",
            get(move || serve(app_hero_js, "text/javascript; charset=utf-8")),
        )
        .route(
            "/app-logs.js",
            get(move || serve(app_logs_js, "text/javascript; charset=utf-8")),
        )
        .route(
            "/app-settings.js",
            get(move || serve(app_settings_js, "text/javascript; charset=utf-8")),
        )
        .route(
            "/style.css",
            get(move || serve(style_css, "text/css; charset=utf-8")),
        )
        .route(
            "/tokens.css",
            get(move || serve(tokens_css, "text/css; charset=utf-8")),
        )
        .route(
            "/components.css",
            get(move || serve(components_css, "text/css; charset=utf-8")),
        )
}

// ==================== unified response body ====================

fn ok<T: Serialize>(data: T) -> Response {
    Json(serde_json::json!({ "code": 0, "data": data })).into_response()
}

fn err(status: StatusCode, code: u32, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({ "code": code, "message": message.into() })),
    )
        .into_response()
}

mod codes {
    pub const BAD_REQUEST: u32 = 40000;
    pub const VALIDATION_FAILED: u32 = 40001;
    pub const INVALID_CREDENTIALS: u32 = 40100;
    pub const TOKEN_EXPIRED: u32 = 40101;
    pub const NOT_FOUND: u32 = 40400;
    pub const RATE_LIMITED: u32 = 42900;
    pub const INTERNAL: u32 = 50000;
}

// ==================== auth ====================

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

fn issue_token(secret: &str) -> Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = Claims {
        sub: "web-admin".into(),
        exp: now + 12 * 3600,
    };
    Ok(jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )?)
}

fn verify_token(secret: &str, token: &str) -> bool {
    jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    )
    .is_ok()
}

/// Source-IP extractor (injected via the ConnectInfo extension).
struct ClientIp(IpAddr);

impl axum::extract::FromRequestParts<ApiState> for ClientIp {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &ApiState,
    ) -> std::result::Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        Ok(ClientIp(ip))
    }
}

async fn auth_middleware(
    State(state): State<ApiState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    // Login/init endpoints are public themselves (login has internal rate limiting)
    if path.starts_with("/api/v1/auth/") {
        return next.run(req).await;
    }
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();
    if verify_token(&state.auth.jwt_secret(), &token) {
        next.run(req).await
    } else {
        err(
            StatusCode::UNAUTHORIZED,
            codes::TOKEN_EXPIRED,
            "未登录或会话已过期",
        )
    }
}

#[derive(Deserialize)]
struct PasswordReq {
    password: String,
}

async fn login(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<PasswordReq>,
) -> Response {
    match state.limiter.check(ip) {
        Err(LoginBlockReason::Locked(secs)) => {
            return err(
                StatusCode::TOO_MANY_REQUESTS,
                codes::RATE_LIMITED,
                format!("连续失败过多，账号已锁定，{} 秒后重试", secs.as_secs()),
            );
        }
        Err(LoginBlockReason::RateLimited) => {
            return err(
                StatusCode::TOO_MANY_REQUESTS,
                codes::RATE_LIMITED,
                "尝试过于频繁，请稍后再试",
            );
        }
        Ok(()) => {}
    }
    if !state.auth.has_password() {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "尚未设置管理密码",
        );
    }
    if !state.auth.verify_password(&req.password) {
        state.limiter.record_failure(ip);
        state
            .auth
            .audit("web.login_fail", serde_json::json!({"ip": ip.to_string()}));
        // Random delay penalty to slow down online brute force
        tokio::time::sleep(Duration::from_millis(150 + rand_u64() % 250)).await;
        return err(
            StatusCode::UNAUTHORIZED,
            codes::INVALID_CREDENTIALS,
            "管理密码错误",
        );
    }
    state.limiter.record_success(ip);
    match issue_token(&state.auth.jwt_secret()) {
        Ok(token) => {
            state
                .auth
                .audit("web.login_ok", serde_json::json!({"ip": ip.to_string()}));
            ok(serde_json::json!({ "access_token": token }))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

/// First-run admin password initialization (available only when unset).
async fn init_password(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<PasswordReq>,
) -> Response {
    if state.auth.has_password() {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "管理密码已设置",
        );
    }
    if req.password.len() < 10 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "管理密码至少 10 位",
        );
    }
    // Same complexity requirement as the server side: upper + lower case letters and digits
    let has_lower = req.password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = req.password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = req.password.chars().any(|c| c.is_ascii_digit());
    if !(has_lower && has_upper && has_digit) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "管理密码须包含大小写字母和数字",
        );
    }
    match state.auth.set_password(&req.password) {
        Ok(()) => {
            state.auth.audit(
                "web.exposure_change",
                serde_json::json!({"change": "password_init", "ip": ip.to_string()}),
            );
            ok(serde_json::json!({ "initialized": true }))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e),
    }
}

fn rand_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64
        ^ (std::process::id() as u64) << 32
}

// ==================== command mapping (same semantics as desktop IPC) ====================

#[derive(Debug, Deserialize)]
struct ConnectInput {
    addr: String,
    username: String,
    password: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    pinned_cert_path: Option<String>,
    #[serde(default)]
    pinned_fingerprint: Option<String>,
    #[serde(default)]
    manage_hosts: bool,
    #[serde(default)]
    save_credential: bool,
    /// Federation P2/P3 delegated credential fields (all optional, plain accounts unaffected)
    #[serde(default)]
    delegated: bool,
    #[serde(default)]
    entries: Vec<String>,
    #[serde(default)]
    entry_fps: Vec<String>,
    #[serde(default)]
    ehint: Option<String>,
    #[serde(default)]
    en: Option<String>,
    #[serde(default)]
    emode: Option<String>,
    #[serde(default)]
    eadmin: bool,
}

async fn connect_node(State(state): State<ApiState>, Json(input): Json<ConnectInput>) -> Response {
    let params = ConnectParams {
        addr: input.addr.clone(),
        username: input.username.clone(),
        password: input.password.clone(),
        insecure: input.insecure,
        pinned_cert_path: input.pinned_cert_path.clone(),
        pinned_fingerprint: input.pinned_fingerprint.clone(),
        manage_hosts: input.manage_hosts,
        delegated: input.delegated,
        entries: input.entries.clone(),
        entry_fps: input.entry_fps.clone(),
        ehint: input.ehint.clone(),
        en: input.en.clone(),
        emode: input.emode.clone(),
        eadmin: input.eadmin,
    };
    let node_state = match state.client.connect(params).await {
        Ok(s) => s,
        Err(e) => return err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, e.to_string()),
    };
    if input.save_credential
        && let Some(store) = &state.creds
    {
        store
            .save(
                &node_state.node_id,
                &Credential {
                    addr: input.addr,
                    username: input.username,
                    password: input.password,
                    insecure: input.insecure,
                    pinned_fingerprint: input.pinned_fingerprint,
                    delegated: input.delegated,
                    entries: input.entries,
                    entry_fps: input.entry_fps,
                    ehint: input.ehint,
                    en: input.en,
                    emode: input.emode,
                    eadmin: input.eadmin,
                },
            )
            .await;
    }
    ok(node_state)
}

#[derive(Deserialize)]
struct NodeIdReq {
    node_id: String,
}

async fn disconnect_node(State(state): State<ApiState>, Json(req): Json<NodeIdReq>) -> Response {
    state.client.disconnect(&req.node_id).await;
    ok(serde_json::json!({ "disconnected": true }))
}

async fn list_nodes(State(state): State<ApiState>) -> Response {
    let mut nodes: Vec<NodeState> = state.client.list_nodes().await;
    for n in &mut nodes {
        n.status = state.client.node_status(&n.node_id);
    }
    ok(nodes)
}

#[derive(Deserialize)]
struct PausedQuery {
    node_id: String,
}

async fn get_paused_rules(State(state): State<ApiState>, Query(q): Query<PausedQuery>) -> Response {
    ok(state.client.get_paused_rules(&q.node_id))
}

#[derive(Deserialize)]
struct SetPausedReq {
    node_id: String,
    keys: Vec<String>,
}

async fn set_paused_rules(
    State(state): State<ApiState>,
    Json(req): Json<SetPausedReq>,
) -> Response {
    state.client.set_paused_rules(&req.node_id, req.keys);
    ok(serde_json::json!({ "updated": true }))
}

#[derive(Deserialize)]
struct TogglePausedReq {
    node_id: String,
    rule_key: String,
    paused: bool,
}

async fn toggle_rule_paused(
    State(state): State<ApiState>,
    Json(req): Json<TogglePausedReq>,
) -> Response {
    state
        .client
        .set_rule_paused(&req.node_id, &req.rule_key, req.paused);
    ok(serde_json::json!({ "updated": true }))
}

async fn list_credentials(State(state): State<ApiState>) -> Response {
    let mut out: Vec<(String, Credential)> = Vec::new();
    if let Some(store) = &state.creds {
        for key in store.keys().await {
            if let Some(cred) = store.get(&key).await {
                out.push((key, cred));
            }
        }
    }
    ok(out)
}

#[derive(Deserialize)]
struct CredKeyQuery {
    key: String,
}

async fn delete_credential(
    State(state): State<ApiState>,
    Query(q): Query<CredKeyQuery>,
) -> Response {
    if let Some(store) = &state.creds {
        store.remove(&q.key).await;
    }
    ok(serde_json::json!({ "deleted": true }))
}

#[derive(Deserialize)]
struct ExportQuery {
    key: String,
    #[serde(default)]
    confirm: bool,
}

/// Export a connect URL (contains plaintext password) — Web exposure requires a `confirm=true` second confirmation.
async fn export_credential(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Query(q): Query<ExportQuery>,
) -> Response {
    if !q.confirm {
        return err(
            StatusCode::CONFLICT,
            codes::VALIDATION_FAILED,
            "凭据导出含明文密码，需二次确认（confirm=true）",
        );
    }
    let Some(store) = &state.creds else {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "凭据存储不可用",
        );
    };
    let Some(c) = store.get(&q.key).await else {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "凭据不存在或已删除",
        );
    };
    state.auth.audit(
        "web.credential_export",
        serde_json::json!({"key": q.key, "ip": ip.to_string()}),
    );
    ok(crate::connect_url_of(&c))
}

#[derive(Deserialize)]
struct StartProxyReq {
    port: u16,
}

async fn start_proxy(State(state): State<ApiState>, Json(req): Json<StartProxyReq>) -> Response {
    match state.client.start_proxy(req.port).await {
        Ok(()) => ok(state.client.proxy_port()),
        Err(e) => err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, e.to_string()),
    }
}

async fn stop_proxy(State(state): State<ApiState>) -> Response {
    state.client.stop_proxy().await;
    ok(serde_json::json!({ "stopped": true }))
}

async fn proxy_status(State(state): State<ApiState>) -> Response {
    let port = state.client.proxy_port();
    ok(serde_json::json!({ "running": port > 0, "port": port }))
}

#[derive(Deserialize)]
struct ParseUrlReq {
    url: String,
}

async fn parse_connect_url(
    State(_state): State<ApiState>,
    Json(req): Json<ParseUrlReq>,
) -> Response {
    match crate::parse_connect_url(&req.url) {
        Ok(input) => ok(input),
        Err(e) => err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, e),
    }
}
