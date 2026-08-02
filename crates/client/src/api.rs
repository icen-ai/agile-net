//! 客户端管理面 Web API（anet-gui 开关C「Web 远程面」的服务端）。
//!
//! 把桌面端 ~15 个管理命令映射为 REST 端点，统一 `{code,data}` / `{code,message}`
//! 信封与错误码段；管理鉴权与服务端同强度：
//! - 管理密码 argon2id 哈希（由宿主经 [`ClientWebAuth`] 注入校验）
//! - 登录颁发 HS256 JWT（12h），认证失败按 IP 限流（5 次/分钟，连续失败锁 15 分钟）
//! - 登录成败与凭据导出经审计回调落盘，严禁记录密码/Token 明文
//! - 凭据导出属敏感操作，必须 `confirm=true` 二次确认（错误码 40001 提示）

use crate::{AgileNetClient, ConnectParams, Credential, CredentialStore, NodeState};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 宿主注入的 Web 管理鉴权（密码哈希存储、JWT 密钥、审计落盘由宿主实现）。
pub trait ClientWebAuth: Send + Sync {
    /// 是否已设置管理密码
    fn has_password(&self) -> bool;
    /// 设置管理密码（宿主负责 argon2id 哈希与持久化）
    fn set_password(&self, password: &str) -> std::result::Result<(), String>;
    /// 校验管理密码（argon2id 验算）
    fn verify_password(&self, password: &str) -> bool;
    /// JWT 签名密钥（稳定持久化；重启后会话仍有效）
    fn jwt_secret(&self) -> String;
    /// 审计回调（action / detail；严禁含密码、Token 明文）
    fn audit(&self, action: &str, detail: serde_json::Value);
}

/// SPA 静态资产（路径 → 内容），由宿主 include_str! 注入。
pub struct SpaAssets {
    pub index: &'static str,
    pub app_js: &'static str,
    pub icons_js: &'static str,
    pub style_css: &'static str,
    /// 共享设计 token（AGENTS.md §6；桌面 index.html 引用，缺失则全站变量失效）
    pub tokens_css: &'static str,
    /// 共享组件样式（ag-select/ag-tabs/agchart；缺失则下拉双 UI、图表浮层无样式）
    pub components_css: &'static str,
    /// 共享图表组件 JS（桌面 index.html 引用，缺失则 AgChart 未定义）
    pub agchart_js: &'static str,
}

#[derive(Clone)]
struct ApiState {
    client: AgileNetClient,
    creds: Option<Arc<CredentialStore>>,
    auth: Arc<dyn ClientWebAuth>,
    limiter: LoginRateLimiter,
}

/// 运行中的 Web API 句柄（`stop` 幂等）。
pub struct ClientApiHandle {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ClientApiHandle {
    /// 实际监听地址（端口 0 动态分配时为回读值）。
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

/// 启动客户端管理面 Web API。
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

// ==================== 统一响应体 ====================

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

// ==================== 鉴权 ====================

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

/// 来源 IP 提取器（经 ConnectInfo 扩展注入）。
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
    // 登录/初始化端点自身公开（登录内部有限流）
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
        // 随机延迟惩罚，拖慢在线爆破
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

/// 首开初始化管理密码（仅在未设置时可用）。
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
    // 与服务端一致的复杂度要求：含大小写字母与数字
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

// ==================== 登录限流 ====================

#[derive(Clone)]
struct LoginRateLimiter {
    inner: Arc<DashMap<IpAddr, LoginAttempts>>,
}

struct LoginAttempts {
    window_start: Instant,
    attempts: u32,
    failures: u32,
    locked_until: Option<Instant>,
}

enum LoginBlockReason {
    RateLimited,
    Locked(Duration),
}

impl LoginRateLimiter {
    const MAX_PER_MINUTE: u32 = 5;
    const LOCK_THRESHOLD: u32 = 5;
    const LOCK_MINUTES: u64 = 15;

    fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    fn check(&self, ip: IpAddr) -> std::result::Result<(), LoginBlockReason> {
        // 惰性清扫：条目数超 1024 时淘汰 30 分钟未活动的失败记录（防内存无上限增长）
        if self.inner.len() > 1024 {
            self.inner
                .retain(|_, e| e.window_start.elapsed() < Duration::from_secs(30 * 60));
        }
        let mut entry = self.inner.entry(ip).or_insert(LoginAttempts {
            window_start: Instant::now(),
            attempts: 0,
            failures: 0,
            locked_until: None,
        });
        let e = entry.value_mut();
        if let Some(until) = e.locked_until {
            if until > Instant::now() {
                return Err(LoginBlockReason::Locked(until - Instant::now()));
            }
            e.locked_until = None;
            e.failures = 0;
        }
        if e.window_start.elapsed() > Duration::from_secs(60) {
            e.window_start = Instant::now();
            e.attempts = 0;
        }
        e.attempts += 1;
        if e.attempts > Self::MAX_PER_MINUTE {
            return Err(LoginBlockReason::RateLimited);
        }
        Ok(())
    }

    fn record_failure(&self, ip: IpAddr) {
        let mut entry = self.inner.entry(ip).or_insert(LoginAttempts {
            window_start: Instant::now(),
            attempts: 0,
            failures: 0,
            locked_until: None,
        });
        let e = entry.value_mut();
        e.failures += 1;
        if e.failures >= Self::LOCK_THRESHOLD {
            e.locked_until = Some(Instant::now() + Duration::from_secs(Self::LOCK_MINUTES * 60));
        }
    }

    fn record_success(&self, ip: IpAddr) {
        self.inner.remove(&ip);
    }
}

// ==================== 命令映射（与桌面 IPC 同语义） ====================

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

/// 导出接入链接（含明文密码）——经 Web 暴露必须 `confirm=true` 二次确认。
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
