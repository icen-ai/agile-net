//! Client control-plane Web API (the server side of anet-gui switch C "Web remote panel",
//! and the svc embedded client role behind the node admin login).
//!
//! Two serving modes share one REST router:
//! - Embedded: [`client_api_router`] / [`client_api_router_with_audit`] expose pure REST routes
//!   (nodes / credentials / proxy / parse-connect-url / consoles) with NO auth middleware —
//!   the host mounts them under its own guard (the node nests them at `/api/v1/client/*`
//!   behind AdminAuth, sharing the admin JWT).
//! - Standalone: [`start_client_api`] wraps the same router with its own password auth
//!   (`/api/v1/auth/login|init` + HS256 JWT, 12h) and optional SPA hosting; this is what the
//!   desktop Web remote panel keeps using.
//!
//! Security (unchanged): admin password argon2id (host-injected), login rate-limited per IP
//! (5/min, locked 15 min after consecutive failures), audits never contain password/token
//! plaintext, credential export requires a `confirm=true` second confirmation (code 40001).

use crate::{AgileNetClient, ConnectParams, Credential, CredentialStore, NodeState};

use agile_net_core::tunnel::opener::ChannelOpener;
use agile_net_core::util::{LoginBlockReason, LoginRateLimiter};
use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, header, request::Parts},
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

/// Audit callback of the pure REST router (credential export / console open; never plaintext).
pub type ClientAudit = Arc<dyn Fn(&str, serde_json::Value) + Send + Sync>;

/// SPA static assets (path → content), injected by the host via include_str!.
/// `index` serves "/" and "/index.html"; every other referenced asset rides in `files`
/// (path without a leading slash, e.g. "lang/desktop-core.js"). A flat list instead of named
/// fields: a newly added shared file can never silently 404 the panel again.
pub struct SpaAssets {
    pub index: &'static str,
    pub files: Vec<(&'static str, &'static str)>,
}

/// State of the pure REST router (auth lives with the host).
#[derive(Clone)]
struct ClientApiState {
    client: AgileNetClient,
    creds: Option<Arc<CredentialStore>>,
    audit: Option<ClientAudit>,
    /// Loopback console forwarders (key -> bound port; accept tasks live for the process,
    /// same ensure-pattern as the desktop host)
    consoles: ConsoleRegistry,
}

type ConsoleRegistry = Arc<tokio::sync::Mutex<std::collections::HashMap<String, u16>>>;

/// Standalone-mode auth state (password login + rate limiting; desktop Web remote panel).
#[derive(Clone)]
struct StandaloneState {
    auth: Arc<dyn ClientWebAuth>,
    limiter: LoginRateLimiter,
}

/// Pure REST router of the client control plane (no auth middleware; the host guards it).
///
/// Paths are relative (`/nodes`, `/credentials`, …): nest at `/api/v1` to reproduce the
/// standalone shape, or at `/api/v1/client` for the svc single-port mount.
pub fn client_api_router<S>(client: AgileNetClient, creds: Option<Arc<CredentialStore>>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    client_api_router_with_audit(client, creds, None)
}

/// [`client_api_router`] with a sensitive-op audit callback (export / console open).
pub fn client_api_router_with_audit<S>(
    client: AgileNetClient,
    creds: Option<Arc<CredentialStore>>,
    audit: Option<ClientAudit>,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let state = ClientApiState {
        client,
        creds,
        audit,
        consoles: ConsoleRegistry::default(),
    };
    Router::new()
        // ---- Nodes ----
        .route("/nodes", get(list_nodes).post(connect_node))
        .route("/nodes/disconnect", post(disconnect_node))
        .route("/nodes/pending-note", post(send_pending_note))
        .route(
            "/nodes/paused-rules",
            get(get_paused_rules).put(set_paused_rules),
        )
        .route("/nodes/paused-rules/toggle", post(toggle_rule_paused))
        // ---- Credentials ----
        .route("/credentials", get(list_credentials))
        .route("/credentials", delete(delete_credential))
        .route("/credentials/export", get(export_credential))
        .route("/credentials/rename", post(rename_credential))
        .route("/credentials/myname", post(set_credential_myname))
        // ---- Machine identity (node.md M4-T4: device card on the client plane) ----
        .route("/identity", get(machine_identity))
        .route("/identity/myname", post(set_machine_myname))
        // ---- Proxy ----
        .route("/proxy/start", post(start_proxy))
        .route("/proxy/stop", post(stop_proxy))
        .route("/proxy/status", get(proxy_status))
        // ---- Delegated admin consoles ----
        .route("/consoles", get(list_consoles))
        .route("/consoles/open", post(open_console))
        // ---- Notifications (node.md M4: session notices / rejections / approvals) ----
        .route("/notifications", get(list_notifications).delete(clear_notifications))
        .route("/notifications/read-all", post(notifications_read_all))
        .route("/notifications/read", post(notification_read))
        // ---- Util ----
        .route("/parse-connect-url", post(parse_connect_url))
        .with_state(state)
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

/// Start the standalone client control-plane Web API (self-contained password auth + optional
/// SPA hosting; the desktop Web remote panel mode).
pub async fn start_client_api(
    client: AgileNetClient,
    creds: Option<Arc<CredentialStore>>,
    auth: Arc<dyn ClientWebAuth>,
    listen: SocketAddr,
    spa: Option<SpaAssets>,
) -> Result<ClientApiHandle> {
    let standalone = StandaloneState {
        auth: auth.clone(),
        limiter: LoginRateLimiter::new(),
    };
    let audit: ClientAudit = Arc::new(move |action: &str, detail: serde_json::Value| {
        auth.audit(action, detail);
    });

    // REST routes keep the historical /api/v1/* shape; login/init stay public, the guard
    // below covers everything defined so far (SPA routes merge after it, unguarded).
    let rest: Router = client_api_router_with_audit(client, creds, Some(audit));
    let auth_routes: Router = Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/init", post(init_password))
        .with_state(standalone.clone());
    let mut app = Router::new()
        .nest("/api/v1", rest)
        .merge(auth_routes)
        .layer(axum::middleware::from_fn_with_state(
            standalone,
            auth_middleware,
        ));

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
    fn content_type_of(path: &str) -> &'static str {
        match path.rsplit('.').next() {
            Some("js") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("html") => "text/html; charset=utf-8",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("woff2") => "font/woff2",
            _ => "application/octet-stream",
        }
    }
    let index = spa.index;
    let mut r = Router::new()
        .route("/", get(move || serve(index, "text/html; charset=utf-8")))
        .route(
            "/index.html",
            get(move || serve(index, "text/html; charset=utf-8")),
        );
    for (path, content) in spa.files {
        let ct = content_type_of(path);
        r = r.route(&format!("/{path}"), get(move || serve(content, ct)));
    }
    r
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

// ==================== auth (standalone mode) ====================

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

/// Source-IP extractor (injected via the ConnectInfo extension; state-agnostic so both
/// serving modes — and the node-nested mount — can use it).
struct ClientIp(IpAddr);

impl<S> axum::extract::FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
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
    State(state): State<StandaloneState>,
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
    State(state): State<StandaloneState>,
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
    State(state): State<StandaloneState>,
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

/// Delegated connect input (the only connection mode).
#[derive(Debug, Deserialize)]
struct ConnectInput {
    addr: String,
    label: String,
    token: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    pinned_fingerprint: Option<String>,
    #[serde(default)]
    manage_hosts: bool,
    #[serde(default)]
    save_credential: bool,
    #[serde(default)]
    entries: Vec<String>,
    #[serde(default)]
    entry_fps: Vec<String>,
    #[serde(default)]
    en: Option<String>,
    #[serde(default)]
    ek: Option<String>,
    #[serde(default)]
    emode: Option<String>,
    #[serde(default)]
    eadmin: bool,
    /// Self-declared display name suggestion ("我的名称", link myname word)
    #[serde(default)]
    myname: Option<String>,
    #[serde(default)]
    visibility: Option<String>,
    /// Anti-correlation padding tier (trust profile G1②, link `pad` word)
    #[serde(default)]
    padding: bool,
}

async fn connect_node(State(state): State<ClientApiState>, Json(input): Json<ConnectInput>) -> Response {
    let params = ConnectParams {
        addr: input.addr.clone(),
        label: input.label.clone(),
        token: input.token.clone(),
        insecure: input.insecure,
        pinned_fingerprint: input.pinned_fingerprint.clone(),
        manage_hosts: input.manage_hosts,
        entries: input.entries.clone(),
        entry_fps: input.entry_fps.clone(),
        en: input.en.clone(),
        ek: input.ek.clone(),
        emode: input.emode.clone(),
        eadmin: input.eadmin,
        myname: input.myname.clone(),
        padding: input.padding,
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
                    label: input.label,
                    token: input.token,
                    name: None,
                    insecure: input.insecure,
                    pinned_fingerprint: input.pinned_fingerprint,
                    entries: input.entries,
                    entry_fps: input.entry_fps,
                    en: input.en,
                    ek: input.ek,
                    emode: input.emode,
                    eadmin: input.eadmin,
                    myname: input.myname,
                    visibility: input.visibility,
                    padding: input.padding,
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

async fn disconnect_node(State(state): State<ClientApiState>, Json(req): Json<NodeIdReq>) -> Response {
    state.client.disconnect(&req.node_id).await;
    ok(serde_json::json!({ "disconnected": true }))
}

// ---- notifications (M4) ----

async fn list_notifications(State(state): State<ClientApiState>) -> Response {
    let center = state.client.notifications();
    ok(serde_json::json!({
        "items": center.list(),
        "unread": center.unread_count(),
    }))
}

async fn notifications_read_all(State(state): State<ClientApiState>) -> Response {
    state.client.notifications().mark_all_read();
    ok(serde_json::json!({ "unread": 0 }))
}

#[derive(Deserialize)]
struct NotificationReadReq {
    id: String,
}

async fn notification_read(State(state): State<ClientApiState>, Json(req): Json<NotificationReadReq>) -> Response {
    state.client.notifications().mark_read(&req.id);
    ok(serde_json::json!({ "read": req.id }))
}

async fn clear_notifications(State(state): State<ClientApiState>) -> Response {
    state.client.notifications().clear();
    ok(serde_json::json!({ "cleared": true }))
}

// ---- pending-session appeals (M4-T3) ----

#[derive(Deserialize)]
struct PendingNoteReq {
    node_id: String,
    body: String,
}

/// Upload one appeal note to the issuer over the pending session's control plane (the issuer
/// caps these at MAX_PENDING_NOTES=3 per session; the UI only offers this in PendingApproval).
async fn send_pending_note(
    State(state): State<ClientApiState>,
    Json(req): Json<PendingNoteReq>,
) -> Response {
    let body = req.body.trim();
    if body.is_empty() || body.chars().count() > 512 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "附言不能为空且不超过 512 字",
        );
    }
    match state.client.send_pending_note(&req.node_id, body).await {
        Ok(()) => ok(serde_json::json!({ "sent": true })),
        Err(e) => err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, e.to_string()),
    }
}

// ---- machine identity (M4-T4) ----

/// Machine identity view: the loaded/created machine identity plus the current self-declared
/// display name (first non-empty credential myname; the card edits it across all credentials).
async fn machine_identity(State(state): State<ClientApiState>) -> Response {
    let id = match tokio::task::spawn_blocking(agile_net_core::device::DeviceIdentity::machine)
        .await
    {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            )
        }
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    };
    let fp = id.device_fp();
    let mut myname = String::new();
    if let Some(store) = &state.creds {
        for key in store.keys().await {
            if let Some(c) = store.get(&key).await
                && let Some(m) = c.myname.as_deref().map(str::trim).filter(|m| !m.is_empty())
            {
                myname = m.to_string();
                break;
            }
        }
    }
    ok(serde_json::json!({
        "device_fp": fp,
        "openssh_pubkey": id.openssh_pubkey(&format!("anet-{}", &fp[..12])),
        "myname": myname,
    }))
}

#[derive(Deserialize)]
struct MynameReq {
    name: String,
}

/// Edit the self-declared display name ("我的名称") across every saved credential; live
/// sessions keep their handshake name — the new value rides the next connect.
async fn set_machine_myname(
    State(state): State<ClientApiState>,
    Json(req): Json<MynameReq>,
) -> Response {
    let name = req.name.trim().to_string();
    if name.chars().count() > 64 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "我的名称最长 64 字",
        );
    }
    let Some(store) = &state.creds else {
        return err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, "凭据存储不可用");
    };
    let mut updated = 0usize;
    for key in store.keys().await {
        if let Some(mut cred) = store.get(&key).await {
            cred.myname = if name.is_empty() { None } else { Some(name.clone()) };
            store.save(&key, &cred).await;
            updated += 1;
        }
    }
    ok(serde_json::json!({ "updated": updated }))
}

async fn list_nodes(State(state): State<ClientApiState>) -> Response {
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

async fn get_paused_rules(State(state): State<ClientApiState>, Query(q): Query<PausedQuery>) -> Response {
    ok(state.client.get_paused_rules(&q.node_id))
}

#[derive(Deserialize)]
struct SetPausedReq {
    node_id: String,
    keys: Vec<String>,
}

async fn set_paused_rules(
    State(state): State<ClientApiState>,
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
    State(state): State<ClientApiState>,
    Json(req): Json<TogglePausedReq>,
) -> Response {
    state
        .client
        .set_rule_paused(&req.node_id, &req.rule_key, req.paused);
    ok(serde_json::json!({ "updated": true }))
}

async fn list_credentials(State(state): State<ClientApiState>) -> Response {
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
    State(state): State<ClientApiState>,
    Query(q): Query<CredKeyQuery>,
) -> Response {
    if let Some(store) = &state.creds {
        store.remove(&q.key).await;
    }
    ok(serde_json::json!({ "deleted": true }))
}

#[derive(Deserialize)]
struct RenameReq {
    key: String,
    name: Option<String>,
}

/// User-assigned display alias (M4-T6 naming triplet, local name field); empty clears it back
/// to the node-id-derived name. The store key (node_id) never changes.
async fn rename_credential(State(state): State<ClientApiState>, Json(req): Json<RenameReq>) -> Response {
    let Some(store) = &state.creds else {
        return err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, "凭据存储不可用");
    };
    let Some(mut cred) = store.get(&req.key).await else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "凭据不存在或已删除");
    };
    let name = req.name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    if let Some(n) = &name
        && n.chars().count() > 32
    {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "名字最长 32 字",
        );
    }
    cred.name = name;
    store.save(&req.key, &cred).await;
    ok(serde_json::json!({ "renamed": true }))
}

#[derive(Deserialize)]
struct CredMynameReq {
    key: String,
    myname: Option<String>,
}

/// Self-declared display name uploaded to the issuer on the next connect (M4-T6 我的名称).
async fn set_credential_myname(
    State(state): State<ClientApiState>,
    Json(req): Json<CredMynameReq>,
) -> Response {
    let Some(store) = &state.creds else {
        return err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, "凭据存储不可用");
    };
    let Some(mut cred) = store.get(&req.key).await else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "凭据不存在或已删除");
    };
    let myname = req.myname.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    if let Some(n) = &myname
        && n.chars().count() > 64
    {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "我的名称最长 64 字",
        );
    }
    cred.myname = myname;
    store.save(&req.key, &cred).await;
    ok(serde_json::json!({ "updated": true }))
}

#[derive(Deserialize)]
struct ExportQuery {
    key: String,
    #[serde(default)]
    confirm: bool,
}

/// Export a connect URL (contains the token plaintext) — Web exposure requires a `confirm=true` second confirmation.
async fn export_credential(
    State(state): State<ClientApiState>,
    ClientIp(ip): ClientIp,
    Query(q): Query<ExportQuery>,
) -> Response {
    if !q.confirm {
        return err(
            StatusCode::CONFLICT,
            codes::VALIDATION_FAILED,
            "凭据导出含明文令牌，需二次确认（confirm=true）",
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
    if let Some(audit) = &state.audit {
        audit(
            "web.credential_export",
            serde_json::json!({"key": q.key, "ip": ip.to_string()}),
        );
    }
    ok(crate::connect_url_of(&c))
}

#[derive(Deserialize)]
struct StartProxyReq {
    port: u16,
}

async fn start_proxy(State(state): State<ClientApiState>, Json(req): Json<StartProxyReq>) -> Response {
    match state.client.start_proxy(req.port).await {
        Ok(()) => ok(state.client.proxy_port()),
        Err(e) => err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, e.to_string()),
    }
}

async fn stop_proxy(State(state): State<ClientApiState>) -> Response {
    state.client.stop_proxy().await;
    ok(serde_json::json!({ "stopped": true }))
}

async fn proxy_status(State(state): State<ClientApiState>) -> Response {
    let port = state.client.proxy_port();
    ok(serde_json::json!({ "running": port > 0, "port": port }))
}

#[derive(Deserialize)]
struct ParseUrlReq {
    url: String,
}

async fn parse_connect_url(
    State(_state): State<ClientApiState>,
    Json(req): Json<ParseUrlReq>,
) -> Response {
    match crate::parse_connect_url(&req.url) {
        Ok(input) => ok(input),
        Err(e) => err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, e),
    }
}

// ==================== delegated admin consoles ====================

#[derive(Serialize)]
struct ConsoleEntry {
    node_id: String,
    name: String,
    /// "issuer" = the credential's own issuer console (eadmin); "upstream" = a
    /// transit-management offer discovered through it (full scope)
    kind: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    scope: String,
}

/// List reachable admin consoles: the issuer of every eadmin credential (admin_console) plus
/// the manageable upstreams discovered through it — drives the SPA's admin dropdown.
async fn list_consoles(State(state): State<ClientApiState>) -> Response {
    let mut out: Vec<ConsoleEntry> = Vec::new();
    for n in state.client.list_nodes().await {
        if n.admin_console {
            out.push(ConsoleEntry {
                node_id: n.node_id.clone(),
                name: n.node_name.clone(),
                kind: "issuer",
                scope: String::new(),
            });
        }
        for m in &n.manageable {
            out.push(ConsoleEntry {
                node_id: n.node_id.clone(),
                name: m.node_name.clone(),
                kind: "upstream",
                scope: m.scope.clone(),
            });
        }
    }
    ok(out)
}

#[derive(Deserialize)]
struct OpenConsoleReq {
    node_id: String,
    #[serde(default)]
    upstream: Option<String>,
}

/// Open (or reuse) a loopback HTTP forwarder into a delegated admin console and return its
/// URL carrying the current bootstrap ticket (same flow as the desktop console window).
async fn open_console(
    State(state): State<ClientApiState>,
    Json(req): Json<OpenConsoleReq>,
) -> Response {
    use agile_net_core::relay::e2e;
    let Some(opener) = state.client.opener(&req.node_id) else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "节点未连接");
    };
    // Fresh ticket per open: the issuer mints one per config pull and the cached one carries a 1h
    // TTL from session start (stale on long-lived sessions); best-effort, falls back to the cache
    let _ = state.client.refresh_delegation_config(&req.node_id).await;
    let (ticket, target, key) = match req.upstream.as_deref() {
        // Issuer console: bridged to the issuer's loopback API via the reserved admin target
        None => {
            let Some((ticket, _port)) = state.client.delegated_console_ticket(&req.node_id)
            else {
                return err(
                    StatusCode::NOT_FOUND,
                    codes::NOT_FOUND,
                    "该凭据未授予管理权限（或配置尚未拉取完成）",
                );
            };
            (
                ticket,
                e2e::DELEGATION_ADMIN_TARGET.to_string(),
                format!("{}|deleg-admin", req.node_id),
            )
        }
        // Transit management: the upstream's control endpoint dialed through the issuer's
        // fan-out session (reserved `upstream:<node_name>` target)
        Some(up) => {
            let Some((ticket, _host, _port, _scope)) =
                state.client.delegated_upstream_ticket(&req.node_id, up)
            else {
                return err(
                    StatusCode::NOT_FOUND,
                    codes::NOT_FOUND,
                    "上游未被发现或未授予穿透管理",
                );
            };
            (
                ticket,
                format!("{}{}", e2e::DELEGATION_UPSTREAM_PREFIX, up),
                format!("{}|deleg|{up}", req.node_id),
            )
        }
    };
    match ensure_console_forwarder(&state.consoles, &key, opener, target).await {
        Ok(port) => {
            if let Some(audit) = &state.audit {
                audit(
                    "web.console_open",
                    serde_json::json!({"node_id": req.node_id, "upstream": req.upstream}),
                );
            }
            ok(serde_json::json!({ "url": format!("http://127.0.0.1:{port}/#boot={ticket}") }))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e),
    }
}

/// Bind a loopback forwarder piping every accepted connection into one console channel
/// (registry-keyed; re-opening the same console reuses its port).
async fn ensure_console_forwarder(
    reg: &ConsoleRegistry,
    key: &str,
    opener: Arc<dyn ChannelOpener>,
    target: String,
) -> std::result::Result<u16, String> {
    let mut map = reg.lock().await;
    if let Some(p) = map.get(key) {
        return Ok(*p);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let opener = opener.clone();
            let target = target.clone();
            tokio::spawn(async move {
                match opener.open("", &target, 0).await {
                    Ok(ch) => {
                        let _ = agile_net_core::relay::bridge::bridge(stream, ch).await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "console channel open failed");
                    }
                }
            });
        }
    });
    map.insert(key.to_string(), port);
    Ok(port)
}
