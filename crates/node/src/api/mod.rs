//! HTTP API routes and shared helpers
//!
//! Uniform response body: success `{"code":0,"data":...}`, error `{"code":xxxxx,"message":"..."}`.
//! Error code ranges follow docs/api/overview.md.

pub mod extractors;
pub mod handlers;

use crate::auth::jwt::JwtService;
use crate::db::Database;
use crate::logs::LogBuffer;
use crate::service::connectors::ConnectorManager;
use agile_net_core::proxy::inbound::ProxyStats;
use agile_net_core::relay::listener::RelayListener;
use agile_net_core::relay::transit::TransitMeter;
use axum::{
    Router,
    routing::{any, delete, get, post, put},
};
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

// Login rate limiter lives in core (shared by server/client); re-exported to keep the crate::api path
pub use agile_net_core::util::{LoginBlockReason, LoginRateLimiter};

/// Runtime shared state (data-plane handles, read by status APIs).
pub struct NodeRuntime {
    pub started_at: Instant,
    pub listener: Option<Arc<RelayListener>>,
    /// Fan-out connector manager (multi-target fan-out/failover; DB is the single source of truth)
    pub connector_manager: Arc<ConnectorManager>,
    pub proxy_stats: Option<Arc<ProxyStats>>,
    pub proxy_listen: Option<String>,
    pub log_buffer: LogBuffer,
    /// Relay cert SHA-256 fingerprint (for client cert pinning; None in ACME mode)
    pub cert_fingerprint: Option<String>,
    /// Relay TLS SNI hostname served by the listener (static: configured sni_hostname; ACME: the domain; None without listener)
    pub relay_sni: Option<String>,
    /// Manageable upstream registry (handshake v2 discovery; for config delivery and status display)
    pub manageable: crate::relay_auth::ManageableRegistry,
    /// Client-role proxy state slot (written by the GUI host; overrides the status proxy section when set)
    pub client_proxy_slot: crate::service::ClientProxySlot,
    /// Relay transit meter (instrumented at listener/connector/proxy; data source for the status transit section)
    pub transit_meter: Arc<TransitMeter>,
    /// This machine's device identity (node.md M2): connectors prove it at the handshake; the
    /// admin identity card renders device_fp + OpenSSH pubkey from it
    pub device: Arc<agile_net_core::device::DeviceIdentity>,
    /// Device gate cache (M3-T2): certification state for the data plane + the pending policy;
    /// None when the relay listener is disabled
    pub device_gate: Option<Arc<crate::service::device_gate::DeviceGateCache>>,
    /// Admin-plane events bus (approval.new / device state changes; WS subscribers)
    pub admin_events: tokio::sync::broadcast::Sender<serde_json::Value>,
}

impl NodeRuntime {
    /// Aggregate fan-out status: connected if any link is up, disabled when no fan-out is configured.
    pub fn connector_status(&self) -> &'static str {
        self.connector_manager.aggregate_status()
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

#[derive(Clone)]
pub struct ApiState {
    pub db: Database,
    pub jwt: Arc<JwtService>,
    pub runtime: Arc<NodeRuntime>,
    pub login_limiter: LoginRateLimiter,
    /// Rate limit for the refresh endpoint (10/min/IP; refresh rotates with a DB write per call, must be throttled)
    pub refresh_limiter: LoginRateLimiter,
    /// Rate limit for admin-bootstrap ticket redemption (10/min/IP; tickets are enumerable, anti brute-force)
    pub bootstrap_limiter: LoginRateLimiter,
    /// Node public endpoint host (hot-updatable via the settings API at runtime)
    public_host: Arc<arc_swap::ArcSwap<String>>,
    /// Admin API port (connect_url points at this endpoint for login)
    api_port: u16,
    /// Relay data-plane port (config.tunnel points at this endpoint to establish tunnels)
    relay_port: u16,
}

impl ApiState {
    pub fn new(
        db: Database,
        jwt: Arc<JwtService>,
        runtime: Arc<NodeRuntime>,
        public_host: String,
        api_port: u16,
        relay_port: u16,
    ) -> Self {
        Self {
            db,
            jwt,
            runtime,
            login_limiter: LoginRateLimiter::new(),
            refresh_limiter: LoginRateLimiter::new().with_config(10, u32::MAX, 15),
            bootstrap_limiter: LoginRateLimiter::new().with_config(10, u32::MAX, 15),
            public_host: Arc::new(arc_swap::ArcSwap::from_pointee(public_host)),
            api_port,
            relay_port,
        }
    }

    /// Admin API port (startup value; NodeServer backfills the actual value for dynamic ports).
    pub fn api_port(&self) -> u16 {
        self.api_port
    }

    /// Backfill the actually bound API port (called after port 0 dynamic allocation).
    pub fn set_api_port(&mut self, port: u16) {
        self.api_port = port;
    }

    /// Public API endpoint (share links / ticket delivery).
    pub async fn public_api_endpoint(&self) -> (String, u16) {
        // Prefer the runtime setting from DB, fall back to the startup value
        let host = self
            .db_call(|db| db.get_config("public_host"))
            .await
            .ok()
            .flatten()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.public_host.load().as_ref().clone());
        (host, self.api_port)
    }

    /// Data-plane tunnel endpoint (for client config).
    pub async fn public_tunnel_endpoint(&self) -> (String, u16) {
        let (host, _) = self.public_api_endpoint().await;
        (host, self.relay_port)
    }

    /// Declared API base address: `public_api_url` (full scheme://host[:port] override for
    /// reverse-proxy fronted APIs, DB config) > public_host:api_port.
    pub async fn public_api_addr(&self) -> String {
        if let Some(url) = self
            .db_call(|db| db.get_config("public_api_url"))
            .await
            .ok()
            .flatten()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
        {
            return url;
        }
        let (host, port) = self.public_api_endpoint().await;
        format!("{host}:{port}")
    }

    /// Whether the declared public host is a real external identity (not the 127.0.0.1 default).
    fn declared_public_host(host: &str) -> bool {
        let h = host.trim();
        !h.is_empty() && h != "127.0.0.1" && h != "localhost" && h != "::1"
    }

    /// Relay data-plane share address (fanout links): the declared public identity
    /// (public_host:relay_port) when set, else the listener's own address.
    pub async fn public_relay_addr(&self) -> String {
        if let Some(addr) = self.declared_relay_addr().await {
            return addr;
        }
        let (host, port) = self.public_tunnel_endpoint().await;
        self.runtime
            .listener
            .as_ref()
            .map(|l| l.listen_addr().to_string())
            .unwrap_or_else(|| format!("{host}:{port}"))
    }

    /// Declared public relay identity (Some only when public_host is a real external address).
    pub async fn declared_relay_addr(&self) -> Option<String> {
        let (host, port) = self.public_tunnel_endpoint().await;
        Self::declared_public_host(&host).then(|| format!("{host}:{port}"))
    }

    /// Declared public API identity: the full public_api_url override wins; else public_host:api_port
    /// when it is a real external address; None when undeclared.
    pub async fn declared_api_addr(&self) -> Option<String> {
        if let Some(url) = self
            .db_call(|db| db.get_config("public_api_url"))
            .await
            .ok()
            .flatten()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
        {
            return Some(url);
        }
        let (host, port) = self.public_api_endpoint().await;
        Self::declared_public_host(&host).then(|| format!("{host}:{port}"))
    }

    /// Share-endpoint candidates for issuance dialogs (federation P1: relay-vs-direct choice).
    /// `public` = the declared public identity for this role (full API URL or host:port),
    /// placed first when present; then LAN IPv4 addresses (non-loopback up interfaces);
    /// loopback as the last resort.
    pub async fn share_endpoints(&self, port: u16, public: Option<String>) -> Vec<ShareEndpoint> {
        let mut out: Vec<ShareEndpoint> = Vec::new();
        if let Some(addr) = public.filter(|a| !a.trim().is_empty()) {
            out.push(ShareEndpoint {
                kind: "public".into(),
                addr,
            });
        }
        let seen: std::collections::HashSet<String> = out.iter().map(|e| e.addr.clone()).collect();
        // Local interface enumeration (fast syscall, issuance-path only)
        let mut lan = lan_ipv4_addrs()
            .into_iter()
            .map(|ip| format!("{ip}:{port}"))
            .filter(|a| !seen.contains(a))
            .map(|addr| ShareEndpoint {
                kind: "lan".into(),
                addr,
            })
            .collect::<Vec<_>>();
        // Stable order for deterministic UI/tests
        lan.sort_by(|a, b| a.addr.cmp(&b.addr));
        out.extend(lan);
        if out.is_empty() {
            out.push(ShareEndpoint {
                kind: "local".into(),
                addr: format!("127.0.0.1:{port}"),
            });
        }
        out
    }

    /// Offload synchronous DB calls to the blocking thread pool.
    ///
    /// rusqlite is a sync API; calling it directly in an async handler holds a tokio worker
    /// (aggregate queries especially); all DB access under handlers goes through this wrapper.
    pub async fn db_call<F, T>(&self, f: F) -> agile_net_core::error::Result<T>
    where
        F: FnOnce(&Database) -> agile_net_core::error::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.db.clone();
        offload(move || f(&db)).await
    }
}

/// Share-endpoint candidate (issuance dialogs: declared public identity / LAN direct / loopback).
#[derive(Debug, Clone, Serialize)]
pub struct ShareEndpoint {
    /// "public" (declared identity) | "lan" (same-LAN direct) | "local" (loopback)
    pub kind: String,
    pub addr: String,
}

/// Enumerate LAN IPv4 addresses (non-loopback, up interfaces; default-net, the anet tool data source).
pub(crate) fn lan_ipv4_addrs() -> Vec<String> {
    let mut out: Vec<String> = default_net::get_interfaces()
        .iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .flat_map(|i| i.ipv4.iter().map(|n| n.addr.to_string()))
        .collect();
    out.sort();
    out.dedup();
    out
}

// ==================== Blocking work offload ====================
/// Unified offload point for sync blocking work: argon2id hash/verify, JWT issue/rotation
/// (with internal DB writes) and other CPU/IO-heavy calls enter the tokio blocking pool
/// here, never holding an async worker. DB access: `ApiState::db_call` (wraps this fn).
pub(crate) async fn offload<F, T>(f: F) -> agile_net_core::error::Result<T>
where
    F: FnOnce() -> agile_net_core::error::Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(e) => Err(agile_net_core::error::Error::Other(format!(
            "blocking task failed: {e}"
        ))),
    }
}

// ==================== Uniform response body ====================

pub fn ok<T: Serialize>(data: T) -> axum::response::Response {
    axum::Json(serde_json::json!({ "code": 0, "data": data })).into_response()
}

/// 201 Created (resource created)
pub fn ok_created<T: Serialize>(data: T) -> axum::response::Response {
    (
        axum::http::StatusCode::CREATED,
        axum::Json(serde_json::json!({ "code": 0, "data": data })),
    )
        .into_response()
}

pub fn err(
    status: axum::http::StatusCode,
    code: u32,
    message: impl Into<String>,
) -> axum::response::Response {
    (
        status,
        axum::Json(serde_json::json!({ "code": code, "message": message.into() })),
    )
        .into_response()
}

pub mod codes {
    pub const BAD_REQUEST: u32 = 40000;
    pub const VALIDATION_FAILED: u32 = 40001;
    pub const INVALID_CREDENTIALS: u32 = 40100;
    pub const TOKEN_EXPIRED: u32 = 40101;
    pub const TOKEN_REVOKED: u32 = 40102;
    pub const FORBIDDEN: u32 = 40300;
    pub const ADMIN_ONLY: u32 = 40301;
    pub const NOT_FOUND: u32 = 40400;
    /// Peer exists but is not connected (or no usable peer), e.g. bandwidth target connector not connected
    pub const PEER_UNAVAILABLE: u32 = 40401;
    pub const DUPLICATE: u32 = 40900;
    pub const RATE_LIMITED: u32 = 42900;
    pub const INTERNAL: u32 = 50000;
}

/// Normalize pagination params (page >= 1, page_size 1..=100).
///
/// Note: serde_urlencoded does not support #[serde(flatten)];
/// query structs must inline page/page_size fields and call this directly.
pub fn normalize_page(page: u32, page_size: u32) -> (u32, u32) {
    (page.max(1), page_size.clamp(1, 100))
}

pub(crate) fn default_page() -> u32 {
    1
}
pub(crate) fn default_page_size() -> u32 {
    20
}

use axum::response::IntoResponse;

pub fn create_app(state: ApiState) -> Router {
    Router::new()
        // ---- Auth (Public) ----
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/refresh", post(handlers::auth::refresh))
        .route("/api/v1/auth/init", post(handlers::auth::init))
        .route("/api/v1/auth/logout", post(handlers::auth::logout))
        .route(
            "/api/v1/auth/admin-bootstrap",
            post(handlers::auth::admin_bootstrap),
        )
        .route("/api/v1/auth/me", get(handlers::auth::me))
        // ---- Admin: Rules ----
        .route(
            "/api/v1/admin/rules",
            get(handlers::rules::list_rules).post(handlers::rules::create_rule),
        )
        .route(
            "/api/v1/admin/rules/batch",
            post(handlers::rules::batch_import),
        )
        .route(
            "/api/v1/admin/rules/{id}",
            put(handlers::rules::update_rule).delete(handlers::rules::delete_rule),
        )
        // ---- Admin: Groups ----
        .route(
            "/api/v1/admin/groups",
            get(handlers::groups::list_groups).post(handlers::groups::create_group),
        )
        .route(
            "/api/v1/admin/groups/{id}",
            get(handlers::groups::get_group)
                .put(handlers::groups::update_group)
                .delete(handlers::groups::delete_group),
        )
        .route(
            "/api/v1/admin/groups/{id}/rules",
            put(handlers::groups::set_group_rules),
        )
        .route(
            "/api/v1/admin/groups/{id}/detail",
            get(handlers::groups::get_group_detail),
        )
        // ---- Admin: Admins ----
        .route(
            "/api/v1/admin/admins",
            get(handlers::admins::list_admins).post(handlers::admins::create_admin),
        )
        .route(
            "/api/v1/admin/admins/{id}",
            delete(handlers::admins::delete_admin),
        )
        .route(
            "/api/v1/auth/password",
            put(handlers::admins::change_password),
        )
        // ---- Admin: Node ----
        .route("/api/v1/admin/node/status", get(handlers::node::status))
        .route("/api/v1/admin/node/logs", get(handlers::node::logs))
        .route(
            "/api/v1/admin/node/settings",
            put(handlers::node::update_settings),
        )
        .route("/api/v1/admin/node/metrics", get(handlers::node::metrics))
        .route("/api/v1/admin/node/kick", post(handlers::node::kick_peer))
        .route(
            "/api/v1/admin/node/relay-tokens",
            get(handlers::relay_tokens::list_tokens).post(handlers::relay_tokens::create_token),
        )
        .route(
            "/api/v1/admin/node/relay-tokens/{id}",
            put(handlers::relay_tokens::update_token).delete(handlers::relay_tokens::delete_token),
        )
        .route(
            "/api/v1/admin/connectors",
            get(handlers::connectors::list_connectors).post(handlers::connectors::create_connector),
        )
        .route(
            "/api/v1/admin/connectors/{id}",
            put(handlers::connectors::update_connector)
                .delete(handlers::connectors::delete_connector),
        )
        .route(
            "/api/v1/admin/connectors/{id}/enable",
            post(handlers::connectors::enable_connector),
        )
        .route(
            "/api/v1/admin/connectors/{id}/disable",
            post(handlers::connectors::disable_connector),
        )
        .route(
            "/api/v1/admin/connectors/{id}/cert-relay",
            post(handlers::connectors::toggle_cert_relay),
        )
        .route("/api/v1/admin/node/events", any(handlers::node::events_ws))
        // ---- Admin: Sessions / Devices / Approvals (node.md M3) ----
        .route(
            "/api/v1/admin/sessions",
            get(handlers::sessions::list_sessions),
        )
        .route(
            "/api/v1/admin/sessions/kick",
            post(handlers::sessions::kick_session),
        )
        .route(
            "/api/v1/admin/sessions/kick_token",
            post(handlers::sessions::kick_token),
        )
        .route(
            "/api/v1/admin/sessions/kick_fanin",
            post(handlers::sessions::kick_fanin),
        )
        .route(
            "/api/v1/admin/devices",
            get(handlers::devices::list_devices),
        )
        .route(
            "/api/v1/admin/devices/policy",
            get(handlers::devices::get_policy).put(handlers::devices::put_policy),
        )
        .route(
            "/api/v1/admin/devices/rebind",
            post(handlers::devices::rebind_device),
        )
        .route(
            "/api/v1/admin/devices/{fp}",
            get(handlers::devices::get_device),
        )
        .route(
            "/api/v1/admin/devices/{fp}/traffic",
            get(handlers::devices::device_traffic),
        )
        .route(
            "/api/v1/admin/devices/{fp}/activity",
            get(handlers::devices::device_activity),
        )
        .route(
            "/api/v1/admin/devices/{fp}/sessions",
            get(handlers::devices::device_sessions),
        )
        .route(
            "/api/v1/admin/devices/{fp}/events",
            get(handlers::devices::device_events),
        )
        .route(
            "/api/v1/admin/devices/{fp}/certify",
            post(handlers::devices::certify_device),
        )
        .route(
            "/api/v1/admin/devices/{fp}/revoke",
            post(handlers::devices::revoke_device),
        )
        .route(
            "/api/v1/admin/approvals",
            get(handlers::approvals::list_approvals),
        )
        .route(
            "/api/v1/admin/approvals/{id}/decide",
            post(handlers::approvals::decide_approval),
        )
        // ---- Admin: Federation (authorizable pool + one-click adoption) ----
        .route(
            "/api/v1/admin/federation/offered",
            get(handlers::federation::offered),
        )
        .route(
            "/api/v1/admin/federation/adopt",
            post(handlers::federation::adopt),
        )
        .route(
            "/api/v1/admin/federation/adopted/{id}/copy",
            post(handlers::federation::copy_adopted),
        )
        .route(
            "/api/v1/admin/federation/cert",
            get(handlers::federation_cert::get_cert_settings).put(handlers::federation_cert::put_cert_settings),
        )
        .route(
            "/api/v1/admin/federation/receipts",
            get(handlers::federation_cert::receipts),
        )
        // ---- Admin: Delegation (federation P2, issuer side) ----
        .route(
            "/api/v1/admin/delegation/tokens",
            get(handlers::delegation::list_tokens).post(handlers::delegation::issue_token),
        )
        .route(
            "/api/v1/admin/delegation/tokens/{id}",
            axum::routing::delete(handlers::delegation::revoke_token),
        )
        // ---- Admin: Tool (batch-4 bandwidth, the only tool command exposed via API) ----
        .route(
            "/api/v1/admin/tool/bandwidth",
            post(handlers::tool::bandwidth_test),
        )
        .route(
            "/api/v1/admin/tool/qr-decode",
            // QR screenshots routinely exceed the 2MB default body limit (decode caps at 20MB)
            post(handlers::tool::qr_decode)
                .layer(axum::extract::DefaultBodyLimit::max(21 * 1024 * 1024)),
        )
        // ---- Admin: Audit ----
        .route(
            "/api/v1/admin/audit-logs",
            get(handlers::audit::list_audit_logs),
        )
        .with_state(state)
}

// ==================== Embedded client-role mount (single-port unified web plane) ====================

/// AdminAuth gate for the embedded client API: the svc client role shares the admin login
/// (one JWT — the browser logged into the admin console calls `/api/v1/client/*` seamlessly).
/// Scope tiers degrade fail-closed exactly like the admin endpoints (full: all; rules/ro: GET).
async fn client_api_admin_guard(
    axum::extract::State(state): axum::extract::State<ApiState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::extract::FromRequestParts;
    let (mut parts, body) = req.into_parts();
    match extractors::AdminAuth::from_request_parts(&mut parts, &state).await {
        Ok(_) => next.run(axum::http::Request::from_parts(parts, body)).await,
        Err(resp) => resp,
    }
}

/// Nest the client-role REST API at `/api/v1/client/*` behind AdminAuth.
/// `audit` receives the sensitive-op events (credential export / console open; never plaintext).
pub fn mount_client_api(
    app: Router,
    state: &ApiState,
    engine: agile_net_client::AgileNetClient,
    creds: Option<Arc<agile_net_client::CredentialStore>>,
    audit: agile_net_client::api::ClientAudit,
) -> Router {
    let client_router: Router =
        agile_net_client::api::client_api_router_with_audit(engine, creds, Some(audit));
    app.nest(
        "/api/v1/client",
        client_router.layer(axum::middleware::from_fn_with_state(
            state.clone(),
            client_api_admin_guard,
        )),
    )
}
