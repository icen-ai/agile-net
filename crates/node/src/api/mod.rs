//! HTTP API 路由与共享设施
//!
//! 统一响应体：成功 `{"code":0,"data":...}`，错误 `{"code":xxxxx,"message":"..."}`。
//! 错误码段遵循 docs/api/overview.md。

pub mod extractors;
pub mod handlers;

use crate::auth::jwt::JwtService;
use crate::db::Database;
use crate::logs::LogBuffer;
use agile_net_core::proxy::inbound::ProxyStats;
use agile_net_core::relay::RelayConnector;
use agile_net_core::relay::connector::ConnectionState;
use agile_net_core::relay::listener::RelayListener;
use axum::{
    Router,
    routing::{any, delete, get, post, put},
};
use dashmap::DashMap;
use serde::Serialize;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 运行时共享状态（数据面句柄，供状态 API 读取）。
pub struct NodeRuntime {
    pub started_at: Instant,
    pub listener: Option<Arc<RelayListener>>,
    /// 全部上游 connector（多上游扇出/容灾）
    pub connectors: Vec<Arc<RelayConnector>>,
    pub proxy_stats: Option<Arc<ProxyStats>>,
    pub proxy_listen: Option<String>,
    pub log_buffer: LogBuffer,
    /// Relay 证书 SHA-256 指纹（客户端证书固定用；ACME 模式为 None）
    pub cert_fingerprint: Option<String>,
    /// 可管理上游注册表（握手 v2 发现；config 下发与状态展示用）
    pub manageable: crate::relay_auth::ManageableRegistry,
}

impl NodeRuntime {
    /// 扇出汇总状态：任一连通则 connected，全无扇出配置则 disabled。
    pub fn connector_status(&self) -> &'static str {
        if self.connectors.is_empty() {
            return "disabled";
        }
        let mut any_connected = false;
        let mut any_active = false;
        for c in &self.connectors {
            match c.state() {
                ConnectionState::Connected => any_connected = true,
                ConnectionState::Connecting | ConnectionState::Reconnecting => any_active = true,
                ConnectionState::Disconnected => {}
            }
        }
        if any_connected {
            "connected"
        } else if any_active {
            "connecting"
        } else {
            "disconnected"
        }
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
    /// refresh 端点限流（10 次/分钟/IP；refresh 每次执行 DB 写入轮换，必须限速）
    pub refresh_limiter: LoginRateLimiter,
    /// 创建/重置账号后的 connect_url 短期缓存（3 分钟，供二维码取用；含明文密码不宜长存）
    connect_url_cache: Arc<DashMap<String, (String, Instant)>>,
    /// 节点公网接入地址（运行时可通过设置 API 热更新）
    public_host: Arc<arc_swap::ArcSwap<String>>,
    /// 管理 API 端口（connect_url 指向此端点登录）
    api_port: u16,
    /// Relay 数据面端口（config.tunnel 指向此端点建立隧道）
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
            connect_url_cache: Arc::new(DashMap::new()),
            public_host: Arc::new(arc_swap::ArcSwap::from_pointee(public_host)),
            api_port,
            relay_port,
        }
    }

    /// 管理 API 端口（启动值；动态端口场景由 NodeServer 回填实际值）。
    pub fn api_port(&self) -> u16 {
        self.api_port
    }

    /// 回填实际绑定的 API 端口（端口 0 动态分配后调用）。
    pub fn set_api_port(&mut self, port: u16) {
        self.api_port = port;
    }

    /// 客户端 API 接入端点（connect_url 用）。
    pub fn public_api_endpoint(&self) -> (String, u16) {
        // 优先读数据库中的运行时设置，回落到启动值
        let host = self
            .db
            .get_config("public_host")
            .ok()
            .flatten()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.public_host.load().as_ref().clone());
        (host, self.api_port)
    }

    /// 数据面隧道端点（client config 用）。
    pub fn public_tunnel_endpoint(&self) -> (String, u16) {
        let (host, _) = self.public_api_endpoint();
        (host, self.relay_port)
    }

    pub fn remember_connect_url(&self, account_id: &str, url: &str) {
        // 顺带清理过期项
        self.connect_url_cache
            .retain(|_, (_, ts)| ts.elapsed() < Duration::from_secs(600));
        self.connect_url_cache
            .insert(account_id.to_string(), (url.to_string(), Instant::now()));
    }

    pub fn take_connect_url(&self, account_id: &str) -> Option<String> {
        self.connect_url_cache.get(account_id).and_then(|e| {
            let (url, ts) = e.value();
            // 含明文密码，仅短期缓存 3 分钟
            if ts.elapsed() < Duration::from_secs(180) {
                Some(url.clone())
            } else {
                None
            }
        })
    }
}

/// 登录频率限制器：5 次/分钟/IP，连续失败 5 次锁定 15 分钟。
#[derive(Clone)]
pub struct LoginRateLimiter {
    inner: Arc<DashMap<IpAddr, LoginAttempts>>,
    max_per_minute: u32,
    lock_threshold: u32,
    lock_duration: Duration,
}

struct LoginAttempts {
    window_start: Instant,
    attempts: u32,
    failures: u32,
    locked_until: Option<Instant>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            max_per_minute: 5,
            lock_threshold: 5,
            lock_duration: Duration::from_secs(15 * 60),
        }
    }

    /// 覆盖默认限流参数（对应 agile-net.toml [limits]）。
    pub fn with_config(
        mut self,
        max_per_minute: u32,
        lock_threshold: u32,
        lock_minutes: u32,
    ) -> Self {
        self.max_per_minute = max_per_minute.max(1);
        self.lock_threshold = lock_threshold.max(1);
        self.lock_duration = Duration::from_secs(lock_minutes.max(1) as u64 * 60);
        self
    }

    /// 检查是否允许尝试登录（限流 + 锁定判定）。
    /// 附带惰性清扫：条目数超 1024 时淘汰 30 分钟未活动的失败记录（防内存无上限增长）。
    pub fn check(&self, ip: IpAddr) -> Result<(), LoginBlockReason> {
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
        if e.attempts > self.max_per_minute {
            return Err(LoginBlockReason::RateLimited);
        }
        Ok(())
    }

    /// 记录一次登录失败（连续失败达阈值则锁定）。
    pub fn record_failure(&self, ip: IpAddr) {
        let mut entry = self.inner.entry(ip).or_insert(LoginAttempts {
            window_start: Instant::now(),
            attempts: 0,
            failures: 0,
            locked_until: None,
        });
        let e = entry.value_mut();
        e.failures += 1;
        if e.failures >= self.lock_threshold {
            e.locked_until = Some(Instant::now() + self.lock_duration);
        }
    }

    /// 登录成功，清零失败计数。
    pub fn record_success(&self, ip: IpAddr) {
        self.inner.remove(&ip);
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub enum LoginBlockReason {
    RateLimited,
    Locked(Duration),
}

// ==================== 统一响应体 ====================

pub fn ok<T: Serialize>(data: T) -> axum::response::Response {
    axum::Json(serde_json::json!({ "code": 0, "data": data })).into_response()
}

/// 201 Created（资源创建成功）
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
    pub const DUPLICATE: u32 = 40900;
    pub const RATE_LIMITED: u32 = 42900;
    pub const INTERNAL: u32 = 50000;
}

/// 分页参数规范化（page >= 1，page_size 1..=100）。
///
/// 注意：serde_urlencoded 不支持 #[serde(flatten)]，
/// 查询结构体请直接内联 page/page_size 字段并调用本函数。
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
        // ---- Client API ----
        .route("/api/v1/client/config", get(handlers::client::get_config))
        .route(
            "/api/v1/client/heartbeat",
            post(handlers::client::heartbeat),
        )
        .route(
            "/api/v1/client/console-ticket",
            post(handlers::client::console_ticket),
        )
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
        // ---- Admin: Accounts ----
        .route(
            "/api/v1/admin/accounts",
            get(handlers::accounts::list_accounts).post(handlers::accounts::create_account),
        )
        .route(
            "/api/v1/admin/accounts/{id}",
            put(handlers::accounts::update_account).delete(handlers::accounts::delete_account),
        )
        .route(
            "/api/v1/admin/accounts/{id}/reset-password",
            post(handlers::accounts::reset_password),
        )
        .route(
            "/api/v1/admin/accounts/{id}/qrcode",
            get(handlers::accounts::qrcode),
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
        .route("/api/v1/admin/node/stats", get(handlers::node::stats))
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
        .route("/api/v1/admin/node/events", any(handlers::node::events_ws))
        // ---- Admin: Audit ----
        .route(
            "/api/v1/admin/audit-logs",
            get(handlers::audit::list_audit_logs),
        )
        .with_state(state)
}
