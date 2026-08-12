//! Auth API handlers (see docs/api/auth.md)
//!
//! Blocking-call convention: argon2id verify/hash (0.5-2s CPU), JWT issue/rotation (with
//! internal DB writes) and all DB access must be offloaded via `offload` / `ApiState::db_call`
//! to the blocking thread pool; never run them synchronously inside an async handler.

use crate::api::extractors::{AnyAuth, ClientIp};
use crate::api::{ApiState, LoginBlockReason, codes, err, offload, ok};
use crate::db::{hash_password, verify_password};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

pub async fn login(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginRequest>,
) -> Response {
    // Rate limiting and lockout
    if let Err(reason) = state.login_limiter.check(ip) {
        let msg = match reason {
            LoginBlockReason::RateLimited => "too many login attempts, try again later".to_string(),
            LoginBlockReason::Locked(d) => {
                format!("account locked, try again in {} seconds", d.as_secs())
            }
        };
        return err(StatusCode::TOO_MANY_REQUESTS, codes::RATE_LIMITED, msg);
    }

    // Input constraints
    if req.username.len() > 64 || req.password.len() > 256 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "invalid input length",
        );
    }

    // Admin login (the only remaining credential kind)
    let username = req.username.clone();
    let admin = state
        .db_call(move |db| db.get_admin_by_username(&username))
        .await;
    if let Ok(Some(admin)) = admin {
        // argon2id verify is CPU-heavy; offload to the blocking pool
        let password = req.password.clone();
        let hash = admin.password_hash.clone();
        let verified = offload(move || verify_password(&password, &hash))
            .await
            .unwrap_or(false);
        if verified {
            state.login_limiter.record_success(ip);
            let jwt = state.jwt.clone();
            let (sub, uname) = (admin.id.clone(), admin.username.clone());
            let tokens = match offload(move || jwt.issue(&sub, &uname, "admin")).await {
                Ok(t) => t,
                Err(e) => {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        codes::INTERNAL,
                        e.to_string(),
                    );
                }
            };
            let (sub, uname, ip_s) = (admin.id.clone(), admin.username.clone(), ip.to_string());
            let _ = state
                .db_call(move |db| {
                    db.record_audit_log(Some(&sub), &uname, "admin.login", None, None, Some(&ip_s))
                })
                .await;
            return ok(json!({
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token,
                "role": "admin",
                "expires_in": tokens.expires_in,
            }))
            .into_response();
        }
        state.login_limiter.record_failure(ip);
        return err(
            StatusCode::UNAUTHORIZED,
            codes::INVALID_CREDENTIALS,
            "invalid username or password",
        );
    }

    // No admin with this username
    state.login_limiter.record_failure(ip);
    err(
        StatusCode::UNAUTHORIZED,
        codes::INVALID_CREDENTIALS,
        "invalid username or password",
    )
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RefreshRequest>,
) -> Response {
    // refresh rotates with a DB write per call (revoke + issue); must be throttled
    if state.refresh_limiter.check(ip).is_err() {
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            codes::RATE_LIMITED,
            "too many refresh attempts, try again later",
        );
    }
    let jwt = state.jwt.clone();
    let rt = req.refresh_token;
    match offload(move || jwt.refresh(&rt)).await {
        Ok((claims, tokens)) => ok(json!({
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "role": claims.role,
            "expires_in": tokens.expires_in,
        }))
        .into_response(),
        Err(_) => err(
            StatusCode::UNAUTHORIZED,
            codes::TOKEN_REVOKED,
            "refresh token expired or revoked",
        ),
    }
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: Option<String>,
}

pub async fn logout(
    State(state): State<ApiState>,
    AnyAuth(claims): AnyAuth,
    Json(req): Json<LogoutRequest>,
) -> Response {
    if let Some(rt) = req.refresh_token {
        let jwt = state.jwt.clone();
        let _ = offload(move || jwt.revoke(&rt)).await;
    }
    let (sub, uname) = (claims.sub.clone(), claims.username.clone());
    let _ = state
        .db_call(move |db| {
            db.record_audit_log(Some(&sub), &uname, "admin.logout", None, None, None)
        })
        .await;
    ok(json!(null)).into_response()
}

#[derive(Deserialize)]
pub struct InitRequest {
    pub username: String,
    pub password: String,
}

/// First-time admin initialization (only available while the DB has no admin).
pub async fn init(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<InitRequest>,
) -> Response {
    // This endpoint is anonymous until the first admin exists: rate-limit it like the other
    // bootstrap path so a network-reachable node can't be brute-forced or first-use hijacked.
    if state.bootstrap_limiter.check(ip).is_err() {
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            codes::RATE_LIMITED,
            "too many init attempts, try again later",
        );
    }
    if state.db_call(|db| db.has_admin()).await.unwrap_or(true) {
        return err(
            StatusCode::FORBIDDEN,
            codes::FORBIDDEN,
            "admin already initialized",
        );
    }

    if let Err(msg) = validate_admin_credentials(&req.username, &req.password) {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }

    // argon2id hash is CPU-heavy; offload to the blocking pool
    let password = req.password.clone();
    let password_hash = match offload(move || hash_password(&password)).await {
        Ok(h) => h,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };

    let username = req.username.clone();
    match state
        .db_call(move |db| db.create_admin(&username, &password_hash))
        .await
    {
        Ok(admin) => {
            let (aid, uname, ip_s) = (admin.id.clone(), admin.username.clone(), ip.to_string());
            let _ = state
                .db_call(move |db| {
                    db.record_audit_log(Some(&aid), &uname, "admin.init", None, None, Some(&ip_s))
                })
                .await;
            ok(json!({
                "admin_id": admin.id,
                "message": "admin created, please login",
            }))
            .into_response()
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

pub async fn me(AnyAuth(claims): AnyAuth) -> Response {
    ok(json!({
        "id": claims.sub,
        "username": claims.username,
        "role": claims.role,
        "scope": claims.scope,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct BootstrapRequest {
    pub ticket: String,
}

/// Redeem an admin bootstrap ticket for an admin session (zero-touch via the console channel).
///
/// Ticket sources: the relay exposed-control-plane handshake (kind=relay, minted per handshake)
/// or the delegation E2E config channel (kind=relay with a `deleg:` subject, minted per pull).
/// Tickets are short-lived, use-capped, hash-only in DB; redemption is audited (identity + path).
pub async fn admin_bootstrap(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<BootstrapRequest>,
) -> Response {
    // Ticket redemption rate limit (same tier as refresh; anti brute-force enumeration)
    if state.bootstrap_limiter.check(ip).is_err() {
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            codes::RATE_LIMITED,
            "too many bootstrap attempts, try again later",
        );
    }
    if req.ticket.len() > 128 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "invalid ticket",
        );
    }
    let ticket = req.ticket.clone();
    let Some(t) = state
        .db_call(move |db| db.redeem_admin_ticket(&ticket))
        .await
        .unwrap_or(None)
    else {
        return err(
            StatusCode::UNAUTHORIZED,
            codes::INVALID_CREDENTIALS,
            "invalid or expired ticket",
        );
    };

    match t.kind.as_str() {
        "relay" => {
            // P2: relay token redeemed for an admin session. subject = "psk_<prefix>@<downstream node name>".
            let jwt = state.jwt.clone();
            let (sub, scope) = (t.subject.clone(), t.scope.clone());
            let tokens =
                match offload(move || jwt.issue_with_scope(&sub, &sub, "admin", &scope)).await {
                    Ok(t) => t,
                    Err(e) => {
                        return err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            codes::INTERNAL,
                            e.to_string(),
                        );
                    }
                };
            let (subject, scope, ip_s) = (t.subject.clone(), t.scope.clone(), ip.to_string());
            let _ = state
                .db_call(move |db| {
                    let node_name = db
                        .get_config("node_name")
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    db.record_audit_log(
                        None,
                        &format!("relay:{subject}"),
                        "admin.session_via_relay",
                        Some(&node_name),
                        Some(&format!(
                            "凭中继会话换取管理会话（scope={scope}，来源=隧道）"
                        )),
                        Some(&ip_s),
                    )
                })
                .await;
            ok(json!({
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token,
                "role": "admin",
                "scope": t.scope,
                "expires_in": tokens.expires_in,
            }))
            .into_response()
        }
        _ => err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "unknown ticket kind",
        ),
    }
}

/// Admin credential strength validation (username rules + password strength).
pub(crate) fn validate_admin_credentials(username: &str, password: &str) -> Result<(), String> {
    if username.is_empty() || username.len() > 32 {
        return Err("username must be 1-32 characters".into());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("username may only contain [a-zA-Z0-9_-]".into());
    }
    validate_password_strength(password)
}

/// Control-plane password strength policy (>= 10 chars with lower/upper letters and digits).
/// Exported for reuse by the desktop Web remote password setup (agile_net_node::api::handlers::auth path).
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 10 {
        return Err("password must be at least 10 characters".into());
    }
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    if !(has_lower && has_upper && has_digit) {
        return Err("password must contain lower, upper and digit characters".into());
    }
    Ok(())
}
