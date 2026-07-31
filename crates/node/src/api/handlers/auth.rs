//! Auth API Handlers（对应 docs/api/auth.md）

use crate::api::extractors::{AnyAuth, ClientIp};
use crate::api::{ApiState, LoginBlockReason, codes, err, ok};
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
    // 频率限制与锁定
    if let Err(reason) = state.login_limiter.check(ip) {
        let msg = match reason {
            LoginBlockReason::RateLimited => "too many login attempts, try again later".to_string(),
            LoginBlockReason::Locked(d) => {
                format!("account locked, try again in {} seconds", d.as_secs())
            }
        };
        return err(StatusCode::TOO_MANY_REQUESTS, codes::RATE_LIMITED, msg);
    }

    // 输入约束
    if req.username.len() > 64 || req.password.len() > 256 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "invalid input length",
        );
    }

    // 1. 尝试 admin 登录
    if let Ok(Some(admin)) = state.db.get_admin_by_username(&req.username) {
        if verify_password(&req.password, &admin.password_hash).unwrap_or(false) {
            state.login_limiter.record_success(ip);
            let tokens = match state.jwt.issue(&admin.id, &admin.username, "admin") {
                Ok(t) => t,
                Err(e) => {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        codes::INTERNAL,
                        e.to_string(),
                    );
                }
            };
            let _ = state.db.record_audit_log(
                Some(&admin.id),
                &admin.username,
                "admin.login",
                None,
                None,
                Some(&ip.to_string()),
            );
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

    // 2. 尝试 client 账号登录
    match state.db.get_account_by_username(&req.username) {
        Ok(Some((account, password_hash))) => {
            if !account.enabled {
                state.login_limiter.record_failure(ip);
                return err(StatusCode::FORBIDDEN, codes::FORBIDDEN, "account disabled");
            }
            if verify_password(&req.password, &password_hash).unwrap_or(false) {
                state.login_limiter.record_success(ip);
                let tokens = match state.jwt.issue(&account.id, &account.username, "client") {
                    Ok(t) => t,
                    Err(e) => {
                        return err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            codes::INTERNAL,
                            e.to_string(),
                        );
                    }
                };
                let _ = state.db.touch_account_seen(&account.id);
                return ok(json!({
                    "access_token": tokens.access_token,
                    "refresh_token": tokens.refresh_token,
                    "tunnel_token": tokens.tunnel_token,
                    "role": "client",
                    "expires_in": tokens.expires_in,
                }))
                .into_response();
            }
            state.login_limiter.record_failure(ip);
            err(
                StatusCode::UNAUTHORIZED,
                codes::INVALID_CREDENTIALS,
                "invalid username or password",
            )
        }
        _ => {
            state.login_limiter.record_failure(ip);
            err(
                StatusCode::UNAUTHORIZED,
                codes::INVALID_CREDENTIALS,
                "invalid username or password",
            )
        }
    }
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh(State(state): State<ApiState>, Json(req): Json<RefreshRequest>) -> Response {
    match state.jwt.refresh(&req.refresh_token) {
        Ok((claims, tokens)) => ok(json!({
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "tunnel_token": tokens.tunnel_token,
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
    if let Some(rt) = &req.refresh_token {
        let _ = state.jwt.revoke(rt);
    }
    let _ = state.db.record_audit_log(
        Some(&claims.sub),
        &claims.username,
        "admin.logout",
        None,
        None,
        None,
    );
    ok(json!(null)).into_response()
}

#[derive(Deserialize)]
pub struct InitRequest {
    pub username: String,
    pub password: String,
}

/// 首次初始化管理员（仅当数据库无任何 admin 时可用）。
pub async fn init(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<InitRequest>,
) -> Response {
    if state.db.has_admin().unwrap_or(true) {
        return err(
            StatusCode::FORBIDDEN,
            codes::FORBIDDEN,
            "admin already initialized",
        );
    }

    if let Err(msg) = validate_admin_credentials(&req.username, &req.password) {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }

    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };

    match state.db.create_admin(&req.username, &password_hash) {
        Ok(admin) => {
            let _ = state.db.record_audit_log(
                Some(&admin.id),
                &admin.username,
                "admin.init",
                None,
                None,
                Some(&ip.to_string()),
            );
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

/// 管理引导票据换取管理会话（控制台通道零开通）。
///
/// 票据来源：管理版接入链接持有者经 console-ticket 端点签发（kind=account），
/// 或中继暴露控制面握手下发（kind=relay，P2）。票据一次性（relay 限期多次）、
/// 短时有效、库中只存哈希；换取即落审计（身份与路径可区分）。
pub async fn admin_bootstrap(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<BootstrapRequest>,
) -> Response {
    if req.ticket.len() > 128 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "invalid ticket",
        );
    }
    let Some(t) = state.db.redeem_admin_ticket(&req.ticket).unwrap_or(None) else {
        return err(
            StatusCode::UNAUTHORIZED,
            codes::INVALID_CREDENTIALS,
            "invalid or expired ticket",
        );
    };

    match t.kind.as_str() {
        "account" => {
            let account = match state.db.get_account(&t.subject) {
                Ok(Some(a)) if a.enabled && a.admin_console => a,
                _ => {
                    return err(StatusCode::FORBIDDEN, codes::FORBIDDEN, "管理权限已被收回");
                }
            };
            let tokens =
                match state
                    .jwt
                    .issue_with_scope(&account.id, &account.username, "admin", &t.scope)
                {
                    Ok(t) => t,
                    Err(e) => {
                        return err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            codes::INTERNAL,
                            e.to_string(),
                        );
                    }
                };
            let _ = state.db.record_audit_log(
                None,
                &format!("link:{}", account.username),
                "admin.console_access",
                Some(
                    &state
                        .db
                        .get_config("node_name")
                        .ok()
                        .flatten()
                        .unwrap_or_default(),
                ),
                Some(&format!("经管理链接换取管理会话（scope={}）", t.scope)),
                Some(&ip.to_string()),
            );
            ok(json!({
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token,
                "role": "admin",
                "scope": t.scope,
                "expires_in": tokens.expires_in,
            }))
            .into_response()
        }
        "relay" => {
            // P2：中继令牌换得管理会话。subject = "psk_前缀@下游节点名"。
            let tokens = match state
                .jwt
                .issue_with_scope(&t.subject, &t.subject, "admin", &t.scope)
            {
                Ok(t) => t,
                Err(e) => {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        codes::INTERNAL,
                        e.to_string(),
                    );
                }
            };
            let _ = state.db.record_audit_log(
                None,
                &format!("relay:{}", t.subject),
                "admin.session_via_relay",
                Some(
                    &state
                        .db
                        .get_config("node_name")
                        .ok()
                        .flatten()
                        .unwrap_or_default(),
                ),
                Some(&format!(
                    "凭中继会话换取管理会话（scope={}，来源=隧道）",
                    t.scope
                )),
                Some(&ip.to_string()),
            );
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

/// 管理员凭据强度校验。
fn validate_admin_credentials(username: &str, password: &str) -> Result<(), String> {
    if username.is_empty() || username.len() > 32 {
        return Err("username must be 1-32 characters".into());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("username may only contain [a-zA-Z0-9_-]".into());
    }
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
