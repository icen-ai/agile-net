//! Auth API Handlers（对应 docs/api/auth.md）
//!
//! 阻塞调用约定：argon2id 校验/哈希（0.5-2s CPU）、JWT 签发轮换（内部含 DB 写）
//! 与全部 DB 访问一律经 `offload` / `ApiState::db_call` 卸载到阻塞线程池，
//! 不得在 async handler 里直接同步执行。

use crate::api::extractors::{AnyAuth, ClientIp};
use crate::api::{ApiState, LoginBlockReason, codes, err, ok, offload};
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
    let username = req.username.clone();
    let admin = state
        .db_call(move |db| db.get_admin_by_username(&username))
        .await;
    if let Ok(Some(admin)) = admin {
        // argon2id 校验为 CPU 密集操作，卸载到阻塞线程池
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

    // 2. 尝试 client 账号登录
    let username = req.username.clone();
    match state
        .db_call(move |db| db.get_account_by_username(&username))
        .await
    {
        Ok(Some((account, password_hash))) => {
            if !account.enabled {
                state.login_limiter.record_failure(ip);
                return err(StatusCode::FORBIDDEN, codes::FORBIDDEN, "account disabled");
            }
            let password = req.password.clone();
            let verified = offload(move || verify_password(&password, &password_hash))
                .await
                .unwrap_or(false);
            if verified {
                state.login_limiter.record_success(ip);
                let jwt = state.jwt.clone();
                let (sub, uname) = (account.id.clone(), account.username.clone());
                let tokens = match offload(move || jwt.issue(&sub, &uname, "client")).await {
                    Ok(t) => t,
                    Err(e) => {
                        return err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            codes::INTERNAL,
                            e.to_string(),
                        );
                    }
                };
                let aid = account.id.clone();
                let _ = state
                    .db_call(move |db| db.touch_account_seen(&aid))
                    .await;
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

pub async fn refresh(
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RefreshRequest>,
) -> Response {
    // refresh 每次执行 DB 写入轮换（吊销+签发+tunnel_token 轮换），必须限速
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
    if let Some(rt) = req.refresh_token {
        let jwt = state.jwt.clone();
        let _ = offload(move || jwt.revoke(&rt)).await;
    }
    let (sub, uname) = (claims.sub.clone(), claims.username.clone());
    let _ = state
        .db_call(move |db| db.record_audit_log(Some(&sub), &uname, "admin.logout", None, None, None))
        .await;
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

    // argon2id 哈希为 CPU 密集操作，卸载到阻塞线程池
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
    // 票据兑换限流（与 refresh 同档；防暴力枚举票据）
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
        "account" => {
            let subject = t.subject.clone();
            let account = match state.db_call(move |db| db.get_account(&subject)).await {
                Ok(Some(a)) if a.enabled && a.admin_console => a,
                _ => {
                    return err(StatusCode::FORBIDDEN, codes::FORBIDDEN, "管理权限已被收回");
                }
            };
            let jwt = state.jwt.clone();
            let (sub, uname, scope) = (
                account.id.clone(),
                account.username.clone(),
                t.scope.clone(),
            );
            let tokens =
                match offload(move || jwt.issue_with_scope(&sub, &uname, "admin", &scope)).await {
                    Ok(t) => t,
                    Err(e) => {
                        return err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            codes::INTERNAL,
                            e.to_string(),
                        );
                    }
                };
            // 审计：节点名读取与落库合并为一次阻塞任务
            let (uname, scope, ip_s) = (account.username.clone(), t.scope.clone(), ip.to_string());
            let _ = state
                .db_call(move |db| {
                    let node_name = db.get_config("node_name").ok().flatten().unwrap_or_default();
                    db.record_audit_log(
                        None,
                        &format!("link:{uname}"),
                        "admin.console_access",
                        Some(&node_name),
                        Some(&format!("经管理链接换取管理会话（scope={scope}）")),
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
        "relay" => {
            // P2：中继令牌换得管理会话。subject = "psk_前缀@下游节点名"。
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
                    let node_name = db.get_config("node_name").ok().flatten().unwrap_or_default();
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

/// 管理员凭据强度校验（用户名规则 + 密码强度）。
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

/// 管理面密码强度策略（≥10 位且含大小写字母与数字）。
/// pub 导出供桌面端 Web 远程面密码设置复用（agile_net_node::api::handlers::auth 路径）。
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
