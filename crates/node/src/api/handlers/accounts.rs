//! Accounts API Handlers（对应 docs/api/accounts.md）
//!
//! 企业级设计：密码由服务端生成（`sk-` + 48 位混合字符，~286 bits 熵），
//! 仅在创建/重置时返回一次；二维码内容即 connect_url。

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, ok_created};
use crate::db::{generate_password, hash_password};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "crate::api::default_page")]
    pub page: u32,
    #[serde(default = "crate::api::default_page_size")]
    pub page_size: u32,
    pub group_id: Option<String>,
    pub enabled: Option<bool>,
    pub q: Option<String>,
}

pub async fn list_accounts(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let (page, page_size) = crate::api::normalize_page(q.page, q.page_size);
    match state.db.list_accounts(
        page,
        page_size,
        q.group_id.as_deref(),
        q.enabled,
        q.q.as_deref(),
    ) {
        Ok((mut items, total)) => {
            // 在线判定：数据面隧道会话存在，或最近 3 分钟有心跳
            let now = chrono::Utc::now();
            for a in &mut items {
                let tunnel_online = state
                    .runtime
                    .listener
                    .as_ref()
                    .map(|l| l.is_client_online(&a.id))
                    .unwrap_or(false);
                let heartbeat_online = a
                    .last_seen_at
                    .as_ref()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|t| (now - t.with_timezone(&chrono::Utc)) < chrono::Duration::minutes(3))
                    .unwrap_or(false);
                a.online = tunnel_online || heartbeat_online;
            }
            ok(json!({
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
            }))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    pub username: String,
    pub group_id: String,
    #[serde(default)]
    pub remark: String,
    /// 同时授予「管理此节点」权限（管理版接入链接，生成页强警示 + 签发审计）
    #[serde(default)]
    pub admin_console: bool,
}

/// 账号名校验：3-32 字符 [a-zA-Z0-9_-]
fn validate_username(username: &str) -> Result<(), String> {
    if username.len() < 3 || username.len() > 32 {
        return Err("username must be 3-32 characters".into());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("username may only contain [a-zA-Z0-9_-]".into());
    }
    Ok(())
}

pub async fn create_account(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateAccountRequest>,
) -> Response {
    let username = req.username.trim();
    if let Err(msg) = validate_username(username) {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }
    if req.remark.len() > 256 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "remark too long (max 256)",
        );
    }
    if state
        .db
        .get_account_by_username(username)
        .unwrap_or(None)
        .is_some()
    {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "username already exists",
        );
    }
    if state.db.get_group(&req.group_id).unwrap_or(None).is_none() {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    }

    // 服务端生成强密码（sk 风格）
    let password = generate_password();
    let password_hash = match hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };

    match state.db.create_account_with_admin(
        username,
        &password_hash,
        &req.group_id,
        &req.remark,
        req.admin_console,
    ) {
        Ok(account) => {
            let mut connect_url = build_connect_url(&state, username, &password);
            if req.admin_console {
                // 管理版接入链接变体：持链接者可管理本节点（强警示 + 签发审计）
                connect_url.push_str("&admin=1");
                audit(
                    &state,
                    &claims,
                    &ip,
                    "account.issue_admin_link",
                    Some(&account.id),
                    username,
                );
            }
            state.remember_connect_url(&account.id, &connect_url);
            audit(
                &state,
                &claims,
                &ip,
                "account.create",
                Some(&account.id),
                username,
            );
            let group = state.db.get_group(&req.group_id).ok().flatten();
            ok_created(json!({
                "id": account.id,
                "username": account.username,
                "password": password,
                "group": group.map(|g| json!({ "id": g.id, "name": g.name })),
                "enabled": true,
                "remark": account.remark,
                "admin_console": account.admin_console,
                "created_at": account.created_at,
                "connect_url": connect_url,
            }))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct UpdateAccountRequest {
    pub group_id: Option<String>,
    pub enabled: Option<bool>,
    pub remark: Option<String>,
    pub admin_console: Option<bool>,
}

pub async fn update_account(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<UpdateAccountRequest>,
) -> Response {
    let existing = match state.db.get_account(&id) {
        Ok(Some(a)) => a,
        Ok(None) => return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "account not found"),
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };

    if let Some(gid) = &req.group_id
        && state.db.get_group(gid).unwrap_or(None).is_none()
    {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    }

    if let Err(e) = state.db.update_account_full(
        &id,
        req.group_id.as_deref(),
        req.enabled,
        req.remark.as_deref(),
        req.admin_console,
    ) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }

    // 管理权限变更：授予记签发审计；收回即断开隧道会话（管理通路立即失效）
    if req.admin_console == Some(true) && !existing.admin_console {
        audit(
            &state,
            &claims,
            &ip,
            "account.issue_admin_link",
            Some(&id),
            &existing.username,
        );
    } else if req.admin_console == Some(false) && existing.admin_console {
        if let Some(listener) = &state.runtime.listener {
            listener.disconnect_client(&id);
        }
        audit(
            &state,
            &claims,
            &ip,
            "account.update",
            Some(&id),
            &existing.username,
        );
    }

    // 禁用：吊销全部 token、清除 tunnel_token，并立即断开活跃隧道会话
    if req.enabled == Some(false) && existing.enabled {
        let _ = state.jwt.revoke_all(&id);
        let _ = state.db.set_account_tunnel_token(&id, None);
        if let Some(listener) = &state.runtime.listener {
            let kicked = listener.disconnect_client(&id);
            if kicked > 0 {
                tracing::info!(account = %id, sessions = kicked, "disabled account sessions kicked");
            }
        }
        audit(
            &state,
            &claims,
            &ip,
            "account.disable",
            Some(&id),
            &existing.username,
        );
    } else if req.enabled == Some(true) && !existing.enabled {
        audit(
            &state,
            &claims,
            &ip,
            "account.enable",
            Some(&id),
            &existing.username,
        );
    }
    if req.group_id.is_some() {
        let _ = state.db.bump_config_version();
    }
    if req.group_id.is_some() || req.remark.is_some() {
        audit(
            &state,
            &claims,
            &ip,
            "account.update",
            Some(&id),
            &existing.username,
        );
    }

    match state.db.get_account(&id) {
        Ok(Some(a)) => ok(a),
        _ => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "reload failed",
        ),
    }
}

pub async fn reset_password(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    let account = match state.db.get_account(&id) {
        Ok(Some(a)) => a,
        Ok(None) => return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "account not found"),
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };

    let password = generate_password();
    let password_hash = match hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };
    if let Err(e) = state.db.set_account_password(&id, &password_hash) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    // 旧凭据立即失效 + 断开活跃隧道会话
    let _ = state.jwt.revoke_all(&id);
    let _ = state.db.set_account_tunnel_token(&id, None);
    if let Some(listener) = &state.runtime.listener {
        listener.disconnect_client(&id);
    }

    let connect_url = build_connect_url(&state, &account.username, &password);
    state.remember_connect_url(&id, &connect_url);
    audit(
        &state,
        &claims,
        &ip,
        "account.reset_password",
        Some(&id),
        &account.username,
    );

    ok(json!({
        "password": password,
        "connect_url": connect_url,
    }))
}

/// 二维码（SVG）：内容为 connect_url，仅在创建/重置后 10 分钟内可取。
pub async fn qrcode(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Response {
    match state.take_connect_url(&id) {
        Some(url) => match qrcode::QrCode::new(url.as_bytes()) {
            Ok(code) => {
                let svg = code
                    .render::<qrcode::render::svg::Color>()
                    .min_dimensions(240, 240)
                    .build();
                (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "image/svg+xml")],
                    svg,
                )
                    .into_response()
            }
            Err(e) => err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            ),
        },
        None => err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "connect_url unavailable (only cached 10 minutes after create/reset)",
        ),
    }
}

pub async fn delete_account(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    let account = match state.db.get_account(&id) {
        Ok(Some(a)) => a,
        Ok(None) => return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "account not found"),
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };
    match state.db.delete_account(&id) {
        Ok(_) => {
            let _ = state.jwt.revoke_all(&id);
            if let Some(listener) = &state.runtime.listener {
                listener.disconnect_client(&id);
            }
            audit(
                &state,
                &claims,
                &ip,
                "account.delete",
                Some(&id),
                &account.username,
            );
            ok(json!(null))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

/// 生成客户端接入 URL（指向管理 API 端点，数据面端点由 config 下发）。
/// 携带证书指纹（若静态证书模式），客户端据此一键做证书固定，无需 insecure。
fn build_connect_url(state: &ApiState, username: &str, password: &str) -> String {
    let (server, port) = state.public_api_endpoint();
    let mut url = format!(
        "agilenet://connect?server={server}&port={port}&account={username}&password={password}&tls=1"
    );
    if let Some(fp) = &state.runtime.cert_fingerprint {
        url.push_str(&format!("&fp={fp}"));
    }
    url
}
