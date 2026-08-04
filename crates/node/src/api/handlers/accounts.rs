//! Accounts API handlers (see docs/api/accounts.md)
//!
//! Design: passwords are server-generated (`sk-` + 48 mixed chars, ~286 bits entropy),
//! returned only once at create/reset; the QR code content is the connect_url.

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, ok_created, offload};
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
    let result = state
        .db_call(move |db| {
            db.list_accounts(
                page,
                page_size,
                q.group_id.as_deref(),
                q.enabled,
                q.q.as_deref(),
            )
        })
        .await;
    match result {
        Ok((mut items, total)) => {
            // Online check: a data-plane tunnel session exists, or a heartbeat seen within 3 minutes
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
    /// Also grant the "manage this node" permission (admin link; strong warning on the create page + issuance audit)
    #[serde(default)]
    pub admin_console: bool,
}

/// Username validation: 3-32 chars [a-zA-Z0-9_-]
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
    let uname = username.to_string();
    let exists = state
        .db_call(move |db| db.get_account_by_username(&uname))
        .await
        .unwrap_or(None)
        .is_some();
    if exists {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "username already exists",
        );
    }
    let gid = req.group_id.clone();
    let group_exists = state
        .db_call(move |db| db.get_group(&gid))
        .await
        .unwrap_or(None)
        .is_some();
    if !group_exists {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    }

    // Server-side strong password (sk style); argon2id hash offloaded to the blocking pool
    let password = generate_password();
    let password_plain = password.clone();
    let password_hash = match offload(move || hash_password(&password_plain)).await {
        Ok(h) => h,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };

    let (uname, group_id, remark) = (
        username.to_string(),
        req.group_id.clone(),
        req.remark.clone(),
    );
    let admin_console = req.admin_console;
    let created = state
        .db_call(move |db| {
            db.create_account_with_admin(&uname, &password_hash, &group_id, &remark, admin_console)
        })
        .await;
    match created {
        Ok(account) => {
            let mut connect_url = build_connect_url(&state, username, &password).await;
            if req.admin_console {
                // Admin-link variant: the link holder can manage this node (strong warning + issuance audit)
                connect_url.push_str("&admin=1");
                audit(
                    &state,
                    &claims,
                    &ip,
                    "account.issue_admin_link",
                    Some(&account.id),
                    username,
                )
                .await;
            }
            state.remember_connect_url(&account.id, &connect_url);
            audit(
                &state,
                &claims,
                &ip,
                "account.create",
                Some(&account.id),
                username,
            )
            .await;
            let gid = req.group_id.clone();
            let group = state
                .db_call(move |db| db.get_group(&gid))
                .await
                .ok()
                .flatten();
            let endpoints = connect_endpoints(&state).await;
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
                "endpoints": endpoints,
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
    let aid = id.clone();
    let existing = match state.db_call(move |db| db.get_account(&aid)).await {
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

    if let Some(gid) = &req.group_id {
        let gid = gid.clone();
        let group_exists = state
            .db_call(move |db| db.get_group(&gid))
            .await
            .unwrap_or(None)
            .is_some();
        if !group_exists {
            return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
        }
    }

    let (aid, group_id, remark) = (id.clone(), req.group_id.clone(), req.remark.clone());
    let (enabled, admin_console) = (req.enabled, req.admin_console);
    if let Err(e) = state
        .db_call(move |db| {
            db.update_account_full(
                &aid,
                group_id.as_deref(),
                enabled,
                remark.as_deref(),
                admin_console,
            )
        })
        .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }

    // Admin permission change: granting records an issuance audit; revoking disconnects tunnel sessions (admin path disabled at once)
    if req.admin_console == Some(true) && !existing.admin_console {
        audit(
            &state,
            &claims,
            &ip,
            "account.issue_admin_link",
            Some(&id),
            &existing.username,
        )
        .await;
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
        )
        .await;
    }

    // Disable: revoke all tokens, clear tunnel_token, and disconnect active tunnel sessions at once
    if req.enabled == Some(false) && existing.enabled {
        let jwt = state.jwt.clone();
        let aid = id.clone();
        let _ = offload(move || jwt.revoke_all(&aid)).await;
        let aid = id.clone();
        let _ = state
            .db_call(move |db| db.set_account_tunnel_token(&aid, None))
            .await;
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
        )
        .await;
    } else if req.enabled == Some(true) && !existing.enabled {
        audit(
            &state,
            &claims,
            &ip,
            "account.enable",
            Some(&id),
            &existing.username,
        )
        .await;
    }
    if req.group_id.is_some() {
        let _ = state.db_call(|db| db.bump_config_version()).await;
    }
    if req.group_id.is_some() || req.remark.is_some() {
        audit(
            &state,
            &claims,
            &ip,
            "account.update",
            Some(&id),
            &existing.username,
        )
        .await;
    }

    match state.db_call(move |db| db.get_account(&id)).await {
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
    let aid = id.clone();
    let account = match state.db_call(move |db| db.get_account(&aid)).await {
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

    // argon2id hash offloaded to the blocking pool
    let password = generate_password();
    let password_plain = password.clone();
    let password_hash = match offload(move || hash_password(&password_plain)).await {
        Ok(h) => h,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };
    let aid = id.clone();
    if let Err(e) = state
        .db_call(move |db| db.set_account_password(&aid, &password_hash))
        .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    // Old credentials invalidated at once + active tunnel sessions disconnected
    let jwt = state.jwt.clone();
    let aid = id.clone();
    let _ = offload(move || jwt.revoke_all(&aid)).await;
    let aid = id.clone();
    let _ = state
        .db_call(move |db| db.set_account_tunnel_token(&aid, None))
        .await;
    if let Some(listener) = &state.runtime.listener {
        listener.disconnect_client(&id);
    }

    let connect_url = build_connect_url(&state, &account.username, &password).await;
    state.remember_connect_url(&id, &connect_url);
    audit(
        &state,
        &claims,
        &ip,
        "account.reset_password",
        Some(&id),
        &account.username,
    )
    .await;

    let endpoints = connect_endpoints(&state).await;
    ok(json!({
        "password": password,
        "connect_url": connect_url,
        "endpoints": endpoints,
    }))
}

/// QR code (SVG): content is the connect_url, available only within 10 minutes after create/reset.
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
    let aid = id.clone();
    let account = match state.db_call(move |db| db.get_account(&aid)).await {
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
    match state.db_call(move |db| db.delete_account(&id)).await {
        Ok(_) => {
            let jwt = state.jwt.clone();
            let aid = account.id.clone();
            let _ = offload(move || jwt.revoke_all(&aid)).await;
            if let Some(listener) = &state.runtime.listener {
                listener.disconnect_client(&account.id);
            }
            audit(
                &state,
                &claims,
                &ip,
                "account.delete",
                Some(&account.id),
                &account.username,
            )
            .await;
            ok(json!(null))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

/// Build the client connect URL (points at the admin API endpoint; the data-plane endpoint comes from config).
/// Carries the cert fingerprint (static cert mode) so the client can pin the cert in one click, no insecure needed.
/// Endpoint resolution: public_api_url (reverse-proxy scheme+port override) > public_host:api_port (federation P1).
async fn build_connect_url(state: &ApiState, username: &str, password: &str) -> String {
    let addr = state.public_api_addr().await;
    agile_net_core::link::build_connect_url(
        &addr,
        username,
        password,
        state.runtime.cert_fingerprint.as_deref(),
    )
}

/// Endpoint candidates for the share dialog (public declared identity > LAN direct > loopback).
async fn connect_endpoints(state: &ApiState) -> Vec<crate::api::ShareEndpoint> {
    let public = state.declared_api_addr().await;
    state.share_endpoints(state.api_port(), public).await
}
