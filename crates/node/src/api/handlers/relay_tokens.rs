//! Relay Token API Handlers（对应 docs/api/node.md 的 relay-tokens 部分）
//!
//! Token 由服务端生成（`psk_` + 48 位），数据库只存 SHA-256 哈希与前缀，
//! 全文仅创建时返回一次。

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, ok_created};
use crate::db::{generate_relay_token, sha256_hex};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(default)]
    pub remark: String,
    /// 允许该下游中继管理本节点（默认关）
    #[serde(default)]
    pub expose_control: bool,
    /// 管理授权档位：ro / rules / full
    #[serde(default = "default_scope")]
    pub control_scope: String,
    /// 收敛权限组（缺省/null = 不收敛，放行一切）
    #[serde(default)]
    pub group_id: Option<String>,
}

fn default_scope() -> String {
    "full".into()
}

fn valid_scope(scope: &str) -> bool {
    matches!(scope, "ro" | "rules" | "full")
}

pub async fn create_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateTokenRequest>,
) -> Response {
    if req.remark.len() > 256 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "remark too long (max 256)",
        );
    }
    if !valid_scope(&req.control_scope) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "control_scope must be one of ro/rules/full",
        );
    }
    if let Some(gid) = &req.group_id
        && state.db.get_group(gid).unwrap_or(None).is_none()
    {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            format!("group not found: {gid}"),
        );
    }

    let token = generate_relay_token();
    let token_hash = sha256_hex(token.as_bytes());
    let prefix = format!("{}****", &token[..8]);

    match state.db.create_relay_token_with_group(
        &token_hash,
        &prefix,
        &req.remark,
        req.expose_control,
        &req.control_scope,
        req.group_id.as_deref(),
    ) {
        Ok(record) => {
            audit(
                &state,
                &claims,
                &ip,
                "relay_token.create",
                Some(&record.id),
                &req.remark,
            );
            if req.expose_control {
                audit(
                    &state,
                    &claims,
                    &ip,
                    "relay_token.expose_control",
                    Some(&record.id),
                    &format!("on (scope={})", req.control_scope),
                );
            }
            if let Some(gid) = &req.group_id {
                audit(
                    &state,
                    &claims,
                    &ip,
                    "relay_token.set_group",
                    Some(&record.id),
                    &format!("group_id={gid}"),
                );
            }
            ok_created(json!({
                "id": record.id,
                "token": token,
                "token_prefix": prefix,
                "remark": record.remark,
                "expose_control": record.expose_control,
                "control_scope": record.control_scope,
                "group_id": record.group_id,
                "created_at": record.created_at,
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
pub struct UpdateTokenRequest {
    pub expose_control: bool,
    #[serde(default = "default_scope")]
    pub control_scope: String,
    /// 收敛组变更三态：缺省 = 不变，null = 不收敛，字符串 = 挂到该组。
    /// （serde 对 Option 的显式 null 也归为 None，须 deserialize_some 区分缺省与置空）
    #[serde(default, deserialize_with = "deserialize_some")]
    pub group_id: Option<serde_json::Value>,
}

/// 字段出现即包 Some（含显式 null），缺省才走 default None。
fn deserialize_some<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(de).map(Some)
}

/// 暴露控制面开关变更（默认关；变更即审计 relay_token.expose_control）。
pub async fn update_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<UpdateTokenRequest>,
) -> Response {
    if !valid_scope(&req.control_scope) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "control_scope must be one of ro/rules/full",
        );
    }
    let Some(existing) = state
        .db
        .list_relay_tokens()
        .ok()
        .and_then(|items| items.into_iter().find(|t| t.id == id))
    else {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "relay token not found",
        );
    };
    // 收敛组入参解析：null = 不收敛，字符串 = 挂到该组（其余类型 400）
    let new_group: Option<Option<String>> = match &req.group_id {
        None => None,
        Some(serde_json::Value::Null) => Some(None),
        Some(serde_json::Value::String(s)) => Some(Some(s.clone())),
        Some(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "group_id must be string or null",
            );
        }
    };
    if let Some(Some(gid)) = &new_group
        && state.db.get_group(gid).unwrap_or(None).is_none()
    {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            format!("group not found: {gid}"),
        );
    }
    if let Err(e) = state
        .db
        .update_relay_token_control(&id, req.expose_control, &req.control_scope)
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    if existing.expose_control != req.expose_control || existing.control_scope != req.control_scope
    {
        audit(
            &state,
            &claims,
            &ip,
            "relay_token.expose_control",
            Some(&id),
            &format!(
                "{} (scope={})",
                if req.expose_control { "on" } else { "off" },
                req.control_scope
            ),
        );
    }

    // 收敛组变更：写库后按哈希踢会话，在线对端重连即按新组收敛（即时生效）
    let mut group_id_resp = existing.group_id.clone();
    if let Some(new_group) = new_group
        && new_group != existing.group_id
    {
        if let Err(e) = state.db.set_relay_token_group(&id, new_group.as_deref()) {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
        if let (Some(listener), Ok(Some(hash))) = (
            &state.runtime.listener,
            state.db.get_relay_token_hash(&id),
        ) && let Some(node_id) = listener.disconnect_by_token_hash(&hash)
        {
            tracing::info!(node = %node_id, "relay token group changed, peer kicked");
        }
        audit(
            &state,
            &claims,
            &ip,
            "relay_token.set_group",
            Some(&id),
            &match &new_group {
                Some(gid) => format!("group_id={gid}"),
                None => "group cleared (unrestricted)".to_string(),
            },
        );
        group_id_resp = new_group;
    }

    ok(json!({
        "id": id,
        "expose_control": req.expose_control,
        "control_scope": req.control_scope,
        "group_id": group_id_resp,
    }))
}

pub async fn list_tokens(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    match state.db.list_relay_tokens() {
        Ok(items) => ok(json!({ "items": items })),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

pub async fn delete_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    // 先取哈希（删除联动：使用该 token 的在线下游节点立即被踢）
    let token_hash = state.db.get_relay_token_hash(&id).unwrap_or(None);
    match state.db.delete_relay_token(&id) {
        Ok(_) => {
            if let (Some(listener), Some(hash)) = (&state.runtime.listener, token_hash)
                && let Some(node_id) = listener.disconnect_by_token_hash(&hash)
            {
                tracing::info!(node = %node_id, "relay token revoked, peer kicked");
            }
            audit(&state, &claims, &ip, "relay_token.delete", Some(&id), "");
            ok(json!(null))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}
