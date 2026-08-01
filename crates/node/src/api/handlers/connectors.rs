//! Connector（扇出）API Handlers（对应 docs/todo/peer-acl.md §4/§7）
//!
//! 扇出 token 为对端签发的连接凭据：加密落库、创建后亦不回显（只允许重置），
//! 审计严禁记录 token 明文/密文。全部变更同步驱动 ConnectorManager 热操作。
//!
//! advertise 入参约定：字符串数组（如 ["10.0.0.0/8", "git.internal"]），
//! 入库序列化为逗号拼接字符串（与 core ConnectorConfig.advertise 对齐）。

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, ok_created};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateConnectorRequest {
    pub name: String,
    pub upstream_addr: String,
    /// 扇出 token（对端签发；加密落库，响应不回显）
    pub token: String,
    #[serde(default)]
    pub sni_hostname: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub ca_cert_path: String,
    #[serde(default)]
    pub pinned_cert_path: String,
    #[serde(default)]
    pub advertise: Vec<String>,
    /// 收敛权限组（缺省/null = 不收敛，放行一切）
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub remark: String,
}

fn validate_connector_input(
    name: &str,
    upstream_addr: &str,
    advertise: &[String],
    remark: &str,
) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("name must be 1-64 characters".into());
    }
    if upstream_addr.is_empty() || upstream_addr.len() > 253 {
        return Err("upstream_addr must be 1-253 characters".into());
    }
    if advertise.len() > 64 || advertise.iter().any(|a| a.len() > 256) {
        return Err("advertise too large (max 64 entries, 256 chars each)".into());
    }
    if remark.len() > 256 {
        return Err("remark too long (max 256)".into());
    }
    Ok(())
}

/// 校验收敛组存在（Some 时）。
fn validate_group(state: &ApiState, group_id: Option<&str>) -> Option<Response> {
    if let Some(gid) = group_id
        && state.db.get_group(gid).unwrap_or(None).is_none()
    {
        return Some(err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            format!("group not found: {gid}"),
        ));
    }
    None
}

/// 视图 JSON：ConnectorView + 实时状态（绝不含 token 明文/密文）。
fn connector_json(state: &ApiState, id: &str) -> Option<serde_json::Value> {
    let v = state
        .db
        .list_connectors()
        .ok()?
        .into_iter()
        .find(|c| c.id == id)?;
    let mut value = serde_json::to_value(&v).ok()?;
    let st = state
        .runtime
        .connector_manager
        .state_of(id)
        .unwrap_or("disconnected");
    value["state"] = json!(st);
    Some(value)
}

pub async fn list_connectors(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    match state.db.list_connectors() {
        Ok(items) => {
            let items: Vec<serde_json::Value> = items
                .into_iter()
                .map(|v| {
                    let st = state
                        .runtime
                        .connector_manager
                        .state_of(&v.id)
                        .unwrap_or("disconnected");
                    let mut value = serde_json::to_value(&v).unwrap_or_else(|_| json!({}));
                    value["state"] = json!(st);
                    value
                })
                .collect();
            ok(json!({ "items": items }))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

pub async fn create_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateConnectorRequest>,
) -> Response {
    let name = req.name.trim();
    if let Err(msg) = validate_connector_input(name, &req.upstream_addr, &req.advertise, &req.remark)
    {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }
    if req.token.is_empty() || req.token.len() > 256 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "token must be 1-256 characters",
        );
    }
    if let Some(resp) = validate_group(&state, req.group_id.as_deref()) {
        return resp;
    }
    // 名称唯一（DB 亦有 UNIQUE 约束，前置校验给出明确 409）
    let name_taken = state
        .db
        .list_connectors()
        .unwrap_or_default()
        .into_iter()
        .any(|c| c.name == name);
    if name_taken {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "connector name already exists",
        );
    }

    let advertise = req.advertise.join(",");
    match state.db.create_connector(
        name,
        &req.upstream_addr,
        &req.token,
        &req.sni_hostname,
        req.insecure,
        &req.ca_cert_path,
        &req.pinned_cert_path,
        &advertise,
        req.group_id.as_deref(),
        &req.remark,
    ) {
        Ok(rec) => {
            // 热装配失败不阻断创建（DB 已落成；状态显示 disconnected，可修正后重试更新）
            if let Err(e) = state.runtime.connector_manager.upsert_from_db(&rec.id).await {
                tracing::error!(connector = %name, error = %e, "connector hot-start failed");
            }
            audit(
                &state,
                &claims,
                &ip,
                "connector.create",
                Some(&rec.id),
                &format!("{name} -> {}", req.upstream_addr),
            );
            match connector_json(&state, &rec.id) {
                Some(v) => ok_created(v),
                None => err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    codes::INTERNAL,
                    "reload failed",
                ),
            }
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct UpdateConnectorRequest {
    pub name: String,
    pub upstream_addr: String,
    /// 留空/null = 保留原 token（token 不回显，只允许重置为新值）
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub sni_hostname: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub ca_cert_path: String,
    #[serde(default)]
    pub pinned_cert_path: String,
    #[serde(default)]
    pub advertise: Vec<String>,
    /// 收敛权限组（PUT 为全量替换语义：缺省/null = 不收敛）
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub remark: String,
}

pub async fn update_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<UpdateConnectorRequest>,
) -> Response {
    if state.db.get_connector(&id).unwrap_or(None).is_none() {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "connector not found",
        );
    }
    let name = req.name.trim();
    if let Err(msg) = validate_connector_input(name, &req.upstream_addr, &req.advertise, &req.remark)
    {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }
    if let Some(t) = &req.token
        && t.len() > 256
    {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "token too long (max 256)",
        );
    }
    if let Some(resp) = validate_group(&state, req.group_id.as_deref()) {
        return resp;
    }
    let name_taken = state
        .db
        .list_connectors()
        .unwrap_or_default()
        .into_iter()
        .any(|c| c.name == name && c.id != id);
    if name_taken {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "connector name already exists",
        );
    }

    // 空串视为未提供（保留原 token）
    let token_reset = req.token.as_deref().filter(|t| !t.is_empty());
    let advertise = req.advertise.join(",");
    if let Err(e) = state.db.update_connector(
        &id,
        name,
        &req.upstream_addr,
        token_reset,
        &req.sni_hostname,
        req.insecure,
        &req.ca_cert_path,
        &req.pinned_cert_path,
        &advertise,
        req.group_id.as_deref(),
        &req.remark,
    ) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    // 重建该条 connector（先断旧再起新）
    if let Err(e) = state.runtime.connector_manager.upsert_from_db(&id).await {
        tracing::error!(connector = %name, error = %e, "connector hot-rebuild failed");
    }
    audit(
        &state,
        &claims,
        &ip,
        "connector.update",
        Some(&id),
        &format!(
            "{name} -> {} (token {})",
            req.upstream_addr,
            if token_reset.is_some() {
                "rotated"
            } else {
                "kept"
            }
        ),
    );
    match connector_json(&state, &id) {
        Some(v) => ok(v),
        None => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "reload failed",
        ),
    }
}

pub async fn delete_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    let Some(rec) = state.db.get_connector(&id).unwrap_or(None) else {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "connector not found",
        );
    };
    match state.db.delete_connector(&id) {
        Ok(_) => {
            state.runtime.connector_manager.remove(&id).await;
            audit(
                &state,
                &claims,
                &ip,
                "connector.delete",
                Some(&id),
                &rec.name,
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

/// 启用/禁用公共实现：启用 = 装配起连，禁用 = 断开移除（DB 记录保留）。
async fn set_enabled(
    state: &ApiState,
    claims: &crate::auth::jwt::Claims,
    ip: &std::net::IpAddr,
    id: &str,
    enabled: bool,
) -> Response {
    let Some(rec) = state.db.get_connector(id).unwrap_or(None) else {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "connector not found",
        );
    };
    if let Err(e) = state.db.set_connector_enabled(id, enabled) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    if enabled {
        if let Err(e) = state.runtime.connector_manager.upsert_from_db(id).await {
            tracing::error!(connector = %rec.name, error = %e, "connector hot-start failed");
        }
    } else {
        state.runtime.connector_manager.remove(id).await;
    }
    audit(
        state,
        claims,
        ip,
        if enabled {
            "connector.enable"
        } else {
            "connector.disable"
        },
        Some(id),
        &rec.name,
    );
    match connector_json(state, id) {
        Some(v) => ok(v),
        None => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "reload failed",
        ),
    }
}

pub async fn enable_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    set_enabled(&state, &claims, &ip, &id, true).await
}

pub async fn disable_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    set_enabled(&state, &claims, &ip, &id, false).await
}
