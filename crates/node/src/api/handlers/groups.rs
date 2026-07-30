//! Groups API Handlers（对应 docs/api/groups.md）

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, ok_created};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "crate::api::default_page")]
    pub page: u32,
    #[serde(default = "crate::api::default_page_size")]
    pub page_size: u32,
    pub q: Option<String>,
}

pub async fn list_groups(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let (page, page_size) = crate::api::normalize_page(q.page, q.page_size);
    match state.db.list_groups(page, page_size, q.q.as_deref()) {
        Ok((items, total)) => ok(json!({
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
        })),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

pub async fn get_group(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Response {
    let group = match state.db.get_group(&id) {
        Ok(Some(g)) => g,
        Ok(None) => return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found"),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    };
    let rules = state.db.rules_of_group(&id).unwrap_or_default();
    let (accounts, _) = state
        .db
        .list_accounts(1, 100, Some(&id), None, None)
        .unwrap_or_default();
    let accounts: Vec<_> = accounts
        .into_iter()
        .map(|a| json!({ "id": a.id, "username": a.username, "enabled": a.enabled }))
        .collect();

    ok(json!({
        "id": group.id,
        "name": group.name,
        "remark": group.remark,
        "rules": rules,
        "accounts": accounts,
        "created_at": group.created_at,
        "updated_at": group.updated_at,
    }))
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
}

fn validate_group_input(name: &str, remark: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("name must be 1-64 characters".into());
    }
    if remark.len() > 256 {
        return Err("remark too long (max 256)".into());
    }
    Ok(())
}

pub async fn create_group(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateGroupRequest>,
) -> Response {
    let name = req.name.trim();
    if let Err(msg) = validate_group_input(name, &req.remark) {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }
    if state.db.get_group_by_name(name).unwrap_or(None).is_some() {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "group name already exists",
        );
    }
    // 校验 rule_ids 存在
    for rid in &req.rule_ids {
        if state.db.get_rule(rid).unwrap_or(None).is_none() {
            return err(
                StatusCode::NOT_FOUND,
                codes::NOT_FOUND,
                format!("rule not found: {rid}"),
            );
        }
    }

    match state.db.create_group(name, &req.remark) {
        Ok(group) => {
            if !req.rule_ids.is_empty() {
                let _ = state.db.set_group_rules(&group.id, &req.rule_ids);
                let _ = state.db.bump_config_version();
            }
            audit(&state, &claims, &ip, "group.create", Some(&group.id), name);
            match state.db.get_group(&group.id) {
                Ok(Some(g)) => ok_created(g),
                _ => ok_created(group),
            }
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub remark: Option<String>,
}

pub async fn update_group(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<UpdateGroupRequest>,
) -> Response {
    if state.db.get_group(&id).unwrap_or(None).is_none() {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    }
    if let Some(name) = &req.name {
        let name = name.trim();
        if let Err(msg) = validate_group_input(name, "") {
            return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
        }
        if let Ok(Some(existing)) = state.db.get_group_by_name(name)
            && existing.id != id
        {
            return err(
                StatusCode::CONFLICT,
                codes::DUPLICATE,
                "group name already exists",
            );
        }
    }
    if let Err(e) = state
        .db
        .update_group(&id, req.name.as_deref(), req.remark.as_deref())
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string());
    }
    audit(&state, &claims, &ip, "group.update", Some(&id), "");
    match state.db.get_group(&id) {
        Ok(Some(g)) => ok(g),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, "reload failed"),
    }
}

#[derive(Deserialize)]
pub struct SetGroupRulesRequest {
    #[serde(default)]
    pub rule_ids: Vec<String>,
}

/// 全量设置权限组关联的规则。
pub async fn set_group_rules(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<SetGroupRulesRequest>,
) -> Response {
    if state.db.get_group(&id).unwrap_or(None).is_none() {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    }
    if req.rule_ids.len() > 500 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "too many rule_ids",
        );
    }
    for rid in &req.rule_ids {
        if state.db.get_rule(rid).unwrap_or(None).is_none() {
            return err(
                StatusCode::NOT_FOUND,
                codes::NOT_FOUND,
                format!("rule not found: {rid}"),
            );
        }
    }
    if let Err(e) = state.db.set_group_rules(&id, &req.rule_ids) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string());
    }
    let _ = state.db.bump_config_version();
    audit(
        &state,
        &claims,
        &ip,
        "group.update_rules",
        Some(&id),
        &format!("rule_count={}", req.rule_ids.len()),
    );
    ok(json!({ "rule_count": req.rule_ids.len() }))
}

#[derive(Deserialize)]
pub struct ForceQuery {
    #[serde(default)]
    pub force: bool,
}

pub async fn delete_group(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Query(q): Query<ForceQuery>,
) -> Response {
    if state.db.get_group(&id).unwrap_or(None).is_none() {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    }
    let account_count = state.db.count_accounts_in_group(&id).unwrap_or(0);
    if account_count > 0 && !q.force {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            format!("group has {account_count} accounts, reassign or delete them first"),
        );
    }
    match state.db.delete_group(&id, q.force) {
        Ok(_) => {
            let _ = state.db.bump_config_version();
            audit(
                &state,
                &claims,
                &ip,
                "group.delete",
                Some(&id),
                &format!("force={} account_count={}", q.force, account_count),
            );
            ok(json!(null))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}
