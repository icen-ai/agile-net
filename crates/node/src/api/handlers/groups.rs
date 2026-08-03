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
    match state
        .db_call(move |db| db.list_groups(page, page_size, q.q.as_deref()))
        .await
    {
        Ok((items, total)) => ok(json!({
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
        })),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

pub async fn get_group(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Response {
    // 组 + 名下规则 + 名下账号合并为一次阻塞任务
    let gid = id.clone();
    let result = state
        .db_call(move |db| {
            let Some(group) = db.get_group(&gid)? else {
                return Ok(None);
            };
            let rules = db.rules_of_group(&gid).unwrap_or_default();
            let (accounts, _) = db
                .list_accounts(1, 100, Some(&gid), None, None)
                .unwrap_or_default();
            Ok(Some((group, rules, accounts)))
        })
        .await;
    let (group, rules, accounts) = match result {
        Ok(Some(v)) => v,
        Ok(None) => return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found"),
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };
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

/// 组详情：名下挂载的三类身份清单（账号 + 扇入令牌 + 扇出对端，各含 id 与名称字段）。
pub async fn get_group_detail(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Response {
    // 组存在性 + 三类身份清单合并为一次阻塞任务
    let gid = id.clone();
    let result = state
        .db_call(move |db| {
            if db.get_group(&gid).unwrap_or(None).is_none() {
                return Ok(None);
            }
            let (accounts, _) = db
                .list_accounts(1, 1000, Some(&gid), None, None)
                .unwrap_or_default();
            let relay_tokens = db.list_relay_tokens().unwrap_or_default();
            let connectors = db.list_connectors().unwrap_or_default();
            Ok(Some((accounts, relay_tokens, connectors)))
        })
        .await;
    let Some((accounts, relay_tokens, connectors)) = (match result {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    }) else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    };
    let accounts: Vec<_> = accounts
        .into_iter()
        .map(|a| json!({ "id": a.id, "username": a.username, "enabled": a.enabled }))
        .collect();
    let relay_tokens: Vec<_> = relay_tokens
        .into_iter()
        .filter(|t| t.group_id.as_deref() == Some(id.as_str()))
        .map(|t| json!({ "id": t.id, "token_prefix": t.token_prefix, "remark": t.remark }))
        .collect();
    let connectors: Vec<_> = connectors
        .into_iter()
        .filter(|c| c.group_id.as_deref() == Some(id.as_str()))
        .map(|c| json!({ "id": c.id, "name": c.name, "upstream_addr": c.upstream_addr, "enabled": c.enabled }))
        .collect();

    ok(json!({
        "accounts": accounts,
        "relay_tokens": relay_tokens,
        "connectors": connectors,
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
    let name_owned = name.to_string();
    let exists = state
        .db_call(move |db| db.get_group_by_name(&name_owned))
        .await
        .unwrap_or(None)
        .is_some();
    if exists {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "group name already exists",
        );
    }
    // 校验 rule_ids 存在（整批一次阻塞任务，返回首个缺失项）
    let rule_ids = req.rule_ids.clone();
    let missing = state
        .db_call(move |db| {
            for rid in &rule_ids {
                if db.get_rule(rid).unwrap_or(None).is_none() {
                    return Ok(Some(rid.clone()));
                }
            }
            Ok(None)
        })
        .await
        .unwrap_or(None);
    if let Some(rid) = missing {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            format!("rule not found: {rid}"),
        );
    }

    let (name_owned, remark) = (name.to_string(), req.remark.clone());
    match state
        .db_call(move |db| db.create_group(&name_owned, &remark))
        .await
    {
        Ok(group) => {
            if !req.rule_ids.is_empty() {
                let (gid, rule_ids) = (group.id.clone(), req.rule_ids.clone());
                let _ = state
                    .db_call(move |db| {
                        let _ = db.set_group_rules(&gid, &rule_ids);
                        db.bump_config_version()
                    })
                    .await;
            }
            audit(&state, &claims, &ip, "group.create", Some(&group.id), name).await;
            let gid = group.id.clone();
            match state.db_call(move |db| db.get_group(&gid)).await {
                Ok(Some(g)) => ok_created(g),
                _ => ok_created(group),
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
    let gid = id.clone();
    let exists = state
        .db_call(move |db| db.get_group(&gid))
        .await
        .unwrap_or(None)
        .is_some();
    if !exists {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    }
    if let Some(name) = &req.name {
        let name = name.trim();
        if let Err(msg) = validate_group_input(name, "") {
            return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
        }
        let (name_owned, gid) = (name.to_string(), id.clone());
        let conflict = state
            .db_call(move |db| {
                Ok(match db.get_group_by_name(&name_owned)? {
                    Some(existing) => existing.id != gid,
                    None => false,
                })
            })
            .await
            .unwrap_or(false);
        if conflict {
            return err(
                StatusCode::CONFLICT,
                codes::DUPLICATE,
                "group name already exists",
            );
        }
    }
    let (gid, name, remark) = (id.clone(), req.name.clone(), req.remark.clone());
    if let Err(e) = state
        .db_call(move |db| db.update_group(&gid, name.as_deref(), remark.as_deref()))
        .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    audit(&state, &claims, &ip, "group.update", Some(&id), "").await;
    match state.db_call(move |db| db.get_group(&id)).await {
        Ok(Some(g)) => ok(g),
        _ => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "reload failed",
        ),
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
    let gid = id.clone();
    let exists = state
        .db_call(move |db| db.get_group(&gid))
        .await
        .unwrap_or(None)
        .is_some();
    if !exists {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    }
    if req.rule_ids.len() > 500 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "too many rule_ids",
        );
    }
    // 校验 + 全量设置 + 版本递增合并为一次阻塞任务
    let (gid, rule_ids) = (id.clone(), req.rule_ids.clone());
    let result = state
        .db_call(move |db| {
            for rid in &rule_ids {
                if db.get_rule(rid).unwrap_or(None).is_none() {
                    return Ok(Some(rid.clone()));
                }
            }
            db.set_group_rules(&gid, &rule_ids)?;
            let _ = db.bump_config_version();
            Ok(None)
        })
        .await;
    let missing = match result {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };
    if let Some(rid) = missing {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            format!("rule not found: {rid}"),
        );
    }
    audit(
        &state,
        &claims,
        &ip,
        "group.update_rules",
        Some(&id),
        &format!("rule_count={}", req.rule_ids.len()),
    )
    .await;
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
    let gid = id.clone();
    let exists = state
        .db_call(move |db| db.get_group(&gid))
        .await
        .unwrap_or(None)
        .is_some();
    if !exists {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "group not found");
    }
    let gid = id.clone();
    let account_count = state
        .db_call(move |db| db.count_accounts_in_group(&gid))
        .await
        .unwrap_or(0);
    if account_count > 0 && !q.force {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            format!("group has {account_count} accounts, reassign or delete them first"),
        );
    }
    let force = q.force;
    let aid = id.clone();
    match state
        .db_call(move |db| {
            db.delete_group(&id, force)?;
            db.bump_config_version()
        })
        .await
    {
        Ok(_) => {
            audit(
                &state,
                &claims,
                &ip,
                "group.delete",
                Some(&aid),
                &format!("force={} account_count={}", q.force, account_count),
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
