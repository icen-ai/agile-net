//! Rules API Handlers（对应 docs/api/rules.md）

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
    #[serde(rename = "type")]
    pub rule_type: Option<String>,
    pub q: Option<String>,
}

pub async fn list_rules(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let (page, page_size) = crate::api::normalize_page(q.page, q.page_size);
    match state
        .db
        .list_rules(page, page_size, q.rule_type.as_deref(), q.q.as_deref())
    {
        Ok((items, total)) => ok(json!({
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
        })),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct RuleInput {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub value: String,
    #[serde(default)]
    pub resolve: bool,
    #[serde(default)]
    pub remark: String,
}

/// 校验规则输入（返回规范化后的值）。
fn validate_rule_input(input: &RuleInput) -> Result<String, String> {
    let value = input.value.trim().to_string();
    match input.rule_type.as_str() {
        "ip-cidr" => {
            value
                .parse::<ip_network::IpNetwork>()
                .map_err(|_| format!("invalid CIDR: {value}"))?;
        }
        "host" => {
            if value.is_empty()
                || value.len() > 253
                || value.contains('/')
                || value.chars().any(|c| c.is_whitespace())
            {
                return Err(format!("invalid host: {value}"));
            }
            // 域名格式粗校验（允许 *. 前缀通配）
            let bare = value.trim_start_matches("*.");
            if bare.is_empty()
                || !bare
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            {
                return Err(format!("invalid host: {value}"));
            }
        }
        other => return Err(format!("invalid rule type: {other}")),
    }
    if input.remark.len() > 256 {
        return Err("remark too long (max 256)".into());
    }
    Ok(value)
}

pub async fn create_rule(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RuleInput>,
) -> Response {
    let value = match validate_rule_input(&req) {
        Ok(v) => v,
        Err(msg) => return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
    };

    if state
        .db
        .rule_exists(&req.rule_type, &value)
        .unwrap_or(false)
    {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "rule with same type and value already exists",
        );
    }

    match state
        .db
        .create_rule(&req.rule_type, &value, req.resolve, &req.remark)
    {
        Ok(rule) => {
            let _ = state.db.bump_config_version();
            audit(&state, &claims, &ip, "rule.create", Some(&rule.id), &req.remark);
            ok_created(rule)
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct UpdateRuleRequest {
    pub value: Option<String>,
    pub resolve: Option<bool>,
    pub remark: Option<String>,
}

pub async fn update_rule(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<UpdateRuleRequest>,
) -> Response {
    let existing = match state.db.get_rule(&id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "rule not found");
        }
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    };

    if let Some(v) = &req.value {
        let probe = RuleInput {
            rule_type: existing.rule_type.clone(),
            value: v.clone(),
            resolve: false,
            remark: String::new(),
        };
        let normalized = match validate_rule_input(&probe) {
            Ok(v) => v,
            Err(msg) => return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
        };
        if normalized != existing.value
            && state
                .db
                .rule_exists(&existing.rule_type, &normalized)
                .unwrap_or(false)
        {
            return err(
                StatusCode::CONFLICT,
                codes::DUPLICATE,
                "rule with same type and value already exists",
            );
        }
    }

    if let Err(e) = state.db.update_rule(
        &id,
        req.value.as_deref(),
        req.resolve,
        req.remark.as_deref(),
    ) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string());
    }
    let _ = state.db.bump_config_version();
    audit(&state, &claims, &ip, "rule.update", Some(&id), "");

    match state.db.get_rule(&id) {
        Ok(Some(rule)) => ok(rule),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, "reload failed"),
    }
}

#[derive(Deserialize)]
pub struct ForceQuery {
    #[serde(default)]
    pub force: bool,
}

pub async fn delete_rule(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Query(q): Query<ForceQuery>,
) -> Response {
    let groups = state.db.rule_referencing_groups(&id).unwrap_or_default();
    if !groups.is_empty() && !q.force {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "code": codes::DUPLICATE,
                "message": format!("rule is referenced by {} groups", groups.len()),
                "data": { "groups": groups },
            })),
        )
            .into_response();
    }

    match state.db.delete_rule(&id, q.force) {
        Ok(_) => {
            let _ = state.db.bump_config_version();
            audit(&state, &claims, &ip, "rule.delete", Some(&id), "");
            ok(json!(null))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct BatchRequest {
    pub rules: Vec<RuleInput>,
    #[serde(default = "default_on_conflict")]
    pub on_conflict: String,
}

fn default_on_conflict() -> String {
    "skip".to_string()
}

pub async fn batch_import(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<BatchRequest>,
) -> Response {
    if req.rules.is_empty() || req.rules.len() > 500 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "rules count must be 1-500",
        );
    }
    if !["skip", "overwrite", "error"].contains(&req.on_conflict.as_str()) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "on_conflict must be skip|overwrite|error",
        );
    }

    // error 模式：预检全部
    if req.on_conflict == "error" {
        for r in &req.rules {
            if let Ok(normalized) = validate_rule_input(r)
                && state.db.rule_exists(&r.rule_type, &normalized).unwrap_or(false)
            {
                return err(
                    StatusCode::CONFLICT,
                    codes::DUPLICATE,
                    format!("duplicate rule: {} {}", r.rule_type, normalized),
                );
            }
        }
    }

    let mut created = 0i64;
    let mut skipped = 0i64;
    let mut updated = 0i64;
    let mut errors = Vec::<String>::new();

    for r in &req.rules {
        let value = match validate_rule_input(r) {
            Ok(v) => v,
            Err(msg) => {
                errors.push(msg);
                continue;
            }
        };
        if state.db.rule_exists(&r.rule_type, &value).unwrap_or(false) {
            match req.on_conflict.as_str() {
                "overwrite" => {
                    // 找到既有记录并更新 remark/resolve
                    let (items, _) = state
                        .db
                        .list_rules(1, 100, Some(&r.rule_type), Some(&value))
                        .unwrap_or_default();
                    if let Some(existing) = items.iter().find(|i| i.value == value) {
                        if state
                            .db
                            .update_rule(&existing.id, None, Some(r.resolve), Some(&r.remark))
                            .is_ok()
                        {
                            updated += 1;
                        } else {
                            errors.push(format!("update failed: {value}"));
                        }
                    }
                }
                _ => skipped += 1,
            }
            continue;
        }
        match state.db.create_rule(&r.rule_type, &value, r.resolve, &r.remark) {
            Ok(_) => created += 1,
            Err(e) => errors.push(format!("{value}: {e}")),
        }
    }

    if created > 0 || updated > 0 {
        let _ = state.db.bump_config_version();
    }
    audit(
        &state,
        &claims,
        &ip,
        "rule.batch_import",
        None,
        &format!("created={created} skipped={skipped} updated={updated}"),
    );

    ok(json!({
        "created": created,
        "skipped": skipped,
        "updated": updated,
        "errors": errors,
    }))
}

use super::audit;
use axum::response::IntoResponse;
