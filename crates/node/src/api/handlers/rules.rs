//! Rules API handlers (see docs/api/rules.md)

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
        .db_call(move |db| db.list_rules(page, page_size, q.rule_type.as_deref(), q.q.as_deref()))
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

/// Validate rule input (returns the normalized value).
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
            // Loose hostname format check (allows the *. wildcard prefix)
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

    let (rule_type, val) = (req.rule_type.clone(), value.clone());
    let exists = state
        .db_call(move |db| db.rule_exists(&rule_type, &val))
        .await
        .unwrap_or(false);
    if exists {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "rule with same type and value already exists",
        );
    }

    // Create + config version bump merged into one blocking task
    let (rule_type, resolve, remark) = (req.rule_type.clone(), req.resolve, req.remark.clone());
    match state
        .db_call(move |db| {
            let rule = db.create_rule(&rule_type, &value, resolve, &remark)?;
            let _ = db.bump_config_version();
            Ok(rule)
        })
        .await
    {
        Ok(rule) => {
            audit(
                &state,
                &claims,
                &ip,
                "rule.create",
                Some(&rule.id),
                &req.remark,
            )
            .await;
            ok_created(rule)
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
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
    let rid = id.clone();
    let existing = match state.db_call(move |db| db.get_rule(&rid)).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "rule not found");
        }
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
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
        if normalized != existing.value {
            let (rule_type, val) = (existing.rule_type.clone(), normalized);
            let exists = state
                .db_call(move |db| db.rule_exists(&rule_type, &val))
                .await
                .unwrap_or(false);
            if exists {
                return err(
                    StatusCode::CONFLICT,
                    codes::DUPLICATE,
                    "rule with same type and value already exists",
                );
            }
        }
    }

    // Update + config version bump merged into one blocking task
    let (rid, value, remark) = (id.clone(), req.value.clone(), req.remark.clone());
    let resolve = req.resolve;
    if let Err(e) = state
        .db_call(move |db| {
            db.update_rule(&rid, value.as_deref(), resolve, remark.as_deref())?;
            db.bump_config_version()
        })
        .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    audit(&state, &claims, &ip, "rule.update", Some(&id), "").await;

    match state.db_call(move |db| db.get_rule(&id)).await {
        Ok(Some(rule)) => ok(rule),
        _ => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "reload failed",
        ),
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
    let rid = id.clone();
    let groups = state
        .db_call(move |db| db.rule_referencing_groups(&rid))
        .await
        .unwrap_or_default();
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

    // Delete + config version bump merged into one blocking task
    let force = q.force;
    let aid = id.clone();
    match state
        .db_call(move |db| {
            db.delete_rule(&id, force)?;
            db.bump_config_version()
        })
        .await
    {
        Ok(_) => {
            audit(&state, &claims, &ip, "rule.delete", Some(&aid), "").await;
            ok(json!(null))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
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

    // error mode: pre-check everything (one blocking task, returns the first conflict)
    if req.on_conflict == "error" {
        let probes: Vec<(String, String)> = req
            .rules
            .iter()
            .filter_map(|r| {
                validate_rule_input(r)
                    .ok()
                    .map(|normalized| (r.rule_type.clone(), normalized))
            })
            .collect();
        let dup = state
            .db_call(move |db| {
                for (rule_type, normalized) in &probes {
                    if db.rule_exists(rule_type, normalized).unwrap_or(false) {
                        return Ok(Some(format!("{rule_type} {normalized}")));
                    }
                }
                Ok(None)
            })
            .await
            .unwrap_or(None);
        if let Some(d) = dup {
            return err(
                StatusCode::CONFLICT,
                codes::DUPLICATE,
                format!("duplicate rule: {d}"),
            );
        }
    }

    // Whole batch import merged into one blocking task (up to 500 entries; per-entry spawn would cost more)
    let (rules_in, on_conflict) = (req.rules, req.on_conflict.clone());
    let batch = state
        .db_call(move |db| {
            let mut created = 0i64;
            let mut skipped = 0i64;
            let mut updated = 0i64;
            let mut errors = Vec::<String>::new();

            for r in &rules_in {
                let value = match validate_rule_input(r) {
                    Ok(v) => v,
                    Err(msg) => {
                        errors.push(msg);
                        continue;
                    }
                };
                if db.rule_exists(&r.rule_type, &value).unwrap_or(false) {
                    match on_conflict.as_str() {
                        "overwrite" => {
                            // Find the existing record and update remark/resolve
                            let (items, _) = db
                                .list_rules(1, 100, Some(&r.rule_type), Some(&value))
                                .unwrap_or_default();
                            if let Some(existing) = items.iter().find(|i| i.value == value) {
                                if db
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
                match db.create_rule(&r.rule_type, &value, r.resolve, &r.remark) {
                    Ok(_) => created += 1,
                    Err(e) => errors.push(format!("{value}: {e}")),
                }
            }

            if created > 0 || updated > 0 {
                let _ = db.bump_config_version();
            }
            Ok((created, skipped, updated, errors))
        })
        .await;
    let (created, skipped, updated, errors) = match batch {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    };
    audit(
        &state,
        &claims,
        &ip,
        "rule.batch_import",
        None,
        &format!("created={created} skipped={skipped} updated={updated}"),
    )
    .await;

    ok(json!({
        "created": created,
        "skipped": skipped,
        "updated": updated,
        "errors": errors,
    }))
}

use super::audit;
use axum::response::IntoResponse;
