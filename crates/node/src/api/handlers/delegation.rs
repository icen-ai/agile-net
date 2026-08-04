//! Delegation API handlers (federation P2, issuer side): issue / list / revoke delegated tokens.
//!
//! A delegated token lets the resource owner hand a consumer direct access to selected local
//! groups through the fan-out upstreams (the disaster set), without creating a local account.
//! Registration rides the fan-out session (protocol v3 Ctrl frames) and lives exactly as long
//! as that session — the plaintext is returned once at issuance, inside the share link.

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, ok_created};
use crate::db::models::DelegatedTokenRecord;
use crate::service::delegation;
use agile_net_core::proto::message::HintEntry;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

/// GET /api/v1/admin/delegation/tokens — every delegated token with its disaster set and
/// per-upstream live registration state.
pub async fn list_tokens(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    let tokens = match state.db_call(|db| db.list_delegated_tokens()).await {
        Ok(v) => v,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    };
    let connectors = state
        .db_call(|db| db.list_connectors())
        .await
        .unwrap_or_default();
    let states: HashMap<(String, String), String> = state
        .runtime
        .connector_manager
        .delegation_states()
        .into_iter()
        .map(|(t, c, s)| ((t, c), s))
        .collect();
    let groups_all = state
        .db_call(|db| db.list_groups(1, 10000, None).map(|(g, _)| g))
        .await
        .unwrap_or_default();

    let items: Vec<serde_json::Value> = tokens
        .into_iter()
        .map(|rec| token_json(&rec, &connectors, &states, &groups_all, None))
        .collect();
    ok(json!({ "items": items }))
}

#[derive(Deserialize)]
pub struct IssueRequest {
    pub label: String,
    /// Local group IDs the token may use (at least one)
    pub group_ids: Vec<String>,
    /// Disaster set: one row per upstream connector, exactly one primary
    pub regs: Vec<IssueReg>,
    /// Optional explicit E2E routing vocabulary; auto-derived from the primary connector's
    /// advertised routes when absent (required once any referenced group is e2e_required)
    #[serde(default)]
    pub hint_map: Vec<HintEntry>,
    /// Consumer mode: `dedicated` (专线, default) or `split` (分流 — the rule vocabulary is
    /// delivered E2E-sealed on pull; requires at least one e2e_required group)
    #[serde(default)]
    pub mode: String,
    /// Admin capability: '' (default) or ro/rules/full — the consumer pulls a bootstrap ticket
    /// over the E2E config channel and manages this issuer; `full` additionally unlocks transit
    /// management of discovered upstreams. Requires at least one e2e_required group.
    #[serde(default)]
    pub admin_scope: String,
}

#[derive(Deserialize)]
pub struct IssueReg {
    pub connector_id: String,
    #[serde(default)]
    pub is_primary: bool,
}

/// POST /api/v1/admin/delegation/tokens — issue a delegated token (plaintext returned once).
pub async fn issue_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<IssueRequest>,
) -> Response {
    if req.label.trim().is_empty() || req.label.len() > 128 {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "备注必填且 ≤128 字符");
    }
    if req.group_ids.is_empty() {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "至少选择一个权限组");
    }
    if req.regs.is_empty() {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "容灾集合不能为空");
    }
    if req.regs.iter().filter(|r| r.is_primary).count() != 1 {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "容灾集合必须恰好一个主入口");
    }
    let mode = if req.mode.is_empty() { "dedicated" } else { req.mode.as_str() };
    if mode != "dedicated" && mode != "split" {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "接入模式只能是 dedicated（专线）或 split（分流）");
    }
    if !["", "ro", "rules", "full"].contains(&req.admin_scope.as_str()) {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "管理授权档位只能是 ro / rules / full");
    }

    // auto-derive the E2E hint from the primary connector's effective advertise set (manual
    // advertise + pushed group rules — the same set the upstream route table will carry) when
    // the caller did not provide one explicitly; mandatory once any referenced group is e2e_required
    let mut hint_map = req.hint_map.clone();
    let db_groups = state
        .db_call(|db| db.list_groups(1, 10000, None).map(|(g, _)| g))
        .await
        .unwrap_or_default();
    let needs_hint = req.group_ids.iter().any(|gid| {
        db_groups
            .iter()
            .any(|g| &g.id == gid && g.e2e_required)
    });
    if hint_map.is_empty() && needs_hint {
        let primary_id = req
            .regs
            .iter()
            .find(|r| r.is_primary)
            .map(|r| r.connector_id.clone())
            .expect("exactly one primary checked above");
        let advertise = state
            .db_call(move |db| {
                db.get_connector(&primary_id).map(|c| {
                    c.map(|c| crate::service::connectors::effective_advertise_of(db, &c))
                })
            })
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        let Some(hint) = delegation::derive_hint(&advertise) else {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "引用组含端到端加密组，但主入口扇出没有任何可路由项（路由宣告与上送组规则均为空），无法生成路由词——请先为该扇出配置上送组或路由宣告",
            );
        };
        let group_names: Vec<String> = req
            .group_ids
            .iter()
            .filter_map(|gid| db_groups.iter().find(|g| &g.id == gid))
            .filter(|g| g.e2e_required)
            .map(|g| g.name.clone())
            .collect();
        hint_map = vec![HintEntry {
            hint,
            groups: group_names,
        }];
    }

    // split tier rides the E2E config channel — it requires at least one e2e_required group
    if mode == "split" && hint_map.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "分流档要求引用组含端到端加密组（规则经 E2E 通道下发）",
        );
    }
    // a bootstrap ticket must never cross a relay in plaintext — admin requires the E2E channel
    if !req.admin_scope.is_empty() && hint_map.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "授权管理要求引用组含端到端加密组（票据经 E2E 通道下发）",
        );
    }

    let regs: Vec<(String, bool)> = req
        .regs
        .iter()
        .map(|r| (r.connector_id.clone(), r.is_primary))
        .collect();
    let label = req.label.trim().to_string();
    let group_ids = req.group_ids.clone();
    let mode_owned = mode.to_string();
    let admin_scope = req.admin_scope.clone();
    let issued = state
        .db_call(move |db| {
            delegation::issue_token(db, &label, &group_ids, &hint_map, &regs, &mode_owned, &admin_scope)
                .map_err(|e| agile_net_core::error::Error::Other(e.to_string()))
        })
        .await;
    let (rec, plaintext) = match issued {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, e.to_string()),
    };

    // warm the enforcement caches immediately (the group may have been created seconds ago,
    // ahead of the config_version watcher tick); session registration rides the connector sync task
    state.runtime.connector_manager.refresh_delegation_keys();
    state.runtime.connector_manager.refresh_push_groups();

    audit(
        &state,
        &claims,
        &ip,
        "delegation.issue",
        Some(&rec.id),
        &format!("label={} groups={} regs={}", rec.label, req.group_ids.len(), rec.regs.len()),
    )
    .await;

    // share link: primary entry first, the rest of the disaster set in order
    let connectors = state
        .db_call(|db| db.list_connectors())
        .await
        .unwrap_or_default();
    let states: HashMap<(String, String), String> = HashMap::new();
    let share_url = build_share_url(&rec, &connectors, &plaintext);
    let groups_all = state
        .db_call(|db| db.list_groups(1, 10000, None).map(|(g, _)| g))
        .await
        .unwrap_or_default();
    ok_created(token_json(&rec, &connectors, &states, &groups_all, Some((&plaintext, &share_url))))
}

/// DELETE /api/v1/admin/delegation/tokens/{id} — revoke (frames go to every online upstream
/// of the disaster set; offline upstreams invalidate by disconnect).
pub async fn revoke_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    match state.runtime.connector_manager.revoke_delegated(&id).await {
        Ok(true) => {
            state.runtime.connector_manager.refresh_delegation_keys();
            audit(&state, &claims, &ip, "delegation.revoke", Some(&id), "").await;
            ok(json!({ "revoked": true }))
        }
        Ok(false) => err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "委托令牌不存在"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

/// Share link for a freshly issued token: `anet://connect` with the `d:` account mark, the
/// primary entry as server/fp, and the whole disaster set as entry/entryfp (failover order).
fn build_share_url(
    rec: &DelegatedTokenRecord,
    connectors: &[crate::db::models::ConnectorView],
    plaintext: &str,
) -> String {
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut sorted_regs = rec.regs.clone();
    sorted_regs.sort_by(|a, b| b.is_primary.cmp(&a.is_primary));
    for reg in &sorted_regs {
        if let Some(c) = connectors.iter().find(|c| c.id == reg.connector_id) {
            entries.push((c.upstream_addr.clone(), c.pinned_fingerprint.clone()));
        }
    }
    let primary = entries
        .first()
        .map(|(a, _)| a.clone())
        .unwrap_or_else(|| "127.0.0.1:54430".to_string());
    // federation P3: the first hint of the map rides the link — the consumer client seals
    // every Open into an E2E envelope when it is present (transparent tier when absent)
    let hint_map: Vec<agile_net_core::proto::message::HintEntry> =
        serde_json::from_str(&rec.hint_map).unwrap_or_default();
    let ehint = hint_map.first().map(|h| h.hint.as_str());
    let emode = (rec.mode == "split").then_some("split");
    agile_net_core::link::build_delegate_url(&primary, &rec.label, plaintext, &entries, ehint, emode, !rec.admin_scope.is_empty())
}

/// Render one token for the API (group names resolved, per-upstream state folded in).
fn token_json(
    rec: &DelegatedTokenRecord,
    connectors: &[crate::db::models::ConnectorView],
    states: &HashMap<(String, String), String>,
    groups_all: &[crate::db::models::GroupRecord],
    issued: Option<(&str, &str)>, // (plaintext, share_url) — only at issuance
) -> serde_json::Value {
    let group_ids: Vec<String> = serde_json::from_str(&rec.groups).unwrap_or_default();
    let groups: Vec<serde_json::Value> = group_ids
        .iter()
        .filter_map(|gid| groups_all.iter().find(|g| &g.id == gid))
        .map(|g| {
            json!({
                "id": g.id,
                "name": g.name,
                "e2e_required": g.e2e_required,
            })
        })
        .collect();
    let regs: Vec<serde_json::Value> = rec
        .regs
        .iter()
        .map(|r| {
            let c = connectors.iter().find(|c| c.id == r.connector_id);
            let state = states
                .get(&(rec.id.clone(), r.connector_id.clone()))
                .cloned()
                .unwrap_or_else(|| "offline".into());
            json!({
                "connector_id": r.connector_id,
                "connector_name": c.map(|c| c.name.clone()).unwrap_or_else(|| r.connector_id.clone()),
                "upstream_addr": c.map(|c| c.upstream_addr.clone()).unwrap_or_default(),
                "is_primary": r.is_primary,
                "state": state,
            })
        })
        .collect();
    let mut v = json!({
        "id": rec.id,
        "token_prefix": rec.token_prefix,
        "label": rec.label,
        "groups": groups,
        "mode": rec.mode,
        "admin_scope": rec.admin_scope,
        "hint_map": serde_json::from_str::<Vec<HintEntry>>(&rec.hint_map).unwrap_or_default(),
        "regs": regs,
        "created_at": rec.created_at,
    });
    if let Some((plaintext, share_url)) = issued {
        v["token"] = json!(plaintext);
        v["share_url"] = json!(share_url);
    }
    v
}
