//! Delegation API handlers (federation P2, issuer side): issue / list / revoke delegated tokens.
//!
//! A delegated token lets the resource owner hand a consumer direct access to selected local
//! groups — the token itself is the only identity. Entry modes: `relay` tokens ride the fan-out
//! disaster set (registration lives exactly as long as the upstream session); `direct` tokens are
//! dialed at this issuer's own listener and self-registered into its persistent local registry.
//! The plaintext is returned once at issuance, inside the share link.

use super::audit;
use super::lifecycle_status;
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
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
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
    /// Disaster set (relay entry mode only): one row per upstream connector, exactly one primary
    #[serde(default)]
    pub regs: Vec<IssueReg>,
    /// Consumer mode: `dedicated` (专线, default) or `split` (分流 — the rule vocabulary is
    /// delivered E2E-sealed on pull; requires at least one e2e_required group)
    #[serde(default)]
    pub mode: String,
    /// Admin capability: '' (default) or ro/rules/full — the consumer pulls a bootstrap ticket
    /// over the E2E config channel and manages this issuer; `full` additionally unlocks transit
    /// management of discovered upstreams. Requires at least one e2e_required group.
    #[serde(default)]
    pub admin_scope: String,
    /// Entry mode: `relay` (default, via the disaster set) or `direct` (dial this issuer's own
    /// listener; regs ignored)
    #[serde(default = "default_entry_mode")]
    pub entry_mode: String,
    /// Concurrency tier: `single` (default, a new session kicks the old) or `multi` (bounded by
    /// the delegation_max_sessions snapshot)
    #[serde(default = "default_concurrency")]
    pub concurrency: String,
    /// Token lifecycle (optional): validity window (RFC3339 or YYYY-MM-DDTHH:MM; empty = never)
    #[serde(default)]
    pub expires_at: String,
    /// Token lifecycle (optional): max data-plane opens (0/absent = unlimited)
    #[serde(default)]
    pub max_uses: Option<i64>,
    /// Suggested self-declared name for the consumer device, prefilled into the generated
    /// link's myname word (node.md M3-T6 naming triplet; link-only, not stored)
    #[serde(default)]
    pub my_name: String,
    /// Topology-visibility tier (node.md M6): '' = domain (default) | disclose | approve
    #[serde(default)]
    pub visibility: String,
}

fn default_entry_mode() -> String {
    "relay".into()
}
fn default_concurrency() -> String {
    "single".into()
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
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "备注必填且 ≤128 字符",
        );
    }
    if req.group_ids.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "至少选择一个权限组",
        );
    }
    if req.entry_mode != "relay" && req.entry_mode != "direct" {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "入口模式只能是 relay（经扇出）或 direct（直连本端点）",
        );
    }
    if req.concurrency != "single" && req.concurrency != "multi" {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "并发档位只能是 single（踢旧）或 multi（多会话）",
        );
    }
    if req.entry_mode == "relay" {
        if req.regs.is_empty() {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "容灾集合不能为空",
            );
        }
        if req.regs.iter().filter(|r| r.is_primary).count() != 1 {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "容灾集合必须恰好一个主入口",
            );
        }
    }
    let mode = if req.mode.is_empty() {
        "dedicated"
    } else {
        req.mode.as_str()
    };
    if mode != "dedicated" && mode != "split" {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "接入模式只能是 dedicated（专线）或 split（分流）",
        );
    }
    if !["", "ro", "rules", "full"].contains(&req.admin_scope.as_str()) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "管理授权档位只能是 ro / rules / full",
        );
    }
    // token lifecycle (optional): normalize the expiry to the canonical UTC form; a past
    // expiry is rejected at issuance instead of dying silently on first use
    let expires_at = if req.expires_at.trim().is_empty() {
        None
    } else {
        match crate::db::normalize_expiry(&req.expires_at) {
            Ok(v) => {
                if !crate::db::expiry_active(Some(&v)) {
                    return err(
                        StatusCode::BAD_REQUEST,
                        codes::VALIDATION_FAILED,
                        "过期时间不能早于当前时间",
                    );
                }
                Some(v)
            }
            Err(msg) => return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
        }
    };
    let max_uses = req.max_uses;
    if max_uses.is_some_and(|v| v <= 0) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "用量上限必须为正整数",
        );
    }
    if req.my_name.chars().count() > 64 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "我的名称最长 64 字符",
        );
    }
    if !["", "domain", "disclose", "approve"].contains(&req.visibility.as_str()) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "拓扑可见性档位只能是 domain / disclose / approve",
        );
    }

    // federation P3 entrust mode: every E2E token automatically carries its opaque entrust word
    // (en_xxx, derived inside issue_token) — routing without rule disclosure; push_groups /
    // advertise are NOT required. The e2e check below only gates the split/admin tiers.
    let db_groups = state
        .db_call(|db| db.list_groups(1, 10000, None).map(|(g, _)| g))
        .await
        .unwrap_or_default();
    let has_e2e = req
        .group_ids
        .iter()
        .any(|gid| db_groups.iter().any(|g| &g.id == gid && g.e2e_required));

    // split tier rides the E2E config channel — it requires at least one e2e_required group
    if mode == "split" && !has_e2e {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "分流档要求引用组含端到端加密组（规则经 E2E 通道下发）",
        );
    }
    // a bootstrap ticket must never cross a relay in plaintext — admin requires the E2E channel
    if !req.admin_scope.is_empty() && !has_e2e {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "授权管理要求引用组含端到端加密组（票据经 E2E 通道下发）",
        );
    }

    // relay mode rides the disaster set; direct mode self-registers on this issuer's listener
    let regs: Vec<(String, bool)> = if req.entry_mode == "relay" {
        req.regs
            .iter()
            .map(|r| (r.connector_id.clone(), r.is_primary))
            .collect()
    } else {
        Vec::new()
    };
    // session cap snapshot for the multi tier (node_config.delegation_max_sessions, default 8)
    let max_sessions = state
        .db_call(|db| db.get_config("delegation_max_sessions"))
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(8);
    let label = req.label.trim().to_string();
    let group_ids = req.group_ids.clone();
    let mode_owned = mode.to_string();
    let admin_scope = req.admin_scope.clone();
    let entry_mode = req.entry_mode.clone();
    let concurrency = req.concurrency.clone();
    let issued = state
        .db_call(move |db| {
            delegation::issue_token(
                db,
                &label,
                &group_ids,
                &regs,
                &mode_owned,
                &admin_scope,
                &entry_mode,
                &concurrency,
                max_sessions,
            )
            .map_err(|e| agile_net_core::error::Error::Other(e.to_string()))
        })
        .await;
    let (mut rec, plaintext) = match issued {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                e.to_string(),
            );
        }
    };

    // token lifecycle: apply the optional window right after issuance (the registration sync
    // polls on a 2s tick, so the follow-up update always lands before any registration)
    if expires_at.is_some() || max_uses.is_some() {
        let (rec_id, exp, mu) = (rec.id.clone(), expires_at.clone(), max_uses);
        let applied = state
            .db_call(move |db| db.set_delegated_token_lifecycle(&rec_id, exp.as_deref(), mu))
            .await;
        if let Err(e) = applied {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
        rec.expires_at = expires_at.clone();
        rec.max_uses = max_uses.filter(|v| *v > 0);
    }

    // M6 visibility tier: apply right after issuance (the registration sync picks it up)
    let visibility = req.visibility.trim();
    if !visibility.is_empty() && visibility != "domain" {
        let (rec_id, vis) = (rec.id.clone(), visibility.to_string());
        let applied = state
            .db_call(move |db| db.set_delegated_token_visibility(&rec_id, &vis))
            .await;
        if let Err(e) = applied {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
        rec.visibility = visibility.to_string();
    }

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
        &format!(
            "label={} groups={} regs={} entry_mode={}",
            rec.label,
            req.group_ids.len(),
            rec.regs.len(),
            rec.entry_mode
        ),
    )
    .await;

    // share link: relay mode = primary entry first + the rest of the disaster set in order;
    // direct mode = this node's own endpoints (public > LAN > loopback)
    let connectors = state
        .db_call(|db| db.list_connectors())
        .await
        .unwrap_or_default();
    let states: HashMap<(String, String), String> = HashMap::new();
    let share_url = build_share_url(&state, &rec, &connectors, &plaintext, req.my_name.trim()).await;
    let groups_all = state
        .db_call(|db| db.list_groups(1, 10000, None).map(|(g, _)| g))
        .await
        .unwrap_or_default();
    ok_created(token_json(
        &rec,
        &connectors,
        &states,
        &groups_all,
        Some((&plaintext, &share_url)),
    ))
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
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

/// Share link for a freshly issued token: `anet://connect` with the `d:` account mark and the
/// whole entry set as entry/entryfp (failover order).
///
/// Entry set by mode: `relay` = the disaster set upstreams (primary first, pinned fingerprints
/// from the connector rows); `direct` = this issuer's own share endpoints (declared public
/// identity > LAN enumeration > loopback fallback; every entry pinned to the local relay cert
/// fingerprint).
async fn build_share_url(
    state: &ApiState,
    rec: &DelegatedTokenRecord,
    connectors: &[crate::db::models::ConnectorView],
    plaintext: &str,
    my_name: &str,
) -> String {
    let entries: Vec<(String, String)> = if rec.entry_mode == "direct" {
        let (_, relay_port) = state.public_tunnel_endpoint().await;
        let public = state.declared_relay_addr().await;
        let fp = state.runtime.cert_fingerprint.clone().unwrap_or_default();
        state
            .share_endpoints(relay_port, public)
            .await
            .into_iter()
            .map(|e| (e.addr, fp.clone()))
            .collect()
    } else {
        let mut sorted_regs = rec.regs.clone();
        sorted_regs.sort_by(|a, b| b.is_primary.cmp(&a.is_primary));
        sorted_regs
            .iter()
            .filter_map(|reg| {
                connectors
                    .iter()
                    .find(|c| c.id == reg.connector_id)
                    .map(|c| (c.upstream_addr.clone(), c.pinned_fingerprint.clone()))
            })
            .collect()
    };
    let primary = entries
        .first()
        .map(|(a, _)| a.clone())
        .unwrap_or_else(|| "127.0.0.1:54430".to_string());
    // federation P3: an E2E token carries exactly one routing word — its opaque entrust word
    // (en_xxx). The consumer client seals every Open into an E2E envelope addressed by it
    // (transparent tier when absent).
    let hint_map: Vec<agile_net_core::proto::message::HintEntry> =
        serde_json::from_str(&rec.hint_map).unwrap_or_default();
    let en = hint_map
        .iter()
        .find(|h| {
            h.hint
                .starts_with(agile_net_core::relay::e2e::ENTRUST_PREFIX)
        })
        .map(|h| h.hint.as_str());
    let emode = (rec.mode == "split").then_some("split");
    let mut url = agile_net_core::link::build_delegate_url(
        &primary,
        &rec.label,
        plaintext,
        &entries,
        en,
        emode,
        !rec.admin_scope.is_empty(),
        // M3-T6: the issuer-suggested "my name" prefills the link's myname word
        Some(my_name).filter(|s| !s.is_empty()),
    );
    // M6: a non-domain visibility tier rides the link as an import-time clause (M4-T5 条款卡)
    if !rec.visibility.is_empty() && rec.visibility != "domain" {
        url.push_str(&format!("&visibility={}", rec.visibility));
    }
    url
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
                // adoption lineage (naming sovereignty): empty = plain local group
                "adopted_node": g.adopted_node,
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
        // SHA-256 of the token (not a secret; the admin session inventory joins on it, node.md M3-T1)
        "token_hash": rec.token_hash,
        "token_prefix": rec.token_prefix,
        "label": rec.label,
        "groups": groups,
        "mode": rec.mode,
        "admin_scope": rec.admin_scope,
        "entry_mode": rec.entry_mode,
        "concurrency": rec.concurrency,
        "max_sessions": rec.max_sessions,
        "visibility": rec.visibility,
        "hint_map": serde_json::from_str::<Vec<HintEntry>>(&rec.hint_map).unwrap_or_default(),
        "regs": regs,
        "created_at": rec.created_at,
        "expires_at": rec.expires_at,
        "max_uses": rec.max_uses,
        "used_count": rec.used_count,
        // token lifecycle status: active | expiring (<72h) | expired | exhausted
        "lifecycle": lifecycle_status(rec.expires_at.as_deref(), rec.max_uses, rec.used_count),
    });
    if let Some((plaintext, share_url)) = issued {
        v["token"] = json!(plaintext);
        v["share_url"] = json!(share_url);
    }
    v
}
