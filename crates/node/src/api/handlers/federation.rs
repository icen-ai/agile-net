//! Federation API handlers (federation P1: authorizable pool + one-click adoption).
//!
//! The authorizable pool is the live view of every online fan-in peer: its advertised routes
//! and the policy groups it pushed at auth (source-tagged by node_id, namespace isolation).
//! Adoption materializes a pushed group into a local group (rules reused by unique
//! (type, value), group name suffixed `@<node_id>`), so the resource owner's policy becomes
//! grantable to local identities without the upstream admin re-typing a single rule.

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

/// Max local group name length (aligned with the groups handler).
const MAX_GROUP_NAME: usize = 64;

/// GET /api/v1/admin/federation/offered — the authorizable pool (online peers only), each
/// pushed group folded with its local adoption state (the adoption dialog's 待采纳/跟随中 split).
pub async fn offered(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    let adopted = state
        .db_call(|db| db.list_adopted_groups())
        .await
        .unwrap_or_default();
    let items: Vec<serde_json::Value> = match &state.runtime.listener {
        Some(listener) => listener
            .peer_offers()
            .into_iter()
            .map(|o| {
                let groups: Vec<serde_json::Value> = o
                    .groups
                    .iter()
                    .map(|g| {
                        let local = adopted
                            .iter()
                            .find(|a| a.adopted_node == o.node_id && a.adopted_name == g.name);
                        json!({
                            "name": g.name,
                            "remark": g.remark,
                            "rules": g.rules,
                            "e2e_required": g.e2e_required,
                            "adopted": local.is_some(),
                            "adopted_id": local.map(|a| a.id.clone()),
                            "adopted_name": local.map(|a| a.name.clone()),
                        })
                    })
                    .collect();
                json!({
                    "node_id": o.node_id,
                    "advertise": o.advertise,
                    "groups": groups,
                })
            })
            .collect(),
        None => Vec::new(),
    };
    ok(json!({ "items": items }))
}

#[derive(Deserialize)]
pub struct AdoptRequest {
    /// Source peer (online fan-in session node_id)
    pub node_id: String,
    /// Pushed group name (as offered by the peer)
    pub group: String,
}

/// Classify a pushed rule literal into the local rule type (mirror of the relay ACL compiler).
fn rule_type_of(value: &str) -> &'static str {
    if value.parse::<ip_network::IpNetwork>().is_ok() {
        "ip-cidr"
    } else {
        // Exact hosts and *.suffix wildcards both map to the host rule type
        "host"
    }
}

/// Adopted group name: `{name}@{node_id}` (source tag, namespace isolation), truncated to
/// the group name limit; collisions get a `·N` suffix.
fn adopt_name(base: &str, node_id: &str, exists: &mut dyn FnMut(&str) -> bool) -> String {
    let raw = format!("{base}@{node_id}");
    let truncated: String = raw.chars().take(MAX_GROUP_NAME).collect();
    if !exists(&truncated) {
        return truncated;
    }
    for n in 2..100 {
        let suffix = format!("·{n}");
        let keep = MAX_GROUP_NAME.saturating_sub(suffix.chars().count());
        let candidate: String = truncated.chars().take(keep).collect::<String>() + &suffix;
        if !exists(&candidate) {
            return candidate;
        }
    }
    // Effectively unreachable (100 same-named groups); fall back to a uuid-suffixed name
    format!(
        "{}·{}",
        truncated.chars().take(56).collect::<String>(),
        &uuid::Uuid::new_v4().to_string()[..6]
    )
}

/// POST /api/v1/admin/federation/adopt — materialize a pushed group into a local group.
pub async fn adopt(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<AdoptRequest>,
) -> Response {
    if req.node_id.is_empty()
        || req.node_id.len() > 128
        || req.group.is_empty()
        || req.group.len() > 128
    {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "invalid node_id or group",
        );
    }
    let Some(listener) = &state.runtime.listener else {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "relay listener not enabled",
        );
    };
    let offers = listener.peer_offers();
    let Some(offer) = offers.iter().find(|o| o.node_id == req.node_id) else {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "peer not online (pushed groups live on the fan-in session)",
        );
    };
    let Some(pushed) = offer.groups.iter().find(|g| g.name == req.group) else {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            format!("pushed group not found: {}", req.group),
        );
    };

    let src_name = pushed.name.clone();
    let src_remark = pushed.remark.clone();
    let rules = pushed.rules.clone();
    let src_e2e = pushed.e2e_required;
    let node_id = req.node_id.clone();
    // Source tag = the issuer-assigned title for this external node (token remark; falls back to
    // node_id) — local naming sovereignty: everything sourced from a peer carries MY name for it.
    // Lineage matching below still keys on node_id (stable), only display uses the title.
    let display = listener
        .peer_display_map()
        .into_iter()
        .find(|(id, _)| id == &req.node_id)
        .map(|(_, d)| d)
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| req.node_id.clone());

    // idempotent: adopting the same pushed group twice returns the existing mirror
    let existing = state
        .db_call({
            let (n, g) = (node_id.clone(), src_name.clone());
            move |db| db.find_adopted_group(&n, &g)
        })
        .await;
    if let Ok(Some(g)) = existing {
        return ok(json!({
            "id": g.id,
            "name": g.name,
            "rule_count": g.rule_count,
            "reused": 0,
            "already": true,
        }));
    }

    let created = state
        .db_call(move |db| {
            // Group name with source tag = my title for the source node (dedup via get_group_by_name)
            let name = adopt_name(&src_name, &display, &mut |n| {
                db.get_group_by_name(n).ok().flatten().is_some()
            });
            // Materialize rules: reuse by unique (type, value), else create with a source-tag remark
            let mut rule_ids: Vec<String> = Vec::new();
            let mut reused = 0usize;
            for value in &rules {
                let value = value.trim();
                if value.is_empty() || value.len() > 256 {
                    continue;
                }
                let ty = rule_type_of(value);
                match db.find_rule_id(ty, value)? {
                    Some(id) => {
                        reused += 1;
                        rule_ids.push(id);
                    }
                    None => {
                        let remark = format!("上送自 {display}/{src_name}");
                        let rec = db.create_rule(ty, value, false, &remark)?;
                        rule_ids.push(rec.id);
                    }
                }
            }
            let group = db.create_group(&name, &format!("上送自 {display}：{src_remark}"))?;
            db.set_group_rules(&group.id, &rule_ids)?;
            // adoption lineage: the group becomes a read-only live mirror of the pushed source
            db.set_group_adoption(&group.id, &node_id, &src_name)?;
            // federation P3: adoption inherits the E2E enforcement flag (fresh group has no
            // attachments yet, so the guard always passes)
            if src_e2e {
                db.set_group_e2e_required(&group.id, true)?;
            }
            db.bump_config_version()?;
            Ok((group, rule_ids.len(), reused))
        })
        .await;

    match created {
        Ok((group, total, reused)) => {
            audit(
                &state,
                &claims,
                &ip,
                "federation.adopt",
                Some(&group.id),
                &format!(
                    "{}@{} rules={} reused={}",
                    req.group, req.node_id, total, reused
                ),
            )
            .await;
            ok(json!({
                "id": group.id,
                "name": group.name,
                "rule_count": total,
                "reused": reused,
            }))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

/// POST /api/v1/admin/federation/adopted/{id}/copy — detach a mirror into an editable local
/// group (same rule bindings; no lineage). The adopted original keeps following its source.
pub async fn copy_adopted(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    let copied = state
        .db_call(move |db| {
            let Some(src) = db.get_group(&id)? else {
                return Ok(Err("采纳组不存在".to_string()));
            };
            if src.adopted_node.is_empty() {
                return Ok(Err("该组不是采纳组".to_string()));
            }
            // detached editable copy: `<name> 副本`, deduped with ·N suffixes
            let base: String = src.name.chars().take(MAX_GROUP_NAME - 6).collect();
            let mut name = format!("{base} 副本");
            let mut n = 2u32;
            while db.get_group_by_name(&name)?.is_some() {
                name = format!("{base} 副本·{n}");
                n += 1;
            }
            let remark = format!("复制自采纳组 {}（上送自 {}）", src.name, src.adopted_node);
            let group = db.create_group(&name, &remark)?;
            let rule_ids: Vec<String> = db
                .rules_of_group(&src.id)?
                .into_iter()
                .map(|r| r.id)
                .collect();
            db.set_group_rules(&group.id, &rule_ids)?;
            db.bump_config_version()?;
            Ok(Ok((group, rule_ids.len())))
        })
        .await;

    match copied {
        Ok(Ok((group, n))) => {
            audit(
                &state,
                &claims,
                &ip,
                "federation.copy",
                Some(&group.id),
                &group.name,
            )
            .await;
            ok(json!({ "id": group.id, "name": group.name, "rule_count": n }))
        }
        Ok(Err(msg)) => err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_type_classification() {
        assert_eq!(rule_type_of("10.0.0.0/8"), "ip-cidr");
        assert_eq!(rule_type_of("192.168.1.1/32"), "ip-cidr");
        assert_eq!(rule_type_of("git.internal"), "host");
        assert_eq!(rule_type_of("*.corp.example.com"), "host");
    }

    #[test]
    fn adopt_name_tags_source_and_dedups() {
        let name = adopt_name("git", "peer-c", &mut |_| false);
        assert_eq!(name, "git@peer-c");
        // Collision chain: base, ·2, ·3 ...
        let mut calls = 0;
        let name = adopt_name("git", "peer-c", &mut |_| {
            calls += 1;
            calls <= 2
        });
        assert_eq!(name, "git@peer-c·3");
        // Long inputs truncated to the limit
        let long = "x".repeat(200);
        let name = adopt_name(&long, "peer-c", &mut |_| false);
        assert_eq!(name.chars().count(), MAX_GROUP_NAME);
    }
}
