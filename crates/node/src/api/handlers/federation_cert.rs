//! Federation trust & topology APIs (node.md M6): transitive-certification switches + trust
//! list, and the topology-visibility receipts view.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok};

/// GET /api/v1/admin/federation/cert — transitive-certification settings + counters.
pub async fn get_cert_settings(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    let (enabled, trust) = state
        .db_call(|db| {
            Ok((
                crate::service::cert_relay::cert_relay_in_enabled(db),
                crate::service::cert_relay::trust_list(db),
            ))
        })
        .await
        .unwrap_or((false, vec![]));
    // adopted transitive devices (certified_by != '') for the source overview
    let adopted = state
        .db_call(|db| {
            Ok(db
                .list_devices(None, None)?
                .into_iter()
                .filter(|d| !d.certified_by.is_empty())
                .map(|d| {
                    json!({
                        "device_fp": d.device_fp,
                        "subject": d.subject,
                        "remark": d.remark,
                        "origin_fp": d.certified_by,
                        "state": d.state,
                    })
                })
                .collect::<Vec<_>>())
        })
        .await
        .unwrap_or_default();
    // this node's own device fingerprint (what peers put in THEIR trust list)
    let own_fp = state.runtime.device.device_fp();
    ok(json!({
        "enabled": enabled,
        "trust_list": trust,
        "own_fp": own_fp,
        "adopted": adopted,
    }))
}

#[derive(Deserialize)]
pub struct CertSettingsReq {
    pub enabled: bool,
    #[serde(default)]
    pub trust_list: Vec<String>,
}

/// PUT /api/v1/admin/federation/cert — inbound propagation switch + trust list (全量替换).
pub async fn put_cert_settings(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CertSettingsReq>,
) -> Response {
    let list: Vec<String> = req
        .trust_list
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 80)
        .take(256)
        .collect();
    let res = state
        .db_call({
            let (enabled, list) = (req.enabled, list.clone());
            move |db| {
                crate::service::cert_relay::set_cert_relay_in(db, enabled)?;
                crate::service::cert_relay::set_trust_list(db, &list)
            }
        })
        .await;
    match res {
        Ok(()) => {
            audit(
                &state,
                &claims,
                &ip,
                "federation.cert_settings",
                None,
                &format!("enabled={} trust={}", req.enabled, list.len()),
            )
            .await;
            ok(json!({ "enabled": req.enabled, "trust_list": list }))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

/// GET /api/v1/admin/federation/receipts — topology-visibility receipts (谁被披露给了谁) for
/// the topo view; plus the per-holder aggregate (domain tier reads this only).
pub async fn receipts(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    let rows = state
        .db_call(|db| db.list_grant_receipts())
        .await
        .unwrap_or_default();
    let labels: std::collections::HashMap<String, String> = state
        .db_call(|db| {
            Ok(db
                .list_delegated_tokens()?
                .into_iter()
                .map(|t| (t.token_hash, t.label))
                .collect())
        })
        .await
        .unwrap_or_default();
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "artifact": labels.get(&r.artifact_ref).cloned().unwrap_or_else(|| r.artifact_ref[..12.min(r.artifact_ref.len())].to_string()),
                "holder": r.holder,
                "lineage": r.lineage,
                "visibility": r.visibility,
                "state": r.state,
                "created_at": r.created_at,
            })
        })
        .collect();
    ok(json!({ "items": items }))
}
