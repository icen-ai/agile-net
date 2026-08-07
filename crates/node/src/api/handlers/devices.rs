//! Device registry APIs (node.md M3-T2/T5): the device list, the identity card data, and the
//! certification state machine (certify / rebind / revoke) with live-session enforcement.

use agile_net_core::proto::message::reason;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok};

#[derive(Deserialize)]
pub struct DeviceQuery {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    q: Option<String>,
}

/// GET /api/v1/admin/devices — device list (state/q filters), each row folded with its live
/// session count and online flag.
pub async fn list_devices(AdminAuth(_): AdminAuth, State(state): State<ApiState>, Query(q): Query<DeviceQuery>) -> Response {
    let rows = state
        .db_call({
            let (st, q) = (q.state.clone(), q.q.clone());
            move |db| db.list_devices(st.as_deref(), q.as_deref())
        })
        .await
        .unwrap_or_default();
    let online: std::collections::HashMap<String, usize> = match &state.runtime.listener {
        Some(l) => {
            let mut m = std::collections::HashMap::new();
            for s in l.sessions_detail() {
                *m.entry(s.meta.device_fp).or_insert(0) += 1;
            }
            m
        }
        None => Default::default(),
    };
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|d| {
            let live = online.get(&d.device_fp).copied().unwrap_or(0);
            json!({
                "device_fp": d.device_fp,
                "short_fp": &d.device_fp[..12.min(d.device_fp.len())],
                "subject": d.subject,
                "my_name": d.my_name,
                "remark": d.remark,
                "state": d.state,
                "certified_by": d.certified_by,
                "certified_at": d.certified_at,
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
                "bytes_up": d.bytes_up,
                "bytes_down": d.bytes_down,
                "online": live > 0,
                "sessions": live,
            })
        })
        .collect();
    ok(json!({ "items": items }))
}

/// GET /api/v1/admin/devices/{fp} — identity card data: registry row + OpenSSH pubkey + live
/// sessions + the credential labels this device has used.
pub async fn get_device(AdminAuth(_): AdminAuth, State(state): State<ApiState>, Path(fp): Path<String>) -> Response {
    let rec = state
        .db_call({
            let fp = fp.clone();
            move |db| db.get_device(&fp)
        })
        .await;
    let Ok(Some(d)) = rec else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "device not found");
    };
    let sessions: Vec<serde_json::Value> = state
        .runtime
        .listener
        .as_ref()
        .map(|l| {
            l.sessions_detail()
                .into_iter()
                .filter(|s| s.meta.device_fp == d.device_fp)
                .map(|s| {
                    json!({
                        "session_id": s.meta.session_id,
                        "session_key": s.meta.session_key,
                        "ip": s.meta.peer_ip,
                        "online_secs": s.meta.connected_at.elapsed().as_secs(),
                        "bytes_up": s.bytes_up,
                        "bytes_down": s.bytes_down,
                        "channels": s.channels,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    // OpenSSH-format public key (display/copy only)
    let openssh = agile_net_core::util::base64_decode(&d.pubkey)
        .map(|raw| agile_net_core::device::openssh_line(&raw, ""))
        .unwrap_or_default();
    ok(json!({
        "device_fp": d.device_fp,
        "pubkey": d.pubkey,
        "openssh": openssh,
        "token_hash": d.token_hash,
        "subject": d.subject,
        "my_name": d.my_name,
        "remark": d.remark,
        "state": d.state,
        "certified_by": d.certified_by,
        "certified_at": d.certified_at,
        "first_seen": d.first_seen,
        "last_seen": d.last_seen,
        "bytes_up": d.bytes_up,
        "bytes_down": d.bytes_down,
        "sessions": sessions,
    }))
}

#[derive(Deserialize)]
pub struct CertifyReq {
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub remark: String,
}

/// POST /api/v1/admin/devices/{fp}/certify — certify onto a logical holder (加绑 when the
/// holder already has devices). Live pending sessions unblock within the gate TTL.
pub async fn certify_device(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(fp): Path<String>,
    Json(req): Json<CertifyReq>,
) -> Response {
    if req.subject.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "subject (逻辑持有者) required");
    }
    let (subject, remark) = (req.subject.trim().to_string(), req.remark.trim().to_string());
    let res = state
        .db_call({
            let (fp, s, r) = (fp.clone(), subject.clone(), remark.clone());
            move |db| db.certify_device(&fp, &s, &r, "")
        })
        .await;
    match res {
        Ok(()) => {
            if let Some(g) = &state.runtime.device_gate {
                g.invalidate(&fp);
            }
            // settle any pending certification approval for this device
            let _ = state
                .db_call({
                    let fp = fp.clone();
                    move |db| {
                        if let Ok(pending) = db.list_approvals(Some("pending")) {
                            for a in pending.into_iter().filter(|a| {
                                a.r#type == crate::service::approvals::DEVICE_CERTIFY && a.object_ref == fp
                            }) {
                                let _ = db.decide_approval(&a.id, true, "admin");
                            }
                        }
                        Ok(())
                    }
                })
                .await;
            audit(&state, &claims, &ip, "device.certify", Some(&fp), &format!("{subject} / {remark}")).await;
            ok(json!({ "certified": true }))
        }
        Err(e) => err(StatusCode::NOT_FOUND, codes::NOT_FOUND, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct RevokeReq {
    #[serde(default)]
    pub message: String,
}

/// POST /api/v1/admin/devices/{fp}/revoke — terminal revocation: the registry row is barred
/// forever, live sessions are kicked with device_revoked + the one-time message.
pub async fn revoke_device(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(fp): Path<String>,
    Json(req): Json<RevokeReq>,
) -> Response {
    let res = state
        .db_call({
            let fp = fp.clone();
            move |db| db.revoke_device(&fp)
        })
        .await;
    match res {
        Ok(()) => {
            if let Some(g) = &state.runtime.device_gate {
                g.invalidate(&fp);
            }
            let kicked = match &state.runtime.listener {
                Some(l) => l.disconnect_device(&fp, reason::DEVICE_REVOKED, &req.message).await,
                None => 0,
            };
            audit(&state, &claims, &ip, "device.revoke", Some(&fp), &format!("kicked={kicked}")).await;
            ok(json!({ "revoked": true, "kicked": kicked }))
        }
        Err(e) => err(StatusCode::NOT_FOUND, codes::NOT_FOUND, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct RebindReq {
    pub old_fp: String,
    pub new_fp: String,
    #[serde(default)]
    pub message: String,
}

/// POST /api/v1/admin/devices/rebind — 换机一键三连: certify the new device onto the old one's
/// holder (stats migrate), revoke the old (terminal), kick the old with device_replaced.
pub async fn rebind_device(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RebindReq>,
) -> Response {
    if req.old_fp == req.new_fp {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "same device");
    }
    let res = state
        .db_call({
            let (o, n) = (req.old_fp.clone(), req.new_fp.clone());
            move |db| db.rebind_device(&o, &n)
        })
        .await;
    match res {
        Ok(()) => {
            if let Some(g) = &state.runtime.device_gate {
                g.invalidate(&req.old_fp);
                g.invalidate(&req.new_fp);
            }
            let kicked = match &state.runtime.listener {
                Some(l) => {
                    l.disconnect_device(&req.old_fp, reason::DEVICE_REPLACED, &req.message)
                        .await
                }
                None => 0,
            };
            audit(
                &state,
                &claims,
                &ip,
                "device.rebind",
                Some(&req.new_fp),
                &format!("from {} kicked={kicked}", &req.old_fp[..12.min(req.old_fp.len())]),
            )
            .await;
            ok(json!({ "rebound": true, "kicked": kicked }))
        }
        Err(e) => err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, e.to_string()),
    }
}

/// GET /api/v1/admin/devices/policy — the pending-device data-plane policy.
pub async fn get_policy(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    let allow = match &state.runtime.device_gate {
        Some(g) => g.is_allow_pending(),
        // no listener (API-only): node_config is the source of truth
        None => state
            .db_call(|db| db.get_config("device_pending_policy"))
            .await
            .ok()
            .flatten()
            .map(|v| v == "allow")
            .unwrap_or(false),
    };
    ok(json!({ "policy": if allow { "allow" } else { "block" } }))
}

#[derive(Deserialize)]
pub struct PolicyReq {
    pub policy: String,
}

/// PUT /api/v1/admin/devices/policy — 'block' (default: pending devices wait for approval) or
/// 'allow' (pending devices pass with a gray flag).
pub async fn put_policy(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<PolicyReq>,
) -> Response {
    let allow = match req.policy.as_str() {
        "block" => false,
        "allow" => true,
        _ => return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "policy must be block|allow"),
    };
    let _ = state
        .db_call(move |db| db.set_config("device_pending_policy", req.policy.as_str()))
        .await;
    if let Some(g) = &state.runtime.device_gate {
        g.set_allow_pending(allow);
    }
    audit(&state, &claims, &ip, "device.policy", None, if allow { "allow" } else { "block" }).await;
    ok(json!({ "policy": if allow { "allow" } else { "block" } }))
}
