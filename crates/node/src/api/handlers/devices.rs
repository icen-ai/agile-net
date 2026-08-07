//! Device registry APIs (node.md M3-T2/T5): the device list, the identity card data, and the
//! certification state machine (certify / rebind / revoke) with live-session enforcement.

use agile_net_core::proto::message::reason;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Response,
};
use chrono::{Datelike, Timelike};
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
            // M6: propagate the fresh certification to opted-in upstreams
            state.runtime.connector_manager.broadcast_cert_records().await;
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
            state.runtime.connector_manager.broadcast_cert_records().await;
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
            state.runtime.connector_manager.broadcast_cert_records().await;
            ok(json!({ "rebound": true, "kicked": kicked }))
        }
        Err(e) => err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct TrafficQuery {
    #[serde(default)]
    range: Option<String>,
}

/// Parse a ledger timestamp ("%Y-%m-%d %H:%M:%S", UTC) to epoch seconds.
fn ledger_ts(s: &str) -> Option<i64> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|d| d.and_utc().timestamp())
}

/// GET /api/v1/admin/devices/{fp}/traffic?range=24h|7d|30d — bucketed up/down series (M5-T4).
pub async fn device_traffic(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Path(fp): Path<String>,
    Query(q): Query<TrafficQuery>,
) -> Response {
    let range = q.range.as_deref().unwrap_or("24h");
    let (days, bucket_secs) = match range {
        "7d" => (7, 3600i64),
        "30d" => (30, 86400),
        _ => (1, 300),
    };
    let since = (chrono::Utc::now() - chrono::Duration::days(days)).format("%Y-%m-%d %H:%M:%S").to_string();
    let rows = state
        .db_call({
            let fp = fp.clone();
            move |db| db.device_traffic_rows(&fp, &since)
        })
        .await
        .unwrap_or_default();
    // bucket in Rust: ts/bucket_secs floored, up = received from device (bytes_in)
    let mut buckets: std::collections::BTreeMap<i64, (i64, i64)> = std::collections::BTreeMap::new();
    for (ts, bin, bout) in rows {
        let Some(t) = ledger_ts(&ts) else { continue };
        let b = t / bucket_secs * bucket_secs;
        let e = buckets.entry(b).or_default();
        e.0 += bin;
        e.1 += bout;
    }
    let series: Vec<serde_json::Value> = buckets
        .into_iter()
        .map(|(t, (up, down))| json!({ "ts": t, "up": up, "down": down }))
        .collect();
    ok(json!({ "range": range, "bucket_secs": bucket_secs, "series": series }))
}

/// GET /api/v1/admin/devices/{fp}/activity — 7x24 activity heatmap (session count + bytes per
/// weekday/hour cell, last 30 days; M5 profile-page heat + M6 anomaly heuristics data source).
pub async fn device_activity(AdminAuth(_): AdminAuth, State(state): State<ApiState>, Path(fp): Path<String>) -> Response {
    let since = (chrono::Utc::now() - chrono::Duration::days(30)).format("%Y-%m-%d %H:%M:%S").to_string();
    let rows = state
        .db_call({
            let fp = fp.clone();
            move |db| db.device_traffic_rows(&fp, &since)
        })
        .await
        .unwrap_or_default();
    let mut cells = vec![vec![(0i64, 0i64); 24]; 7];
    for (ts, bin, bout) in rows {
        let Some(t) = ledger_ts(&ts) else { continue };
        let dt = chrono::DateTime::from_timestamp(t, 0).unwrap_or_default();
        let wd = dt.weekday().num_days_from_sunday() as usize;
        let hr = dt.hour() as usize;
        cells[wd][hr].0 += 1;
        cells[wd][hr].1 += bin + bout;
    }
    let cells: Vec<serde_json::Value> = cells
        .into_iter()
        .enumerate()
        .map(|(wd, hours)| json!({ "weekday": wd, "hours": hours.iter().map(|(n, b)| json!({ "sessions": n, "bytes": b })).collect::<Vec<_>>() }))
        .collect();
    ok(json!({ "days": 30, "cells": cells }))
}

/// GET /api/v1/admin/devices/{fp}/sessions — closed-session history (entry/IP/duration/bytes/
/// close_reason; the "被管理员断开" visibility of the session tab).
pub async fn device_sessions(AdminAuth(_): AdminAuth, State(state): State<ApiState>, Path(fp): Path<String>) -> Response {
    let rows = state
        .db_call(move |db| db.device_sessions(&fp, 200))
        .await
        .unwrap_or_default();
    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "entry": r.entry,
                "ip": r.ip,
                "started_at": r.started_at,
                "ended_at": r.ended_at,
                "bytes_up": r.bytes_in,
                "bytes_down": r.bytes_out,
                "close_reason": r.close_reason,
            })
        })
        .collect();
    ok(json!({ "items": items }))
}

/// GET /api/v1/admin/devices/{fp}/events — merged vertical timeline (approvals + audit hits
/// mentioning this fingerprint), newest first (device profile events tab).
pub async fn device_events(AdminAuth(_): AdminAuth, State(state): State<ApiState>, Path(fp): Path<String>) -> Response {
    let items = state
        .db_call({
            let fp = fp.clone();
            move |db| {
                let mut out: Vec<serde_json::Value> = Vec::new();
                for a in db.list_approvals(None)? {
                    if a.object_ref == fp
                        || a.requester == fp
                        || a.detail.contains(&fp)
                    {
                        out.push(json!({
                            "ts": a.decided_at.clone().unwrap_or(a.created_at.clone()),
                            "kind": "approval",
                            "title": format!("{} → {}", a.r#type, a.state),
                            "detail": a.detail,
                        }));
                    }
                }
                // audit hits (certify/revoke/rebind/kick actions carry the fp as target/detail)
                let short = &fp[..12.min(fp.len())];
                for e in db.list_audit_logs(1, 300, None, None)?.0 {
                    let hit = e.target.as_deref() == Some(fp.as_str())
                        || e.detail.as_deref().map(|d| d.contains(&fp) || d.contains(short)).unwrap_or(false);
                    if hit {
                        out.push(json!({
                            "ts": e.created_at,
                            "kind": "audit",
                            "title": format!("{} ({})", e.action, e.operator),
                            "detail": e.detail.unwrap_or_default(),
                        }));
                    }
                }
                out.sort_by(|a, b| b["ts"].as_str().cmp(&a["ts"].as_str()));
                out.truncate(100);
                Ok(out)
            }
        })
        .await;
    match items {
        Ok(items) => ok(json!({ "items": items })),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
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
