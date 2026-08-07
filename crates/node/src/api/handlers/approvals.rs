//! Approval center APIs (node.md M3-T4): pluggable human-adjudication events. Actions:
//! approve (optionally restating subject/remark) / reject / reject-and-revoke — all audited,
//! all pushing their side effects (certify / rebind / revoke + live kicks) immediately.

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
pub struct ApprovalQuery {
    #[serde(default)]
    state: Option<String>,
}

/// GET /api/v1/admin/approvals — items (default: all, pending first), messages inlined.
pub async fn list_approvals(AdminAuth(_): AdminAuth, State(state): State<ApiState>, Query(q): Query<ApprovalQuery>) -> Response {
    let items = state
        .db_call({
            let st = q.state.clone();
            move |db| {
                let list = db.list_approvals(st.as_deref())?;
                let mut out = Vec::new();
                for a in list {
                    let messages = db.approval_messages(&a.id).unwrap_or_default();
                    out.push((a, messages));
                }
                Ok(out)
            }
        })
        .await;
    match items {
        Ok(items) => {
            let items: Vec<serde_json::Value> = items
                .into_iter()
                .map(|(a, msgs)| {
                    json!({
                        "id": a.id,
                        "type": a.r#type,
                        "state": a.state,
                        "object_ref": a.object_ref,
                        "requester": a.requester,
                        "detail": serde_json::from_str::<serde_json::Value>(&a.detail).unwrap_or(json!({})),
                        "decided_by": a.decided_by,
                        "decided_at": a.decided_at,
                        "created_at": a.created_at,
                        "messages": msgs,
                    })
                })
                .collect();
            ok(json!({ "items": items }))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct DecideReq {
    /// approve | reject | reject_revoke
    pub action: String,
    /// approve: holder subject (device_certify) — may restate the requested one
    #[serde(default)]
    pub subject: String,
    /// approve: capsule remark
    #[serde(default)]
    pub remark: String,
    /// reject/reject_revoke: final one-time notice to the applicant (immutable once sent)
    #[serde(default)]
    pub notice: String,
}

/// POST /api/v1/admin/approvals/{id}/decide — adjudicate. Side effects by type:
/// device_certify approve -> certify onto the holder; device_rebind approve -> rebind;
/// reject_revoke -> revoke + kick. Reject kicks the pending session with the notice.
pub async fn decide_approval(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<DecideReq>,
) -> Response {
    let item = state
        .db_call({
            let id = id.clone();
            move |db| Ok(db.list_approvals(None)?.into_iter().find(|a| a.id == id))
        })
        .await;
    let Ok(Some(item)) = item else {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "approval not found");
    };
    if item.state != "pending" && req.action != "reopen" {
        return err(StatusCode::CONFLICT, codes::VALIDATION_FAILED, "already decided");
    }

    let fp = item.object_ref.clone();
    match req.action.as_str() {
        // rejected → pending (accidental-reject recovery); approved items and revoked devices
        // stay pinned (revocation is terminal — the consumer re-connects and goes through rebind)
        "reopen" => {
            if item.state != "rejected" {
                return err(StatusCode::CONFLICT, codes::VALIDATION_FAILED, "仅被拒绝的审批可重新打开");
            }
            let kind = item.r#type.clone();
            let res = state
                .db_call({
                    let fp = fp.clone();
                    move |db| {
                        if matches!(
                            item.r#type.as_str(),
                            crate::service::approvals::DEVICE_CERTIFY | crate::service::approvals::DEVICE_REBIND
                        ) && let Ok(Some(d)) = db.get_device(&fp)
                            && d.state == "revoked"
                        {
                            return Ok(Err("设备已吊销（终态）——请让消费者重新接入并走换绑".to_string()));
                        }
                        db.reopen_approval(&item.id)?;
                        Ok(Ok(()))
                    }
                })
                .await;
            match res {
                Ok(Ok(())) => {
                    audit(&state, &claims, &ip, "approval.reopen", Some(&id), &kind).await;
                    ok(json!({ "state": "pending" }))
                }
                Ok(Err(msg)) => err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
                Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
            }
        }
        "approve" => {
            let side = state
                .db_call({
                    let (fp, item, subject, remark) =
                        (fp.clone(), item.clone(), req.subject.trim().to_string(), req.remark.trim().to_string());
                    let decided_by = claims.username.clone();
                    move |db| {
                        match item.r#type.as_str() {
                            crate::service::approvals::DEVICE_CERTIFY => {
                                if subject.is_empty() {
                                    return Ok(Err("subject (逻辑持有者) required".to_string()));
                                }
                                if let Err(e) = db.certify_device(&fp, &subject, &remark, "") {
                                    // Heal approvals filed before the registry row existed (relay-entry
                                    // first sight): register the device, then certify once more.
                                    if matches!(e, agile_net_core::error::Error::NotFound(_)) {
                                        db.touch_device(&fp, "", "", "")?;
                                        db.certify_device(&fp, &subject, &remark, "")?;
                                    } else {
                                        return Err(e);
                                    }
                                }
                            }
                            crate::service::approvals::DEVICE_REBIND => {
                                let detail: serde_json::Value =
                                    serde_json::from_str(&item.detail).unwrap_or_default();
                                let new_fp = detail["new_fp"].as_str().unwrap_or("").to_string();
                                if new_fp.is_empty() {
                                    return Ok(Err("rebind detail missing new_fp".to_string()));
                                }
                                db.rebind_device(&fp, &new_fp)?;
                                return Ok(Ok(new_fp));
                            }
                            crate::service::approvals::REF_CERT_ADOPT => {
                                // reference certification adopted (M6): certify with origin lineage
                                crate::service::cert_relay::adopt_reference(db, &item.id)
                                    .map_err(agile_net_core::error::Error::Other)?;
                            }
                            // unknown types approve without data-plane side effects (pluggable;
                            // topo_approve takes effect at the next registration sync tick)
                            _ => {}
                        }
                        db.decide_approval(&item.id, true, &decided_by)?;
                        Ok(Ok(String::new()))
                    }
                })
                .await;
            match side {
                Ok(Ok(extra_fp)) => {
                    if let Some(g) = &state.runtime.device_gate {
                        g.invalidate(&fp);
                        if !extra_fp.is_empty() {
                            g.invalidate(&extra_fp);
                        }
                    }
                    // rebind: kick the old device with device_replaced
                    if !extra_fp.is_empty()
                        && let Some(l) = &state.runtime.listener
                    {
                        l.disconnect_device(&fp, reason::DEVICE_REPLACED, "").await;
                    }
                    audit(&state, &claims, &ip, "approval.approve", Some(&item.id), &item.r#type).await;
                    ok(json!({ "state": "approved" }))
                }
                Ok(Err(msg)) => err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
                Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
            }
        }
        "reject" | "reject_revoke" => {
            let revoke = req.action == "reject_revoke";
            let notice = req.notice.clone();
            let res = state
                .db_call({
                    let (id, fp, notice, decided_by) =
                        (item.id.clone(), fp.clone(), notice.clone(), claims.username.clone());
                    move |db| {
                        if !notice.is_empty() {
                            db.add_approval_message(&id, "notice", &notice)?;
                        }
                        if revoke {
                            // the one-time notice rides the device row (gate Deny / config pull deliver it)
                            db.revoke_device_with_notice(&fp, &notice)?;
                        } else if !notice.is_empty() {
                            // plain reject: device stays pending; store the note so the next gated
                            // open / config pull explains the rejection (relay-entry included)
                            db.set_device_notice(&fp, &notice)?;
                        }
                        db.decide_approval(&id, false, &decided_by)?;
                        Ok(())
                    }
                })
                .await;
            match res {
                Ok(()) => {
                    if let Some(g) = &state.runtime.device_gate {
                        g.invalidate(&fp);
                    }
                    // drop the pending/revoked session with the reason + one-time notice
                    if let Some(l) = &state.runtime.listener {
                        let rc = if revoke { reason::DEVICE_REVOKED } else { reason::KICKED };
                        l.disconnect_device(&fp, rc, &notice).await;
                    }
                    audit(
                        &state,
                        &claims,
                        &ip,
                        if revoke { "approval.reject_revoke" } else { "approval.reject" },
                        Some(&item.id),
                        &item.r#type,
                    )
                    .await;
                    ok(json!({ "state": "rejected", "revoked": revoke }))
                }
                Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
            }
        }
        _ => err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, "action must be approve|reject|reject_revoke"),
    }
}
