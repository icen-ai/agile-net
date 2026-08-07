//! Relay token API handlers (see the relay-tokens section of docs/api/node.md)
//!
//! Tokens are server-generated (`psk_` + 48 chars); the DB stores only the SHA-256 hash
//! and prefix, and the full token is returned only once at creation.

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, ok_created};
use crate::db::{generate_relay_token, sha256_hex};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(default)]
    pub remark: String,
    /// Suggested self-declared name for the consuming peer, prefilled into the share link's
    /// myname word (node.md M3-T6 naming triplet; link-only, not stored)
    #[serde(default)]
    pub my_name: String,
    /// Allow this fan-in relay to manage the node (default off)
    #[serde(default)]
    pub expose_control: bool,
    /// Admin grant scope: ro / rules / full
    #[serde(default = "default_scope")]
    pub control_scope: String,
    /// ACL group (absent/null = unrestricted, allow all)
    #[serde(default)]
    pub group_id: Option<String>,
    /// Bandwidth quota (KB/s; absent/null = unlimited; >0 takes effect, <=0 invalid)
    #[serde(default)]
    pub rate_limit_kbps: Option<i64>,
    /// Token lifecycle (optional): validity window (RFC3339 or YYYY-MM-DDTHH:MM; empty = never)
    #[serde(default)]
    pub expires_at: String,
    /// Token lifecycle (optional): max successful fan-in auths (0/absent = unlimited)
    #[serde(default)]
    pub max_uses: Option<i64>,
}

fn default_scope() -> String {
    "full".into()
}

fn valid_scope(scope: &str) -> bool {
    matches!(scope, "ro" | "rules" | "full")
}

/// Quota validation: >0 or absent is valid; <=0 rejected (the DB layer has a normalizing backstop).
fn valid_rate_limit(rate_limit_kbps: Option<i64>) -> bool {
    rate_limit_kbps.is_none_or(|v| v > 0)
}

pub async fn create_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateTokenRequest>,
) -> Response {
    if req.remark.len() > 256 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "remark too long (max 256)",
        );
    }
    if req.my_name.chars().count() > 64 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "my_name too long (max 64)",
        );
    }
    if !valid_scope(&req.control_scope) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "control_scope must be one of ro/rules/full",
        );
    }
    if !valid_rate_limit(req.rate_limit_kbps) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "rate_limit_kbps must be positive",
        );
    }
    // token lifecycle (optional): normalize the expiry; reject a past window at creation
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
    if req.max_uses.is_some_and(|v| v <= 0) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "max_uses must be a positive integer",
        );
    }
    // ACL group set (comma-separated multi-group): each member must exist; federation P3:
    // e2e_required groups hang only on delegated tokens
    if let Some(csv) = &req.group_id {
        for gid in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let probe = gid.to_string();
            let group = state
                .db_call(move |db| db.get_group(&probe))
                .await
                .unwrap_or(None);
            let Some(g) = group else {
                return err(
                    StatusCode::NOT_FOUND,
                    codes::NOT_FOUND,
                    format!("group not found: {gid}"),
                );
            };
            if let Some(r) = super::groups::reject_e2e_group(&g) {
                return r;
            }
        }
    }

    let token = generate_relay_token();
    let token_hash = sha256_hex(token.as_bytes());
    let prefix = format!("{}****", &token[..8]);

    let params = (
        token_hash,
        prefix.clone(),
        req.remark.clone(),
        req.control_scope.clone(),
        req.group_id.clone(),
    );
    let (expose_control, rate_limit_kbps) = (req.expose_control, req.rate_limit_kbps);
    let created = state
        .db_call(move |db| {
            let (token_hash, prefix, remark, control_scope, group_id) = params;
            db.create_relay_token_with_quota(
                &token_hash,
                &prefix,
                &remark,
                expose_control,
                &control_scope,
                group_id.as_deref(),
                rate_limit_kbps,
            )
        })
        .await;
    match created {
        Ok(record) => {
            audit(
                &state,
                &claims,
                &ip,
                "relay_token.create",
                Some(&record.id),
                &req.remark,
            )
            .await;
            // token lifecycle (optional window)
            if expires_at.is_some() || req.max_uses.is_some() {
                let (rid, exp, mu) = (record.id.clone(), expires_at.clone(), req.max_uses);
                if let Err(e) = state
                    .db_call(move |db| db.set_relay_token_lifecycle(&rid, exp.as_deref(), mu))
                    .await
                {
                    return err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        codes::INTERNAL,
                        e.to_string(),
                    );
                }
                audit(
                    &state,
                    &claims,
                    &ip,
                    "relay_token.set_lifecycle",
                    Some(&record.id),
                    &format!(
                        "expires_at={} max_uses={}",
                        expires_at.as_deref().unwrap_or(""),
                        req.max_uses.map(|v| v.to_string()).unwrap_or_default()
                    ),
                )
                .await;
            }
            if req.expose_control {
                audit(
                    &state,
                    &claims,
                    &ip,
                    "relay_token.expose_control",
                    Some(&record.id),
                    &format!("on (scope={})", req.control_scope),
                )
                .await;
            }
            if let Some(gid) = &req.group_id {
                audit(
                    &state,
                    &claims,
                    &ip,
                    "relay_token.set_group",
                    Some(&record.id),
                    &format!("group_id={gid}"),
                )
                .await;
            }
            if let Some(kbps) = req.rate_limit_kbps {
                audit(
                    &state,
                    &claims,
                    &ip,
                    "relay_token.set_rate_limit",
                    Some(&record.id),
                    &format!("rate_limit_kbps={kbps}"),
                )
                .await;
            }
            // Federation P1: one-click import link (anet://fanout; address priority: declared
            // public identity > listener address) + endpoint candidates for the share dialog
            let relay_addr = state.public_relay_addr().await;
            let sni = state.runtime.relay_sni.clone().unwrap_or_default();
            let share_url = agile_net_core::link::build_fanout_url(
                &relay_addr,
                &token,
                &sni,
                state.runtime.cert_fingerprint.as_deref(),
                // M3-T6: the issuer-suggested "my name" rides the link's myname word
                Some(req.my_name.trim()).filter(|s| !s.is_empty()),
            );
            let (_, relay_port) = state.public_tunnel_endpoint().await;
            let public = state.declared_relay_addr().await;
            let endpoints = state.share_endpoints(relay_port, public).await;
            ok_created(json!({
                "id": record.id,
                "token": token,
                "token_prefix": prefix,
                "remark": record.remark,
                "expose_control": record.expose_control,
                "control_scope": record.control_scope,
                "group_id": record.group_id,
                "rate_limit_kbps": record.rate_limit_kbps,
                "expires_at": expires_at,
                "max_uses": req.max_uses,
                "created_at": record.created_at,
                "share_url": share_url,
                "endpoints": endpoints,
            }))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct UpdateTokenRequest {
    pub expose_control: bool,
    #[serde(default = "default_scope")]
    pub control_scope: String,
    /// Local display name of the consuming peer (tri-state: absent = unchanged, string = set;
    /// this is the issuer-assigned name shown in fan-in lists)
    #[serde(default)]
    pub remark: Option<String>,
    /// ACL group change tri-state: absent = unchanged, null = unrestricted, string = mount to that group.
    /// (serde maps an explicit null on Option to None too; deserialize_some distinguishes absent from cleared)
    #[serde(default, deserialize_with = "deserialize_some")]
    pub group_id: Option<serde_json::Value>,
    /// Quota change tri-state: absent = unchanged, null = unlimited, positive integer = set to that value (KB/s).
    #[serde(default, deserialize_with = "deserialize_some")]
    pub rate_limit_kbps: Option<serde_json::Value>,
    /// Lifecycle window tri-state: absent = unchanged, null = never expires, string = new expiry.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub expires_at: Option<serde_json::Value>,
    /// Usage cap tri-state: absent = unchanged, null = unlimited, positive integer = set.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub max_uses: Option<serde_json::Value>,
}

/// Wraps the field in Some when present (including explicit null); only absent falls back to default None.
fn deserialize_some<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(de).map(Some)
}

/// Expose-control-plane switch update (default off; every change audited as relay_token.expose_control).
pub async fn update_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<UpdateTokenRequest>,
) -> Response {
    if !valid_scope(&req.control_scope) {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "control_scope must be one of ro/rules/full",
        );
    }
    let tid = id.clone();
    let Some(existing) = state
        .db_call(move |db| {
            Ok(db
                .list_relay_tokens()
                .ok()
                .and_then(|items| items.into_iter().find(|t| t.id == tid)))
        })
        .await
        .unwrap_or(None)
    else {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "relay token not found",
        );
    };
    // Parse ACL group input: null = unrestricted, string = mount to that group (any other type 400)
    let new_group: Option<Option<String>> = match &req.group_id {
        None => None,
        Some(serde_json::Value::Null) => Some(None),
        Some(serde_json::Value::String(s)) => Some(Some(s.clone())),
        Some(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "group_id must be string or null",
            );
        }
    };
    if let Some(Some(csv)) = &new_group {
        // ACL group set (comma-separated multi-group): each member must exist; federation P3:
        // e2e_required groups hang only on delegated tokens
        for gid in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let probe = gid.to_string();
            let group = state
                .db_call(move |db| db.get_group(&probe))
                .await
                .unwrap_or(None);
            let Some(g) = group else {
                return err(
                    StatusCode::NOT_FOUND,
                    codes::NOT_FOUND,
                    format!("group not found: {gid}"),
                );
            };
            if let Some(r) = super::groups::reject_e2e_group(&g) {
                return r;
            }
        }
    }
    // Parse quota input: null = unlimited, positive integer = set to that value (other types/<=0 all 400)
    let new_rate_limit: Option<Option<i64>> = match &req.rate_limit_kbps {
        None => None,
        Some(serde_json::Value::Null) => Some(None),
        Some(serde_json::Value::Number(n)) => match n.as_i64() {
            Some(v) if v > 0 => Some(Some(v)),
            _ => {
                return err(
                    StatusCode::BAD_REQUEST,
                    codes::VALIDATION_FAILED,
                    "rate_limit_kbps must be positive",
                );
            }
        },
        Some(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "rate_limit_kbps must be a positive integer or null",
            );
        }
    };
    let (tid, scope) = (id.clone(), req.control_scope.clone());
    let expose_control = req.expose_control;
    if let Err(e) = state
        .db_call(move |db| db.update_relay_token_control(&tid, expose_control, &scope))
        .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    if existing.expose_control != req.expose_control || existing.control_scope != req.control_scope
    {
        audit(
            &state,
            &claims,
            &ip,
            "relay_token.expose_control",
            Some(&id),
            &format!(
                "{} (scope={})",
                if req.expose_control { "on" } else { "off" },
                req.control_scope
            ),
        )
        .await;
    }

    // Local display name (remark) change: absent = unchanged
    if let Some(remark) = &req.remark {
        let remark = remark.trim();
        if remark.len() > 256 {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "remark too long (max 256)",
            );
        }
        if remark != existing.remark {
            let (tid, r) = (id.clone(), remark.to_string());
            if let Err(e) = state
                .db_call(move |db| db.set_relay_token_remark(&tid, &r))
                .await
            {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    codes::INTERNAL,
                    e.to_string(),
                );
            }
            audit(&state, &claims, &ip, "relay_token.set_remark", Some(&id), remark).await;
        }
    }

    // ACL group change: kick sessions by token hash after the DB write; online peers reconnect under the new group (takes effect at once)
    let mut group_id_resp = existing.group_id.clone();
    if let Some(new_group) = new_group
        && new_group != existing.group_id
    {
        // DB write + hash fetch merged into one blocking task
        let (tid, gid) = (id.clone(), new_group.clone());
        let token_hash = match state
            .db_call(move |db| {
                db.set_relay_token_group(&tid, gid.as_deref())?;
                Ok(db.get_relay_token_hash(&tid).unwrap_or(None))
            })
            .await
        {
            Ok(h) => h,
            Err(e) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    codes::INTERNAL,
                    e.to_string(),
                );
            }
        };
        if let (Some(listener), Some(hash)) = (&state.runtime.listener, token_hash)
            && let Some(node_id) = listener
                .disconnect_by_token_hash(&hash, agile_net_core::proto::message::reason::KICKED, "")
                .await
        {
            tracing::info!(node = %node_id, "relay token group changed, peer kicked");
        }
        audit(
            &state,
            &claims,
            &ip,
            "relay_token.set_group",
            Some(&id),
            &match &new_group {
                Some(gid) => format!("group_id={gid}"),
                None => "group cleared (unrestricted)".to_string(),
            },
        )
        .await;
        group_id_resp = new_group;
    }

    // Quota change: effective on DB write (new sessions limited to the new value; existing sessions await the core rate-limit hook joining the reconnect policy)
    let mut rate_limit_resp = existing.rate_limit_kbps;
    if let Some(new_rate_limit) = new_rate_limit
        && new_rate_limit != existing.rate_limit_kbps
    {
        let tid = id.clone();
        if let Err(e) = state
            .db_call(move |db| db.set_relay_token_rate_limit(&tid, new_rate_limit))
            .await
        {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
        audit(
            &state,
            &claims,
            &ip,
            "relay_token.set_rate_limit",
            Some(&id),
            &match new_rate_limit {
                Some(kbps) => format!("rate_limit_kbps={kbps}"),
                None => "rate_limit cleared (unlimited)".to_string(),
            },
        )
        .await;
        rate_limit_resp = new_rate_limit;
    }

    // Lifecycle window change (tri-state per field; merged with the current values into one write).
    // New sessions authenticate only while the window is alive (the data-plane check treats an
    // expired/exhausted token as unknown); existing sessions are not kicked mid-flight.
    let mut lifecycle_touched = false;
    let mut expires_resp = existing.expires_at.clone();
    let mut max_uses_resp = existing.max_uses;
    match &req.expires_at {
        None => {}
        Some(serde_json::Value::Null) => {
            expires_resp = None;
            lifecycle_touched = true;
        }
        Some(serde_json::Value::String(s)) => match crate::db::normalize_expiry(s) {
            Ok(v) => {
                expires_resp = Some(v);
                lifecycle_touched = true;
            }
            Err(msg) => return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
        },
        Some(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "expires_at must be a datetime string or null",
            );
        }
    }
    match &req.max_uses {
        None => {}
        Some(serde_json::Value::Null) => {
            max_uses_resp = None;
            lifecycle_touched = true;
        }
        Some(serde_json::Value::Number(n)) => match n.as_i64() {
            Some(v) if v > 0 => {
                max_uses_resp = Some(v);
                lifecycle_touched = true;
            }
            _ => {
                return err(
                    StatusCode::BAD_REQUEST,
                    codes::VALIDATION_FAILED,
                    "max_uses must be a positive integer or null",
                );
            }
        },
        Some(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "max_uses must be a positive integer or null",
            );
        }
    }
    if lifecycle_touched {
        let (tid, exp, mu) = (id.clone(), expires_resp.clone(), max_uses_resp);
        if let Err(e) = state
            .db_call(move |db| db.set_relay_token_lifecycle(&tid, exp.as_deref(), mu))
            .await
        {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
        audit(
            &state,
            &claims,
            &ip,
            "relay_token.set_lifecycle",
            Some(&id),
            &format!(
                "expires_at={} max_uses={}",
                expires_resp.as_deref().unwrap_or("∅"),
                max_uses_resp
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "∅".into())
            ),
        )
        .await;
    }

    ok(json!({
        "id": id,
        "expose_control": req.expose_control,
        "control_scope": req.control_scope,
        "group_id": group_id_resp,
        "rate_limit_kbps": rate_limit_resp,
        "expires_at": expires_resp,
        "max_uses": max_uses_resp,
    }))
}

pub async fn list_tokens(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    match state
        .db_call(|db| {
            let items = db.list_relay_tokens()?;
            // the session inventory joins on token_hash (node.md M3-T1; the hash is not a secret)
            let hashes: Vec<Option<String>> = items
                .iter()
                .map(|t| db.get_relay_token_hash(&t.id).unwrap_or(None))
                .collect();
            Ok(items.into_iter().zip(hashes).collect::<Vec<_>>())
        })
        .await
    {
        Ok(items) => {
            // fold the computed lifecycle status + token hash into each serialized record
            let items: Vec<serde_json::Value> = items
                .into_iter()
                .map(|(t, hash)| {
                    let mut v = serde_json::to_value(&t).unwrap_or_default();
                    v["lifecycle"] = serde_json::Value::String(
                        super::lifecycle_status(t.expires_at.as_deref(), t.max_uses, t.used_count)
                            .into(),
                    );
                    v["token_hash"] = hash.map(serde_json::Value::String).unwrap_or(serde_json::Value::Null);
                    v
                })
                .collect();
            ok(json!({ "items": items }))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

pub async fn delete_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    // Fetch the hash, then delete, merged into one blocking task
    // (delete side effect: online downstream nodes using this token are kicked at once)
    let tid = id.clone();
    match state
        .db_call(move |db| {
            let hash = db.get_relay_token_hash(&id).unwrap_or(None);
            db.delete_relay_token(&id).map(|_| hash)
        })
        .await
    {
        Ok(token_hash) => {
            if let (Some(listener), Some(hash)) = (&state.runtime.listener, token_hash)
                && let Some(node_id) = listener
                    .disconnect_by_token_hash(&hash, agile_net_core::proto::message::reason::REVOKED_BY_ADMIN, "")
                    .await
            {
                tracing::info!(node = %node_id, "relay token revoked, peer kicked");
            }
            audit(&state, &claims, &ip, "relay_token.delete", Some(&tid), "").await;
            ok(json!(null))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}
