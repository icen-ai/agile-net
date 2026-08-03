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
    if let Some(gid) = &req.group_id {
        let probe = gid.clone();
        let exists = state
            .db_call(move |db| db.get_group(&probe))
            .await
            .unwrap_or(None)
            .is_some();
        if !exists {
            return err(
                StatusCode::NOT_FOUND,
                codes::NOT_FOUND,
                format!("group not found: {gid}"),
            );
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
            ok_created(json!({
                "id": record.id,
                "token": token,
                "token_prefix": prefix,
                "remark": record.remark,
                "expose_control": record.expose_control,
                "control_scope": record.control_scope,
                "group_id": record.group_id,
                "rate_limit_kbps": record.rate_limit_kbps,
                "created_at": record.created_at,
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
    /// ACL group change tri-state: absent = unchanged, null = unrestricted, string = mount to that group.
    /// (serde maps an explicit null on Option to None too; deserialize_some distinguishes absent from cleared)
    #[serde(default, deserialize_with = "deserialize_some")]
    pub group_id: Option<serde_json::Value>,
    /// Quota change tri-state: absent = unchanged, null = unlimited, positive integer = set to that value (KB/s).
    #[serde(default, deserialize_with = "deserialize_some")]
    pub rate_limit_kbps: Option<serde_json::Value>,
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
    if let Some(Some(gid)) = &new_group {
        let probe = gid.clone();
        let exists = state
            .db_call(move |db| db.get_group(&probe))
            .await
            .unwrap_or(None)
            .is_some();
        if !exists {
            return err(
                StatusCode::NOT_FOUND,
                codes::NOT_FOUND,
                format!("group not found: {gid}"),
            );
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
            && let Some(node_id) = listener.disconnect_by_token_hash(&hash)
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

    ok(json!({
        "id": id,
        "expose_control": req.expose_control,
        "control_scope": req.control_scope,
        "group_id": group_id_resp,
        "rate_limit_kbps": rate_limit_resp,
    }))
}

pub async fn list_tokens(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    match state.db_call(|db| db.list_relay_tokens()).await {
        Ok(items) => ok(json!({ "items": items })),
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
                && let Some(node_id) = listener.disconnect_by_token_hash(&hash)
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
