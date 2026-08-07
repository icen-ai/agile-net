//! Connector (fan-out) API handlers (see docs/todo/peer-acl.md §4/§7)
//!
//! The fan-out token is a connection credential issued by the peer: stored encrypted, never
//! shown again after creation (reset-only); audit must never record token plaintext/ciphertext.
//! Every change drives ConnectorManager hot operations.
//!
//! advertise input convention: a string array (e.g. ["10.0.0.0/8", "git.internal"]),
//! serialized to a comma-joined string in DB (aligned with core ConnectorConfig.advertise).

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok, ok_created};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct CreateConnectorRequest {
    pub name: String,
    /// Self-declared name uploaded to the peer in AuthRequest.my_name (empty = node_id)
    #[serde(default)]
    pub my_name: String,
    pub upstream_addr: String,
    /// Fan-out token (issued by the peer; stored encrypted, never echoed in responses)
    pub token: String,
    #[serde(default)]
    pub sni_hostname: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub ca_cert_path: String,
    #[serde(default)]
    pub pinned_cert_path: String,
    /// Cert fingerprint pinning (SHA-256 hex; empty = unused). Priority over pinned_cert_path/ca/insecure.
    #[serde(default)]
    pub pinned_fingerprint: String,
    #[serde(default)]
    pub advertise: Vec<String>,
    /// ACL group (absent/null = unrestricted, allow all)
    #[serde(default)]
    pub group_id: Option<String>,
    /// Policy upload (federation P1): local group IDs pushed upstream at auth (empty = no upload)
    #[serde(default)]
    pub push_groups: Vec<String>,
    #[serde(default)]
    pub remark: String,
}

/// Fingerprint format: empty (unused) or 64 hex chars (SHA-256, case-insensitive; normalized to lowercase).
fn normalize_fingerprint(fp: &str) -> Result<String, String> {
    let fp = fp.trim().to_lowercase();
    if fp.is_empty() {
        return Ok(fp);
    }
    if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("pinned_fingerprint must be 64 hex chars (SHA-256)".into());
    }
    Ok(fp)
}

fn validate_connector_input(
    name: &str,
    my_name: &str,
    upstream_addr: &str,
    advertise: &[String],
    remark: &str,
) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("name must be 1-64 characters".into());
    }
    if my_name.chars().count() > 64 {
        return Err("my_name too long (max 64)".into());
    }
    if upstream_addr.is_empty() || upstream_addr.len() > 253 {
        return Err("upstream_addr must be 1-253 characters".into());
    }
    if advertise.len() > 64 || advertise.iter().any(|a| a.len() > 256) {
        return Err("advertise too large (max 64 entries, 256 chars each)".into());
    }
    if remark.len() > 256 {
        return Err("remark too long (max 256)".into());
    }
    Ok(())
}

/// Validate the ACL group set (when Some): comma-separated multi-group sets (union ACL);
/// federation P3: e2e_required groups hang only on delegated tokens, never on a connector's
/// reverse-traffic restriction.
async fn validate_group(state: &ApiState, group_id: Option<&str>) -> Option<Response> {
    if let Some(csv) = group_id {
        for gid in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let gid_owned = gid.to_string();
            let group = state
                .db_call(move |db| db.get_group(&gid_owned))
                .await
                .unwrap_or(None);
            let Some(g) = group else {
                return Some(err(
                    StatusCode::NOT_FOUND,
                    codes::NOT_FOUND,
                    format!("group not found: {gid}"),
                ));
            };
            if let Some(r) = super::groups::reject_e2e_group(&g) {
                return Some(r);
            }
        }
    }
    None
}

/// Validate and normalize pushed group IDs (federation P1): each must exist; dedup;
/// cap at the protocol pool size. Returns the DB-serialized comma-joined string.
async fn validate_push_groups(state: &ApiState, ids: &[String]) -> Result<String, Response> {
    if ids.len() > agile_net_core::relay::listener::MAX_PUSHED_GROUPS {
        return Err(err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "push_groups too large (max 32)",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for gid in ids {
        if !seen.insert(gid.clone()) {
            continue;
        }
        let probe = gid.clone();
        let exists = state
            .db_call(move |db| db.get_group(&probe))
            .await
            .unwrap_or(None)
            .is_some();
        if !exists {
            return Err(err(
                StatusCode::NOT_FOUND,
                codes::NOT_FOUND,
                format!("group not found: {gid}"),
            ));
        }
        out.push(gid.clone());
    }
    Ok(out.join(","))
}

/// View JSON: ConnectorView + live state (never contains token plaintext/ciphertext).
async fn connector_json(state: &ApiState, id: &str) -> Option<serde_json::Value> {
    let v = state
        .db_call(|db| db.list_connectors())
        .await
        .ok()?
        .into_iter()
        .find(|c| c.id == id)?;
    let mut value = serde_json::to_value(&v).ok()?;
    let st = state
        .runtime
        .connector_manager
        .state_of(id)
        .unwrap_or("disconnected");
    value["state"] = json!(st);
    // upstream self-declared node name (live session only; empty = offline/unannounced)
    value["peer_node"] = json!(state
        .runtime
        .connector_manager
        .peer_node_of(id)
        .unwrap_or_default());
    Some(value)
}

pub async fn list_connectors(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    match state.db_call(|db| db.list_connectors()).await {
        Ok(items) => {
            let items: Vec<serde_json::Value> = items
                .into_iter()
                .map(|v| {
                    let st = state
                        .runtime
                        .connector_manager
                        .state_of(&v.id)
                        .unwrap_or("disconnected");
                    let ver = state
                        .runtime
                        .connector_manager
                        .upstream_version_of(&v.id)
                        .unwrap_or(0);
                    // upstream self-declared node name (live session only; empty = offline/unannounced)
                    let peer = state
                        .runtime
                        .connector_manager
                        .peer_node_of(&v.id)
                        .unwrap_or_default();
                    let mut value = serde_json::to_value(&v).unwrap_or_else(|_| json!({}));
                    value["state"] = json!(st);
                    // negotiated upstream protocol version (federation P2: delegation needs >= 3)
                    value["upstream_version"] = json!(ver);
                    value["peer_node"] = json!(peer);
                    value
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

pub async fn create_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateConnectorRequest>,
) -> Response {
    let name = req.name.trim();
    let my_name = req.my_name.trim();
    if let Err(msg) =
        validate_connector_input(name, my_name, &req.upstream_addr, &req.advertise, &req.remark)
    {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }
    if req.token.is_empty() || req.token.len() > 256 {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "token must be 1-256 characters",
        );
    }
    if let Some(resp) = validate_group(&state, req.group_id.as_deref()).await {
        return resp;
    }
    let push_groups = match validate_push_groups(&state, &req.push_groups).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    // Name uniqueness (DB has a UNIQUE constraint too; the pre-check gives a clear 409)
    let name_owned = name.to_string();
    let name_taken = state
        .db_call(move |db| {
            Ok(db
                .list_connectors()
                .unwrap_or_default()
                .into_iter()
                .any(|c| c.name == name_owned))
        })
        .await
        .unwrap_or(false);
    if name_taken {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "connector name already exists",
        );
    }

    let advertise = req.advertise.join(",");
    let pinned_fingerprint = match normalize_fingerprint(&req.pinned_fingerprint) {
        Ok(fp) => fp,
        Err(msg) => return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
    };
    let params = (
        name.to_string(),
        my_name.to_string(),
        req.upstream_addr.clone(),
        req.token.clone(),
        req.sni_hostname.clone(),
        req.ca_cert_path.clone(),
        req.pinned_cert_path.clone(),
        pinned_fingerprint,
        advertise,
        req.group_id.clone(),
        req.remark.clone(),
    );
    let insecure = req.insecure;
    let created = state
        .db_call(move |db| {
            let (
                name,
                my_name,
                upstream_addr,
                token,
                sni_hostname,
                ca_cert_path,
                pinned_cert_path,
                pinned_fingerprint,
                advertise,
                group_id,
                remark,
            ) = params;
            db.create_connector(
                &name,
                &my_name,
                &upstream_addr,
                &token,
                &sni_hostname,
                insecure,
                &ca_cert_path,
                &pinned_cert_path,
                &pinned_fingerprint,
                &advertise,
                group_id.as_deref(),
                &remark,
            )
        })
        .await;
    match created {
        Ok(rec) => {
            // Policy upload (federation P1): set before the first hot assembly so the groups ride the first handshake
            if !push_groups.is_empty() {
                let (cid, pg) = (rec.id.clone(), push_groups.clone());
                if let Err(e) = state
                    .db_call(move |db| db.set_connector_push_groups(&cid, &pg))
                    .await
                {
                    tracing::error!(connector = %name, error = %e, "set push_groups failed");
                }
            }
            // Hot assembly failure does not block creation (DB row exists; state shows disconnected, fix and retry via update)
            if let Err(e) = state
                .runtime
                .connector_manager
                .upsert_from_db(&rec.id)
                .await
            {
                tracing::error!(connector = %name, error = %e, "connector hot-start failed");
            }
            audit(
                &state,
                &claims,
                &ip,
                "connector.create",
                Some(&rec.id),
                &format!("{name} -> {}", req.upstream_addr),
            )
            .await;
            match connector_json(&state, &rec.id).await {
                Some(v) => ok_created(v),
                None => err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    codes::INTERNAL,
                    "reload failed",
                ),
            }
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct UpdateConnectorRequest {
    pub name: String,
    /// Self-declared name uploaded to the peer (PUT full-replace: empty string = back to node_id)
    #[serde(default)]
    pub my_name: String,
    pub upstream_addr: String,
    /// Empty/null = keep the current token (token is never echoed, only resettable to a new value)
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub sni_hostname: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub ca_cert_path: String,
    #[serde(default)]
    pub pinned_cert_path: String,
    #[serde(default)]
    pub pinned_fingerprint: String,
    #[serde(default)]
    pub advertise: Vec<String>,
    /// ACL group (PUT is full-replace semantics: absent/null = unrestricted)
    #[serde(default)]
    pub group_id: Option<String>,
    /// Policy upload (federation P1): absent = keep current; provided (incl. empty) = replace
    #[serde(default)]
    pub push_groups: Option<Vec<String>>,
    #[serde(default)]
    pub remark: String,
}

pub async fn update_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<UpdateConnectorRequest>,
) -> Response {
    let cid = id.clone();
    let exists = state
        .db_call(move |db| db.get_connector(&cid))
        .await
        .unwrap_or(None)
        .is_some();
    if !exists {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "connector not found",
        );
    }
    let name = req.name.trim();
    let my_name = req.my_name.trim();
    if let Err(msg) =
        validate_connector_input(name, my_name, &req.upstream_addr, &req.advertise, &req.remark)
    {
        return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg);
    }
    if let Some(t) = &req.token
        && t.len() > 256
    {
        return err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "token too long (max 256)",
        );
    }
    if let Some(resp) = validate_group(&state, req.group_id.as_deref()).await {
        return resp;
    }
    // Policy upload (federation P1): absent = keep; provided = validated replacement
    let push_groups = match &req.push_groups {
        Some(ids) => match validate_push_groups(&state, ids).await {
            Ok(s) => Some(s),
            Err(resp) => return resp,
        },
        None => None,
    };
    let (name_owned, cid) = (name.to_string(), id.clone());
    let name_taken = state
        .db_call(move |db| {
            Ok(db
                .list_connectors()
                .unwrap_or_default()
                .into_iter()
                .any(|c| c.name == name_owned && c.id != cid))
        })
        .await
        .unwrap_or(false);
    if name_taken {
        return err(
            StatusCode::CONFLICT,
            codes::DUPLICATE,
            "connector name already exists",
        );
    }

    // Empty string counts as not provided (keep the current token)
    let token_reset = req.token.as_deref().filter(|t| !t.is_empty());
    let advertise = req.advertise.join(",");
    let pinned_fingerprint = match normalize_fingerprint(&req.pinned_fingerprint) {
        Ok(fp) => fp,
        Err(msg) => return err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
    };
    let params = (
        id.clone(),
        name.to_string(),
        my_name.to_string(),
        req.upstream_addr.clone(),
        token_reset.map(str::to_string),
        req.sni_hostname.clone(),
        req.ca_cert_path.clone(),
        req.pinned_cert_path.clone(),
        pinned_fingerprint,
        advertise,
        req.group_id.clone(),
        req.remark.clone(),
    );
    let insecure = req.insecure;
    let updated = state
        .db_call(move |db| {
            let (
                id,
                name,
                my_name,
                upstream_addr,
                token_reset,
                sni_hostname,
                ca_cert_path,
                pinned_cert_path,
                pinned_fingerprint,
                advertise,
                group_id,
                remark,
            ) = params;
            db.update_connector(
                &id,
                &name,
                &my_name,
                &upstream_addr,
                token_reset.as_deref(),
                &sni_hostname,
                insecure,
                &ca_cert_path,
                &pinned_cert_path,
                &pinned_fingerprint,
                &advertise,
                group_id.as_deref(),
                &remark,
            )
        })
        .await;
    if let Err(e) = updated {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    // Policy upload replacement (federation P1; before the hot rebuild so the new set rides the next handshake)
    if let Some(pg) = &push_groups {
        let (cid, pg) = (id.clone(), pg.clone());
        if let Err(e) = state
            .db_call(move |db| db.set_connector_push_groups(&cid, &pg))
            .await
        {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
    }
    // Rebuild this connector (drop the old link, then bring up the new one)
    if let Err(e) = state.runtime.connector_manager.upsert_from_db(&id).await {
        tracing::error!(connector = %name, error = %e, "connector hot-rebuild failed");
    }
    audit(
        &state,
        &claims,
        &ip,
        "connector.update",
        Some(&id),
        &format!(
            "{name} -> {} (token {}{})",
            req.upstream_addr,
            if token_reset.is_some() {
                "rotated"
            } else {
                "kept"
            },
            match &push_groups {
                Some(pg) => format!(
                    ", push_groups={}",
                    if pg.is_empty() {
                        "cleared".into()
                    } else {
                        pg.split(',').count().to_string()
                    }
                ),
                None => String::new(),
            }
        ),
    )
    .await;
    match connector_json(&state, &id).await {
        Some(v) => ok(v),
        None => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "reload failed",
        ),
    }
}

pub async fn delete_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    let cid = id.clone();
    let Some(rec) = state
        .db_call(move |db| db.get_connector(&cid))
        .await
        .unwrap_or(None)
    else {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "connector not found",
        );
    };
    match state.db_call(move |db| db.delete_connector(&id)).await {
        Ok(_) => {
            state.runtime.connector_manager.remove(&rec.id).await;
            audit(
                &state,
                &claims,
                &ip,
                "connector.delete",
                Some(&rec.id),
                &rec.name,
            )
            .await;
            ok(json!(null))
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}

/// Shared enable/disable impl: enable = assemble and connect, disable = disconnect and remove (DB row kept).
async fn set_enabled(
    state: &ApiState,
    claims: &crate::auth::jwt::Claims,
    ip: &std::net::IpAddr,
    id: &str,
    enabled: bool,
) -> Response {
    let cid = id.to_string();
    let Some(rec) = state
        .db_call(move |db| db.get_connector(&cid))
        .await
        .unwrap_or(None)
    else {
        return err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            "connector not found",
        );
    };
    let cid = id.to_string();
    if let Err(e) = state
        .db_call(move |db| db.set_connector_enabled(&cid, enabled))
        .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        );
    }
    if enabled {
        if let Err(e) = state.runtime.connector_manager.upsert_from_db(id).await {
            tracing::error!(connector = %rec.name, error = %e, "connector hot-start failed");
        }
    } else {
        state.runtime.connector_manager.remove(id).await;
    }
    audit(
        state,
        claims,
        ip,
        if enabled {
            "connector.enable"
        } else {
            "connector.disable"
        },
        Some(id),
        &rec.name,
    )
    .await;
    match connector_json(state, id).await {
        Some(v) => ok(v),
        None => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "reload failed",
        ),
    }
}

pub async fn enable_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    set_enabled(&state, &claims, &ip, &id, true).await
}

pub async fn disable_connector(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> Response {
    set_enabled(&state, &claims, &ip, &id, false).await
}
