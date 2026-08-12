//! Session inventory + kick APIs (node.md M3-T1): per-device/per-session rows for the
//! three-tab resource pages (监听 | 连接 | 签发), with kick-by-session and kick-by-device.

use agile_net_core::proto::message::reason;
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

/// GET /api/v1/admin/sessions — live session inventory (fan-in peers + delegated consumers),
/// each row carrying the proven device identity, entry class and live counters. Relay-entry
/// consumers (terminated at an intermediate relay, reported upstream via ConsumerSessionReport)
/// are merged in from the delegation engine's reported-sessions cache.
pub async fn list_sessions(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    let Some(listener) = &state.runtime.listener else {
        return ok(json!({ "items": [] }));
    };
    let display = listener.peer_display_map().into_iter().collect::<std::collections::HashMap<_, _>>();
    let local = listener.local_delegated_registry();
    let mut items: Vec<serde_json::Value> = listener
        .sessions_detail()
        .into_iter()
        .map(|s| {
            let m = &s.meta;
            let consumer = m.session_key.starts_with("delegated:");
            let (token_label, entry) = if consumer {
                let reg = listener.delegated_registry();
                if let Some(t) = local.get(&m.token_hash) {
                    (t.label.clone(), "direct")
                } else if let Some(t) = reg.get(&m.token_hash) {
                    (t.label.clone(), "relay")
                } else {
                    (String::new(), "")
                }
            } else {
                (String::new(), "")
            };
            json!({
                "session_id": m.session_id,
                "session_key": m.session_key,
                "kind": if consumer { "consumer" } else { "fanin" },
                "node_id": if consumer { serde_json::Value::Null } else { json!(m.session_key) },
                "display": if consumer { serde_json::Value::Null } else { json!(display.get(&m.session_key).cloned().unwrap_or_default()) },
                "device_fp": m.device_fp,
                "my_name": m.my_name,
                "ip": m.peer_ip,
                "connected_at": m.connected_at.elapsed().as_secs(), // seconds online (uptime)
                "bytes_up": s.bytes_up,
                "bytes_down": s.bytes_down,
                "channels": s.channels,
                "token_hash": m.token_hash,
                "token_label": token_label,
                "entry": entry,
            })
        })
        .collect();

    // federation P2: relay-entry consumers reported upstream by intermediate relays. These
    // sessions are NOT terminated at this listener (the relay owns them), so they don't appear
    // in sessions_detail() — merge them from the delegation engine's reported-sessions cache.
    let reported = state.runtime.connector_manager.delegation_engine().reported_sessions();
    for (token_hash, sessions) in reported.iter() {
        let token_label = state
            .runtime
            .listener
            .as_ref()
            .and_then(|l| {
                let reg = l.delegated_registry();
                reg.get(token_hash).map(|t| t.label.clone())
            })
            .unwrap_or_default();
        for info in sessions {
            items.push(json!({
                "session_id": info.session_id,
                "session_key": format!("delegated:{token_hash}:{}", info.session_id),
                "kind": "consumer",
                "node_id": serde_json::Value::Null,
                "display": serde_json::Value::Null,
                "device_fp": info.device_fp,
                "my_name": info.my_name,
                "ip": info.peer_ip,
                "connected_at": 0, // uptime unknown (session lives on the relay, not here)
                "bytes_up": 0,
                "bytes_down": 0,
                "channels": 0,
                "token_hash": token_hash,
                "token_label": token_label,
                "entry": "relay",
            }));
        }
    }

    ok(json!({ "items": items }))
}

#[derive(Deserialize)]
pub struct KickReq {
    pub session_key: String,
    #[serde(default)]
    pub message: String,
}

/// POST /api/v1/admin/sessions/kick — force-close one session (SessionNotice 'kicked' first).
/// Security boundary: relay-transit consumer sessions (authenticated by a remote issuer's
/// delegated token, not by this node) cannot be kicked by this node's admin — the issuer owns
/// those consumers. Fan-in peer sessions and direct-entry consumers are always kickable.
pub async fn kick_session(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<KickReq>,
) -> Response {
    let Some(listener) = &state.runtime.listener else {
        return err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, "relay listener not enabled");
    };
    // relay-transit consumer sessions: delegated:<token_hash>:<node_id> where token_hash is NOT
    // in the local registry → this node is just a relay, the token belongs to a remote issuer
    if let Some(rest) = req.session_key.strip_prefix("delegated:")
        && let Some(hash) = rest.split(':').next()
        && !listener.is_local_delegated_token(hash)
    {
        return err(
            StatusCode::FORBIDDEN,
            codes::FORBIDDEN,
            "relay-transit session: only the token issuer may kick this consumer",
        );
    }
    let n = if listener.is_peer_online(&req.session_key) {
        listener
            .disconnect_peer(&req.session_key, reason::KICKED, &req.message)
            .await as usize
    } else {
        listener
            .disconnect_client(&req.session_key, reason::KICKED, &req.message)
            .await
    };
    if n == 0 {
        return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, "session not online");
    }
    audit(&state, &claims, &ip, "session.kick", Some(&req.session_key), &req.message).await;
    ok(json!({ "kicked": n }))
}

#[derive(Deserialize)]
pub struct KickTokenReq {
    pub token_hash: String,
    #[serde(default)]
    pub message: String,
}

/// POST /api/v1/admin/sessions/kick_token — force-close every consumer session of one
/// delegated token (the toolbar "全部下线" action). Security boundary: only locally-issued
/// tokens (direct-entry) may be kicked by this admin; relay-transit tokens belong to a remote
/// issuer and are off-limits to this node's admin.
pub async fn kick_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<KickTokenReq>,
) -> Response {
    let Some(listener) = &state.runtime.listener else {
        return err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, "relay listener not enabled");
    };
    if !listener.is_local_delegated_token(&req.token_hash) {
        return err(
            StatusCode::FORBIDDEN,
            codes::FORBIDDEN,
            "relay-transit token: only the token issuer may kick its consumers",
        );
    }
    let n = listener
        .disconnect_delegated_token(&req.token_hash, reason::KICKED, &req.message)
        .await;
    audit(&state, &claims, &ip, "session.kick_token", Some(&req.token_hash), &format!("{n} sessions")).await;
    ok(json!({ "kicked": n }))
}

/// POST /api/v1/admin/sessions/kick_fanin — force-close the fan-in node session(s) of one
/// relay token (same toolbar action on the 监听 tab).
pub async fn kick_fanin(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<KickTokenReq>,
) -> Response {
    let Some(listener) = &state.runtime.listener else {
        return err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, "relay listener not enabled");
    };
    let node = listener
        .disconnect_by_token_hash(&req.token_hash, reason::KICKED, &req.message)
        .await;
    let kicked = if node.is_some() { 1 } else { 0 };
    audit(
        &state,
        &claims,
        &ip,
        "session.kick_fanin",
        Some(&req.token_hash),
        node.as_deref().unwrap_or("offline"),
    )
    .await;
    ok(json!({ "kicked": kicked, "node_id": node }))
}
