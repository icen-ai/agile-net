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
/// each row carrying the proven device identity, entry class and live counters.
pub async fn list_sessions(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    let Some(listener) = &state.runtime.listener else {
        return ok(json!({ "items": [] }));
    };
    let display = listener.peer_display_map().into_iter().collect::<std::collections::HashMap<_, _>>();
    let local = listener.local_delegated_registry();
    let items: Vec<serde_json::Value> = listener
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
    ok(json!({ "items": items }))
}

#[derive(Deserialize)]
pub struct KickReq {
    pub session_key: String,
    #[serde(default)]
    pub message: String,
}

/// POST /api/v1/admin/sessions/kick — force-close one session (SessionNotice 'kicked' first).
pub async fn kick_session(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<KickReq>,
) -> Response {
    let Some(listener) = &state.runtime.listener else {
        return err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, "relay listener not enabled");
    };
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
/// delegated token (the toolbar "全部下线" action).
pub async fn kick_token(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<KickTokenReq>,
) -> Response {
    let Some(listener) = &state.runtime.listener else {
        return err(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, "relay listener not enabled");
    };
    let n = listener
        .disconnect_delegated_token(&req.token_hash, reason::KICKED, &req.message)
        .await;
    audit(&state, &claims, &ip, "session.kick_token", Some(&req.token_hash), &format!("{n} sessions")).await;
    ok(json!({ "kicked": n }))
}
