//! Node 状态/统计/日志/设置 API Handlers（对应 docs/api/node.md）

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok};
use axum::{
    Json,
    extract::{Query, State, ws::{Message, WebSocket, WebSocketUpgrade}},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

pub async fn status(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
) -> Response {
    let db = &state.db;
    let node_name = db
        .get_config("node_name")
        .ok()
        .flatten()
        .unwrap_or_else(|| "AgileNet Node".to_string());
    let rule_count = db.list_rules(1, 1, None, None).map(|(_, t)| t).unwrap_or(0);
    let (accounts_total, accounts_disabled) = db.account_stats().unwrap_or((0, 0));

    let (listener_json, online_accounts) = match &state.runtime.listener {
        Some(l) => (
            json!({
                "enabled": true,
                "addr": l.listen_addr().to_string(),
                "tls": true,
                "connected_connectors": l.peer_count(),
                "peers": l.list_peers(),
                "online_clients": l.online_client_count(),
            }),
            l.online_client_count() as i64,
        ),
        None => (json!({ "enabled": false }), 0),
    };

    let connector_json = match &state.runtime.connector {
        Some(c) => json!({
            "enabled": true,
            "upstream": c.upstream_addr().to_string(),
            "status": state.runtime.connector_status(),
        }),
        None => json!({ "enabled": false }),
    };

    let proxy_json = match (&state.runtime.proxy_listen, &state.runtime.proxy_stats) {
        (Some(addr), Some(stats)) => json!({
            "enabled": true,
            "listen": addr,
            "active_connections": stats.active_connections.load(std::sync::atomic::Ordering::Relaxed),
            "total_connections": stats.total_connections.load(std::sync::atomic::Ordering::Relaxed),
            "bytes_up": stats.bytes_up.load(std::sync::atomic::Ordering::Relaxed),
            "bytes_down": stats.bytes_down.load(std::sync::atomic::Ordering::Relaxed),
            "rule_count": rule_count,
        }),
        _ => json!({ "enabled": false, "rule_count": rule_count }),
    };

    ok(json!({
        "node_name": node_name,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": state.runtime.uptime_secs(),
        "roles": {
            "listener": listener_json,
            "connector": connector_json,
        },
        "proxy": proxy_json,
        "accounts": {
            "total": accounts_total,
            "online": online_accounts,
            "disabled": accounts_disabled,
        },
        "system": system_stats(),
    }))
}

/// 系统资源占用（跨平台 sysinfo）。
fn system_stats() -> serde_json::Value {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_memory();
    let pid = sysinfo::get_current_pid().ok();
    let mut cpu = 0.0f32;
    let mut mem_bytes = 0u64;
    if let Some(pid) = pid {
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        if let Some(p) = sys.process(pid) {
            cpu = p.cpu_usage();
            mem_bytes = p.memory();
        }
    }
    json!({
        "cpu_usage": cpu,
        "memory_mb": mem_bytes / 1024 / 1024,
        "total_memory_mb": sys.total_memory() / 1024 / 1024,
    })
}

#[derive(Deserialize)]
pub struct StatsQuery {
    #[serde(default = "default_period")]
    pub period: String,
    #[serde(default = "default_group_by")]
    pub group_by: String,
}

fn default_period() -> String {
    "1h".to_string()
}
fn default_group_by() -> String {
    "account".to_string()
}

fn period_hours(period: &str) -> i64 {
    match period {
        "1h" => 1,
        "24h" => 24,
        "7d" => 24 * 7,
        "30d" => 24 * 30,
        _ => 1,
    }
}

pub async fn stats(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Query(q): Query<StatsQuery>,
) -> Response {
    let hours = period_hours(&q.period);
    match q.group_by.as_str() {
        "account" => match state.db.traffic_by_account(hours) {
            Ok((breakdown, total_tx, total_rx)) => ok(json!({
                "period": q.period,
                "total_tx": total_tx,
                "total_rx": total_rx,
                "breakdown": breakdown,
            })),
            Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
        },
        "time" => match state.db.traffic_by_time(hours) {
            Ok(points) => ok(json!({
                "period": q.period,
                "interval": "1h",
                "points": points,
            })),
            Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string()),
        },
        _ => err(
            StatusCode::BAD_REQUEST,
            codes::VALIDATION_FAILED,
            "group_by must be account|time",
        ),
    }
}

#[derive(Deserialize)]
pub struct LogsQuery {
    #[serde(default = "default_limit")]
    pub limit: u32,
    pub level: Option<String>,
    pub module: Option<String>,
}

fn default_limit() -> u32 {
    100
}

pub async fn logs(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Query(q): Query<LogsQuery>,
) -> Response {
    let limit = q.limit.clamp(1, 1000) as usize;
    let items = state
        .runtime
        .log_buffer
        .query(limit, q.level.as_deref(), q.module.as_deref());
    ok(json!({ "items": items }))
}

#[derive(Deserialize)]
pub struct SettingsRequest {
    pub node_name: Option<String>,
}

pub async fn update_settings(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<SettingsRequest>,
) -> Response {
    let mut applied = Vec::new();
    if let Some(name) = &req.node_name {
        let name = name.trim();
        if name.is_empty() || name.len() > 64 {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "node_name must be 1-64 characters",
            );
        }
        if let Err(e) = state.db.set_config("node_name", name) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, codes::INTERNAL, e.to_string());
        }
        applied.push("node_name");
    }
    audit(
        &state,
        &claims,
        &ip,
        "node.update_settings",
        None,
        &applied.join(","),
    );
    ok(json!({
        "applied": applied,
        "restart_required": [],
    }))
}

/// WebSocket 实时事件流（节点/客户端上下线 + 30s 统计快照）。
pub async fn events_ws(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: ApiState) {
    use agile_net_core::relay::listener::PeerEvent;

    let mut event_rx = state
        .runtime
        .listener
        .as_ref()
        .map(|l| l.subscribe_events());

    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let msg = tokio::select! {
            evt = async {
                match &mut event_rx {
                    Some(rx) => rx.recv().await.ok(),
                    None => std::future::pending().await,
                }
            } => {
                match evt {
                    Some(PeerEvent::NodeConnected { node_id }) => json!({
                        "type": "connector.connected",
                        "time": chrono::Utc::now().to_rfc3339(),
                        "data": { "node_id": node_id },
                    }),
                    Some(PeerEvent::NodeDisconnected { node_id }) => json!({
                        "type": "connector.disconnected",
                        "time": chrono::Utc::now().to_rfc3339(),
                        "data": { "node_id": node_id },
                    }),
                    Some(PeerEvent::ClientConnected { account_id }) => json!({
                        "type": "account.online",
                        "time": chrono::Utc::now().to_rfc3339(),
                        "data": { "account_id": account_id },
                    }),
                    Some(PeerEvent::ClientDisconnected { account_id }) => json!({
                        "type": "account.offline",
                        "time": chrono::Utc::now().to_rfc3339(),
                        "data": { "account_id": account_id },
                    }),
                    None => break,
                }
            }
            _ = ticker.tick() => {
                let stats = state.runtime.proxy_stats.as_ref().map(|s| json!({
                    "active_connections": s.active_connections.load(std::sync::atomic::Ordering::Relaxed),
                    "total_connections": s.total_connections.load(std::sync::atomic::Ordering::Relaxed),
                    "bytes_up": s.bytes_up.load(std::sync::atomic::Ordering::Relaxed),
                    "bytes_down": s.bytes_down.load(std::sync::atomic::Ordering::Relaxed),
                })).unwrap_or_else(|| json!({}));
                json!({
                    "type": "stats.snapshot",
                    "time": chrono::Utc::now().to_rfc3339(),
                    "data": stats,
                })
            }
        };

        if socket
            .send(Message::Text(msg.to_string().into()))
            .await
            .is_err()
        {
            break;
        }
    }
}
