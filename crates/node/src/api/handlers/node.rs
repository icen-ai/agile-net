//! Node status/stats/logs/settings API handlers (see docs/api/node.md)

use super::audit;
use crate::api::extractors::{AdminAuth, ClientIp};
use crate::api::{ApiState, codes, err, ok};
use axum::{
    Json,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

pub async fn status(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    // Merge overview reads into one blocking task (name/rule count/account stats/24h traffic series;
    // node_traffic_24h is an hourly aggregate query; on failure fall back to an empty series, never block status)
    let (node_name, rule_count, accounts_total, accounts_disabled, traffic_24h) = state
        .db_call(|db| {
            let node_name = db
                .get_config("node_name")
                .ok()
                .flatten()
                .unwrap_or_else(|| "AgileNet Node".to_string());
            let rule_count = db.list_rules(1, 1, None, None).map(|(_, t)| t).unwrap_or(0);
            let (accounts_total, accounts_disabled) = db.account_stats().unwrap_or((0, 0));
            let traffic_24h = db
                .node_traffic_24h()
                .map(|v| serde_json::to_value(v).unwrap_or_else(|_| empty_traffic_24h()))
                .unwrap_or_else(|_| empty_traffic_24h());
            Ok((
                node_name,
                rule_count,
                accounts_total,
                accounts_disabled,
                traffic_24h,
            ))
        })
        .await
        .unwrap_or_else(|_| {
            (
                "AgileNet Node".to_string(),
                0,
                0,
                0,
                empty_traffic_24h(),
            )
        });

    let (listener_json, online_accounts) = match &state.runtime.listener {
        Some(l) => (
            json!({
                "enabled": true,
                "addr": l.listen_addr().to_string(),
                "tls": true,
                "connected_connectors": l.peer_count(),
                "peers": l.list_peers(),
                "peer_traffic": l.peer_traffic().into_iter().map(|(id, out, inn)| json!({
                    "node_id": id,
                    "bytes_up": out,
                    "bytes_down": inn,
                })).collect::<Vec<_>>(),
                "online_clients": l.online_client_count(),
            }),
            l.online_client_count() as i64,
        ),
        None => (json!({ "enabled": false }), 0),
    };

    // Fan-out (multi-target: address + per-link state; data source is ConnectorManager)
    let connectors_json: Vec<serde_json::Value> = state
        .runtime
        .connector_manager
        .states()
        .into_iter()
        .map(|(upstream, status)| {
            json!({
                "upstream": upstream,
                "status": status,
            })
        })
        .collect();

    // Manageable upstreams (handshake v2 discovery; sanitized: no tickets)
    let manageable_json: Vec<serde_json::Value> = state
        .runtime
        .manageable
        .iter()
        .map(|item| {
            let o = item.value();
            json!({
                "node_name": o.node_name,
                "api": format!("{}:{}", o.api_host.as_deref().unwrap_or("?"), o.api_port),
                "scope": o.scope,
            })
        })
        .collect();

    // Client-role proxy slot (real state written by the GUI host) takes precedence;
    // an empty slot (pure anet-svc) keeps the legacy node-role proxy_listen behavior (no mode field)
    let client_proxy = state.runtime.client_proxy_slot.load();
    let proxy_json = match &**client_proxy {
        Some(info) => json!({
            "enabled": info.enabled,
            "mode": info.mode,
            "listen": info.listen,
        }),
        None => match (&state.runtime.proxy_listen, &state.runtime.proxy_stats) {
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
        },
    };

    // Per-connector fan-out traffic (live counters of the current session; disconnected connectors read 0, history in traffic_24h)
    let fanout_traffic: Vec<serde_json::Value> = state
        .runtime
        .connector_manager
        .traffic()
        .into_iter()
        .map(|(name, up, down)| {
            json!({
                "name": name,
                "bytes_up": up,
                "bytes_down": down,
            })
        })
        .collect();

    // Relay transit (live snapshot: totals + origin->terminus pairs; the two adjacent hops visible to this node)
    let (t_up, t_down, t_pairs) = state.runtime.transit_meter.snapshot();
    let transit_json = json!({
        "bytes_up": t_up,
        "bytes_down": t_down,
        "pairs": t_pairs.into_iter().map(|p| json!({
            "from": p.from,
            "to": p.to,
            "bytes_up": p.bytes_up,
            "bytes_down": p.bytes_down,
        })).collect::<Vec<_>>(),
    });

    ok(json!({
        "node_name": node_name,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime": state.runtime.uptime_secs(),
        "manageable_upstreams": manageable_json,
        "roles": {
            "listener": listener_json,
            "connectors": connectors_json,
            "connector_status": state.runtime.connector_status(),
            "fanout_traffic": fanout_traffic,
            "transit": transit_json,
        },
        "traffic_24h": traffic_24h,
        "proxy": proxy_json,
        "accounts": {
            "total": accounts_total,
            "online": online_accounts,
            "disabled": accounts_disabled,
        },
        "system": system_stats(),
        "cert_fingerprint": state.runtime.cert_fingerprint,
    }))
}

/// Empty traffic_24h series (fallback on DB errors, keeps the contract fields intact).
fn empty_traffic_24h() -> serde_json::Value {
    json!({"fanin": [], "fanout": [], "transit": []})
}

/// System resource usage (cross-platform sysinfo).
/// Process-level cached System instance: a fresh instance has no history delta, so CPU usage
/// reads a meaningless 0, and rebuilding per 15s overview poll is wasteful; the refresh set
/// stays minimal (memory + this process), do not expand.
fn system_stats() -> serde_json::Value {
    use std::sync::{Mutex, OnceLock};
    use sysinfo::System;
    static SYS: OnceLock<Mutex<System>> = OnceLock::new();
    // Lock poisoning must not block status: recover the inner data and keep going
    let mut sys = SYS
        .get_or_init(|| Mutex::new(System::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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
        "account" => match state.db_call(move |db| db.traffic_by_account(hours)).await {
            Ok((breakdown, total_tx, total_rx)) => ok(json!({
                "period": q.period,
                "total_tx": total_tx,
                "total_rx": total_rx,
                "breakdown": breakdown,
            })),
            Err(e) => err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            ),
        },
        "time" => match state.db_call(move |db| db.traffic_by_time(hours)).await {
            Ok(points) => ok(json!({
                "period": q.period,
                "interval": "1h",
                "points": points,
            })),
            Err(e) => err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            ),
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
    pub public_host: Option<String>,
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
        let name = name.to_string();
        if let Err(e) = state
            .db_call(move |db| db.set_config("node_name", &name))
            .await
        {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
        applied.push("node_name");
    }
    if let Some(host) = &req.public_host {
        let host = host.trim();
        if host.is_empty() || host.len() > 253 || host.contains('/') || host.contains(' ') {
            return err(
                StatusCode::BAD_REQUEST,
                codes::VALIDATION_FAILED,
                "invalid public_host",
            );
        }
        let host = host.to_string();
        if let Err(e) = state
            .db_call(move |db| db.set_config("public_host", &host))
            .await
        {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                e.to_string(),
            );
        }
        applied.push("public_host");
    }
    audit(
        &state,
        &claims,
        &ip,
        "node.update_settings",
        None,
        &applied.join(","),
    )
    .await;
    ok(json!({
        "applied": applied,
        "restart_required": [],
    }))
}

#[derive(Deserialize)]
pub struct KickRequest {
    pub node_id: String,
}

/// Force-disconnect a downstream node (the kicked peer's reconnect is governed by its own backoff policy).
pub async fn kick_peer(
    AdminAuth(claims): AdminAuth,
    State(state): State<ApiState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<KickRequest>,
) -> Response {
    let Some(listener) = &state.runtime.listener else {
        return err(
            StatusCode::BAD_REQUEST,
            codes::BAD_REQUEST,
            "relay listener not enabled",
        );
    };
    if listener.disconnect_peer(&req.node_id) {
        audit(
            &state,
            &claims,
            &ip,
            "node.kick_peer",
            Some(&req.node_id),
            "",
        )
        .await;
        ok(json!({ "kicked": true }))
    } else {
        err(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            format!("peer {} not connected", req.node_id),
        )
    }
}

/// Prometheus-format metrics export (admin auth).
pub async fn metrics(AdminAuth(_): AdminAuth, State(state): State<ApiState>) -> Response {
    let mut out = String::new();
    let uptime = state.runtime.uptime_secs();
    let (rule_count, acc_total, acc_disabled) = state
        .db_call(|db| {
            let rule_count = db.list_rules(1, 1, None, None).map(|(_, t)| t).unwrap_or(0);
            let (acc_total, acc_disabled) = db.account_stats().unwrap_or((0, 0));
            Ok((rule_count, acc_total, acc_disabled))
        })
        .await
        .unwrap_or((0, 0, 0));

    out.push_str(
        "# HELP agilenet_uptime_seconds Node uptime\n# TYPE agilenet_uptime_seconds gauge\n",
    );
    out.push_str(&format!("agilenet_uptime_seconds {uptime}\n"));
    out.push_str(
        "# HELP agilenet_rules_total Configured routing rules\n# TYPE agilenet_rules_total gauge\n",
    );
    out.push_str(&format!("agilenet_rules_total {rule_count}\n"));
    out.push_str(
        "# HELP agilenet_accounts_total Client accounts\n# TYPE agilenet_accounts_total gauge\n",
    );
    out.push_str(&format!(
        "agilenet_accounts_total {acc_total}\nagilenet_accounts_disabled {acc_disabled}\n"
    ));

    if let Some(l) = &state.runtime.listener {
        out.push_str(
            "# HELP agilenet_peers Connected downstream nodes\n# TYPE agilenet_peers gauge\n",
        );
        out.push_str(&format!("agilenet_peers {}\n", l.peer_count()));
        out.push_str("# HELP agilenet_online_clients Online client tunnels\n# TYPE agilenet_online_clients gauge\n");
        out.push_str(&format!(
            "agilenet_online_clients {}\n",
            l.online_client_count()
        ));
        out.push_str("# HELP agilenet_peer_bytes Peer data-plane traffic\n# TYPE agilenet_peer_bytes counter\n");
        for (id, up, down) in l.peer_traffic() {
            out.push_str(&format!(
                "agilenet_peer_bytes{{node_id=\"{id}\",direction=\"up\"}} {up}\n"
            ));
            out.push_str(&format!(
                "agilenet_peer_bytes{{node_id=\"{id}\",direction=\"down\"}} {down}\n"
            ));
        }
    }
    if let Some(stats) = &state.runtime.proxy_stats {
        use std::sync::atomic::Ordering::Relaxed;
        out.push_str("# HELP agilenet_proxy_connections Proxy inbound connections\n# TYPE agilenet_proxy_connections gauge\n");
        out.push_str(&format!(
            "agilenet_proxy_active_connections {}\nagilenet_proxy_total_connections {}\n",
            stats.active_connections.load(Relaxed),
            stats.total_connections.load(Relaxed)
        ));
        out.push_str("# HELP agilenet_proxy_bytes Proxy inbound traffic\n# TYPE agilenet_proxy_bytes counter\n");
        out.push_str(&format!(
            "agilenet_proxy_bytes{{direction=\"up\"}} {}\nagilenet_proxy_bytes{{direction=\"down\"}} {}\n",
            stats.bytes_up.load(Relaxed),
            stats.bytes_down.load(Relaxed)
        ));
    }

    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        out,
    )
        .into_response()
}

/// WebSocket live event stream (node/client online-offline + 30s stats snapshot).
///
/// Browser WebSockets cannot set request headers; to keep the token out of access logs
/// and browser history, auth uses the **first message after upgrade**: the client sends its
/// access_token immediately on connect (5s timeout); the server verifies admin role and
/// scope tier (fail-closed) before pushing events.
pub async fn events_ws(State(state): State<ApiState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

/// Wait for the first-message auth (close on timeout or failure).
async fn ws_authenticate(socket: &mut WebSocket, state: &ApiState) -> bool {
    use axum::extract::ws::Message;
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv()).await;
    let token = match msg {
        Ok(Some(Ok(Message::Text(t)))) => t.trim().to_string(),
        _ => return false,
    };
    state
        .jwt
        .verify(&token)
        .map(|c| {
            c.typ == "access"
                && c.role == "admin"
                && matches!(c.scope.as_str(), "ro" | "rules" | "full")
        })
        .unwrap_or(false)
}

async fn handle_ws(mut socket: WebSocket, state: ApiState) {
    use agile_net_core::relay::listener::PeerEvent;

    // First-message auth (token never goes through the URL, keeping it out of access logs/browser history)
    if !ws_authenticate(&mut socket, &state).await {
        return; // drop closes the connection
    }

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
                    Some(PeerEvent::AclDenied { peer_label, target }) => json!({
                        "type": "peer.acl_denied",
                        "time": chrono::Utc::now().to_rfc3339(),
                        "data": { "peer_label": peer_label, "target": target },
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
