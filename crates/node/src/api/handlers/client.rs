//! Client API Handlers（对应 docs/api/config.md）
//!
//! 客户端登录后拉取路由配置（支持长轮询），并通过心跳上报在线状态与流量。

use crate::api::extractors::ClientAuth;
use crate::api::{ApiState, codes, err, ok};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use serde_json::json;

/// 长轮询超时（秒）
const LONG_POLL_TIMEOUT_SECS: u64 = 30;

/// 单次心跳上报流量的合理上限（1 TiB，防恶意刷统计）。
const MAX_HEARTBEAT_BYTES: i64 = 1 << 40;

#[derive(Deserialize)]
pub struct ConfigQuery {
    #[serde(default)]
    pub wait: bool,
    pub version: Option<u64>,
}

pub async fn get_config(
    ClientAuth(claims): ClientAuth,
    State(state): State<ApiState>,
    Query(q): Query<ConfigQuery>,
) -> Response {
    let client_version = q.version.unwrap_or(0);

    if q.wait {
        // 长轮询：等待配置版本超过客户端版本，超时返回 304
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(LONG_POLL_TIMEOUT_SECS);
        loop {
            let current = state.db.config_version().unwrap_or(0);
            if current > client_version {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return StatusCode::NOT_MODIFIED.into_response();
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    build_config_response(&state, &claims.sub)
}

fn build_config_response(state: &ApiState, account_id: &str) -> Response {
    let version = state.db.config_version().unwrap_or(0);
    let node_name = state
        .db
        .get_config("node_name")
        .ok()
        .flatten()
        .unwrap_or_else(|| "AgileNet Node".to_string());

    let rules = state
        .db
        .rules_of_account(account_id)
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "type": r.rule_type,
                "value": r.value,
                "resolve": r.resolve,
            })
        })
        .collect::<Vec<_>>();

    let (server, port) = state.public_tunnel_endpoint();

    let admin_console = state
        .db
        .get_account(account_id)
        .ok()
        .flatten()
        .map(|a| a.admin_console)
        .unwrap_or(false);

    // 可管理上游自动发现（握手 v2）：仅管理版账号下发；
    // 票据经 console-ticket 端点按需取用，不随配置广播
    let manageable: Vec<serde_json::Value> = if admin_console {
        state
            .runtime
            .manageable
            .iter()
            .map(|item| {
                let o = item.value();
                json!({
                    "node_name": o.node_name,
                    "api": format!("{}:{}", o.api_host.as_deref().unwrap_or("?"), o.api_port),
                    "scope": o.scope,
                    "via": "relay",
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    ok(json!({
        "version": version,
        "node_name": node_name,
        "admin_console": admin_console,
        "manageable": manageable,
        "rules": rules,
        "tunnel": {
            "server": server,
            "port": port,
            "tls": true,
            "heartbeat_interval": 25,
            "heartbeat_jitter": 10,
        },
    }))
}

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub uptime: u64,
    #[serde(default)]
    pub bytes_tx: i64,
    #[serde(default)]
    pub bytes_rx: i64,
    #[serde(default)]
    pub active_connections: i64,
}

pub async fn heartbeat(
    ClientAuth(claims): ClientAuth,
    State(state): State<ApiState>,
    Json(req): Json<HeartbeatRequest>,
) -> Response {
    let account_id = &claims.sub;

    // 账号被禁用/删除时强制下线
    let account = match state.db.get_account(account_id) {
        Ok(Some(a)) => a,
        _ => {
            return ok(json!({
                "config_version": 0,
                "force_disconnect": true,
            }));
        }
    };
    if !account.enabled {
        return ok(json!({
            "config_version": state.db.config_version().unwrap_or(0),
            "force_disconnect": true,
        }));
    }

    let _ = state.db.touch_account_seen(account_id);

    // bytes_tx/rx 为自上次心跳以来的增量（心跳间隔 60s），按小时聚合入库
    let delta_tx = req.bytes_tx.clamp(0, MAX_HEARTBEAT_BYTES);
    let delta_rx = req.bytes_rx.clamp(0, MAX_HEARTBEAT_BYTES);
    if delta_tx > 0 || delta_rx > 0 {
        let _ = state.db.add_traffic(
            account_id,
            delta_tx,
            delta_rx,
            req.active_connections.clamp(0, 1_000_000),
        );
    }

    ok(json!({
        "config_version": state.db.config_version().unwrap_or(0),
        "force_disconnect": false,
    }))
}

use axum::response::IntoResponse;

/// 控制台引导票据签发（管理版接入链接持有者专用）。
///
/// 仅当账号被授予「管理此节点」权限（admin_console）时签发；
/// 票据 10 分钟一次性，凭它在 /api/v1/auth/admin-bootstrap 换取管理会话。
#[derive(Deserialize)]
pub struct ConsoleTicketRequest {
    /// 上游节点名（可管理上游；缺省为本节点自身）
    #[serde(default)]
    pub upstream: Option<String>,
}

pub async fn console_ticket(
    ClientAuth(claims): ClientAuth,
    State(state): State<ApiState>,
    body: Option<Json<ConsoleTicketRequest>>,
) -> Response {
    let account = match state.db.get_account(&claims.sub) {
        Ok(Some(a)) if a.enabled => a,
        _ => {
            return err(
                StatusCode::FORBIDDEN,
                codes::FORBIDDEN,
                "account unavailable",
            );
        }
    };
    if !account.admin_console {
        return err(
            StatusCode::FORBIDDEN,
            codes::FORBIDDEN,
            "管理权限未授予该账号",
        );
    }

    // 上游目标：返回握手 v2 发现的当前票据与端点（中继令牌换取，scoped）
    if let Some(upstream) = body.and_then(|b| b.upstream.clone()) {
        let Some(offer) = state.runtime.manageable.get(&upstream).map(|o| o.clone()) else {
            return err(
                StatusCode::NOT_FOUND,
                codes::NOT_FOUND,
                "该上游未暴露控制面或已断开",
            );
        };
        return ok(json!({
            "ticket": offer.ticket,
            "api": format!("{}:{}", offer.api_host.as_deref().unwrap_or("?"), offer.api_port),
            "node_name": offer.node_name,
            "scope": offer.scope,
            "via": "relay",
        }))
        .into_response();
    }

    match state
        .db
        .create_admin_ticket("account", &account.id, "full", 1, 600)
    {
        Ok(ticket) => ok(json!({
            "ticket": ticket,
            "expires_in": 600,
        }))
        .into_response(),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            e.to_string(),
        ),
    }
}
