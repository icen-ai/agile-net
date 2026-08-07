//! Split out of lib.rs-style cmd layout: connection log commands (design docs/todo/conn-log.md).
//!
//! The engine-owned ConnLog (state.client.conn_log()) records one row per local-proxy inbound connection
//! (ring layer) and aggregates per target host:port (primary 连接记录 view: live counters + session totals
//! plus persisted historical baseline). Enabled flag persists as roles.conn_log_enabled (default off —
//! records are browsing history, strictly opt-in). Persistence is the smart-flush task: snapshot write
//! to ~/.anet/gui/conn-stats.json on dirty (5s tick) / 30s idle sweep with active conns / disable —
//! atomic tmp+rename, never per-connection writes. Clear removes memory + file.

use crate::{roles, AppState};
use agile_net_core::proxy::conlog::{ConnFilter, ConnLog, HostStat, QueryOut};
use roles::RoleSettings;
use serde::Serialize;
use std::sync::Arc;
use tauri::{AppHandle, Manager, State};

/// Persistence file (~/.anet/gui/conn-stats.json)
pub(crate) fn conn_stats_path() -> std::path::PathBuf {
    roles::data_dir().join("conn-stats.json")
}

fn log_of(state: &State<'_, AppState>) -> Arc<ConnLog> {
    state.client.conn_log()
}

/// Toolbar status: enabled flag + session totals (target-aggregated, live values included)
#[derive(Serialize)]
pub struct ConlogStatus {
    pub enabled: bool,
    pub active: usize,
    pub hosts: usize,
    pub up: u64,
    pub down: u64,
}

#[tauri::command]
pub(crate) async fn conlog_status(state: State<'_, AppState>) -> Result<ConlogStatus, String> {
    let log = log_of(&state);
    let t = log.totals();
    Ok(ConlogStatus {
        enabled: log.is_enabled(),
        active: t.active,
        hosts: t.hosts,
        up: t.up,
        down: t.down,
    })
}

#[allow(clippy::too_many_arguments)]
fn to_filter(
    keyword: Option<String>,
    outbound: Option<String>,
    row_state: Option<String>,
    hit: Option<String>,
    source: Option<String>,
    sort: Option<String>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> ConnFilter {
    ConnFilter {
        keyword,
        outbound,
        state: row_state,
        hit,
        source,
        sort,
        from_ms,
        to_ms,
        offset: offset.unwrap_or(0),
        limit: limit.unwrap_or(50),
    }
}

/// Aggregated per-target page (primary 连接记录 view; 50-row pages driven by the frontend's offset/limit).
/// `row_state` = active|closed|failed (target semantics: has-live / none-live / has-failures);
/// `outbound`/`row_state`/`hit` accept comma-separated OR sets (header funnels are multi-select);
/// `hit` = HitLayer snake_case set; `source` = all|tun_relay (default hides TunRelay);
/// `sort` = "last|conns|target:asc|desc" (live targets always pin first).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn conlog_hosts(
    state: State<'_, AppState>,
    keyword: Option<String>,
    outbound: Option<String>,
    row_state: Option<String>,
    hit: Option<String>,
    source: Option<String>,
    sort: Option<String>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<HostQueryView, String> {
    let f = to_filter(keyword, outbound, row_state, hit, source, sort, from_ms, to_ms, offset, limit);
    let out = log_of(&state).query_hosts(&f);
    Ok(HostQueryView {
        total: out.total,
        items: out.items,
        sub_exits: sub_exit_map(&state).await,
    })
}

/// Aggregated page + subscription-kernel exit annotation: the anet inbound only sees the forward arm
/// ("handed to the subscription kernel"); what the kernel then decided (DIRECT by its own rules vs an
/// actual node vs REJECT) is merged in here so the 出口 column can tell 订阅放行 apart from 订阅·节点.
#[derive(Serialize)]
pub(crate) struct HostQueryView {
    total: usize,
    items: Vec<HostStat>,
    /// "host:port" (lowercased host) → kernel chain joined with " → " (last segment = final exit)
    sub_exits: std::collections::HashMap<String, String>,
}

/// Newest connection per target wins; empty map when the kernel is down (badges degrade to plain 订阅).
async fn sub_exit_map(state: &State<'_, AppState>) -> std::collections::HashMap<String, String> {
    let mut best: std::collections::HashMap<String, (u64, String)> = std::collections::HashMap::new();
    if !state.kernel.running().await {
        return std::collections::HashMap::new();
    }
    let (active, closed) = state.kernel.connections();
    for c in active.into_iter().chain(closed.into_iter()) {
        if c.host.is_empty() || c.port == 0 || c.chains.is_empty() {
            continue;
        }
        let key = format!("{}:{}", c.host.to_lowercase(), c.port);
        match best.get(&key) {
            Some((start, _)) if *start >= c.start => {}
            _ => {
                best.insert(key, (c.start, c.chains.join(" → ")));
            }
        }
    }
    best.into_iter().map(|(k, (_, chain))| (k, chain)).collect()
}

/// Per-connection page (ring layer; used by the row detail expand and the agent's conlog_recent).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn conlog_query(
    state: State<'_, AppState>,
    keyword: Option<String>,
    outbound: Option<String>,
    row_state: Option<String>,
    source: Option<String>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<QueryOut, String> {
    let f = to_filter(keyword, outbound, row_state, None, source, None, from_ms, to_ms, offset, limit);
    Ok(log_of(&state).query(&f))
}

/// Toggle recording (persisted). Disabling flushes the snapshot first, so nothing recorded is lost.
#[tauri::command]
pub(crate) async fn conlog_set_enabled(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    let log = log_of(&state);
    if !enabled {
        flush_now(&log);
    }
    log.set_enabled(enabled);
    {
        let mut r = state.roles.lock().await;
        r.conn_log_enabled = enabled;
        r.save()?;
    }
    roles::audit("gui.conlog_toggle", serde_json::json!({"enabled": enabled}));
    Ok(())
}

/// One-click clear: in-memory rows + aggregation map + the persistence file (incl. the legacy JSONL).
#[tauri::command]
pub(crate) async fn conlog_clear(state: State<'_, AppState>) -> Result<(), String> {
    let log = log_of(&state);
    log.clear();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = std::fs::remove_file(conn_stats_path());
        let _ = std::fs::remove_file(roles::data_dir().join("conn-log.jsonl")); // legacy P1 file
    })
    .await;
    roles::audit("gui.conlog_clear", serde_json::json!({}));
    Ok(())
}

/// Force-close every active connection to a target (aggregated row right-click 强制打断);
/// fired rows finalize as Closed. Returns how many connections were killed.
#[tauri::command]
pub(crate) async fn conlog_kill_target(
    state: State<'_, AppState>,
    host: String,
    port: u16,
) -> Result<u32, String> {
    Ok(log_of(&state).kill_target(&host, port))
}

/// Force-close one active connection by id (kept for the agent tool / future per-conn UI).
#[tauri::command]
pub(crate) async fn conlog_kill(state: State<'_, AppState>, id: u64) -> Result<bool, String> {
    Ok(log_of(&state).kill(id))
}

/// Write the snapshot (tmp + rename; blocking IO off the async path, fire-and-forget).
fn flush_now(log: &Arc<ConnLog>) {
    let rows = log.stats_snapshot();
    let path = conn_stats_path();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into());
        let ok = std::fs::File::create(&tmp)
            .and_then(|mut f| f.write_all(body.as_bytes()))
            .and_then(|_| std::fs::rename(&tmp, &path));
        if let Err(e) = ok {
            tracing::warn!(error = %e, "conn-stats snapshot flush failed");
        }
    });
}

/// Smart flush loop (5s tick): flush when dirty; additionally a 30s sweep while connections are active
/// (long-lived connections only move byte counters, which never set the dirty flag).
fn spawn_flush_task(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut last = std::time::Instant::now();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let log = app.state::<AppState>().client.conn_log();
            let dirty = log.take_dirty();
            let idle_due = last.elapsed() >= std::time::Duration::from_secs(30) && log.has_active();
            if !dirty && !idle_due {
                continue;
            }
            flush_now(&log);
            last = std::time::Instant::now();
        }
    });
}

/// Startup wiring (lib.rs setup): replay the persisted baselines, restore enabled/tun-relay flags,
/// spawn the smart-flush task.
pub(crate) fn init_conn_log(app: &AppHandle) {
    let log = app.state::<AppState>().client.conn_log();
    if let Ok(content) = std::fs::read_to_string(conn_stats_path()) {
        if let Ok(rows) = serde_json::from_str(&content) {
            log.restore_stats(rows);
        }
    }
    let roles = RoleSettings::load();
    log.set_tun_relay(roles.tun_mode);
    log.set_enabled(roles.conn_log_enabled);
    spawn_flush_task(app.clone());
}
