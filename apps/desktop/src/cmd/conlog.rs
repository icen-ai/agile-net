//! Split out of lib.rs-style cmd layout: connection log commands (design docs/todo/conn-log.md).
//!
//! The engine-owned ConnLog (state.client.conn_log()) records one row per local-proxy inbound connection
//! across Direct/Tunnel/Forward with the hit layer. Enabled flag persists as roles.conn_log_enabled
//! (default off — records are browsing history, strictly opt-in). Persistence is the smart-flush task:
//! JSONL append to ~/.anet/gui/conn-log.jsonl on batch (>=200 unflushed) / 30s idle sweep / disable,
//! never per-record writes; startup replays the tail into memory. Clear removes memory + file.

use crate::{roles, AppState};
use agile_net_core::proxy::conlog::{ConnFilter, ConnLog, ConnRec, QueryOut, CONLOG_FLUSH_BATCH};
use roles::RoleSettings;
use serde::Serialize;
use std::sync::Arc;
use tauri::{AppHandle, Manager, State};

/// Persistence file (~/.anet/gui/conn-log.jsonl)
pub(crate) fn conn_log_path() -> std::path::PathBuf {
    roles::data_dir().join("conn-log.jsonl")
}

fn log_of(state: &State<'_, AppState>) -> Arc<ConnLog> {
    state.client.conn_log()
}

/// Toolbar status: enabled flag + session totals (active count and live up/down included)
#[derive(Serialize)]
pub struct ConlogStatus {
    pub enabled: bool,
    pub active: usize,
    pub closed: usize,
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
        closed: t.closed,
        up: t.up,
        down: t.down,
    })
}

/// Filtered/paged query (50-row pages driven by the frontend's offset/limit).
/// `row_state` = active|closed|failed; `outbound` = direct|tunnel|forward; `source` = all|tun_relay (default hides TunRelay).
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
    let f = ConnFilter {
        keyword,
        outbound,
        state: row_state,
        source,
        from_ms,
        to_ms,
        offset: offset.unwrap_or(0),
        limit: limit.unwrap_or(50),
    };
    Ok(log_of(&state).query(&f))
}

/// Toggle recording (persisted). Disabling flushes everything pending first, so nothing recorded is lost.
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

/// One-click clear: in-memory rows + pending buffer + the persistence file.
#[tauri::command]
pub(crate) async fn conlog_clear(state: State<'_, AppState>) -> Result<(), String> {
    let log = log_of(&state);
    log.clear();
    let path = conn_log_path();
    let _ = tokio::task::spawn_blocking(move || std::fs::remove_file(path)).await;
    roles::audit("gui.conlog_clear", serde_json::json!({}));
    Ok(())
}

/// Force-close an active connection (row right-click 强制打断); the row finalizes as Closed.
#[tauri::command]
pub(crate) async fn conlog_kill(state: State<'_, AppState>, id: u64) -> Result<bool, String> {
    Ok(log_of(&state).kill(id))
}

/// Append pending rows to the JSONL file (blocking IO off the async path, fire-and-forget).
fn flush_now(log: &Arc<ConnLog>) {
    let rows = log.take_unflushed();
    if rows.is_empty() {
        return;
    }
    let path = conn_log_path();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else {
            return;
        };
        for r in &rows {
            if let Ok(line) = serde_json::to_string(r) {
                let _ = writeln!(f, "{line}");
            }
        }
    });
}

/// Smart flush loop (5s tick): flush on batch (>= CONLOG_FLUSH_BATCH unflushed) or a 30s idle sweep.
fn spawn_flush_task(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut last = std::time::Instant::now();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let log = app.state::<AppState>().client.conn_log();
            let n = log.unflushed_len();
            let idle_due = last.elapsed() >= std::time::Duration::from_secs(30);
            if n == 0 || (n < CONLOG_FLUSH_BATCH && !idle_due) {
                continue;
            }
            flush_now(&log);
            last = std::time::Instant::now();
        }
    });
}

/// Startup wiring (lib.rs setup): replay the JSONL tail into memory, restore enabled/tun-relay flags,
/// spawn the smart-flush task.
pub(crate) fn init_conn_log(app: &AppHandle) {
    let log = app.state::<AppState>().client.conn_log();
    if let Ok(content) = std::fs::read_to_string(conn_log_path()) {
        let rows = content
            .lines()
            .filter_map(|l| serde_json::from_str::<ConnRec>(l).ok())
            .collect::<Vec<_>>();
        log.restore(rows);
    }
    let roles = RoleSettings::load();
    log.set_tun_relay(roles.tun_mode);
    log.set_enabled(roles.conn_log_enabled);
    spawn_flush_task(app.clone());
}
