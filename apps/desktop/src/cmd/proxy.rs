//! Split out of lib.rs: local proxy and system proxy management (pure move, zero logic changes)

use crate::{map_err, roles, sysproxy, AppState};
use serde::Serialize;
use tauri::{Manager, State};

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
}

/// Shared start-local-proxy logic (reused by the start_proxy command / proxy_power_toggle):
/// engages the system proxy per the system_proxy role preference (idempotent; the snapshot is never overwritten twice).
/// Locked mode (sysproxy_lock) counts as managed too: the patrol would reclaim within 30s anyway,
/// engaging here keeps the takeover immediate and the snapshot semantics identical.
pub(crate) async fn start_proxy_inner(app: &tauri::AppHandle, state: &State<'_, AppState>, port: u16) -> Result<u16, String> {
    if !state.roles.lock().await.client {
        return Err("扇入已停用，请在首页开启".into());
    }
    state.client.start_proxy(port).await.map_err(map_err)?;
    crate::refresh_tray_icon(app);
    let managed = {
        let r = state.roles.lock().await;
        r.system_proxy || r.sysproxy_lock
    };
    if managed {
        let server = expected_sysproxy(state);
        let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
    }
    crate::report_client_proxy(state).await;
    Ok(state.client.proxy_port())
}

/// Shared stop-local-proxy logic: restores the system proxy whenever it is managed (preference on,
/// locked mode, or both) — the system proxy must never be left pointing at a dead port;
/// the mode preference is kept, so the next start takes over automatically.
pub(crate) async fn stop_proxy_inner(app: &tauri::AppHandle, state: &State<'_, AppState>) -> Result<(), String> {
    state.client.stop_proxy().await;
    let managed = {
        let r = state.roles.lock().await;
        r.system_proxy || r.sysproxy_lock
    };
    if managed {
        let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
    }
    crate::report_client_proxy(state).await;
    crate::refresh_tray_icon(app);
    Ok(())
}

/// Start the local proxy
#[tauri::command]
pub(crate) async fn start_proxy(app: tauri::AppHandle, state: State<'_, AppState>, port: u16) -> Result<u16, String> {
    start_proxy_inner(&app, &state, port).await
}

/// Stop the local proxy
#[tauri::command]
pub(crate) async fn stop_proxy(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    stop_proxy_inner(&app, &state).await
}

/// Global power-switch state (home dashboard; proxy_power response body)
#[derive(Debug, Clone, Serialize)]
pub struct PowerState {
    /// Whether the local proxy is listening
    pub on: bool,
    /// Listen address (e.g. 127.0.0.1:57890) or "stopped"
    pub detail: String,
}

/// Snapshot of the current power state (pure in-memory read, no network IO, safe for frontend polling).
pub(crate) fn power_state_of(state: &State<'_, AppState>) -> PowerState {
    let port = state.client.proxy_port();
    PowerState {
        on: port > 0,
        detail: if port > 0 { format!("127.0.0.1:{port}") } else { "已停止".into() },
    }
}

/// Query the global power state (cheap to poll)
#[tauri::command]
pub(crate) async fn proxy_power(state: State<'_, AppState>) -> Result<PowerState, String> {
    Ok(power_state_of(&state))
}

/// Global power toggle: on -> stop (including system proxy restore); off -> start (default port 57890,
/// taking over the system proxy per the system_proxy role preference). TUN and system proxy are mutually exclusive; direct toggle is forbidden while TUN runs.
#[tauri::command]
pub(crate) async fn proxy_power_toggle(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<PowerState, String> {
    if state.roles.lock().await.tun_mode {
        return Err("TUN 模式运行中，请先关闭 TUN".into());
    }
    if state.client.proxy_port() > 0 {
        stop_proxy_inner(&app, &state).await?;
    } else {
        // Same default port as auto-start from the "Connect" page / system proxy
        start_proxy_inner(&app, &state, 57890).await?;
    }
    let st = power_state_of(&state);
    roles::audit("gui.proxy_power", serde_json::json!({"on": st.on, "detail": st.detail}));
    Ok(st)
}

/// Proxy status
#[tauri::command]
pub(crate) async fn proxy_status(state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    let port = state.client.proxy_port();
    Ok(ProxyStatus {
        running: port > 0,
        port,
    })
}

// ==================== System proxy management ====================

/// Expected system proxy value (local proxy port).
pub(crate) fn expected_sysproxy(state: &State<'_, AppState>) -> String {
    format!("127.0.0.1:{}", state.client.proxy_port())
}

#[tauri::command]
pub(crate) async fn set_system_proxy(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    if enabled {
        // Auto-start the local proxy if not running (default port 57890, same as the "Connect" page),
        // removing the "must start the local proxy manually first" ordering trap
        if state.client.proxy_port() == 0 {
            if !state.roles.lock().await.client {
                return Err("扇入已停用，请在首页开启".into());
            }
            state.client.start_proxy(57890).await.map_err(map_err)?;
        }
        let server = expected_sysproxy(&state);
        tokio::task::spawn_blocking(move || sysproxy::engage(&server))
            .await
            .map_err(map_err)??;
    } else {
        tokio::task::spawn_blocking(sysproxy::disengage)
            .await
            .map_err(map_err)??;
    }
    {
        let mut roles = state.roles.lock().await;
        roles.system_proxy = enabled;
        roles.save()?;
    }
    crate::report_client_proxy(&state).await;
    Ok(())
}

#[tauri::command]
pub(crate) async fn sysproxy_status(state: State<'_, AppState>) -> Result<sysproxy::SysProxyStatus, String> {
    // TUN mode / locked mode count as managed (system proxy points at 57890; watch auto-reclaims)
    let managed = {
        let r = state.roles.lock().await;
        r.system_proxy || r.tun_mode || r.sysproxy_lock
    };
    let running = state.client.proxy_port() > 0;
    let expected = expected_sysproxy(&state);
    let mut st = tokio::task::spawn_blocking(move || sysproxy::inspect(managed, &expected))
        .await
        .map_err(map_err)??;
    // No conflict when the proxy is not running: startup cleanup already restored leftovers,
    // and in default system proxy mode "proxy not started yet" is not a takeover
    if !running {
        st.conflict = false;
    }
    Ok(st)
}

#[tauri::command]
pub(crate) async fn reclaim_sysproxy(state: State<'_, AppState>) -> Result<(), String> {
    let server = expected_sysproxy(&state);
    tokio::task::spawn_blocking(move || sysproxy::reclaim(&server))
        .await
        .map_err(map_err)?
}

// ==================== Proxy mode tri-state (floating ball menu) ====================

/// Current proxy mode: tun (TUN takeover) / system (local proxy + system proxy) / local (local proxy only).
#[tauri::command]
pub(crate) async fn proxy_mode_get(state: State<'_, AppState>) -> Result<String, String> {
    let r = state.roles.lock().await;
    Ok(if r.tun_mode {
        "tun"
    } else if r.system_proxy {
        "system"
    } else {
        "local"
    }
    .to_string())
}

/// Set the proxy mode (floating ball menu). Returns the mode string actually in effect.
/// - "tun": reuses the full set_tun_mode enable path (§2.2 admin check NEED_ELEVATION / artifact download errors passed through verbatim)
/// - "system" / "local": turns TUN off first if on (reuses the set_tun_mode disable path); starts the local proxy if not running (57890);
///   then engages / disengages the system proxy per mode and persists the preference
#[tauri::command]
pub(crate) async fn proxy_mode_set(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    mode: String,
) -> Result<String, String> {
    match mode.as_str() {
        "tun" => {
            crate::set_tun_mode(app, state, true).await?;
            roles::audit("gui.proxy_mode", serde_json::json!({"mode": "tun"}));
            Ok("tun".to_string())
        }
        "system" | "local" => {
            if state.roles.lock().await.tun_mode {
                crate::set_tun_mode(app.clone(), state.clone(), false).await?;
            }
            // Auto-start the local proxy if not running (start_proxy_inner validates the fan-in role; default port same as the "Connect" page)
            if state.client.proxy_port() == 0 {
                start_proxy_inner(&app, &state, 57890).await?;
            }
            if mode == "system" {
                let server = expected_sysproxy(&state);
                tokio::task::spawn_blocking(move || sysproxy::engage(&server))
                    .await
                    .map_err(map_err)??;
            } else {
                tokio::task::spawn_blocking(sysproxy::disengage)
                    .await
                    .map_err(map_err)??;
            }
            {
                let mut roles = state.roles.lock().await;
                roles.system_proxy = mode == "system";
                roles.save()?;
            }
            crate::report_client_proxy(&state).await;
            crate::emit_settings(&app, &state).await;
            roles::audit("gui.proxy_mode", serde_json::json!({"mode": mode}));
            Ok(mode)
        }
        _ => Err(format!("非法代理方式: {mode}")),
    }
}

/// System proxy takeover toggle (floating ball menu): restores if the system proxy already points at the expected
/// value (returns false), otherwise takes over (returns true). Unlike set_system_proxy: the direction is decided by an inspect probe, so the frontend need not query state first.
#[tauri::command]
pub(crate) async fn sysproxy_toggle(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    if state.roles.lock().await.tun_mode {
        return Err("TUN 模式运行中，请先关闭 TUN".into());
    }
    let expected = expected_sysproxy(&state);
    let engaged = {
        let st = tokio::task::spawn_blocking(move || sysproxy::inspect(true, &expected))
            .await
            .map_err(map_err)??;
        !st.current.is_empty() && st.current == st.expected
    };
    let on = !engaged;
    if on {
        if state.client.proxy_port() == 0 {
            start_proxy_inner(&app, &state, 57890).await?;
        }
        let server = expected_sysproxy(&state);
        tokio::task::spawn_blocking(move || sysproxy::engage(&server))
            .await
            .map_err(map_err)??;
    } else {
        tokio::task::spawn_blocking(sysproxy::disengage)
            .await
            .map_err(map_err)??;
    }
    {
        let mut roles = state.roles.lock().await;
        roles.system_proxy = on;
        roles.save()?;
    }
    crate::report_client_proxy(&state).await;
    roles::audit("gui.sysproxy_toggle", serde_json::json!({"on": on}));
    Ok(on)
}

/// System proxy conflict watch (30s): while managed, any system value != expected is audited.
/// TUN mode (§2.6) and locked mode (sysproxy_lock) escalate to auto-reclaim: on takeover, rewrite the expected
/// value and audit (including the offending value; lock-sourced entries note lock:true in detail), every round;
/// without auto-reclaim, keep "remind to reclaim manually" (each conflict round audited once, re-armed after recovery).
pub(crate) async fn sysproxy_watch(app: tauri::AppHandle) {
    let mut in_conflict = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let state = app.state::<AppState>();
        let (pref, tun_mode, lock) = {
            let r = state.roles.lock().await;
            (r.system_proxy, r.tun_mode, r.sysproxy_lock)
        };
        // TUN mode and locked mode count as managed (auto-reclaim policy); no conflict when the proxy is not running (same as sysproxy_status)
        let managed = pref || tun_mode || lock;
        if !managed || state.client.proxy_port() == 0 {
            in_conflict = false;
            continue;
        }
        let expected = expected_sysproxy(&state);
        if let Ok(Ok(st)) =
            tokio::task::spawn_blocking(move || sysproxy::inspect(true, &expected)).await
        {
            if st.conflict && (tun_mode || lock) {
                roles::audit(
                    "gui.sysproxy_conflict",
                    serde_json::json!({"expected": st.expected, "current": st.current, "auto_reclaim": true, "lock": lock}),
                );
                let server = st.expected.clone();
                let _ = tokio::task::spawn_blocking(move || sysproxy::reclaim(&server)).await;
                crate::float_notify(&app, "系统代理被修改，已自动收回");
            } else if st.conflict && !in_conflict {
                roles::audit(
                    "gui.sysproxy_conflict",
                    serde_json::json!({"expected": st.expected, "current": st.current}),
                );
                crate::float_notify(&app, "检测到系统代理冲突");
            }
            in_conflict = st.conflict;
        }
    }
}
