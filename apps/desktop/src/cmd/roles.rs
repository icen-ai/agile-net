//! Split from lib.rs: role toggles (client / server / web remote / subscription / TUN) and preferences (pure move, zero logic change)

use crate::roles::{self, RoleSettings};
use crate::tun::{self, Elevation};
use crate::{download, map_err, subscription, sysproxy, AppState};
#[cfg(windows)]
use crate::floatball;
use agile_net_node::service::NodeServer;
use serde::Serialize;
use std::sync::Arc;
use tauri::{Emitter, Manager, State};

/// Enable/disable autostart on boot (desktop-only capability)
#[tauri::command]
pub(crate) fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    #[cfg(desktop)]
    {
        use tauri_plugin_autostart::ManagerExt;
        let manager = app.autolaunch();
        if enabled {
            return manager.enable().map_err(map_err);
        }
        return manager.disable().map_err(map_err);
    }
    #[cfg(not(desktop))]
    {
        let _ = (app, enabled);
        Err("开机自启为桌面端能力".into())
    }
}

/// Query autostart-on-boot status (mobile: always false)
#[tauri::command]
pub(crate) fn get_autostart(app: tauri::AppHandle) -> Result<bool, String> {
    #[cfg(desktop)]
    {
        use tauri_plugin_autostart::ManagerExt;
        return app.autolaunch().is_enabled().map_err(map_err);
    }
    #[cfg(not(desktop))]
    {
        let _ = app;
        Ok(false)
    }
}

// ==================== Three role toggles (client / server / web remote) ====================

#[derive(Debug, Clone, Serialize)]
pub struct ServerStatus {
    pub running: bool,
    pub has_admin: bool,
    pub api_addr: String,
    pub relay_addr: String,
    /// Relay cert SHA-256 fingerprint (for fan-out peers to pin; None while not running)
    pub cert_fingerprint: Option<String>,
    /// Public endpoint host shown in connect_url (DB node_config.public_host; empty = default 127.0.0.1)
    pub public_host: String,
    /// (target addr, status) per fan-out connection (live while running; empty otherwise)
    pub connectors: Vec<(String, String)>,
}

#[tauri::command]
pub(crate) async fn get_role_settings(state: State<'_, AppState>) -> Result<RoleSettings, String> {
    Ok(state.roles.lock().await.clone())
}

/// Broadcast the current role settings to every window (`ag-roles`; float-ball / tray mode
/// switches must converge the main window's `_rolesCache` immediately, not on the next poll —
/// web.md §1.3). Fire-and-forget: no listener is required for correctness.
pub(crate) async fn emit_settings(app: &tauri::AppHandle, state: &State<'_, AppState>) {
    let settings = state.roles.lock().await.clone();
    let _ = app.emit("ag-roles", settings);
}

/// Toggle A: client role. Disabling disconnects all nodes and stops the local proxy.
#[tauri::command]
pub(crate) async fn set_client_role(app: tauri::AppHandle, state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    if !enabled {
        state.client.disconnect_all().await;
        // every node-scoped console forwarder dies with the client role (local|<upstream>
        // forwarders belong to the server role and are unaffected)
        super::misc::drop_console_forwarders(&state, |k| !k.starts_with("local|")).await;
        // Stop through the shared inner so a managed system proxy (preference on / locked) is
        // restored too — it must never keep pointing at the now-dead port
        super::proxy::stop_proxy_inner(&app, &state).await?;
    }
    let mut roles = state.roles.lock().await;
    roles.client = enabled;
    roles.save()?;
    drop(roles);
    roles::audit("gui.role_toggle", serde_json::json!({"role": "client", "on": enabled}));
    Ok(())
}

/// Server role runtime status.
#[tauri::command]
pub(crate) async fn server_status(state: State<'_, AppState>) -> Result<ServerStatus, String> {
    let connectors = {
        let slot = state.server.lock().await;
        slot.as_ref().map(|s| s.connector_states()).unwrap_or_default()
    };
    let cert_fingerprint = {
        let slot = state.server.lock().await;
        slot.as_ref().and_then(|s| s.runtime().cert_fingerprint.clone())
    };
    let running = state.server.lock().await.is_some();
    let has_admin = roles::open_embedded_db()
        .and_then(|db| db.has_admin().map_err(|e| e.to_string()))
        .unwrap_or(false);
    let public_host = roles::open_embedded_db()
        .and_then(|db| db.get_config("public_host").map_err(|e| e.to_string()))
        .ok()
        .flatten()
        .unwrap_or_default();
    Ok(ServerStatus {
        running,
        has_admin,
        api_addr: roles::EMBEDDED_API_ADDR.into(),
        relay_addr: roles::EMBEDDED_RELAY_ADDR.into(),
        cert_fingerprint,
        public_host,
        connectors,
    })
}

/// Set the embedded node's public endpoint host (written to node_config.public_host; hot — the next
/// generated connect_url uses it immediately, no server-role restart needed; empty = default 127.0.0.1).
#[tauri::command]
pub(crate) async fn set_server_public_host(host: String) -> Result<(), String> {
    let host = host.trim();
    if host.len() > 253 || host.contains('/') || host.contains(' ') {
        return Err("对外地址格式非法（应为 IP 或域名，不含路径与空格）".into());
    }
    let db = roles::open_embedded_db()?;
    db.set_config("public_host", host).map_err(map_err)?;
    roles::audit("gui.fanout_change", serde_json::json!({"action": "public_host", "host": host}));
    Ok(())
}

/// First-run forced admin password: create the embedded node admin (argon2id hash persisted to db).
#[tauri::command]
pub(crate) async fn init_server_admin(username: String, password: String) -> Result<(), String> {
    if username.trim().is_empty() {
        return Err("管理员账号不能为空".into());
    }
    if password.len() < 10 {
        return Err("管理密码至少 10 位".into());
    }
    let db = roles::open_embedded_db()?;
    if db.has_admin().map_err(|e| e.to_string())? {
        return Err("管理员已存在，请在控制台内变更".into());
    }
    let hash = agile_net_node::db::hash_password(&password).map_err(map_err)?;
    db.create_admin(username.trim(), &hash).map_err(map_err)?;
    Ok(())
}

/// Start the embedded node (reads current role config; injects client engine routes before publishing).
pub(crate) async fn start_embedded_node(state: &State<'_, AppState>) -> Result<NodeServer, String> {
    NodeServer::start_with(
        roles::build_embedded_config(),
        agile_net_node::service::NodeServerOptions {
            db_path: Some(roles::embedded_db_path().to_string_lossy().to_string()),
            api_listen: Some(roles::EMBEDDED_API_ADDR.into()),
            skip_env_seed: true,
            client_routes: Some((
                state.client.shared_router_handle(),
                state.client.openers_handle(),
            )),
            client_proxy_slot: state.client_proxy_slot.clone(),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        let msg = format!("{e:#}");
        format!("内嵌节点启动失败: {msg}{}", bind_hint(&msg))
    })
}

/// Actionable hints for common Windows bind failures (appended to the startup error toast).
fn bind_hint(msg: &str) -> &'static str {
    if msg.contains("os error 10013") {
        "（端口被系统保留或安全软件拦截：运行 netsh interface ipv4 show excludedportrange protocol=tcp 查系统保留段（Hyper-V/WSL2/Docker 常见），netsh interface portproxy show all 查端口代理规则，并检查 360/火绒等安全软件的联网控制）"
    } else if msg.contains("os error 10048") {
        "（端口已被占用：检查是否有残留的 anet 进程，或更换端口）"
    } else {
        ""
    }
}

/// Toggle B: server role. Enabling starts the embedded node (admin password required first); disabling stops it.
#[tauri::command]
pub(crate) async fn set_server_role(state: State<'_, AppState>, enabled: bool) -> Result<ServerStatus, String> {
    if enabled {
        let has_admin = roles::open_embedded_db()
            .and_then(|db| db.has_admin().map_err(|e| e.to_string()))
            .unwrap_or(false);
        if !has_admin {
            return Err("NO_ADMIN:首开服务端角色须先设置管理密码".into());
        }
        let mut slot = state.server.lock().await;
        if slot.is_none() {
            let server = start_embedded_node(&state).await?;
            tracing::info!(api = %server.api_addr(), "embedded node started");
            *slot = Some(server);
        }
    } else {
        let server = state.server.lock().await.take();
        if let Some(s) = server {
            s.stop().await;
        }
        // server-role upstream consoles (local|<upstream> forwarders) die with the server role
        super::misc::drop_console_forwarders(&state, |k| k.starts_with("local|")).await;
    }
    {
        let mut roles = state.roles.lock().await;
        roles.server = enabled;
        roles.save()?;
    }
    roles::audit("gui.role_toggle", serde_json::json!({"role": "server", "on": enabled}));
    server_status(state).await
}

#[tauri::command]
pub(crate) async fn has_web_password() -> Result<bool, String> {
    Ok(roles::has_web_password())
}

/// Set the web remote admin password (argon2id hash persisted to disk).
#[tauri::command]
pub(crate) async fn set_web_password(password: String) -> Result<(), String> {
    roles::set_web_password(&password)?;
    roles::audit("web.exposure_change", serde_json::json!({"change": "password_set"}));
    Ok(())
}

/// Toggle C: web remote. Admin password mandatory first; enabling starts the admin Web API on the listen addr.
#[tauri::command]
pub(crate) async fn set_web_role(state: State<'_, AppState>, enabled: bool, listen: Option<String>) -> Result<(), String> {
    if enabled && !roles::has_web_password() {
        return Err("NO_WEB_PASSWORD:开启 Web 远程面须先设置管理密码".into());
    }
    let listen = listen.filter(|s| !s.trim().is_empty());
    if let Some(l) = &listen {
        l.parse::<std::net::SocketAddr>()
            .map_err(|_| "监听地址格式应为 host:port".to_string())?;
    }
    let target_listen = {
        let mut roles = state.roles.lock().await;
        let old_listen = roles.web_listen.clone();
        roles.web = enabled;
        if let Some(l) = listen {
            roles.web_listen = l;
        }
        let new_listen = roles.web_listen.clone();
        roles.save()?;
        if enabled && old_listen != new_listen {
            roles::audit("web.exposure_change", serde_json::json!({"listen": new_listen}));
        }
        new_listen
    };

    // Stop the old instance first (listen addr changed or disabled), then start as needed
    if let Some(h) = state.web_api.lock().await.take() {
        h.stop().await;
    }
    if enabled {
        let addr: std::net::SocketAddr = target_listen.parse().map_err(|_| "监听地址格式应为 host:port".to_string())?;
        if addr.ip().is_unspecified() {
            tracing::warn!(addr = %addr, "web 远程面监听在全部网卡——请确认已设强管理密码");
        }
        let handle = agile_net_client::api::start_client_api(
            state.client.clone(),
            state.creds.as_ref().clone(),
            Arc::new(roles::DesktopWebAuth),
            addr,
            Some(crate::spa_assets()),
        )
        .await
        .map_err(|e| format!("Web 远程面启动失败: {e}"))?;
        tracing::info!(addr = %handle.addr(), "web remote api started");
        *state.web_api.lock().await = Some(handle);
    }
    roles::audit("gui.role_toggle", serde_json::json!({"role": "web", "on": enabled, "listen": target_listen}));
    Ok(())
}

/// Theme change broadcast: console window (external-source SPA) follows the main window theme in real time via Tauri events
#[tauri::command]
pub(crate) fn broadcast_theme(app: tauri::AppHandle, theme: String) -> Result<(), String> {
    use tauri::Emitter;
    #[cfg(windows)]
    floatball::set_dark(theme == "dark");
    app.emit("ag-theme", theme).map_err(map_err)
}

/// Restore the server role at startup (it was enabled at last exit).
pub(crate) async fn restore_server_role(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    let enabled = state.roles.lock().await.server;
    if !enabled {
        return;
    }
    let has_admin = roles::open_embedded_db()
        .and_then(|db| db.has_admin().map_err(|e| e.to_string()))
        .unwrap_or(false);
    if !has_admin {
        tracing::warn!("server role was enabled but no admin exists — keeping embedded node stopped");
        return;
    }
    match start_embedded_node(&state).await {
        Ok(server) => {
            tracing::info!(api = %server.api_addr(), "embedded node restored");
            *state.server.lock().await = Some(server);
        }
        Err(e) => tracing::error!(error = %e, "failed to restore embedded node"),
    }
}

/// Restore web remote at startup (was enabled at last exit and an admin password is set).
pub(crate) async fn restore_web_role(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    let (enabled, listen) = {
        let r = state.roles.lock().await;
        (r.web, r.web_listen.clone())
    };
    if !enabled || !roles::has_web_password() {
        return;
    }
    let addr: std::net::SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!(listen = %listen, "invalid web listen addr, skipping restore");
            return;
        }
    };
    match agile_net_client::api::start_client_api(
        state.client.clone(),
        state.creds.as_ref().clone(),
        Arc::new(roles::DesktopWebAuth),
        addr,
        Some(crate::spa_assets()),
    )
    .await
    {
        Ok(handle) => {
            tracing::info!(addr = %handle.addr(), "web remote api restored");
            *state.web_api.lock().await = Some(handle);
        }
        Err(e) => tracing::error!(error = %e, "failed to restore web remote api"),
    }
}

// ==================== TUN mode (docs/plan/tun.md P1: anet in front, FlClash behind) ====================

/// TUN status (polled by frontend: running / insufficient privileges / upstream unreachable)
#[derive(Debug, Clone, Serialize)]
pub struct TunStatus {
    /// Current platform supports TUN (Windows x64 and kernel installable)
    pub supported: bool,
    /// TUN toggle (persisted)
    pub enabled: bool,
    /// Kernel running (configured as TUN skeleton)
    pub running: bool,
    /// Current process is already admin
    pub admin: bool,
    /// External upstream (fallback target)
    pub upstream: String,
    /// Latest probe result (None = not probed yet)
    pub upstream_ok: Option<bool>,
    /// One-shot notice for an abandoned enable (cleared on read; frontend toasts it once)
    pub notice: Option<String>,
}

/// Unified fallback for abandoning a TUN enable: persist toggle off + audit + one-shot notice.
/// Semantics (per user request): TUN is an independent option; quietly abandon on privilege/start failure, never affecting other features.
pub(crate) async fn abandon_tun(app: &tauri::AppHandle, state: &State<'_, AppState>, reason: &str) {
    {
        let mut roles = state.roles.lock().await;
        roles.tun_mode = false;
        let _ = roles.save();
    }
    // the conlog TunRelay marking must follow too — otherwise every record begun after the abandon
    // is still marked TunRelay and hidden by default (连接记录「看起来空了」的根因)
    state.client.conn_log().set_tun_relay(false);
    roles::audit("gui.tun_abandon", serde_json::json!({"reason": reason}));
    *state.tun_notice.lock().await = Some(format!(
        "TUN 已放弃开启：{reason}（已回退普通模式，不影响其它功能）"
    ));
    emit_settings(app, state).await;
}

pub(crate) async fn tun_status_of(state: &State<'_, AppState>) -> TunStatus {
    let (enabled, upstream) = {
        let r = state.roles.lock().await;
        (r.tun_mode, r.external_upstream.clone())
    };
    TunStatus {
        supported: cfg!(all(target_os = "windows", target_arch = "x86_64"))
            && subscription::kernel_supported(),
        enabled,
        running: enabled && state.kernel.running().await,
        admin: tun::SystemElevation.is_admin(),
        upstream,
        upstream_ok: *state.tun_upstream_ok.lock().await,
        notice: state.tun_notice.lock().await.take(),
    }
}

#[tauri::command]
pub(crate) async fn tun_status(state: State<'_, AppState>) -> Result<TunStatus, String> {
    Ok(tun_status_of(&state).await)
}

/// Data-plane/system-proxy side effects after enabling TUN (shared by enable and elevated-relaunch restore):
/// pin local proxy to 57890 (ANET-IN target) → fallback = external upstream → system proxy auto-takeover of 57890 (§2.6)
/// → probe external upstream once over TCP (unreachable only triggers a frontend Dynamic Island alert, non-blocking; §2.4).
pub(crate) async fn tun_side_effects(app: &tauri::AppHandle, state: &State<'_, AppState>) -> Result<(), String> {
    let port = state.client.proxy_port();
    if port != 57890 {
        if port > 0 {
            state.client.stop_proxy().await;
        }
        state.client.start_proxy(57890).await.map_err(map_err)?;
        crate::report_client_proxy(app, state).await;
        crate::refresh_tray_icon(app);
    }
    crate::apply_proxy_fallback(state).await;
    let server = crate::expected_sysproxy(state);
    let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
    // Probe the effective fallback target (subscription exit or external upstream; unreachable only triggers a frontend Dynamic Island alert, non-blocking; §2.4)
    let ok = match crate::effective_fallback(state).await {
        Some(sa) => tun::tcp_reachable(sa).await,
        None => false,
    };
    *state.tun_upstream_ok.lock().await = Some(ok);
    Ok(())
}

/// TUN mode toggle (§2.2 elevation / §2.4 fallback / §2.5 mutual exclusion / §2.6 system proxy).
#[tauri::command]
pub(crate) async fn set_tun_mode(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<TunStatus, String> {
    if enabled {
        // §2.2 admin elevation: non-admin → NEED_ELEVATION (frontend shows a dialog and takes the runas relaunch path)
        tun::precheck(&tun::SystemElevation)?;
        // Missing artifact is no longer downloaded on the spot: start a background download and return NEED_DOWNLOAD; frontend shows a download card and auto-retries on completion
        if !subscription::kernel_bin_exists() {
            state.dl.start(download::Artifact::Kernel)?;
            return Err(format!(
                "{}订阅内核未安装，正在后台下载",
                subscription::NEED_DOWNLOAD_PREFIX
            ));
        }
        // §2.1 wintun.dll: passes if already present or a local candidate is reused; still missing → background download
        if let Err(e) = subscription::ensure_wintun().await {
            if e.starts_with(subscription::NEED_DOWNLOAD_PREFIX) {
                state.dl.start(download::Artifact::Wintun)?;
                return Err(format!(
                    "{}wintun 组件未安装，正在后台下载",
                    subscription::NEED_DOWNLOAD_PREFIX
                ));
            }
            return Err(e);
        }
        if subscription::list_subscriptions().is_empty() {
            return Err("请先添加订阅".into());
        }
        {
            let mut roles = state.roles.lock().await;
            // §2.4 fallback target validity (hard constraint; refuse to enable on violation)
            roles::validate_external_upstream(&roles.external_upstream)?;
            roles.tun_mode = true;
            roles.subscription = true;
            roles.save()?;
        }
        roles::audit(
            "gui.tun_enable",
            serde_json::json!({"upstream": state.roles.lock().await.external_upstream}),
        );
        // Restart kernel to load the TUN skeleton + data-plane side effects; any failure rolls back entirely to normal mode (subscription unaffected)
        state.kernel.stop().await;
        let start_result = match state.kernel.start().await {
            Ok(()) => tun_side_effects(&app, &state).await,
            Err(e) => Err(e),
        };
        if let Err(e) = start_result {
            abandon_tun(&app, &state, &format!("启动失败（{e}）")).await;
            // After rollback, try restarting the kernel in normal mode so the subscription role stays usable
            let _ = state.kernel.start().await;
            crate::apply_proxy_fallback(&state).await;
            return Err(format!("TUN 开启失败，已回退普通模式: {e}"));
        }
        emit_settings(&app, &state).await;
    } else {
        {
            let mut roles = state.roles.lock().await;
            roles.tun_mode = false;
            roles.save()?;
        }
        roles::audit("gui.tun_disable", serde_json::json!({}));
        *state.tun_upstream_ok.lock().await = None;
        // Kernel returns to normal config (subscription role stays on)
        state.kernel.stop().await;
        state.kernel.start().await?;
        crate::apply_proxy_fallback(&state).await;
        // §2.6 TUN off: restore the system proxy snapshot; if the system proxy preference is still on and the proxy is running, re-take over per preference
        let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
        let system_pref = state.roles.lock().await.system_proxy;
        if system_pref && state.client.proxy_port() > 0 {
            let server = crate::expected_sysproxy(&state);
            let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
        }
        emit_settings(&app, &state).await;
    }
    // Connection log TUN-relay marking (docs/todo/conn-log.md §5; inbound rows begun under TUN carry source=TunRelay)
    state.client.conn_log().set_tun_relay(enabled);
    Ok(tun_status_of(&state).await)
}

/// "Relaunch as administrator" (§2.2): persist TUN toggle (auto-restored on after relaunch) → audit → runas self → exit.
#[tauri::command]
pub(crate) async fn tun_relaunch_elevated(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        roles.tun_mode = true;
        roles.subscription = true;
        roles.save()?;
    }
    roles::audit("gui.tun_elevation", serde_json::json!({"granted": true}));
    tun::SystemElevation.relaunch_elevated()?;
    app.exit(0);
    Ok(())
}

/// Elevation dialog cancelled: stay as-is, audit declined (§2.2).
#[tauri::command]
pub(crate) fn tun_elevation_declined() -> Result<(), String> {
    roles::audit("gui.tun_elevation", serde_json::json!({"granted": false}));
    Ok(())
}

/// Change external upstream (§2.4): persist after strict validation (§2.5); if TUN is running, re-apply fallback and probe.
#[tauri::command]
pub(crate) async fn set_tun_upstream(state: State<'_, AppState>, addr: String) -> Result<TunStatus, String> {
    let sa = roles::validate_external_upstream(&addr)?;
    let tun_on = {
        let mut roles = state.roles.lock().await;
        roles.external_upstream = sa.to_string();
        roles.save()?;
        roles.tun_mode
    };
    if tun_on && state.kernel.running().await {
        crate::apply_proxy_fallback(&state).await;
        let ok = tun::tcp_reachable(sa).await;
        *state.tun_upstream_ok.lock().await = Some(ok);
    }
    Ok(tun_status_of(&state).await)
}

/// Toggle D: subscription proxy role. Enabling starts the kernel (auto backoff-restart on crash); disabling stops it.
/// Missing kernel is no longer downloaded on the spot: start a background download and return NEED_DOWNLOAD; frontend shows a download card and auto-retries on completion.
#[tauri::command]
pub(crate) async fn set_subscription_role(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<subscription::KernelStatus, String> {
    if !enabled && state.roles.lock().await.tun_mode {
        return Err("TUN 模式开启中，请先关闭 TUN 模式".into());
    }
    if enabled {
        if !subscription::kernel_bin_exists() {
            state.dl.start(download::Artifact::Kernel)?;
            return Err(format!(
                "{}订阅内核未安装，正在后台下载",
                subscription::NEED_DOWNLOAD_PREFIX
            ));
        }
        if let Err(e) = state.kernel.start().await {
            crate::float_notify(&app, format!("订阅内核启动失败：{e}"));
            return Err(e);
        }
        // Subscription traffic only takes effect through the local proxy (master power): auto-start it when off,
        // otherwise the kernel runs but nothing reaches it. Skipped while TUN runs (TUN carries traffic itself);
        // on failure roll the kernel back so the toggle reports a whole failure (fan-in role disabled, etc.).
        if state.client.proxy_port() == 0 && !state.roles.lock().await.tun_mode {
            if let Err(e) = super::proxy::start_proxy_inner(&app, &state, 57890).await {
                state.kernel.stop().await;
                return Err(format!("订阅代理需配合总代理（本地代理）生效，自动开启失败：{e}"));
            }
        }
    } else {
        state.kernel.stop().await;
    }
    {
        let mut roles = state.roles.lock().await;
        roles.subscription = enabled;
        roles.save()?;
    }
    roles::audit(
        "gui.role_toggle",
        serde_json::json!({"role": "subscription", "on": enabled}),
    );
    crate::apply_proxy_fallback(&state).await;
    Ok(state.kernel.status().await)
}

/// Switch subscription outbound mode: persist; if the kernel is running, hot-switch via controller PATCH /configs (fall back to restart on failure).
#[tauri::command]
pub(crate) async fn set_sub_mode(state: State<'_, AppState>, mode: String) -> Result<(), String> {
    if !roles::valid_sub_mode(&mode) {
        return Err("非法出站模式（rule|global|direct）".into());
    }
    // In TUN mode the outbound mode is fixed to rule: global/direct would bypass rules (incl. MATCH→ANET-IN),
    // traffic would no longer be split by anet, violating the anet-in-front design
    if state.roles.lock().await.tun_mode {
        return Err("TUN 模式下出站模式固定为规则（全局/直连会绕过 anet 分流）".into());
    }
    {
        let mut roles = state.roles.lock().await;
        roles.sub_mode = mode.clone();
        roles.save()?;
    }
    roles::audit("gui.sub_mode", serde_json::json!({"mode": mode}));
    if state.kernel.running().await {
        let patched = match subscription::kernel_api().await {
            Ok(api) => api.set_mode(&mode).await.is_ok(),
            Err(_) => false,
        };
        if !patched {
            // Hot-switch fallback: restart the kernel to regenerate config with the new setting
            state.kernel.stop().await;
            state.kernel.start().await?;
            crate::apply_proxy_fallback(&state).await;
        }
    }
    Ok(())
}

/// System proxy lock (hardcore mode): treated as taken over; patrol auto-restores expected values when system values are changed.
#[tauri::command]
pub(crate) async fn set_sysproxy_lock(state: State<'_, AppState>, on: bool) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        roles.sysproxy_lock = on;
        roles.save()?;
    }
    roles::audit("gui.sysproxy_lock", serde_json::json!({"on": on}));
    Ok(())
}

/// Performance mode (frontend disables blur/animations based on this; backend only persists it).
#[tauri::command]
pub(crate) async fn set_reduce_effects(state: State<'_, AppState>, on: bool) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        roles.reduce_effects = on;
        roles.save()?;
    }
    roles::audit("gui.reduce_effects", serde_json::json!({"on": on}));
    Ok(())
}
