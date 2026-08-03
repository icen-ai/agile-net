//! 从 lib.rs 拆分：角色开关（客户端 / 服务端 / Web 远程面 / 订阅 / TUN）与偏好设置（纯搬运，零逻辑变更）

use crate::roles::{self, RoleSettings};
use crate::tun::{self, Elevation};
use crate::{download, map_err, subscription, sysproxy, AppState};
#[cfg(windows)]
use crate::floatball;
use agile_net_node::service::NodeServer;
use serde::Serialize;
use std::sync::Arc;
use tauri::{Manager, State};

/// 设置开机自启
#[tauri::command]
pub(crate) fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    if enabled {
        manager.enable().map_err(map_err)
    } else {
        manager.disable().map_err(map_err)
    }
}

/// 查询开机自启状态
#[tauri::command]
pub(crate) fn get_autostart(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(map_err)
}

// ==================== 三路角色开关（客户端 / 服务端 / Web 远程面） ====================

#[derive(Debug, Clone, Serialize)]
pub struct ServerStatus {
    pub running: bool,
    pub has_admin: bool,
    pub api_addr: String,
    pub relay_addr: String,
    /// 各扇出连接的（目标地址, 状态）（running 时实时；未运行为空）
    pub connectors: Vec<(String, String)>,
}

#[tauri::command]
pub(crate) async fn get_role_settings(state: State<'_, AppState>) -> Result<RoleSettings, String> {
    Ok(state.roles.lock().await.clone())
}

/// 开关A：客户端角色。关闭即断开全部节点并停止本地代理。
#[tauri::command]
pub(crate) async fn set_client_role(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    if !enabled {
        state.client.disconnect_all().await;
        state.client.stop_proxy().await;
    }
    let mut roles = state.roles.lock().await;
    roles.client = enabled;
    roles.save()?;
    drop(roles);
    if !enabled {
        crate::report_client_proxy(&state).await;
    }
    roles::audit("gui.role_toggle", serde_json::json!({"role": "client", "on": enabled}));
    Ok(())
}

/// 服务端角色运行状态。
#[tauri::command]
pub(crate) async fn server_status(state: State<'_, AppState>) -> Result<ServerStatus, String> {
    let connectors = {
        let slot = state.server.lock().await;
        slot.as_ref().map(|s| s.connector_states()).unwrap_or_default()
    };
    let running = state.server.lock().await.is_some();
    let has_admin = roles::open_embedded_db()
        .and_then(|db| db.has_admin().map_err(|e| e.to_string()))
        .unwrap_or(false);
    Ok(ServerStatus {
        running,
        has_admin,
        api_addr: roles::EMBEDDED_API_ADDR.into(),
        relay_addr: roles::EMBEDDED_RELAY_ADDR.into(),
        connectors,
    })
}

/// 首开强制设管理密码：创建内嵌节点管理员（argon2id 哈希落库）。
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

/// 启动内嵌节点（读当前角色配置；注入客户端引擎路由再发布）。
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
    .map_err(|e| format!("内嵌节点启动失败: {e}"))
}

/// 开关B：服务端角色。开启即启动内嵌节点（须先设管理密码），关闭即停机。
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
    }
    {
        let mut roles = state.roles.lock().await;
        roles.server = enabled;
        roles.save()?;
    }
    roles::audit("gui.role_toggle", serde_json::json!({"role": "server", "on": enabled}));
    let has_admin = roles::open_embedded_db()
        .and_then(|db| db.has_admin().map_err(|e| e.to_string()))
        .unwrap_or(false);
    let connectors = {
        let slot = state.server.lock().await;
        slot.as_ref().map(|s| s.connector_states()).unwrap_or_default()
    };
    Ok(ServerStatus {
        running: enabled,
        has_admin,
        api_addr: roles::EMBEDDED_API_ADDR.into(),
        relay_addr: roles::EMBEDDED_RELAY_ADDR.into(),
        connectors,
    })
}

#[tauri::command]
pub(crate) async fn has_web_password() -> Result<bool, String> {
    Ok(roles::has_web_password())
}

/// 设置 Web 远程面管理密码（argon2id 哈希落盘）。
#[tauri::command]
pub(crate) async fn set_web_password(password: String) -> Result<(), String> {
    roles::set_web_password(&password)?;
    roles::audit("web.exposure_change", serde_json::json!({"change": "password_set"}));
    Ok(())
}

/// 开关C：Web 远程面。强制先设管理密码；开启即在监听地址上启动管理面 Web API。
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

    // 先停旧实例（监听地址变更或关闭），再按需启动
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

/// 主题变更广播：控制台窗口（外部源 SPA）经 Tauri 事件实时跟随主窗主题
#[tauri::command]
pub(crate) fn broadcast_theme(app: tauri::AppHandle, theme: String) -> Result<(), String> {
    use tauri::Emitter;
    #[cfg(windows)]
    floatball::set_dark(theme == "dark");
    app.emit("ag-theme", theme).map_err(map_err)
}

/// 启动时恢复服务端角色（上次退出时处于开启状态）。
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

/// 启动时恢复 Web 远程面（上次退出时处于开启状态且已设管理密码）。
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

// ==================== TUN 模式（docs/plan/tun.md P1：anet 在前 FlClash 在后） ====================

/// TUN 状态（前端轮询展示：运行中/权限不足/上游不可达）
#[derive(Debug, Clone, Serialize)]
pub struct TunStatus {
    /// 当前平台支持 TUN（Windows x64 且内核可安装）
    pub supported: bool,
    /// TUN 开关（持久化）
    pub enabled: bool,
    /// 内核运行中（配置为 TUN 骨架）
    pub running: bool,
    /// 当前进程已是管理员
    pub admin: bool,
    /// 外部上游（回落目标）
    pub upstream: String,
    /// 最近一次拨测结果（None = 未拨测）
    pub upstream_ok: Option<bool>,
    /// 放弃开启的一次性提示（读取即清除；前端 toast 后不再出现）
    pub notice: Option<String>,
}

/// TUN 放弃开启的统一兜底：关开关持久化 + 审计 + 一次性提示。
/// 语义（用户要求）：TUN 是独立可选项，权限不足/启动失败时安静放弃，绝不影响其它功能。
pub(crate) async fn abandon_tun(state: &State<'_, AppState>, reason: &str) {
    {
        let mut roles = state.roles.lock().await;
        roles.tun_mode = false;
        let _ = roles.save();
    }
    roles::audit("gui.tun_abandon", serde_json::json!({"reason": reason}));
    *state.tun_notice.lock().await = Some(format!(
        "TUN 已放弃开启：{reason}（已回退普通模式，不影响其它功能）"
    ));
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

/// TUN 开启后的数据面/系统代理副作用（开启与提权重启恢复共用）：
/// 本地代理钉 57890（ANET-IN 目标）→ 回落 = 外部上游 → 系统代理自动托管 57890（§2.6）
/// → 外部上游 TCP 拨测一次（不通仅前端灵动岛告警，不阻断；§2.4）。
pub(crate) async fn tun_side_effects(app: &tauri::AppHandle, state: &State<'_, AppState>) -> Result<(), String> {
    let port = state.client.proxy_port();
    if port != 57890 {
        if port > 0 {
            state.client.stop_proxy().await;
        }
        state.client.start_proxy(57890).await.map_err(map_err)?;
        crate::report_client_proxy(state).await;
        crate::refresh_tray_icon(app);
    }
    crate::apply_proxy_fallback(state).await;
    let server = crate::expected_sysproxy(state);
    let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
    // 拨测生效回落目标（订阅出口或外部上游；不通仅前端灵动岛告警，不阻断；§2.4）
    let ok = match crate::effective_fallback(state).await {
        Some(sa) => tun::tcp_reachable(sa).await,
        None => false,
    };
    *state.tun_upstream_ok.lock().await = Some(ok);
    Ok(())
}

/// TUN 模式开关（§2.2 提权 / §2.4 回落 / §2.5 互斥 / §2.6 系统代理）。
#[tauri::command]
pub(crate) async fn set_tun_mode(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<TunStatus, String> {
    if enabled {
        // §2.2 管理员提权：非管理员 → NEED_ELEVATION（前端弹对话框走 runas 重启路径）
        tun::precheck(&tun::SystemElevation)?;
        // 制品缺失不再当场下载：后台开始下载并返回 NEED_DOWNLOAD，前端展示下载卡，完成后自动重试
        if !subscription::kernel_bin_exists() {
            state.dl.start(download::Artifact::Kernel)?;
            return Err(format!(
                "{}订阅内核未安装，正在后台下载",
                subscription::NEED_DOWNLOAD_PREFIX
            ));
        }
        // §2.1 wintun.dll：已存在/本地候选复用即过；仍缺失 → 后台下载
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
            // §2.4 回落目标合法性（硬约束；违规拒绝开启）
            roles::validate_external_upstream(&roles.external_upstream)?;
            roles.tun_mode = true;
            roles.subscription = true;
            roles.save()?;
        }
        roles::audit(
            "gui.tun_enable",
            serde_json::json!({"upstream": state.roles.lock().await.external_upstream}),
        );
        // 重启内核加载 TUN 骨架 + 数据面副作用；任一步失败都整体回退普通模式（订阅不受影响）
        state.kernel.stop().await;
        let start_result = match state.kernel.start().await {
            Ok(()) => tun_side_effects(&app, &state).await,
            Err(e) => Err(e),
        };
        if let Err(e) = start_result {
            abandon_tun(&state, &format!("启动失败（{e}）")).await;
            // 回滚后尝试以普通模式重启内核，订阅角色保持可用
            let _ = state.kernel.start().await;
            crate::apply_proxy_fallback(&state).await;
            return Err(format!("TUN 开启失败，已回退普通模式: {e}"));
        }
    } else {
        {
            let mut roles = state.roles.lock().await;
            roles.tun_mode = false;
            roles.save()?;
        }
        roles::audit("gui.tun_disable", serde_json::json!({}));
        *state.tun_upstream_ok.lock().await = None;
        // 内核回到普通配置（订阅角色保持开启）
        state.kernel.stop().await;
        state.kernel.start().await?;
        crate::apply_proxy_fallback(&state).await;
        // §2.6 关 TUN：还原系统代理快照；系统代理偏好仍开且代理在跑则按偏好重新托管
        let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
        let system_pref = state.roles.lock().await.system_proxy;
        if system_pref && state.client.proxy_port() > 0 {
            let server = crate::expected_sysproxy(&state);
            let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
        }
    }
    Ok(tun_status_of(&state).await)
}

/// 「以管理员身份重启」（§2.2）：持久化 TUN 开关（重启后自动恢复开启）→ 审计 → runas 拉起自身 → 退出。
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

/// 提权对话框取消：停留现状，审计 declined（§2.2）。
#[tauri::command]
pub(crate) fn tun_elevation_declined() -> Result<(), String> {
    roles::audit("gui.tun_elevation", serde_json::json!({"granted": false}));
    Ok(())
}

/// 修改外部上游（§2.4）：严格校验（§2.5）后持久化；TUN 运行中即重应用回落并拨测。
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

/// 开关D：订阅代理角色。开启即启动内核（崩溃自动退避重启），关闭即停机。
/// 内核缺失时不再当场下载：后台开始下载并返回 NEED_DOWNLOAD，前端展示下载卡，完成后自动重试。
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

/// 切换订阅出站模式：持久化；内核运行中走控制器 PATCH /configs 热切（失败则重启兜底）。
#[tauri::command]
pub(crate) async fn set_sub_mode(state: State<'_, AppState>, mode: String) -> Result<(), String> {
    if !roles::valid_sub_mode(&mode) {
        return Err("非法出站模式（rule|global|direct）".into());
    }
    // TUN 模式下出站模式固定为规则：global/direct 会绕过 rules（含 MATCH→ANET-IN），
    // 流量不再经 anet 分流，违反 anet 在前设计
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
            // 热切失败兜底：重启内核按新设置重生成配置
            state.kernel.stop().await;
            state.kernel.start().await?;
            crate::apply_proxy_fallback(&state).await;
        }
    }
    Ok(())
}

/// 系统代理锁定（硬核模式）：视同托管，巡检发现系统值被改即自动收回期望值。
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

/// 性能模式（前端据此关模糊/动画；后端仅持久化存取）。
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
