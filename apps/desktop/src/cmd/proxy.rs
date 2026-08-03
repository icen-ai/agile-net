//! 从 lib.rs 拆分：本地代理与系统代理托管（纯搬运，零逻辑变更）

use crate::{map_err, roles, sysproxy, AppState};
use serde::Serialize;
use tauri::{Manager, State};

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
}

/// 启动本地代理共用逻辑（start_proxy 命令 / proxy_power_toggle 复用）：
/// 按 system_proxy 角色偏好决定是否 engage 系统代理（幂等，快照不会重复覆盖）。
pub(crate) async fn start_proxy_inner(app: &tauri::AppHandle, state: &State<'_, AppState>, port: u16) -> Result<u16, String> {
    if !state.roles.lock().await.client {
        return Err("扇入已停用，请在首页开启".into());
    }
    state.client.start_proxy(port).await.map_err(map_err)?;
    crate::refresh_tray_icon(app);
    if state.roles.lock().await.system_proxy {
        let server = expected_sysproxy(state);
        let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
    }
    crate::report_client_proxy(state).await;
    Ok(state.client.proxy_port())
}

/// 停止本地代理共用逻辑：系统代理模式下还原系统代理（避免指向已死端口）；
/// 模式偏好保留，下次启动自动再接管。
pub(crate) async fn stop_proxy_inner(app: &tauri::AppHandle, state: &State<'_, AppState>) -> Result<(), String> {
    state.client.stop_proxy().await;
    if state.roles.lock().await.system_proxy {
        let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
    }
    crate::report_client_proxy(state).await;
    crate::refresh_tray_icon(app);
    Ok(())
}

/// 启动本地代理
#[tauri::command]
pub(crate) async fn start_proxy(app: tauri::AppHandle, state: State<'_, AppState>, port: u16) -> Result<u16, String> {
    start_proxy_inner(&app, &state, port).await
}

/// 停止本地代理
#[tauri::command]
pub(crate) async fn stop_proxy(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    stop_proxy_inner(&app, &state).await
}

/// 全局总开关状态（首页大中控台；proxy_power 返回体）
#[derive(Debug, Clone, Serialize)]
pub struct PowerState {
    /// 本地代理是否正在监听
    pub on: bool,
    /// 监听地址（如 127.0.0.1:57890）或「已停止」
    pub detail: String,
}

/// 当前总开关状态快照（纯内存读，无网络 IO，可供前端轮询）。
pub(crate) fn power_state_of(state: &State<'_, AppState>) -> PowerState {
    let port = state.client.proxy_port();
    PowerState {
        on: port > 0,
        detail: if port > 0 { format!("127.0.0.1:{port}") } else { "已停止".into() },
    }
}

/// 全局总开关状态查询（廉价轮询用）
#[tauri::command]
pub(crate) async fn proxy_power(state: State<'_, AppState>) -> Result<PowerState, String> {
    Ok(power_state_of(&state))
}

/// 全局总开关切换：on→停止（含系统代理还原）；off→启动（默认端口 57890，
/// 按 system_proxy 角色偏好接管系统代理）。TUN 与系统代理互斥，TUN 运行中禁止直接 toggle。
#[tauri::command]
pub(crate) async fn proxy_power_toggle(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<PowerState, String> {
    if state.roles.lock().await.tun_mode {
        return Err("TUN 模式运行中，请先关闭 TUN".into());
    }
    if state.client.proxy_port() > 0 {
        stop_proxy_inner(&app, &state).await?;
    } else {
        // 与「连接」页/系统代理自动拉起同一默认端口
        start_proxy_inner(&app, &state, 57890).await?;
    }
    let st = power_state_of(&state);
    roles::audit("gui.proxy_power", serde_json::json!({"on": st.on, "detail": st.detail}));
    Ok(st)
}

/// 代理状态
#[tauri::command]
pub(crate) async fn proxy_status(state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    let port = state.client.proxy_port();
    Ok(ProxyStatus {
        running: port > 0,
        port,
    })
}

// ==================== 系统代理托管 ====================

/// 期望的系统代理值（本地代理端口）。
pub(crate) fn expected_sysproxy(state: &State<'_, AppState>) -> String {
    format!("127.0.0.1:{}", state.client.proxy_port())
}

#[tauri::command]
pub(crate) async fn set_system_proxy(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    if enabled {
        // 本地代理未启动则自动拉起（默认端口同「连接」页 57890），
        // 消除"必须先手动启动本地代理"的顺序陷阱
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
    // TUN 模式 / 锁定模式视同托管（系统自动代理指向 57890，巡检自动收回）
    let managed = {
        let r = state.roles.lock().await;
        r.system_proxy || r.tun_mode || r.sysproxy_lock
    };
    let running = state.client.proxy_port() > 0;
    let expected = expected_sysproxy(&state);
    let mut st = tokio::task::spawn_blocking(move || sysproxy::inspect(managed, &expected))
        .await
        .map_err(map_err)??;
    // 代理未运行时不判冲突：启动清理已还原残留，
    // 默认系统代理模式下"还没启动代理"不属于被抢占
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

// ==================== 代理方式三态（悬浮球菜单） ====================

/// 当前代理方式：tun（TUN 接管）/ system（本地代理 + 系统代理）/ local（仅本地代理）。
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

/// 设置代理方式（悬浮球菜单）。返回实际生效的模式字符串。
/// - "tun"：复用 set_tun_mode 开启全逻辑（§2.2 管理员检查 NEED_ELEVATION / 制品下载等错误原样透传）
/// - "system" / "local"：TUN 开着先关（复用 set_tun_mode 关闭路径）；本地代理未起则拉起（57890）；
///   然后按模式 engage / disengage 系统代理并持久化偏好
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
            // 本地代理未启动则自动拉起（start_proxy_inner 内部校验扇入角色；端口同「连接」页默认）
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
            roles::audit("gui.proxy_mode", serde_json::json!({"mode": mode}));
            Ok(mode)
        }
        _ => Err(format!("非法代理方式: {mode}")),
    }
}

/// 系统代理接管 toggle（悬浮球菜单）：当前系统代理已指向期望值则还原（返 false），
/// 否则接管（返 true）。与 set_system_proxy 的差别：方向由 inspect 实测决定，无需前端先查状态。
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

/// 系统代理冲突巡检（30s）：托管中系统值 ≠ 期望值即记审计。
/// TUN 模式（§2.6）与锁定模式（sysproxy_lock）升级为自动收回：被抢即重写期望值并记审计
/// （含来源值；锁定来源 detail 注明 lock:true），每轮处理；
/// 非自动收回维持"提醒手动收回"（每轮冲突只记一次，恢复后可再记）。
pub(crate) async fn sysproxy_watch(app: tauri::AppHandle) {
    let mut in_conflict = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let state = app.state::<AppState>();
        let (pref, tun_mode, lock) = {
            let r = state.roles.lock().await;
            (r.system_proxy, r.tun_mode, r.sysproxy_lock)
        };
        // TUN 模式与锁定模式视同托管（自动收回策略）；代理未运行时不判冲突（同 sysproxy_status）
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
