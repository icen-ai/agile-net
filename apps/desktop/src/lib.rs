//! AgileNet 桌面客户端 Tauri 后端
//!
//! 通过 IPC 向前端暴露节点管理、代理控制与凭据存储能力，
//! 全部网络逻辑复用 agile-net-client 引擎（与 CLI/daemon 同一数据面）。
//! 服务端角色内嵌完整 agile-net-node（与 anet-svc 同一装配根 NodeServer）。

use agile_net_client::{AgileNetClient, ConnectParams, Credential, CredentialStore, NodeState, ParsedConnect};
use agile_net_node::service::NodeServer;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{Manager, State};

mod download;
#[cfg(windows)]
mod floatball;
mod roles;
mod subscription;
mod sub_script;
mod sync;
mod sysproxy;
mod tun;
use roles::RoleSettings;
use tun::Elevation;

/// 前端传入的连接参数（与 Web REST 共用 agile-net-client::ParsedConnect）
pub type ConnectInput = ParsedConnect;

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
}

pub struct AppState {
    client: AgileNetClient,
    creds: Arc<Option<Arc<CredentialStore>>>,
    web_api: Arc<tokio::sync::Mutex<Option<agile_net_client::api::ClientApiHandle>>>,
    roles: Arc<tokio::sync::Mutex<RoleSettings>>,
    server: Arc<tokio::sync::Mutex<Option<NodeServer>>>,
    /// 控制台 loopback 转发器：node_id → 本地环回端口
    consoles: Arc<tokio::sync::Mutex<std::collections::HashMap<String, u16>>>,
    /// 订阅内核（mihomo sidecar）
    kernel: Arc<subscription::KernelManager>,
    /// 制品下载管理器（mihomo 内核 / wintun.dll；进度状态机 + 手动安装）
    dl: download::DownloadManager,
    /// 客户端代理真实状态槽（传给内嵌节点；管理端「本地代理」卡数据源）
    client_proxy_slot: agile_net_node::service::ClientProxySlot,
    /// TUN 最近一次外部上游拨测结果（None = 未拨测；前端状态行/灵动岛告警数据源）
    tun_upstream_ok: Arc<tokio::sync::Mutex<Option<bool>>>,
    /// TUN 放弃开启的一次性提示（权限不足/启动失败回退普通模式；前端读取后清除）
    tun_notice: Arc<tokio::sync::Mutex<Option<String>>>,
    /// 最近一次应用的回落上游（变化时审计 gui.fallback_change，记地址不记凭据）
    last_fallback: Arc<tokio::sync::Mutex<Option<std::net::SocketAddr>>>,
    /// 悬浮球气泡通知开关的廉价缓存（float_notify 同步门控用；与 roles.notify_float_ball 同步）
    notify_float_ball: Arc<AtomicBool>,
}

impl AppState {
    fn new() -> Self {
        let roles = RoleSettings::load();
        let notify_float_ball = roles.notify_float_ball;
        // 开机初值：代理未启动 + 已保存的代理模式偏好（开机恢复态）
        let client_proxy_slot = agile_net_node::service::new_client_proxy_slot();
        client_proxy_slot.store(Arc::new(Some(agile_net_node::service::ClientProxyInfo {
            enabled: false,
            mode: if roles.system_proxy { "system" } else { "local" }.to_string(),
            listen: String::new(),
        })));
        Self {
            client: AgileNetClient::new(),
            creds: Arc::new(CredentialStore::open_default().ok().map(Arc::new)),
            web_api: Arc::new(tokio::sync::Mutex::new(None)),
            roles: Arc::new(tokio::sync::Mutex::new(roles)),
            server: Arc::new(tokio::sync::Mutex::new(None)),
            consoles: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            kernel: Arc::new(subscription::KernelManager::default()),
            dl: download::DownloadManager::default(),
            client_proxy_slot,
            tun_upstream_ok: Arc::new(tokio::sync::Mutex::new(None)),
            tun_notice: Arc::new(tokio::sync::Mutex::new(None)),
            last_fallback: Arc::new(tokio::sync::Mutex::new(None)),
            notify_float_ball: Arc::new(AtomicBool::new(notify_float_ball)),
        }
    }
}

fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// 连接节点
#[tauri::command]
async fn connect_node(state: State<'_, AppState>, input: ConnectInput) -> Result<NodeState, String> {
    if !state.roles.lock().await.client {
        return Err("扇入已停用，请在首页开启".into());
    }
    let params = ConnectParams {
        addr: input.addr.clone(),
        username: input.username.clone(),
        password: input.password.clone(),
        insecure: input.insecure,
        pinned_cert_path: input.pinned_cert_path.clone(),
        pinned_fingerprint: input.pinned_fingerprint.clone(),
        manage_hosts: input.manage_hosts,
    };
    let node_state = state.client.connect(params).await.map_err(map_err)?;

    if input.save_credential {
        if let Some(store) = state.creds.as_ref() {
            store
                .save(
                    &node_state.node_id,
                    &Credential {
                        addr: input.addr,
                        username: input.username,
                        password: input.password,
                        insecure: input.insecure,
                        pinned_fingerprint: input.pinned_fingerprint,
                    },
                )
                .await;
        }
    }
    Ok(node_state)
}

/// 断开节点（保留已保存凭据；删除凭据走 delete_credential）
#[tauri::command]
async fn disconnect_node(state: State<'_, AppState>, node_id: String) -> Result<(), String> {
    state.client.disconnect(&node_id).await;
    let mut map = state.consoles.lock().await;
    map.remove(&node_id);
    let prefix = format!("{node_id}|");
    map.retain(|k, _| !k.starts_with(&prefix));
    Ok(())
}

/// 删除已保存的凭据
#[tauri::command]
async fn delete_credential(state: State<'_, AppState>, key: String) -> Result<(), String> {
    if let Some(store) = state.creds.as_ref() {
        store.remove(&key).await;
    }
    Ok(())
}

/// 导出已保存凭据为 agilenet://connect 接入链接（含明文密码，谨慎分享）
#[tauri::command]
async fn export_credential(state: State<'_, AppState>, key: String) -> Result<String, String> {
    let store = state.creds.as_ref().as_ref().ok_or("凭据存储不可用")?;
    let c = store.get(&key).await.ok_or("凭据不存在或已删除")?;
    Ok(agile_net_client::connect_url_of(&c))
}

/// 暂停/恢复一条路由规则（rule_key 格式 "type:value"）
#[tauri::command]
async fn set_rule_paused(
    state: State<'_, AppState>,
    node_id: String,
    rule_key: String,
    paused: bool,
) -> Result<(), String> {
    state.client.set_rule_paused(&node_id, &rule_key, paused);
    Ok(())
}

/// 查询某节点被暂停的规则
#[tauri::command]
async fn get_paused_rules(state: State<'_, AppState>, node_id: String) -> Result<Vec<String>, String> {
    Ok(state.client.get_paused_rules(&node_id))
}

/// 整体恢复某节点的暂停集合（前端持久化恢复用）
#[tauri::command]
async fn set_paused_rules(
    state: State<'_, AppState>,
    node_id: String,
    keys: Vec<String>,
) -> Result<(), String> {
    state.client.set_paused_rules(&node_id, keys);
    Ok(())
}

/// 节点列表（含实时状态）
#[tauri::command]
async fn list_nodes(state: State<'_, AppState>) -> Result<Vec<NodeState>, String> {
    let mut nodes = state.client.list_nodes().await;
    for n in &mut nodes {
        n.status = state.client.node_status(&n.node_id);
    }
    Ok(nodes)
}

/// 已保存凭据列表
#[tauri::command]
async fn list_credentials(state: State<'_, AppState>) -> Result<Vec<(String, Credential)>, String> {
    let Some(store) = state.creds.as_ref() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for key in store.keys().await {
        if let Some(cred) = store.get(&key).await {
            out.push((key, cred));
        }
    }
    Ok(out)
}

/// 启动本地代理共用逻辑（start_proxy 命令 / proxy_power_toggle 复用）：
/// 按 system_proxy 角色偏好决定是否 engage 系统代理（幂等，快照不会重复覆盖）。
async fn start_proxy_inner(app: &tauri::AppHandle, state: &State<'_, AppState>, port: u16) -> Result<u16, String> {
    if !state.roles.lock().await.client {
        return Err("扇入已停用，请在首页开启".into());
    }
    state.client.start_proxy(port).await.map_err(map_err)?;
    refresh_tray_icon(app);
    if state.roles.lock().await.system_proxy {
        let server = expected_sysproxy(state);
        let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
    }
    report_client_proxy(state).await;
    Ok(state.client.proxy_port())
}

/// 停止本地代理共用逻辑：系统代理模式下还原系统代理（避免指向已死端口）；
/// 模式偏好保留，下次启动自动再接管。
async fn stop_proxy_inner(app: &tauri::AppHandle, state: &State<'_, AppState>) -> Result<(), String> {
    state.client.stop_proxy().await;
    if state.roles.lock().await.system_proxy {
        let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
    }
    report_client_proxy(state).await;
    refresh_tray_icon(app);
    Ok(())
}

/// 启动本地代理
#[tauri::command]
async fn start_proxy(app: tauri::AppHandle, state: State<'_, AppState>, port: u16) -> Result<u16, String> {
    start_proxy_inner(&app, &state, port).await
}

/// 停止本地代理
#[tauri::command]
async fn stop_proxy(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
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
fn power_state_of(state: &State<'_, AppState>) -> PowerState {
    let port = state.client.proxy_port();
    PowerState {
        on: port > 0,
        detail: if port > 0 { format!("127.0.0.1:{port}") } else { "已停止".into() },
    }
}

/// 全局总开关状态查询（廉价轮询用）
#[tauri::command]
async fn proxy_power(state: State<'_, AppState>) -> Result<PowerState, String> {
    Ok(power_state_of(&state))
}

/// 全局总开关切换：on→停止（含系统代理还原）；off→启动（默认端口 57890，
/// 按 system_proxy 角色偏好接管系统代理）。TUN 与系统代理互斥，TUN 运行中禁止直接 toggle。
#[tauri::command]
async fn proxy_power_toggle(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<PowerState, String> {
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
async fn proxy_status(state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    let port = state.client.proxy_port();
    Ok(ProxyStatus {
        running: port > 0,
        port,
    })
}

/// 解析 agilenet://connect?... 接入链接（实现位于 agile-net-client，与 Web REST 共用）
#[tauri::command]
fn parse_connect_url(url: String) -> Result<ConnectInput, String> {
    agile_net_client::parse_connect_url(&url)
}

/// 设置开机自启
#[tauri::command]
fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
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
fn get_autostart(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(map_err)
}

/// 用系统默认浏览器打开外部链接（仅 http/https）。
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("非法链接".into());
    }
    #[cfg(windows)]
    std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", &url])
        .spawn()
        .map_err(map_err)?;
    #[cfg(target_os = "macos")]
    std::process::Command::new("open").arg(&url).spawn().map_err(map_err)?;
    #[cfg(all(unix, not(target_os = "macos")))]
    std::process::Command::new("xdg-open")
        .arg(&url)
        .spawn()
        .map_err(map_err)?;
    Ok(())
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
async fn get_role_settings(state: State<'_, AppState>) -> Result<RoleSettings, String> {
    Ok(state.roles.lock().await.clone())
}

/// 开关A：客户端角色。关闭即断开全部节点并停止本地代理。
#[tauri::command]
async fn set_client_role(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    if !enabled {
        state.client.disconnect_all().await;
        state.client.stop_proxy().await;
    }
    let mut roles = state.roles.lock().await;
    roles.client = enabled;
    roles.save()?;
    drop(roles);
    if !enabled {
        report_client_proxy(&state).await;
    }
    roles::audit("gui.role_toggle", serde_json::json!({"role": "client", "on": enabled}));
    Ok(())
}

/// 服务端角色运行状态。
#[tauri::command]
async fn server_status(state: State<'_, AppState>) -> Result<ServerStatus, String> {
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
async fn init_server_admin(username: String, password: String) -> Result<(), String> {
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
async fn start_embedded_node(state: &State<'_, AppState>) -> Result<NodeServer, String> {
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
async fn set_server_role(state: State<'_, AppState>, enabled: bool) -> Result<ServerStatus, String> {
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
async fn has_web_password() -> Result<bool, String> {
    Ok(roles::has_web_password())
}

/// 设置 Web 远程面管理密码（argon2id 哈希落盘）。
#[tauri::command]
async fn set_web_password(password: String) -> Result<(), String> {
    roles::set_web_password(&password)?;
    roles::audit("web.exposure_change", serde_json::json!({"change": "password_set"}));
    Ok(())
}

/// 开关C：Web 远程面。强制先设管理密码；开启即在监听地址上启动管理面 Web API。
#[tauri::command]
async fn set_web_role(state: State<'_, AppState>, enabled: bool, listen: Option<String>) -> Result<(), String> {
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
            Some(spa_assets()),
        )
        .await
        .map_err(|e| format!("Web 远程面启动失败: {e}"))?;
        tracing::info!(addr = %handle.addr(), "web remote api started");
        *state.web_api.lock().await = Some(handle);
    }
    roles::audit("gui.role_toggle", serde_json::json!({"role": "web", "on": enabled, "listen": target_listen}));
    Ok(())
}

/// 桌面端管理 SPA 静态资产（include_str! 内嵌，无 Node 构建链）。
fn spa_assets() -> agile_net_client::api::SpaAssets {
    agile_net_client::api::SpaAssets {
        index: include_str!("../ui/index.html"),
        app_js: include_str!("../ui/app.js"),
        icons_js: include_str!("../ui/icons.js"),
        agchart_js: include_str!("../ui/agchart.js"),
        style_css: include_str!("../ui/style.css"),
        tokens_css: include_str!("../ui/tokens.css"),
        components_css: include_str!("../ui/components.css"),
    }
}

/// 统一开窗规格：主屏逻辑宽 1/2、宽高比 4:3、屏幕居中（主窗与控制台一致）
fn normalize_window_geometry(window: &tauri::WebviewWindow) {
    if let Ok(Some(monitor)) = window.primary_monitor() {
        let scale = monitor.scale_factor();
        let logical_w = monitor.size().width as f64 / scale;
        let w = (logical_w * 0.5).round().max(860.0);
        let h = (w * 0.75).round().max(600.0);
        let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
            width: w,
            height: h,
        }));
    }
    let _ = window.center();
}

/// 主题 query 片段（仅接受 light/dark；控制台 SPA 据此与主窗主题一致）
fn theme_query(theme: &Option<String>) -> String {
    match theme.as_deref() {
        Some("dark") => "?theme=dark".to_string(),
        Some("light") => "?theme=light".to_string(),
        _ => String::new(),
    }
}

/// 主题变更广播：控制台窗口（外部源 SPA）经 Tauri 事件实时跟随主窗主题
#[tauri::command]
fn broadcast_theme(app: tauri::AppHandle, theme: String) -> Result<(), String> {
    use tauri::Emitter;
    #[cfg(windows)]
    floatball::set_dark(theme == "dark");
    app.emit("ag-theme", theme).map_err(map_err)
}

/// 管理端控制台 URL：主窗内嵌 iframe 加载（不再开子窗口）。
/// - 无参 → 内嵌节点（本机服务端角色，SPA 登录页）
/// - node_id → 经客户端隧道的远端端点（管理引导票据自举，#boot 不进日志与历史）
/// - node_id + upstream → 可管理上游（握手 v2 发现）
/// URL 恒带 embed=1（SPA 隐藏自身侧栏与标题栏，导航经 postMessage 由主窗驱动）。
#[tauri::command]
async fn console_url(
    state: State<'_, AppState>,
    node_id: Option<String>,
    upstream: Option<String>,
    theme: Option<String>,
) -> Result<String, String> {
    let embed = match theme_query(&theme) {
        q if q.is_empty() => "?embed=1".to_string(),
        q => format!("{q}&embed=1"),
    };
    match (node_id, upstream) {
        (None, None) => {
            let addr = {
                let slot = state.server.lock().await;
                slot.as_ref().map(|s| s.api_addr())
            }
            .ok_or("服务端角色未运行")?;
            Ok(format!("http://{addr}/{embed}"))
        }
        (Some(node_id), None) => {
            // 管理引导票据（10 分钟一次性；节点侧校验 admin_console 授权）
            let (ticket, api_port) = state.client.console_ticket(&node_id).await.map_err(map_err)?;
            let local_port = ensure_console_forwarder(&state, &node_id, "127.0.0.1", api_port).await?;
            roles::audit(
                "admin.console_access",
                serde_json::json!({"target": node_id, "path": "本机→客户端隧道", "identity": "管理链接"}),
            );
            Ok(format!(
                "http://127.0.0.1:{local_port}/{embed}#boot={ticket}"
            ))
        }
        (Some(node_id), Some(upstream)) => {
            let (ticket, api_host, api_port, scope) = state
                .client
                .upstream_console_ticket(&node_id, &upstream)
                .await
                .map_err(map_err)?;
            let fwd_key = format!("{node_id}|{upstream}");
            let local_port = ensure_console_forwarder(&state, &fwd_key, &api_host, api_port).await?;
            roles::audit(
                "admin.console_access",
                serde_json::json!({
                    "target": upstream,
                    "path": format!("本机→{node_id}→relay"),
                    "identity": format!("relay 票据（scope={scope}）"),
                }),
            );
            Ok(format!(
                "http://127.0.0.1:{local_port}/{embed}#boot={ticket}"
            ))
        }
        (None, Some(_)) => Err("缺少端点参数".into()),
    }
}

// ==================== 控制台通道（管理此节点） ====================

/// 控制台 loopback 转发器：本地环回端口 → 指定节点隧道 → 目标 API。
/// key 去重（node_id 或 node_id|upstream）；断开重连后由调用方清理重建。
async fn ensure_console_forwarder(
    state: &State<'_, AppState>,
    key: &str,
    target_host: &str,
    target_port: u16,
) -> Result<u16, String> {
    let mut map = state.consoles.lock().await;
    if let Some(p) = map.get(key) {
        return Ok(*p);
    }
    // key 的第一段恒为 node_id
    let node_id = key.split('|').next().unwrap_or(key);
    let opener = state.client.opener(node_id).ok_or("节点未连接")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(map_err)?;
    let port = listener.local_addr().map_err(map_err)?.port();
    let target_host = target_host.to_string();
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let opener = opener.clone();
            let target_host = target_host.clone();
            tauri::async_runtime::spawn(async move {
                match opener.open("", &target_host, target_port).await {
                    Ok(ch) => {
                        let _ = agile_net_core::relay::bridge::bridge(stream, ch).await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "console channel open failed");
                    }
                }
            });
        }
    });
    map.insert(key.to_string(), port);
    Ok(port)
}

/// 启动时恢复服务端角色（上次退出时处于开启状态）。
async fn restore_server_role(app: &tauri::AppHandle) {
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

// ==================== 扇出连接管理（DB 为唯一事实来源；运行中经 ConnectorManager 热操作，无需重启） ====================

/// 扇出列表视图（token 脱敏仅前缀，绝不回显；编辑需重新输入或留空保留）。
#[derive(Debug, Clone, Serialize)]
pub struct ServerConnectorView {
    pub id: String,
    pub name: String,
    pub upstream_addr: String,
    pub token_prefix: String,
    pub sni_hostname: String,
    pub insecure: bool,
    /// 路由再发布（逗号分隔入库；编辑回显拆行）
    pub advertise: String,
    /// 收敛权限组（None = 不收敛，放行一切）
    pub group_id: Option<String>,
    pub group_name: Option<String>,
    pub enabled: bool,
    pub remark: String,
    /// 实时状态（connected/connecting/reconnecting/disconnected；内嵌节点未运行恒 disconnected）
    pub state: String,
}

/// 权限组下拉选项（扇出表单用）
#[derive(Debug, Clone, Serialize)]
pub struct GroupOption {
    pub id: String,
    pub name: String,
}

/// 本机内嵌节点的权限组清单（扇出表单「权限组」下拉；留空 = 不收敛）。
#[tauri::command]
async fn list_embedded_groups() -> Result<Vec<GroupOption>, String> {
    let db = roles::open_embedded_db()?;
    let (groups, _) = db.list_groups(1, 1000, None).map_err(map_err)?;
    Ok(groups
        .into_iter()
        .map(|g| GroupOption { id: g.id, name: g.name })
        .collect())
}

/// 运行中的内嵌节点热应用单条扇出变更（先断旧再起新；未运行则跳过，启动时自 DB 装配）。
async fn hot_upsert_connector(state: &State<'_, AppState>, id: &str, name: &str) {
    // 先取 ConnectorManager 句柄即放锁，避免持锁跨 await（upsert 内含 DNS 解析）
    let manager = state.server.lock().await.as_ref().map(|s| s.connector_manager());
    if let Some(m) = manager {
        if let Err(e) = m.upsert_from_db(id).await {
            tracing::error!(connector = %name, error = %e, "connector hot-upsert failed");
        }
    }
}

/// 校验收敛组存在（Some 时），给前端友好报错（DB 外键报错不易读）。
fn validate_group(db: &agile_net_node::db::Database, group_id: Option<&str>) -> Result<(), String> {
    if let Some(gid) = group_id {
        if db.get_group(gid).map_err(map_err)?.is_none() {
            return Err("权限组不存在".into());
        }
    }
    Ok(())
}

#[tauri::command]
async fn list_server_connectors(
    state: State<'_, AppState>,
) -> Result<Vec<ServerConnectorView>, String> {
    let db = roles::open_embedded_db()?;
    let items = db.list_connectors().map_err(map_err)?;
    let slot = state.server.lock().await;
    Ok(items
        .into_iter()
        .map(|v| {
            let state_str = slot
                .as_ref()
                .and_then(|s| s.connector_manager().state_of(&v.id))
                .unwrap_or("disconnected");
            ServerConnectorView {
                id: v.id,
                name: v.name,
                upstream_addr: v.upstream_addr,
                token_prefix: v.token_prefix,
                sni_hostname: v.sni_hostname,
                insecure: v.insecure,
                advertise: v.advertise,
                group_id: v.group_id,
                group_name: v.group_name,
                enabled: v.enabled,
                remark: v.remark,
                state: state_str.into(),
            }
        })
        .collect())
}

#[tauri::command]
async fn add_server_connector(
    state: State<'_, AppState>,
    upstream_addr: String,
    token: String,
    sni_hostname: String,
    insecure: bool,
    group_id: Option<String>,
    name: Option<String>,
    advertise: Option<String>,
    remark: Option<String>,
) -> Result<(), String> {
    let addr = upstream_addr.trim();
    if addr.is_empty() || token.trim().is_empty() {
        return Err("扇出目标地址与 Relay Token 不能为空".into());
    }
    // 名称可空：留空 = 取目标地址（沿用 TOML 导入惯例；connector.name 唯一约束）
    let name = name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| addr.to_string());
    let advertise = advertise.unwrap_or_default().trim().to_string();
    let remark = remark.unwrap_or_default().trim().to_string();
    let group_id = group_id.filter(|g| !g.trim().is_empty());
    let db = roles::open_embedded_db()?;
    validate_group(&db, group_id.as_deref())?;
    if db
        .list_connectors()
        .map_err(map_err)?
        .iter()
        .any(|c| c.name == name)
    {
        return Err("同名扇出连接已存在".into());
    }
    let rec = db
        .create_connector(
            &name,
            addr,
            token.trim(),
            sni_hostname.trim(),
            insecure,
            "",
            "",
            &advertise,
            group_id.as_deref(),
            &remark,
        )
        .map_err(map_err)?;
    roles::audit("gui.fanout_change", serde_json::json!({"action": "add", "name": name}));
    hot_upsert_connector(&state, &rec.id, &name).await;
    Ok(())
}

#[tauri::command]
async fn update_server_connector(
    state: State<'_, AppState>,
    id: String,
    upstream_addr: String,
    token: String,
    sni_hostname: String,
    insecure: bool,
    group_id: Option<String>,
    name: Option<String>,
    advertise: Option<String>,
    remark: Option<String>,
) -> Result<(), String> {
    let addr = upstream_addr.trim();
    if addr.is_empty() {
        return Err("扇出目标地址不能为空".into());
    }
    // 名称可空：留空 = 取目标地址（与 add 同惯例）
    let name = name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| addr.to_string());
    let group_id = group_id.filter(|g| !g.trim().is_empty());
    let db = roles::open_embedded_db()?;
    let Some(old) = db.get_connector(&id).map_err(map_err)? else {
        return Err("扇出连接不存在".into());
    };
    validate_group(&db, group_id.as_deref())?;
    if db
        .list_connectors()
        .map_err(map_err)?
        .iter()
        .any(|c| c.name == name && c.id != id)
    {
        return Err("同名扇出连接已存在".into());
    }
    // token / advertise / remark 三态：token 留空 = 保留原值；advertise/remark 缺省(None) = 保留，
    // 前端恒传（空串 = 用户显式清空）；证书路径 GUI 不编辑，原样保留
    let token_reset = if token.trim().is_empty() {
        None
    } else {
        Some(token.trim().to_string())
    };
    let advertise = advertise
        .map(|a| a.trim().to_string())
        .unwrap_or_else(|| old.advertise.clone());
    let remark = remark
        .map(|r| r.trim().to_string())
        .unwrap_or_else(|| old.remark.clone());
    db.update_connector(
        &id,
        &name,
        addr,
        token_reset.as_deref(),
        sni_hostname.trim(),
        insecure,
        &old.ca_cert_path,
        &old.pinned_cert_path,
        &advertise,
        group_id.as_deref(),
        &remark,
    )
    .map_err(map_err)?;
    roles::audit("gui.fanout_change", serde_json::json!({"action": "update", "name": name}));
    hot_upsert_connector(&state, &id, &name).await;
    Ok(())
}

#[tauri::command]
async fn remove_server_connector(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let db = roles::open_embedded_db()?;
    let Some(rec) = db.get_connector(&id).map_err(map_err)? else {
        return Err("扇出连接不存在".into());
    };
    db.delete_connector(&id).map_err(map_err)?;
    roles::audit("gui.fanout_change", serde_json::json!({"action": "remove", "name": rec.name}));
    let manager = state.server.lock().await.as_ref().map(|s| s.connector_manager());
    if let Some(m) = manager {
        m.remove(&id).await;
    }
    Ok(())
}

/// 启动时恢复 Web 远程面（上次退出时处于开启状态且已设管理密码）。
async fn restore_web_role(app: &tauri::AppHandle) {
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
        Some(spa_assets()),
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

// ==================== 订阅代理（mihomo sidecar） ====================

/// 当前生效的回落地址（统一出口为派生语义，无用户开关：订阅内核开 = 未命中走订阅出口）：
/// - TUN 模式：订阅出口优先（TUN mihomo socks 入站 57893→AGILE-SUB，无 FlClash 也能出网）；
///   无激活订阅时回落外部上游（§2.4），异常值宁可无回落也不成环
/// - 非 TUN：订阅角色开 + 内核运行 → 回落到内核 mixed（57892）
/// - 其余：无回落（未命中直连）
async fn effective_fallback(state: &State<'_, AppState>) -> Option<std::net::SocketAddr> {
    let (sub, tun_mode, upstream_raw) = {
        let r = state.roles.lock().await;
        (r.subscription, r.tun_mode, r.external_upstream.clone())
    };
    let running = state.kernel.running().await;
    if tun_mode && running {
        if subscription::list_subscriptions().iter().any(|s| s.active) {
            Some(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                subscription::MIHOMO_SOCKS_PORT,
            )))
        } else {
            roles::validate_external_upstream(&upstream_raw).ok()
        }
    } else if sub && running {
        Some(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            subscription::MIHOMO_MIXED_PORT,
        )))
    } else {
        None
    }
}

/// 应用回落上游（记地址不记凭据；变化时审计 gui.fallback_change）
async fn apply_proxy_fallback(state: &State<'_, AppState>) {
    let addr = effective_fallback(state).await;
    let mut last = state.last_fallback.lock().await;
    if *last != addr {
        roles::audit(
            "gui.fallback_change",
            serde_json::json!({"addr": addr.map(|a| a.to_string())}),
        );
        *last = addr;
    }
    drop(last);
    state.client.set_proxy_fallback(addr);
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
async fn abandon_tun(state: &State<'_, AppState>, reason: &str) {
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

async fn tun_status_of(state: &State<'_, AppState>) -> TunStatus {
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
async fn tun_status(state: State<'_, AppState>) -> Result<TunStatus, String> {
    Ok(tun_status_of(&state).await)
}

/// TUN 开启后的数据面/系统代理副作用（开启与提权重启恢复共用）：
/// 本地代理钉 57890（ANET-IN 目标）→ 回落 = 外部上游 → 系统代理自动托管 57890（§2.6）
/// → 外部上游 TCP 拨测一次（不通仅前端灵动岛告警，不阻断；§2.4）。
async fn tun_side_effects(app: &tauri::AppHandle, state: &State<'_, AppState>) -> Result<(), String> {
    let port = state.client.proxy_port();
    if port != 57890 {
        if port > 0 {
            state.client.stop_proxy().await;
        }
        state.client.start_proxy(57890).await.map_err(map_err)?;
        report_client_proxy(state).await;
        refresh_tray_icon(app);
    }
    apply_proxy_fallback(state).await;
    let server = expected_sysproxy(state);
    let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
    // 拨测生效回落目标（订阅出口或外部上游；不通仅前端灵动岛告警，不阻断；§2.4）
    let ok = match effective_fallback(state).await {
        Some(sa) => tun::tcp_reachable(sa).await,
        None => false,
    };
    *state.tun_upstream_ok.lock().await = Some(ok);
    Ok(())
}

/// TUN 模式开关（§2.2 提权 / §2.4 回落 / §2.5 互斥 / §2.6 系统代理）。
#[tauri::command]
async fn set_tun_mode(
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
            apply_proxy_fallback(&state).await;
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
        apply_proxy_fallback(&state).await;
        // §2.6 关 TUN：还原系统代理快照；系统代理偏好仍开且代理在跑则按偏好重新托管
        let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
        let system_pref = state.roles.lock().await.system_proxy;
        if system_pref && state.client.proxy_port() > 0 {
            let server = expected_sysproxy(&state);
            let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
        }
    }
    Ok(tun_status_of(&state).await)
}

/// 「以管理员身份重启」（§2.2）：持久化 TUN 开关（重启后自动恢复开启）→ 审计 → runas 拉起自身 → 退出。
#[tauri::command]
async fn tun_relaunch_elevated(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
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
fn tun_elevation_declined() -> Result<(), String> {
    roles::audit("gui.tun_elevation", serde_json::json!({"granted": false}));
    Ok(())
}

/// 修改外部上游（§2.4）：严格校验（§2.5）后持久化；TUN 运行中即重应用回落并拨测。
#[tauri::command]
async fn set_tun_upstream(state: State<'_, AppState>, addr: String) -> Result<TunStatus, String> {
    let sa = roles::validate_external_upstream(&addr)?;
    let tun_on = {
        let mut roles = state.roles.lock().await;
        roles.external_upstream = sa.to_string();
        roles.save()?;
        roles.tun_mode
    };
    if tun_on && state.kernel.running().await {
        apply_proxy_fallback(&state).await;
        let ok = tun::tcp_reachable(sa).await;
        *state.tun_upstream_ok.lock().await = Some(ok);
    }
    Ok(tun_status_of(&state).await)
}

#[tauri::command]
async fn list_subscriptions() -> Result<Vec<subscription::Subscription>, String> {
    Ok(subscription::list_subscriptions())
}

/// 安装订阅内核：开始后台下载（流式进度经 dl_state 轮询展示，完成自动校验落盘）。
/// 内核运行中禁止重装（Windows 文件锁会让落盘失败）。
#[tauri::command]
async fn install_kernel(state: State<'_, AppState>) -> Result<(), String> {
    if state.kernel.running().await {
        return Err("内核运行中，请先关闭订阅代理再重新下载".into());
    }
    state.dl.start(download::Artifact::Kernel)
}

// ==================== 制品下载管理（mihomo 内核 / wintun.dll） ====================

/// 下载状态机快照（前端 2s 轮询渲染下载卡）
#[tauri::command]
async fn dl_state(state: State<'_, AppState>) -> Result<download::DlState, String> {
    Ok(state.dl.state())
}

/// 开始/重试下载（同制品下载中幂等）
#[tauri::command]
async fn dl_start(state: State<'_, AppState>, artifact: String) -> Result<(), String> {
    let artifact = download::Artifact::parse(&artifact)?;
    if artifact == download::Artifact::Kernel && state.kernel.running().await {
        return Err("内核运行中，请先关闭订阅代理再下载".into());
    }
    state.dl.start(artifact)
}

/// 取消下载（回 idle；前端同时放弃「完成后自动重试」）
#[tauri::command]
async fn dl_cancel(state: State<'_, AppState>) -> Result<(), String> {
    state.dl.cancel();
    Ok(())
}

/// 手动安装本地制品文件：钉值校验通过才落盘；
/// 不符返回 hash_mismatch（前端弹确认框明示风险），用户确认后带 allow_mismatch=true 重调强装。
#[tauri::command]
async fn dl_install_manual(
    state: State<'_, AppState>,
    artifact: String,
    path: String,
    allow_mismatch: bool,
) -> Result<download::ManualInstallResult, String> {
    let artifact = download::Artifact::parse(&artifact)?;
    if artifact == download::Artifact::Kernel && state.kernel.running().await {
        return Err("内核运行中，请先关闭订阅代理再安装".into());
    }
    let p = std::path::PathBuf::from(path.trim());
    if p.as_os_str().is_empty() {
        return Err("请填写文件完整路径".into());
    }
    tokio::task::spawn_blocking(move || download::install_manual(artifact, &p, allow_mismatch))
        .await
        .map_err(map_err)?
}

/// 激活/停用订阅功能入口（侧栏「订阅/代理」可见性；停用即停机并关角色）。
#[tauri::command]
async fn activate_subscription_feature(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    if enabled && !subscription::kernel_bin_exists() {
        return Err("内核尚未安装".into());
    }
    if !enabled && state.roles.lock().await.tun_mode {
        return Err("TUN 模式开启中，请先关闭 TUN 模式".into());
    }
    if !enabled {
        state.kernel.stop().await;
        state.client.set_proxy_fallback(None);
    }
    {
        let mut roles = state.roles.lock().await;
        roles.subscription_feature = enabled;
        if !enabled {
            roles.subscription = false;
        }
        roles.save()?;
    }
    roles::audit(
        "gui.subscription_feature",
        serde_json::json!({"on": enabled}),
    );
    Ok(())
}

/// 单选激活订阅；角色开启中即重启内核加载新激活项。
#[tauri::command]
async fn set_active_subscription(
    state: State<'_, AppState>,
    id: String,
) -> Result<subscription::Subscription, String> {
    let sub = subscription::set_active_subscription(&id)?;
    if state.roles.lock().await.subscription {
        state.kernel.stop().await;
        state.kernel.start().await?;
        apply_proxy_fallback(&state).await;
    }
    Ok(sub)
}

/// 添加订阅（先拉取校验）；角色开启中且新订阅为激活项时重启内核。
#[tauri::command]
async fn add_subscription(
    state: State<'_, AppState>,
    name: String,
    url: String,
) -> Result<subscription::Subscription, String> {
    let sub = subscription::add_subscription(&name, &url).await?;
    if state.roles.lock().await.subscription && sub.active {
        state.kernel.stop().await;
        if let Err(e) = state.kernel.start().await {
            return Err(format!("订阅已保存，但内核重启失败: {e}"));
        }
        apply_proxy_fallback(&state).await;
    }
    Ok(sub)
}

/// 导入本地 YAML 订阅：校验路径（存在/yaml 扩展名/≤5MB）→ 读取内容走与 URL 订阅
/// 相同的嗅探入库路径（subscription::add_local_subscription，provider 渲染为 type: file）。
/// 名称取文件名去扩展名；角色开启中且新订阅为激活项时重启内核。
#[tauri::command]
async fn import_local_subscription(
    state: State<'_, AppState>,
    path: String,
) -> Result<subscription::Subscription, String> {
    let p = std::path::PathBuf::from(path.trim());
    let meta = std::fs::metadata(&p).map_err(|_| "文件不存在或不可读".to_string())?;
    if !meta.is_file() {
        return Err("所选路径不是文件".into());
    }
    let ext = p
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if ext != "yaml" && ext != "yml" {
        return Err("仅支持 .yaml / .yml 订阅文件".into());
    }
    if meta.len() > 5 * 1024 * 1024 {
        return Err("文件过大（上限 5MB）".into());
    }
    let body = std::fs::read_to_string(&p).map_err(|e| format!("读取文件失败: {e}"))?;
    let name = p
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let sub = subscription::add_local_subscription(&name, &body)?;
    if state.roles.lock().await.subscription && sub.active {
        state.kernel.stop().await;
        if let Err(e) = state.kernel.start().await {
            return Err(format!("订阅已导入，但内核重启失败: {e}"));
        }
        apply_proxy_fallback(&state).await;
    }
    Ok(sub)
}

/// 删除订阅；角色开启中即重启内核（清空则停机）。
#[tauri::command]
async fn remove_subscription(state: State<'_, AppState>, id: String) -> Result<(), String> {
    subscription::remove_subscription(&id)?;
    if state.roles.lock().await.subscription {
        state.kernel.stop().await;
        if !subscription::list_subscriptions().is_empty() {
            state.kernel.start().await?;
        }
        apply_proxy_fallback(&state).await;
    }
    Ok(())
}

#[tauri::command]
async fn update_subscription(id: String) -> Result<subscription::Subscription, String> {
    subscription::update_subscription(&id).await
}

#[tauri::command]
async fn subscription_status(state: State<'_, AppState>) -> Result<subscription::KernelStatus, String> {
    Ok(state.kernel.status().await)
}

/// 代理组与节点：内核在运行返回实时数据并落缓存；
/// 内核未运行回落到最近缓存（cached 标记），代理页只读展示节点情况
#[tauri::command]
async fn proxy_groups() -> Result<serde_json::Value, String> {
    let live = match subscription::kernel_api().await {
        Ok(api) => match api.proxies().await {
            Ok(mut v) => {
                // 并入 provider 节点协议/历史（/proxies 全局表不含 provider 节点）
                if let Ok(pv) = api.provider_proxies().await {
                    subscription::merge_provider_details(&mut v, &pv);
                }
                Some(v)
            }
            Err(_) => None,
        },
        Err(_) => None,
    };
    match live {
        Some(v) => {
            subscription::save_proxy_cache(&v);
            Ok(v)
        }
        None => subscription::load_proxy_cache().ok_or_else(|| "订阅内核未运行".into()),
    }
}

#[tauri::command]
async fn select_proxy(group: String, name: String) -> Result<(), String> {
    subscription::kernel_api().await?.select(&group, &name).await
}

/// 组测速：provider 节点只能经 /group/{group}/delay 测（内核并发一次测全组），
/// 返回 name → ms（超时节点已被剔除）。
#[tauri::command]
async fn test_delay(group: String) -> Result<std::collections::HashMap<String, u32>, String> {
    subscription::kernel_api().await?.group_delay(&group).await
}

/// 节点测速结果（sub_test_group 返回体；delay=0 表示超时/失败）
#[derive(Debug, Clone, Serialize)]
pub struct NodeDelay {
    pub name: String,
    pub delay: u32,
}

/// 节点批量测速（节点页「每日选妃」）：HTTPS 204 探测、3000ms 超时；
/// 失败/超时节点 delay 归一为 0 并排尾，有效延迟升序返回。
#[tauri::command]
async fn sub_test_group(state: State<'_, AppState>, group: String) -> Result<Vec<NodeDelay>, String> {
    if !state.kernel.running().await {
        return Err("内核未运行".into());
    }
    let mut v: Vec<NodeDelay> = subscription::kernel_api()
        .await?
        .group_delay_all(&group, 3000)
        .await?
        .into_iter()
        .map(|(name, delay)| NodeDelay { name, delay })
        .collect();
    v.sort_by_key(|n| if n.delay == 0 { u32::MAX } else { n.delay });
    Ok(v)
}

/// 开关D：订阅代理角色。开启即启动内核（崩溃自动退避重启），关闭即停机。
/// 内核缺失时不再当场下载：后台开始下载并返回 NEED_DOWNLOAD，前端展示下载卡，完成后自动重试。
#[tauri::command]
async fn set_subscription_role(
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
            float_notify(&app, format!("订阅内核启动失败：{e}"));
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
    apply_proxy_fallback(&state).await;
    Ok(state.kernel.status().await)
}

/// 订阅内核流量快照（/traffic WS 累计；内核停止即清零）。
#[tauri::command]
async fn sub_traffic(state: State<'_, AppState>) -> Result<subscription::TrafficSnapshot, String> {
    Ok(state.kernel.traffic())
}

// ==================== 订阅内核连接/日志采集（/connections、/logs WS） ====================

/// 连接快照返回体（sub_connections 契约）
#[derive(Debug, Clone, Default, Serialize)]
pub struct ConnectionsView {
    /// 活跃连接（up_rate/down_rate 为快照差分速率）
    pub active: Vec<subscription::ConnectionInfo>,
    /// 最近已关闭（新的在前，上限 300）
    pub closed: Vec<subscription::ConnectionInfo>,
}

/// 连接快照：活跃 + 最近已关闭；内核未运行返回空集而非报错。
#[tauri::command]
async fn sub_connections(state: State<'_, AppState>) -> Result<ConnectionsView, String> {
    if !state.kernel.running().await {
        return Ok(ConnectionsView::default());
    }
    let (active, closed) = state.kernel.connections();
    Ok(ConnectionsView { active, closed })
}

/// 内核日志（旧→新排列，上限 500；前端倒序展示自行处理；内核未运行返回空集）。
#[tauri::command]
async fn sub_logs(state: State<'_, AppState>) -> Result<Vec<subscription::LogEntry>, String> {
    if !state.kernel.running().await {
        return Ok(Vec::new());
    }
    Ok(state.kernel.logs())
}

/// 规则命中聚合（count 降序 top 100；内核未运行返回空集）。
#[tauri::command]
async fn sub_rule_hits(state: State<'_, AppState>) -> Result<Vec<subscription::RuleHit>, String> {
    if !state.kernel.running().await {
        return Ok(Vec::new());
    }
    Ok(state.kernel.rule_hits())
}

/// 关闭单条连接（DELETE /connections/{id}）。
#[tauri::command]
async fn sub_close_connection(id: String) -> Result<(), String> {
    if id.is_empty() || id.chars().any(|c| c == '/' || c.is_whitespace()) {
        return Err("连接 id 不合法".into());
    }
    subscription::kernel_api().await?.close_connection(&id).await
}

/// 清空内核日志与规则命中缓冲（连接态不动）。
#[tauri::command]
async fn sub_clear_logs(state: State<'_, AppState>) -> Result<(), String> {
    state.kernel.clear_logs();
    Ok(())
}

/// 一键加规则：把主机加入自定义规则（target=direct 直连放行 / subscription 经订阅出口）。
/// host 自动去 scheme/端口/路径并校验；同主机规则已存在时幂等返回成功。
#[tauri::command]
async fn sub_add_rule_for_host(
    state: State<'_, AppState>,
    host: String,
    target: String,
) -> Result<(), String> {
    let via_subscription = match target.as_str() {
        "direct" => false,
        "subscription" => true,
        _ => return Err("target 参数须为 direct（直连放行）或 subscription（经订阅出口）".into()),
    };
    let host = custom_rules::normalize_host(&host)?;
    // 幂等：同 pattern 规则已存在即视为成功（不改动既有规则的出口取向）
    let exists = custom_rules::snapshot()
        .bypass
        .iter()
        .any(|r| r.pattern.eq_ignore_ascii_case(&host));
    if exists {
        return Ok(());
    }
    custom_rules::add_bypass(&state.client, &host, via_subscription)?;
    roles::audit(
        "gui.sub_rule_for_host",
        serde_json::json!({"host": host, "target": target}),
    );
    Ok(())
}

// ==================== 订阅覆写脚本 / 出站模式 ====================

/// 脚本变更后内核在运行即重启加载新配置（与激活订阅同一热更路径：重写配置 + 重启）。
async fn reload_kernel_if_running(state: &State<'_, AppState>) -> Result<(), String> {
    if state.roles.lock().await.subscription {
        state.kernel.stop().await;
        state.kernel.start().await?;
        apply_proxy_fallback(state).await;
    }
    Ok(())
}

#[tauri::command]
async fn list_sub_scripts(state: State<'_, AppState>) -> Result<Vec<roles::SubScript>, String> {
    Ok(state.roles.lock().await.sub_scripts.clone())
}

/// 新建脚本（默认启用，追加到链尾）；内核运行中即重启生效。
#[tauri::command]
async fn add_sub_script(
    state: State<'_, AppState>,
    name: String,
    code: String,
) -> Result<roles::SubScript, String> {
    if code.trim().is_empty() {
        return Err("脚本代码不能为空".into());
    }
    let sc = {
        let mut roles = state.roles.lock().await;
        let sc = roles::SubScript {
            id: uuid::Uuid::new_v4().simple().to_string(),
            name: if name.trim().is_empty() {
                format!("脚本 {}", roles.sub_scripts.len() + 1)
            } else {
                name.trim().to_string()
            },
            code,
            enabled: true,
            order: roles.sub_scripts.len(),
        };
        roles.sub_scripts.push(sc.clone());
        roles.save()?;
        sc
    };
    roles::audit("gui.sub_script_add", serde_json::json!({"name": sc.name}));
    reload_kernel_if_running(&state).await?;
    Ok(sc)
}

/// 更新脚本名称/代码；内核运行中即重启生效。
#[tauri::command]
async fn update_sub_script(
    state: State<'_, AppState>,
    id: String,
    name: String,
    code: String,
) -> Result<(), String> {
    if code.trim().is_empty() {
        return Err("脚本代码不能为空".into());
    }
    {
        let mut roles = state.roles.lock().await;
        let sc = roles
            .sub_scripts
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or("脚本不存在")?;
        sc.name = if name.trim().is_empty() { sc.name.clone() } else { name.trim().to_string() };
        sc.code = code;
        roles.save()?;
    }
    roles::audit("gui.sub_script_update", serde_json::json!({"id": id}));
    reload_kernel_if_running(&state).await
}

#[tauri::command]
async fn remove_sub_script(state: State<'_, AppState>, id: String) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        let before = roles.sub_scripts.len();
        roles.sub_scripts.retain(|s| s.id != id);
        if roles.sub_scripts.len() == before {
            return Err("脚本不存在".into());
        }
        for (i, s) in roles.sub_scripts.iter_mut().enumerate() {
            s.order = i;
        }
        roles.save()?;
    }
    roles::audit("gui.sub_script_remove", serde_json::json!({"id": id}));
    reload_kernel_if_running(&state).await
}

#[tauri::command]
async fn set_sub_script_enabled(
    state: State<'_, AppState>,
    id: String,
    enabled: bool,
) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        let sc = roles
            .sub_scripts
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or("脚本不存在")?;
        sc.enabled = enabled;
        roles.save()?;
    }
    reload_kernel_if_running(&state).await
}

/// 拖拽排序：ids 为全量脚本 id 的目标顺序（须为现有 id 的排列）。
#[tauri::command]
async fn reorder_sub_scripts(state: State<'_, AppState>, ids: Vec<String>) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        let cur = &roles.sub_scripts;
        if ids.len() != cur.len()
            || !ids.iter().all(|id| cur.iter().any(|s| &s.id == id))
            || !cur.iter().all(|s| ids.contains(&s.id))
        {
            return Err("排序参数与现有脚本不一致".into());
        }
        let mut next: Vec<roles::SubScript> = Vec::with_capacity(cur.len());
        for id in &ids {
            next.push(cur.iter().find(|s| &s.id == id).unwrap().clone());
        }
        for (i, s) in next.iter_mut().enumerate() {
            s.order = i;
        }
        roles.sub_scripts = next;
        roles.save()?;
    }
    reload_kernel_if_running(&state).await
}

/// 试跑：对当前订阅配置（含现有启用脚本管线结果）执行一次，返回摘要或错误。
#[tauri::command]
async fn test_sub_script(state: State<'_, AppState>, code: String) -> Result<String, String> {
    let (mode, scripts) = {
        let r = state.roles.lock().await;
        (r.sub_mode.clone(), r.sub_scripts.clone())
    };
    // 与生产同管线：基础 render（非 TUN；脚本不作用于 TUN 骨架，既定决策）→
    // 启用脚本链（失败跳过）→ 试跑代码（错误透出）
    let store = subscription::current_store();
    let base = subscription::render_config(&store, &mode, false);
    let (effective, _) = sub_script::apply_scripts(&base, &scripts);
    let before: serde_json::Value =
        serde_yaml::from_str(&effective).map_err(|e| format!("当前配置解析失败: {e}"))?;
    let after = sub_script::test_run(&code, &effective)?;
    let count = |v: &serde_json::Value, key: &str| v[key].as_array().map(|a| a.len()).unwrap_or(0);
    let fmt = |key: &str, label: &str| {
        let (b, a) = (count(&before, key), count(&after, key));
        if b == a {
            format!("{label} {a}（不变）")
        } else {
            format!("{label} {b} → {a}")
        }
    };
    Ok(format!(
        "执行成功：{}，{}，{}",
        fmt("proxies", "proxies"),
        fmt("proxy-groups", "groups"),
        fmt("rules", "rules"),
    ))
}

/// 切换订阅出站模式：持久化；内核运行中走控制器 PATCH /configs 热切（失败则重启兜底）。
#[tauri::command]
async fn set_sub_mode(state: State<'_, AppState>, mode: String) -> Result<(), String> {
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
            apply_proxy_fallback(&state).await;
        }
    }
    Ok(())
}

// ==================== 系统代理托管 ====================

/// 期望的系统代理值（本地代理端口）。
fn expected_sysproxy(state: &State<'_, AppState>) -> String {
    format!("127.0.0.1:{}", state.client.proxy_port())
}

/// 客户端代理真实状态写入内嵌节点状态槽（start/stop/模式切换/角色关闭后调用；
/// 管理端「本地代理」卡经 node status 读取，模式来自 GUI 代理设置）。
async fn report_client_proxy(state: &State<'_, AppState>) {
    let port = state.client.proxy_port();
    let system = state.roles.lock().await.system_proxy;
    state.client_proxy_slot.store(Arc::new(Some(
        agile_net_node::service::ClientProxyInfo {
            enabled: port > 0,
            mode: if system { "system" } else { "local" }.to_string(),
            listen: if port > 0 {
                format!("127.0.0.1:{port}")
            } else {
                String::new()
            },
        },
    )));
}

#[tauri::command]
async fn set_system_proxy(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
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
    report_client_proxy(&state).await;
    Ok(())
}

#[tauri::command]
async fn sysproxy_status(state: State<'_, AppState>) -> Result<sysproxy::SysProxyStatus, String> {
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
async fn reclaim_sysproxy(state: State<'_, AppState>) -> Result<(), String> {
    let server = expected_sysproxy(&state);
    tokio::task::spawn_blocking(move || sysproxy::reclaim(&server))
        .await
        .map_err(map_err)?
}

/// 系统代理锁定（硬核模式）：视同托管，巡检发现系统值被改即自动收回期望值。
#[tauri::command]
async fn set_sysproxy_lock(state: State<'_, AppState>, on: bool) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        roles.sysproxy_lock = on;
        roles.save()?;
    }
    roles::audit("gui.sysproxy_lock", serde_json::json!({"on": on}));
    Ok(())
}

// ==================== 代理方式三态（悬浮球菜单） ====================

/// 当前代理方式：tun（TUN 接管）/ system（本地代理 + 系统代理）/ local（仅本地代理）。
#[tauri::command]
async fn proxy_mode_get(state: State<'_, AppState>) -> Result<String, String> {
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
async fn proxy_mode_set(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    mode: String,
) -> Result<String, String> {
    match mode.as_str() {
        "tun" => {
            set_tun_mode(app, state, true).await?;
            roles::audit("gui.proxy_mode", serde_json::json!({"mode": "tun"}));
            Ok("tun".to_string())
        }
        "system" | "local" => {
            if state.roles.lock().await.tun_mode {
                set_tun_mode(app.clone(), state.clone(), false).await?;
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
            report_client_proxy(&state).await;
            roles::audit("gui.proxy_mode", serde_json::json!({"mode": mode}));
            Ok(mode)
        }
        _ => Err(format!("非法代理方式: {mode}")),
    }
}

/// 系统代理接管 toggle（悬浮球菜单）：当前系统代理已指向期望值则还原（返 false），
/// 否则接管（返 true）。与 set_system_proxy 的差别：方向由 inspect 实测决定，无需前端先查状态。
#[tauri::command]
async fn sysproxy_toggle(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
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
    report_client_proxy(&state).await;
    roles::audit("gui.sysproxy_toggle", serde_json::json!({"on": on}));
    Ok(on)
}

// ==================== 网络检测（出口 IP / 内网 IP） ====================

/// 出口探测结果：归属地仅用文字（国家代码/名称），不使用国旗图标
#[derive(Debug, Clone, Serialize)]
pub struct ExitIpInfo {
    pub ip: String,
    pub country: String,
    pub country_code: String,
}

/// 解析 ipwho.is 响应（{success, ip, country, country_code}）
fn parse_ipwho(v: &serde_json::Value) -> Option<ExitIpInfo> {
    if v["success"].as_bool() != Some(true) {
        return None;
    }
    Some(ExitIpInfo {
        ip: v["ip"].as_str()?.to_string(),
        country: v["country"].as_str().unwrap_or_default().to_string(),
        country_code: v["country_code"].as_str().unwrap_or_default().to_string(),
    })
}

/// 解析 ip-api.com 响应（{status, query, country, countryCode}）
fn parse_ip_api(v: &serde_json::Value) -> Option<ExitIpInfo> {
    if v["status"].as_str() != Some("success") {
        return None;
    }
    Some(ExitIpInfo {
        ip: v["query"].as_str()?.to_string(),
        country: v["country"].as_str().unwrap_or_default().to_string(),
        country_code: v["countryCode"].as_str().unwrap_or_default().to_string(),
    })
}

/// 出口 IP 探测：HTTPS 端点优先，失败回落备用端点；via_proxy 时经 mihomo mixed 出口
/// （验证订阅流量真实出口）。5s 超时，全部失败由前端呈现「探测失败」。
#[tauri::command]
async fn fetch_exit_ip(state: State<'_, AppState>, via_proxy: bool) -> Result<ExitIpInfo, String> {
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("anet-gui/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(5));
    if via_proxy {
        // TUN 模式 mixed 口（57892）按防环设计关闭，探测改走订阅出口 socks 口（57893）：
        // socks5h scheme（域名交代理侧解析，避开 fake-ip 段地址在本机直连失败）；
        // 非 TUN 走 mixed 口 http 代理。
        let proxy = if state.roles.lock().await.tun_mode {
            reqwest::Proxy::all(format!(
                "socks5h://127.0.0.1:{}",
                subscription::MIHOMO_SOCKS_PORT
            ))
        } else {
            reqwest::Proxy::all(format!(
                "http://127.0.0.1:{}",
                subscription::MIHOMO_MIXED_PORT
            ))
        }
        .map_err(map_err)?;
        builder = builder.proxy(proxy);
    }
    let client = builder.build().map_err(map_err)?;

    // 首选 ipwho.is（HTTPS、无需密钥）
    if let Ok(resp) = client.get("https://ipwho.is/").send().await {
        if let Ok(v) = resp.json::<serde_json::Value>().await {
            if let Some(info) = parse_ipwho(&v) {
                return Ok(info);
            }
        }
    }
    // 备选 ip-api.com（免费档仅 HTTP）
    let resp = client
        .get("http://ip-api.com/json")
        .send()
        .await
        .map_err(map_err)?;
    let v = resp.json::<serde_json::Value>().await.map_err(map_err)?;
    parse_ip_api(&v).ok_or_else(|| "出口探测失败".into())
}

/// 内网 IP 探测结果（默认网卡首个 IPv4）
#[derive(Debug, Clone, Serialize)]
pub struct LanIpInfo {
    pub ip: String,
    pub iface: String,
}

/// 从 ifconfig 网卡清单挑选内网 IPv4：默认网卡优先，其次第一块 UP 且非回环的网卡。
fn pick_lan_ip(ifaces: &[serde_json::Value]) -> Option<LanIpInfo> {
    let pick = |pred: &dyn Fn(&serde_json::Value) -> bool| -> Option<LanIpInfo> {
        ifaces.iter().filter(|i| pred(i)).find_map(|i| {
            // ipv4 元素带前缀长度（如 192.168.1.5/24），展示只取地址段
            let raw = i["ipv4"].as_array()?.first()?.as_str()?;
            let ip = raw.split('/').next()?.to_string();
            let iface = i["friendly_name"]
                .as_str()
                .or_else(|| i["name"].as_str())
                .unwrap_or_default()
                .to_string();
            Some(LanIpInfo { ip, iface })
        })
    };
    pick(&|i| i["is_default"].as_bool() == Some(true)).or_else(|| {
        pick(&|i| i["is_up"].as_bool() == Some(true) && i["is_loopback"].as_bool() != Some(true))
    })
}

/// 内网 IP：复用 anet tool ifconfig 的网卡枚举（Windows 含 netsh 子进程，放阻塞池执行）。
#[tauri::command]
async fn lan_ip() -> Result<LanIpInfo, String> {
    tokio::task::spawn_blocking(|| {
        let out = agile_net_node::tool::netif::ifconfig();
        let ifaces = out.json["interfaces"].as_array().cloned().unwrap_or_default();
        pick_lan_ip(&ifaces).ok_or_else(|| "未检测到内网 IPv4".to_string())
    })
    .await
    .map_err(map_err)?
}

// ==================== 卸载 ====================

/// 卸载清理选项（勾选哪些本地数据随卸载一并删除）
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UninstallOptions {
    /// 已保存的节点与凭据（credentials.json）
    pub credentials: bool,
    /// 服务端节点数据（embedded-node/：数据库与证书）
    pub server_data: bool,
    /// 配置与偏好（gui-settings.json / web-auth.json；主题语言由前端清 localStorage）
    pub prefs: bool,
    /// 审计日志（gui-audit.jsonl）
    pub audit: bool,
}

/// 卸载应用：记审计 → 停机释放文件锁 → 清理所选数据 → 关闭自启 → 拉起系统卸载程序并退出。
#[tauri::command]
async fn uninstall_app(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    options: UninstallOptions,
) -> Result<(), String> {
    roles::audit(
        "gui.uninstall",
        serde_json::json!({
            "credentials": options.credentials,
            "server_data": options.server_data,
            "prefs": options.prefs,
            "audit": options.audit,
        }),
    );

    // 停掉内嵌节点 / Web 远程面 / 订阅内核 / 全部隧道（释放 SQLite 与端口占用）
    if let Some(s) = state.server.lock().await.take() {
        s.stop().await;
    }
    if let Some(h) = state.web_api.lock().await.take() {
        h.stop().await;
    }
    state.kernel.stop().await;
    state.client.disconnect_all().await;
    state.client.stop_proxy().await;

    // 系统代理托管中（含 TUN 模式自动托管）：卸载前还原系统代理
    {
        let r = state.roles.lock().await;
        if r.system_proxy || r.tun_mode {
            drop(r);
            let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
        }
    }

    // 卸载必做：移除开机自启
    {
        use tauri_plugin_autostart::ManagerExt;
        let _ = app.autolaunch().disable();
    }

    let dir = roles::data_dir();
    if options.credentials {
        let _ = std::fs::remove_file(dir.join("credentials.json"));
        let _ = std::fs::remove_file(dir.join("subscriptions.json"));
    }
    if options.prefs {
        let _ = std::fs::remove_file(dir.join("gui-settings.json"));
        let _ = std::fs::remove_file(dir.join("web-auth.json"));
    }
    if options.audit {
        let _ = std::fs::remove_file(dir.join("gui-audit.jsonl"));
    }
    if options.server_data {
        let _ = std::fs::remove_dir_all(roles::embedded_dir());
        let _ = std::fs::remove_dir_all(subscription::kernel_dir());
    }

    launch_system_uninstaller()?;
    app.exit(0);
    Ok(())
}

/// 拉起系统卸载程序（Windows NSIS：安装目录 uninstall.exe，自带确认页，
/// 用户确认时本进程已退出，可正常删除安装目录）。
#[cfg(windows)]
fn launch_system_uninstaller() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(map_err)?;
    let uninstaller = exe
        .parent()
        .map(|p| p.join("uninstall.exe"))
        .unwrap_or_default();
    if !uninstaller.exists() {
        return Err("未找到系统卸载程序（数据已按所选清理；便携版请手动删除应用目录）".into());
    }
    std::process::Command::new(uninstaller)
        .spawn()
        .map_err(map_err)?;
    Ok(())
}

/// 非 Windows 桌面平台无系统卸载程序：数据已清理，提示用户手动移除应用本体。
#[cfg(not(windows))]
fn launch_system_uninstaller() -> Result<(), String> {
    Err("数据已按所选清理；请将应用本体移入废纸篓/删除以完成卸载".into())
}

// ==================== 托盘图标（zap 开 / zap-off 关，黑白随系统主题自适应） ====================

/// 托盘图标（64px 透明底 PNG；dark=黑色图形用于浅色任务栏，light=白色图形用于深色任务栏）
const TRAY_ZAP_DARK: &[u8] = include_bytes!("../icons/tray-zap-dark.png");
const TRAY_ZAP_LIGHT: &[u8] = include_bytes!("../icons/tray-zap-light.png");
const TRAY_ZAP_OFF_DARK: &[u8] = include_bytes!("../icons/tray-zap-off-dark.png");
const TRAY_ZAP_OFF_LIGHT: &[u8] = include_bytes!("../icons/tray-zap-off-light.png");

/// 当前系统主题下应使用的托盘图标。
/// macOS 走模板图标（icon_as_template），系统按菜单栏外观自动反色，固定取黑色版本；
/// Windows/Linux 按主窗口跟踪的系统主题手动选黑白。
fn tray_icon(app: &tauri::AppHandle, proxy_on: bool) -> tauri::image::Image<'static> {
    #[cfg(target_os = "macos")]
    let dark_taskbar = false;
    #[cfg(not(target_os = "macos"))]
    let dark_taskbar = app
        .get_webview_window("main")
        .and_then(|w| w.theme().ok())
        .map(|t| matches!(t, tauri::Theme::Dark))
        .unwrap_or(false);
    let bytes = match (proxy_on, dark_taskbar) {
        (true, true) => TRAY_ZAP_LIGHT,
        (true, false) => TRAY_ZAP_DARK,
        (false, true) => TRAY_ZAP_OFF_LIGHT,
        (false, false) => TRAY_ZAP_OFF_DARK,
    };
    tauri::image::Image::from_bytes(bytes).expect("托盘图标 PNG 解码失败")
}

/// 刷新托盘图标：代理运行=zap / 停止=zap-off，黑白随系统主题。
fn refresh_tray_icon(app: &tauri::AppHandle) {
    let Some(tray) = app.tray_by_id("anet-tray") else {
        return;
    };
    let proxy_on = app.state::<AppState>().client.proxy_port() > 0;
    let _ = tray.set_icon(Some(tray_icon(app, proxy_on)));
}

/// 启动时恢复订阅内核（上次退出时订阅角色处于开启状态）。
/// TUN 模式持久化恢复（§2.2 提权重启后自动恢复开启）：补 wintun → 启动内核（TUN 骨架）
/// → 数据面/系统代理副作用（拨测结果进状态槽，前端灵动岛告警）。
async fn restore_subscription_role(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    let (sub_on, tun_mode) = {
        let r = state.roles.lock().await;
        (r.subscription, r.tun_mode)
    };
    if !sub_on {
        return;
    }
    if subscription::list_subscriptions().is_empty() {
        tracing::warn!("subscription role was enabled but no subscription exists — keeping kernel stopped");
        return;
    }
    // 内核缺失：后台下载（不再阻塞恢复流程；完成后用户重开订阅角色即生效）
    if !subscription::kernel_bin_exists() {
        if let Err(e) = state.dl.start(download::Artifact::Kernel) {
            tracing::error!(error = %e, "failed to start kernel download on restore");
        } else {
            tracing::info!("kernel missing on restore — background download started");
        }
        return;
    }
    // 提权重启后被用户取消（UAC 拒绝）或权限已丢失：放弃 TUN 改普通模式恢复，不影响使用
    let mut tun_mode = tun_mode;
    if tun_mode && !tun::SystemElevation.is_admin() {
        tracing::warn!("persisted TUN mode but process is not elevated — abandoning TUN, restore as normal mode");
        abandon_tun(&state, "需要管理员权限").await;
        tun_mode = false;
    }
    if tun_mode {
        if let Err(e) = subscription::ensure_wintun().await {
            // wintun 缺失：后台下载（完成后用户重开 TUN 即可）；其它错误同样只放弃 TUN，不阻断普通模式恢复
            if e.starts_with(subscription::NEED_DOWNLOAD_PREFIX) {
                let _ = state.dl.start(download::Artifact::Wintun);
                abandon_tun(&state, "wintun 组件未安装，已转为后台下载").await;
            } else {
                tracing::error!(error = %e, "failed to ensure wintun for persisted TUN mode");
                abandon_tun(&state, &format!("wintun 组件不可用（{e}）")).await;
            }
            tun_mode = false;
        }
    }
    match state.kernel.start().await {
        Ok(()) => {
            tracing::info!(tun = tun_mode, "subscription kernel restored");
            apply_proxy_fallback(&state).await;
            if tun_mode {
                if let Err(e) = tun_side_effects(app, &state).await {
                    tracing::error!(error = %e, "failed to apply TUN side effects on restore");
                }
            }
        }
        Err(e) => {
            if tun_mode {
                // TUN 配置启动失败：放弃 TUN 再以普通模式重试一次
                tracing::error!(error = %e, "failed to restore kernel with TUN, retrying normal mode");
                abandon_tun(&state, &format!("启动失败（{e}）")).await;
                match state.kernel.start().await {
                    Ok(()) => {
                        tracing::info!("subscription kernel restored in normal mode after TUN failure");
                        apply_proxy_fallback(&state).await;
                    }
                    Err(e2) => tracing::error!(error = %e2, "failed to restore subscription kernel"),
                }
            } else {
                tracing::error!(error = %e, "failed to restore subscription kernel");
            }
        }
    }
}

/// 系统代理冲突巡检（30s）：托管中系统值 ≠ 期望值即记审计。
/// TUN 模式（§2.6）与锁定模式（sysproxy_lock）升级为自动收回：被抢即重写期望值并记审计
/// （含来源值；锁定来源 detail 注明 lock:true），每轮处理；
/// 非自动收回维持"提醒手动收回"（每轮冲突只记一次，恢复后可再记）。
async fn sysproxy_watch(app: tauri::AppHandle) {
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
                float_notify(&app, "系统代理被修改，已自动收回");
            } else if st.conflict && !in_conflict {
                roles::audit(
                    "gui.sysproxy_conflict",
                    serde_json::json!({"expected": st.expected, "current": st.current}),
                );
                float_notify(&app, "检测到系统代理冲突");
            }
            in_conflict = st.conflict;
        }
    }
}

/// 托盘 tooltip 实时网速（1s）：内核运行且有速率时显示 ↑/↓，否则回退静态文案；
/// 平台差异容错（set_tooltip 失败静默，不 panic）。
async fn tray_speed_watch(app: tauri::AppHandle) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let Some(tray) = app.tray_by_id("anet-tray") else {
            continue;
        };
        let state = app.state::<AppState>();
        let snap = state.kernel.traffic();
        let tip = if state.kernel.running().await && (snap.up_rate > 0 || snap.down_rate > 0) {
            format!(
                "↑ {}/s ↓ {}/s · AgileNet",
                subscription::format_rate(snap.up_rate),
                subscription::format_rate(snap.down_rate)
            )
        } else {
            "AgileNet 客户端".to_string()
        };
        let _ = tray.set_tooltip(Some(&tip));
    }
}

/// 构建系统托盘（左键/双击打开主窗口，右键弹出菜单面板；无系统原生菜单）
fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    TrayIconBuilder::with_id("anet-tray")
        .icon(tray_icon(app.handle(), false))
        .icon_as_template(true) // macOS 模板图标：系统按菜单栏深浅自动反色
        .tooltip("AgileNet 客户端")
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button,
                button_state,
                position,
                ..
            } = event
            {
                if button_state != MouseButtonState::Up {
                    return;
                }
                match button {
                    // 左键（含双击，两次单击事件）：直接打开主窗口
                    MouseButton::Left => show_main_window(tray.app_handle()),
                    // 右键：托盘菜单面板
                    MouseButton::Right => toggle_tray_popup(
                        tray.app_handle(),
                        tauri::PhysicalPosition::new(position.x, position.y),
                    ),
                    _ => {}
                }
            }
        })
        .build(app)?;
    Ok(())
}

/// 显示并聚焦主窗口（托盘左键与托盘面板共用）
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

// ---- 弹窗定位（全程物理坐标；clamp_popup / tray_popup_position 为纯函数，单测覆盖） ----

/// 把期望矩形 (ex, ey, w, h) 收进工作区 (left, top, right, bottom)，四边留 8px 边距。
/// 工作区比窗口还小时退化为贴左上边距（clamp 的 min>max 防御）。
fn clamp_popup(ex: f64, ey: f64, w: f64, h: f64, area: (f64, f64, f64, f64)) -> (i32, i32) {
    const M: f64 = 8.0;
    let (left, top, right, bottom) = area;
    let x = ex.clamp(left + M, (right - w - M).max(left + M));
    let y = ey.clamp(top + M, (bottom - h - M).max(top + M));
    (x.round() as i32, y.round() as i32)
}

/// 托盘弹窗期望位：弹窗底边贴 anchor 上方 8px、水平居中；anchor 上方空间不足
/// （y 越出工作区顶边距）则翻转到 anchor 下方 8px；最后 clamp 进工作区。
/// 多显示器 / 任务栏在任意边（含 macOS 顶部菜单栏）均正确。
fn tray_popup_position(anchor: (f64, f64), size: (f64, f64), area: (f64, f64, f64, f64)) -> (i32, i32) {
    let (w, h) = size;
    let mut y = anchor.1 - h - 8.0;
    if y < area.1 + 8.0 {
        y = anchor.1 + 8.0;
    }
    clamp_popup(anchor.0 - w / 2.0, y, w, h, area)
}

/// anchor 所在显示器的工作区（物理坐标 (left, top, right, bottom)）与缩放因子。
/// 取不到显示器信息时给一个足够大的区域（仅保证 clamp 后非负）。
fn work_area_at(app: &tauri::AppHandle, x: f64, y: f64) -> ((f64, f64, f64, f64), f64) {
    let monitor = app
        .monitor_from_point(x, y)
        .ok()
        .flatten()
        .or_else(|| app.primary_monitor().ok().flatten());
    match monitor {
        Some(m) => {
            let area = m.work_area();
            let p = area.position;
            let s = area.size;
            (
                (
                    p.x as f64,
                    p.y as f64,
                    p.x as f64 + s.width as f64,
                    p.y as f64 + s.height as f64,
                ),
                m.scale_factor(),
            )
        }
        None => ((0.0, 0.0, f64::MAX / 2.0, f64::MAX / 2.0), 1.0),
    }
}

/// 失焦隐藏/关闭监听「延迟武装」：show 首帧会立即触发一次 Focused(false)，
/// 若在 build 期就挂监听会把刚显示的窗口当场隐藏/关闭（用户看到闪一下不出现，第二次才好）。
/// 故 show 之后延时 400ms 再挂监听。close=false 隐藏（托盘面板复用语义），true 关闭（一次性小窗）。
fn arm_blur_close(window: &tauri::WebviewWindow, close: bool) {
    let w = window.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(400));
        let w2 = w.clone();
        w.on_window_event(move |event| {
            if let tauri::WindowEvent::Focused(false) = event {
                if close {
                    let _ = w2.close();
                } else {
                    let _ = w2.hide();
                }
            }
        });
    });
}

/// 弹出/收起托盘面板（懒创建；失焦自动隐藏）。
/// 坐标全程物理坐标系：anchor 来自托盘事件（物理），工作区同样物理；
/// builder 不设 position，build 后以物理坐标 set_position → show → set_focus，杜绝首击闪帧。
fn toggle_tray_popup(app: &tauri::AppHandle, anchor: tauri::PhysicalPosition<f64>) {
    // 托盘事件跑在主线程：work_area_at/monitor_from_point/is_visible 等 getter 均
    // channel 阻塞式（等事件循环应答），主线程调用即自锁——整体移到工作线程。
    let app = app.clone();
    std::thread::spawn(move || {
        toggle_tray_popup_inner(&app, anchor);
    });
}
fn toggle_tray_popup_inner(app: &tauri::AppHandle, anchor: tauri::PhysicalPosition<f64>) {
    const W: f64 = 292.0;
    const H: f64 = 420.0;
    // 尺寸×缩放 = 物理像素：anchor/工作区均物理坐标，逻辑尺寸不换算会把弹窗放出屏外
    let (area, scale) = work_area_at(app, anchor.x, anchor.y);
    let (x, y) = tray_popup_position((anchor.x, anchor.y), (W * scale, H * scale), area);
    if let Some(w) = app.get_webview_window("tray-popup") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
            return;
        }
        let _ = w.set_position(tauri::PhysicalPosition::new(x, y));
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let Ok(window) = tauri::WebviewWindowBuilder::new(
        app,
        "tray-popup",
        tauri::WebviewUrl::App("tray.html".into()),
    )
    .title("AgileNet")
    .inner_size(W, H)
    .resizable(false)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .visible(false) // 先定位后显示，杜绝左上角闪帧
    .build()
    else {
        return;
    };
    arm_blur_close(&window, false);
    let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
    let _ = window.show();
    let _ = window.set_focus();
}

/// 托盘面板：显示主窗口
#[tauri::command]
fn tray_show_main(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(w) = app.get_webview_window("tray-popup") {
        let _ = w.hide();
    }
    show_main_window(&app);
    Ok(())
}

/// 托盘面板：退出应用
#[tauri::command]
fn tray_quit(app: tauri::AppHandle) {
    app.exit(0);
}

// ==================== 悬浮球窗口（仅桌面） ====================

/// 悬浮球锚点信息：球体可视区左上物理坐标 (x, y)、球可视高、球所在显示器工作区与缩放因子。
/// 用 inner_position/inner_size：outer_* 在 Windows 含 DWM 隐形边框（72→170），会算歪菜单位置。
/// 球不存在返回 None。
fn ball_anchor(app: &tauri::AppHandle) -> Option<(f64, f64, f64, (f64, f64, f64, f64), f64)> {
    // Windows 原生球：位置由 floatball 静态槽提供（无 webview 窗口）
    #[cfg(windows)]
    if let Some((bx, by, bs)) = floatball::rect() {
        let (area, scale) = work_area_at(app, bx as f64, by as f64);
        return Some((bx as f64, by as f64, bs as f64, area, scale));
    }
    let ball = app.get_webview_window("float-ball")?;
    let pos = ball.inner_position().ok()?;
    let size = ball.inner_size().ok()?;
    let (area, scale) = work_area_at(app, pos.x as f64, pos.y as f64);
    Some((pos.x as f64, pos.y as f64, size.height as f64, area, scale))
}

/// 悬浮球气泡通知（桥接既有告警点与 float_ball_notify 命令共用）：
/// 单例窗口 float-bubble + 事件 ag-bubble-text 续命——窗口已存在则只发新文本，
/// 前端渲染后 4s 自行 close（窗口销毁由前端驱动，后端无需清理）。
/// 用户关闭「悬浮球通知」偏好后全局静默（含既有桥接点）。
fn float_notify(app: &tauri::AppHandle, text: impl Into<String>) {
    use tauri::Emitter;
    if let Some(state) = app.try_state::<AppState>() {
        if !state.notify_float_ball.load(Ordering::Relaxed) {
            return;
        }
    }
    let text = text.into();
    if app.get_webview_window("float-bubble").is_some() {
        let _ = app.emit_to("float-bubble", "ag-bubble-text", text);
        return;
    }
    // ball_anchor/build 等 channel 阻塞式调用：本函数可能被主线程上下文
    // （sync 命令）调到，窗口操作整体丢工作线程，杜绝自锁。
    let app = app.clone();
    std::thread::spawn(move || {
        float_notify_inner(&app, text);
    });
}
/// 气泡待读文本：float_notify_inner 写入，float-bubble 页加载完成后经 float_bubble_take 取走。
/// （替代原先的 emit + 600ms 补发：首帧 webview 未挂监听会丢事件，气泡空卡常驻）
static BUBBLE_PENDING: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// float-bubble 页就绪后取待读文本（取走即清；None = 无通知，前端应立即自关窗口）。
#[tauri::command]
fn float_bubble_take() -> Option<String> {
    BUBBLE_PENDING.lock().ok()?.take()
}

fn float_notify_inner(app: &tauri::AppHandle, text: String) {
    const W: f64 = 220.0;
    const H: f64 = 96.0;
    // 不透明卡片（气泡即卡片，不依赖 transparent；同源同窗扩容方案在 Windows 透明失效后废弃）
    let Ok(window) = tauri::WebviewWindowBuilder::new(
        app,
        "float-bubble",
        tauri::WebviewUrl::App("float-bubble.html".into()),
    )
    .title("AgileNet")
    .inner_size(W, H)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(false) // 先定位后显示
    .build()
    else {
        return;
    };
    // 位置：球左边 10px、垂直与球居中，clamp 进球所在工作区
    if let Some((bx, by, bh, area, scale)) = ball_anchor(app) {
        let (x, y) = clamp_popup(
            bx - W * scale - 10.0,
            by + (bh - H * scale) / 2.0,
            W * scale,
            H * scale,
            area,
        );
        let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
    }
    // 文本落待读槽（若槽里有旧文本被覆盖：前端取最新一条即可），页面 ready 后自取
    if let Ok(mut p) = BUBBLE_PENDING.lock() {
        *p = Some(text);
    }
    let _ = window.show();
}

/// 创建悬浮球窗口（幂等）：72×72 无框透明常驻，默认定位主屏右下角偏移
/// （取主屏方式与 normalize_window_geometry 一致）。
#[cfg(desktop)]
#[cfg(all(desktop, windows))]
fn create_float_ball(app: &tauri::AppHandle) -> Result<(), String> {
    // Windows：原生分层窗球（GDI+ 绘制，不经 WebView；透明/窗框/裁剪整类问题根绝）
    floatball::create(app)
}

#[cfg(all(desktop, not(windows)))]
fn create_float_ball(app: &tauri::AppHandle) -> Result<(), String> {
    const SIZE: f64 = 72.0;
    if app.get_webview_window("float-ball").is_some() {
        return Ok(());
    }
    let mut x = 100.0;
    let mut y = 100.0;
    if let Ok(Some(m)) = app.primary_monitor() {
        let scale = m.scale_factor();
        let logical_w = m.size().width as f64 / scale;
        let logical_h = m.size().height as f64 / scale;
        x = (logical_w - SIZE - 24.0).max(0.0);
        y = (logical_h - SIZE - 96.0).max(0.0);
    }
    tauri::WebviewWindowBuilder::new(
        app,
        "float-ball",
        tauri::WebviewUrl::App("float.html".into()),
    )
    .title("AgileNet")
    .inner_size(SIZE, SIZE)
    .decorations(false)
    .transparent(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .position(x, y)
    .build()
    .map_err(map_err)?;
    Ok(())
}

/// 移动端不支持悬浮球（平台判定返回不支持；保持 mobile 目标编译不破）。
#[cfg(not(desktop))]
fn create_float_ball(_app: &tauri::AppHandle) -> Result<(), String> {
    Err("悬浮球仅支持桌面端".into())
}

/// 悬浮球开关：on=创建窗口，off=销毁；持久化 + 审计（setup 恢复读取同一字段）。
#[tauri::command]
async fn set_float_ball(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    on: bool,
) -> Result<(), String> {
    if on {
        create_float_ball(&app)?;
    } else {
        #[cfg(windows)]
        floatball::destroy();
        if let Some(w) = app.get_webview_window("float-ball") {
            let _ = w.close();
        }
    }
    {
        let mut roles = state.roles.lock().await;
        roles.float_ball = on;
        roles.save()?;
    }
    roles::audit("gui.float_ball", serde_json::json!({"on": on}));
    Ok(())
}

/// 悬浮球气泡通知开关：false 时 float_notify 桥接点与 float_ball_notify 命令均不再 emit。
#[tauri::command]
async fn set_notify_float_ball(state: State<'_, AppState>, on: bool) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        roles.notify_float_ball = on;
        roles.save()?;
    }
    state.notify_float_ball.store(on, Ordering::Relaxed);
    roles::audit("gui.notify_float_ball", serde_json::json!({"on": on}));
    Ok(())
}

/// 性能模式（前端据此关模糊/动画；后端仅持久化存取）。
#[tauri::command]
async fn set_reduce_effects(state: State<'_, AppState>, on: bool) -> Result<(), String> {
    {
        let mut roles = state.roles.lock().await;
        roles.reduce_effects = on;
        roles.save()?;
    }
    roles::audit("gui.reduce_effects", serde_json::json!({"on": on}));
    Ok(())
}

/// 悬浮球气泡通知通道（前端主窗 → 悬浮球气泡窗口）。
#[tauri::command]
fn float_ball_notify(app: tauri::AppHandle, text: String) -> Result<(), String> {
    float_notify(&app, text);
    Ok(())
}

/// 悬浮球右键菜单（独立小窗 float-menu；toggle 语义：已可见则关闭）。
/// 不透明卡片（菜单本就该不透明，不依赖 transparent）；失焦自动关闭（延迟武装 400ms）。
/// 必须 async：ball_anchor 的 outer_position/outer_size 是 channel 阻塞式调用，
/// sync 命令跑在主线程会自锁（菜单弹不出 + 主窗卡死）。
#[tauri::command]
async fn float_open_menu(app: tauri::AppHandle) -> Result<(), String> {
    float_open_menu_impl(&app).await
}

/// 菜单打开/定位的共享实现（命令与原生悬浮球右键共用）。
pub(crate) async fn float_open_menu_impl(app: &tauri::AppHandle) -> Result<(), String> {
    const W: f64 = 200.0;
    const H: f64 = 320.0; // 268 + 出站模式按钮组（规则/全局/直连）
    // 期望位：菜单右边距球左边 10px，底边对齐球底，clamp 进球所在工作区
    let position = |app: &tauri::AppHandle| -> Option<tauri::PhysicalPosition<i32>> {
        let (bx, by, bh, area, scale) = ball_anchor(app)?;
        let (x, y) = clamp_popup(bx - W * scale - 10.0, by + bh - H * scale, W * scale, H * scale, area);
        Some(tauri::PhysicalPosition::new(x, y))
    };
    if let Some(w) = app.get_webview_window("float-menu") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.close();
            return Ok(());
        }
        if let Some(p) = position(&app) {
            let _ = w.set_position(p);
        }
        let _ = w.show();
        let _ = w.set_focus();
        return Ok(());
    }
    let window = tauri::WebviewWindowBuilder::new(
        app,
        "float-menu",
        tauri::WebviewUrl::App("float-menu.html".into()),
    )
    .title("AgileNet")
    .inner_size(W, H)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .visible(false) // 先定位后显示
    .build()
    .map_err(map_err)?;
    arm_blur_close(&window, true);
    if let Some(p) = position(&app) {
        let _ = window.set_position(p);
    }
    let _ = window.show();
    let _ = window.set_focus();
    Ok(())
}

/// 自我诊断（与 `anet doctor` 共用同一引擎；检查含 netstat/注册表/文件 IO 等阻塞操作，
/// 整体丢进 spawn_blocking 再 block_on 驱动异步探测，避免占住运行时线程）
#[tauri::command]
async fn run_doctor(app: tauri::AppHandle) -> Result<agile_net_node::tool::doctor::DoctorReport, String> {
    use agile_net_node::tool::doctor as doc;
    use tauri::Emitter as _;
    roles::audit("gui.doctor", serde_json::json!({}));
    // 流式诊断：先发检查节计划（前端渲染骨架），每完成一节推一个事件，最后返回完整报告
    let _ = app.emit("ag-doctor-begin", doc::SECTION_PLAN);
    tauri::async_runtime::spawn_blocking(move || {
        tauri::async_runtime::block_on(doc::run_streaming(doc::DoctorContext::gui(), |sec| {
            let _ = app.emit("ag-doctor-section", sec);
        }))
    })
    .await
    .map_err(map_err)
}

/// 事件中心：gui-audit.jsonl 尾部倒读白名单事件（新的在前；默认 50 条，上限 200）。
/// 文件不存在返回空 Vec。
#[tauri::command]
fn recent_events(limit: Option<u32>) -> Result<Vec<roles::GuiEvent>, String> {
    let n = limit.unwrap_or(50).clamp(1, 200) as usize;
    Ok(roles::recent_events(n))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            connect_node,
            disconnect_node,
            list_nodes,
            list_credentials,
            delete_credential,
            export_credential,
            set_rule_paused,
            get_paused_rules,
            set_paused_rules,
            start_proxy,
            stop_proxy,
            proxy_status,
            proxy_power,
            proxy_power_toggle,
            parse_connect_url,
            open_url,
            tray_show_main,
            tray_quit,
            set_float_ball,
            float_ball_notify,
            float_open_menu,
            float_bubble_take,
            set_notify_float_ball,
            set_reduce_effects,
            run_doctor,
            recent_events,
            set_autostart,
            get_autostart,
            get_role_settings,
            set_client_role,
            server_status,
            init_server_admin,
            set_server_role,
            has_web_password,
            set_web_password,
            set_web_role,
            console_url,
            broadcast_theme,
            list_server_connectors,
            add_server_connector,
            update_server_connector,
            remove_server_connector,
            list_embedded_groups,
            uninstall_app,
            list_subscriptions,
            add_subscription,
            remove_subscription,
            update_subscription,
            set_active_subscription,
            subscription_status,
            install_kernel,
            dl_state,
            dl_start,
            dl_cancel,
            dl_install_manual,
            activate_subscription_feature,
            proxy_groups,
            select_proxy,
            test_delay,
            sub_test_group,
            set_subscription_role,
            sub_traffic,
            sub_connections,
            sub_logs,
            sub_rule_hits,
            sub_close_connection,
            sub_clear_logs,
            sub_add_rule_for_host,
            import_local_subscription,
            list_sub_scripts,
            add_sub_script,
            update_sub_script,
            remove_sub_script,
            set_sub_script_enabled,
            reorder_sub_scripts,
            test_sub_script,
            set_sub_mode,
            set_system_proxy,
            sysproxy_status,
            sysproxy_toggle,
            proxy_mode_get,
            proxy_mode_set,
            reclaim_sysproxy,
            set_sysproxy_lock,
            tun_status,
            set_tun_mode,
            tun_relaunch_elevated,
            tun_elevation_declined,
            set_tun_upstream,
            fetch_exit_ip,
            lan_ip,
            list_custom_rules,
            add_bypass_rule,
            add_host_mapping,
            set_custom_rule_enabled,
            remove_custom_rule,
            list_rule_combos,
            add_combo,
            update_combo,
            remove_combo,
            set_combo_enabled,
            sync::get_sync_config,
            sync::set_sync_config,
            sync::sync_check,
            sync::sync_upload,
            sync::sync_restore,
            sync::sync_export,
            sync::sync_import,
        ])
        .setup(|app| {
            setup_tray(app)?;

            // 恢复上次开启的服务端角色（内嵌节点）与订阅内核；启动系统代理巡检
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                restore_server_role(&handle).await;
                restore_web_role(&handle).await;
                restore_subscription_role(&handle).await;
                // 恢复自定义规则（放行/hosts 映射/组合的生效并集 → 引擎热更）
                custom_rules::restore(&handle.state::<AppState>().client);
            });
            // 启动清理：上次异常退出（进程被杀）可能遗留系统代理指向已死端口，按快照还原
            tauri::async_runtime::spawn(async move {
                let _ = tokio::task::spawn_blocking(sysproxy::cleanup_if_pending).await;
            });
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                sysproxy_watch(handle).await;
            });
            // 托盘 tooltip 实时网速（1s）
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tray_speed_watch(handle).await;
            });
            // 恢复悬浮球（上次退出时处于开启状态；仅桌面，移动端 create 返回不支持）
            if roles::RoleSettings::load().float_ball {
                let _ = create_float_ball(app.handle());
            }

            // 窗口尺寸与定位：主屏逻辑宽 1/2、4:3、屏幕居中（与控制台统一规格）；
            // 创建即隐藏（conf visible:false），定位完成后再显示，杜绝左上角闪帧
            if let Some(window) = app.get_webview_window("main") {
                normalize_window_geometry(&window);
                let _ = window.show();
                let _ = window.set_focus();
            }

            // 关闭窗口时最小化到托盘（不退出进程）；系统主题变化时刷新托盘图标黑白
            if let Some(window) = app.get_webview_window("main") {
                let w = window.clone();
                let handle = app.handle().clone();
                window.on_window_event(move |event| match event {
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        let _ = w.hide();
                    }
                    tauri::WindowEvent::ThemeChanged(_) => refresh_tray_icon(&handle),
                    _ => {}
                });
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building AgileNet desktop");
    app.run(|app_handle: &tauri::AppHandle, event: tauri::RunEvent| {
        // §2.6 退出 GUI（TUN 模式）：停内核（mihomo 退出自动清理 TUN 适配器与路由）
        // + 还原系统代理快照；事件回调在主线程，block_on 安全
        if let tauri::RunEvent::ExitRequested { .. } = event {
            let state = app_handle.state::<AppState>();
            let tun_on =
                tauri::async_runtime::block_on(async { state.roles.lock().await.tun_mode });
            if tun_on {
                let kernel = state.kernel.clone();
                let _ = tauri::async_runtime::block_on(async move {
                    tokio::time::timeout(std::time::Duration::from_secs(5), kernel.stop()).await
                });
                let _ = sysproxy::disengage();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipwho_response() {
        let v = serde_json::json!({"success": true, "ip": "203.0.113.7", "country": "China", "country_code": "CN"});
        let info = parse_ipwho(&v).expect("应解析成功");
        assert_eq!(info.ip, "203.0.113.7");
        assert_eq!(info.country, "China");
        assert_eq!(info.country_code, "CN");
        // success=false / 缺 ip 均不取
        assert!(parse_ipwho(&serde_json::json!({"success": false, "message": "invalid"})).is_none());
        assert!(parse_ipwho(&serde_json::json!({"success": true})).is_none());
    }

    #[test]
    fn parses_ip_api_response() {
        let v = serde_json::json!({"status": "success", "query": "198.51.100.9", "country": "United States", "countryCode": "US"});
        let info = parse_ip_api(&v).expect("应解析成功");
        assert_eq!(info.ip, "198.51.100.9");
        assert_eq!(info.country, "United States");
        assert_eq!(info.country_code, "US");
        assert!(parse_ip_api(&serde_json::json!({"status": "fail"})).is_none());
    }

    #[test]
    fn picks_default_iface_ipv4_and_strips_prefix() {
        let ifaces = vec![
            serde_json::json!({"name": "lo", "is_up": true, "is_loopback": true, "is_default": false, "ipv4": ["127.0.0.1/8"]}),
            serde_json::json!({"name": "eth0", "is_up": true, "is_loopback": false, "is_default": true, "ipv4": ["192.168.1.5/24"]}),
        ];
        let info = pick_lan_ip(&ifaces).expect("应选中默认网卡");
        assert_eq!(info.ip, "192.168.1.5");
        assert_eq!(info.iface, "eth0");
    }

    #[test]
    fn falls_back_to_first_up_non_loopback() {
        let ifaces = vec![
            serde_json::json!({"name": "lo", "is_up": true, "is_loopback": true, "is_default": false, "ipv4": ["127.0.0.1/8"]}),
            serde_json::json!({"friendly_name": "WLAN", "name": "{GUID}", "is_up": true, "is_loopback": false, "is_default": false, "ipv4": ["10.0.0.8/24"]}),
        ];
        let info = pick_lan_ip(&ifaces).expect("应回落到首块可用网卡");
        assert_eq!(info.ip, "10.0.0.8");
        // friendly_name 优先（Windows 网卡名为 GUID 不具可读性）
        assert_eq!(info.iface, "WLAN");
        assert!(pick_lan_ip(&[]).is_none());
    }

    #[test]
    fn clamps_popup_into_work_area() {
        // 工作区 (0,0)-(1920,1040)（底部任务栏占 40）
        let area = (0.0, 0.0, 1920.0, 1040.0);
        // 期望位越出右/下边界 → 收回并留 8px 边距
        assert_eq!(
            clamp_popup(1900.0, 1100.0, 292.0, 420.0, area),
            (1920 - 292 - 8, 1040 - 420 - 8)
        );
        // 期望位为负 → 收到左上边距
        assert_eq!(clamp_popup(-50.0, -50.0, 292.0, 420.0, area), (8, 8));
        // 工作区比窗口小 → 退化贴左上边距（不 panic）
        assert_eq!(clamp_popup(500.0, 500.0, 292.0, 420.0, (0.0, 0.0, 100.0, 100.0)), (8, 8));
    }

    #[test]
    fn tray_popup_prefers_above_anchor_and_flips_below() {
        // 任务栏在底部：anchor 靠近底边 → 弹窗在 anchor 上方 8px、水平居中
        let area = (0.0, 0.0, 1920.0, 1080.0);
        let (x, y) = tray_popup_position((1000.0, 1080.0), (292.0, 420.0), area);
        assert_eq!((x, y), (1000 - 146, 1080 - 420 - 8));
        // 任务栏在顶部（工作区 top=40）：anchor 贴顶 → 上方空间不足翻转到下方 8px
        let area_top_taskbar = (0.0, 40.0, 1920.0, 1080.0);
        let (_, y2) = tray_popup_position((1000.0, 40.0), (292.0, 420.0), area_top_taskbar);
        assert_eq!(y2, 48);
        // 左侧任务栏 + 多显示器负坐标工作区：clamp 进该区（不被钳到 0）
        let area_left = (-1920.0, 0.0, 0.0, 1080.0);
        let (x3, _) = tray_popup_position((-1900.0, 1000.0), (292.0, 420.0), area_left);
        assert_eq!(x3, -1920 + 8);
    }
}

// ==================== 自定义规则（放行 / hosts 映射 / 组合） ====================
//
// 模型 / 存储 / 系统 hosts 托管 / 生效并集见 custom_rules.rs；
// 引擎集成（set_custom_rules ArcSwap 热更 → rebuild 烘焙路由自定义层，
// 本地代理入站评估优先于合并路由与订阅回落）见 agile-net-client。
// 规则 key 约定：自定义规则 = 其 id；拉取规则 = 现有 ruleKey（type:value 小写，app.js ruleKey），
// 组合中的拉取规则 key 由前端经既有暂停接口（set_rule_paused）另行处理。

mod custom_rules;

/// 自定义规则列表视图（list_custom_rules 返回形状即 WaveB 前端契约）。
#[derive(Debug, Clone, Serialize)]
pub struct CustomRulesView {
    pub bypass: Vec<custom_rules::BypassRule>,
    pub hosts: Vec<HostRuleView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostRuleView {
    pub id: String,
    pub hostname: String,
    pub ip: String,
    pub enabled: bool,
    /// user = 用户自建；system = 系统 hosts 既有（非本软件托管，只读）
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddHostResult {
    pub id: String,
    /// system = 已落系统 hosts 托管块；internal = 仅进程内映射（无权限等回落）
    pub persisted: String,
}

#[tauri::command]
async fn list_custom_rules() -> Result<CustomRulesView, String> {
    let data = custom_rules::snapshot();
    let mut hosts: Vec<HostRuleView> = data
        .hosts
        .iter()
        .map(|r| HostRuleView {
            id: r.id.clone(),
            hostname: r.hostname.clone(),
            ip: r.ip.clone(),
            enabled: r.enabled,
            source: "user".into(),
        })
        .collect();
    // 系统 hosts 既有（非本软件托管）映射合并展示；与用户自建同名时以用户条目为准
    for (hostname, ip) in custom_rules::SystemHosts::new().read_entries() {
        if data.hosts.iter().any(|r| r.hostname == hostname) {
            continue;
        }
        hosts.push(HostRuleView {
            id: format!("sys-{hostname}"),
            hostname,
            ip,
            enabled: true,
            source: "system".into(),
        });
    }
    Ok(CustomRulesView {
        bypass: data.bypass,
        hosts,
    })
}

#[tauri::command]
async fn add_bypass_rule(
    state: State<'_, AppState>,
    pattern: String,
    via_subscription: bool,
) -> Result<String, String> {
    custom_rules::add_bypass(&state.client, &pattern, via_subscription)
}

#[tauri::command]
async fn add_host_mapping(
    state: State<'_, AppState>,
    hostname: String,
    ip: String,
    to_system: bool,
) -> Result<AddHostResult, String> {
    let (id, persisted) = custom_rules::add_host(&state.client, &hostname, &ip, to_system)?;
    Ok(AddHostResult {
        id,
        persisted: persisted.to_string(),
    })
}

#[tauri::command]
async fn set_custom_rule_enabled(
    state: State<'_, AppState>,
    id: String,
    enabled: bool,
) -> Result<(), String> {
    custom_rules::set_enabled(&state.client, &id, enabled)
}

#[tauri::command]
async fn remove_custom_rule(state: State<'_, AppState>, id: String) -> Result<(), String> {
    custom_rules::remove(&state.client, &id)
}

#[tauri::command]
async fn list_rule_combos() -> Result<Vec<custom_rules::RuleCombo>, String> {
    Ok(custom_rules::snapshot().combos)
}

#[tauri::command]
async fn add_combo(state: State<'_, AppState>, name: String) -> Result<String, String> {
    custom_rules::add_combo(&state.client, &name)
}

#[tauri::command]
async fn update_combo(
    state: State<'_, AppState>,
    id: String,
    name: String,
    rule_keys: Vec<String>,
) -> Result<(), String> {
    custom_rules::update_combo(&state.client, &id, &name, rule_keys)
}

#[tauri::command]
async fn remove_combo(state: State<'_, AppState>, id: String) -> Result<(), String> {
    custom_rules::remove_combo(&state.client, &id)
}

#[tauri::command]
async fn set_combo_enabled(
    state: State<'_, AppState>,
    id: String,
    enabled: bool,
) -> Result<(), String> {
    custom_rules::set_combo_enabled(&state.client, &id, enabled)
}
