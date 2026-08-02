//! AgileNet 桌面客户端 Tauri 后端
//!
//! 通过 IPC 向前端暴露节点管理、代理控制与凭据存储能力，
//! 全部网络逻辑复用 agile-net-client 引擎（与 CLI/daemon 同一数据面）。
//! 服务端角色内嵌完整 agile-net-node（与 anet-svc 同一装配根 NodeServer）。

use agile_net_client::{AgileNetClient, ConnectParams, Credential, CredentialStore, NodeState, ParsedConnect};
use agile_net_node::service::NodeServer;
use serde::Serialize;
use std::sync::Arc;
use tauri::{Manager, State};

mod roles;
mod subscription;
mod sub_script;
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
    /// 客户端代理真实状态槽（传给内嵌节点；管理端「本地代理」卡数据源）
    client_proxy_slot: agile_net_node::service::ClientProxySlot,
    /// TUN 最近一次外部上游拨测结果（None = 未拨测；前端状态行/灵动岛告警数据源）
    tun_upstream_ok: Arc<tokio::sync::Mutex<Option<bool>>>,
    /// TUN 放弃开启的一次性提示（权限不足/启动失败回退普通模式；前端读取后清除）
    tun_notice: Arc<tokio::sync::Mutex<Option<String>>>,
    /// 最近一次应用的回落上游（变化时审计 gui.fallback_change，记地址不记凭据）
    last_fallback: Arc<tokio::sync::Mutex<Option<std::net::SocketAddr>>>,
}

impl AppState {
    fn new() -> Self {
        let roles = RoleSettings::load();
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
            client_proxy_slot,
            tun_upstream_ok: Arc::new(tokio::sync::Mutex::new(None)),
            tun_notice: Arc::new(tokio::sync::Mutex::new(None)),
            last_fallback: Arc::new(tokio::sync::Mutex::new(None)),
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

/// 启动本地代理
#[tauri::command]
async fn start_proxy(app: tauri::AppHandle, state: State<'_, AppState>, port: u16) -> Result<u16, String> {
    if !state.roles.lock().await.client {
        return Err("扇入已停用，请在首页开启".into());
    }
    state.client.start_proxy(port).await.map_err(map_err)?;
    refresh_tray_icon(&app);
    // 系统代理模式（默认开）：启动代理即接管系统代理；engage 幂等，快照不会被重复覆盖
    if state.roles.lock().await.system_proxy {
        let server = expected_sysproxy(&state);
        let _ = tokio::task::spawn_blocking(move || sysproxy::engage(&server)).await;
    }
    report_client_proxy(&state).await;
    Ok(state.client.proxy_port())
}

/// 停止本地代理
#[tauri::command]
async fn stop_proxy(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    state.client.stop_proxy().await;
    // 系统代理模式：停止即还原系统代理（避免指向已死端口）；模式偏好保留，下次启动自动再接管
    if state.roles.lock().await.system_proxy {
        let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
    }
    report_client_proxy(&state).await;
    refresh_tray_icon(&app);
    Ok(())
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

/// 当前生效的回落地址：
/// - TUN 模式：订阅出口优先（TUN mihomo socks 入站 57893→AGILE-SUB，无 FlClash 也能出网）；
///   无激活订阅时回落外部上游（§2.4），异常值宁可无回落也不成环
/// - 非 TUN：订阅角色开 + 统一出口开 + 内核运行 → 回落到内核 mixed（57892）
/// - 其余：无回落（未命中直连）
async fn effective_fallback(state: &State<'_, AppState>) -> Option<std::net::SocketAddr> {
    let (sub, unified, tun_mode, upstream_raw) = {
        let r = state.roles.lock().await;
        (
            r.subscription,
            r.subscription_unified,
            r.tun_mode,
            r.external_upstream.clone(),
        )
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
    } else if sub && unified && running {
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
        // §2.1 wintun.dll 钉版本下发（SHA-256 校验，失败拒落盘 + gui.wintun_tamper）
        subscription::ensure_wintun().await?;
        if subscription::list_subscriptions().is_empty() {
            return Err("请先添加订阅".into());
        }
        {
            let mut roles = state.roles.lock().await;
            // §2.4 回落目标合法性（硬约束；违规拒绝开启）
            roles::validate_external_upstream(&roles.external_upstream)?;
            roles.tun_mode = true;
            roles.subscription = true;
            // §2.5 严格互斥：统一出口在 TUN 期间由运行时排除（effective_fallback 的 TUN 分支
            // 优先），不破坏其持久化偏好——TUN 关闭后统一出口自动恢复原值
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
        // 统一出口偏好保留（TUN 期间运行时排除，关闭后自动恢复，见 set_tun_mode 注释）
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

/// 安装订阅内核（下载钉版本 + 校验；成功后才允许激活订阅功能）。
#[tauri::command]
async fn install_kernel(state: State<'_, AppState>) -> Result<subscription::KernelStatus, String> {
    subscription::ensure_kernel().await?;
    roles::audit("gui.kernel_install", serde_json::json!({}));
    Ok(state.kernel.status().await)
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

/// 开关D：订阅代理角色。开启即下载/启动内核（崩溃自动退避重启），关闭即停机。
#[tauri::command]
async fn set_subscription_role(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<subscription::KernelStatus, String> {
    if !enabled && state.roles.lock().await.tun_mode {
        return Err("TUN 模式开启中，请先关闭 TUN 模式".into());
    }
    if enabled {
        state.kernel.start().await?;
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

/// 订阅流量是否经统一出口（ProxyRouter 回落）。
#[tauri::command]
async fn set_subscription_unified(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    // §2.5 严格互斥：TUN 开启中统一出口严禁开启（57890→57892→MATCH→57890 是死环）
    if enabled && state.roles.lock().await.tun_mode {
        return Err("TUN 模式下统一出口强制关闭（防环硬约束）".into());
    }
    {
        let mut roles = state.roles.lock().await;
        roles.subscription_unified = enabled;
        roles.save()?;
    }
    apply_proxy_fallback(&state).await;
    Ok(())
}

/// 订阅内核流量快照（/traffic WS 累计；内核停止即清零）。
#[tauri::command]
async fn sub_traffic(state: State<'_, AppState>) -> Result<subscription::TrafficSnapshot, String> {
    Ok(state.kernel.traffic())
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
    // TUN 模式视同托管（系统自动代理指向 57890，巡检自动收回）
    let managed = {
        let r = state.roles.lock().await;
        r.system_proxy || r.tun_mode
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
        // TUN 模式 mixed 口（57892）按防环设计关闭，探测改走订阅出口 socks 口（57893）
        let port = if state.roles.lock().await.tun_mode {
            subscription::MIHOMO_SOCKS_PORT
        } else {
            subscription::MIHOMO_MIXED_PORT
        };
        let proxy =
            reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).map_err(map_err)?;
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
    // 提权重启后被用户取消（UAC 拒绝）或权限已丢失：放弃 TUN 改普通模式恢复，不影响使用
    let mut tun_mode = tun_mode;
    if tun_mode && !tun::SystemElevation.is_admin() {
        tracing::warn!("persisted TUN mode but process is not elevated — abandoning TUN, restore as normal mode");
        abandon_tun(&state, "需要管理员权限").await;
        tun_mode = false;
    }
    if tun_mode {
        if let Err(e) = subscription::ensure_wintun().await {
            // wintun 不可用同样只放弃 TUN，不阻断普通模式恢复
            tracing::error!(error = %e, "failed to ensure wintun for persisted TUN mode");
            abandon_tun(&state, &format!("wintun 组件不可用（{e}）")).await;
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
/// TUN 模式（§2.6）升级为自动收回：被抢即重写期望值并记审计（含来源值），每轮处理；
/// 非 TUN 维持"提醒手动收回"（每轮冲突只记一次，恢复后可再记）。
async fn sysproxy_watch(app: tauri::AppHandle) {
    let mut in_conflict = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let state = app.state::<AppState>();
        let (pref, tun_mode) = {
            let r = state.roles.lock().await;
            (r.system_proxy, r.tun_mode)
        };
        // TUN 模式视同托管（自动收回策略）；代理未运行时不判冲突（同 sysproxy_status）
        let managed = pref || tun_mode;
        if !managed || state.client.proxy_port() == 0 {
            in_conflict = false;
            continue;
        }
        let expected = expected_sysproxy(&state);
        if let Ok(Ok(st)) =
            tokio::task::spawn_blocking(move || sysproxy::inspect(true, &expected)).await
        {
            if st.conflict && tun_mode {
                roles::audit(
                    "gui.sysproxy_conflict",
                    serde_json::json!({"expected": st.expected, "current": st.current, "auto_reclaim": true}),
                );
                let server = st.expected.clone();
                let _ = tokio::task::spawn_blocking(move || sysproxy::reclaim(&server)).await;
            } else if st.conflict && !in_conflict {
                roles::audit(
                    "gui.sysproxy_conflict",
                    serde_json::json!({"expected": st.expected, "current": st.current}),
                );
            }
            in_conflict = st.conflict;
        }
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

/// 弹出/收起托盘面板（懒创建；失焦自动隐藏）
fn toggle_tray_popup(app: &tauri::AppHandle, anchor: tauri::PhysicalPosition<f64>) {
    const W: f64 = 292.0;
    const H: f64 = 400.0;
    let x = (anchor.x - W / 2.0).max(0.0);
    let y = (anchor.y - H - 10.0).max(0.0);
    if let Some(w) = app.get_webview_window("tray-popup") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
            return;
        }
        let _ = w.set_position(tauri::PhysicalPosition::new(x as i32, y as i32));
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
    .position(x, y)
    .build()
    else {
        return;
    };
    let w = window.clone();
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::Focused(false) = event {
            let _ = w.hide();
        }
    });
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
            parse_connect_url,
            open_url,
            tray_show_main,
            tray_quit,
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
            activate_subscription_feature,
            subscription_status,
            proxy_groups,
            select_proxy,
            test_delay,
            set_subscription_role,
            set_subscription_unified,
            sub_traffic,
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
            reclaim_sysproxy,
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
