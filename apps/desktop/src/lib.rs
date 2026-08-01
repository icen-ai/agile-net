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
mod sysproxy;
use roles::RoleSettings;

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
}

impl AppState {
    fn new() -> Self {
        Self {
            client: AgileNetClient::new(),
            creds: Arc::new(CredentialStore::open_default().ok().map(Arc::new)),
            web_api: Arc::new(tokio::sync::Mutex::new(None)),
            roles: Arc::new(tokio::sync::Mutex::new(RoleSettings::load())),
            server: Arc::new(tokio::sync::Mutex::new(None)),
            consoles: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            kernel: Arc::new(subscription::KernelManager::default()),
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
        style_css: include_str!("../ui/style.css"),
        tokens_css: include_str!("../ui/tokens.css"),
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
    /// 收敛权限组（None = 不收敛，放行一切）
    pub group_id: Option<String>,
    pub group_name: Option<String>,
    pub enabled: bool,
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
                group_id: v.group_id,
                group_name: v.group_name,
                enabled: v.enabled,
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
) -> Result<(), String> {
    let addr = upstream_addr.trim();
    if addr.is_empty() || token.trim().is_empty() {
        return Err("扇出目标地址与 Relay Token 不能为空".into());
    }
    let group_id = group_id.filter(|g| !g.trim().is_empty());
    let db = roles::open_embedded_db()?;
    validate_group(&db, group_id.as_deref())?;
    // 显示名沿用 TOML 导入惯例 = 目标地址（connector.name 唯一约束；GUI 无独立名称字段）
    if db
        .list_connectors()
        .map_err(map_err)?
        .iter()
        .any(|c| c.name == addr)
    {
        return Err("该扇出目标已存在".into());
    }
    let rec = db
        .create_connector(
            addr,
            addr,
            token.trim(),
            sni_hostname.trim(),
            insecure,
            "",
            "",
            "",
            group_id.as_deref(),
            "",
        )
        .map_err(map_err)?;
    roles::audit("gui.fanout_change", serde_json::json!({"action": "add", "name": addr}));
    hot_upsert_connector(&state, &rec.id, addr).await;
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
) -> Result<(), String> {
    let addr = upstream_addr.trim();
    if addr.is_empty() {
        return Err("扇出目标地址不能为空".into());
    }
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
        .any(|c| c.name == addr && c.id != id)
    {
        return Err("该扇出目标已存在".into());
    }
    // token 留空 = 保留原值；advertise / 证书路径 / 备注 GUI 不编辑，原样保留；
    // 名称同步跟随目标地址（GUI 无独立名称字段，与 add 同惯例）
    let token_reset = if token.trim().is_empty() {
        None
    } else {
        Some(token.trim().to_string())
    };
    db.update_connector(
        &id,
        addr,
        addr,
        token_reset.as_deref(),
        sni_hostname.trim(),
        insecure,
        &old.ca_cert_path,
        &old.pinned_cert_path,
        &old.advertise,
        group_id.as_deref(),
        &old.remark,
    )
    .map_err(map_err)?;
    roles::audit("gui.fanout_change", serde_json::json!({"action": "update", "name": addr}));
    hot_upsert_connector(&state, &id, addr).await;
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

/// 应用回落上游：订阅角色开 + 统一出口开 + 内核运行 → 未命中规则的流量回落到内核 mixed。
async fn apply_proxy_fallback(state: &State<'_, AppState>) {
    let (sub, unified) = {
        let r = state.roles.lock().await;
        (r.subscription, r.subscription_unified)
    };
    let running = state.kernel.running().await;
    let addr = if sub && unified && running {
        Some(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            subscription::MIHOMO_MIXED_PORT,
        )))
    } else {
        None
    };
    state.client.set_proxy_fallback(addr);
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
    {
        let mut roles = state.roles.lock().await;
        roles.subscription_unified = enabled;
        roles.save()?;
    }
    apply_proxy_fallback(&state).await;
    Ok(())
}

// ==================== 系统代理托管 ====================

/// 期望的系统代理值（本地代理端口）。
fn expected_sysproxy(state: &State<'_, AppState>) -> String {
    format!("127.0.0.1:{}", state.client.proxy_port())
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
    Ok(())
}

#[tauri::command]
async fn sysproxy_status(state: State<'_, AppState>) -> Result<sysproxy::SysProxyStatus, String> {
    let managed = state.roles.lock().await.system_proxy;
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

    // 系统代理托管中：卸载前还原系统代理
    if state.roles.lock().await.system_proxy {
        let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
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
async fn restore_subscription_role(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    if !state.roles.lock().await.subscription {
        return;
    }
    if subscription::list_subscriptions().is_empty() {
        tracing::warn!("subscription role was enabled but no subscription exists — keeping kernel stopped");
        return;
    }
    match state.kernel.start().await {
        Ok(()) => {
            tracing::info!("subscription kernel restored");
            apply_proxy_fallback(&state).await;
        }
        Err(e) => tracing::error!(error = %e, "failed to restore subscription kernel"),
    }
}

/// 系统代理冲突巡检（30s）：托管中系统值 ≠ 期望值即记审计（每轮冲突只记一次，恢复后可再记）。
async fn sysproxy_watch(app: tauri::AppHandle) {
    let mut in_conflict = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let state = app.state::<AppState>();
        let managed = state.roles.lock().await.system_proxy;
        // 代理未运行时不判冲突（同 sysproxy_status）
        if !managed || state.client.proxy_port() == 0 {
            in_conflict = false;
            continue;
        }
        let expected = expected_sysproxy(&state);
        if let Ok(Ok(st)) =
            tokio::task::spawn_blocking(move || sysproxy::inspect(true, &expected)).await
        {
            if st.conflict && !in_conflict {
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

    tauri::Builder::default()
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
            set_system_proxy,
            sysproxy_status,
            reclaim_sysproxy,
        ])
        .setup(|app| {
            setup_tray(app)?;

            // 恢复上次开启的服务端角色（内嵌节点）与订阅内核；启动系统代理巡检
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                restore_server_role(&handle).await;
                restore_web_role(&handle).await;
                restore_subscription_role(&handle).await;
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
        .run(tauri::generate_context!())
        .expect("error while running AgileNet desktop");
}
