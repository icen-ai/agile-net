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
}

impl AppState {
    fn new() -> Self {
        Self {
            client: AgileNetClient::new(),
            creds: Arc::new(CredentialStore::open_default().ok().map(Arc::new)),
            web_api: Arc::new(tokio::sync::Mutex::new(None)),
            roles: Arc::new(tokio::sync::Mutex::new(RoleSettings::load())),
            server: Arc::new(tokio::sync::Mutex::new(None)),
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
        return Err("客户端角色已停用，请在「设置 → 角色与远程面」开启".into());
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
async fn start_proxy(state: State<'_, AppState>, port: u16) -> Result<u16, String> {
    if !state.roles.lock().await.client {
        return Err("客户端角色已停用，请在「设置 → 角色与远程面」开启".into());
    }
    state.client.start_proxy(port).await.map_err(map_err)?;
    Ok(state.client.proxy_port())
}

/// 停止本地代理
#[tauri::command]
async fn stop_proxy(state: State<'_, AppState>) -> Result<(), String> {
    state.client.stop_proxy().await;
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

// ==================== 三路角色开关（客户端 / 服务端 / Web 远程面） ====================

#[derive(Debug, Clone, Serialize)]
pub struct ServerStatus {
    pub running: bool,
    pub has_admin: bool,
    pub api_addr: String,
    pub relay_addr: String,
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
    let running = state.server.lock().await.is_some();
    let has_admin = roles::open_embedded_db()
        .and_then(|db| db.has_admin().map_err(|e| e.to_string()))
        .unwrap_or(false);
    Ok(ServerStatus {
        running,
        has_admin,
        api_addr: roles::EMBEDDED_API_ADDR.into(),
        relay_addr: roles::EMBEDDED_RELAY_ADDR.into(),
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
            let server = NodeServer::start_with(
                roles::build_embedded_config(),
                agile_net_node::service::NodeServerOptions {
                    db_path: Some(roles::embedded_db_path().to_string_lossy().to_string()),
                    api_listen: Some(roles::EMBEDDED_API_ADDR.into()),
                    skip_env_seed: true,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| format!("内嵌节点启动失败: {e}"))?;
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
    Ok(ServerStatus {
        running: enabled,
        has_admin,
        api_addr: roles::EMBEDDED_API_ADDR.into(),
        relay_addr: roles::EMBEDDED_RELAY_ADDR.into(),
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
    }
}

/// 打开内嵌节点控制台（独立窗口复用节点管理 SPA）。
#[tauri::command]
async fn open_console(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let addr = {
        let slot = state.server.lock().await;
        slot.as_ref().map(|s| s.api_addr())
    }
    .ok_or("服务端角色未运行")?;
    if let Some(w) = app.get_webview_window("console") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return Ok(());
    }
    let url: tauri::Url = format!("http://{addr}/").parse().map_err(map_err)?;
    tauri::WebviewWindowBuilder::new(&app, "console", tauri::WebviewUrl::External(url))
        .title("AgileNet 控制台")
        .inner_size(1180.0, 780.0)
        .min_inner_size(860.0, 600.0)
        .build()
        .map_err(map_err)?;
    Ok(())
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
    match NodeServer::start_with(
        roles::build_embedded_config(),
        agile_net_node::service::NodeServerOptions {
            db_path: Some(roles::embedded_db_path().to_string_lossy().to_string()),
            api_listen: Some(roles::EMBEDDED_API_ADDR.into()),
            skip_env_seed: true,
            ..Default::default()
        },
    )
    .await
    {
        Ok(server) => {
            tracing::info!(api = %server.api_addr(), "embedded node restored");
            *state.server.lock().await = Some(server);
        }
        Err(e) => tracing::error!(error = %e, "failed to restore embedded node"),
    }
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

/// 构建系统托盘（显示窗口 / 代理开关 / 退出）
fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{MenuBuilder, MenuItemBuilder};
    use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};

    let show_item = MenuItemBuilder::with_id("show", "显示主窗口").build(app)?;
    let proxy_item = MenuItemBuilder::with_id("toggle_proxy", "启动/停止代理").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "退出 AgileNet").build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&show_item, &proxy_item, &quit_item])
        .build()?;

    TrayIconBuilder::new()
        .icon(app.default_window_icon().expect("window icon").clone())
        .menu(&menu)
        .tooltip("AgileNet 客户端")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.unminimize();
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "toggle_proxy" => {
                let state = app.state::<AppState>();
                let client = state.client.clone();
                tauri::async_runtime::spawn(async move {
                    if client.proxy_port() > 0 {
                        client.stop_proxy().await;
                    } else {
                        let _ = client.start_proxy(57890).await;
                    }
                });
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // 左键双击显示主窗口
            if let TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.unminimize();
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
        })
        .build(app)?;
    Ok(())
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
            open_console,
        ])
        .setup(|app| {
            setup_tray(app)?;

            // 恢复上次开启的服务端角色（内嵌节点）
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                restore_server_role(&handle).await;
                restore_web_role(&handle).await;
            });

            // 关闭窗口时最小化到托盘（不退出进程）
            if let Some(window) = app.get_webview_window("main") {
                let w = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = w.hide();
                    }
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running AgileNet desktop");
}
