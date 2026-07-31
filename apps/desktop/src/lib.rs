//! AgileNet 桌面客户端 Tauri 后端
//!
//! 通过 IPC 向前端暴露节点管理、代理控制与凭据存储能力，
//! 全部网络逻辑复用 agile-net-client 引擎（与 CLI/daemon 同一数据面）。

use agile_net_client::{AgileNetClient, ConnectParams, Credential, CredentialStore, NodeState};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Manager, State};

/// 前端传入的连接参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectInput {
    pub addr: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub pinned_cert_path: Option<String>,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    #[serde(default)]
    pub manage_hosts: bool,
    /// 连接成功后是否保存凭据
    #[serde(default)]
    pub save_credential: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub port: u16,
}

pub struct AppState {
    client: AgileNetClient,
    creds: Arc<tokio::sync::Mutex<Option<CredentialStore>>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            client: AgileNetClient::new(),
            creds: Arc::new(tokio::sync::Mutex::new(CredentialStore::open_default().ok())),
        }
    }
}

fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// 连接节点
#[tauri::command]
async fn connect_node(state: State<'_, AppState>, input: ConnectInput) -> Result<NodeState, String> {
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
        let guard = state.creds.lock().await;
        if let Some(store) = guard.as_ref() {
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

/// 断开节点
#[tauri::command]
async fn disconnect_node(state: State<'_, AppState>, node_id: String) -> Result<(), String> {
    state.client.disconnect(&node_id).await;
    let guard = state.creds.lock().await;
    if let Some(store) = guard.as_ref() {
        store.remove(&node_id).await;
    }
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
    let guard = state.creds.lock().await;
    let Some(store) = guard.as_ref() else {
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

/// 解析 agilenet://connect?... 接入链接
#[tauri::command]
fn parse_connect_url(url: String) -> Result<ConnectInput, String> {
    let rest = url
        .strip_prefix("agilenet://connect?")
        .ok_or_else(|| "无效的接入链接前缀".to_string())?;
    let mut server = String::new();
    let mut port: Option<u16> = None;
    let mut account = String::new();
    let mut password = String::new();
    let mut fp: Option<String> = None;
    for pair in rest.split('&') {
        let mut kv = pair.splitn(2, '=');
        let (k, v) = (kv.next().unwrap_or(""), kv.next().unwrap_or(""));
        let v = url_decode(v);
        match k {
            "server" => server = v,
            "port" => port = v.parse().ok(),
            "account" => account = v,
            "password" => password = v,
            "fp" => fp = Some(v),
            _ => {}
        }
    }
    if server.is_empty() || account.is_empty() || password.is_empty() {
        return Err("接入链接缺少必要参数 (server/account/password)".into());
    }
    // server 未含端口时用 port 参数补全
    let addr = if server.contains(':') {
        server
    } else {
        format!("{}:{}", server, port.unwrap_or(59090))
    };
    Ok(ConnectInput {
        addr,
        username: account,
        password,
        insecure: false,
        pinned_cert_path: None,
        pinned_fingerprint: fp,
        manage_hosts: false,
        save_credential: true,
    })
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
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
            start_proxy,
            stop_proxy,
            proxy_status,
            parse_connect_url,
            set_autostart,
            get_autostart,
        ])
        .setup(|app| {
            setup_tray(app)?;

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
