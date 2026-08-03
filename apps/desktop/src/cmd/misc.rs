//! Split out of lib.rs: misc — external links / uninstall / console channels / fan-out connection management / event center (pure move, zero logic change).
//! report_client_proxy is shared by the proxy and roles domains; by convention it lives here (call sites unchanged via crate-root re-export).

use crate::{map_err, roles, subscription, sysproxy, AppState};
use serde::Serialize;
use std::sync::Arc;
use tauri::State;

/// Open an external link with the system default browser (http/https only).
#[tauri::command]
pub(crate) fn open_url(url: String) -> Result<(), String> {
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

/// Desktop admin SPA static assets (embedded via include_str!, no Node build chain).
pub(crate) fn spa_assets() -> agile_net_client::api::SpaAssets {
    agile_net_client::api::SpaAssets {
        index: include_str!("../../ui/index.html"),
        app_js: include_str!("../../ui/app.js"),
        icons_js: include_str!("../../ui/icons.js"),
        agchart_js: include_str!("../../ui/agchart.js"),
        app_core_js: include_str!("../../ui/app-core.js"),
        app_views_js: include_str!("../../ui/app-views.js"),
        app_subscription_js: include_str!("../../ui/app-subscription.js"),
        app_hero_js: include_str!("../../ui/app-hero.js"),
        app_logs_js: include_str!("../../ui/app-logs.js"),
        app_settings_js: include_str!("../../ui/app-settings.js"),
        style_css: include_str!("../../ui/style.css"),
        tokens_css: include_str!("../../ui/tokens.css"),
        components_css: include_str!("../../ui/components.css"),
    }
}

/// Theme query fragment (accepts light/dark only; lets the console SPA match the main window theme)
pub(crate) fn theme_query(theme: &Option<String>) -> String {
    match theme.as_deref() {
        Some("dark") => "?theme=dark".to_string(),
        Some("light") => "?theme=light".to_string(),
        _ => String::new(),
    }
}

/// Admin console URL, loaded in the main window's embedded iframe (no more child windows).
/// - no args → embedded node (local server role, SPA login page)
/// - node_id → remote endpoint via the client tunnel (bootstrap with admin ticket; #boot stays out of logs and history)
/// - node_id + upstream → manageable upstream (discovered via handshake v2)
/// URL always carries embed=1 (SPA hides its own sidebar and title bar; navigation is driven by the main window via postMessage).
#[tauri::command]
pub(crate) async fn console_url(
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
            // Admin bootstrap ticket (one-time, 10 min TTL; the node side checks admin_console authorization)
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

// ==================== Console channels (manage this node) ====================

/// Console loopback forwarder: local loopback port → target node tunnel → target API.
/// Deduped by key (node_id or node_id|upstream); the caller cleans up and rebuilds after reconnect.
pub(crate) async fn ensure_console_forwarder(
    state: &State<'_, AppState>,
    key: &str,
    target_host: &str,
    target_port: u16,
) -> Result<u16, String> {
    let mut map = state.consoles.lock().await;
    if let Some(p) = map.get(key) {
        return Ok(*p);
    }
    // The first segment of key is always node_id
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

// ==================== Fan-out connection management (DB is the single source of truth; hot-apply via ConnectorManager at runtime, no restart) ====================

/// Fan-out list view (token redacted to prefix only, never echoed; editing requires re-entry or leaving it blank to keep).
#[derive(Debug, Clone, Serialize)]
pub struct ServerConnectorView {
    pub id: String,
    pub name: String,
    pub upstream_addr: String,
    pub token_prefix: String,
    pub sni_hostname: String,
    pub insecure: bool,
    /// Re-advertised routes (stored comma-separated; the edit form echoes them one per line)
    pub advertise: String,
    /// Restricting group (None = unrestricted, allow everything)
    pub group_id: Option<String>,
    pub group_name: Option<String>,
    pub enabled: bool,
    pub remark: String,
    /// Live state (connected/connecting/reconnecting/disconnected; always disconnected while the embedded node is not running)
    pub state: String,
}

/// Group dropdown option (for the fan-out form)
#[derive(Debug, Clone, Serialize)]
pub struct GroupOption {
    pub id: String,
    pub name: String,
}

/// Groups of the local embedded node (the "group" dropdown in the fan-out form; empty = unrestricted).
#[tauri::command]
pub(crate) async fn list_embedded_groups() -> Result<Vec<GroupOption>, String> {
    let db = roles::open_embedded_db()?;
    let (groups, _) = db.list_groups(1, 1000, None).map_err(map_err)?;
    Ok(groups
        .into_iter()
        .map(|g| GroupOption { id: g.id, name: g.name })
        .collect())
}

/// Hot-apply a single fan-out change to the running embedded node (tear down the old, then bring up the new; skipped when not running — startup assembles from DB).
pub(crate) async fn hot_upsert_connector(state: &State<'_, AppState>, id: &str, name: &str) {
    // Grab the ConnectorManager handle and release the lock immediately — never hold it across await (upsert does DNS resolution)
    let manager = state.server.lock().await.as_ref().map(|s| s.connector_manager());
    if let Some(m) = manager {
        if let Err(e) = m.upsert_from_db(id).await {
            tracing::error!(connector = %name, error = %e, "connector hot-upsert failed");
        }
    }
}

/// Validate the restricting group exists (when Some) so the frontend gets a readable error (DB foreign-key errors are not).
pub(crate) fn validate_group(db: &agile_net_node::db::Database, group_id: Option<&str>) -> Result<(), String> {
    if let Some(gid) = group_id {
        if db.get_group(gid).map_err(map_err)?.is_none() {
            return Err("权限组不存在".into());
        }
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn list_server_connectors(
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

/// Fan-out form (shared parameters of the add/update commands).
/// Note: a tauri command's flat parameters are the frontend invoke contract (camelCase per-arg mapping);
/// a struct cannot be passed as a single argument (tauri does not support serde flatten),
/// so this is internal-only — command boundaries keep flat signatures and waive the too-many-args lint.
struct ConnectorForm {
    upstream_addr: String,
    token: String,
    sni_hostname: String,
    insecure: bool,
    group_id: Option<String>,
    name: Option<String>,
    advertise: Option<String>,
    remark: Option<String>,
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // flat parameters = frontend invoke contract, see ConnectorForm
pub(crate) async fn add_server_connector(
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
    let form = ConnectorForm {
        upstream_addr,
        token,
        sni_hostname,
        insecure,
        group_id,
        name,
        advertise,
        remark,
    };
    add_server_connector_inner(&state, form).await
}

async fn add_server_connector_inner(
    state: &State<'_, AppState>,
    form: ConnectorForm,
) -> Result<(), String> {
    let addr = form.upstream_addr.trim();
    if addr.is_empty() || form.token.trim().is_empty() {
        return Err("扇出目标地址与 Relay Token 不能为空".into());
    }
    // Name is optional: blank = use the target address (TOML import convention; connector.name has a unique constraint)
    let name = form
        .name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| addr.to_string());
    let advertise = form.advertise.unwrap_or_default().trim().to_string();
    let remark = form.remark.unwrap_or_default().trim().to_string();
    let group_id = form.group_id.filter(|g| !g.trim().is_empty());
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
            form.token.trim(),
            form.sni_hostname.trim(),
            form.insecure,
            "",
            "",
            &advertise,
            group_id.as_deref(),
            &remark,
        )
        .map_err(map_err)?;
    roles::audit("gui.fanout_change", serde_json::json!({"action": "add", "name": name}));
    hot_upsert_connector(state, &rec.id, &name).await;
    Ok(())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // flat parameters = frontend invoke contract, see ConnectorForm
pub(crate) async fn update_server_connector(
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
    let form = ConnectorForm {
        upstream_addr,
        token,
        sni_hostname,
        insecure,
        group_id,
        name,
        advertise,
        remark,
    };
    update_server_connector_inner(&state, &id, form).await
}

async fn update_server_connector_inner(
    state: &State<'_, AppState>,
    id: &str,
    form: ConnectorForm,
) -> Result<(), String> {
    let addr = form.upstream_addr.trim();
    if addr.is_empty() {
        return Err("扇出目标地址不能为空".into());
    }
    // Name is optional: blank = use the target address (same convention as add)
    let name = form
        .name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| addr.to_string());
    let group_id = form.group_id.filter(|g| !g.trim().is_empty());
    let db = roles::open_embedded_db()?;
    let Some(old) = db.get_connector(id).map_err(map_err)? else {
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
    // Tri-state token / advertise / remark: blank token = keep the old value; advertise/remark absent (None) = keep,
    // the frontend always sends them (empty string = user cleared explicitly); cert paths are not edited in the GUI, kept as-is
    let token_reset = if form.token.trim().is_empty() {
        None
    } else {
        Some(form.token.trim().to_string())
    };
    let advertise = form
        .advertise
        .map(|a| a.trim().to_string())
        .unwrap_or_else(|| old.advertise.clone());
    let remark = form
        .remark
        .map(|r| r.trim().to_string())
        .unwrap_or_else(|| old.remark.clone());
    db.update_connector(
        id,
        &name,
        addr,
        token_reset.as_deref(),
        form.sni_hostname.trim(),
        form.insecure,
        &old.ca_cert_path,
        &old.pinned_cert_path,
        &advertise,
        group_id.as_deref(),
        &remark,
    )
    .map_err(map_err)?;
    roles::audit("gui.fanout_change", serde_json::json!({"action": "update", "name": name}));
    hot_upsert_connector(state, id, &name).await;
    Ok(())
}

#[tauri::command]
pub(crate) async fn remove_server_connector(state: State<'_, AppState>, id: String) -> Result<(), String> {
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

/// Write the real client proxy state into the embedded node state slot (call after start/stop/mode switch/role shutdown;
/// the admin "local proxy" card reads it via node status; the mode comes from the GUI proxy settings).
pub(crate) async fn report_client_proxy(state: &State<'_, AppState>) {
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

// ==================== Uninstall ====================

/// Uninstall cleanup options (which local data to delete along with the uninstall)
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UninstallOptions {
    /// Saved nodes and credentials (credentials.json)
    pub credentials: bool,
    /// Server node data (embedded-node/: database and certificates)
    pub server_data: bool,
    /// Config and preferences (gui-settings.json / web-auth.json; theme and language are cleared from localStorage by the frontend)
    pub prefs: bool,
    /// Audit log (gui-audit.jsonl)
    pub audit: bool,
}

/// Uninstall the app: write audit → shut down to release file locks → clean the selected data → disable autostart → launch the system uninstaller and exit.
#[tauri::command]
pub(crate) async fn uninstall_app(
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

    // Stop embedded node / web remote access / subscription kernel / all tunnels (release SQLite and port usage)
    if let Some(s) = state.server.lock().await.take() {
        s.stop().await;
    }
    if let Some(h) = state.web_api.lock().await.take() {
        h.stop().await;
    }
    state.kernel.stop().await;
    state.client.disconnect_all().await;
    state.client.stop_proxy().await;

    // System proxy is managed (including auto-management in TUN mode): restore the system proxy before uninstall
    {
        let r = state.roles.lock().await;
        if r.system_proxy || r.tun_mode {
            drop(r);
            let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
        }
    }

    // Mandatory on uninstall: remove login autostart
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

/// Launch the system uninstaller (Windows NSIS: uninstall.exe in the install dir, with its own confirmation page;
/// by the time the user confirms, this process has exited, so the install dir can be deleted).
#[cfg(windows)]
pub(crate) fn launch_system_uninstaller() -> Result<(), String> {
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

/// Non-Windows desktops have no system uninstaller: data is cleaned; ask the user to remove the app manually.
#[cfg(not(windows))]
pub(crate) fn launch_system_uninstaller() -> Result<(), String> {
    Err("数据已按所选清理；请将应用本体移入废纸篓/删除以完成卸载".into())
}

/// Event center: read whitelisted events backwards from the tail of gui-audit.jsonl (newest first; default 50, max 200).
/// Returns an empty Vec when the file does not exist.
#[tauri::command]
pub(crate) fn recent_events(limit: Option<u32>) -> Result<Vec<roles::GuiEvent>, String> {
    let n = limit.unwrap_or(50).clamp(1, 200) as usize;
    Ok(roles::recent_events(n))
}
