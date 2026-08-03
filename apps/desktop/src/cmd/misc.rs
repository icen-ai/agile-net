//! 从 lib.rs 拆分：杂项——外部链接 / 卸载 / 控制台通道 / 扇出连接管理 / 事件中心（纯搬运，零逻辑变更）。
//! report_client_proxy 被 proxy 与 roles 两域共用，按约定集中放于此（crate 根 re-export 后调用点不变）。

use crate::{map_err, roles, subscription, sysproxy, AppState};
use serde::Serialize;
use std::sync::Arc;
use tauri::State;

/// 用系统默认浏览器打开外部链接（仅 http/https）。
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

/// 桌面端管理 SPA 静态资产（include_str! 内嵌，无 Node 构建链）。
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

/// 主题 query 片段（仅接受 light/dark；控制台 SPA 据此与主窗主题一致）
pub(crate) fn theme_query(theme: &Option<String>) -> String {
    match theme.as_deref() {
        Some("dark") => "?theme=dark".to_string(),
        Some("light") => "?theme=light".to_string(),
        _ => String::new(),
    }
}

/// 管理端控制台 URL：主窗内嵌 iframe 加载（不再开子窗口）。
/// - 无参 → 内嵌节点（本机服务端角色，SPA 登录页）
/// - node_id → 经客户端隧道的远端端点（管理引导票据自举，#boot 不进日志与历史）
/// - node_id + upstream → 可管理上游（握手 v2 发现）
/// URL 恒带 embed=1（SPA 隐藏自身侧栏与标题栏，导航经 postMessage 由主窗驱动）。
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
pub(crate) async fn list_embedded_groups() -> Result<Vec<GroupOption>, String> {
    let db = roles::open_embedded_db()?;
    let (groups, _) = db.list_groups(1, 1000, None).map_err(map_err)?;
    Ok(groups
        .into_iter()
        .map(|g| GroupOption { id: g.id, name: g.name })
        .collect())
}

/// 运行中的内嵌节点热应用单条扇出变更（先断旧再起新；未运行则跳过，启动时自 DB 装配）。
pub(crate) async fn hot_upsert_connector(state: &State<'_, AppState>, id: &str, name: &str) {
    // 先取 ConnectorManager 句柄即放锁，避免持锁跨 await（upsert 内含 DNS 解析）
    let manager = state.server.lock().await.as_ref().map(|s| s.connector_manager());
    if let Some(m) = manager {
        if let Err(e) = m.upsert_from_db(id).await {
            tracing::error!(connector = %name, error = %e, "connector hot-upsert failed");
        }
    }
}

/// 校验收敛组存在（Some 时），给前端友好报错（DB 外键报错不易读）。
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

/// 扇出表单（add/update 两命令的公共参数）。
/// 注意：tauri command 的扁平参数即前端 invoke 契约（camelCase 逐参映射），
/// 结构体无法作为单参整体传入（tauri 不支持 serde flatten），
/// 故仅用于内部收敛，命令边界保留扁平签名并豁免参数过多 lint。
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
#[allow(clippy::too_many_arguments)] // 扁平参数 = 前端 invoke 契约，缘由见 ConnectorForm
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
    // 名称可空：留空 = 取目标地址（沿用 TOML 导入惯例；connector.name 唯一约束）
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
#[allow(clippy::too_many_arguments)] // 扁平参数 = 前端 invoke 契约，缘由见 ConnectorForm
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
    // 名称可空：留空 = 取目标地址（与 add 同惯例）
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
    // token / advertise / remark 三态：token 留空 = 保留原值；advertise/remark 缺省(None) = 保留，
    // 前端恒传（空串 = 用户显式清空）；证书路径 GUI 不编辑，原样保留
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

/// 客户端代理真实状态写入内嵌节点状态槽（start/stop/模式切换/角色关闭后调用；
/// 管理端「本地代理」卡经 node status 读取，模式来自 GUI 代理设置）。
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

/// 非 Windows 桌面平台无系统卸载程序：数据已清理，提示用户手动移除应用本体。
#[cfg(not(windows))]
pub(crate) fn launch_system_uninstaller() -> Result<(), String> {
    Err("数据已按所选清理；请将应用本体移入废纸篓/删除以完成卸载".into())
}

/// 事件中心：gui-audit.jsonl 尾部倒读白名单事件（新的在前；默认 50 条，上限 200）。
/// 文件不存在返回空 Vec。
#[tauri::command]
pub(crate) fn recent_events(limit: Option<u32>) -> Result<Vec<roles::GuiEvent>, String> {
    let n = limit.unwrap_or(50).clamp(1, 200) as usize;
    Ok(roles::recent_events(n))
}
