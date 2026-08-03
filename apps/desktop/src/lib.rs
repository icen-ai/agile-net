//! AgileNet 桌面客户端 Tauri 后端
//!
//! 通过 IPC 向前端暴露节点管理、代理控制与凭据存储能力，
//! 全部网络逻辑复用 agile-net-client 引擎（与 CLI/daemon 同一数据面）。
//! 服务端角色内嵌完整 agile-net-node（与 anet-svc 同一装配根 NodeServer）。

use agile_net_client::{AgileNetClient, CredentialStore, ParsedConnect};
use agile_net_node::service::NodeServer;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tauri::Manager;

mod cmd;
mod custom_rules;
mod download;
#[cfg(windows)]
mod floatball;
pub(crate) mod kernel;
mod roles;
mod subscription;
mod sub_script;
mod sync;
mod sysproxy;
mod tun;
use roles::RoleSettings;

// Tauri 命令与窗口/托盘/悬浮球管理已拆分至 cmd/（纯搬运，零逻辑变更）；
// 全量 re-export 使下方 generate_handler![...] 列表与 crate:: 路径引用（floatball.rs 等）保持不变。
pub(crate) use cmd::*;

/// 前端传入的连接参数（与 Web REST 共用 agile-net-client::ParsedConnect）
pub type ConnectInput = ParsedConnect;

pub struct AppState {
    pub(crate) client: AgileNetClient,
    pub(crate) creds: Arc<Option<Arc<CredentialStore>>>,
    pub(crate) web_api: Arc<tokio::sync::Mutex<Option<agile_net_client::api::ClientApiHandle>>>,
    pub(crate) roles: Arc<tokio::sync::Mutex<RoleSettings>>,
    pub(crate) server: Arc<tokio::sync::Mutex<Option<NodeServer>>>,
    /// 控制台 loopback 转发器：node_id → 本地环回端口
    pub(crate) consoles: Arc<tokio::sync::Mutex<std::collections::HashMap<String, u16>>>,
    /// 订阅内核（mihomo sidecar）
    pub(crate) kernel: Arc<subscription::KernelManager>,
    /// 制品下载管理器（mihomo 内核 / wintun.dll；进度状态机 + 手动安装）
    pub(crate) dl: download::DownloadManager,
    /// 客户端代理真实状态槽（传给内嵌节点；管理端「本地代理」卡数据源）
    pub(crate) client_proxy_slot: agile_net_node::service::ClientProxySlot,
    /// TUN 最近一次外部上游拨测结果（None = 未拨测；前端状态行/灵动岛告警数据源）
    pub(crate) tun_upstream_ok: Arc<tokio::sync::Mutex<Option<bool>>>,
    /// TUN 放弃开启的一次性提示（权限不足/启动失败回退普通模式；前端读取后清除）
    pub(crate) tun_notice: Arc<tokio::sync::Mutex<Option<String>>>,
    /// 最近一次应用的回落上游（变化时审计 gui.fallback_change，记地址不记凭据）
    pub(crate) last_fallback: Arc<tokio::sync::Mutex<Option<std::net::SocketAddr>>>,
    /// 悬浮球气泡通知开关的廉价缓存（float_notify 同步门控用；与 roles.notify_float_ball 同步）
    pub(crate) notify_float_ball: Arc<AtomicBool>,
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

pub(crate) fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
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
