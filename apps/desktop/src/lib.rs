//! AgileNet desktop client Tauri backend
//!
//! Exposes node management, proxy control and credential storage to the frontend over IPC;
//! all network logic reuses the agile-net-client engine (same data plane as CLI/daemon).
//! The server role embeds the full agile-net-node (same assembly root NodeServer as anet-svc).

use agile_net_client::{AgileNetClient, CredentialStore, ParsedConnect};
use agile_net_node::service::NodeServer;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tauri::{Emitter, Manager};

/// Forward deep links (anet:// / legacy agilenet://) and .anet file-association paths to the
/// frontend as `ag-open-payload` (kind: link|file), focusing the main window (federation P1).
fn open_payloads_from_argv(app: &tauri::AppHandle, argv: &[String]) {
    let mut hit = false;
    for arg in argv.iter().skip(1) {
        if arg.starts_with("anet://") || arg.starts_with("agilenet://") {
            let _ = app.emit_to(
                "main",
                "ag-open-payload",
                serde_json::json!({"kind": "link", "value": arg}),
            );
            hit = true;
        } else if arg.to_lowercase().ends_with(".anet") {
            let _ = app.emit_to(
                "main",
                "ag-open-payload",
                serde_json::json!({"kind": "file", "value": arg}),
            );
            hit = true;
        }
    }
    if hit {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.unminimize();
            let _ = w.show();
            let _ = w.set_focus();
        }
    }
}

mod cmd;
mod custom_rules;
mod download;
#[cfg(windows)]
mod floatball;
pub(crate) mod agent;
pub(crate) mod kernel;
pub(crate) mod llm;
mod roles;
mod subscription;
mod sub_script;
mod sync;
mod sysproxy;
mod tun;
use roles::RoleSettings;

// Tauri commands and window/tray/float-ball management were split into cmd/ (pure move, zero logic change);
// full re-exports keep the generate_handler![...] list below and crate:: path references (floatball.rs etc.) unchanged.
pub(crate) use cmd::*;

/// Connect parameters from the frontend (shares agile-net-client::ParsedConnect with Web REST)
pub type ConnectInput = ParsedConnect;

pub struct AppState {
    pub(crate) client: AgileNetClient,
    pub(crate) creds: Arc<Option<Arc<CredentialStore>>>,
    pub(crate) web_api: Arc<tokio::sync::Mutex<Option<agile_net_client::api::ClientApiHandle>>>,
    pub(crate) roles: Arc<tokio::sync::Mutex<RoleSettings>>,
    pub(crate) server: Arc<tokio::sync::Mutex<Option<NodeServer>>>,
    /// Console loopback forwarders: node_id → local loopback port
    pub(crate) consoles: Arc<tokio::sync::Mutex<std::collections::HashMap<String, u16>>>,
    /// Subscription kernel (mihomo sidecar)
    pub(crate) kernel: Arc<subscription::KernelManager>,
    /// Artifact download manager (mihomo kernel / wintun.dll; progress state machine + manual install)
    pub(crate) dl: download::DownloadManager,
    /// Real client proxy state slot (passed to the embedded node; data source of the admin UI "local proxy" card)
    pub(crate) client_proxy_slot: agile_net_node::service::ClientProxySlot,
    /// Latest TUN external upstream probe result (None = not probed; data source for the frontend status line / dynamic-island warning)
    pub(crate) tun_upstream_ok: Arc<tokio::sync::Mutex<Option<bool>>>,
    /// One-shot notice for aborted TUN enabling (insufficient privileges / startup failure, fell back to normal mode; cleared after frontend reads)
    pub(crate) tun_notice: Arc<tokio::sync::Mutex<Option<String>>>,
    /// Last applied fallback upstream (changes audited as gui.fallback_change; address logged, never credentials)
    pub(crate) last_fallback: Arc<tokio::sync::Mutex<Option<std::net::SocketAddr>>>,
    /// Cheap cache of the float ball bubble notification toggle (for sync gating in float_notify; kept in sync with roles.notify_float_ball)
    pub(crate) notify_float_ball: Arc<AtomicBool>,
    /// Built-in network security agent (session-scoped conversation owned here; see agent.rs)
    pub(crate) agent: Arc<agent::AgentState>,
    /// App-side tracing ring buffer (anet logs; 实时日志 tab fallback source when the kernel is off)
    pub(crate) app_logs: agile_net_node::logs::LogBuffer,
}

impl AppState {
    fn new(app_logs: agile_net_node::logs::LogBuffer) -> Self {
        let roles = RoleSettings::load();
        let notify_float_ball = roles.notify_float_ball;
        // Boot initial values: proxy not started + saved proxy mode preference (boot restore state)
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
            agent: Arc::new(agent::AgentState::new()),
            app_logs,
        }
    }
}

pub(crate) fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}


#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // One-shot data layout migration (~/.agile-net → ~/.anet/{svc,gui,root}).
    // Idempotent: no-op if legacy dir absent or new dir already exists. Must run
    // before any module loads `~/.anet/...` paths (RoleSettings, credentials, …).
    if let Err(e) = agile_net_core::util::migrate_legacy_layout() {
        eprintln!("warn: legacy layout migration failed: {e}; continuing");
    }

    let app_log_buf = agile_net_node::logs::LogBuffer::new();
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer())
        // in-memory ring buffer: the GUI 实时日志 tab's anet-side fallback when the kernel is off
        .with(agile_net_node::logs::LogBufferLayer::new(app_log_buf.clone()))
        .init();

    let mut builder = tauri::Builder::default();
    // Single instance must register first: deep links / file-association launches on Windows
    // reach the running instance as argv; forwarded to the frontend as open payloads (desktop only)
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            open_payloads_from_argv(app, &argv);
        }));
    }
    let app = builder
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(AppState::new(app_log_buf))
        .invoke_handler(tauri::generate_handler![
            connect_node,
            disconnect_node,
            list_nodes,
            rename_credential,
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
            set_server_public_host,
            has_web_password,
            set_web_password,
            set_web_role,
            console_url,
            server_manageable,
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
            anet_save_file,
            anet_open_file,
            read_text_file,
            qr_pick_decode,
            conlog_status,
            conlog_query,
            conlog_hosts,
            conlog_set_enabled,
            conlog_clear,
            conlog_kill,
            conlog_kill_target,
            proxy_traffic,
            app_logs,
            app_logs_clear,
            agent::agent_get_state,
            agent::agent_send,
            agent::agent_stop,
            agent::agent_clear,
            agent::agent_confirm,
            agent::agent_config_set,
            agent::agent_skill_save,
            agent::agent_skill_toggle,
            agent::agent_skill_delete,
        ])
        .setup(|app| {
            setup_tray(app)?;

            // Deep links (macOS/iOS/Android deliver via the plugin event; Windows/Linux via argv —
            // single-instance above and the first-launch argv below)
            {
                use tauri::Listener as _;
                let handle = app.handle().clone();
                app.listen("deep-link://new-url", move |event| {
                    let urls: Vec<String> = serde_json::from_str(event.payload())
                        .or_else(|_| serde_json::from_str(event.payload()).map(|u: String| vec![u]))
                        .unwrap_or_default();
                    let argv: Vec<String> = std::iter::once(String::new())
                        .chain(urls.into_iter().filter(|u| u.starts_with("anet://") || u.starts_with("agilenet://")))
                        .collect();
                    if argv.len() > 1 {
                        open_payloads_from_argv(&handle, &argv);
                    }
                });
            }
            // First-launch argv (Windows file association / scheme launch with no running instance)
            open_payloads_from_argv(&app.handle().clone(), &std::env::args().collect::<Vec<_>>());

            // Restore previously enabled server role (embedded node) and subscription kernel; start the system proxy patrol
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                restore_server_role(&handle).await;
                restore_web_role(&handle).await;
                restore_subscription_role(&handle).await;
                // Seed the built-in direct presets (LAN/link-local/loopback/CGNAT, first launch only;
                // no-op when the store already carries presets — deleted presets stay deleted) then restore custom rules.
                custom_rules::seed_presets();
                // Restore custom rules (effective union of bypass/hosts mapping/combo → engine hot reload)
                custom_rules::restore(&handle.state::<AppState>().client);
            });
            // Startup cleanup: a previous abnormal exit (killed process) may leave the system proxy pointing at a dead port; restore from snapshot
            tauri::async_runtime::spawn(async move {
                let _ = tokio::task::spawn_blocking(sysproxy::cleanup_if_pending).await;
            });
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                sysproxy_watch(handle).await;
            });
            // Connection log (docs/todo/conn-log.md): replay persisted rows, restore enabled/tun-relay flags, spawn the smart-flush task
            init_conn_log(app.handle());
            // Tray tooltip live speed (1s)
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tray_speed_watch(handle).await;
            });
            // Restore float ball (was enabled at last exit; desktop only, mobile create returns unsupported)
            if roles::RoleSettings::load().float_ball {
                let _ = create_float_ball(app.handle());
            }

            // Window size and position: half the primary monitor's logical width, 4:3, screen-centered (same spec as the console);
            // created hidden (conf visible:false) and shown after positioning, eliminating top-left flicker
            if let Some(window) = app.get_webview_window("main") {
                normalize_window_geometry(&window);
                let _ = window.show();
                let _ = window.set_focus();
            }

            // Minimize to tray instead of exiting on window close; refresh tray icon black/white on system theme change
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
        // §2.6 Exit GUI (TUN mode): stop the kernel (mihomo exit auto-cleans the TUN adapter and routes)
        // + restore the system proxy snapshot; the event callback runs on the main thread, block_on is safe
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
