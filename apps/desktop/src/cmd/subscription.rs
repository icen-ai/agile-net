//! Split out of lib.rs: subscription proxy (mihomo sidecar) / artifact download / override scripts (pure move, zero logic changes)

use crate::tun::{self, Elevation};
use crate::{custom_rules, download, map_err, roles, sub_script, subscription, AppState};
use serde::Serialize;
use tauri::{Manager, State};

// ==================== Subscription proxy (mihomo sidecar) ====================

/// Currently effective fallback address (unified egress is derived, no user toggle: subscription kernel on = misses via subscription egress):
/// - TUN mode: subscription egress first (TUN mihomo socks inbound 57893→AGILE-SUB, works without FlClash);
///   with no active subscription fall back to the external upstream (§2.4); for bad values prefer no fallback over a loop
/// - Non-TUN: subscription role on + kernel running → fall back to kernel mixed (57892)
/// - Otherwise: no fallback (misses go direct)
pub(crate) async fn effective_fallback(state: &State<'_, AppState>) -> Option<std::net::SocketAddr> {
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

/// Apply fallback upstream (remember address only, no credentials; audit gui.fallback_change on change)
pub(crate) async fn apply_proxy_fallback(state: &State<'_, AppState>) {
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

#[tauri::command]
pub(crate) async fn list_subscriptions() -> Result<Vec<subscription::Subscription>, String> {
    Ok(subscription::list_subscriptions())
}

/// Install the subscription kernel: start a background download (streamed progress polled via dl_state, verified and written to disk on completion).
/// Reinstall is forbidden while the kernel is running (Windows file locks would fail the write).
#[tauri::command]
pub(crate) async fn install_kernel(state: State<'_, AppState>) -> Result<(), String> {
    if state.kernel.running().await {
        return Err("内核运行中，请先关闭订阅代理再重新下载".into());
    }
    state.dl.start(download::Artifact::Kernel)
}

// ==================== Artifact download management (mihomo kernel / wintun.dll) ====================

/// Download state machine snapshot (frontend polls every 2s to render the download card)
#[tauri::command]
pub(crate) async fn dl_state(state: State<'_, AppState>) -> Result<download::DlState, String> {
    Ok(state.dl.state())
}

/// Start/retry download (idempotent while the same artifact is downloading)
#[tauri::command]
pub(crate) async fn dl_start(state: State<'_, AppState>, artifact: String) -> Result<(), String> {
    let artifact = download::Artifact::parse(&artifact)?;
    if artifact == download::Artifact::Kernel && state.kernel.running().await {
        return Err("内核运行中，请先关闭订阅代理再下载".into());
    }
    state.dl.start(artifact)
}

/// Cancel download (back to idle; frontend also drops "auto-retry on completion")
#[tauri::command]
pub(crate) async fn dl_cancel(state: State<'_, AppState>) -> Result<(), String> {
    state.dl.cancel();
    Ok(())
}

/// Manually install a local artifact file: written to disk only after pinned-hash verification passes;
/// on mismatch returns hash_mismatch (frontend shows a risk confirmation), then the user re-calls with allow_mismatch=true to force install.
#[tauri::command]
pub(crate) async fn dl_install_manual(
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

/// Enable/disable the subscription feature (sidebar "Subscription/Proxy" visibility; disabling stops the kernel and turns off the role).
#[tauri::command]
pub(crate) async fn activate_subscription_feature(
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

/// Activate a single subscription; if the role is on, restart the kernel to load the newly active one.
#[tauri::command]
pub(crate) async fn set_active_subscription(
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

/// Add a subscription (fetched and validated first); restart the kernel if the role is on and the new subscription is active.
#[tauri::command]
pub(crate) async fn add_subscription(
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

/// Import a local YAML subscription: validate path (exists / yaml extension / ≤5MB) → read content through the same
/// sniff-and-store path as URL subscriptions (subscription::add_local_subscription, provider rendered as type: file).
/// Name is the file name without extension; restart the kernel if the role is on and the new subscription is active.
#[tauri::command]
pub(crate) async fn import_local_subscription(
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

/// Remove a subscription; if the role is on, restart the kernel (stop it if none remain).
#[tauri::command]
pub(crate) async fn remove_subscription(state: State<'_, AppState>, id: String) -> Result<(), String> {
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
pub(crate) async fn update_subscription(id: String) -> Result<subscription::Subscription, String> {
    subscription::update_subscription(&id).await
}

#[tauri::command]
pub(crate) async fn subscription_status(state: State<'_, AppState>) -> Result<subscription::KernelStatus, String> {
    Ok(state.kernel.status().await)
}

/// Proxy groups and nodes: when the kernel is running, return live data and update the cache;
/// otherwise fall back to the latest cache (cached flag); the proxy page shows nodes read-only
#[tauri::command]
pub(crate) async fn proxy_groups() -> Result<serde_json::Value, String> {
    let live = match subscription::kernel_api().await {
        Ok(api) => match api.proxies().await {
            Ok(mut v) => {
                // Merge in provider node protocol/history (the /proxies global table excludes provider nodes)
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
pub(crate) async fn select_proxy(group: String, name: String) -> Result<(), String> {
    subscription::kernel_api().await?.select(&group, &name).await
}

/// Group latency test: provider nodes can only be tested via /group/{group}/delay (kernel tests the whole group concurrently in one pass),
/// returns name → ms (timed-out nodes already filtered out).
#[tauri::command]
pub(crate) async fn test_delay(group: String) -> Result<std::collections::HashMap<String, u32>, String> {
    subscription::kernel_api().await?.group_delay(&group).await
}

/// Node latency result (sub_test_group response body; delay=0 means timeout/failure)
#[derive(Debug, Clone, Serialize)]
pub struct NodeDelay {
    pub name: String,
    pub delay: u32,
}

/// Batch node latency test (node page "daily pick"): HTTPS 204 probe, 3000ms timeout;
/// failed/timed-out nodes get delay normalized to 0 and sorted last; valid latencies returned ascending.
#[tauri::command]
pub(crate) async fn sub_test_group(state: State<'_, AppState>, group: String) -> Result<Vec<NodeDelay>, String> {
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

/// Subscription kernel traffic snapshot (accumulated over /traffic WS; cleared when the kernel stops).
#[tauri::command]
pub(crate) async fn sub_traffic(state: State<'_, AppState>) -> Result<subscription::TrafficSnapshot, String> {
    Ok(state.kernel.traffic())
}

// ==================== Subscription kernel connection/log collection (/connections, /logs WS) ====================

/// Connection snapshot response body (sub_connections contract)
#[derive(Debug, Clone, Default, Serialize)]
pub struct ConnectionsView {
    /// Active connections (up_rate/down_rate are snapshot-diff rates)
    pub active: Vec<subscription::ConnectionInfo>,
    /// Recently closed (newest first, capped at 300)
    pub closed: Vec<subscription::ConnectionInfo>,
}

/// Connection snapshot: active + recently closed; returns an empty set instead of an error when the kernel is not running.
#[tauri::command]
pub(crate) async fn sub_connections(state: State<'_, AppState>) -> Result<ConnectionsView, String> {
    if !state.kernel.running().await {
        return Ok(ConnectionsView::default());
    }
    let (active, closed) = state.kernel.connections();
    Ok(ConnectionsView { active, closed })
}

/// Kernel logs (oldest→newest, capped at 500; frontend handles reverse display itself; empty set when kernel is not running).
#[tauri::command]
pub(crate) async fn sub_logs(state: State<'_, AppState>) -> Result<Vec<subscription::LogEntry>, String> {
    if !state.kernel.running().await {
        return Ok(Vec::new());
    }
    Ok(state.kernel.logs())
}

/// Rule hit aggregation (top 100 by count descending; empty set when kernel is not running).
#[tauri::command]
pub(crate) async fn sub_rule_hits(state: State<'_, AppState>) -> Result<Vec<subscription::RuleHit>, String> {
    if !state.kernel.running().await {
        return Ok(Vec::new());
    }
    Ok(state.kernel.rule_hits())
}

/// Close a single connection (DELETE /connections/{id}).
#[tauri::command]
pub(crate) async fn sub_close_connection(id: String) -> Result<(), String> {
    if id.is_empty() || id.chars().any(|c| c == '/' || c.is_whitespace()) {
        return Err("连接 id 不合法".into());
    }
    subscription::kernel_api().await?.close_connection(&id).await
}

/// Clear kernel logs and rule-hit buffers (connection state untouched).
#[tauri::command]
pub(crate) async fn sub_clear_logs(state: State<'_, AppState>) -> Result<(), String> {
    state.kernel.clear_logs();
    Ok(())
}

/// One-click add rule: add the host to custom rules (target=direct for direct allow / subscription via the subscription egress).
/// host is auto-stripped of scheme/port/path and validated; idempotent success if a rule for the same host already exists.
#[tauri::command]
pub(crate) async fn sub_add_rule_for_host(
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
    // Idempotent: an existing rule with the same pattern counts as success (does not change the existing rule's egress)
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

// ==================== Subscription override scripts / outbound mode ====================

/// After a script change, restart the running kernel to load the new config (same hot-reload path as activating a subscription: rewrite config + restart).
pub(crate) async fn reload_kernel_if_running(state: &State<'_, AppState>) -> Result<(), String> {
    if state.roles.lock().await.subscription {
        state.kernel.stop().await;
        state.kernel.start().await?;
        apply_proxy_fallback(state).await;
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn list_sub_scripts(state: State<'_, AppState>) -> Result<Vec<roles::SubScript>, String> {
    Ok(state.roles.lock().await.sub_scripts.clone())
}

/// Create a script (enabled by default, appended to the end of the chain); restart takes effect if the kernel is running.
#[tauri::command]
pub(crate) async fn add_sub_script(
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

/// Update script name/code; restart takes effect if the kernel is running.
#[tauri::command]
pub(crate) async fn update_sub_script(
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
pub(crate) async fn remove_sub_script(state: State<'_, AppState>, id: String) -> Result<(), String> {
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
pub(crate) async fn set_sub_script_enabled(
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

/// Drag reorder: ids is the target order of all script ids (must be a permutation of existing ids).
#[tauri::command]
pub(crate) async fn reorder_sub_scripts(state: State<'_, AppState>, ids: Vec<String>) -> Result<(), String> {
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

/// Dry run: execute once against the current subscription config (including the existing enabled-script pipeline result), returning a summary or error.
#[tauri::command]
pub(crate) async fn test_sub_script(state: State<'_, AppState>, code: String) -> Result<String, String> {
    let (mode, scripts) = {
        let r = state.roles.lock().await;
        (r.sub_mode.clone(), r.sub_scripts.clone())
    };
    // Same pipeline as production: base render (non-TUN; scripts do not apply to the TUN skeleton, established decision) →
    // enabled script chain (failures skipped) → dry-run code (errors surfaced)
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

/// Restore the subscription kernel at startup (subscription role was on at last exit).
/// Persisted TUN mode restore (§2.2 auto-restore after elevated restart): ensure wintun → start kernel (TUN skeleton)
/// → data-plane/system-proxy side effects (probe results go into the state slot, frontend Dynamic Island alert).
pub(crate) async fn restore_subscription_role(app: &tauri::AppHandle) {
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
    // Kernel missing: background download (no longer blocks the restore flow; user re-enables the subscription role after it completes)
    if !subscription::kernel_bin_exists() {
        if let Err(e) = state.dl.start(download::Artifact::Kernel) {
            tracing::error!(error = %e, "failed to start kernel download on restore");
        } else {
            tracing::info!("kernel missing on restore — background download started");
        }
        return;
    }
    // Elevated restart cancelled by the user (UAC denied) or elevation lost: abandon TUN and restore in normal mode, usage unaffected
    let mut tun_mode = tun_mode;
    if tun_mode && !tun::SystemElevation.is_admin() {
        tracing::warn!("persisted TUN mode but process is not elevated — abandoning TUN, restore as normal mode");
        crate::abandon_tun(&state, "需要管理员权限").await;
        tun_mode = false;
    }
    if tun_mode {
        if let Err(e) = subscription::ensure_wintun().await {
            // wintun missing: background download (user re-enables TUN after it completes); other errors likewise only abandon TUN, not blocking normal-mode restore
            if e.starts_with(subscription::NEED_DOWNLOAD_PREFIX) {
                let _ = state.dl.start(download::Artifact::Wintun);
                crate::abandon_tun(&state, "wintun 组件未安装，已转为后台下载").await;
            } else {
                tracing::error!(error = %e, "failed to ensure wintun for persisted TUN mode");
                crate::abandon_tun(&state, &format!("wintun 组件不可用（{e}）")).await;
            }
            tun_mode = false;
        }
    }
    match state.kernel.start().await {
        Ok(()) => {
            tracing::info!(tun = tun_mode, "subscription kernel restored");
            apply_proxy_fallback(&state).await;
            if tun_mode {
                if let Err(e) = crate::tun_side_effects(app, &state).await {
                    tracing::error!(error = %e, "failed to apply TUN side effects on restore");
                }
            }
        }
        Err(e) => {
            if tun_mode {
                // TUN config start failed: abandon TUN and retry once in normal mode
                tracing::error!(error = %e, "failed to restore kernel with TUN, retrying normal mode");
                crate::abandon_tun(&state, &format!("启动失败（{e}）")).await;
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
