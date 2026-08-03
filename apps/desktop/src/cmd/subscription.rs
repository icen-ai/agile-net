//! 从 lib.rs 拆分：订阅代理（mihomo sidecar）/ 制品下载 / 覆写脚本（纯搬运，零逻辑变更）

use crate::tun::{self, Elevation};
use crate::{custom_rules, download, map_err, roles, sub_script, subscription, AppState};
use serde::Serialize;
use tauri::{Manager, State};

// ==================== 订阅代理（mihomo sidecar） ====================

/// 当前生效的回落地址（统一出口为派生语义，无用户开关：订阅内核开 = 未命中走订阅出口）：
/// - TUN 模式：订阅出口优先（TUN mihomo socks 入站 57893→AGILE-SUB，无 FlClash 也能出网）；
///   无激活订阅时回落外部上游（§2.4），异常值宁可无回落也不成环
/// - 非 TUN：订阅角色开 + 内核运行 → 回落到内核 mixed（57892）
/// - 其余：无回落（未命中直连）
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

/// 应用回落上游（记地址不记凭据；变化时审计 gui.fallback_change）
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

/// 安装订阅内核：开始后台下载（流式进度经 dl_state 轮询展示，完成自动校验落盘）。
/// 内核运行中禁止重装（Windows 文件锁会让落盘失败）。
#[tauri::command]
pub(crate) async fn install_kernel(state: State<'_, AppState>) -> Result<(), String> {
    if state.kernel.running().await {
        return Err("内核运行中，请先关闭订阅代理再重新下载".into());
    }
    state.dl.start(download::Artifact::Kernel)
}

// ==================== 制品下载管理（mihomo 内核 / wintun.dll） ====================

/// 下载状态机快照（前端 2s 轮询渲染下载卡）
#[tauri::command]
pub(crate) async fn dl_state(state: State<'_, AppState>) -> Result<download::DlState, String> {
    Ok(state.dl.state())
}

/// 开始/重试下载（同制品下载中幂等）
#[tauri::command]
pub(crate) async fn dl_start(state: State<'_, AppState>, artifact: String) -> Result<(), String> {
    let artifact = download::Artifact::parse(&artifact)?;
    if artifact == download::Artifact::Kernel && state.kernel.running().await {
        return Err("内核运行中，请先关闭订阅代理再下载".into());
    }
    state.dl.start(artifact)
}

/// 取消下载（回 idle；前端同时放弃「完成后自动重试」）
#[tauri::command]
pub(crate) async fn dl_cancel(state: State<'_, AppState>) -> Result<(), String> {
    state.dl.cancel();
    Ok(())
}

/// 手动安装本地制品文件：钉值校验通过才落盘；
/// 不符返回 hash_mismatch（前端弹确认框明示风险），用户确认后带 allow_mismatch=true 重调强装。
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

/// 激活/停用订阅功能入口（侧栏「订阅/代理」可见性；停用即停机并关角色）。
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

/// 单选激活订阅；角色开启中即重启内核加载新激活项。
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

/// 添加订阅（先拉取校验）；角色开启中且新订阅为激活项时重启内核。
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

/// 导入本地 YAML 订阅：校验路径（存在/yaml 扩展名/≤5MB）→ 读取内容走与 URL 订阅
/// 相同的嗅探入库路径（subscription::add_local_subscription，provider 渲染为 type: file）。
/// 名称取文件名去扩展名；角色开启中且新订阅为激活项时重启内核。
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

/// 删除订阅；角色开启中即重启内核（清空则停机）。
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

/// 代理组与节点：内核在运行返回实时数据并落缓存；
/// 内核未运行回落到最近缓存（cached 标记），代理页只读展示节点情况
#[tauri::command]
pub(crate) async fn proxy_groups() -> Result<serde_json::Value, String> {
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
pub(crate) async fn select_proxy(group: String, name: String) -> Result<(), String> {
    subscription::kernel_api().await?.select(&group, &name).await
}

/// 组测速：provider 节点只能经 /group/{group}/delay 测（内核并发一次测全组），
/// 返回 name → ms（超时节点已被剔除）。
#[tauri::command]
pub(crate) async fn test_delay(group: String) -> Result<std::collections::HashMap<String, u32>, String> {
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

/// 订阅内核流量快照（/traffic WS 累计；内核停止即清零）。
#[tauri::command]
pub(crate) async fn sub_traffic(state: State<'_, AppState>) -> Result<subscription::TrafficSnapshot, String> {
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
pub(crate) async fn sub_connections(state: State<'_, AppState>) -> Result<ConnectionsView, String> {
    if !state.kernel.running().await {
        return Ok(ConnectionsView::default());
    }
    let (active, closed) = state.kernel.connections();
    Ok(ConnectionsView { active, closed })
}

/// 内核日志（旧→新排列，上限 500；前端倒序展示自行处理；内核未运行返回空集）。
#[tauri::command]
pub(crate) async fn sub_logs(state: State<'_, AppState>) -> Result<Vec<subscription::LogEntry>, String> {
    if !state.kernel.running().await {
        return Ok(Vec::new());
    }
    Ok(state.kernel.logs())
}

/// 规则命中聚合（count 降序 top 100；内核未运行返回空集）。
#[tauri::command]
pub(crate) async fn sub_rule_hits(state: State<'_, AppState>) -> Result<Vec<subscription::RuleHit>, String> {
    if !state.kernel.running().await {
        return Ok(Vec::new());
    }
    Ok(state.kernel.rule_hits())
}

/// 关闭单条连接（DELETE /connections/{id}）。
#[tauri::command]
pub(crate) async fn sub_close_connection(id: String) -> Result<(), String> {
    if id.is_empty() || id.chars().any(|c| c == '/' || c.is_whitespace()) {
        return Err("连接 id 不合法".into());
    }
    subscription::kernel_api().await?.close_connection(&id).await
}

/// 清空内核日志与规则命中缓冲（连接态不动）。
#[tauri::command]
pub(crate) async fn sub_clear_logs(state: State<'_, AppState>) -> Result<(), String> {
    state.kernel.clear_logs();
    Ok(())
}

/// 一键加规则：把主机加入自定义规则（target=direct 直连放行 / subscription 经订阅出口）。
/// host 自动去 scheme/端口/路径并校验；同主机规则已存在时幂等返回成功。
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

/// 新建脚本（默认启用，追加到链尾）；内核运行中即重启生效。
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

/// 更新脚本名称/代码；内核运行中即重启生效。
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

/// 拖拽排序：ids 为全量脚本 id 的目标顺序（须为现有 id 的排列）。
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

/// 试跑：对当前订阅配置（含现有启用脚本管线结果）执行一次，返回摘要或错误。
#[tauri::command]
pub(crate) async fn test_sub_script(state: State<'_, AppState>, code: String) -> Result<String, String> {
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

/// 启动时恢复订阅内核（上次退出时订阅角色处于开启状态）。
/// TUN 模式持久化恢复（§2.2 提权重启后自动恢复开启）：补 wintun → 启动内核（TUN 骨架）
/// → 数据面/系统代理副作用（拨测结果进状态槽，前端灵动岛告警）。
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
        crate::abandon_tun(&state, "需要管理员权限").await;
        tun_mode = false;
    }
    if tun_mode {
        if let Err(e) = subscription::ensure_wintun().await {
            // wintun 缺失：后台下载（完成后用户重开 TUN 即可）；其它错误同样只放弃 TUN，不阻断普通模式恢复
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
                // TUN 配置启动失败：放弃 TUN 再以普通模式重试一次
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
