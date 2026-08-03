//! 从 lib.rs 拆分：自定义规则命令（放行 / hosts 映射 / 组合）（纯搬运，零逻辑变更）

use crate::{custom_rules, AppState};
use serde::Serialize;
use tauri::State;

// ==================== 自定义规则（放行 / hosts 映射 / 组合） ====================
//
// 模型 / 存储 / 系统 hosts 托管 / 生效并集见 custom_rules.rs；
// 引擎集成（set_custom_rules ArcSwap 热更 → rebuild 烘焙路由自定义层，
// 本地代理入站评估优先于合并路由与订阅回落）见 agile-net-client。
// 规则 key 约定：自定义规则 = 其 id；拉取规则 = 现有 ruleKey（type:value 小写，app.js ruleKey），
// 组合中的拉取规则 key 由前端经既有暂停接口（set_rule_paused）另行处理。

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
pub(crate) async fn list_custom_rules() -> Result<CustomRulesView, String> {
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
pub(crate) async fn add_bypass_rule(
    state: State<'_, AppState>,
    pattern: String,
    via_subscription: bool,
) -> Result<String, String> {
    custom_rules::add_bypass(&state.client, &pattern, via_subscription)
}

#[tauri::command]
pub(crate) async fn add_host_mapping(
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
pub(crate) async fn set_custom_rule_enabled(
    state: State<'_, AppState>,
    id: String,
    enabled: bool,
) -> Result<(), String> {
    custom_rules::set_enabled(&state.client, &id, enabled)
}

#[tauri::command]
pub(crate) async fn remove_custom_rule(state: State<'_, AppState>, id: String) -> Result<(), String> {
    custom_rules::remove(&state.client, &id)
}

#[tauri::command]
pub(crate) async fn list_rule_combos() -> Result<Vec<custom_rules::RuleCombo>, String> {
    Ok(custom_rules::snapshot().combos)
}

#[tauri::command]
pub(crate) async fn add_combo(state: State<'_, AppState>, name: String) -> Result<String, String> {
    custom_rules::add_combo(&state.client, &name)
}

#[tauri::command]
pub(crate) async fn update_combo(
    state: State<'_, AppState>,
    id: String,
    name: String,
    rule_keys: Vec<String>,
) -> Result<(), String> {
    custom_rules::update_combo(&state.client, &id, &name, rule_keys)
}

#[tauri::command]
pub(crate) async fn remove_combo(state: State<'_, AppState>, id: String) -> Result<(), String> {
    custom_rules::remove_combo(&state.client, &id)
}

#[tauri::command]
pub(crate) async fn set_combo_enabled(
    state: State<'_, AppState>,
    id: String,
    enabled: bool,
) -> Result<(), String> {
    custom_rules::set_combo_enabled(&state.client, &id, enabled)
}
