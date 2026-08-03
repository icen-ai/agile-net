//! Split from lib.rs: custom rule commands (bypass / hosts mapping / combo) (pure move, zero logic change)

use crate::{custom_rules, AppState};
use serde::Serialize;
use tauri::State;

// ==================== Custom rules (bypass / hosts mapping / combo) ====================
//
// Model / storage / system hosts management / effective union: see custom_rules.rs;
// engine integration (set_custom_rules ArcSwap hot reload → rebuild bakes the custom routing layer,
// evaluated at local proxy ingress ahead of merged routes and subscription fallback): see agile-net-client.
// Rule key convention: custom rule = its id; pulled rule = existing ruleKey (lowercase type:value, app.js ruleKey);
// pulled-rule keys inside combos are handled separately by the frontend via the existing pause API (set_rule_paused).

/// Custom rules list view (list_custom_rules return shape is the WaveB frontend contract).
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
    /// user = user-created; system = pre-existing system hosts entry (not managed by this app, read-only)
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddHostResult {
    pub id: String,
    /// system = persisted to the system hosts managed block; internal = in-process mapping only (fallback e.g. on missing privileges)
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
    // Merge pre-existing system hosts mappings (not managed by this app) into the view; user entries win on hostname collision
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
