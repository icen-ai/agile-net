//! Split from lib.rs: endpoint connect / credentials / rule pause (pure move, zero logic change)

use crate::{map_err, roles, AppState, ConnectInput};
use agile_net_client::{ConnectParams, Credential, NodeState};
use tauri::State;

/// Connect to a node
#[tauri::command]
pub(crate) async fn connect_node(state: State<'_, AppState>, input: ConnectInput) -> Result<NodeState, String> {
    if !state.roles.lock().await.client {
        return Err("扇入已停用，请在首页开启".into());
    }
    let params = ConnectParams {
        addr: input.addr.clone(),
        label: input.label.clone(),
        token: input.token.clone(),
        insecure: input.insecure,
        pinned_fingerprint: input.pinned_fingerprint.clone(),
        manage_hosts: input.manage_hosts,
        entries: input.entries.clone(),
        entry_fps: input.entry_fps.clone(),
        en: input.en.clone(),
        emode: input.emode.clone(),
        eadmin: input.eadmin,
    };
    let node_state = state.client.connect(params).await.map_err(map_err)?;

    if input.save_credential {
        if let Some(store) = state.creds.as_ref() {
            store
                .save(
                    &node_state.node_id,
                    &Credential {
                        addr: input.addr,
                        label: input.label,
                        token: input.token,
                        name: None,
                        insecure: input.insecure,
                        pinned_fingerprint: input.pinned_fingerprint,
                        entries: input.entries,
                        entry_fps: input.entry_fps,
                        en: input.en,
                        emode: input.emode,
                        eadmin: input.eadmin,
                    },
                )
                .await;
        }
    }
    Ok(node_state)
}

/// Disconnect a node (saved credentials are kept; removal goes through delete_credential)
#[tauri::command]
pub(crate) async fn disconnect_node(state: State<'_, AppState>, node_id: String) -> Result<(), String> {
    state.client.disconnect(&node_id).await;
    let mut map = state.consoles.lock().await;
    map.remove(&node_id);
    let prefix = format!("{node_id}|");
    map.retain(|k, _| !k.starts_with(&prefix));
    Ok(())
}

/// Delete a saved credential
#[tauri::command]
pub(crate) async fn delete_credential(state: State<'_, AppState>, key: String) -> Result<(), String> {
    if let Some(store) = state.creds.as_ref() {
        store.remove(&key).await;
    }
    Ok(())
}

/// Export a saved credential as an anet://connect delegated URL (contains the token plaintext; share with care)
#[tauri::command]
pub(crate) async fn export_credential(state: State<'_, AppState>, key: String) -> Result<String, String> {
    let store = state.creds.as_ref().as_ref().ok_or("凭据存储不可用")?;
    let c = store.get(&key).await.ok_or("凭据不存在或已删除")?;
    Ok(agile_net_client::connect_url_of(&c))
}

/// Pause/resume a routing rule (rule_key format "type:value")
#[tauri::command]
pub(crate) async fn set_rule_paused(
    state: State<'_, AppState>,
    node_id: String,
    rule_key: String,
    paused: bool,
) -> Result<(), String> {
    state.client.set_rule_paused(&node_id, &rule_key, paused);
    Ok(())
}

/// List a node's paused rules
#[tauri::command]
pub(crate) async fn get_paused_rules(state: State<'_, AppState>, node_id: String) -> Result<Vec<String>, String> {
    Ok(state.client.get_paused_rules(&node_id))
}

/// Replace a node's paused set as a whole (for frontend persistence restore)
#[tauri::command]
pub(crate) async fn set_paused_rules(
    state: State<'_, AppState>,
    node_id: String,
    keys: Vec<String>,
) -> Result<(), String> {
    state.client.set_paused_rules(&node_id, keys);
    Ok(())
}

/// Node list (with live status)
#[tauri::command]
pub(crate) async fn list_nodes(state: State<'_, AppState>) -> Result<Vec<NodeState>, String> {
    let mut nodes = state.client.list_nodes().await;
    for n in &mut nodes {
        n.status = state.client.node_status(&n.node_id);
    }
    Ok(nodes)
}

/// List saved credentials
#[tauri::command]
pub(crate) async fn list_credentials(state: State<'_, AppState>) -> Result<Vec<(String, Credential)>, String> {
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

/// Rename a saved fan-in (user-assigned display alias; empty/whitespace clears it back to the
/// node-id-derived name). The store key (node_id) never changes, so connections are unaffected.
#[tauri::command]
pub(crate) async fn rename_credential(
    state: State<'_, AppState>,
    key: String,
    name: Option<String>,
) -> Result<(), String> {
    let Some(store) = state.creds.as_ref() else {
        return Err("凭据存储不可用".into());
    };
    let Some(mut cred) = store.get(&key).await else {
        return Err("凭据不存在".into());
    };
    let name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    if let Some(n) = &name {
        if n.chars().count() > 32 {
            return Err("名字最长 32 字".into());
        }
    }
    cred.name = name;
    store.save(&key, &cred).await;
    roles::audit("gui.cred_rename", serde_json::json!({"key": key, "name": cred.name}));
    Ok(())
}

/// Parse an anet://connect?... delegated URL (implemented in agile-net-client, shared with Web REST)
#[tauri::command]
pub(crate) fn parse_connect_url(url: String) -> Result<ConnectInput, String> {
    agile_net_client::parse_connect_url(&url)
}
