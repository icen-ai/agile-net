//! Split from lib.rs: endpoint connect / credentials / rule pause (pure move, zero logic change)

use crate::{map_err, roles, AppState, ConnectInput};
use agile_net_client::{ConnectParams, Credential, NodeState};
use tauri::{Manager, State};

/// Notification center fan-out (node.md M4-T1): every fresh inbox entry is broadcast to all
/// windows as `ag-notify` (tray / float-ball are separate JS contexts — a Tauri event is the
/// only instant channel) and mirrored to the float-ball bubble (gated by the bubble toggle).
/// mark_all_read/clear never bump the channel, so every wakeup carries a fresh unread entry.
pub(crate) async fn notify_watch(app: tauri::AppHandle) {
    use tauri::Emitter;
    let center = app.state::<AppState>().client.notifications();
    let mut rx = center.subscribe();
    let mut last_id = String::new();
    while rx.recv().await.is_ok() {
        let Some(n) = center.list().into_iter().next() else {
            continue;
        };
        // Burst pushes share one newest entry across wakeups; emit each notification once
        if n.id == last_id {
            continue;
        }
        last_id = n.id.clone();
        let _ = app.emit("ag-notify", &n);
        crate::float_notify(&app, &n.title);
    }
}

/// Node-state change forwarder: engine touches (connect/reconnect/blocked/admin-capable/pause)
/// arrive as `ag-nodes` so the fan-in list + title-bar admin entry repaint instantly
/// (the 10s AgPulse is now only the fallback, same contract as ag-roles/ag-notify).
pub(crate) async fn nodes_watch(app: tauri::AppHandle) {
    use tauri::Emitter;
    let notify = app.state::<AppState>().client.state_notify();
    loop {
        notify.notified().await;
        let _ = app.emit("ag-nodes", ());
    }
}

/// Kernel lifecycle forwarder (start ready / stop / crash-restart / give-up) → `ag-kernel`:
/// the subscription toggle/card and the TUN panel repaint instantly instead of at the next poll.
pub(crate) async fn kernel_watch(app: tauri::AppHandle) {
    use tauri::Emitter;
    let notify = app.state::<AppState>().kernel.state_notify();
    loop {
        notify.notified().await;
        let _ = app.emit("ag-kernel", ());
    }
}

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
        ek: input.ek.clone(),
        emode: input.emode.clone(),
        eadmin: input.eadmin,
        myname: input.myname.clone(),
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
                        ek: input.ek,
                        emode: input.emode,
                        eadmin: input.eadmin,
                        myname: input.myname,
                        // Topology-visibility clause accepted at import (M4-T5); kept for display
                        visibility: input.visibility,
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
    // kill this node's console forwarders outright (abort the accept task, don't just forget
    // the port — a detached listener task would leak the port and pin the opener's token)
    let prefix = format!("{node_id}|");
    super::misc::drop_console_forwarders(&state, |k| k == node_id || k.starts_with(&prefix)).await;
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

// ==================== Notification center (node.md M4-T1) ====================

/// Inbox list + unread count (titlebar bell badge / notify view data source)
#[tauri::command]
pub(crate) async fn list_notifications(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let center = state.client.notifications();
    Ok(serde_json::json!({
        "items": center.list(),
        "unread": center.unread_count(),
    }))
}

/// Mark every inbox entry read (badge clears)
#[tauri::command]
pub(crate) async fn notifications_read_all(state: State<'_, AppState>) -> Result<(), String> {
    state.client.notifications().mark_all_read();
    Ok(())
}

/// Clear the whole inbox (UI confirms first)
#[tauri::command]
pub(crate) async fn clear_notifications(state: State<'_, AppState>) -> Result<(), String> {
    state.client.notifications().clear();
    Ok(())
}

/// Pending-session appeal (M4-T3): upload one note to the issuer over the pending node's live
/// session control plane (issuer caps at 3 per session; the UI shows the composer only in
/// PendingApproval)
#[tauri::command]
pub(crate) async fn send_pending_note(
    state: State<'_, AppState>,
    node_id: String,
    body: String,
) -> Result<(), String> {
    let body = body.trim();
    if body.is_empty() || body.chars().count() > 512 {
        return Err("附言不能为空且不超过 512 字".into());
    }
    state.client.send_pending_note(&node_id, body).await.map_err(map_err)
}

// ==================== Machine identity card (node.md M4-T4) ====================

/// Machine identity view: device fingerprint + OpenSSH public key line + current self-declared
/// display name (first non-empty credential myname)
#[tauri::command]
pub(crate) async fn get_machine_identity(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let id = tokio::task::spawn_blocking(agile_net_core::device::DeviceIdentity::machine)
        .await
        .map_err(map_err)?
        .map_err(map_err)?;
    let fp = id.device_fp();
    let mut myname = String::new();
    if let Some(store) = state.creds.as_ref() {
        for key in store.keys().await {
            let m = store
                .get(&key)
                .await
                .and_then(|c| c.myname)
                .map(|m| m.trim().to_string())
                .filter(|m| !m.is_empty());
            if let Some(m) = m {
                myname = m;
                break;
            }
        }
    }
    Ok(serde_json::json!({
        "device_fp": fp,
        "openssh_pubkey": id.openssh_pubkey(&format!("anet-{}", &fp[..12])),
        "myname": myname,
    }))
}

/// Edit the self-declared display name ("我的名称") across every saved credential; live
/// sessions keep their handshake name — the new value rides the next connect.
#[tauri::command]
pub(crate) async fn set_machine_myname(state: State<'_, AppState>, name: String) -> Result<usize, String> {
    let name = name.trim().to_string();
    if name.chars().count() > 64 {
        return Err("我的名称最长 64 字".into());
    }
    let Some(store) = state.creds.as_ref() else {
        return Err("凭据存储不可用".into());
    };
    let mut updated = 0usize;
    for key in store.keys().await {
        if let Some(mut cred) = store.get(&key).await {
            cred.myname = if name.is_empty() { None } else { Some(name.clone()) };
            store.save(&key, &cred).await;
            updated += 1;
        }
    }
    roles::audit("gui.machine_myname", serde_json::json!({"name": name, "updated": updated}));
    Ok(updated)
}

/// Per-credential 我的名称 edit (M4-T6 naming triplet; empty clears, ≤64 chars)
#[tauri::command]
pub(crate) async fn set_credential_myname(
    state: State<'_, AppState>,
    key: String,
    myname: Option<String>,
) -> Result<(), String> {
    let Some(store) = state.creds.as_ref() else {
        return Err("凭据存储不可用".into());
    };
    let Some(mut cred) = store.get(&key).await else {
        return Err("凭据不存在".into());
    };
    let myname = myname.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    if let Some(n) = &myname {
        if n.chars().count() > 64 {
            return Err("我的名称最长 64 字".into());
        }
    }
    cred.myname = myname;
    store.save(&key, &cred).await;
    roles::audit("gui.cred_myname", serde_json::json!({"key": key, "myname": cred.myname}));
    Ok(())
}
