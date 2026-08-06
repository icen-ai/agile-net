//! Unified issuance (签发) — the desktop fan-out page's 签发 tab is a native client of the
//! embedded server role's admin REST (loopback). The GUI owns the node data dir, so it mints a
//! short-lived full-scope admin JWT from the embedded DB's jwt_secret instead of asking the
//! user for the admin password; the token never leaves the Rust side.

use crate::{map_err, roles, AppState};
use tauri::State;

/// Cached loopback admin access token (JWT TTL is 15min; re-minted after 10min — every mint
/// also persists a refresh-token row, so per-request minting would bloat that table).
static ADMIN_JWT_CACHE: std::sync::Mutex<Option<(String, std::time::Instant)>> = std::sync::Mutex::new(None);

/// Mint (or reuse) a full-scope admin access token for the embedded node.
fn embedded_admin_jwt() -> Result<String, String> {
    {
        let cache = ADMIN_JWT_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((tok, at)) = cache.as_ref() {
            if at.elapsed() < std::time::Duration::from_secs(600) {
                return Ok(tok.clone());
            }
        }
    }
    let db = roles::open_embedded_db()?;
    let jwt = agile_net_node::auth::jwt::JwtService::load_or_create(db).map_err(map_err)?;
    let tok = jwt
        .issue("desktop-gui", "desktop-gui", "admin")
        .map_err(map_err)?
        .access_token;
    let mut cache = ADMIN_JWT_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *cache = Some((tok.clone(), std::time::Instant::now()));
    Ok(tok)
}

/// Loopback admin REST call against the running embedded node; unwraps the {code, data} /
/// {code, message} envelope (the message is already localized by the server).
async fn embedded_admin_rest(
    state: &State<'_, AppState>,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let addr = {
        let slot = state.server.lock().await;
        slot.as_ref().map(|s| s.api_addr())
    }
    .ok_or("服务端角色未运行，请先在「监听」页签开启扇出监听")?;
    let token = embedded_admin_jwt()?;
    // loopback admin call: never let environment proxy variables hijack it
    let client = reqwest::Client::builder().no_proxy().build().map_err(map_err)?;
    let mut req = client
        .request(method, format!("http://{addr}{path}"))
        .bearer_auth(token);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.map_err(map_err)?;
    let v: serde_json::Value = resp.json().await.map_err(map_err)?;
    if v.get("code").and_then(|c| c.as_u64()) == Some(0) {
        Ok(v.get("data").cloned().unwrap_or(serde_json::Value::Null))
    } else {
        Err(v
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("请求失败")
            .to_string())
    }
}

/// Issued delegated token list (entry/concurrency/mode/E2E badges + per-upstream reg states).
#[tauri::command]
pub(crate) async fn list_delegated_tokens(state: State<'_, AppState>) -> Result<Vec<serde_json::Value>, String> {
    let data = embedded_admin_rest(&state, reqwest::Method::GET, "/api/v1/admin/delegation/tokens", None).await?;
    Ok(data
        .get("items")
        .and_then(|i| i.as_array())
        .cloned()
        .unwrap_or_default())
}

/// Issue a delegated token (request body forwarded verbatim — validation lives server-side;
/// the response carries the one-time plaintext + share_url).
#[tauri::command]
pub(crate) async fn issue_delegated_token(
    state: State<'_, AppState>,
    request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let label = request
        .get("label")
        .and_then(|l| l.as_str())
        .unwrap_or("")
        .to_string();
    let data = embedded_admin_rest(&state, reqwest::Method::POST, "/api/v1/admin/delegation/tokens", Some(request)).await?;
    // Never audit the plaintext/share_url — label only
    roles::audit("gui.delegation_issue", serde_json::json!({"label": label}));
    Ok(data)
}

/// Revoke a delegated token (registration frames go to every online upstream of the set).
#[tauri::command]
pub(crate) async fn revoke_delegated_token(state: State<'_, AppState>, id: String) -> Result<(), String> {
    embedded_admin_rest(
        &state,
        reqwest::Method::DELETE,
        &format!("/api/v1/admin/delegation/tokens/{id}"),
        None,
    )
    .await?;
    roles::audit("gui.delegation_revoke", serde_json::json!({"id": id}));
    Ok(())
}
