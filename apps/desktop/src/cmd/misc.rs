//! Split out of lib.rs: misc — external links / uninstall / console channels / fan-out connection management / event center (pure move, zero logic change).
//! report_client_proxy is shared by the proxy and roles domains; by convention it lives here (call sites unchanged via crate-root re-export).

use crate::{map_err, roles, subscription, sysproxy, AppState};
use serde::Serialize;
use std::sync::Arc;
use tauri::State;

/// Open an external link with the system default browser (http/https only).
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

/// Desktop admin SPA static assets (embedded via include_str!, no Node build chain).
/// Every asset index.html references must appear here — a missing entry 404s the web remote panel
/// (the `spa_assets_cover_index_references` test guards this list against index.html drift).
pub(crate) fn spa_assets() -> agile_net_client::api::SpaAssets {
    agile_net_client::api::SpaAssets {
        index: include_str!("../../ui/index.html"),
        files: vec![
            ("app.js", include_str!("../../ui/app.js")),
            ("app-core.js", include_str!("../../ui/app-core.js")),
            ("app-views.js", include_str!("../../ui/app-views.js")),
            ("app-subscription.js", include_str!("../../ui/app-subscription.js")),
            ("app-hero.js", include_str!("../../ui/app-hero.js")),
            ("app-logs.js", include_str!("../../ui/app-logs.js")),
            ("app-settings.js", include_str!("../../ui/app-settings.js")),
            ("agent.js", include_str!("../../ui/agent.js")),
            ("icons.js", include_str!("../../ui/icons.js")),
            ("agchart.js", include_str!("../../ui/agchart.js")),
            ("agutil.js", include_str!("../../ui/agutil.js")),
            ("agtbl.js", include_str!("../../ui/agtbl.js")),
            ("aglink.js", include_str!("../../ui/aglink.js")),
            ("aganet.js", include_str!("../../ui/aganet.js")),
            ("agimport.js", include_str!("../../ui/agimport.js")),
            ("agi18n.js", include_str!("../../ui/agi18n.js")),
            ("aglang.js", include_str!("../../ui/aglang.js")),
            ("lang-switcher.js", include_str!("../../ui/lang-switcher.js")),
            ("lang/desktop-html.js", include_str!("../../ui/lang/desktop-html.js")),
            ("lang/desktop-views.js", include_str!("../../ui/lang/desktop-views.js")),
            ("lang/desktop-sub.js", include_str!("../../ui/lang/desktop-sub.js")),
            ("lang/desktop-core.js", include_str!("../../ui/lang/desktop-core.js")),
            ("lang/desktop-trayfloat.js", include_str!("../../ui/lang/desktop-trayfloat.js")),
            ("lang/desktop-agent.js", include_str!("../../ui/lang/desktop-agent.js")),
            ("style.css", include_str!("../../ui/style.css")),
            ("tokens.css", include_str!("../../ui/tokens.css")),
            ("components.css", include_str!("../../ui/components.css")),
        ],
    }
}

/// Theme query fragment (accepts light/dark only; lets the console SPA match the main window theme)
pub(crate) fn theme_query(theme: &Option<String>) -> String {
    match theme.as_deref() {
        Some("dark") => "?theme=dark".to_string(),
        Some("light") => "?theme=light".to_string(),
        _ => String::new(),
    }
}

/// Admin console URL, loaded in the main window's embedded iframe (no more child windows).
/// - no args → embedded node (local server role, SPA login page)
/// - node_id → remote endpoint via the client tunnel (bootstrap with admin ticket; #boot stays out of logs and history)
/// - node_id + upstream → manageable upstream (discovered via handshake v2)
/// URL always carries embed=1 (SPA hides its own sidebar and title bar; navigation is driven by the main window via postMessage).
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
            // Local embedded console: auto-login with a freshly minted bootstrap ticket instead of
            // the password form. The GUI process is the trust anchor (it already holds the DB), and
            // the unguessable per-open ticket keeps this safe — a blind "loopback = trusted" rule
            // would let ANY local page/script drive the admin API (port scan → full control).
            // Direct browser access without the ticket still lands on the login form, unchanged.
            match roles::open_embedded_db().and_then(|db| {
                db.create_admin_ticket(
                    "relay",
                    "local:embedded@gui",
                    "full",
                    agile_net_node::relay_auth::RELAY_TICKET_MAX_USES,
                    agile_net_node::relay_auth::RELAY_TICKET_TTL_SECS,
                )
                .map_err(|e| e.to_string())
            }) {
                Ok(ticket) => {
                    roles::audit(
                        "admin.console_access",
                        serde_json::json!({"target": "embedded", "path": "本机内嵌节点", "identity": "local 票据（免登录）"}),
                    );
                    Ok(format!("http://{addr}/{embed}#boot={ticket}"))
                }
                Err(e) => {
                    tracing::warn!(error = %e, "embedded console ticket mint failed — falling back to the login form");
                    Ok(format!("http://{addr}/{embed}"))
                }
            }
        }
        (Some(node_id), None) => {
            // Delegated admin console: every node is delegated now — the ticket is pulled over
            // the E2E config channel; the console bridges to the issuer's loopback API via the
            // reserved admin target. Re-pull first so the ticket is freshly minted (the cached
            // ticket's 1h TTL counts from the session's config pull and may be stale on a
            // long-lived session); a failed refresh falls back to the cached ticket.
            let _ = state.client.refresh_delegation_config(&node_id).await;
            let (ticket, _) = state
                .client
                .delegated_console_ticket(&node_id)
                .ok_or("该委托凭据未授予管理权限（或配置尚未拉取完成）")?;
            let opener = state.client.opener(&node_id).ok_or("节点未连接")?;
            let fwd_key = format!("{node_id}|deleg-admin");
            let local_port = ensure_console_forwarder(
                &state,
                &fwd_key,
                opener,
                agile_net_core::relay::e2e::DELEGATION_ADMIN_TARGET,
                0,
            )
            .await?;
            roles::audit(
                "admin.console_access",
                serde_json::json!({"target": node_id, "path": "本机→委托 E2E 通道→签发端", "identity": "deleg 票据"}),
            );
            Ok(format!(
                "http://127.0.0.1:{local_port}/{embed}#boot={ticket}"
            ))
        }
        (Some(node_id), Some(upstream)) => {
            // Delegated transit management (full scope): the upstream's control
            // endpoint is dialed through the issuer's fan-out session (reserved upstream: target).
            // Re-pull the config channel first so the offer tickets are freshly minted (1h TTL
            // from the session's pull; falls back to the cached offer on refresh failure).
            let _ = state.client.refresh_delegation_config(&node_id).await;
            let (ticket, _, _, scope) = state
                .client
                .delegated_upstream_ticket(&node_id, &upstream)
                .ok_or("上游未被发现或未授予穿透管理")?;
            let opener = state.client.opener(&node_id).ok_or("节点未连接")?;
            let fwd_key = format!("{node_id}|deleg|{upstream}");
            let target = format!(
                "{}{}",
                agile_net_core::relay::e2e::DELEGATION_UPSTREAM_PREFIX,
                upstream
            );
            let local_port = ensure_console_forwarder(&state, &fwd_key, opener, &target, 0).await?;
            roles::audit(
                "admin.console_access",
                serde_json::json!({
                    "target": upstream,
                    "path": format!("本机→委托 E2E 通道→{node_id}→relay"),
                    "identity": format!("relay 票据（scope={scope}）"),
                }),
            );
            Ok(format!(
                "http://127.0.0.1:{local_port}/{embed}#boot={ticket}"
            ))
        }
        (None, Some(upstream)) => {
            // Manage a fan-out upstream through the embedded server role (handshake v2 offer):
            // ticket + control endpoint from the manageable registry, channels dialed by the connector
            let (offer, cm) = {
                let slot = state.server.lock().await;
                let s = slot.as_ref().ok_or("服务端角色未运行")?;
                let offer = s
                    .runtime()
                    .manageable
                    .get(&upstream)
                    .map(|o| o.clone())
                    .ok_or("上游管理面未暴露（对端未开启控制面或扇出离线）")?;
                (offer, s.connector_manager())
            };
            let api_host = offer.api_host.clone().unwrap_or_else(|| "127.0.0.1".into());
            let opener: std::sync::Arc<dyn agile_net_core::tunnel::opener::ChannelOpener> =
                std::sync::Arc::new(ServerUpstreamOpener {
                    cm,
                    upstream: upstream.clone(),
                });
            let fwd_key = format!("local|{upstream}");
            let local_port =
                ensure_console_forwarder(&state, &fwd_key, opener, &api_host, offer.api_port).await?;
            roles::audit(
                "admin.console_access",
                serde_json::json!({
                    "target": upstream,
                    "path": "本机→服务端扇出→relay",
                    "identity": format!("relay 票据（scope={}）", offer.scope),
                }),
            );
            Ok(format!(
                "http://127.0.0.1:{local_port}/{embed}#boot={}",
                offer.ticket
            ))
        }
    }
}

// ==================== Console channels (manage this node) ====================

/// Fan-out upstreams discovered by the embedded server role (handshake v2; sanitized: no tickets).
#[tauri::command]
pub(crate) async fn server_manageable(
    state: State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let slot = state.server.lock().await;
    let Some(s) = slot.as_ref() else {
        return Ok(Vec::new());
    };
    Ok(s
        .runtime()
        .manageable
        .iter()
        .map(|item| {
            let o = item.value();
            serde_json::json!({
                "node_name": o.node_name,
                "api": format!("{}:{}", o.api_host.as_deref().unwrap_or("?"), o.api_port),
                "scope": o.scope,
            })
        })
        .collect())
}

/// Fan-out upstream opener (handshake v2 manageability): channels are dialed through the
/// embedded server's connector whose control offer names the upstream (manage this relay
/// through the local server role's fan-out session).
struct ServerUpstreamOpener {
    cm: std::sync::Arc<agile_net_node::service::connectors::ConnectorManager>,
    upstream: String,
}

impl agile_net_core::tunnel::opener::ChannelOpener for ServerUpstreamOpener {
    fn open<'a>(
        &'a self,
        _node_id: &'a str,
        target_host: &'a str,
        target_port: u16,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = agile_net_core::error::Result<agile_net_core::tunnel::opener::BoxedChannel>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let ch = self
                .cm
                .open_manageable_stream(&self.upstream, target_host, target_port)
                .await
                .ok_or_else(|| {
                    agile_net_core::error::Error::Other(
                        "上游管理面未暴露或扇出离线".into(),
                    )
                })?;
            Ok(Box::new(ch) as agile_net_core::tunnel::opener::BoxedChannel)
        })
    }
}

/// Console loopback forwarder: local loopback port → opener channel → target API.
/// Deduped by key (node_id / node_id|upstream / local|upstream); the caller cleans up and rebuilds after reconnect.
pub(crate) async fn ensure_console_forwarder(
    state: &State<'_, AppState>,
    key: &str,
    opener: std::sync::Arc<dyn agile_net_core::tunnel::opener::ChannelOpener>,
    target_host: &str,
    target_port: u16,
) -> Result<u16, String> {
    let mut map = state.consoles.lock().await;
    if let Some(p) = map.get(key) {
        return Ok(*p);
    }
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

// ==================== Fan-out connection management (DB is the single source of truth; hot-apply via ConnectorManager at runtime, no restart) ====================

/// Fan-out list view (token redacted to prefix only, never echoed; editing requires re-entry or leaving it blank to keep).
#[derive(Debug, Clone, Serialize)]
pub struct ServerConnectorView {
    pub id: String,
    pub name: String,
    /// Self-declared name uploaded to the peer (empty = node_id; edit form echoes it)
    pub my_name: String,
    pub upstream_addr: String,
    pub token_prefix: String,
    pub sni_hostname: String,
    pub insecure: bool,
    /// Cert fingerprint pinning (SHA-256 hex; empty = unused; editable in the GUI, echo is safe — it's a public hash)
    pub pinned_fingerprint: String,
    /// Re-advertised routes (stored comma-separated; the edit form echoes them one per line)
    pub advertise: String,
    /// Effective advertise set (manual ∪ pushed-group rules — what the upstream route table
    /// will actually carry; delegation E2E hints are derived from this set)
    pub effective_advertise: Vec<String>,
    /// Restricting group (None = unrestricted, allow everything)
    pub group_id: Option<String>,
    /// Resolved ACL group set (naming sovereignty: name + adoption lineage; empty = unrestricted)
    pub groups: Vec<agile_net_node::db::models::GroupRef>,
    /// Upstream's self-declared node name of the live session (empty = offline/unannounced)
    pub peer_node: String,
    /// Policy upload (federation P1): comma-separated local group IDs pushed upstream at auth (empty = no upload)
    pub push_groups: String,
    pub enabled: bool,
    pub remark: String,
    /// Live state (connected/connecting/reconnecting/disconnected; always disconnected while the embedded node is not running)
    pub state: String,
}

/// Group dropdown option (for the fan-out form)
#[derive(Debug, Clone, Serialize)]
pub struct GroupOption {
    pub id: String,
    pub name: String,
    /// E2E groups only attach to delegated tokens — shown disabled in ACL pickers
    pub e2e_required: bool,
    /// Adoption lineage (empty = plain local group; the picker renders a source badge)
    pub adopted_node: String,
}

/// Groups of the local embedded node (the "group" dropdown in the fan-out form; empty = unrestricted).
#[tauri::command]
pub(crate) async fn list_embedded_groups() -> Result<Vec<GroupOption>, String> {
    let db = roles::open_embedded_db()?;
    let (groups, _) = db.list_groups(1, 1000, None, None).map_err(map_err)?;
    Ok(groups
        .into_iter()
        .map(|g| GroupOption { id: g.id, name: g.name, e2e_required: g.e2e_required, adopted_node: g.adopted_node })
        .collect())
}

/// Hot-apply a single fan-out change to the running embedded node (tear down the old, then bring up the new; skipped when not running — startup assembles from DB).
pub(crate) async fn hot_upsert_connector(state: &State<'_, AppState>, id: &str, name: &str) {
    // Grab the ConnectorManager handle and release the lock immediately — never hold it across await (upsert does DNS resolution)
    let manager = state.server.lock().await.as_ref().map(|s| s.connector_manager());
    if let Some(m) = manager {
        if let Err(e) = m.upsert_from_db(id).await {
            tracing::error!(connector = %name, error = %e, "connector hot-upsert failed");
        }
    }
}

/// Validate the restricting group set (when Some): comma-separated multi-group sets (union
/// ACL); each member must exist and must not be E2E-enforced (those hang on delegated tokens
/// only) so the frontend gets a readable error (DB foreign-key errors are not).
pub(crate) fn validate_group(db: &agile_net_node::db::Database, group_id: Option<&str>) -> Result<(), String> {
    if let Some(csv) = group_id {
        for gid in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match db.get_group(gid).map_err(map_err)? {
                None => return Err(format!("权限组不存在：{gid}")),
                Some(g) if g.e2e_required => {
                    return Err(format!("端到端加密组「{}」仅可用于签发委托，不可挂扇出收敛", g.name));
                }
                Some(_) => {}
            }
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
            let peer_node = slot
                .as_ref()
                .and_then(|s| s.connector_manager().peer_node_of(&v.id))
                .unwrap_or_default();
            ServerConnectorView {
                id: v.id.clone(),
                name: v.name,
                my_name: v.my_name,
                upstream_addr: v.upstream_addr,
                token_prefix: v.token_prefix,
                sni_hostname: v.sni_hostname,
                insecure: v.insecure,
                pinned_fingerprint: v.pinned_fingerprint,
                advertise: v.advertise,
                effective_advertise: db
                    .get_connector(&v.id)
                    .ok()
                    .flatten()
                    .map(|rec| agile_net_node::service::connectors::effective_advertise_of(&db, &rec))
                    .unwrap_or_default(),
                group_id: v.group_id,
                groups: v.groups,
                peer_node,
                push_groups: v.push_groups,
                enabled: v.enabled,
                remark: v.remark,
                state: state_str.into(),
            }
        })
        .collect())
}

/// Fan-out form (shared parameters of the add/update commands).
/// Note: a tauri command's flat parameters are the frontend invoke contract (camelCase per-arg mapping);
/// a struct cannot be passed as a single argument (tauri does not support serde flatten),
/// so this is internal-only — command boundaries keep flat signatures and waive the too-many-args lint.
struct ConnectorForm {
    upstream_addr: String,
    token: String,
    sni_hostname: String,
    insecure: bool,
    pinned_fingerprint: String,
    group_id: Option<String>,
    /// Policy upload (federation P1): local group IDs pushed upstream at auth; add: None = no upload; update: None = keep
    push_groups: Option<Vec<String>>,
    name: Option<String>,
    /// Self-declared name uploaded to the peer in AuthRequest.my_name (M4-T6; empty = node_id)
    my_name: Option<String>,
    advertise: Option<String>,
    remark: Option<String>,
}

/// Validate pushed group IDs and serialize (comma-joined; empty = no upload).
fn normalize_push_groups(db: &agile_net_node::db::Database, ids: &[String]) -> Result<String, String> {
    if ids.len() > 32 {
        return Err("上送权限组过多（最多 32 个）".into());
    }
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for gid in ids {
        if seen.insert(gid.clone()) {
            validate_group(db, Some(gid))?;
            out.push(gid.clone());
        }
    }
    Ok(out.join(","))
}

/// Fingerprint format: empty (unused) or 64 hex chars (SHA-256; normalized to lowercase).
fn normalize_fingerprint(fp: &str) -> Result<String, String> {
    let fp = fp.trim().to_lowercase();
    if fp.is_empty() {
        return Ok(fp);
    }
    if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("证书指纹须为 64 位十六进制（SHA-256）".into());
    }
    Ok(fp)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // flat parameters = frontend invoke contract, see ConnectorForm
pub(crate) async fn add_server_connector(
    state: State<'_, AppState>,
    upstream_addr: String,
    token: String,
    sni_hostname: String,
    insecure: bool,
    pinned_fingerprint: Option<String>,
    group_id: Option<String>,
    push_groups: Option<Vec<String>>,
    name: Option<String>,
    my_name: Option<String>,
    advertise: Option<String>,
    remark: Option<String>,
) -> Result<(), String> {
    let form = ConnectorForm {
        upstream_addr,
        token,
        sni_hostname,
        insecure,
        pinned_fingerprint: pinned_fingerprint.unwrap_or_default(),
        group_id,
        push_groups,
        name,
        my_name,
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
    // Name is optional: blank = use the target address (TOML import convention; connector.name has a unique constraint)
    let name = form
        .name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| addr.to_string());
    let advertise = form.advertise.unwrap_or_default().trim().to_string();
    let remark = form.remark.unwrap_or_default().trim().to_string();
    let my_name = form.my_name.unwrap_or_default().trim().to_string();
    if my_name.chars().count() > 64 {
        return Err("我的名称最长 64 字".into());
    }
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
            &my_name,
            addr,
            form.token.trim(),
            form.sni_hostname.trim(),
            form.insecure,
            "",
            "",
            &normalize_fingerprint(&form.pinned_fingerprint)?,
            &advertise,
            group_id.as_deref(),
            &remark,
        )
        .map_err(map_err)?;
    // Policy upload (federation P1): set before the hot assembly so the groups ride the first handshake
    if let Some(ids) = &form.push_groups {
        let pg = normalize_push_groups(&db, ids)?;
        if !pg.is_empty() {
            db.set_connector_push_groups(&rec.id, &pg).map_err(map_err)?;
        }
    }
    roles::audit("gui.fanout_change", serde_json::json!({"action": "add", "name": name}));
    hot_upsert_connector(state, &rec.id, &name).await;
    Ok(())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // flat parameters = frontend invoke contract, see ConnectorForm
pub(crate) async fn update_server_connector(
    state: State<'_, AppState>,
    id: String,
    upstream_addr: String,
    token: String,
    sni_hostname: String,
    insecure: bool,
    pinned_fingerprint: Option<String>,
    group_id: Option<String>,
    push_groups: Option<Vec<String>>,
    name: Option<String>,
    my_name: Option<String>,
    advertise: Option<String>,
    remark: Option<String>,
) -> Result<(), String> {
    let form = ConnectorForm {
        upstream_addr,
        token,
        sni_hostname,
        insecure,
        pinned_fingerprint: pinned_fingerprint.unwrap_or_default(),
        group_id,
        push_groups,
        name,
        my_name,
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
    // Name is optional: blank = use the target address (same convention as add)
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
    // Tri-state token / advertise / remark: blank token = keep the old value; advertise/remark absent (None) = keep,
    // the frontend always sends them (empty string = user cleared explicitly); cert paths are not edited in the GUI, kept as-is
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
    // my_name tri-state like remark: None = keep, Some = replace (empty = back to node_id)
    let my_name = form
        .my_name
        .map(|m| m.trim().to_string())
        .unwrap_or_else(|| old.my_name.clone());
    if my_name.chars().count() > 64 {
        return Err("我的名称最长 64 字".into());
    }
    db.update_connector(
        id,
        &name,
        &my_name,
        addr,
        token_reset.as_deref(),
        form.sni_hostname.trim(),
        form.insecure,
        &old.ca_cert_path,
        &old.pinned_cert_path,
        &normalize_fingerprint(&form.pinned_fingerprint)?,
        &advertise,
        group_id.as_deref(),
        &remark,
    )
    .map_err(map_err)?;
    // Policy upload (federation P1): None = keep current; Some (incl. empty) = replace
    if let Some(ids) = &form.push_groups {
        let pg = normalize_push_groups(&db, ids)?;
        db.set_connector_push_groups(id, &pg).map_err(map_err)?;
    }
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

// ==================== .anet credential files (federation P1 §2.8) ====================

/// .anet export: native save dialog (console bridge / fan-in export); false = user cancelled.
#[tauri::command]
pub(crate) async fn anet_save_file(app: tauri::AppHandle, suggested: String, content: String) -> Result<bool, String> {
    use tauri_plugin_dialog::DialogExt;
    let suggested = if suggested.trim().is_empty() {
        "credential.anet".to_string()
    } else {
        suggested
    };
    let Some(path) = app
        .dialog()
        .file()
        .set_file_name(&suggested)
        .add_filter("AgileNet 凭据", &["anet"])
        .blocking_save_file()
    else {
        return Ok(false);
    };
    let pb = path.as_path().ok_or("不支持的文件路径")?;
    std::fs::write(pb, content).map_err(|e| format!("写入文件失败：{e}"))?;
    roles::audit("gui.anet_export", serde_json::json!({"file": pb.file_name().unwrap_or_default().to_string_lossy()}));
    Ok(true)
}

/// .anet import: native open dialog; None = cancelled.
#[tauri::command]
pub(crate) async fn anet_open_file(app: tauri::AppHandle) -> Result<Option<serde_json::Value>, String> {
    use tauri_plugin_dialog::DialogExt;
    let Some(path) = app
        .dialog()
        .file()
        .add_filter("AgileNet 凭据", &["anet"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    let pb = path.as_path().ok_or("不支持的文件路径")?;
    let content = std::fs::read_to_string(pb).map_err(|e| format!("读取文件失败：{e}"))?;
    Ok(Some(serde_json::json!({
        "name": pb.file_name().unwrap_or_default().to_string_lossy(),
        "content": content,
    })))
}

/// File-association open (double-click / second-instance argv): read the .anet content for the import dialog.
#[tauri::command]
pub(crate) async fn read_text_file(path: String) -> Result<String, String> {
    if path.len() > 4096 {
        return Err("路径过长".into());
    }
    std::fs::read_to_string(&path).map_err(|e| format!("读取文件失败：{e}"))
}

/// QR import (universal import wizard): native image picker + rqrr decode to the link text; None = cancelled.
#[tauri::command]
pub(crate) async fn qr_pick_decode(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let Some(path) = app
        .dialog()
        .file()
        .add_filter("QR 图片", &["png", "jpg", "jpeg"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    let pb = path.as_path().ok_or("不支持的文件路径")?;
    let bytes = std::fs::read(pb).map_err(|e| format!("读取文件失败：{e}"))?;
    agile_net_node::qr::decode_qr_image(&bytes).map(Some)
}

/// Write the real client proxy state into the embedded node state slot (call after start/stop/mode switch/role shutdown;
/// the admin "local proxy" card reads it via node status; the mode comes from the GUI proxy settings).
/// Also broadcasts `ag-proxy` (every mutation path funnels through here): tray / float-ball / remote
/// toggles repaint the main window's power button + proxy card instantly instead of at the next poll.
pub(crate) async fn report_client_proxy(app: &tauri::AppHandle, state: &State<'_, AppState>) {
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
    use tauri::Emitter;
    let _ = app.emit("ag-proxy", port > 0);
}

// ==================== Uninstall ====================

/// Uninstall cleanup options (which local data to delete along with the uninstall)
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UninstallOptions {
    /// Saved nodes and credentials (credentials.json)
    pub credentials: bool,
    /// Server node data (embedded-node/: database and certificates)
    pub server_data: bool,
    /// Config and preferences (gui-settings.json / web-auth.json; theme and language are cleared from localStorage by the frontend)
    pub prefs: bool,
    /// Audit log (gui-audit.jsonl)
    pub audit: bool,
}

/// Uninstall the app: write audit → shut down to release file locks → clean the selected data → disable autostart → launch the system uninstaller and exit.
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

    // Stop embedded node / web remote access / subscription kernel / all tunnels (release SQLite and port usage)
    if let Some(s) = state.server.lock().await.take() {
        s.stop().await;
    }
    if let Some(h) = state.web_api.lock().await.take() {
        h.stop().await;
    }
    state.kernel.stop().await;
    state.client.disconnect_all().await;
    state.client.stop_proxy().await;

    // System proxy is managed (system-proxy preference / locked mode / TUN auto-management): restore it before uninstall
    {
        let r = state.roles.lock().await;
        if sysproxy::managed(&r) {
            drop(r);
            let _ = tokio::task::spawn_blocking(sysproxy::disengage).await;
        }
    }

    // Mandatory on uninstall: remove login autostart
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

/// Launch the system uninstaller (Windows NSIS: uninstall.exe in the install dir, with its own confirmation page;
/// by the time the user confirms, this process has exited, so the install dir can be deleted).
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

/// Non-Windows desktops have no system uninstaller: data is cleaned; ask the user to remove the app manually.
#[cfg(not(windows))]
pub(crate) fn launch_system_uninstaller() -> Result<(), String> {
    Err("数据已按所选清理；请将应用本体移入废纸篓/删除以完成卸载".into())
}

/// Event center: read whitelisted events backwards from the tail of gui-audit.jsonl (newest first; default 50, max 200).
/// Returns an empty Vec when the file does not exist.
#[tauri::command]
pub(crate) fn recent_events(limit: Option<u32>) -> Result<Vec<roles::GuiEvent>, String> {
    let n = limit.unwrap_or(50).clamp(1, 200) as usize;
    Ok(roles::recent_events(n))
}

#[cfg(test)]
mod tests {
    /// Every local .js/.css that index.html references must be served by the web remote panel —
    /// a missing entry is a 404 blank-panel storm (the agi18n/aglang/lang-shard incident).
    #[test]
    fn spa_assets_cover_index_references() {
        let assets = super::spa_assets();
        let served: std::collections::HashSet<&str> =
            assets.files.iter().map(|(p, _)| *p).collect();
        let html = assets.index;
        for attr in ["src=\"", "href=\""] {
            let mut rest = html;
            while let Some(i) = rest.find(attr) {
                let after = &rest[i + attr.len()..];
                let end = after.find('"').unwrap();
                let v = &after[..end];
                if (v.ends_with(".js") || v.ends_with(".css")) && !v.contains("://") {
                    assert!(served.contains(v), "index.html references {v} but spa_assets lacks it");
                }
                rest = &after[end..];
            }
        }
    }
}
