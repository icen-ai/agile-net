//! Multi-node engine: connection lifecycle, route merging, background tasks, and local proxy inbound.
//!
//! Delegated credentials are the only connection mode: the engine dials relay entries directly
//! (no API roundtrip), fails over across the disaster set, and — with an entrust word — seals
//! every Open into an E2E envelope.

use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::tunnel::client_tunnel::ClientTunnel;
use agile_net_core::tunnel::opener::{BoxedChannel, ChannelOpener};
use agile_net_core::tunnel::tls::TlsConfigBuilder;

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

use crate::custom_rules::{CustomRules, apply_custom_rules};
use crate::hosts::HostsManager;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeStatus {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    /// Authenticated but gated: the device awaits issuer certification (node.md M3-T2/M4-T3)
    PendingApproval,
    /// Terminal rejection (device revoked / token revoked / session takeover): no auto-retry,
    /// the reason + one-time notice sit in the notification center
    Blocked,
}

/// Delegated connect parameters (the only connection mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectParams {
    /// Primary relay entry (host:port)
    pub addr: String,
    /// Delegated token label (the `d:` mark stripped)
    pub label: String,
    /// Delegated token plaintext (pure data-plane key; also the E2E key material)
    pub token: String,
    /// Skip TLS certificate verification (dev/debug only)
    #[serde(default)]
    pub insecure: bool,
    /// Fingerprint pinning: entry certificate SHA-256 (one-click distribution via connect_url, MITM-resistant)
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    /// Whether to auto-maintain system hosts (resolve rules)
    #[serde(default)]
    pub manage_hosts: bool,
    /// Disaster-set relay entries (failover order; empty = single entry `addr`)
    #[serde(default)]
    pub entries: Vec<String>,
    /// Per-entry relay cert fingerprints (parallel to `entries`; "" = TOFU)
    #[serde(default)]
    pub entry_fps: Vec<String>,
    /// Entrust word (en_xxx opaque routing ID): every Open is E2E-sealed when set; None = transparent tier
    #[serde(default)]
    pub en: Option<String>,
    /// Consumer mode (`split` = E2E rule delivery; None = dedicated 专线)
    #[serde(default)]
    pub emode: Option<String>,
    /// Delegated admin capability hint (ticket pull via the E2E config channel)
    #[serde(default)]
    pub eadmin: bool,
    /// Self-declared display name uploaded to the issuer ("我的名称"; decorative, the issuer's
    /// certification remark is the authoritative identity)
    #[serde(default)]
    pub myname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRule {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub value: String,
    #[serde(default)]
    pub resolve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node_id: String,
    pub addr: String,
    pub node_name: String,
    /// Delegated token label
    #[serde(default)]
    pub label: String,
    pub status: NodeStatus,
    pub rules: Vec<ClientRule>,
    /// This token was granted "manage the issuer" permission (eadmin; the bootstrap ticket
    /// arrives over the E2E config channel)
    #[serde(default)]
    pub admin_console: bool,
    /// Manageable upstreams (delegated admin transit discovery; full-scope tokens only)
    #[serde(default)]
    pub manageable: Vec<ManageableNode>,
    /// Tunnel traffic: upstream bytes (to the issuer; cumulative across failovers)
    #[serde(default)]
    pub bytes_up: u64,
    /// Tunnel traffic: downstream bytes (from the issuer; cumulative across failovers)
    #[serde(default)]
    pub bytes_down: u64,
    /// Failover: the entry currently dialed
    #[serde(default)]
    pub current_entry: String,
    /// Device certification state announced by the issuer ("active" / "pending")
    #[serde(default)]
    pub device_state: String,
    /// Terminal block reason (M2 reason_code) when status = Blocked
    #[serde(default)]
    pub block_reason: String,
    /// One-time admin notice attached to the block (immutable)
    #[serde(default)]
    pub block_message: String,
}

/// Manageable node (issuer / upstream chain discovery via the delegated config channel).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManageableNode {
    pub node_name: String,
    /// Admin API endpoint (host:port, reachable via tunnel)
    pub api: String,
    /// Management scope tier: ro / rules / full
    #[serde(default = "default_manageable_scope")]
    pub scope: String,
    /// Discovery path: deleg (delegated config channel)
    #[serde(default)]
    pub via: String,
}

fn default_manageable_scope() -> String {
    "full".into()
}

/// Runtime handle of a single node connection.
struct NodeHandle {
    state: NodeState,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    manage_hosts: bool,
    /// Failover opener (the proxy inbound opens channels through it)
    opener: Arc<DelegatedOpener>,
}

// ==================== Delegated connections ====================

/// Delegated connection opener: the proxy inbound opens channels through the currently live
/// failover tunnel; with an entrust word every Open is sealed into an E2E envelope addressed
/// by the word (the relay stays blind), otherwise Opens go out transparently.
struct DelegatedOpener {
    /// Currently live tunnel (swapped by the supervisor on failover; None while redialing)
    current: arc_swap::ArcSwapOption<ClientTunnel>,
    /// Delegated token plaintext (PSK; also the E2E key material)
    token: String,
    /// Entrust word (en_xxx opaque routing ID; None/empty = transparent tier)
    en: Option<String>,
    /// Cumulative traffic across failover tunnels (closed-session bytes are folded in)
    total_up: AtomicU64,
    total_down: AtomicU64,
    /// Current entry address (display; the supervisor updates it on every switch)
    current_entry: arc_swap::ArcSwap<String>,
    /// Named group matchers from the split-tier config channel (§7.2.1): empty until the
    /// issuer answers; the seal path fills per-target accurate group identities with it.
    group_map: arc_swap::ArcSwap<Vec<(String, std::sync::Arc<agile_net_core::proxy::router::ProxyRouter>)>>,
}

impl DelegatedOpener {
    fn new(token: String, en: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            current: arc_swap::ArcSwapOption::from_pointee(None),
            token,
            en: en.filter(|h| !h.trim().is_empty()),
            total_up: AtomicU64::new(0),
            total_down: AtomicU64::new(0),
            current_entry: arc_swap::ArcSwap::from_pointee(String::new()),
            group_map: arc_swap::ArcSwap::from_pointee(Vec::new()),
        })
    }

    /// Store the named group matchers of the latest config answer (split-tier pulls).
    fn set_group_map(&self, groups: Vec<(String, std::sync::Arc<agile_net_core::proxy::router::ProxyRouter>)>) {
        self.group_map.store(std::sync::Arc::new(groups));
    }

    /// Per-target group identities for the E2E seal (§7.2.1): the names whose vocabulary the
    /// target hits; empty = inherit the token's full set (dedicated tier / no config answer
    /// yet / no match — the issuer's union check stays the fallback).
    fn match_groups(&self, target_host: &str) -> Vec<String> {
        let map = self.group_map.load();
        if map.is_empty() {
            return Vec::new();
        }
        map.iter()
            .filter(|(_, r)| r.matches(target_host))
            .map(|(n, _)| n.clone())
            .collect()
    }

    fn is_connected(&self) -> bool {
        self.current
            .load()
            .as_ref()
            .map(|t| t.is_connected())
            .unwrap_or(false)
    }

    /// Cumulative traffic (closed sessions + the live one).
    async fn traffic(&self) -> (u64, u64) {
        let (mut up, mut down) = (
            self.total_up.load(Ordering::Relaxed),
            self.total_down.load(Ordering::Relaxed),
        );
        if let Some(t) = self.current.load_full() {
            let (u, d) = t.traffic().await;
            up += u;
            down += d;
        }
        (up, down)
    }

    /// Fold a closed tunnel's session counters into the cumulative totals (failover bookkeeping).
    async fn note_tunnel_closed(&self, tunnel: &ClientTunnel) {
        let (up, down) = tunnel.traffic().await;
        self.total_up.fetch_add(up, Ordering::Relaxed);
        self.total_down.fetch_add(down, Ordering::Relaxed);
    }

    async fn disconnect_now(&self) {
        if let Some(t) = self.current.load_full() {
            t.disconnect().await;
        }
    }
}

impl ChannelOpener for DelegatedOpener {
    fn open<'a>(
        &'a self,
        _node_id: &'a str,
        target_host: &'a str,
        target_port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = agile_net_core::error::Result<BoxedChannel>> + Send + 'a>> {
        Box::pin(async move {
            let tunnel = self
                .current
                .load_full()
                .ok_or_else(|| agile_net_core::error::Error::Other("delegated tunnel not connected".into()))?;
            match self.en.as_deref() {
                Some(word) => {
                    use agile_net_core::relay::e2e;
                    let key = e2e::derive_key(&self.token);
                    let hash = agile_net_core::util::sha256_hex(self.token.as_bytes());
                    // §7.2.1: seal the per-target group identities (matched against the
                    // config-channel vocabulary), not always the token's full set
                    let groups = self.match_groups(target_host);
                    let (env, cipher) =
                        e2e::seal_open(&key, e2e::kid_of(&hash), word, target_host, target_port, &groups);
                    let open = agile_net_core::proto::message::OpenChannel {
                        target_addr: word.to_string(),
                        target_port: 0,
                        groups: Vec::new(),
                        e2e: Some(env),
                        // the relay stamps the proven fp (M3-T2); consumers never self-assert it
                        device_fp: String::new(),
                    };
                    let payload = serde_json::to_vec(&open)
                        .map_err(|e| agile_net_core::error::Error::Protocol(e.to_string()))?;
                    let ch = tunnel.open_channel_raw(payload).await?;
                    Ok(Box::new(e2e::E2eStream::new(ch, cipher)) as BoxedChannel)
                }
                None => {
                    let ch = tunnel.open_channel(target_host, target_port).await?;
                    Ok(Box::new(ch) as BoxedChannel)
                }
            }
        })
    }
}

/// Delegated nodes route everything through the tunnel (the consumer's whole purpose is the
/// issuer's network): IPv4 catch-all plus the wildcard host suffix as the domain catch-all.
fn delegated_rules() -> Vec<ClientRule> {
    vec![
        ClientRule {
            id: String::new(),
            rule_type: "ip-cidr".into(),
            value: "0.0.0.0/0".into(),
            resolve: false,
        },
        ClientRule {
            id: String::new(),
            rule_type: "host".into(),
            value: "*".into(),
            resolve: false,
        },
    ]
}

/// Shared inner state (background tasks access it safely via Arc).
struct ClientInner {
    nodes: DashMap<String, NodeHandle>,
    /// Node connection order (route conflicts resolve first-connected-wins)
    node_order: std::sync::Mutex<Vec<String>>,
    shared_router: Arc<ArcSwap<ProxyRouter>>,
    proxy_port: ArcSwap<u16>,
    inbound_shutdown_tx: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>,
    hosts_manager: HostsManager,
    /// Proxy inbound stats (available after the proxy starts)
    proxy_stats: Arc<arc_swap::ArcSwapOption<agile_net_core::proxy::inbound::ProxyStats>>,
    /// User-paused rules (node_id → lowercase "type:value" set), skipped when rebuilding merged routes
    paused_rules: DashMap<String, std::collections::HashSet<String>>,
    /// Proxy fallback upstream (subscription kernel mixed inbound; None = direct for unmatched rules)
    proxy_fallback: arc_swap::ArcSwapOption<SocketAddr>,
    /// Custom rules (GUI bypass / hosts mapping; ArcSwap hot reload, baked into the router custom layer on rebuild)
    custom_rules: ArcSwap<CustomRules>,
    /// Delegated admin state pulled over the E2E config channel: node_id -> current
    /// bootstrap ticket + transit-management offers (full scope). Session-scoped, refetched per session.
    deleg_admin: DashMap<String, DelegAdminState>,
    /// Connection log (docs/todo/conn-log.md; engine-owned, injected into the proxy inbound on start)
    conn_log: Arc<agile_net_core::proxy::conlog::ConnLog>,
    /// Notification center (node.md M4-T1): session notices / rejections / approval states
    notify: arc_swap::ArcSwapAny<Arc<crate::notify::NotificationCenter>>,
}

/// Delegated admin state: the issuer's current bootstrap ticket + port, plus the
/// discovered upstream offers of a full-scope token (transit management).
#[derive(Debug, Clone)]
struct DelegAdminState {
    ticket: String,
    port: u16,
    upstreams: Vec<DelegUpstreamState>,
}

/// One discovered upstream offer passed through by the issuer (transit management).
#[derive(Debug, Clone)]
struct DelegUpstreamState {
    node_name: String,
    ticket: String,
    api_host: String,
    api_port: u16,
    scope: String,
}

impl ClientInner {
    /// Merge route rules from all connected nodes.
    ///
    /// Conflict semantics (deterministic): by connection order, **first-connected-wins** —
    /// identical CIDR/host patterns resolve to the first-connected node (standard longest-prefix match still wins over order).
    fn rebuild_merged_router(&self) {
        let mut new_router = ProxyRouter::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        let order = self
            .node_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for node_id in &order {
            let Some(item) = self.nodes.get(node_id) else {
                continue;
            };
            let state = &item.value().state;
            if state.status != NodeStatus::Connected {
                continue;
            }
            let paused = self.paused_rules.get(node_id);
            for rule in &state.rules {
                let key = format!("{}:{}", rule.rule_type, rule.value.to_lowercase());
                if paused.as_ref().is_some_and(|s| s.contains(&key)) {
                    continue; // Paused by user: does not occupy a conflict slot; another node's same-named rule may take over
                }
                if !seen.insert(key) {
                    continue; // Conflict: later-connected node yields to the first-connected one
                }
                let outbound = Outbound::tunnel(state.node_id.clone());
                match rule.rule_type.as_str() {
                    "ip-cidr" => {
                        let _ = new_router.add_cidr(&rule.value, outbound);
                    }
                    "host" => {
                        if rule.value.contains('*') {
                            new_router.add_host_suffix(&rule.value, outbound);
                        } else {
                            new_router.add_host_exact(&rule.value, outbound);
                        }
                    }
                    _ => {}
                }
            }
            // Control-plane implicit routes: manageable upstream API endpoints reachable via this node's tunnel
            // (Unified ACL: revoked permission loses the management path; conflict slots follow explicit rules, first-connected-wins)
            if state.admin_console {
                add_manageable_routes(
                    &mut new_router,
                    &state.node_id,
                    &state.manageable,
                    &mut seen,
                );
            }
        }
        // Fallback upstream (subscription kernel): traffic matching no rule is forwarded to the loopback upstream proxy
        if let Some(addr) = self.proxy_fallback.load().as_ref() {
            new_router.set_default(Outbound::forward(**addr));
        }
        // Custom rules layer (bypass / hosts mapping): evaluated before merged routes and fallback at local proxy inbound
        let custom = self.custom_rules.load();
        apply_custom_rules(
            &mut new_router,
            &custom,
            self.proxy_fallback.load().as_deref().copied(),
        );
        self.shared_router.store(Arc::new(new_router));
        self.apply_hosts();
    }

    /// Maintain system hosts (resolve rules of nodes connected with manage_hosts=true).
    fn apply_hosts(&self) {
        let mut hosts = Vec::new();
        let mut any_managed = false;
        for item in self.nodes.iter() {
            let handle = item.value();
            if !handle.manage_hosts {
                continue;
            }
            any_managed = true;
            let state = &handle.state;
            if state.status != NodeStatus::Connected {
                continue;
            }
            for rule in &state.rules {
                if rule.rule_type == "host" && rule.resolve && !rule.value.contains('*') {
                    hosts.push(rule.value.clone());
                }
            }
        }
        if !any_managed {
            return;
        }
        if let Err(e) = self.hosts_manager.apply(&hosts) {
            warn!(error = %e, "failed to update system hosts (need admin/root?)");
        }
    }
}

#[derive(Clone)]
pub struct AgileNetClient {
    inner: Arc<ClientInner>,
}

impl AgileNetClient {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ClientInner {
                nodes: DashMap::new(),
                node_order: std::sync::Mutex::new(Vec::new()),
                shared_router: Arc::new(ArcSwap::from_pointee(ProxyRouter::new())),
                proxy_port: ArcSwap::from_pointee(0),
                inbound_shutdown_tx: tokio::sync::Mutex::new(None),
                openers: Arc::new(DashMap::new()),
                deleg_admin: DashMap::new(),
                hosts_manager: HostsManager::new(),
                proxy_stats: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
                paused_rules: DashMap::new(),
                proxy_fallback: arc_swap::ArcSwapOption::from_pointee(None),
                custom_rules: ArcSwap::from_pointee(CustomRules::default()),
                conn_log: Arc::new(agile_net_core::proxy::conlog::ConnLog::new()),
                notify: arc_swap::ArcSwapAny::new(crate::notify::NotificationCenter::in_memory()),
            }),
        }
    }

    /// Swap in the persistent notification center (~/.anet/notifications.json) — the desktop
    /// GUI and the svc client role call this at startup; tests keep the in-memory default.
    pub fn with_persistent_notifications(self) -> Self {
        self.inner
            .notify
            .store(crate::notify::NotificationCenter::open_default());
        self
    }

    /// Notification center handle (inbox list / unread count / live subscription).
    pub fn notifications(&self) -> Arc<crate::notify::NotificationCenter> {
        self.inner.notify.load_full()
    }

    pub fn proxy_router(&self) -> Arc<ProxyRouter> {
        self.inner.shared_router.load_full()
    }

    /// Engine-owned connection log (docs/todo/conn-log.md; injected into the proxy inbound on start).
    pub fn conn_log(&self) -> Arc<agile_net_core::proxy::conlog::ConnLog> {
        self.inner.conn_log.clone()
    }

    /// Proxy inbound stats handle (Some while the local proxy runs). The GUI reads cumulative
    /// bytes/active counts here when the subscription kernel is off — mihomo only ever owned the
    /// subscription mechanism; rates and egress state must not go blind with it.
    pub fn proxy_stats(&self) -> Option<Arc<agile_net_core::proxy::inbound::ProxyStats>> {
        self.inner.proxy_stats.load_full()
    }

    /// Shared handle of the merged router (route re-publishing: injects the embedded node connector).
    pub fn shared_router_handle(&self) -> Arc<ArcSwap<ProxyRouter>> {
        self.inner.shared_router.clone()
    }

    /// Set the proxy fallback upstream (subscription kernel mixed inbound; None restores direct for unmatched traffic).
    pub fn set_proxy_fallback(&self, addr: Option<SocketAddr>) {
        self.inner.proxy_fallback.store(addr.map(Arc::new));
        self.inner.rebuild_merged_router();
    }

    /// Hot-reload custom rules (GUI bypass / hosts mapping; rebuilds merged routes immediately, no proxy restart needed).
    pub fn set_custom_rules(&self, rules: CustomRules) {
        self.inner.custom_rules.store(Arc::new(rules));
        self.inner.rebuild_merged_router();
    }

    /// Shared handle of the channel opener registry (route re-publishing: injects the embedded node connector).
    pub fn openers_handle(&self) -> Arc<DashMap<String, Arc<dyn ChannelOpener>>> {
        self.inner.openers.clone()
    }

    pub fn proxy_port(&self) -> u16 {
        **self.inner.proxy_port.load()
    }

    pub fn node_count(&self) -> usize {
        self.inner.nodes.len()
    }

    /// Connect a delegated credential — no API roundtrip at all. The engine dials the primary
    /// relay entry directly (fail-fast on a bad token/address), registers the failover opener,
    /// and the supervisor rotates through the disaster set on every drop (with an entrust word
    /// every Open is E2E-sealed by the opener).
    pub async fn connect(&self, params: ConnectParams) -> Result<NodeState> {
        let label = params.label.trim().to_string();
        if label.is_empty() || label.len() > 128 {
            return Err(anyhow!("invalid delegated label"));
        }
        let entries: Vec<String> = if params.entries.is_empty() {
            vec![params.addr.clone()]
        } else {
            params.entries.clone()
        };

        let account_id = format!("d:{label}");
        // dial the primary entry synchronously (fail fast on unreachable address / bad token)
        let first_fp = params
            .entry_fps
            .first()
            .filter(|s| !s.is_empty())
            .or(params.pinned_fingerprint.as_ref());
        let tunnel = connect_delegated_entry(&params, &entries[0], first_fp, &account_id).await?;

        let node_id = format!("{label}@delegated:{}", entries[0]);
        let opener = DelegatedOpener::new(params.token.clone(), params.en.clone());
        opener.current.store(Some(tunnel.clone()));
        opener.current_entry.store(Arc::new(entries[0].clone()));
        self.inner
            .openers
            .insert(node_id.clone(), opener.clone() as Arc<dyn ChannelOpener>);

        let state = NodeState {
            node_id: node_id.clone(),
            addr: params.addr.clone(),
            node_name: label.clone(),
            label: label.clone(),
            // M3-T2: a pending device authenticates but is gated until certified (M4-T3 display)
            status: if tunnel.device_state().as_deref() == Some("pending") {
                NodeStatus::PendingApproval
            } else {
                NodeStatus::Connected
            },
            rules: delegated_rules(),
            admin_console: false,
            manageable: Vec::new(),
            bytes_up: 0,
            bytes_down: 0,
            current_entry: entries[0].clone(),
            device_state: tunnel.device_state().unwrap_or_default(),
            block_reason: String::new(),
            block_message: String::new(),
        };
        if state.status == NodeStatus::PendingApproval {
            self.inner.notify.load().push(
                "approval",
                format!("等待 {label} 的管理员认证"),
                "设备已登记为待认证；认证通过前数据面保持暂停（可在签发端审批中心跟进）。".into(),
                agile_net_core::proto::message::reason::PENDING_APPROVAL,
                &node_id,
            );
        }

        let supervisor = spawn_delegated_supervisor(
            self.inner.clone(),
            node_id.clone(),
            params.clone(),
            entries,
            opener.clone(),
            tunnel.clone(),
            account_id,
        );

        let handle = NodeHandle {
            state: state.clone(),
            tasks: vec![supervisor],
            manage_hosts: params.manage_hosts,
            opener: opener.clone(),
        };
        self.inner.nodes.insert(node_id.clone(), handle);
        self.inner
            .node_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node_id.clone());
        self.inner.rebuild_merged_router();

        // split tier: pull the token's rule vocabulary over the E2E config channel and swap
        // routes from catch-all to selective (refetched after every failover)
        maybe_spawn_config_fetch(&self.inner, &node_id, &params, &opener);

        info!(node = %node_id, "delegated credential connected");
        Ok(state)
    }

    /// Disconnect a node: stop tasks, tear down the tunnel, remove routes and hosts.
    pub async fn disconnect(&self, node_id: &str) {
        if let Some((_, handle)) = self.inner.nodes.remove(node_id) {
            for t in &handle.tasks {
                t.abort();
            }
            handle.opener.disconnect_now().await;
            self.inner.openers.remove(node_id);
            self.inner.deleg_admin.remove(node_id);
            self.inner
                .node_order
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|id| id != node_id);
            self.inner.rebuild_merged_router();
            info!(node = %node_id, "node disconnected");
        }
    }

    pub async fn disconnect_all(&self) {
        let ids: Vec<String> = self.inner.nodes.iter().map(|r| r.key().clone()).collect();
        for id in ids {
            self.disconnect(&id).await;
        }
        self.inner.hosts_manager.cleanup();
    }

    pub async fn get_node(&self, node_id: &str) -> Option<NodeState> {
        self.inner.nodes.get(node_id).map(|r| r.state.clone())
    }

    pub async fn list_nodes(&self) -> Vec<NodeState> {
        // Fix status and take opener handles synchronously first, then read traffic async (avoid holding dashmap guards across await)
        let mut states = Vec::with_capacity(self.inner.nodes.len());
        let mut openers = Vec::with_capacity(self.inner.nodes.len());
        for mut r in self.inner.nodes.iter_mut() {
            // Correct the cached status from the live data-plane state:
            // on remote close / network loss the cached Connected is never rewritten (control-plane buttons toggle on it).
            // The supervisor owns the status; a live tunnel wins — but PendingApproval/Blocked
            // survive (a gated/blocked device can hold a live session that opens nothing).
            let live = if r.opener.is_connected() {
                match r.state.status {
                    NodeStatus::PendingApproval | NodeStatus::Blocked => r.state.status.clone(),
                    _ => NodeStatus::Connected,
                }
            } else {
                r.state.status.clone()
            };
            if r.state.status != live {
                r.state.status = live;
            }
            states.push(r.state.clone());
            openers.push(r.opener.clone());
        }
        for (state, opener) in states.iter_mut().zip(openers) {
            let (up, down) = opener.traffic().await;
            state.bytes_up = up;
            state.bytes_down = down;
        }
        states
    }

    pub fn node_status(&self, node_id: &str) -> NodeStatus {
        self.inner
            .nodes
            .get(node_id)
            .map(|r| {
                if r.opener.is_connected() {
                    match r.state.status {
                        NodeStatus::PendingApproval | NodeStatus::Blocked => r.state.status.clone(),
                        _ => NodeStatus::Connected,
                    }
                } else {
                    r.state.status.clone()
                }
            })
            .unwrap_or(NodeStatus::Disconnected)
    }

    pub fn set_node_status(&self, node_id: &str, status: NodeStatus) {
        if let Some(mut n) = self.inner.nodes.get_mut(node_id) {
            n.state.status = status;
        }
    }

    /// Rebuild the merged router (for external/test callers).
    pub fn rebuild_merged_router(&self) {
        self.inner.rebuild_merged_router();
    }

    /// Pause/resume one rule of a node (rule_key format "type:value"; rebuilds merged routes immediately).
    pub fn set_rule_paused(&self, node_id: &str, rule_key: &str, paused: bool) {
        if paused {
            self.inner
                .paused_rules
                .entry(node_id.to_string())
                .or_default()
                .insert(rule_key.to_string());
        } else if let Some(mut set) = self.inner.paused_rules.get_mut(node_id) {
            set.remove(rule_key);
        }
        self.inner.rebuild_merged_router();
    }

    /// List of currently paused rule keys of a node.
    pub fn get_paused_rules(&self, node_id: &str) -> Vec<String> {
        self.inner
            .paused_rules
            .get(node_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Restore the whole paused set of a node (frontend restores from local persistence on startup).
    pub fn set_paused_rules(&self, node_id: &str, keys: Vec<String>) {
        if keys.is_empty() {
            self.inner.paused_rules.remove(node_id);
        } else {
            self.inner
                .paused_rules
                .insert(node_id.to_string(), keys.into_iter().collect());
        }
        self.inner.rebuild_merged_router();
    }

    /// Start the local proxy inbound (127.0.0.1).
    pub async fn start_proxy(&self, port: u16) -> Result<()> {
        self.start_proxy_with_auth(port, None).await
    }

    /// Start the local proxy inbound (optional auth).
    pub async fn start_proxy_with_auth(
        &self,
        port: u16,
        auth: Option<(String, String)>,
    ) -> Result<()> {
        let listen_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        // The inbound shares the engine's opener registry (node up/down takes effect immediately)
        let mut inbound = ProxyInbound::new(listen_addr, self.inner.shared_router.clone())
            .with_openers_map(self.inner.openers.clone())
            .with_conn_log(self.inner.conn_log.clone());
        if let Some((u, p)) = auth {
            inbound = inbound.with_auth(u, p);
        }

        // Bind first to get the actual port (supports port=0), then hand it to inbound (eliminates startup race)
        let bound = tokio::net::TcpListener::bind(listen_addr).await?;
        let actual_port = bound.local_addr()?.port();
        self.inner.proxy_port.store(Arc::new(actual_port));

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        *self.inner.inbound_shutdown_tx.lock().await = Some(tx);

        let inbound = Arc::new(inbound);
        self.inner.proxy_stats.store(Some(inbound.stats()));
        tokio::spawn(async move {
            tokio::select! {
                _ = inbound.start_on(bound) => {},
                _ = rx => {},
            }
        });

        Ok(())
    }

    pub async fn stop_proxy(&self) {
        if let Some(tx) = self.inner.inbound_shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        self.inner.proxy_stats.store(None);
        self.inner.proxy_port.store(Arc::new(0));
    }

    /// Data plane channel opener of a node (for the console loopback forwarder).
    pub fn opener(&self, node_id: &str) -> Option<Arc<dyn ChannelOpener>> {
        self.inner.openers.get(node_id).map(|r| r.value().clone())
    }

    /// Delegated admin console: the issuer's current bootstrap ticket + API port of a
    /// delegated node, pulled over the E2E config channel (None = no admin capability).
    pub fn delegated_console_ticket(&self, node_id: &str) -> Option<(String, u16)> {
        self.inner
            .deleg_admin
            .get(node_id)
            .map(|s| (s.ticket.clone(), s.port))
    }

    /// Delegated transit management (full scope): a discovered upstream's current offer —
    /// (ticket, api_host, api_port, scope); the console dials it through the issuer's fan-out
    /// session via the reserved `upstream:<node_name>` target.
    pub fn delegated_upstream_ticket(
        &self,
        node_id: &str,
        upstream: &str,
    ) -> Option<(String, String, u16, String)> {
        let s = self.inner.deleg_admin.get(node_id)?;
        let u = s.upstreams.iter().find(|u| u.node_name == upstream)?;
        Some((u.ticket.clone(), u.api_host.clone(), u.api_port, u.scope.clone()))
    }
}

impl Default for AgileNetClient {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== helpers ====================

/// Merge manageable upstream API endpoints into the router (implicit tunnel routes).
///
/// IPs get /32 CIDRs, hostnames get exact hosts; slots follow conflict order (first-connected-wins).
fn add_manageable_routes(
    router: &mut ProxyRouter,
    node_id: &str,
    manageable: &[ManageableNode],
    seen: &mut std::collections::HashSet<String>,
) {
    for m in manageable {
        let Some(host) = m
            .api
            .rsplit_once(':')
            .map(|(h, _)| h)
            .filter(|h| !h.is_empty())
        else {
            continue;
        };
        let outbound = Outbound::tunnel(node_id.to_string());
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let value = format!("{ip}/32");
            if seen.insert(format!("ip-cidr:{}", value.to_lowercase())) {
                let _ = router.add_cidr(&value, outbound);
            }
        } else if seen.insert(format!("host:{}", host.to_lowercase())) {
            router.add_host_exact(host, outbound);
        }
    }
}

async fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    let direct = format!("{host}:{port}");
    if let Ok(a) = direct.parse::<SocketAddr>() {
        return Ok(a);
    }
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(&direct).await?.collect();
    // IPv4 preferred (avoids connect failures on dual-stack hosts where IPv6 is unreachable)
    resolved
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| resolved.first())
        .copied()
        .ok_or_else(|| anyhow!("cannot resolve relay entry: {direct}"))
}

// ==================== Delegated failover ====================

/// Failover supervisor of a delegated connection: watches the live tunnel; on a drop it folds
/// the session traffic into the cumulative counters, clears the opener slot, and redials the
/// next entry of the disaster set (per-entry fingerprint pinning, exponential backoff + jitter,
/// same cadence as tunnels). The task is simply aborted on disconnect.
fn spawn_delegated_supervisor(
    inner: Arc<ClientInner>,
    node_id: String,
    params: ConnectParams,
    entries: Vec<String>,
    opener: Arc<DelegatedOpener>,
    first: Arc<ClientTunnel>,
    account_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut idx = 0usize;
        let mut attempt: u32 = 0;
        let mut live: Option<Arc<ClientTunnel>> = Some(first);
        loop {
            // wait for the live tunnel to die
            if let Some(t) = &live {
                while t.is_connected() {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                opener.note_tunnel_closed(t).await;
                if let Some(cur) = opener.current.load_full()
                    && Arc::ptr_eq(&cur, t)
                {
                    opener.current.store(None);
                }
                // M4: a session notice arriving with the close decides terminal vs transient
                let notice = t.take_notice();
                t.disconnect().await;
                live = None;
                idx = idx.saturating_add(1);
                if let Some((rc, msg)) = notice {
                    if is_terminal_reason(&rc) {
                        block_node(&inner, &node_id, &rc, &msg);
                        return; // terminal: no auto-retry — the inbox carries the full notice
                    }
                    set_delegated_status(&inner, &node_id, NodeStatus::Reconnecting, None);
                } else {
                    set_delegated_status(&inner, &node_id, NodeStatus::Reconnecting, None);
                }
            }

            let entry = entries[idx % entries.len()].clone();
            let fp = params
                .entry_fps
                .get(idx % entries.len())
                .filter(|s| !s.is_empty())
                .or(params.pinned_fingerprint.as_ref());
            match connect_delegated_entry(&params, &entry, fp, &account_id).await {
                Ok(t) => {
                    attempt = 0;
                    opener.current.store(Some(t.clone()));
                    opener.current_entry.store(Arc::new(entry.clone()));
                    // pending certification rides every reconnect (gate state may have changed)
                    let ds = t.device_state().unwrap_or_default();
                    let pending = ds == "pending";
                    if let Some(mut n) = inner.nodes.get_mut(&node_id) {
                        n.state.device_state = ds;
                        n.state.status = if pending {
                            NodeStatus::PendingApproval
                        } else {
                            NodeStatus::Connected
                        };
                        n.state.current_entry = entry.clone();
                    }
                    info!(node = %node_id, entry = %entry, pending, "delegated entry connected");
                    live = Some(t);
                    // split tier: refetch the rule vocabulary on the fresh session
                    maybe_spawn_config_fetch(&inner, &node_id, &params, &opener);
                }
                Err(e) => {
                    // structured auth rejection: terminal reasons stop the loop (M4-T2)
                    if let Some(rej) = &e.reject
                        && is_terminal_reason(&rej.reason_code)
                    {
                        block_node(&inner, &node_id, &rej.reason_code, &rej.message);
                        return;
                    }
                    debug!(node = %node_id, entry = %entry, error = %e.err, "delegated entry connect failed");
                    idx = idx.saturating_add(1);
                    attempt = attempt.saturating_add(1);
                    set_delegated_status(&inner, &node_id, NodeStatus::Reconnecting, None);
                    // exponential backoff 1s -> 2s -> ... -> 60s cap, full jitter
                    let backoff_ms = (1000u64 << attempt.min(6)).min(60_000);
                    let jitter = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_millis() as u64)
                        % backoff_ms;
                    tokio::time::sleep(std::time::Duration::from_millis(jitter.max(500))).await;
                }
            }
        }
    })
}

/// Terminal session/auth reasons (M4): no auto-retry — the reason + one-time notice go to the
/// inbox and the node rests in Blocked until the user acts (re-import, contact the admin).
fn is_terminal_reason(rc: &str) -> bool {
    use agile_net_core::proto::message::reason as r;
    matches!(
        rc,
        r::REVOKED_BY_ADMIN
            | r::DEVICE_REVOKED
            | r::DEVICE_REPLACED
            | r::TOKEN_EXPIRED
            | r::KICKED
            | r::SESSION_TAKEOVER
            | r::BAD_CREDENTIALS
            | r::DEVICE_PROOF_INVALID
    )
}

/// Terminal block: push the notice into the inbox and park the node in Blocked (reason visible).
fn block_node(inner: &ClientInner, node_id: &str, rc: &str, msg: &str) {
    if let Some(mut n) = inner.nodes.get_mut(node_id) {
        n.state.status = NodeStatus::Blocked;
        n.state.block_reason = rc.to_string();
        n.state.block_message = msg.to_string();
    }
    let label = node_id.split('@').next().unwrap_or(node_id).to_string();
    inner.notify.load().push(
        "session",
        format!("{label}：{rc}"),
        if msg.is_empty() { rc.to_string() } else { msg.to_string() },
        rc,
        node_id,
    );
    info!(node = %node_id, reason = %rc, "node blocked (terminal session notice)");
}

fn set_delegated_status(
    inner: &ClientInner,
    node_id: &str,
    status: NodeStatus,
    entry: Option<&str>,
) {
    if let Some(mut n) = inner.nodes.get_mut(node_id) {
        n.state.status = status;
        if let Some(entry) = entry {
            n.state.current_entry = entry.to_string();
        }
    }
}

/// Delegated config channel: when the credential has an entrust word and either the split
/// tier (`emode=split`) or the admin hint (`eadmin=1`), pull the issuer's config answer over
/// the reserved E2E target — split swaps routes from catch-all to the token's rule vocabulary,
/// admin stashes the bootstrap ticket + transit-management offers.
/// Detached short task; any failure keeps the catch-all set (dedicated-tier behavior).
fn maybe_spawn_config_fetch(
    inner: &Arc<ClientInner>,
    node_id: &str,
    params: &ConnectParams,
    opener: &Arc<DelegatedOpener>,
) {
    let split = params.emode.as_deref() == Some("split");
    if params.en.is_none() || (!split && !params.eadmin) {
        return;
    }
    let inner = inner.clone();
    let node_id = node_id.to_string();
    let opener = opener.clone();
    tokio::spawn(async move {
        let cfg = match fetch_deleg_config(&opener).await {
            Ok(c) => c,
            Err(e) => {
                warn!(node = %node_id, error = %e, "delegated config fetch failed — keeping catch-all routes");
                return;
            }
        };
        // named group matchers (§7.2.1): the seal path fills per-target identities with them
        opener.set_group_map(cfg.groups);
        // certification state overlay (M3-T2): a relay-entry pending device learns it here
        // (the config channel is the only issuer-reachable path for a gated consumer)
        if !cfg.device_state.is_empty()
            && let Some(mut h) = inner.nodes.get_mut(&node_id)
        {
            let was_pending = h.state.device_state == "pending";
            h.state.device_state = cfg.device_state.clone();
            let now_pending = cfg.device_state == "pending";
            if now_pending {
                h.state.status = NodeStatus::PendingApproval;
            } else if h.state.status == NodeStatus::PendingApproval {
                h.state.status = NodeStatus::Connected;
            }
            if now_pending && !was_pending {
                let label = h.state.label.clone();
                drop(h);
                inner.notify.load().push(
                    "approval",
                    format!("等待 {label} 的管理员认证"),
                    "设备已登记为待认证；认证通过前数据面保持暂停。".into(),
                    agile_net_core::proto::message::reason::PENDING_APPROVAL,
                    &node_id,
                );
            }
        }
        if split {
            if cfg.rules.is_empty() {
                warn!(node = %node_id, "split-tier config empty — keeping catch-all routes");
            } else {
                let n = cfg.rules.len();
                if let Some(mut h) = inner.nodes.get_mut(&node_id) {
                    h.state.rules = cfg.rules.clone();
                }
                inner.rebuild_merged_router();
                info!(node = %node_id, count = n, "split-tier rules applied");
            }
        }
        if let Some(admin) = cfg.admin {
            let upstreams: Vec<DelegUpstreamState> = cfg
                .upstreams
                .iter()
                .map(|u| DelegUpstreamState {
                    node_name: u.node_name.clone(),
                    ticket: u.ticket.clone(),
                    api_host: u.api_host.clone(),
                    api_port: u.api_port,
                    scope: u.scope.clone(),
                })
                .collect();
            inner.deleg_admin.insert(
                node_id.clone(),
                DelegAdminState {
                    ticket: admin.ticket,
                    port: admin.port,
                    upstreams: upstreams.clone(),
                },
            );
            if let Some(mut h) = inner.nodes.get_mut(&node_id) {
                h.state.admin_console = true;
                h.state.manageable = upstreams
                    .iter()
                    .map(|u| ManageableNode {
                        node_name: u.node_name.clone(),
                        api: format!("{}:{}", u.api_host, u.api_port),
                        scope: u.scope.clone(),
                        via: "deleg".into(),
                    })
                    .collect();
            }
            info!(node = %node_id, upstreams = upstreams.len(), "delegated admin capability pulled");
        }
    });
}

/// Wire shape of the issuer's config answer (rules arrive as plain strings).
#[derive(serde::Deserialize)]
struct DelegConfigWire {
    #[serde(default)]
    rules: Vec<String>,
    #[serde(default)]
    groups: Vec<agile_net_core::relay::DelegationGroupEntry>,
    admin: Option<agile_net_core::relay::DelegationAdmin>,
    #[serde(default)]
    upstreams: Vec<agile_net_core::relay::DelegationUpstream>,
    /// Certification state overlay (node.md M3-T2 relay-entry pending channel)
    #[serde(default)]
    device_state: String,
}

/// Parsed config answer with rules mapped to client rules.
struct DelegConfig {
    rules: Vec<ClientRule>,
    /// Named group breakdown (§7.2.1): per-group compiled matcher for per-target sealing
    groups: Vec<(String, std::sync::Arc<agile_net_core::proxy::router::ProxyRouter>)>,
    admin: Option<agile_net_core::relay::DelegationAdmin>,
    upstreams: Vec<agile_net_core::relay::DelegationUpstream>,
    /// "active" / "pending" / "denied" (empty = feature off)
    device_state: String,
}

/// One config-channel roundtrip: open the reserved target (the opener seals it like any E2E
/// Open), read the issuer's JSON answer to EOF.
async fn fetch_deleg_config(opener: &Arc<DelegatedOpener>) -> Result<DelegConfig> {
    let fut = async {
        let mut ch = opener
            .open("", agile_net_core::relay::e2e::DELEGATION_CONFIG_TARGET, 0)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut ch, &mut buf)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        let wire: DelegConfigWire = serde_json::from_slice(&buf)?;
        Ok(DelegConfig {
            rules: wire
                .rules
                .iter()
                .map(|value| ClientRule {
                    id: String::new(),
                    rule_type: if value.contains('/') { "ip-cidr" } else { "host" }.into(),
                    value: value.clone(),
                    resolve: false,
                })
                .collect(),
            groups: wire
                .groups
                .iter()
                .map(|g| (g.name.clone(), agile_net_core::relay::build_acl_router(&g.rules)))
                .collect(),
            admin: wire.admin,
            upstreams: wire.upstreams,
            device_state: wire.device_state,
        })
    };
    match tokio::time::timeout(std::time::Duration::from_secs(8), fut).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("config fetch timed out")),
    }
}

/// Dial one disaster-set entry (per-entry fingerprint pinning; TOFU for unpinned entries).
/// Entry connect failure: the supervisor reads `reject` (structured AuthFail) to decide
/// terminal-vs-transient retry behavior (node.md M4-T2/T3).
struct EntryFail {
    err: anyhow::Error,
    reject: Option<agile_net_core::proto::message::FailReason>,
}

impl From<anyhow::Error> for EntryFail {
    fn from(err: anyhow::Error) -> Self {
        Self { err, reject: None }
    }
}

impl From<agile_net_core::error::Error> for EntryFail {
    fn from(err: agile_net_core::error::Error) -> Self {
        Self {
            err: anyhow::anyhow!(err.to_string()),
            reject: None,
        }
    }
}

impl From<EntryFail> for anyhow::Error {
    fn from(e: EntryFail) -> Self {
        e.err
    }
}

async fn connect_delegated_entry(
    params: &ConnectParams,
    entry: &str,
    fp: Option<&String>,
    account_id: &str,
) -> std::result::Result<Arc<ClientTunnel>, EntryFail> {
    let addr = resolve_host_port(entry).await.map_err(EntryFail::from)?;
    let mut tls = TlsConfigBuilder::new();
    tls = match fp.filter(|s| !s.is_empty()) {
        Some(fp) => tls.pinned_fingerprint(fp.clone()),
        None if params.insecure => tls.allow_self_signed(true),
        None => tls,
    };
    let tunnel = ClientTunnel::with_tls_builder(addr, account_id, params.token.clone(), tls)
        .map_err(EntryFail::from)?
        .with_device(machine_device())
        .with_my_name(params.myname.clone().unwrap_or_default());
    let tunnel = Arc::new(tunnel);
    if let Err(e) = tunnel.connect().await {
        return Err(EntryFail {
            reject: tunnel.take_reject(),
            err: e.into(),
        });
    }
    Ok(tunnel)
}

/// Machine device identity (`~/.anet/device.key`, load-or-create), one per process; falls back
/// to an ephemeral identity when the data dir is unwritable (readonly home etc.).
fn machine_device() -> Arc<agile_net_core::device::DeviceIdentity> {
    static INSTANCE: std::sync::OnceLock<Arc<agile_net_core::device::DeviceIdentity>> =
        std::sync::OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            Arc::new(
                agile_net_core::device::DeviceIdentity::machine().unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "machine device identity unavailable, using ephemeral");
                    agile_net_core::device::DeviceIdentity::ephemeral()
                }),
            )
        })
        .clone()
}

/// Resolve a `host:port` entry into a SocketAddr (IPv4 preferred; IPv6 literals bracketed).
async fn resolve_host_port(entry: &str) -> Result<SocketAddr> {
    let entry = entry.trim();
    if let Ok(a) = entry.parse::<SocketAddr>() {
        return Ok(a);
    }
    let (host, port) = entry
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("entry missing port: {entry}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("bad entry port: {entry}"))?;
    resolve_addr(host, port).await
}

// ==================== unit tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom_rules::CustomBypassRule;

    fn m(node_name: &str, api: &str) -> ManageableNode {
        ManageableNode {
            node_name: node_name.into(),
            api: api.into(),
            scope: "rules".into(),
            via: "deleg".into(),
        }
    }

    #[test]
    fn manageable_routes_ip_and_host() {
        let mut router = ProxyRouter::new();
        let mut seen = std::collections::HashSet::new();
        let list = vec![
            m("root", "172.28.0.10:59090"),
            m("ops", "ops.internal:59090"),
        ];
        add_manageable_routes(&mut router, "n1@x:1", &list, &mut seen);

        // IP endpoint → /32 CIDR hit
        assert!(matches!(
            router.route_target("172.28.0.10:59090"),
            Outbound::Tunnel { node_id } if node_id == "n1@x:1"
        ));
        // Hostname endpoint → exact host hit
        assert!(matches!(
            router.route_target("ops.internal:59090"),
            Outbound::Tunnel { node_id } if node_id == "n1@x:1"
        ));
        // Other ports of the same host also hit (host-based routing)
        assert!(matches!(
            router.route_target("ops.internal:443"),
            Outbound::Tunnel { .. }
        ));
        // Unrelated targets unaffected (default direct)
        assert!(matches!(
            router.route_target("other.net:80"),
            Outbound::Direct
        ));
    }

    #[test]
    fn manageable_routes_respect_first_wins() {
        let mut router = ProxyRouter::new();
        let mut seen = std::collections::HashSet::new();
        // Explicit rule occupying the slot first (host:ops.internal belongs to another node)
        seen.insert("host:ops.internal".to_string());
        router.add_host_exact("ops.internal", Outbound::tunnel("n0@a:1"));

        let list = vec![m("ops", "ops.internal:59090")];
        add_manageable_routes(&mut router, "n1@x:1", &list, &mut seen);
        // Implicit routes must not preempt an occupied slot
        assert!(matches!(
            router.route_target("ops.internal:59090"),
            Outbound::Tunnel { node_id } if node_id == "n0@a:1"
        ));
    }

    // ==================== custom rules engine hot reload ====================

    fn bypass(pattern: &str, via_subscription: bool) -> CustomBypassRule {
        CustomBypassRule {
            pattern: pattern.into(),
            via_subscription,
            sort: 0,
        }
    }

    #[test]
    fn engine_set_custom_rules_hot_update() {
        let client = AgileNetClient::new();
        let fallback: SocketAddr = "127.0.0.1:57891".parse().unwrap();
        client.set_proxy_fallback(Some(fallback));
        client.set_custom_rules(CustomRules {
            bypass: vec![bypass("*.corp.internal", true)],
            hosts: vec![("git.corp.internal".into(), "10.9.9.9".into())],
        });
        let router = client.proxy_router();
        assert!(matches!(
            router.custom_bypass_match("app.corp.internal"),
            Some(Outbound::Forward { addr }) if *addr == fallback
        ));
        assert_eq!(
            router.map_host("git.corp.internal"),
            Some("10.9.9.9".parse().unwrap())
        );
        // Clearing restores the defaults (hot-reload semantics)
        client.set_custom_rules(CustomRules::default());
        let router = client.proxy_router();
        assert!(router.custom_bypass_match("app.corp.internal").is_none());
        assert_eq!(router.map_host("git.corp.internal"), None);
    }

    #[test]
    fn custom_rules_do_not_alter_merged_routes() {
        // The custom layer stays out of route_target / route_count / rule_values:
        // fan-in connectors and route re-publishing keep the existing behavior
        let client = AgileNetClient::new();
        client.set_custom_rules(CustomRules {
            bypass: vec![bypass("*.corp.internal", false)],
            hosts: vec![("git.corp.internal".into(), "10.9.9.9".into())],
        });
        let router = client.proxy_router();
        assert_eq!(router.route_count(), 0);
        assert!(router.rule_values().is_empty());
        assert!(matches!(
            router.route_target("app.corp.internal:443"),
            Outbound::Direct
        ));
    }

    #[test]
    fn delegated_opener_match_groups_per_target() {
        let opener = DelegatedOpener::new("psk_x".into(), Some("en_abc".into()));
        // no config answer yet -> inherit-all (empty)
        assert!(opener.match_groups("10.1.2.3").is_empty());

        opener.set_group_map(vec![
            (
                "dev".to_string(),
                agile_net_core::relay::build_acl_router(&["10.1.0.0/16".to_string()]),
            ),
            (
                "ops".to_string(),
                agile_net_core::relay::build_acl_router(&["10.2.0.0/16".to_string(), "ops.internal".to_string()]),
            ),
        ]);
        // per-target identities: only the matching group is sealed
        assert_eq!(opener.match_groups("10.1.2.3"), vec!["dev".to_string()]);
        assert_eq!(opener.match_groups("ops.internal"), vec!["ops".to_string()]);
        // no match -> empty (the issuer's union check stays the fallback)
        assert!(opener.match_groups("8.8.8.8").is_empty());
    }
}
