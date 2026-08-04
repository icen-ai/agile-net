//! Multi-node engine: connection lifecycle, route merging, background tasks, and local proxy inbound.

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

use crate::config_cache::{CachedNodeConfig, ConfigCache};
use crate::custom_rules::{CustomRules, apply_custom_rules};
use crate::hosts::HostsManager;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeStatus {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectParams {
    /// Node API address (host:port or http(s)://...)
    pub addr: String,
    pub username: String,
    pub password: String,
    /// Skip TLS certificate verification (dev/debug only)
    #[serde(default)]
    pub insecure: bool,
    /// Certificate pinning: node certificate PEM path (recommended in production)
    #[serde(default)]
    pub pinned_cert_path: Option<String>,
    /// Fingerprint pinning: node certificate SHA-256 (one-click distribution via connect_url, MITM-resistant)
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    /// Whether to auto-maintain system hosts (resolve rules)
    #[serde(default)]
    pub manage_hosts: bool,
    /// Federation P2: delegated credential — pure data-plane key; the engine dials the relay
    /// entries directly (no API login/config), fails over across the disaster set
    #[serde(default)]
    pub delegated: bool,
    /// Disaster-set relay entries (failover order; empty = single entry `addr`)
    #[serde(default)]
    pub entries: Vec<String>,
    /// Per-entry relay cert fingerprints (parallel to `entries`; "" = TOFU)
    #[serde(default)]
    pub entry_fps: Vec<String>,
    /// Federation P3: E2E routing hint (every Open sealed when set; empty/None = transparent)
    #[serde(default)]
    pub ehint: Option<String>,
    /// Federation P3 consumer mode (`split` = E2E rule delivery; None = dedicated 专线)
    #[serde(default)]
    pub emode: Option<String>,
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
    /// Login account (the endpoint list shows "endpoint name · username")
    #[serde(default)]
    pub username: String,
    pub status: NodeStatus,
    pub rules: Vec<ClientRule>,
    pub config_version: u64,
    /// This account was granted "manage this node" permission (admin connect URL)
    #[serde(default)]
    pub admin_console: bool,
    /// Manageable upstreams (handshake v2 auto-discovery; only issued to admin accounts)
    #[serde(default)]
    pub manageable: Vec<ManageableNode>,
    /// Tunnel traffic: upstream bytes (to the node; per-session counter, reset on reconnect, 0 when not connected)
    #[serde(default)]
    pub bytes_up: u64,
    /// Tunnel traffic: downstream bytes (from the node; per-session counter, reset on reconnect, 0 when not connected)
    #[serde(default)]
    pub bytes_down: u64,
    /// Federation P2: this node is a delegated credential (direct relay access, no API account)
    #[serde(default)]
    pub delegated: bool,
    /// Delegated failover: the entry currently dialed (display only; empty for regular nodes)
    #[serde(default)]
    pub current_entry: String,
}

/// Manageable node (local machine / connected node / upstream chain auto-discovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManageableNode {
    pub node_name: String,
    /// Admin API endpoint (host:port, reachable via tunnel)
    pub api: String,
    /// Management scope tier: ro / rules / full
    #[serde(default = "default_manageable_scope")]
    pub scope: String,
    /// Discovery path: relay (upstream chain)
    #[serde(default)]
    pub via: String,
}

fn default_manageable_scope() -> String {
    "full".into()
}

/// Runtime handle of a single node connection.
struct NodeHandle {
    state: NodeState,
    tunnel: Arc<ClientTunnel>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    manage_hosts: bool,
    /// Original connect params (for login retry after offline degradation)
    params: ConnectParams,
    /// Current access token (synced after config long-poll refresh; used for console ticket issuance)
    access_token: Arc<ArcSwap<String>>,
    /// Federation P2: delegated connection runtime (failover opener; None = regular API account)
    delegated: Option<Arc<DelegatedOpener>>,
}

// ==================== Delegated connections (federation P2/P3) ====================

/// Delegated connection opener (federation P2/P3): the proxy inbound opens channels through
/// the currently live failover tunnel; with an E2E hint every Open is sealed into an envelope
/// addressed by the hint (the relay stays blind), otherwise Opens go out transparently.
struct DelegatedOpener {
    /// Currently live tunnel (swapped by the supervisor on failover; None while redialing)
    current: arc_swap::ArcSwapOption<ClientTunnel>,
    /// Delegated token plaintext (PSK; also the E2E key material)
    token: String,
    /// E2E routing hint (None/empty = transparent tier)
    ehint: Option<String>,
    /// Cumulative traffic across failover tunnels (closed-session bytes are folded in)
    total_up: AtomicU64,
    total_down: AtomicU64,
    /// Current entry address (display; the supervisor updates it on every switch)
    current_entry: arc_swap::ArcSwap<String>,
}

impl DelegatedOpener {
    fn new(token: String, ehint: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            current: arc_swap::ArcSwapOption::from_pointee(None),
            token,
            ehint: ehint.filter(|h| !h.trim().is_empty()),
            total_up: AtomicU64::new(0),
            total_down: AtomicU64::new(0),
            current_entry: arc_swap::ArcSwap::from_pointee(String::new()),
        })
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
            match self.ehint.as_deref() {
                Some(hint) => {
                    use agile_net_core::relay::e2e;
                    let key = e2e::derive_key(&self.token);
                    let hash = agile_net_core::util::sha256_hex(self.token.as_bytes());
                    let (env, cipher) =
                        e2e::seal_open(&key, e2e::kid_of(&hash), hint, target_host, target_port, &[]);
                    let open = agile_net_core::proto::message::OpenChannel {
                        target_addr: hint.to_string(),
                        target_port: 0,
                        groups: Vec::new(),
                        e2e: Some(env),
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
    http_client: reqwest::Client,
    inbound_shutdown_tx: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>,
    hosts_manager: HostsManager,
    /// Proxy inbound stats (available after the proxy starts)
    proxy_stats: Arc<arc_swap::ArcSwapOption<agile_net_core::proxy::inbound::ProxyStats>>,
    /// Offline node config cache
    cache: Arc<ConfigCache>,
    /// User-paused rules (node_id → lowercase "type:value" set), skipped when rebuilding merged routes
    paused_rules: DashMap<String, std::collections::HashSet<String>>,
    /// Proxy fallback upstream (subscription kernel mixed inbound; None = direct for unmatched rules)
    proxy_fallback: arc_swap::ArcSwapOption<SocketAddr>,
    /// Custom rules (GUI bypass / hosts mapping; ArcSwap hot reload, baked into the router custom layer on rebuild)
    custom_rules: ArcSwap<CustomRules>,
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
                http_client: reqwest::Client::new(),
                inbound_shutdown_tx: tokio::sync::Mutex::new(None),
                openers: Arc::new(DashMap::new()),
                hosts_manager: HostsManager::new(),
                proxy_stats: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
                cache: Arc::new(
                    ConfigCache::new()
                        .unwrap_or_else(|_| ConfigCache::with_dir(std::env::temp_dir())),
                ),
                paused_rules: DashMap::new(),
                proxy_fallback: arc_swap::ArcSwapOption::from_pointee(None),
                custom_rules: ArcSwap::from_pointee(CustomRules::default()),
            }),
        }
    }

    pub fn proxy_router(&self) -> Arc<ProxyRouter> {
        self.inner.shared_router.load_full()
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

    /// Connect to a node: login → pull config → establish tunnel → merge routes → background maintenance tasks.
    pub async fn connect(&self, params: ConnectParams) -> Result<NodeState> {
        // Federation P2: delegated credentials skip the API entirely (direct relay failover)
        if params.delegated {
            return self.connect_delegated(params).await;
        }
        let base_url = api_base_url(&params.addr);

        // 1. Login (fall back to the offline cache when the network is unreachable)
        let resp = match self
            .inner
            .http_client
            .post(format!("{base_url}/api/v1/auth/login"))
            .json(&serde_json::json!({
                "username": params.username,
                "password": params.password,
            }))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Network error → offline cache degradation (keep stale rules while offline + background login retry)
                return self.connect_offline(params, e).await;
            }
        };
        if !resp.status().is_success() {
            return Err(anyhow!("login failed: HTTP {}", resp.status()));
        }
        let login_json: serde_json::Value = resp.json().await?;
        let data = &login_json["data"];
        let access_token = data["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("missing access_token"))?
            .to_string();
        let refresh_token = data["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("missing refresh_token"))?
            .to_string();
        let tunnel_token = data["tunnel_token"]
            .as_str()
            .ok_or_else(|| anyhow!("missing tunnel_token (not a client account?)"))?
            .to_string();

        // 2. Pull config
        let config = pull_config(&self.inner.http_client, &base_url, &access_token, 0).await?;
        let node_name = config["node_name"].as_str().unwrap_or("node").to_string();
        let tunnel_server = config["tunnel"]["server"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let tunnel_port = config["tunnel"]["port"].as_u64().unwrap_or(443) as u16;
        let version = config["version"].as_u64().unwrap_or(0);
        let admin_console = config["admin_console"].as_bool().unwrap_or(false);
        let manageable = parse_manageable(&config);
        let rules = parse_rules(&config);

        // 3. Establish the data plane tunnel
        let tunnel_addr: SocketAddr = resolve_addr(&tunnel_server, tunnel_port).await?;
        let tls_builder = build_tls(&params)?;
        let account_id = claims_sub(&access_token).unwrap_or_else(|| params.username.clone());
        let tunnel = Arc::new(ClientTunnel::with_tls_builder(
            tunnel_addr,
            account_id,
            tunnel_token.clone(),
            tls_builder,
        )?);
        tunnel.connect().await?;

        // Unique node key: node_name@addr
        let node_id = format!("{node_name}@{}", params.addr);

        // Register the channel opener
        self.inner
            .openers
            .insert(node_id.clone(), tunnel.clone() as Arc<dyn ChannelOpener>);

        let state = NodeState {
            node_id: node_id.clone(),
            addr: params.addr.clone(),
            node_name: node_name.clone(),
            username: params.username.clone(),
            status: NodeStatus::Connected,
            rules,
            config_version: version,
            admin_console,
            manageable,
            bytes_up: 0,
            bytes_down: 0,
            delegated: false,
            current_entry: String::new(),
        };

        // 4. Background tasks: tunnel auto-reconnect + heartbeat + config long-poll
        let access_shared = Arc::new(ArcSwap::from_pointee(access_token.clone()));
        let mut tasks = Vec::new();
        {
            let t = tunnel.clone();
            tasks.push(tokio::spawn(async move {
                t.run().await;
            }));
        }
        tasks.push(spawn_heartbeat(
            self.inner.http_client.clone(),
            self.inner.proxy_stats.clone(),
            node_id.clone(),
            base_url.clone(),
            access_token.clone(),
        ));
        tasks.push(spawn_config_watcher(
            self.inner.clone(),
            node_id.clone(),
            base_url.clone(),
            access_shared.clone(),
            refresh_token.clone(),
            version,
        ));

        // 5. Write the offline cache (used while offline)
        self.inner.cache.save(&CachedNodeConfig {
            addr: params.addr.clone(),
            username: params.username.clone(),
            node_name: node_name.clone(),
            rules: state.rules.clone(),
            config_version: version,
            tunnel_server,
            tunnel_port,
            tunnel_token: tunnel_token.clone(),
            refresh_token: refresh_token.clone(),
            insecure: params.insecure,
            pinned_fingerprint: params.pinned_fingerprint.clone(),
            updated_at: chrono_now(),
        });

        let handle = NodeHandle {
            state: state.clone(),
            tunnel,
            tasks,
            manage_hosts: params.manage_hosts,
            params: params.clone(),
            access_token: access_shared,
            delegated: None,
        };
        self.inner.nodes.insert(node_id.clone(), handle);
        self.inner
            .node_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node_id.clone());
        self.inner.rebuild_merged_router();

        info!(node = %node_id, admin_console, "node connected");
        Ok(state)
    }

    /// Offline degradation: when the network is unreachable, build the mesh from cached rules and retry login periodically in the background.
    async fn connect_offline(
        &self,
        params: ConnectParams,
        net_err: reqwest::Error,
    ) -> Result<NodeState> {
        let cached = self
            .inner
            .cache
            .load(&params.addr, &params.username)
            .ok_or_else(|| anyhow!("无法连接节点且无离线缓存: {net_err}"))?;

        warn!(
            addr = %params.addr,
            "节点不可达，启用离线缓存（{} 条规则，缓存于 {}）",
            cached.rules.len(),
            cached.updated_at
        );

        let node_id = format!("{}@{}", cached.node_name, params.addr);
        let tunnel_addr: SocketAddr =
            resolve_addr(&cached.tunnel_server, cached.tunnel_port).await?;
        let tls_builder = build_tls(&params)?;
        let account_id = cached.username.clone();
        let tunnel = Arc::new(ClientTunnel::with_tls_builder(
            tunnel_addr,
            account_id,
            cached.tunnel_token.clone(),
            tls_builder,
        )?);
        // Tunnel reconnect task (the token may have expired, but stays usable until the server rotates it)
        tunnel.connect().await.ok();

        self.inner
            .openers
            .insert(node_id.clone(), tunnel.clone() as Arc<dyn ChannelOpener>);

        let state = NodeState {
            node_id: node_id.clone(),
            addr: params.addr.clone(),
            node_name: cached.node_name.clone(),
            username: cached.username.clone(),
            status: NodeStatus::Reconnecting,
            rules: cached.rules.clone(),
            config_version: cached.config_version,
            admin_console: false,
            manageable: Vec::new(),
            bytes_up: 0,
            bytes_down: 0,
            delegated: false,
            current_entry: String::new(),
        };

        let mut tasks = Vec::new();
        {
            let t = tunnel.clone();
            tasks.push(tokio::spawn(async move {
                t.run().await;
            }));
        }
        // Background login retry: seamless upgrade once back online
        tasks.push(spawn_offline_retry(
            self.inner.clone(),
            node_id.clone(),
            params.clone(),
        ));

        let handle = NodeHandle {
            state: state.clone(),
            tunnel,
            tasks,
            manage_hosts: params.manage_hosts,
            params: params.clone(),
            access_token: Arc::new(ArcSwap::from_pointee(String::new())),
            delegated: None,
        };
        self.inner.nodes.insert(node_id.clone(), handle);
        self.inner
            .node_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node_id.clone());
        self.inner.rebuild_merged_router();

        Ok(state)
    }

    /// Federation P2: connect a delegated credential — no API roundtrip at all. The engine
    /// dials the primary relay entry directly (fail-fast on a bad token/address, same UX as a
    /// regular connect), registers the failover opener, and the supervisor rotates through the
    /// disaster set on every drop (P3: with an ehint every Open is E2E-sealed by the opener).
    async fn connect_delegated(&self, params: ConnectParams) -> Result<NodeState> {
        let label = params.username.trim_start_matches("d:").trim().to_string();
        if label.is_empty() || label.len() > 128 {
            return Err(anyhow!("invalid delegated label (expected the d:<label> account mark)"));
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
        let opener = DelegatedOpener::new(params.password.clone(), params.ehint.clone());
        opener.current.store(Some(tunnel.clone()));
        opener.current_entry.store(Arc::new(entries[0].clone()));
        self.inner
            .openers
            .insert(node_id.clone(), opener.clone() as Arc<dyn ChannelOpener>);

        let state = NodeState {
            node_id: node_id.clone(),
            addr: params.addr.clone(),
            node_name: label.clone(),
            username: params.username.clone(),
            status: NodeStatus::Connected,
            rules: delegated_rules(),
            config_version: 0,
            admin_console: false,
            manageable: Vec::new(),
            bytes_up: 0,
            bytes_down: 0,
            delegated: true,
            current_entry: entries[0].clone(),
        };

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
            tunnel,
            tasks: vec![supervisor],
            manage_hosts: params.manage_hosts,
            params: params.clone(),
            access_token: Arc::new(ArcSwap::from_pointee(String::new())),
            delegated: Some(opener.clone()),
        };
        self.inner.nodes.insert(node_id.clone(), handle);
        self.inner
            .node_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node_id.clone());
        self.inner.rebuild_merged_router();

        // split tier (federation P3): pull the token's rule vocabulary over the E2E config
        // channel and swap routes from catch-all to selective (refetched after every failover)
        maybe_spawn_split_fetch(&self.inner, &node_id, &params, &opener);

        info!(node = %node_id, "delegated credential connected");
        Ok(state)
    }

    /// Disconnect a node: stop tasks, tear down the tunnel, remove routes and hosts.
    pub async fn disconnect(&self, node_id: &str) {
        if let Some((_, handle)) = self.inner.nodes.remove(node_id) {
            for t in &handle.tasks {
                t.abort();
            }
            handle.tunnel.disconnect().await;
            if let Some(d) = &handle.delegated {
                d.disconnect_now().await;
            }
            self.inner.openers.remove(node_id);
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
        // Fix status and take tunnel handles synchronously first, then read traffic async (avoid holding dashmap guards across await)
        let mut states = Vec::with_capacity(self.inner.nodes.len());
        let mut tunnels = Vec::with_capacity(self.inner.nodes.len());
        let mut delegateds = Vec::with_capacity(self.inner.nodes.len());
        for mut r in self.inner.nodes.iter_mut() {
            // Correct the cached status from the live data-plane state:
            // on remote close / network loss the cached Connected is never rewritten (control-plane buttons toggle on it)
            let live = if let Some(d) = &r.delegated {
                // delegated connections: the supervisor owns the status; a live tunnel wins
                if d.is_connected() {
                    NodeStatus::Connected
                } else {
                    r.state.status.clone()
                }
            } else if r.tunnel.is_connected() {
                NodeStatus::Connected
            } else {
                match r.tunnel.state() {
                    agile_net_core::relay::ConnectionState::Reconnecting => {
                        NodeStatus::Reconnecting
                    }
                    agile_net_core::relay::ConnectionState::Connecting => NodeStatus::Connecting,
                    _ => NodeStatus::Disconnected,
                }
            };
            if r.state.status != live {
                r.state.status = live;
            }
            states.push(r.state.clone());
            tunnels.push(r.tunnel.clone());
            delegateds.push(r.delegated.clone());
        }
        for ((state, tunnel), delegated) in states.iter_mut().zip(tunnels).zip(delegateds) {
            let (up, down) = match delegated {
                Some(d) => d.traffic().await,
                None => tunnel.traffic().await,
            };
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
                if let Some(d) = &r.delegated {
                    return if d.is_connected() {
                        NodeStatus::Connected
                    } else {
                        r.state.status.clone()
                    };
                }
                if r.tunnel.is_connected() {
                    NodeStatus::Connected
                } else {
                    match r.tunnel.state() {
                        agile_net_core::relay::ConnectionState::Reconnecting => {
                            NodeStatus::Reconnecting
                        }
                        agile_net_core::relay::ConnectionState::Connecting => {
                            NodeStatus::Connecting
                        }
                        _ => NodeStatus::Disconnected,
                    }
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
            .with_openers_map(self.inner.openers.clone());
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

    /// Request a console ticket for a manageable upstream (exchanged with the relay token, scoped; current ticket from handshake v2 discovery).
    ///
    /// Returns (ticket, api_host, api_port, scope): the console reaches the upstream control plane via this node's tunnel.
    pub async fn upstream_console_ticket(
        &self,
        node_id: &str,
        upstream: &str,
    ) -> Result<(String, String, u16, String)> {
        let handle = self
            .inner
            .nodes
            .get(node_id)
            .ok_or_else(|| anyhow!("节点未连接: {node_id}"))?;
        if !handle.state.admin_console {
            return Err(anyhow!("该节点未授予管理权限"));
        }
        let base_url = api_base_url(&handle.params.addr);
        let token = handle.access_token.load().as_ref().clone();
        drop(handle);

        let resp = self
            .inner
            .http_client
            .post(format!("{base_url}/api/v1/client/console-ticket"))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "upstream": upstream }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "上游 console-ticket 签发失败: HTTP {}",
                resp.status()
            ));
        }
        let json: serde_json::Value = resp.json().await?;
        let data = &json["data"];
        let ticket = data["ticket"]
            .as_str()
            .ok_or_else(|| anyhow!("响应缺少 ticket"))?
            .to_string();
        let api = data["api"]
            .as_str()
            .ok_or_else(|| anyhow!("响应缺少 api"))?
            .to_string();
        let scope = data["scope"].as_str().unwrap_or("full").to_string();
        let (host, port) = match api.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse().map_err(|_| anyhow!("api 端点端口非法: {api}"))?,
            ),
            None => return Err(anyhow!("api 端点格式非法: {api}")),
        };
        Ok((ticket, host, port, scope))
    }

    /// Request a console bootstrap ticket (only for accounts granted "manage this node").
    ///
    /// Returns (ticket, api_port): the console window loads the node admin SPA via the loopback forwarder
    /// and exchanges #boot=ticket for an admin session; api_port is the node API port (tunnel peer loopback target).
    pub async fn console_ticket(&self, node_id: &str) -> Result<(String, u16)> {
        let handle = self
            .inner
            .nodes
            .get(node_id)
            .ok_or_else(|| anyhow!("节点未连接: {node_id}"))?;
        if !handle.state.admin_console {
            return Err(anyhow!("该节点未授予管理权限"));
        }
        let base_url = api_base_url(&handle.params.addr);
        let token = handle.access_token.load().as_ref().clone();
        let api_port = api_port_of(&handle.params.addr);
        drop(handle);

        let resp = self
            .inner
            .http_client
            .post(format!("{base_url}/api/v1/client/console-ticket"))
            .bearer_auth(&token)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("console-ticket 签发失败: HTTP {}", resp.status()));
        }
        let json: serde_json::Value = resp.json().await?;
        let ticket = json["data"]["ticket"]
            .as_str()
            .ok_or_else(|| anyhow!("console-ticket 响应缺少 ticket"))?
            .to_string();
        Ok((ticket, api_port))
    }
}

/// Extract the API port from a connect address (host:port or http(s)://host[:port], default 59090).
fn api_port_of(addr: &str) -> u16 {
    let stripped = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    match stripped.rsplit_once(':') {
        Some((_, p)) => p.parse().unwrap_or(59090),
        None => 59090,
    }
}

impl Default for AgileNetClient {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== background tasks ====================

async fn pull_config(
    http: &reqwest::Client,
    base_url: &str,
    access_token: &str,
    current_version: u64,
) -> Result<serde_json::Value> {
    let url = if current_version > 0 {
        format!("{base_url}/api/v1/client/config?version={current_version}")
    } else {
        format!("{base_url}/api/v1/client/config")
    };
    let resp = http.get(&url).bearer_auth(access_token).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("config pull failed: HTTP {}", resp.status()));
    }
    let json: serde_json::Value = resp.json().await?;
    Ok(json["data"].clone())
}

/// Login retry after offline degradation: seamless upgrade to a full connection once back online.
fn spawn_offline_retry(
    inner: Arc<ClientInner>,
    node_id: String,
    params: ConnectParams,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let jitter = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_millis()
                % 10000) as u64;
            tokio::time::sleep(
                std::time::Duration::from_secs(30) + std::time::Duration::from_millis(jitter),
            )
            .await;

            match offline_relogin_once(&inner, &node_id, &params).await {
                Ok(()) => {
                    info!(node = %node_id, "offline node reconnected, upgraded to full connection");
                    break;
                }
                Err(e) => {
                    debug!(node = %node_id, error = %e, "offline relogin attempt failed");
                }
            }
        }
    })
}

/// One full re-login while offline: on success, update tokens/rules/cache/status.
async fn offline_relogin_once(
    inner: &Arc<ClientInner>,
    node_id: &str,
    params: &ConnectParams,
) -> Result<()> {
    let base_url = api_base_url(&params.addr);
    let http = &inner.http_client;

    let resp = http
        .post(format!("{base_url}/api/v1/auth/login"))
        .json(&serde_json::json!({
            "username": params.username,
            "password": params.password,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("login failed: HTTP {}", resp.status()));
    }
    let login_json: serde_json::Value = resp.json().await?;
    let data = &login_json["data"];
    let access_token = data["access_token"]
        .as_str()
        .ok_or_else(|| anyhow!("no access_token"))?
        .to_string();
    let refresh_token = data["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let tunnel_token = data["tunnel_token"]
        .as_str()
        .ok_or_else(|| anyhow!("no tunnel_token"))?
        .to_string();

    let config = pull_config(http, &base_url, &access_token, 0).await?;
    let version = config["version"].as_u64().unwrap_or(0);
    let rules = parse_rules(&config);

    // Update the handle: token rotation + rules + status + cache
    let Some(mut handle) = inner.nodes.get_mut(node_id) else {
        return Err(anyhow!("node gone"));
    };
    handle.tunnel.update_token(tunnel_token.clone());
    handle.state.rules = rules.clone();
    handle.state.config_version = version;
    handle.state.status = NodeStatus::Connected;
    handle.state.admin_console = config["admin_console"].as_bool().unwrap_or(false);
    handle.access_token.store(Arc::new(access_token.clone()));
    let node_name = handle.state.node_name.clone();
    let (tunnel_server, tunnel_port) = (
        config["tunnel"]["server"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        config["tunnel"]["port"].as_u64().unwrap_or(443) as u16,
    );
    drop(handle);

    inner.cache.save(&CachedNodeConfig {
        addr: params.addr.clone(),
        username: params.username.clone(),
        node_name,
        rules,
        config_version: version,
        tunnel_server,
        tunnel_port,
        tunnel_token,
        refresh_token,
        insecure: params.insecure,
        pinned_fingerprint: params.pinned_fingerprint.clone(),
        updated_at: chrono_now(),
    });
    inner.rebuild_merged_router();
    Ok(())
}

fn spawn_heartbeat(
    http: reqwest::Client,
    stats_slot: Arc<arc_swap::ArcSwapOption<agile_net_core::proxy::inbound::ProxyStats>>,
    node_id: String,
    base_url: String,
    access_token: String,
) -> tokio::task::JoinHandle<()> {
    let started = std::time::Instant::now();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_tx: u64 = 0;
        let mut last_rx: u64 = 0;
        loop {
            interval.tick().await;

            // Real traffic stats (delta since the last report)
            let (delta_tx, delta_rx, active) = match stats_slot.load().as_ref() {
                Some(stats) => {
                    let tx = stats.bytes_up.load(std::sync::atomic::Ordering::Relaxed);
                    let rx = stats.bytes_down.load(std::sync::atomic::Ordering::Relaxed);
                    let active = stats
                        .active_connections
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let d_tx = tx.saturating_sub(last_tx);
                    let d_rx = rx.saturating_sub(last_rx);
                    last_tx = tx;
                    last_rx = rx;
                    (d_tx as i64, d_rx as i64, active as i64)
                }
                None => (0, 0, 0),
            };

            let body = serde_json::json!({
                "uptime": started.elapsed().as_secs(),
                "bytes_tx": delta_tx,
                "bytes_rx": delta_rx,
                "active_connections": active,
            });
            let resp = http
                .post(format!("{base_url}/api/v1/client/heartbeat"))
                .bearer_auth(&access_token)
                .json(&body)
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    if let Ok(json) = r.json::<serde_json::Value>().await
                        && json["data"]["force_disconnect"].as_bool() == Some(true)
                    {
                        info!(node = %node_id, "force disconnected by server");
                        break;
                    }
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    debug!(node = %node_id, "heartbeat unauthorized (token rotated by watcher)");
                }
                _ => {}
            }
        }
    })
}

fn spawn_config_watcher(
    inner: Arc<ClientInner>,
    node_id: String,
    base_url: String,
    access_shared: Arc<ArcSwap<String>>,
    refresh_token: String,
    initial_version: u64,
) -> tokio::task::JoinHandle<()> {
    let http = inner.http_client.clone();
    tokio::spawn(async move {
        let mut version = initial_version;
        let mut access = access_shared.load().as_ref().clone();
        let mut refresh = refresh_token;
        loop {
            // Long-poll for a new version
            let url = format!("{base_url}/api/v1/client/config?wait=true&version={version}");
            let resp = http.get(&url).bearer_auth(&access).send().await;

            let resp = match resp {
                Ok(r) => r,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
                continue;
            }
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                // Refresh the token
                let refresh_resp = http
                    .post(format!("{base_url}/api/v1/auth/refresh"))
                    .json(&serde_json::json!({ "refresh_token": refresh }))
                    .send()
                    .await;
                match refresh_resp {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(json) = r.json::<serde_json::Value>().await {
                            access = json["data"]["access_token"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string();
                            access_shared.store(Arc::new(access.clone()));
                            refresh = json["data"]["refresh_token"]
                                .as_str()
                                .unwrap_or(refresh.as_str())
                                .to_string();
                            // Server rotated tunnel_token → sync it to the tunnel for the next reconnect
                            if let Some(new_tun) = json["data"]["tunnel_token"].as_str()
                                && let Some(h) = inner.nodes.get(&node_id)
                            {
                                h.tunnel.update_token(new_tun.to_string());
                            }
                            // Refresh the refresh_token in the cache
                            if let Some(h) = inner.nodes.get(&node_id) {
                                let p = &h.params;
                                if let Some(mut cached) = inner.cache.load(&p.addr, &p.username) {
                                    cached.refresh_token = refresh.clone();
                                    cached.updated_at = chrono_now();
                                    inner.cache.save(&cached);
                                }
                            }
                        }
                    }
                    _ => {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                }
                continue;
            }
            if !resp.status().is_success() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let data = &json["data"];
                let new_version = data["version"].as_u64().unwrap_or(version);
                let rules = parse_rules(data);
                version = new_version;
                info!(node = %node_id, version, "config updated");

                if let Some(mut h) = inner.nodes.get_mut(&node_id) {
                    h.state.rules = rules;
                    h.state.config_version = version;
                    h.state.admin_console = data["admin_console"].as_bool().unwrap_or(false);
                    h.state.manageable = parse_manageable(data);
                }
                inner.rebuild_merged_router();
            }
        }
    })
}

// ==================== helpers ====================

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

fn api_base_url(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.trim_end_matches('/').to_string()
    } else {
        // Plain HTTP is the node API's factory default (built-in HTTPS requires node-side cert config);
        // warn explicitly on non-loopback plaintext; production should use HTTPS or cert pinning
        let host = addr.trim_end_matches('/');
        let is_loopback = host
            .split(':')
            .next()
            .map(|h| h == "127.0.0.1" || h == "localhost" || h == "::1")
            .unwrap_or(false);
        if !is_loopback {
            tracing::warn!(addr = %addr, "节点 API 使用明文 HTTP：生产环境请为节点配置内置 HTTPS，或使用证书固定");
        }
        format!("http://{host}")
    }
}

fn parse_rules(config: &serde_json::Value) -> Vec<ClientRule> {
    config["rules"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    Some(ClientRule {
                        id: r["id"].as_str().unwrap_or_default().to_string(),
                        rule_type: r["type"].as_str()?.to_string(),
                        value: r["value"].as_str()?.to_string(),
                        resolve: r["resolve"].as_bool().unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Merge manageable upstream API endpoints into the router (implicit tunnel routes).
///
/// Only handles upstream-chain (via=relay) endpoints; local management goes through the loopback forwarder and takes no route slot.
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

fn parse_manageable(config: &serde_json::Value) -> Vec<ManageableNode> {
    config["manageable"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    Some(ManageableNode {
                        node_name: m["node_name"].as_str()?.to_string(),
                        api: m["api"].as_str()?.to_string(),
                        scope: m["scope"].as_str().unwrap_or("full").to_string(),
                        via: m["via"].as_str().unwrap_or("relay").to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn build_tls(params: &ConnectParams) -> Result<TlsConfigBuilder> {
    let builder = TlsConfigBuilder::new();
    if let Some(fp) = &params.pinned_fingerprint {
        // Fingerprint pinning takes top priority (one-click distribution via connect_url, MITM-resistant)
        Ok(builder.pinned_fingerprint(fp.clone()))
    } else if let Some(pinned_path) = &params.pinned_cert_path {
        let data = std::fs::read(pinned_path)?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut data.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("parse pinned cert: {e}"))?;
        if certs.is_empty() {
            return Err(anyhow!("no certificates in pinned cert file"));
        }
        Ok(builder.pinned_certs(certs))
    } else if params.insecure {
        Ok(builder.allow_self_signed(true))
    } else {
        Ok(builder)
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
        .ok_or_else(|| anyhow!("cannot resolve tunnel server: {direct}"))
}

// ==================== Delegated failover (federation P2) ====================

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
                t.disconnect().await;
                live = None;
                idx = idx.saturating_add(1);
                set_delegated_status(&inner, &node_id, NodeStatus::Reconnecting, None);
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
                    set_delegated_status(&inner, &node_id, NodeStatus::Connected, Some(&entry));
                    info!(node = %node_id, entry = %entry, "delegated entry connected");
                    live = Some(t);
                    // split tier: refetch the rule vocabulary on the fresh session
                    maybe_spawn_split_fetch(&inner, &node_id, &params, &opener);
                }
                Err(e) => {
                    debug!(node = %node_id, entry = %entry, error = %e, "delegated entry connect failed");
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

/// Split-tier rule delivery (federation P3): when the credential carries `emode=split` and an
/// E2E hint, pull the token's effective rule vocabulary over the E2E config channel (reserved
/// target, answered by the issuer) and swap the node routes from catch-all to selective.
/// Detached short task; any failure keeps the catch-all set (dedicated-tier behavior).
fn maybe_spawn_split_fetch(
    inner: &Arc<ClientInner>,
    node_id: &str,
    params: &ConnectParams,
    opener: &Arc<DelegatedOpener>,
) {
    if params.emode.as_deref() != Some("split") || params.ehint.is_none() {
        return;
    }
    let inner = inner.clone();
    let node_id = node_id.to_string();
    let opener = opener.clone();
    tokio::spawn(async move {
        match fetch_split_rules(&opener).await {
            Ok(rules) if !rules.is_empty() => {
                let n = rules.len();
                if let Some(mut h) = inner.nodes.get_mut(&node_id) {
                    h.state.rules = rules;
                }
                inner.rebuild_merged_router();
                info!(node = %node_id, count = n, "split-tier rules applied");
            }
            Ok(_) => warn!(node = %node_id, "split-tier config empty — keeping catch-all routes"),
            Err(e) => warn!(node = %node_id, error = %e, "split-tier config fetch failed — keeping catch-all routes"),
        }
    });
}

/// One config-channel roundtrip: open the reserved target (the opener seals it like any E2E
/// Open), read the issuer's JSON answer to EOF, map rule strings to client rules.
async fn fetch_split_rules(opener: &Arc<DelegatedOpener>) -> Result<Vec<ClientRule>> {
    let fut = async {
        let mut ch = opener
            .open("", agile_net_core::relay::e2e::DELEGATION_CONFIG_TARGET, 0)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut ch, &mut buf)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;
        let v: serde_json::Value = serde_json::from_slice(&buf)?;
        let rules = v["rules"]
            .as_array()
            .ok_or_else(|| anyhow!("config answer missing the rules array"))?;
        Ok(rules
            .iter()
            .filter_map(|r| r.as_str())
            .map(|value| ClientRule {
                id: String::new(),
                rule_type: if value.contains('/') { "ip-cidr" } else { "host" }.into(),
                value: value.to_string(),
                resolve: false,
            })
            .collect::<Vec<_>>())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(8), fut).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("config fetch timed out")),
    }
}

/// Dial one disaster-set entry (per-entry fingerprint pinning; TOFU for unpinned entries).
async fn connect_delegated_entry(
    params: &ConnectParams,
    entry: &str,
    fp: Option<&String>,
    account_id: &str,
) -> Result<Arc<ClientTunnel>> {
    let addr = resolve_host_port(entry).await?;
    let mut tls = TlsConfigBuilder::new();
    tls = match fp.filter(|s| !s.is_empty()) {
        Some(fp) => tls.pinned_fingerprint(fp.clone()),
        None if params.insecure => tls.allow_self_signed(true),
        None => tls,
    };
    let tunnel = Arc::new(ClientTunnel::with_tls_builder(
        addr,
        account_id,
        params.password.clone(),
        tls,
    )?);
    tunnel.connect().await?;
    Ok(tunnel)
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

/// Extract sub from a JWT (no signature verification; local identification only).
fn claims_sub(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64_url_decode(payload)?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json["sub"].as_str().map(|s| s.to_string())
}

fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table_map = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        table_map[c as usize] = i as u8;
    }
    table_map[b'-' as usize] = 62;
    table_map[b'_' as usize] = 63;

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut nbits = 0u32;
    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let v = table_map[b as usize];
        if v == 255 {
            return None;
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
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
            via: "relay".into(),
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
}
