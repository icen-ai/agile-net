//! Fan-out connector manager: runtime assembly and hot ops with the DB as the single source of truth.
//!
//! At startup, assembles all enabled connectors from the DB (TOML `[[connectors]]` is imported
//! as seed data early in NodeServer startup); at runtime, `upsert_from_db` / `remove` react to
//! control-plane changes — old connection torn down before the new one starts, no node restart.

use crate::db::Database;
use crate::db::models::ConnectorRecord;
use crate::relay_auth::ManageableRegistry;
use crate::service::acl::PeerAclRegistry;
use crate::service::{ClientRoutes, load_pem_certs, resolve_upstream};
use agile_net_core::proto::message::PushedGroupMsg;
use agile_net_core::relay::transit::TransitMeter;
use agile_net_core::relay::{ConnectionState, PeerEvent, RelayConnector, RelayListener};
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use anyhow::Result;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Runtime handle of a single connector (connector instance plus all its background tasks).
struct ConnectorHandle {
    connector: Arc<RelayConnector>,
    /// Federation P1: pushed policy group slot (hot-swapped by refresh_push_groups;
    /// the connector reconnects to re-push on change)
    push_slot: Arc<arc_swap::ArcSwap<Vec<PushedGroupMsg>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Fan-out connector manager (connector_id -> runtime handle).
pub struct ConnectorManager {
    db: Database,
    /// This node's name (identifies itself to the upstream during handshake)
    node_id: String,
    /// Downstream-routing listener (for multi-hop chains, Open requests keep forwarding downstream)
    listener: Option<Arc<RelayListener>>,
    /// Route re-publish: client engine merged routes + opener registry (injected when embedded in the GUI)
    client_routes: Option<ClientRoutes>,
    /// Peer ACL registry (connector.group_id -> allowed set for reverse traffic)
    acl: Arc<PeerAclRegistry>,
    /// Manageable upstream registry (handshake v2 discovery sync)
    manageable: ManageableRegistry,
    /// Transit metering (None = assembled connectors are not metered)
    transit: Option<Arc<TransitMeter>>,
    handles: DashMap<String, ConnectorHandle>,
}

impl ConnectorManager {
    /// Minimal constructor (tests/embedding); runtime deps injected via with_*.
    pub fn new(db: Database) -> Self {
        Self {
            db,
            node_id: "anet-node".to_string(),
            listener: None,
            client_routes: None,
            acl: Arc::new(PeerAclRegistry::new()),
            manageable: Arc::new(DashMap::new()),
            transit: None,
            handles: DashMap::new(),
        }
    }

    pub fn with_node_id(mut self, node_id: String) -> Self {
        self.node_id = node_id;
        self
    }

    pub fn with_listener(mut self, listener: Option<Arc<RelayListener>>) -> Self {
        self.listener = listener;
        self
    }

    pub fn with_client_routes(mut self, client_routes: Option<ClientRoutes>) -> Self {
        self.client_routes = client_routes;
        self
    }

    pub fn with_acl_registry(mut self, registry: Arc<PeerAclRegistry>) -> Self {
        self.acl = registry;
        self
    }

    pub fn with_manageable(mut self, registry: ManageableRegistry) -> Self {
        self.manageable = registry;
        self
    }

    /// Attach the transit meter (assembled connectors account traffic under their own name as source).
    pub fn with_transit_meter(mut self, meter: Arc<TransitMeter>) -> Self {
        self.transit = Some(meter);
        self
    }

    /// Startup assembly: bring up all enabled connectors from the DB (a single failure is logged only).
    pub async fn start_all(&self) {
        let views = match self.db.list_connectors() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "list connectors failed");
                return;
            }
        };
        for v in views.into_iter().filter(|v| v.enabled) {
            if let Err(e) = self.upsert_from_db(&v.id).await {
                tracing::error!(connector = %v.name, error = %e, "connector start failed");
            }
        }
    }

    /// Create or rebuild a connector (tear down old before starting new; missing/disabled record just removes).
    pub async fn upsert_from_db(&self, id: &str) -> Result<()> {
        self.remove(id).await;
        if let Some(handle) = self.build(id).await? {
            self.handles.insert(id.to_string(), handle);
        }
        Ok(())
    }

    /// Disconnect and remove a connector (idempotent).
    pub async fn remove(&self, id: &str) {
        if let Some((_, handle)) = self.handles.remove(id) {
            handle.connector.disconnect().await;
            for t in handle.tasks {
                t.abort();
            }
        }
    }

    /// Disconnect all (node shutdown).
    pub async fn shutdown(&self) {
        let ids: Vec<String> = self.handles.iter().map(|e| e.key().clone()).collect();
        for id in ids {
            self.remove(&id).await;
        }
    }

    /// (upstream addr, state) of each connector (same semantics as the former connector_states).
    pub fn states(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self
            .handles
            .iter()
            .map(|h| {
                (
                    h.connector.upstream_addr().to_string(),
                    state_str(h.connector.state()).to_string(),
                )
            })
            .collect();
        out.sort();
        out
    }

    /// Live state of one connector (no runtime handle = None; callers render it as disconnected).
    pub fn state_of(&self, id: &str) -> Option<&'static str> {
        self.handles.get(id).map(|h| state_str(h.connector.state()))
    }

    /// Current-session traffic per connector (connector name, bytes out, bytes in);
    /// disconnected connectors report (0, 0) (session counters only; historical totals are sampled in node_traffic_log).
    pub fn traffic(&self) -> Vec<(String, u64, u64)> {
        let views = self.db.list_connectors().unwrap_or_default();
        let mut out: Vec<(String, u64, u64)> = self
            .handles
            .iter()
            .map(|h| {
                let name = views
                    .iter()
                    .find(|c| c.id == *h.key())
                    .map(|c| c.name.clone())
                    .unwrap_or_else(|| h.connector.upstream_addr().to_string());
                let (up, down) = h.connector.traffic();
                (name, up, down)
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Fan-out aggregate status: any connected = connected; no fan-out at all = disabled.
    pub fn aggregate_status(&self) -> &'static str {
        if self.handles.is_empty() {
            return "disabled";
        }
        let mut any_connected = false;
        let mut any_active = false;
        for h in self.handles.iter() {
            match h.connector.state() {
                ConnectionState::Connected => any_connected = true,
                ConnectionState::Connecting | ConnectionState::Reconnecting => any_active = true,
                ConnectionState::Disconnected => {}
            }
        }
        if any_connected {
            "connected"
        } else if any_active {
            "connecting"
        } else {
            "disconnected"
        }
    }

    /// Resolve the peer for a bandwidth test (`anet tool bandwidth` / tool API):
    /// - `Some(p)`: match by connector name or upstream addr, must be connected;
    /// - `None`: first connected connector.
    ///
    /// Returns (peer display name, connector handle) or a precise error.
    pub fn resolve_bandwidth_peer(
        &self,
        peer: Option<&str>,
    ) -> std::result::Result<(String, Arc<RelayConnector>), BandwidthPeerError> {
        let views = self.db.list_connectors().unwrap_or_default();
        match peer {
            Some(p) => {
                let Some(rec) = views.iter().find(|c| c.name == p || c.upstream_addr == p)
                else {
                    return Err(BandwidthPeerError::NotFound(format!(
                        "connector not found: {p}"
                    )));
                };
                match self.handles.get(&rec.id) {
                    Some(h) if h.connector.is_connected() => {
                        Ok((rec.name.clone(), h.connector.clone()))
                    }
                    _ => Err(BandwidthPeerError::NotConnected(format!(
                        "对端未连接: {}（connector 存在但当前非 connected）",
                        rec.name
                    ))),
                }
            }
            None => {
                for h in self.handles.iter() {
                    if h.connector.is_connected() {
                        let label = views
                            .iter()
                            .find(|c| c.id == *h.key())
                            .map(|c| c.name.clone())
                            .unwrap_or_else(|| h.connector.upstream_addr().to_string());
                        return Ok((label, h.connector.clone()));
                    }
                }
                Err(BandwidthPeerError::NotConnected(
                    "无已连接的扇出对端（无 connected 状态的 connector）".into(),
                ))
            }
        }
    }

    /// Build and bring up one connector from its DB record (None = record missing or disabled).
    async fn build(&self, id: &str) -> Result<Option<ConnectorHandle>> {
        let Some(rec) = self.db.get_connector(id)? else {
            return Ok(None);
        };
        if !rec.enabled {
            return Ok(None);
        }

        let upstream = resolve_upstream(&rec.upstream_addr).await?;
        let mut tls_builder = TlsConfigBuilder::new().sni_hostname(&rec.sni_hostname);
        // cert verification priority matches core TlsConfigBuilder: fingerprint > pinned certs > ca > insecure
        if !rec.pinned_fingerprint.is_empty() {
            tls_builder = tls_builder.pinned_fingerprint(rec.pinned_fingerprint.clone());
            tracing::info!(connector = %rec.name, "connector TLS: certificate fingerprint pinning enabled");
        } else if !rec.pinned_cert_path.is_empty() {
            let certs = load_pem_certs(&rec.pinned_cert_path)?;
            tls_builder = tls_builder.pinned_certs(certs);
            tracing::info!(connector = %rec.name, "connector TLS: certificate pinning enabled");
        } else if !rec.ca_cert_path.is_empty() {
            let certs = load_pem_certs(&rec.ca_cert_path)?;
            tls_builder = tls_builder.ca_certs(certs);
        } else if rec.insecure {
            tracing::warn!(
                connector = %rec.name,
                "connector TLS: INSECURE mode (no certificate verification) — dev only!"
            );
            tls_builder = tls_builder.allow_self_signed(true);
        }

        // token plaintext is used only for connecting (decrypted from the encrypted store); never log/audit it
        let token = self.db.get_connector_secret(id)?;
        let mut connector = RelayConnector::with_tls_builder(
            upstream,
            self.node_id.clone(),
            token,
            tls_builder,
        )?
        .with_advertise(parse_advertise(&rec.advertise))
        .with_acl(self.acl.handle(rec.group_id.as_deref()));

        // Federation P1: assemble the pushed policy groups (connector.push_groups -> name + rules)
        let push_slot = Arc::new(arc_swap::ArcSwap::from_pointee(
            self.pushed_groups_of(&rec),
        ));
        connector = connector.with_push_groups(push_slot.clone());

        // transit metering: upstream reverse inbound accounted with from=connector name
        if let Some(m) = &self.transit {
            connector = connector.with_transit_meter(m.clone(), rec.name.clone());
        }

        if let Some(l) = &self.listener {
            connector = connector.with_peer_router(l.clone());
        }
        // route re-publish: client tunnel routes resold downstream (injected when embedded in the GUI)
        if let Some((cr, ops)) = &self.client_routes {
            connector = connector.with_client_routes(cr.clone(), ops.clone());
        }
        let connector = Arc::new(connector);

        let mut tasks = Vec::new();
        let c = connector.clone();
        tasks.push(tokio::spawn(async move {
            c.run().await;
        }));
        tracing::info!(connector = %rec.name, upstream = %upstream, "relay connector running");

        // handshake v2: sync the upstream's exposed control endpoint into the manageable registry
        {
            let c = connector.clone();
            let registry = self.manageable.clone();
            tasks.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(2));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    match c.control_offer() {
                        Some(offer) => {
                            let key = if offer.node_name.is_empty() {
                                "upstream".to_string()
                            } else {
                                offer.node_name.clone()
                            };
                            let stale = registry
                                .get(&key)
                                .map(|old| old.ticket != offer.ticket)
                                .unwrap_or(true);
                            if stale {
                                tracing::info!(upstream = %key, api = %format!("{:?}:{}", offer.api_host, offer.api_port), "manageable upstream discovered");
                            }
                            registry.insert(key, offer);
                        }
                        None => {
                            if !registry.is_empty() {
                                registry.clear();
                            }
                        }
                    }
                }
            }));
        }

        // ACL-denied events -> audit (detail carries connector name and target; deduped per peer+target per minute)
        tasks.push(spawn_acl_audit_task(
            self.db.clone(),
            format!("connector={}", rec.name),
            connector.subscribe_events(),
        ));

        Ok(Some(ConnectorHandle {
            connector,
            push_slot,
            tasks,
        }))
    }

    /// Assemble the pushed policy groups of a connector record (push_groups ids -> name + rule values).
    fn pushed_groups_of(&self, rec: &ConnectorRecord) -> Vec<PushedGroupMsg> {
        rec.push_groups
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|gid| {
                let g = self.db.get_group(gid).ok()??;
                let rules = self
                    .db
                    .rules_of_group(gid)
                    .map(|rs| rs.into_iter().map(|r| r.value).collect())
                    .unwrap_or_default();
                Some(PushedGroupMsg {
                    name: g.name,
                    remark: g.remark,
                    rules,
                })
            })
            .collect()
    }

    /// Federation P1: refresh every connector's pushed-group slot from the DB (config_version watcher;
    /// a content change reconnects the connector to re-push upstream).
    pub fn refresh_push_groups(&self) {
        for h in self.handles.iter() {
            if let Ok(Some(rec)) = self.db.get_connector(h.key()) {
                let groups = self.pushed_groups_of(&rec);
                if h.push_slot.load().as_ref() != &groups {
                    h.push_slot.store(Arc::new(groups));
                }
            }
        }
    }
}

/// ACL-denied audit task: subscribes to `PeerEvent::AclDenied`, at most one entry per peer+target per minute (anti-flood).
/// `source` tags the origin (`connector=<name>` / `listener`); audit records only peer label and target — never sensitive values.
pub(crate) fn spawn_acl_audit_task(
    db: Database,
    source: String,
    mut rx: tokio::sync::broadcast::Receiver<PeerEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut seen: std::collections::HashMap<String, Instant> = std::collections::HashMap::new();
        loop {
            match rx.recv().await {
                Ok(PeerEvent::AclDenied { peer_label, target }) => {
                    let now = Instant::now();
                    // lazy sweep: keep the dedup table from growing unbounded
                    if seen.len() > 4096 {
                        seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
                    }
                    let key = format!("{peer_label}|{target}");
                    if seen
                        .get(&key)
                        .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60))
                    {
                        continue;
                    }
                    seen.insert(key, now);
                    let _ = db.record_audit_log(
                        None,
                        "system",
                        "peer.acl_denied",
                        Some(&peer_label),
                        Some(&format!("{source} target={target}")),
                        None,
                    );
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, source = %source, "acl audit events lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Restore the DB-serialized advertise list (comma-joined) into entries.
fn parse_advertise(advertise: &str) -> Vec<String> {
    advertise
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Connection state literal (matches the API display).
fn state_str(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::Connected => "connected",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Reconnecting => "reconnecting",
        ConnectionState::Disconnected => "disconnected",
    }
}

/// Bandwidth-test peer resolution error (kind maps to API error codes).
#[derive(Debug)]
pub enum BandwidthPeerError {
    /// No connector record for the given name/upstream addr
    NotFound(String),
    /// Connector exists but is not connected (or none connected when unspecified)
    NotConnected(String),
}

impl std::fmt::Display for BandwidthPeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BandwidthPeerError::NotFound(m) | BandwidthPeerError::NotConnected(m) => {
                write!(f, "{m}")
            }
        }
    }
}
