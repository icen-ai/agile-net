//! Fan-out connector manager: runtime assembly and hot ops with the DB as the single source of truth.
//!
//! At startup, assembles all enabled connectors from the DB (TOML `[[connectors]]` is imported
//! as seed data early in NodeServer startup); at runtime, `upsert_from_db` / `remove` react to
//! control-plane changes — old connection torn down before the new one starts, no node restart.

use crate::db::Database;
use crate::db::models::ConnectorRecord;
use crate::relay_auth::ManageableRegistry;
use crate::service::acl::PeerAclRegistry;
use crate::service::delegation::{DelegationEngine, build_register_msg};
use crate::service::{ClientRoutes, load_pem_certs, resolve_upstream};
use agile_net_core::proto::frame::{Frame, FrameType};
use agile_net_core::proto::message::{CtrlMessage, PROTOCOL_VERSION_DELEGATION, PushedGroupMsg};
use agile_net_core::relay::transit::TransitMeter;
use agile_net_core::relay::{ConnectionState, MuxSession, PeerEvent, RelayConnector, RelayListener};
use agile_net_core::tunnel::tls::TlsConfigBuilder;
use anyhow::Result;
use dashmap::DashMap;
use std::collections::HashMap;
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
    /// Federation P2: delegated-token registration state, (token_id, connector_id) ->
    /// "pending" / "registered" / "failed: <reason>" / "offline" / "unsupported" (upstream < v3)
    delegation_states: Arc<DashMap<(String, String), String>>,
    /// Federation P2/P3: data-plane enforcement engine (group ACL / E2E unwrap / fail-close),
    /// shared by every connector this node runs
    delegation: Arc<DelegationEngine>,
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
            delegation_states: Arc::new(DashMap::new()),
            delegation: DelegationEngine::new(),
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
        // federation P2/P3: warm the delegation caches before any Open can arrive
        self.delegation.refresh_keys(&self.db);
        self.delegation.refresh_groups(&self.db);
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
        // Same-upstream multi-links must not share one identity on the peer (same node_id
        // sessions kick each other): force a `name#connector` suffix when another enabled
        // connector points at the same upstream (federation P2 identity discipline)
        let peer_node_id = {
            let same_upstream = self
                .db
                .list_connectors()
                .unwrap_or_default()
                .into_iter()
                .filter(|c| c.enabled && c.id != rec.id && c.upstream_addr == rec.upstream_addr)
                .count();
            if same_upstream > 0 {
                format!("{}#{}", self.node_id, rec.name)
            } else {
                self.node_id.clone()
            }
        };
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
            peer_node_id,
            token,
            tls_builder,
        )?
        .with_advertise(parse_advertise(&rec.advertise))
        .with_acl(self.acl.handle(rec.group_id.as_deref()))
        .with_delegation_hooks(self.delegation.clone());

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
                let mut last_key: Option<String> = None;
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
                            registry.insert(key.clone(), offer);
                            last_key = Some(key);
                        }
                        None => {
                            // remove only this connector's own entry — a global clear()
                            // would wipe upstreams discovered by sibling connectors
                            if let Some(k) = last_key.take() {
                                registry.remove(&k);
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

        // federation P2: delegated-token registration sync — re-register every token of this
        // connector on each new session (the relay registry is volatile), register newly issued
        // tokens incrementally, and fold registration acks into the state table for the API
        {
            let c = connector.clone();
            let db = self.db.clone();
            let connector_id = id.to_string();
            let states = self.delegation_states.clone();
            tasks.push(tokio::spawn(async move {
                let mut last_mux: Option<Arc<MuxSession>> = None;
                // token_id -> token_hash, already sent on the current session
                let mut live: HashMap<String, String> = HashMap::new();
                let mut interval = tokio::time::interval(Duration::from_secs(2));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    let tokens = db
                        .delegated_tokens_of_connector(&connector_id)
                        .unwrap_or_default();

                    let connected = c.is_connected();
                    let supported =
                        connected && c.upstream_version() >= PROTOCOL_VERSION_DELEGATION;
                    if !supported {
                        let label = if connected { "unsupported" } else { "offline" };
                        for rec in &tokens {
                            states.insert((rec.id.clone(), connector_id.clone()), label.into());
                        }
                        last_mux = None;
                        live.clear();
                        continue;
                    }

                    let mux = c.current_mux();
                    let new_session = match (&last_mux, &mux) {
                        (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
                        (None, Some(_)) => true,
                        _ => false,
                    };
                    if new_session {
                        c.clear_delegation_acks();
                        live.clear();
                    }
                    last_mux = mux.clone();
                    let Some(mux) = mux else { continue };

                    // fold acks of this session into the state table
                    for (tid, hash) in &live {
                        if let Some((ok, err)) = c.delegation_ack(hash) {
                            let v = if ok {
                                "registered".into()
                            } else {
                                format!("failed: {err}")
                            };
                            states.insert((tid.clone(), connector_id.clone()), v);
                        }
                    }

                    // register tokens not yet sent on this session
                    for rec in tokens {
                        if live.contains_key(&rec.id) {
                            continue;
                        }
                        let msg = build_register_msg(&db, &rec);
                        let hash = rec.token_hash.clone();
                        let Ok(payload) = serde_json::to_vec(&msg) else {
                            continue;
                        };
                        if mux
                            .send_frame(Frame::new(FrameType::Ctrl, 0, payload))
                            .await
                            .is_err()
                        {
                            break; // session died mid-flush; next tick re-evaluates
                        }
                        states.insert((rec.id.clone(), connector_id.clone()), "pending".into());
                        live.insert(rec.id.clone(), hash);
                    }
                }
            }));
        }

        Ok(Some(ConnectorHandle {
            connector,
            push_slot,
            tasks,
        }))
    }

    /// Assemble the pushed policy groups of a connector record (push_groups ids -> name + rule values).
    fn pushed_groups_of(&self, rec: &ConnectorRecord) -> Vec<PushedGroupMsg> {
        pushed_group_msgs(&self.db, rec)
    }

    /// Federation P1: refresh every connector's pushed-group slot from the DB (config_version watcher;
    /// a content change reconnects the connector to re-push upstream).
    pub fn refresh_push_groups(&self) {
        // federation P2/P3: group/rule edits also invalidate the delegation enforcement cache
        self.delegation.refresh_groups(&self.db);
        for h in self.handles.iter() {
            if let Ok(Some(rec)) = self.db.get_connector(h.key()) {
                let groups = self.pushed_groups_of(&rec);
                if h.push_slot.load().as_ref() != &groups {
                    h.push_slot.store(Arc::new(groups));
                }
            }
        }
    }

    /// Federation P2/P3: rebuild the delegation E2E key cache (call after issue/revoke).
    pub fn refresh_delegation_keys(&self) {
        self.delegation.refresh_keys(&self.db);
    }

    /// Open a stream toward a discovered manageable upstream (handshake v2): the connector
    /// whose current control offer names this upstream dials the offered control endpoint
    /// through the fan-out session. None = upstream not discovered / connector offline.
    pub async fn open_manageable_stream(
        &self,
        upstream: &str,
        target_addr: &str,
        target_port: u16,
    ) -> Option<agile_net_core::relay::MuxChannel> {
        for h in self.handles.iter() {
            if let Some(o) = h.connector.control_offer()
                && o.exposed
                && o.node_name == upstream
            {
                return h.connector.open_stream(target_addr, target_port).await.ok();
            }
        }
        None
    }

    /// Federation P2: revoke a delegated token — delete locally and send the revocation frame to
    /// every online upstream of its disaster set (offline upstreams invalidate by disconnect).
    pub async fn revoke_delegated(&self, token_id: &str) -> Result<bool> {
        let Some(rec) = crate::service::delegation::revoke_token(&self.db, token_id)? else {
            return Ok(false);
        };
        for reg in &rec.regs {
            if let Some(h) = self.handles.get(&reg.connector_id)
                && h.connector.is_connected()
                && h.connector.upstream_version() >= PROTOCOL_VERSION_DELEGATION
                && let Some(mux) = h.connector.current_mux()
            {
                let msg = CtrlMessage::TokenRevoke {
                    token_hash: rec.token_hash.clone(),
                };
                if let Ok(payload) = serde_json::to_vec(&msg) {
                    let _ = mux
                        .send_frame(Frame::new(FrameType::Ctrl, 0, payload))
                        .await;
                }
            }
            self.delegation_states
                .remove(&(token_id.to_string(), reg.connector_id.clone()));
        }
        Ok(true)
    }

    /// Federation P2: registration state of every delegated token, (token_id, connector_id, state).
    pub fn delegation_states(&self) -> Vec<(String, String, String)> {
        self.delegation_states
            .iter()
            .map(|e| (e.key().0.clone(), e.key().1.clone(), e.value().clone()))
            .collect()
    }

    /// Negotiated upstream protocol version of a connector (None = no runtime handle; 0 = offline).
    pub fn upstream_version_of(&self, id: &str) -> Option<u32> {
        self.handles.get(id).map(|h| h.connector.upstream_version())
    }
}

/// ACL-denied audit task: subscribes to `PeerEvent::AclDenied`, at most one entry per peer+target per minute (anti-flood).
/// `source` tags the origin (`connector=<name>` / `listener`); audit records only peer label and target — never sensitive values.
/// Federation P2: delegated token register/revoke events on the relay are audited the same way
/// (deduped per peer+label per minute; blob/plaintext/targets are never logged).
pub(crate) fn spawn_acl_audit_task(
    db: Database,
    source: String,
    mut rx: tokio::sync::broadcast::Receiver<PeerEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut seen: std::collections::HashMap<String, Instant> = std::collections::HashMap::new();
        loop {
            // flood guard: one audit entry per dedup key per minute
            let mut pass = |key: String| {
                let now = Instant::now();
                // lazy sweep: keep the dedup table from growing unbounded
                if seen.len() > 4096 {
                    seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
                }
                if seen
                    .get(&key)
                    .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60))
                {
                    return false;
                }
                seen.insert(key, now);
                true
            };
            match rx.recv().await {
                Ok(PeerEvent::AclDenied { peer_label, target }) => {
                    if !pass(format!("{peer_label}|{target}")) {
                        continue;
                    }
                    let _ = db.record_audit_log(
                        None,
                        "system",
                        "peer.acl_denied",
                        Some(&peer_label),
                        Some(&format!("{source} target={target}")),
                        None,
                    );
                }
                Ok(PeerEvent::DelegationRegistered { node_id, label }) => {
                    if !pass(format!("deleg-reg|{node_id}|{label}")) {
                        continue;
                    }
                    let _ = db.record_audit_log(
                        None,
                        "system",
                        "delegation.register",
                        Some(&node_id),
                        Some(&format!("{source} label={label}")),
                        None,
                    );
                }
                Ok(PeerEvent::DelegationRevoked { node_id, label }) => {
                    if !pass(format!("deleg-rev|{node_id}|{label}")) {
                        continue;
                    }
                    let _ = db.record_audit_log(
                        None,
                        "system",
                        "delegation.revoke",
                        Some(&node_id),
                        Some(&format!("{source} label={label}")),
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

/// Assemble the pushed policy groups of a connector record (push_groups ids -> name + rule values).
fn pushed_group_msgs(db: &Database, rec: &ConnectorRecord) -> Vec<PushedGroupMsg> {
    rec.push_groups
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|gid| {
            let g = db.get_group(gid).ok()??;
            let rules = db
                .rules_of_group(gid)
                .map(|rs| rs.into_iter().map(|r| r.value).collect())
                .unwrap_or_default();
            Some(PushedGroupMsg {
                name: g.name,
                remark: g.remark,
                rules,
                e2e_required: g.e2e_required,
            })
        })
        .collect()
}

/// Effective advertise set of a connector record, mirroring `RelayConnector::effective_advertise`
/// (minus client-tunnel re-advertise): manual advertise + pushed group rules, deduped with the
/// first occurrence kept (manual entries first). Delegation E2E hints are derived from this set
/// so the hint always matches what the upstream route table will actually carry.
pub fn effective_advertise_of(db: &Database, rec: &ConnectorRecord) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut push = |e: String| {
        if seen.insert(e.clone()) {
            out.push(e);
        }
    };
    for e in parse_advertise(&rec.advertise) {
        push(e);
    }
    for g in pushed_group_msgs(db, rec) {
        for r in g.rules {
            push(r);
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(advertise: &str, push_groups: &str) -> ConnectorRecord {
        ConnectorRecord {
            id: "c1".into(),
            name: "c1".into(),
            upstream_addr: "127.0.0.1:54430".into(),
            token_enc: String::new(),
            sni_hostname: String::new(),
            insecure: false,
            ca_cert_path: String::new(),
            pinned_cert_path: String::new(),
            pinned_fingerprint: String::new(),
            advertise: advertise.into(),
            group_id: None,
            push_groups: push_groups.into(),
            enabled: true,
            remark: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn effective_advertise_unions_pushed_group_rules() {
        let db = Database::in_memory().unwrap();
        let gid = db.create_group("dev", "").unwrap().id;
        let r1 = db.create_rule("ip-cidr", "10.12.0.0/16", false, "").unwrap().id;
        let r2 = db.create_rule("host", "git.internal", false, "").unwrap().id;
        db.set_group_rules(&gid, &[r1, r2]).unwrap();

        // manual advertise first, pushed rules appended, duplicates dropped (first occurrence kept)
        let v = effective_advertise_of(&db, &rec("10.12.0.0/16, corp.example.com", &gid));
        assert_eq!(
            v,
            vec![
                "10.12.0.0/16".to_string(),
                "corp.example.com".to_string(),
                "git.internal".to_string()
            ]
        );

        // empty manual advertise: pushed rules alone make the endpoint routable (rule order is
        // DB-defined — compare as a set)
        let mut v = effective_advertise_of(&db, &rec("", &gid));
        v.sort();
        assert_eq!(v, vec!["10.12.0.0/16".to_string(), "git.internal".to_string()]);

        // no push groups: manual advertise only
        let v = effective_advertise_of(&db, &rec("10.0.0.0/8", ""));
        assert_eq!(v, vec!["10.0.0.0/8".to_string()]);
    }
}
