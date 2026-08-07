//! Relay Listener — upstream role, accepts downstream nodes and clients
//!
//! Security design:
//! - 10s timeout for the whole TLS handshake + auth (anti-Slowloris half-open exhaustion)
//! - constant-time token comparison (anti timing side channel)
//! - random delay on auth failure + per-source-IP rate limiting (anti online brute force)
//! - caps on concurrent connections and pending-auth connections (anti connection flood)
//! - per-group target ACL checks on client sessions

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::{
    AuthKind, AuthRequest, Concurrency, FailReason, OpenChannel, PROTOCOL_VERSION,
    PROTOCOL_VERSION_FLOW_CONTROL, reason,
};
use crate::proxy::router::{Outbound, ProxyRouter};
use crate::relay::acl::PeerAcl;
use crate::relay::limit::TokenBucket;
use crate::relay::mux::{MuxChannel, MuxSession, OpenRequest, SessionEvents};
use crate::relay::transit::{TO_LOCAL, TransitMeter};
use crate::tunnel::tls::TlsConfigBuilder;
use crate::util::sha256_hex;

use bytes::Bytes;
use dashmap::DashMap;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, broadcast};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// TLS handshake + auth must complete within this time.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// Default max concurrent connections (including unauthenticated).
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// Default max pending-auth connections.
pub const DEFAULT_MAX_PENDING_AUTH: usize = 256;
/// Default max auth failures per IP within a 60s window.
pub const DEFAULT_MAX_AUTH_FAILURES_PER_MINUTE: u32 = 20;
/// Max concurrently handled peer Opens per session (anti Open-flood task/connection
/// exhaustion; the local open_channel direction is already guarded by
/// MAX_CHANNELS_PER_SESSION — this cap covers the peer-initiated direction).
pub const MAX_INBOUND_OPENS_PER_SESSION: usize = 256;

/// Principal identity after successful auth.
#[derive(Debug, Clone)]
pub enum AuthIdentity {
    /// Downstream node
    Node {
        node_id: String,
        /// Advertised serviceable CIDRs/domains
        advertise: Vec<String>,
        /// Policy groups pushed for the upstream authorizable pool (federation P1)
        groups: Vec<crate::proto::message::PushedGroupMsg>,
        /// Handshake v2: management endpoint pushed to this downstream when exposing a control plane (carried in AuthOk)
        control: Option<crate::proto::message::ControlOffer>,
        /// Fan-in restriction: allowlist for target connections initiated by this peer (None = unrestricted, allow all)
        acl: Option<Arc<PeerAcl>>,
        /// Admin-assigned display name (relay token remark; None = fall back to node_id).
        /// The peer's self-reported node name is decorative and often a default like "AgileNet 内嵌端点";
        /// the issuer-side token remark is the authoritative identity for admin displays.
        display: Option<String>,
    },
    /// Delegated consumer session (unified issuance): authenticated by the listener itself
    /// against the delegated token registries (persistent local first, then session-scoped).
    Delegated(DelegatedIdentity),
}

/// Identity of a delegated consumer session.
#[derive(Debug, Clone)]
pub struct DelegatedIdentity {
    /// Consumer's self-reported node id (AuthRequest.node_id) — part of the session key
    pub node_id: String,
    /// ACL snapshot: the token's transparent rules plus its hint vocabulary (seed for the
    /// session's hot ACL state; every open re-resolves the registry entry)
    pub acl: Vec<String>,
}

/// Federation P2: a delegated token registered by an online fan-out endpoint (session-scoped,
/// relay-side volatile state — dropped when the issuer session ends, revoke-by-disconnect) or
/// injected into the listener's persistent local registry (self-entry/direct mode).
#[derive(Debug, Clone)]
pub struct DelegatedToken {
    /// Issuer node_id (the fan-out session that registered this token)
    pub issuer: String,
    pub label: String,
    /// Issuer group names the token may use (already intersected with pushed groups)
    pub groups: Vec<String>,
    /// Transparent-tier ACL snapshot: union of the referenced pushed-group rules
    pub acl_rules: Vec<String>,
    /// Coarse E2E routing vocabulary (validated against the issuer's advertised routes)
    pub hint_map: Vec<crate::proto::message::HintEntry>,
    /// Consumer-session concurrency policy (enforced by the listener at auth)
    pub concurrency: Concurrency,
    /// Max simultaneous consumer sessions under the multi policy
    pub max_sessions: u32,
}

/// Relay-side delegated token registry (token_hash -> token). Volatile by design: nothing is
/// persisted, a relay restart clears it and issuers re-register on reconnect.
pub type DelegatedRegistry = Arc<DashMap<String, DelegatedToken>>;

/// Authorizable-pool entry of one online peer (federation P1): its advertised routes and
/// pushed policy groups, source-tagged by node_id.
#[derive(Debug, Clone)]
pub struct PeerOffer {
    pub node_id: String,
    pub advertise: Vec<String>,
    pub groups: Vec<crate::proto::message::PushedGroupMsg>,
}

/// Caps for pushed policy groups (anti-abuse; a compromised/malicious peer cannot flood the pool).
pub const MAX_PUSHED_GROUPS: usize = 32;
pub const MAX_PUSHED_GROUP_NAME: usize = 128;
pub const MAX_PUSHED_GROUP_RULES: usize = 256;
pub const MAX_PUSHED_RULE_LEN: usize = 256;
/// Cap for entrust registrations per issuer (anti-abuse: en_ words skip route validation, so a
/// malicious issuer could otherwise fill relay memory with self-minted opaque IDs).
pub const MAX_ENTRUST_PER_ISSUER: usize = 1024;
/// Cap for a delegated token's `max_sessions` (anti-abuse bound on the consumer session table).
pub const MAX_DELEGATED_SESSIONS: u32 = 1024;

/// Sanitize pushed groups before pooling (drop offending entries, never reject the session).
pub fn sanitize_pushed_groups(
    groups: Vec<crate::proto::message::PushedGroupMsg>,
) -> Vec<crate::proto::message::PushedGroupMsg> {
    groups
        .into_iter()
        .filter(|g| !g.name.trim().is_empty() && g.name.len() <= MAX_PUSHED_GROUP_NAME)
        .take(MAX_PUSHED_GROUPS)
        .map(|mut g| {
            g.remark.truncate(MAX_PUSHED_RULE_LEN);
            g.rules = g
                .rules
                .into_iter()
                .filter(|r| !r.trim().is_empty() && r.len() <= MAX_PUSHED_RULE_LEN)
                .take(MAX_PUSHED_GROUP_RULES)
                .collect();
            g
        })
        .collect()
}

/// Token validator: implemented by the upper layer (node crate's database or static config).
pub trait TokenValidator: Send + Sync {
    /// Returns the principal identity on success, None on failure.
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity>;
}

/// Static single-token validator (static config / tests), constant-time comparison.
pub struct StaticTokenValidator {
    token: String,
}

impl StaticTokenValidator {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

impl TokenValidator for StaticTokenValidator {
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity> {
        if auth.kind != AuthKind::Node {
            return None;
        }
        if constant_time_eq(auth.token.as_bytes(), self.token.as_bytes()) {
            Some(AuthIdentity::Node {
                node_id: auth.node_id.clone(),
                advertise: auth.advertise.clone(),
                groups: auth.groups.clone(),
                control: None,
                acl: None,
                display: None,
            })
        } else {
            None
        }
    }
}

/// Constant-time byte comparison, avoiding timing side channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Node/consumer online-offline events (for control-plane status updates).
#[derive(Debug, Clone)]
pub enum PeerEvent {
    NodeConnected { node_id: String },
    NodeDisconnected { node_id: String },
    /// Delegated consumer session up/down; `session_key` = `delegated:<token_hash>:<node_id>`
    ClientConnected { session_key: String },
    ClientDisconnected { session_key: String },
    /// Restriction denial: a peer-initiated target connection was intercepted by PeerAcl (for control-plane audit).
    /// `peer_label` is the peer identifier (fan-in=node_id, fan-out=upstream_addr).
    AclDenied { peer_label: String, target: String },
    /// Federation P2: a fan-out endpoint registered/revoked a delegated token on its session.
    DelegationRegistered { node_id: String, label: String },
    DelegationRevoked { node_id: String, label: String },
}

/// Connected node session
pub struct PeerSession {
    pub node_id: String,
    pub mux: Arc<MuxSession>,
    /// SHA-256 of the token used for auth (sessions are kicked by hash when the token is revoked)
    pub token_hash: String,
    /// Display name: the auth identity's admin-assigned label (token remark) when present, else node_id
    pub display: String,
    /// Proven device identity (handshake v4): sha256 of the device public key, derived locally
    pub device_fp: String,
    /// Peer's self-declared display name ("我的名称"; decorative, shown next to OUR remark)
    pub my_name: String,
}

/// Device identity proven during the handshake (device_fp derived locally from the presented
/// public key — never trusted from the wire).
#[derive(Debug, Clone)]
pub struct DeviceMeta {
    pub device_fp: String,
    /// The presented ed25519 public key (canonical base64; for the device registry)
    pub pubkey: String,
    /// Peer's self-declared display name ("我的名称"; decorative, capped at 64 chars)
    pub my_name: String,
}

/// Proven device identity + connection metadata of one authenticated session (node.md M2 → M3
/// session tables / device profile). Keyed by a unique per-session id (multi tokens can run
/// several sessions under one session key); `session_key` links back to the kick tables.
#[derive(Debug, Clone)]
pub struct SessionMeta {
    /// Unique per accepted session
    pub session_id: String,
    /// node_id for fan-in peers, `delegated:<token_hash>:<node_id>` for consumers
    pub session_key: String,
    /// Locally derived device fingerprint (sha256 of the presented ed25519 pubkey)
    pub device_fp: String,
    /// The presented ed25519 public key (canonical base64)
    pub pubkey: String,
    /// Credential the session authenticated with (token sha256)
    pub token_hash: String,
    /// Peer's self-declared display name (decorative)
    pub my_name: String,
    /// Remote IP of the TLS connection
    pub peer_ip: String,
    /// Session start (uptime/duration display)
    pub connected_at: std::time::Instant,
}

/// Route table advertised by downstream nodes (target -> peer node_id).
#[derive(Default)]
struct AdvertisedRoutes {
    cidrs: IpNetworkTable<String>,
    hosts: HashMap<String, String>,
    suffixes: Vec<(String, String)>,
}

/// Session bandwidth limit provider: returns the bytes/sec cap per authenticated identity (None = unlimited).
type RateLimitProvider = Arc<dyn Fn(&AuthIdentity, &str) -> Option<u64> + Send + Sync>;

/// Relay listener.
pub struct RelayListener {
    listen_addr: SocketAddr,
    /// This node's self-declared name (announced to fan-out peers in AuthOk; display only)
    node_id: String,
    validator: Arc<dyn TokenValidator>,
    tls_acceptor: TlsAcceptor,
    peers: Arc<DashMap<String, PeerSession>>,
    /// Raw route entries advertised by each downstream node
    peer_advertise: Arc<DashMap<String, Vec<String>>>,
    /// Policy groups pushed by each downstream node (federation P1 authorizable pool)
    peer_groups: Arc<DashMap<String, Vec<crate::proto::message::PushedGroupMsg>>>,
    /// Federation P2: delegated tokens registered by online fan-out endpoints (session-scoped)
    delegated: DelegatedRegistry,
    /// Self-entry (direct mode): persistent local delegated token registry. Same value type as
    /// the session-scoped registry, but the node layer injects the handle and registers/removes
    /// entries directly at runtime — entries NEVER die with any session. Auth and route
    /// resolution consult it before the session-scoped registry.
    local_delegated: DelegatedRegistry,
    /// Federation P3 entrust mode: opaque routing words (en_xxx -> issuer node_id). Entries are
    /// registered from token_register hint_map entries carrying the en_ prefix (no advertised-route
    /// validation — the word is issuer-self-minted and semantics-free), and die with their issuer
    /// session exactly like delegated registrations.
    entrust: Arc<DashMap<String, String>>,
    /// Aggregated queryable route table (RCU hot update)
    routes: Arc<arc_swap::ArcSwap<AdvertisedRoutes>>,
    /// Online consumer sessions (session key -> session handle list, for online checks and forced
    /// disconnect; delegated consumers key on `delegated:<token_hash>:<node_id>`)
    clients: Arc<DashMap<String, Vec<Arc<MuxSession>>>>,
    /// Proven device identity + connection metadata, keyed by unique session id (M3 session
    /// tables); entries die with their session
    session_meta: Arc<DashMap<String, SessionMeta>>,
    events: broadcast::Sender<PeerEvent>,
    active_connections: Arc<AtomicUsize>,
    pending_auth: Arc<AtomicUsize>,
    auth_attempts: Arc<DashMap<IpAddr, (u32, Instant)>>,
    max_connections: usize,
    max_pending_auth: usize,
    max_auth_failures_per_minute: u32,
    /// Relay transit metering (None = no metering; fan-in peer-initiated forwards booked with from=node_id)
    transit: Option<Arc<TransitMeter>>,
    /// Session bandwidth limit provider: returns the bytes/sec cap per authenticated identity (None = unlimited)
    rate_limit_provider: Option<RateLimitProvider>,
}

impl RelayListener {
    /// Create a new RelayListener (static token validation, auto-generated self-signed cert).
    pub fn new(listen_addr: SocketAddr, expected_token: impl Into<String>) -> Result<Self> {
        let (server_config, _) = TlsConfigBuilder::new().build_server()?;
        let tls_acceptor = TlsAcceptor::from(server_config);
        Ok(Self::with_validator(
            listen_addr,
            Arc::new(StaticTokenValidator::new(expected_token)),
            tls_acceptor,
        ))
    }

    /// Create with a custom TlsAcceptor + static token.
    pub fn with_tls_acceptor(
        listen_addr: SocketAddr,
        expected_token: impl Into<String>,
        tls_acceptor: TlsAcceptor,
    ) -> Self {
        Self::with_validator(
            listen_addr,
            Arc::new(StaticTokenValidator::new(expected_token)),
            tls_acceptor,
        )
    }

    /// Create with a custom token validator and TlsAcceptor.
    pub fn with_validator(
        listen_addr: SocketAddr,
        validator: Arc<dyn TokenValidator>,
        tls_acceptor: TlsAcceptor,
    ) -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            listen_addr,
            node_id: String::new(),
            validator,
            tls_acceptor,
            peers: Arc::new(DashMap::new()),
            peer_advertise: Arc::new(DashMap::new()),
            peer_groups: Arc::new(DashMap::new()),
            delegated: Arc::new(DashMap::new()),
            local_delegated: Arc::new(DashMap::new()),
            entrust: Arc::new(DashMap::new()),
            routes: Arc::new(arc_swap::ArcSwap::from_pointee(AdvertisedRoutes::default())),
            clients: Arc::new(DashMap::new()),
            session_meta: Arc::new(DashMap::new()),
            events,
            active_connections: Arc::new(AtomicUsize::new(0)),
            pending_auth: Arc::new(AtomicUsize::new(0)),
            auth_attempts: Arc::new(DashMap::new()),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_pending_auth: DEFAULT_MAX_PENDING_AUTH,
            max_auth_failures_per_minute: DEFAULT_MAX_AUTH_FAILURES_PER_MINUTE,
            transit: None,
            rate_limit_provider: None,
        }
    }

    /// Attach the relay transit meter (fan-in peer-initiated forwards booked with from=node_id).
    pub fn with_transit_meter(mut self, meter: Arc<TransitMeter>) -> Self {
        self.transit = Some(meter);
        self
    }

    /// Set this node's self-declared name (announced to authenticated fan-out peers in AuthOk —
    /// the peer renders it as the upstream identity badge).
    pub fn with_node_id(mut self, node_id: String) -> Self {
        self.node_id = node_id;
        self
    }

    /// Inject a shared delegated token registry (federation P2): the node layer hands one
    /// instance to both the listener (register/revoke writes) and the token validator (auth
    /// reads), so the two always see the same live state.
    pub fn with_delegated_registry(mut self, registry: DelegatedRegistry) -> Self {
        self.delegated = registry;
        self
    }

    /// Inject the persistent local delegated token registry (self-entry/direct mode): the node
    /// layer registers/removes entries through the handle at runtime; the listener consults it
    /// before the session-scoped registry at auth and route resolution, and never clears it.
    pub fn with_local_delegated_registry(mut self, registry: DelegatedRegistry) -> Self {
        self.local_delegated = registry;
        self
    }

    /// Attach a session bandwidth limit provider: after auth, returns the session's
    /// bytes/sec cap by (identity, token hash); None (or no provider) means unlimited.
    /// The limit applies in the mux data plane, merging both directions; burst is
    /// `rate.max(64*1024)` (see session_limiter).
    pub fn with_session_rate_limit<F>(mut self, f: F) -> Self
    where
        F: Fn(&AuthIdentity, &str) -> Option<u64> + Send + Sync + 'static,
    {
        self.rate_limit_provider = Some(Arc::new(f));
        self
    }

    /// Build the session token bucket per authenticated identity (None = unlimited).
    fn session_limiter(&self, identity: &AuthIdentity, token_hash: &str) -> Option<Arc<TokenBucket>> {
        let rate = self.rate_limit_provider.as_ref()?(identity, token_hash)?;
        // burst at least 64 KiB (>= one full 16 KiB Data chunk): even at very low rates
        // a single frame must get its tokens at once, otherwise every frame queues on the
        // deficit for a long time and low-rate sessions degrade to unusable
        Some(Arc::new(TokenBucket::new(rate, rate.max(64 * 1024))))
    }

    /// Override default rate-limit parameters (maps to agile-net.toml [limits]).
    pub fn with_limits(
        mut self,
        max_connections: usize,
        max_pending_auth: usize,
        max_auth_failures_per_minute: u32,
    ) -> Self {
        self.max_connections = max_connections;
        self.max_pending_auth = max_pending_auth;
        self.max_auth_failures_per_minute = max_auth_failures_per_minute;
        self
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Number of connected and authenticated downstream nodes.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// List online downstream node IDs (routing/session keys — NOT display names; admin UIs should
    /// render `peer_display_map` values instead, since self-reported node names are decorative).
    pub fn list_peers(&self) -> Vec<String> {
        self.peers.iter().map(|p| p.key().clone()).collect()
    }

    /// node_id → display name (token remark when the issuer assigned one, else node_id).
    pub fn peer_display_map(&self) -> Vec<(String, String)> {
        self.peers
            .iter()
            .map(|p| (p.key().clone(), p.value().display.clone()))
            .collect()
    }

    /// Force-disconnect a downstream node (control-plane kick / effective immediately after token revocation).
    /// The session gets a SessionNotice (reason + one-time message) before the close.
    /// Returns whether such a node session existed.
    pub async fn disconnect_peer(&self, node_id: &str, reason_code: &str, message: &str) -> bool {
        if let Some((_, peer)) = self.peers.remove(node_id) {
            Self::notify_and_shutdown(&peer.mux, reason_code, message).await;
            self.session_meta.retain(|_, m| m.session_key != node_id);
            self.set_peer_routes(node_id, Vec::new());
            self.peer_groups.remove(node_id);
            let _ = self.events.send(PeerEvent::NodeDisconnected {
                node_id: node_id.to_string(),
            });
            true
        } else {
            false
        }
    }

    /// Federation P1 authorizable pool: advertised routes + pushed policy groups of every online peer.
    pub fn peer_offers(&self) -> Vec<PeerOffer> {
        self.peers
            .iter()
            .map(|p| {
                let node_id = p.key().clone();
                PeerOffer {
                    advertise: self
                        .peer_advertise
                        .get(&node_id)
                        .map(|v| v.clone())
                        .unwrap_or_default(),
                    groups: self
                        .peer_groups
                        .get(&node_id)
                        .map(|v| v.clone())
                        .unwrap_or_default(),
                    node_id,
                }
            })
            .collect()
    }

    /// Federation P2: shared handle of the delegated token registry (entries die with their
    /// issuer session).
    pub fn delegated_registry(&self) -> DelegatedRegistry {
        self.delegated.clone()
    }

    /// Self-entry (direct mode): shared handle of the persistent local delegated token registry
    /// (the node layer registers/removes entries at runtime; never cleared by session logic).
    pub fn local_delegated_registry(&self) -> DelegatedRegistry {
        self.local_delegated.clone()
    }

    /// Resolve a delegated token by hash: persistent local registry first (self-entry/direct
    /// mode), then the session-scoped registry.
    fn resolve_delegated_token(&self, token_hash: &str) -> Option<DelegatedToken> {
        self.local_delegated
            .get(token_hash)
            .map(|e| e.clone())
            .or_else(|| self.delegated.get(token_hash).map(|e| e.clone()))
    }

    /// Delegated consumer auth (unified issuance): resolve the token against the delegated
    /// registries and enforce the token's session concurrency policy — single kicks every older
    /// session of the token; multi admits while active sessions stay below `max_sessions`.
    async fn delegated_auth(&self, auth: &AuthRequest, token_hash: &str) -> Option<AuthIdentity> {
        let entry = self.resolve_delegated_token(token_hash)?;
        match entry.concurrency {
            Concurrency::Single => {
                self.disconnect_delegated_token(token_hash, reason::SESSION_TAKEOVER, "")
                    .await;
            }
            Concurrency::Multi => {
                if self.active_delegated_sessions(token_hash) >= entry.max_sessions as usize {
                    warn!(token_hash, max = entry.max_sessions, "delegated session cap reached, rejecting auth");
                    return None;
                }
            }
        }
        Some(AuthIdentity::Delegated(DelegatedIdentity {
            node_id: auth.node_id.clone(),
            acl: delegated_acl_of(&entry),
        }))
    }

    /// Active consumer sessions of one delegated token (any node_id).
    fn active_delegated_sessions(&self, token_hash: &str) -> usize {
        let prefix = delegated_session_prefix(token_hash);
        self.clients
            .iter()
            .filter(|c| c.key().starts_with(&prefix))
            .map(|c| c.value().len())
            .sum()
    }

    /// Force-disconnect every consumer session authenticated from one delegated token (any
    /// node_id) — token revocation, single-policy kick, issuer-session teardown. Each session
    /// gets a SessionNotice (reason + one-time message) before the close. Returns the number of
    /// disconnected sessions.
    pub async fn disconnect_delegated_token(
        &self,
        token_hash: &str,
        reason_code: &str,
        message: &str,
    ) -> usize {
        let prefix = delegated_session_prefix(token_hash);
        let keys: Vec<String> = self
            .clients
            .iter()
            .filter(|c| c.key().starts_with(&prefix))
            .map(|c| c.key().clone())
            .collect();
        let mut n = 0;
        for k in keys {
            n += self.disconnect_client(&k, reason_code, message).await;
        }
        n
    }

    /// Number of online consumer sessions (delegated session keys).
    pub fn online_client_count(&self) -> usize {
        self.clients.len()
    }

    /// Whether a consumer session with the given key is online.
    pub fn is_client_online(&self, session_key: &str) -> bool {
        self.clients
            .get(session_key)
            .map(|sessions| !sessions.is_empty())
            .unwrap_or(false)
    }

    /// Send a session notice (reason + one-time message) right before a forced close; the write
    /// is flushed first so the peer reliably sees WHY the session died (M4 client notification).
    async fn notify_and_shutdown(mux: &Arc<MuxSession>, reason_code: &str, message: &str) {
        if !reason_code.is_empty() {
            let notice = crate::proto::message::CtrlMessage::SessionNotice {
                reason_code: reason_code.to_string(),
                message: message.to_string(),
            };
            if let Ok(p) = serde_json::to_vec(&notice) {
                let _ = mux.send_frame(Frame::new(FrameType::Ctrl, 0, Bytes::from(p))).await;
            }
        }
        mux.shutdown();
    }

    /// Force-disconnect all sessions under one consumer session key (a SessionNotice with the
    /// reason precedes the close). Returns the number of disconnected sessions.
    pub async fn disconnect_client(&self, session_key: &str, reason_code: &str, message: &str) -> usize {
        let Some((_, sessions)) = self.clients.remove(session_key) else {
            return 0;
        };
        self.session_meta.retain(|_, m| m.session_key != session_key);
        let count = sessions.len();
        for mux in sessions {
            Self::notify_and_shutdown(&mux, reason_code, message).await;
        }
        let _ = self.events.send(PeerEvent::ClientDisconnected {
            session_key: session_key.to_string(),
        });
        count
    }

    /// Force-close every session (peers and clients) — server shutdown / role stop.
    /// A SessionNotice(server_shutdown) precedes each close, and the mux shutdown drops the TLS
    /// streams, so the remote ends see a clean disconnect and can fail over immediately instead
    /// of waiting out the idle timeout.
    pub async fn shutdown_all(&self) {
        let peers: Vec<String> = self.peers.iter().map(|p| p.key().clone()).collect();
        for id in peers {
            self.disconnect_peer(&id, reason::SERVER_SHUTDOWN, "").await;
        }
        let clients: Vec<String> = self.clients.iter().map(|c| c.key().clone()).collect();
        for id in clients {
            self.disconnect_client(&id, reason::SERVER_SHUTDOWN, "").await;
        }
    }

    /// Per-downstream-node data-plane traffic stats (node_id, egress bytes, ingress bytes).
    pub fn peer_traffic(&self) -> Vec<(String, u64, u64)> {
        self.peers
            .iter()
            .map(|p| {
                let (out, inn) = p.value().mux.traffic();
                (p.key().clone(), out, inn)
            })
            .collect()
    }

    /// Force-disconnect a downstream node session by token hash (called when a relay token is revoked).
    /// Returns the disconnected node ID (if online).
    pub async fn disconnect_by_token_hash(&self, token_hash: &str, reason_code: &str, message: &str) -> Option<String> {
        let node_id = self
            .peers
            .iter()
            .find(|p| p.value().token_hash == token_hash)
            .map(|p| p.key().clone())?;
        if self.disconnect_peer(&node_id, reason_code, message).await {
            Some(node_id)
        } else {
            None
        }
    }

    /// Subscribe to online/offline events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<PeerEvent> {
        self.events.subscribe()
    }

    /// Snapshot of every live session's device/connection metadata (M3 session tables).
    pub fn session_metas(&self) -> Vec<SessionMeta> {
        self.session_meta.iter().map(|e| e.value().clone()).collect()
    }

    /// Resolve an entrust word (en_xxx opaque ID) to its issuer node_id (federation P3 entrust
    /// mode; None = unknown word). Session-scoped like the delegated registry.
    pub fn entrust_resolve(&self, word: &str) -> Option<String> {
        self.entrust.get(word).map(|v| v.clone())
    }

    /// Resolve the downstream node for a target address (based on the advertised route table).
    pub fn resolve_peer(&self, host_or_ip: &str) -> Option<String> {
        let routes = self.routes.load();
        if let Ok(ip) = host_or_ip.parse::<IpAddr>() {
            return routes.cidrs.longest_match(ip).map(|(_, id)| id.clone());
        }
        let host = host_or_ip.to_lowercase();
        if let Some(id) = routes.hosts.get(&host) {
            return Some(id.clone());
        }
        for (suffix, id) in &routes.suffixes {
            if host.ends_with(suffix) {
                return Some(id.clone());
            }
        }
        None
    }

    /// Resolve a routing word against the delegated registries: local registry hints first
    /// (self-entry/direct mode — the issuer is this very node, so Some(None) = terminate
    /// locally), then the session-scoped entrust registry (en_xxx -> issuer node_id).
    /// None = no delegated route at all (caller falls back to the advertised route table).
    fn resolve_delegated_route(&self, word: &str) -> Option<Option<String>> {
        for entry in self.local_delegated.iter() {
            if entry.hint_map.iter().any(|h| h.hint == word) {
                return Some(None);
            }
        }
        self.entrust.get(word).map(|v| Some(v.clone()))
    }

    /// Start the listen service
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        self.serve(listener).await
    }

    /// Serve on a pre-bound socket (caller binds first so bind failures surface at startup, not in a spawned task).
    pub async fn serve(self: &Arc<Self>, listener: TcpListener) -> Result<()> {
        info!(addr = %self.listen_addr, "relay listener started");

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            // TCP mimicry + latency: browser HTTPS connections commonly set TCP_NODELAY (native tokio API, no socket2 needed)
            let _ = stream.set_nodelay(true);

            // concurrent connection cap: drop immediately when exceeded
            let current = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
            if current > self.max_connections {
                self.active_connections.fetch_sub(1, Ordering::Relaxed);
                warn!(peer = %peer_addr, "connection limit reached, dropping");
                drop(stream);
                continue;
            }

            // auth failure rate limit: drop when failures within the window exceed the cap (does not affect normal node reconnects)
            if self.is_auth_failure_limited(&peer_addr.ip()) {
                self.active_connections.fetch_sub(1, Ordering::Relaxed);
                warn!(peer = %peer_addr, "auth failure rate limit exceeded, dropping");
                drop(stream);
                continue;
            }

            let this = self.clone();
            tokio::spawn(async move {
                // auto-decrement the counter when the connection ends
                let _guard = ConnGuard(this.active_connections.clone());
                if let Err(err) = this.handle_connection(stream, peer_addr).await {
                    debug!(peer = %peer_addr, error = %err, "relay connection closed with error");
                }
            });
        }
    }

    /// Whether this IP is rate-limited for excessive auth failures.
    fn is_auth_failure_limited(&self, ip: &IpAddr) -> bool {
        let Some(entry) = self.auth_attempts.get(ip) else {
            return false;
        };
        let (count, window_start) = *entry.value();
        window_start.elapsed() <= Duration::from_secs(60)
            && count > self.max_auth_failures_per_minute
    }

    /// Record one auth failure.
    fn record_auth_failure(&self, ip: &IpAddr) {
        let mut entry = self.auth_attempts.entry(*ip).or_insert((0, Instant::now()));
        let (count, window_start) = entry.value_mut();
        if window_start.elapsed() > Duration::from_secs(60) {
            *count = 0;
            *window_start = Instant::now();
        }
        *count += 1;
    }

    /// Auth success: reset this IP's failure count.
    fn clear_auth_failures(&self, ip: &IpAddr) {
        self.auth_attempts.remove(ip);
    }

    /// Handle a single TCP connection (TLS handshake + auth + control loop)
    async fn handle_connection(
        self: &Arc<Self>,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        // pending-auth connection cap
        let pending = self.pending_auth.fetch_add(1, Ordering::Relaxed) + 1;
        if pending > self.max_pending_auth {
            self.pending_auth.fetch_sub(1, Ordering::Relaxed);
            return Err(Error::Protocol("too many pending auth connections".into()));
        }
        let _pending_guard = ConnGuard(self.pending_auth.clone());

        // time-box the whole TLS handshake + first-frame auth, anti-Slowloris
        let authed =
            tokio::time::timeout(AUTH_TIMEOUT, self.tls_handshake_and_auth(stream, peer_addr))
                .await
                .map_err(|_| Error::Timeout)??;

        let (tls_stream, identity, token_hash, peer_version, device_meta) = match authed {
            Some(v) => v,
            None => return Err(Error::Auth("authentication failed".into())),
        };
        drop(_pending_guard);

        let flow_control = peer_version >= PROTOCOL_VERSION_FLOW_CONTROL;
        // session-level bandwidth limit: build the token bucket once the identity is known (None = unlimited), injected into the mux with the session
        let limiter = self.session_limiter(&identity, &token_hash);
        match identity {
            AuthIdentity::Node {
                node_id,
                advertise,
                groups,
                acl,
                display,
                ..
            } => {
                self.serve_node_session(
                    tls_stream,
                    peer_addr,
                    node_id,
                    advertise,
                    groups,
                    token_hash,
                    flow_control,
                    acl,
                    limiter,
                    display,
                    device_meta,
                )
                .await
            }
            AuthIdentity::Delegated(identity) => {
                let session_key = delegated_session_key(&token_hash, &identity.node_id);
                self.serve_delegated_session(
                    tls_stream,
                    peer_addr,
                    session_key,
                    identity.acl,
                    token_hash,
                    flow_control,
                    limiter,
                    device_meta,
                )
                .await
            }
        }
    }

    /// TLS handshake and Auth frame validation. On failure, AuthFail has been sent and a delay penalty applied.
    async fn tls_handshake_and_auth(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<
        Option<(
            tokio_rustls::server::TlsStream<TcpStream>,
            AuthIdentity,
            String,
            u32,
            DeviceMeta,
        )>,
    > {
        let mut tls_stream = self.tls_acceptor.accept(stream).await?;
        debug!(peer = %peer_addr, "tls handshake completed");

        // active-probing mimicry: on first-frame read failure / non-Auth / malformed payload,
        // always reply 400 like nginx and close — never send the private AuthFail frame and
        // give ourselves away; legitimate clients' error path is unaffected (AuthOk/AuthFail frames flow as usual)
        let frame = match Frame::read_from(&mut tls_stream).await {
            Ok(f) => f,
            Err(e) => {
                write_fake_http_400(&mut tls_stream).await;
                return Err(Error::Io(e));
            }
        };
        if frame.frame_type != FrameType::Auth {
            write_fake_http_400(&mut tls_stream).await;
            return Err(Error::Protocol("expected Auth frame".into()));
        }

        let auth_req: AuthRequest = match serde_json::from_slice(&frame.payload) {
            Ok(r) => r,
            Err(e) => {
                write_fake_http_400(&mut tls_stream).await;
                return Err(Error::Protocol(format!("invalid auth payload: {e}")));
            }
        };

        // node ID length constraint, guards against malformed data
        if auth_req.node_id.is_empty() || auth_req.node_id.len() > 128 {
            write_fake_http_400(&mut tls_stream).await;
            return Err(Error::Protocol("invalid node_id".into()));
        }

        // Device identity proof (mandatory since handshake v4): the signature covers the
        // TLS-exporter challenge (RFC 5705, replay-bound to this session); device_fp is derived
        // from the presented pubkey — a wire-claimed fingerprint is never trusted. Failures get
        // the standard auth-failure penalty (rate limit + random delay), same as a bad token.
        let device_meta = match crate::device::session_challenge(tls_stream.get_ref().1)
            .ok()
            .and_then(|ch| auth_req.verify_device_proof(&ch))
        {
            Some((fp, pubkey)) => DeviceMeta {
                device_fp: fp,
                pubkey,
                my_name: auth_req.my_name.chars().take(64).collect(),
            },
            None => {
                warn!(peer = %peer_addr, node_id = %auth_req.node_id, "auth failed: invalid device proof");
                self.record_auth_failure(&peer_addr.ip());
                let delay_ms = 150 + rand::random::<u64>() % 250;
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let fail = FailReason {
                    reason_code: reason::DEVICE_PROOF_INVALID.into(),
                    message: String::new(),
                };
                let payload = serde_json::to_vec(&fail).unwrap_or_default();
                let _ = Frame::new(FrameType::AuthFail, 0, Bytes::from(payload))
                    .write_to(&mut tls_stream)
                    .await;
                return Ok(None);
            }
        };

        let token_hash = sha256_hex(auth_req.token.as_bytes());
        // node/relay tokens resolve through the injected validator hook; consumer auths
        // (kind = Client) fall through to the listener's own delegated token registries
        // (persistent local first, then session-scoped) with concurrency enforcement
        let identity = match self.validator.validate(&auth_req) {
            Some(identity) => Some(identity),
            None if auth_req.kind == AuthKind::Client => self.delegated_auth(&auth_req, &token_hash).await,
            None => None,
        };
        match identity {
            Some(identity) => {
                self.clear_auth_failures(&peer_addr.ip());
                let peer_version = auth_req.version;
                // handshake v2: push the control-plane endpoint when the downstream token carries the expose flag (old downstreams ignore unknown fields)
                let auth_ok = match &identity {
                    AuthIdentity::Node {
                        control: Some(offer),
                        ..
                    } => {
                        serde_json::json!({ "version": PROTOCOL_VERSION, "node_id": self.node_id, "control": offer })
                    }
                    _ => serde_json::json!({ "version": PROTOCOL_VERSION, "node_id": self.node_id }),
                };
                Frame::new(
                    FrameType::AuthOk,
                    0,
                    bytes::Bytes::from(auth_ok.to_string()),
                )
                .write_to(&mut tls_stream)
                .await?;
                Ok(Some((tls_stream, identity, token_hash, peer_version, device_meta)))
            }
            None => {
                warn!(peer = %peer_addr, node_id = %auth_req.node_id, "auth failed: bad token");
                self.record_auth_failure(&peer_addr.ip());
                // random 150-400ms delay to slow down online brute force
                let delay_ms = 150 + rand::random::<u64>() % 250;
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let fail = FailReason {
                    reason_code: reason::BAD_CREDENTIALS.into(),
                    message: String::new(),
                };
                let payload = serde_json::to_vec(&fail).unwrap_or_default();
                let _ = Frame::new(FrameType::AuthFail, 0, Bytes::from(payload))
                    .write_to(&mut tls_stream)
                    .await;
                Ok(None)
            }
        }
    }

    /// Node session: register the peer, load advertised routes and pushed groups, handle peer-initiated Open requests until disconnect.
    #[allow(clippy::too_many_arguments)]
    async fn serve_node_session(
        self: &Arc<Self>,
        tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        node_id: String,
        advertise: Vec<String>,
        groups: Vec<crate::proto::message::PushedGroupMsg>,
        token_hash: String,
        flow_control: bool,
        acl: Option<Arc<PeerAcl>>,
        limiter: Option<Arc<TokenBucket>>,
        display: Option<String>,
        device_meta: DeviceMeta,
    ) -> Result<()> {
        info!(peer = %peer_addr, node_id = %node_id, device = %device_meta.device_fp, "node authenticated successfully");

        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<OpenRequest>(64);
        let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        let (mux, reader_handle) = MuxSession::start(
            tls_stream,
            1,
            SessionEvents::open_and_ctrl(open_tx, ctrl_tx),
            flow_control,
            limiter,
        );

        // same-identity re-auth kicks the stale session (tolerates restart flapping; the hijack
        // boundary equals relay-token revocation — the token is the identity). The stale
        // session's delegated registrations die with it (federation P2, session-scoped).
        if let Some((_, old)) = self.peers.remove(&node_id) {
            info!(node = %node_id, "duplicate node session: kicking the stale one");
            Self::notify_and_shutdown(&old.mux, reason::SESSION_TAKEOVER, "").await;
            let stale: Vec<String> = self
                .delegated
                .iter()
                .filter(|e| e.value().issuer == node_id)
                .map(|e| e.key().clone())
                .collect();
            for hash in stale {
                self.delegated.remove(&hash);
                self.disconnect_delegated_token(&hash, reason::SESSION_TAKEOVER, "")
                    .await;
            }
            let _ = self.events.send(PeerEvent::NodeDisconnected {
                node_id: node_id.clone(),
            });
        }
        let session_id = new_session_id();
        self.session_meta.insert(
            session_id.clone(),
            SessionMeta {
                session_id: session_id.clone(),
                session_key: node_id.clone(),
                device_fp: device_meta.device_fp.clone(),
                pubkey: device_meta.pubkey.clone(),
                token_hash: token_hash.clone(),
                my_name: device_meta.my_name.clone(),
                peer_ip: peer_addr.ip().to_string(),
                connected_at: Instant::now(),
            },
        );
        self.peers.insert(
            node_id.clone(),
            PeerSession {
                node_id: node_id.clone(),
                mux: mux.clone(),
                token_hash,
                display: display.filter(|d| !d.trim().is_empty()).unwrap_or_else(|| node_id.clone()),
                device_fp: device_meta.device_fp,
                my_name: device_meta.my_name,
            },
        );
        self.set_peer_routes(&node_id, advertise);
        // Federation P1: pool the pushed policy groups (sanitized; cleared on disconnect)
        let groups = sanitize_pushed_groups(groups);
        if groups.is_empty() {
            self.peer_groups.remove(&node_id);
        } else {
            info!(node_id = %node_id, groups = groups.len(), "peer pushed policy groups (authorizable pool)");
            self.peer_groups.insert(node_id.clone(), groups);
        }
        let _ = self.events.send(PeerEvent::NodeConnected {
            node_id: node_id.clone(),
        });

        // handle this peer's Open requests until the connection drops
        // (open_tx is released when the reader task ends and recv returns None)
        // concurrency cap: on a peer Open flood every request would spawn a task and dial
        // out; beyond the cap reply OpenFail, guarding task/connection resources
        let open_permits = Arc::new(Semaphore::new(MAX_INBOUND_OPENS_PER_SESSION));
        loop {
            tokio::select! {
                req = open_rx.recv() => {
                    let Some(req) = req else { break };
                    let Ok(permit) = open_permits.clone().try_acquire_owned() else {
                        debug!(node = %node_id, channel = req.channel_id, "inbound open limit reached, rejecting");
                        let _ = mux
                            .send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                            .await;
                        continue;
                    };
                    let this = self.clone();
                    let mux = mux.clone();
                    let node_id = node_id.clone();
                    let acl = acl.clone();
                    tokio::spawn(async move {
                        let _permit = permit; // permit held by the task until the bridge ends
                        this.handle_node_open(mux, req, node_id, acl).await;
                    });
                }
                payload = ctrl_rx.recv() => {
                    let Some(payload) = payload else { break };
                    self.handle_node_ctrl(&mux, &node_id, &payload).await;
                }
            }
        }

        let _ = reader_handle.await;

        // cleanup ONLY if the registry still points at this session — a kicked stale session's
        // exit path must not strip the fresh session's routes / pushed groups / registrations
        self.session_meta.remove(&session_id);
        if self
            .peers
            .remove_if(&node_id, |_, p| Arc::ptr_eq(&p.mux, &mux))
            .is_some()
        {
            self.set_peer_routes(&node_id, Vec::new());
            self.peer_groups.remove(&node_id);
            // federation P2: delegated tokens die with their issuer session (revoke-by-disconnect);
            // kick every delegated client session they had authenticated
            let dead: Vec<String> = self
                .delegated
                .iter()
                .filter(|e| e.value().issuer == node_id)
                .map(|e| e.key().clone())
                .collect();
            for hash in dead {
                self.delegated.remove(&hash);
                self.disconnect_delegated_token(&hash, reason::ISSUER_OFFLINE, "")
                    .await;
            }
            // entrust words die with the issuer session too (same revoke-by-disconnect contract)
            self.entrust.retain(|_, v| v != &node_id);
        }
        let _ = self.events.send(PeerEvent::NodeDisconnected {
            node_id: node_id.clone(),
        });
        info!(node_id = %node_id, "peer disconnected");
        Ok(())
    }

    /// Handle a session control-plane message (federation P2): delegated token register/revoke,
    /// answered with a TokenAck. Malformed frames are logged and ignored (never fatal to the session).
    async fn handle_node_ctrl(self: &Arc<Self>, mux: &Arc<MuxSession>, node_id: &str, payload: &[u8]) {
        use crate::proto::message::CtrlMessage as C;
        let msg = match serde_json::from_slice::<C>(payload) {
            Ok(m) => m,
            Err(e) => {
                debug!(node = %node_id, error = %e, "malformed ctrl frame ignored");
                return;
            }
        };
        match msg {
            C::TokenRegister {
                token_hash,
                label,
                groups,
                hint_map,
                concurrency,
                max_sessions,
            } => {
                let (ok, error) = match self.register_delegated(
                    node_id,
                    &token_hash,
                    &label,
                    groups,
                    hint_map,
                    concurrency,
                    max_sessions,
                ) {
                    Ok(()) => {
                        info!(node = %node_id, label = %label, "delegated token registered");
                        let _ = self.events.send(PeerEvent::DelegationRegistered {
                            node_id: node_id.to_string(),
                            label,
                        });
                        (true, String::new())
                    }
                    Err(e) => {
                        warn!(node = %node_id, reason = %e, "delegated token registration rejected");
                        (false, e)
                    }
                };
                self.send_ctrl_ack(mux, token_hash, ok, error).await;
            }
            C::TokenRevoke {
                token_hash,
                reason_code,
                message,
                ..
            } => {
                if let Some(label) = self
                    .revoke_delegated(node_id, &token_hash, &reason_code, &message)
                    .await
                {
                    info!(node = %node_id, label = %label, "delegated token revoked");
                    let _ = self.events.send(PeerEvent::DelegationRevoked {
                        node_id: node_id.to_string(),
                        label,
                    });
                }
                self.send_ctrl_ack(mux, token_hash, true, String::new()).await;
            }
            C::TokenAck { .. } => {
                debug!(node = %node_id, "unexpected TokenAck from issuer ignored");
            }
            C::SessionNotice { .. } | C::PendingNote { .. } => {
                // SessionNotice flows TO the kicked peer; PendingNote flows from a pending
                // consumer to its issuer (the node crate's delegated console, M3) — neither is
                // meaningful on an issuer session at this relay
                debug!(node = %node_id, "unexpected session-notice/pending-note from issuer ignored");
            }
        }
    }

    async fn send_ctrl_ack(&self, mux: &Arc<MuxSession>, token_hash: String, ok: bool, error: String) {
        let ack = crate::proto::message::CtrlMessage::TokenAck {
            token_hash,
            ok,
            error,
        };
        if let Ok(p) = serde_json::to_vec(&ack) {
            let _ = mux.send_frame(Frame::new(FrameType::Ctrl, 0, Bytes::from(p))).await;
        }
    }

    /// Validate and register a delegated token (federation P2):
    /// - the token's groups are intersected with the issuer's pushed policy groups (an empty
    ///   register set means "all pushed groups"); an empty intersection is rejected — unless the
    ///   token carries entrust hints (en_ words, federation P3 entrust mode: routing without rule
    ///   disclosure; the issuer need not push anything, the declared groups are recorded verbatim
    ///   for observability and the transparent-tier ACL stays empty = fail closed)
    /// - every non-entrust hint must route back to this very issuer via the advertised route table
    ///   (a hint that routes nowhere — or to another peer — can never serve, fail closed);
    ///   entrust hints skip this check (self-minted opaque words, no other node's routes to steal)
    /// - one token_hash belongs to one issuer (a second issuer claiming it is rejected)
    /// - `max_sessions` must be in 1..=MAX_DELEGATED_SESSIONS
    #[allow(clippy::too_many_arguments)]
    fn register_delegated(
        &self,
        node_id: &str,
        token_hash: &str,
        label: &str,
        groups: Vec<String>,
        hint_map: Vec<crate::proto::message::HintEntry>,
        concurrency: Concurrency,
        max_sessions: u32,
    ) -> std::result::Result<(), String> {
        if token_hash.len() != 64 || !token_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid token_hash".into());
        }
        if label.len() > 128 {
            return Err("label too long".into());
        }
        if max_sessions == 0 || max_sessions > MAX_DELEGATED_SESSIONS {
            return Err("max_sessions out of range".into());
        }
        if let Some(existing) = self.delegated.get(token_hash)
            && existing.issuer != node_id
        {
            return Err("token_hash already registered by another issuer".into());
        }

        // entrust hints ride the opaque registry; regular hints keep the route-table validation
        let (entrust_hints, regular_hints): (Vec<_>, Vec<_>) = hint_map
            .iter()
            .partition(|h| h.hint.starts_with(crate::relay::e2e::ENTRUST_PREFIX));

        // intersect the token's groups with the issuer's pushed pool; empty set = all pushed
        let pushed = self
            .peer_groups
            .get(node_id)
            .map(|v| v.clone())
            .unwrap_or_default();
        let wanted: Vec<_> = if groups.is_empty() {
            pushed.iter().collect()
        } else {
            pushed.iter().filter(|g| groups.contains(&g.name)).collect()
        };
        let mut names = Vec::with_capacity(wanted.len());
        let mut rules: Vec<String> = Vec::new();
        if wanted.is_empty() {
            if entrust_hints.is_empty() {
                return Err("no known groups (push policy groups before registering)".into());
            }
            // entrust mode: nothing pushed — record the declared groups verbatim (capped) for
            // observability; acl_rules stays empty so transparent opens fail closed at this relay
            names = groups
                .into_iter()
                .filter(|g| !g.trim().is_empty() && g.len() <= MAX_PUSHED_GROUP_NAME)
                .take(MAX_PUSHED_GROUPS)
                .collect();
        } else {
            for g in &wanted {
                names.push(g.name.clone());
                for r in &g.rules {
                    if !rules.contains(r) {
                        rules.push(r.clone());
                    }
                }
            }
        }

        // regular hints must resolve to this issuer over the advertised route table
        for h in &regular_hints {
            if self.resolve_peer(&h.hint).as_deref() != Some(node_id) {
                return Err(format!("hint '{}' does not route to this issuer", h.hint));
            }
        }

        // entrust hints: insert into the opaque registry (per-issuer cap — anti-flood)
        if !entrust_hints.is_empty() {
            let current = self
                .entrust
                .iter()
                .filter(|e| e.value() == node_id)
                .count();
            if current + entrust_hints.len() > MAX_ENTRUST_PER_ISSUER {
                return Err("entrust registry capacity exceeded for this issuer".into());
            }
            for h in &entrust_hints {
                // one en_ word one issuer: a different issuer's re-registration is rejected, just
                // like token_hash (deterministic derivation makes cross-issuer collision impossible
                // in practice; the guard keeps a malicious issuer from squatting another's word)
                if let Some(existing) = self.entrust.get(&h.hint)
                    && existing.value() != node_id
                {
                    return Err(format!("entrust id '{}' already registered by another issuer", h.hint));
                }
                self.entrust.insert(h.hint.clone(), node_id.to_string());
            }
        }

        self.delegated.insert(
            token_hash.to_string(),
            DelegatedToken {
                issuer: node_id.to_string(),
                label: label.to_string(),
                groups: names,
                acl_rules: rules,
                hint_map,
                concurrency,
                max_sessions,
            },
        );
        Ok(())
    }

    /// Drop a delegated token (issuer-scoped) and kick the consumer sessions it authenticated
    /// (a SessionNotice with the revoke reason + one-time message precedes each close).
    /// Returns the label for audit when a registration existed.
    async fn revoke_delegated(&self, node_id: &str, token_hash: &str, reason_code: &str, message: &str) -> Option<String> {
        let (hash, tok) = self
            .delegated
            .remove_if(token_hash, |_, v| v.issuer == node_id)?;
        // entrust words of this token leave the opaque registry with it
        for h in &tok.hint_map {
            if h.hint.starts_with(crate::relay::e2e::ENTRUST_PREFIX) {
                self.entrust.remove_if(&h.hint, |_, v| v == node_id);
            }
        }
        let label = tok.label;
        // an issuer-initiated revoke without an explicit reason defaults to an admin revoke
        let rc = if reason_code.is_empty() {
            reason::REVOKED_BY_ADMIN
        } else {
            reason_code
        };
        self.disconnect_delegated_token(&hash, rc, message).await;
        Some(label)
    }

    /// Delegated consumer session: handle inbound Open requests (ACL + downstream routing + direct connect).
    #[allow(clippy::too_many_arguments)]
    async fn serve_delegated_session(
        self: &Arc<Self>,
        tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        session_key: String,
        acl: Vec<String>,
        token_hash: String,
        flow_control: bool,
        limiter: Option<Arc<TokenBucket>>,
        device_meta: DeviceMeta,
    ) -> Result<()> {
        info!(peer = %peer_addr, session = %session_key, device = %device_meta.device_fp, "delegated consumer authenticated successfully");

        // Hot ACL state: the router is rebuilt in place whenever the token's registry snapshot
        // changes (rule edits / revocation take effect on live sessions, no reconnect needed).
        let acl_router = build_acl_router(&acl);
        let acl_state = Arc::new(arc_swap::ArcSwap::from_pointee((acl, acl_router)));
        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<OpenRequest>(64);
        let (mux, reader_handle) =
            MuxSession::start(tls_stream, 1, SessionEvents::open(open_tx), flow_control, limiter);

        self.clients
            .entry(session_key.clone())
            .or_default()
            .push(mux.clone());
        let session_id = new_session_id();
        self.session_meta.insert(
            session_id.clone(),
            SessionMeta {
                session_id: session_id.clone(),
                session_key: session_key.clone(),
                device_fp: device_meta.device_fp,
                pubkey: device_meta.pubkey,
                token_hash: token_hash.clone(),
                my_name: device_meta.my_name,
                peer_ip: peer_addr.ip().to_string(),
                connected_at: Instant::now(),
            },
        );
        let _ = self.events.send(PeerEvent::ClientConnected {
            session_key: session_key.clone(),
        });

        // handle this consumer's Open requests until the connection drops
        // (open_tx is released when the reader task ends and recv returns None)
        // concurrency cap: same as node sessions, guards against peer Open floods exhausting task/connection resources
        let open_permits = Arc::new(Semaphore::new(MAX_INBOUND_OPENS_PER_SESSION));
        while let Some(req) = open_rx.recv().await {
            let Ok(permit) = open_permits.clone().try_acquire_owned() else {
                debug!(session = %session_key, channel = req.channel_id, "inbound open limit reached, rejecting");
                let _ = mux
                    .send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                    .await;
                continue;
            };
            let this = self.clone();
            let mux = mux.clone();
            let acl_state = acl_state.clone();
            let token_hash = token_hash.clone();
            tokio::spawn(async move {
                let _permit = permit; // permit held by the task until the bridge ends
                this.handle_delegated_open(mux, req, acl_state, token_hash).await;
            });
        }

        let _ = reader_handle.await;
        // remove this session from the session table (may already have been cleared by disconnect_client)
        self.session_meta.remove(&session_id);
        if let Some(mut sessions) = self.clients.get_mut(&session_key) {
            sessions.retain(|m| !Arc::ptr_eq(m, &mux));
            let empty = sessions.is_empty();
            drop(sessions);
            if empty {
                self.clients.remove(&session_key);
            }
        }
        let _ = self.events.send(PeerEvent::ClientDisconnected {
            session_key: session_key.clone(),
        });
        info!(session = %session_key, "delegated consumer disconnected");
        Ok(())
    }

    /// Handle a consumer Open: hot ACL refresh -> ACL check -> group stamp (kept only towards
    /// the issuer hop, see route_open) -> routing, then bridge.
    async fn handle_delegated_open(
        self: &Arc<Self>,
        mux: Arc<MuxSession>,
        req: OpenRequest,
        acl_state: Arc<arc_swap::ArcSwap<(Vec<String>, Arc<ProxyRouter>)>>,
        token_hash: String,
    ) {
        // Re-resolve the token registration per open: rule edits refresh the router in place,
        // a vanished registration (revoked / issuer session gone) fails closed at once.
        let Some(entry) = self.resolve_delegated_token(&token_hash) else {
            warn!(session = %token_hash, "delegated token registration gone, denying open");
            let _ = mux
                .send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                .await;
            return;
        };
        let issuer = entry.issuer.clone();
        let groups = entry.groups.clone();
        let hints: Vec<String> = entry.hint_map.iter().map(|h| h.hint.clone()).collect();
        let fresh_acl = delegated_acl_of(&entry);
        if acl_state.load().0 != fresh_acl {
            let router = build_acl_router(&fresh_acl);
            acl_state.store(Arc::new((fresh_acl, router)));
        }
        let acl_router = acl_state.load().1.clone();

        let open_req: OpenChannel = match serde_json::from_slice(&req.payload) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "invalid open payload from consumer");
                let _ = mux
                    .send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                    .await;
                return;
            }
        };

        let target = format!("{}:{}", open_req.target_addr, open_req.target_port);

        // ACL: the target must hit the token's rule snapshot
        // (the snapshot covers transparent rules plus the hint vocabulary)
        if !acl_router.matches_target(&target) {
            warn!(target = %target, "delegated open denied by ACL");
            let _ = mux
                .send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                .await;
            return;
        }

        // federation P2: stamp the Open with the token's group tags for the issuer's per-group
        // enforcement — route_open drops the stamp again unless the next hop is the issuer
        // session itself. E2E envelopes pass through blind (kid/hint consistency checked)
        let mut open_req = open_req;
        match &open_req.e2e {
            Some(e2e) => {
                // kid is an exact 12-hex match against the session's token hash
                if e2e.kid != crate::relay::e2e::kid_of(&token_hash)
                    || e2e.hint != open_req.target_addr
                    || !hints.contains(&open_req.target_addr)
                {
                    warn!(target = %target, "delegated e2e open rejected (kid/hint mismatch)");
                    let _ = mux
                        .send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                        .await;
                    return;
                }
                open_req.groups = Vec::new(); // group tags travel sealed inside the blob
            }
            None => {
                open_req.groups = groups.clone();
            }
        }

        // consumer traffic is metered issuer-side; transit pairs skip duplicate metering (from = None)
        self.route_open(mux, req, open_req, target, None, Some(&issuer))
            .await;
    }

    /// Handle a fan-in peer Open: PeerAcl restriction -> downstream routing -> direct connect, then bridge.
    async fn handle_node_open(
        self: &Arc<Self>,
        mux: Arc<MuxSession>,
        req: OpenRequest,
        node_id: String,
        acl: Option<Arc<PeerAcl>>,
    ) {
        let open_req: OpenChannel = match serde_json::from_slice(&req.payload) {
            Ok(v) => v,
            Err(e) => {
                warn!(node = %node_id, error = %e, "invalid open payload from peer");
                let _ = mux
                    .send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                    .await;
                return;
            }
        };

        let target = format!("{}:{}", open_req.target_addr, open_req.target_port);

        // bandwidth-diagnostic reserved address: intercept before the PeerAcl restriction check
        // (protocol-level diagnostic service, same tier as heartbeat; answered locally,
        // no routing capability, restricted nodes equally testable, not an ACL bypass)
        if crate::relay::bandwidth::intercept(&mux, &req, &open_req.target_addr).await {
            return;
        }

        // fan-in restriction: with a restriction table, targets must hit the allowlist (None = unrestricted, allow all)
        if let Some(acl) = &acl
            && !acl.allowed(&target)
        {
            warn!(node = %node_id, target = %target, "peer open denied by ACL");
            let _ = self.events.send(PeerEvent::AclDenied {
                peer_label: node_id.clone(),
                target: target.clone(),
            });
            let _ = mux
                .send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                .await;
            return;
        }

        // transit metering: fan-in peer-initiated forwards booked with from=node_id
        self.route_open(mux, req, open_req, target, Some(&node_id), None)
            .await;
    }

    /// Open routing and bridging: prefer downstream-node advertised routes, else local direct connect.
    /// The Open payload is forwarded verbatim (group tags / E2E envelopes pass through, keeping
    /// multi-hop federation chains transparent end to end).
    /// `from` is the transit-metering source label (fan-in peer node_id; None = no metering).
    async fn route_open(
        self: &Arc<Self>,
        mux: Arc<MuxSession>,
        req: OpenRequest,
        mut open_req: OpenChannel,
        target: String,
        from: Option<&str>,
        delegated_issuer: Option<&str>,
    ) {
        let channel = mux.accept_channel(req.channel_id);
        let meter_from = self.transit.clone().zip(from.map(str::to_string));

        // routing resolution order: persistent local delegated hints (self-entry — the issuer
        // is this very node, terminate locally) -> session-scoped entrust words (en_xxx ->
        // issuer peer) -> advertised route table; no match = local direct connect
        let routed_peer = match self.resolve_delegated_route(&open_req.target_addr) {
            Some(peer) => peer,
            None => self.resolve_peer(&open_req.target_addr),
        };
        // Unified issuance: a group stamp is issuer-local ACL metadata, kept only while the next
        // hop is the token's issuer session (rendezvous forwarding back to the issuer). Once the
        // trust boundary terminates here (direct issuer / any other hop), the onward Open is this
        // node's own and travels clean — foreign group names would fail-close or forgery-kill at
        // downstream delegation hooks.
        if let Some(issuer) = delegated_issuer
            && routed_peer.as_deref() != Some(issuer)
        {
            open_req.groups.clear();
        }
        let bridged = if let Some(peer_id) = routed_peer {
            match self.open_channel_full(&peer_id, &open_req).await {
                Ok(peer_channel) => {
                    if mux
                        .send_frame(Frame::empty(FrameType::OpenOk, req.channel_id))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    // bridge(channel, peer): up = source->destination (downstream peer)
                    if let Ok((up, down)) = crate::relay::bridge::bridge(channel, peer_channel).await
                        && let Some((m, f)) = &meter_from
                    {
                        m.record(f, &peer_id, up, down);
                    }
                    true
                }
                Err(e) => {
                    debug!(peer = %peer_id, error = %e, "open via downstream peer failed");
                    false
                }
            }
        } else {
            match TcpStream::connect(&target).await {
                Ok(local) => {
                    if mux
                        .send_frame(Frame::empty(FrameType::OpenOk, req.channel_id))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    // bridge(channel, local): up = source->destination (locally terminated)
                    if let Ok((up, down)) = crate::relay::bridge::bridge(channel, local).await
                        && let Some((m, f)) = &meter_from
                    {
                        m.record(f, TO_LOCAL, up, down);
                    }
                    true
                }
                Err(e) => {
                    debug!(target = %target, error = %e, "direct connect failed");
                    false
                }
            }
        };

        if !bridged {
            let _ = mux
                .send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                .await;
        }
        mux.close_channel(req.channel_id);
    }

    /// Update a downstream node's advertised routes and rebuild the aggregate table.
    fn set_peer_routes(&self, node_id: &str, entries: Vec<String>) {
        if entries.is_empty() {
            self.peer_advertise.remove(node_id);
        } else {
            self.peer_advertise.insert(node_id.to_string(), entries);
        }
        self.rebuild_routes();
    }

    fn rebuild_routes(&self) {
        let mut table = AdvertisedRoutes::default();
        for item in self.peer_advertise.iter() {
            let (node_id, entries) = (item.key(), item.value());
            for entry in entries {
                let entry = entry.trim();
                if entry.is_empty() || entry.len() > 256 {
                    continue;
                }
                if let Ok(cidr) = entry.parse::<IpNetwork>() {
                    table.cidrs.insert(cidr, node_id.clone());
                } else if entry.contains('*') {
                    let suffix = entry.trim_start_matches('*').to_lowercase();
                    if !suffix.is_empty() {
                        table.suffixes.push((suffix, node_id.clone()));
                    }
                } else {
                    table.hosts.insert(entry.to_lowercase(), node_id.clone());
                }
            }
        }
        // longest suffix first
        table.suffixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        self.routes.store(Arc::new(table));
    }

    /// Initiate a new connection request to the given node (plain Open; wrapper of `open_channel_full`).
    pub async fn open_channel(
        &self,
        node_id: &str,
        target_addr: &str,
        target_port: u16,
    ) -> Result<MuxChannel> {
        self.open_channel_full(node_id, &OpenChannel::new(target_addr, target_port))
            .await
    }

    /// Initiate a new connection request to the given node, forwarding the Open payload verbatim
    /// (federation P2/P3: group tags and E2E envelopes are preserved across hops).
    pub async fn open_channel_full(&self, node_id: &str, open: &OpenChannel) -> Result<MuxChannel> {
        let peer = self
            .peers
            .get(node_id)
            .ok_or_else(|| Error::NotFound(format!("peer node {node_id} not connected")))?;

        let payload = serde_json::to_vec(open).map_err(|e| Error::Protocol(e.to_string()))?;

        peer.mux.open_channel(Bytes::from(payload)).await
    }
}

/// Connection count guard: auto-decrements on drop.
struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Consumer-session key of a delegated token (unified issuance): sessions authenticated by a
/// delegated token are tracked/kicked under `delegated:<token_hash>:<node_id>` — one token may
/// hold several concurrent consumer sessions (multi policy), distinguished by consumer node_id.
pub fn delegated_session_key(token_hash: &str, node_id: &str) -> String {
    format!("delegated:{token_hash}:{node_id}")
}

/// Key prefix covering every consumer session of one delegated token (any node_id).
fn delegated_session_prefix(token_hash: &str) -> String {
    format!("delegated:{token_hash}:")
}

/// Unique per-session id (session metadata tables; M3 session management).
fn new_session_id() -> String {
    format!("sess_{:012x}", rand::random::<u64>() & 0xffff_ffff_ffff)
}

/// Effective ACL vocabulary of a delegated token: transparent rules plus the hint words.
fn delegated_acl_of(entry: &DelegatedToken) -> Vec<String> {
    let mut acl = entry.acl_rules.clone();
    acl.extend(entry.hint_map.iter().map(|h| h.hint.clone()));
    acl
}

/// Compile ACL rule strings into a ProxyRouter (a hit means allowed).
pub fn build_acl_router(rules: &[String]) -> Arc<ProxyRouter> {
    let mut router = ProxyRouter::new();
    for rule in rules {
        let rule = rule.trim();
        if rule.is_empty() || rule.len() > 256 {
            continue;
        }
        if rule.parse::<IpNetwork>().is_ok() {
            let _ = router.add_cidr(rule, Outbound::Direct);
        } else if rule.contains('*') {
            router.add_host_suffix(rule, Outbound::Direct);
        } else {
            router.add_host_exact(rule, Outbound::Direct);
        }
    }
    Arc::new(router)
}

/// Active-probing mimicry response: emulates nginx `400 Bad Request` (inside TLS, matching a
/// real HTTPS server's behavior) instead of the private-protocol AuthFail frame. The caller
/// closes/drops the connection; auth-failure rate limiting and delay penalties are unaffected.
async fn write_fake_http_400<S>(stream: &mut S)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    const RESP: &[u8] = b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let _ = stream.write_all(RESP).await;
    let _ = stream.shutdown().await;
}
