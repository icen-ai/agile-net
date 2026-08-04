//! Relay Connector — downstream role, actively connects upstream
//!
//! Connects to the upstream Listener, completes the TLS handshake and Auth,
//! maintains heartbeats (30s +/- 5s random jitter), declares the connection dead
//! after 90s without response, auto-reconnects with exponential backoff + jitter,
//! and answers Open frames to set up forwarding.

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::{
    AuthKind, AuthRequest, ControlOffer, CtrlMessage, OpenChannel, PROTOCOL_VERSION,
    PROTOCOL_VERSION_FLOW_CONTROL, PushedGroupMsg,
};
use crate::proxy::router::{Outbound, ProxyRouter};
use crate::relay::acl::PeerAcl;
use crate::relay::bridge::bridge;
use crate::relay::listener::{AUTH_TIMEOUT, PeerEvent, RelayListener};
use crate::relay::mux::{MuxChannel, MuxSession, OpenRequest, SessionEvents};
use crate::relay::transit::{TO_LOCAL, TransitMeter};
use crate::tunnel::opener::ChannelOpener;
use crate::tunnel::tls::TlsConfigBuilder;

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Notify, broadcast, mpsc};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

/// Heartbeat base interval (actually 25s + 0-10s random, mimicking natural HTTPS behavior).
/// Heartbeat timeout: no frame from the peer for longer than this means the connection is dead.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Reconnect backoff cap.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Reconnecting = 3,
}

impl From<u8> for ConnectionState {
    fn from(v: u8) -> Self {
        match v {
            1 => ConnectionState::Connecting,
            2 => ConnectionState::Connected,
            3 => ConnectionState::Reconnecting,
            _ => ConnectionState::Disconnected,
        }
    }
}

/// Relay connector.
pub struct RelayConnector {
    upstream_addr: SocketAddr,
    node_id: String,
    token: String,
    tls_connector: TlsConnector,
    sni_hostname: String,
    /// Listener through which this node routes to **downstream** (chained forwarding in multi-hop chains)
    peer_router: Option<Arc<RelayListener>>,
    /// Serviceable CIDRs/domains advertised upstream (static config)
    advertise: Vec<String>,
    /// Policy groups pushed upstream at auth (federation P1; hot-swappable slot —
    /// a change triggers a reconnect to re-push, same pattern as route re-advertise)
    push_groups: Arc<arc_swap::ArcSwap<Vec<PushedGroupMsg>>>,
    /// Handshake v2: management endpoint pushed by the upstream when it exposes a control plane
    control: Arc<arc_swap::ArcSwapOption<ControlOffer>>,
    /// Route re-advertise: client-tunnel merged routes (rules resold downstream, via=client tunnel)
    client_router: Option<Arc<arc_swap::ArcSwap<ProxyRouter>>>,
    /// Route re-advertise: node_id -> client tunnel opener
    openers: Option<Arc<dashmap::DashMap<String, Arc<dyn ChannelOpener>>>>,
    /// Fan-out restriction: allowlist for peer-initiated reverse target connections (None = unrestricted, allow all)
    acl: Option<Arc<PeerAcl>>,
    /// Current session mux handle (available while connected; used by control-plane diagnostics to open streams)
    current_mux: Arc<arc_swap::ArcSwapOption<MuxSession>>,
    /// Negotiated upstream protocol version (0 = not connected / unknown; gates v3 delegation features)
    upstream_version: Arc<AtomicU32>,
    /// Federation P2: latest registration/revocation ack per delegated token hash (control plane replies)
    delegation_acks: Arc<dashmap::DashMap<String, (bool, String)>>,
    /// Relay transit metering (meter + source label = connector name; reverse flows from upstream booked with from=this label)
    transit: Option<(Arc<TransitMeter>, String)>,
    /// Observable events such as restriction denials (subscribed by the control plane for audit)
    events: broadcast::Sender<PeerEvent>,
    state: Arc<AtomicU8>,
    shutdown_notify: Arc<Notify>,
    shutdown_flag: Arc<AtomicBool>,
}

impl RelayConnector {
    /// Create a new RelayConnector (dev mode: no certificate verification).
    ///
    /// In production use `with_tls_builder` to configure a CA or certificate pinning.
    pub fn new(
        upstream_addr: SocketAddr,
        node_id: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self> {
        Self::with_tls_builder(
            upstream_addr,
            node_id,
            token,
            TlsConfigBuilder::new().allow_self_signed(true),
        )
    }

    /// Create with a custom TLS config.
    pub fn with_tls_builder(
        upstream_addr: SocketAddr,
        node_id: impl Into<String>,
        token: impl Into<String>,
        tls_builder: TlsConfigBuilder,
    ) -> Result<Self> {
        let client_config = tls_builder.build_client()?;
        let tls_connector = TlsConnector::from(client_config);
        let (events, _) = broadcast::channel(256);

        Ok(Self {
            upstream_addr,
            node_id: node_id.into(),
            token: token.into(),
            tls_connector,
            sni_hostname: tls_builder.sni_hostname,
            peer_router: None,
            advertise: Vec::new(),
            push_groups: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            control: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
            client_router: None,
            openers: None,
            acl: None,
            current_mux: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
            upstream_version: Arc::new(AtomicU32::new(0)),
            delegation_acks: Arc::new(dashmap::DashMap::new()),
            transit: None,
            events,
            state: Arc::new(AtomicU8::new(ConnectionState::Disconnected as u8)),
            shutdown_notify: Arc::new(Notify::new()),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Set the downstream routing Listener (Open requests can be forwarded further downstream in multi-hop chains).
    pub fn with_peer_router(mut self, listener: Arc<RelayListener>) -> Self {
        self.peer_router = Some(listener);
        self
    }

    /// Set the CIDR/domain list advertised upstream.
    pub fn with_advertise(mut self, advertise: Vec<String>) -> Self {
        self.advertise = advertise;
        self
    }

    /// Federation P1: inject the pushed-policy-group slot (shared with the control plane;
    /// updates land at the next reconnect, and the run loop reconnects on change to re-push).
    pub fn with_push_groups(mut self, slot: Arc<arc_swap::ArcSwap<Vec<PushedGroupMsg>>>) -> Self {
        self.push_groups = slot;
        self
    }

    /// Route re-advertise: inject the client engine's merged routes and opener registry.
    ///
    /// Effect: client tunnel rules are merged into the advertise set at handshake;
    /// Open requests hitting these rules are forwarded via the matching client tunnel
    /// (rule via=client tunnel); rule-set changes trigger an automatic reconnect to
    /// re-advertise (reconnect is the refresh — no new frame type, fully compatible with old upstreams).
    pub fn with_client_routes(
        mut self,
        router: Arc<arc_swap::ArcSwap<ProxyRouter>>,
        openers: Arc<dashmap::DashMap<String, Arc<dyn ChannelOpener>>>,
    ) -> Self {
        self.client_router = Some(router);
        self.openers = Some(openers);
        self
    }

    /// Handshake v2: control-plane endpoint exposed by the upstream (None when not exposed / not connected).
    pub fn control_offer(&self) -> Option<ControlOffer> {
        self.control.load_full().map(|a| (*a).clone())
    }

    /// Current session's mux handle (None when not connected).
    pub fn current_mux(&self) -> Option<Arc<MuxSession>> {
        self.current_mux.load_full()
    }

    /// Current session traffic (egress bytes, ingress bytes); (0, 0) when not connected.
    pub fn traffic(&self) -> (u64, u64) {
        self.current_mux
            .load_full()
            .map(|m| m.traffic())
            .unwrap_or((0, 0))
    }

    /// Attach the relay transit meter (reverse flows from upstream booked with from=`from_label`, the connector name).
    pub fn with_transit_meter(mut self, meter: Arc<TransitMeter>, from_label: String) -> Self {
        self.transit = Some((meter, from_label));
        self
    }

    /// Open a stream to the given target through the current tunnel (control-plane diagnostics; NotFound when not connected).
    pub async fn open_stream(&self, target_addr: &str, target_port: u16) -> Result<MuxChannel> {
        let mux = self
            .current_mux()
            .ok_or_else(|| Error::NotFound("connector not connected".into()))?;
        let payload = serde_json::to_vec(&OpenChannel::new(target_addr, target_port))
            .map_err(|e| Error::Protocol(e.to_string()))?;
        mux.open_channel(Bytes::from(payload)).await
    }

    /// Fan-out restriction: set the allowlist for peer-initiated reverse target connections (None = unrestricted, allow all).
    pub fn with_acl(mut self, acl: Option<Arc<PeerAcl>>) -> Self {
        self.acl = acl;
        self
    }

    /// Subscribe to observable events such as restriction denials (control plane writes audit).
    pub fn subscribe_events(&self) -> broadcast::Receiver<PeerEvent> {
        self.events.subscribe()
    }

    /// Current effective advertise set = static config + client tunnel rule values (route re-advertise).
    fn effective_advertise(&self) -> Vec<String> {
        let mut set: std::collections::BTreeSet<String> = self.advertise.iter().cloned().collect();
        if let Some(r) = &self.client_router {
            set.extend(r.load().rule_values());
        }
        set.into_iter().collect()
    }

    pub fn upstream_addr(&self) -> SocketAddr {
        self.upstream_addr
    }

    pub fn state(&self) -> ConnectionState {
        self.state.load(Ordering::Relaxed).into()
    }

    pub fn is_connected(&self) -> bool {
        self.state() == ConnectionState::Connected
    }

    /// Negotiated upstream protocol version of the current session (0 = not connected / unknown).
    /// Federation P2 delegation features (Ctrl-frame token register/revoke) require
    /// `>= PROTOCOL_VERSION_DELEGATION` — the issuer must stay silent towards older upstreams.
    pub fn upstream_version(&self) -> u32 {
        self.upstream_version.load(Ordering::Relaxed)
    }

    /// Latest delegation ack for a token hash ((ok, error); consumed by the re-registration task).
    pub fn delegation_ack(&self, token_hash: &str) -> Option<(bool, String)> {
        self.delegation_acks.get(token_hash).map(|v| v.clone())
    }

    /// Reset the ack table (called before re-registering a fresh session, so stale acks of a
    /// previous session are never attributed to the new one).
    pub fn clear_delegation_acks(&self) {
        self.delegation_acks.clear();
    }

    /// Single connection: TLS handshake + auth + spawn the session maintenance task.
    ///
    /// Returns once connected; the state flips to Disconnected when the session drops
    /// (no auto-reconnect — use `run` for that).
    pub async fn connect(&self) -> Result<()> {
        self.connect_once().await.map(|_| ())
    }

    /// Establish one connection and spawn the background maintenance task; returns the session handle.
    async fn connect_once(&self) -> Result<Arc<MuxSession>> {
        self.state
            .store(ConnectionState::Connecting as u8, Ordering::Relaxed);

        let session = match tokio::time::timeout(AUTH_TIMEOUT, self.handshake()).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.state
                    .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
                return Err(e);
            }
            Err(_) => {
                self.state
                    .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
                return Err(Error::Timeout);
            }
        };

        // publish the current session handle (for control-plane diagnostic streams), then mark Connected
        self.current_mux.store(Some(session.clone()));
        self.state
            .store(ConnectionState::Connected as u8, Ordering::Relaxed);
        Ok(session)
    }

    /// TLS handshake + Auth + spawn the session maintenance task.
    async fn handshake(&self) -> Result<Arc<MuxSession>> {
        let tcp_stream = TcpStream::connect(self.upstream_addr).await?;
        // TCP mimicry + latency: browser HTTPS connections commonly set TCP_NODELAY (native tokio API)
        let _ = tcp_stream.set_nodelay(true);
        let server_name = rustls::pki_types::ServerName::try_from(self.sni_hostname.clone())
            .map_err(|e| Error::Tls(e.to_string()))?;

        let mut tls_stream = self.tls_connector.connect(server_name, tcp_stream).await?;
        debug!(upstream = %self.upstream_addr, "tls connected to upstream");

        // send the Auth frame (advertise set = static + re-advertised client tunnel rules; groups = pushed policy slot)
        let auth_req = AuthRequest {
            node_id: self.node_id.clone(),
            token: self.token.clone(),
            kind: AuthKind::Node,
            advertise: self.effective_advertise(),
            groups: self.push_groups.load().as_ref().clone(),
            version: PROTOCOL_VERSION,
        };
        let payload = serde_json::to_vec(&auth_req).map_err(|e| Error::Protocol(e.to_string()))?;
        Frame::new(FrameType::Auth, 0, Bytes::from(payload))
            .write_to(&mut tls_stream)
            .await?;

        // read the Auth reply
        let res_frame = Frame::read_from(&mut tls_stream).await?;
        let mut server_version = 1u32;
        match res_frame.frame_type {
            FrameType::AuthOk => {
                info!(upstream = %self.upstream_addr, "authenticated successfully with upstream");
                // server version (AuthOk payload {"version":N}, defaults to 1) + optional control-plane endpoint
                if !res_frame.payload.is_empty()
                    && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&res_frame.payload)
                {
                    server_version = v["version"].as_u64().unwrap_or(1) as u32;
                    if let Some(cv) = v.get("control") {
                        match serde_json::from_value::<ControlOffer>(cv.clone()) {
                            Ok(mut offer) => {
                                // fall back to the connector's configured upstream address when the upstream did not enroll one
                                if offer.api_host.is_none() {
                                    offer.api_host = Some(self.upstream_addr.ip().to_string());
                                }
                                info!(
                                    upstream = %self.upstream_addr,
                                    node = %offer.node_name,
                                    api = %format!("{}:{}", offer.api_host.as_deref().unwrap_or("?"), offer.api_port),
                                    scope = %offer.scope,
                                    "upstream exposes control plane (manageable)"
                                );
                                self.control.store(Some(Arc::new(offer)));
                            }
                            Err(e) => {
                                debug!(error = %e, "ignore malformed control offer");
                            }
                        }
                    } else {
                        self.control.store(None);
                    }
                }
            }
            FrameType::AuthFail => {
                return Err(Error::Auth("upstream rejected authentication token".into()));
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected frame during auth: {other:?}"
                )));
            }
        }

        // flow control negotiation: enable per-channel window flow control when both sides are >= v2
        let flow_control = server_version >= PROTOCOL_VERSION_FLOW_CONTROL;
        // publish the negotiated version (gates v3 delegation: Ctrl-frame token register/revoke)
        self.upstream_version.store(server_version, Ordering::Relaxed);
        debug!(
            server_version,
            flow_control, "mux session flow control negotiated"
        );

        let (open_tx, mut open_rx) = mpsc::channel::<OpenRequest>(64);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Bytes>(64);
        // no session rate limiting on the connector side (limits are injected by the listener per identity)
        let (mux, reader_handle) = MuxSession::start(
            tls_stream,
            2,
            SessionEvents::open_and_ctrl(open_tx, ctrl_tx),
            flow_control,
            None,
        );

        // background maintenance loop: heartbeat (with jitter), idle timeout detection, Open channel requests
        let shutdown_notify = self.shutdown_notify.clone();
        let shutdown_flag = self.shutdown_flag.clone();
        let state = self.state.clone();
        let peer_router = self.peer_router.clone();
        let client_router = self.client_router.clone();
        let openers = self.openers.clone();
        let acl = self.acl.clone();
        let events = self.events.clone();
        let transit = self.transit.clone();
        let peer_label = self.upstream_addr.to_string();
        let mux_task = mux.clone();
        let current_mux = self.current_mux.clone();
        let upstream_version = self.upstream_version.clone();
        let delegation_acks = self.delegation_acks.clone();

        tokio::spawn(async move {
            let mut ping_timeout = next_ping_delay();
            let mut last_ping = std::time::Instant::now();
            let mut ping_timer = tokio::time::interval(Duration::from_secs(5));
            ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = shutdown_notify.notified() => {
                        info!("connector shutdown requested");
                        let _ = mux_task.send_frame(Frame::empty(FrameType::Close, 0)).await;
                        break;
                    }
                    _ = ping_timer.tick() => {
                        // backstop check of the shutdown flag (guards against a missed notify wakeup race)
                        if shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        // idle timeout: no frame from the peer for 90s -> connection considered dead
                        if mux_task.is_idle_beyond(IDLE_TIMEOUT) {
                            warn!("no frame from upstream for 90s, connection considered dead");
                            break;
                        }
                        // send the heartbeat when due and reschedule the next random interval
                        if last_ping.elapsed() >= ping_timeout {
                            debug!("sending ping to upstream");
                            if let Err(e) = mux_task.send_frame(Frame::empty(FrameType::Ping, 0)).await {
                                warn!(error = %e, "failed to send ping frame");
                                break;
                            }
                            last_ping = std::time::Instant::now();
                            ping_timeout = next_ping_delay();
                        }
                    }
                    Some(req) = open_rx.recv() => {
                        let mux_inner = mux_task.clone();
                        let peer_router = peer_router.clone();
                        let client_router = client_router.clone();
                        let openers = openers.clone();
                        let acl = acl.clone();
                        let events = events.clone();
                        let transit = transit.clone();
                        let peer_label = peer_label.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_open(mux_inner, req, peer_router, client_router, openers, acl, events, transit, peer_label).await {
                                debug!(error = %e, "open channel handling finished with error");
                            }
                        });
                    }
                    Some(payload) = ctrl_rx.recv() => {
                        // session control plane (v3): only TokenAck flows relay -> issuer
                        match serde_json::from_slice::<CtrlMessage>(&payload) {
                            Ok(CtrlMessage::TokenAck { token_hash, ok, error }) => {
                                debug!(ok, error = %error, "delegation ack received");
                                delegation_acks.insert(token_hash, (ok, error));
                            }
                            _ => debug!("ignoring unknown/malformed ctrl frame from upstream"),
                        }
                    }
                }
            }

            reader_handle.abort();
            // clear the current session handle (only if it still points to this session, to avoid clobbering a reconnected new session)
            if let Some(cur) = current_mux.load_full()
                && Arc::ptr_eq(&cur, &mux_task)
            {
                current_mux.store(None);
            }
            upstream_version.store(0, Ordering::Relaxed);
            state.store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
        });

        Ok(mux)
    }

    /// Run forever: auto-reconnect with exponential backoff + jitter after drops, until shutdown.
    pub async fn run(&self) {
        let mut attempt: u32 = 0;

        loop {
            if self.shutdown_flag.load(Ordering::Relaxed) {
                break;
            }

            match self.connect_once().await {
                Ok(session) => {
                    attempt = 0;
                    // wait for the session to drop (the background task flips state to Disconnected);
                    // proactively reconnect to re-advertise upstream when client tunnel rules change (route re-advertise)
                    // or when the pushed policy groups change (federation P1 re-push)
                    let mut last_router = self.client_router.as_ref().map(|r| r.load_full());
                    let mut last_groups = self.push_groups.load_full();
                    while self.state() == ConnectionState::Connected {
                        if self.shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        let cur_groups = self.push_groups.load_full();
                        if !Arc::ptr_eq(&last_groups, &cur_groups) {
                            info!("pushed policy groups changed — reconnecting to re-push");
                            self.shutdown_notify.notify_waiters();
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            break;
                        }
                        last_groups = cur_groups;
                        if let Some(r) = &self.client_router {
                            let cur = r.load_full();
                            let changed = match &last_router {
                                Some(prev) => !Arc::ptr_eq(prev, &cur),
                                None => true,
                            };
                            if changed {
                                info!(
                                    "client tunnel routes changed — reconnecting to re-advertise"
                                );
                                self.shutdown_notify.notify_waiters();
                                tokio::time::sleep(Duration::from_millis(300)).await;
                                break;
                            }
                            last_router = Some(cur);
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    drop(session);
                }
                Err(e) => {
                    debug!(error = %e, "connect attempt failed");
                }
            }

            if self.shutdown_flag.load(Ordering::Relaxed) {
                break;
            }

            self.state
                .store(ConnectionState::Reconnecting as u8, Ordering::Relaxed);

            // exponential backoff 1s -> 2s -> 4s -> ... -> 60s, full jitter (same strategy as tor):
            // uniform sampling in [0, backoff] — a fixed backoff + small-jitter reconnect cadence can be fingerprinted by a censor
            let backoff = Duration::from_secs(1)
                .saturating_mul(1u32 << attempt.min(6))
                .min(MAX_BACKOFF);
            // uniform sampling in [500ms, backoff]
            let delay = Duration::from_millis(
                (rand::random::<u64>() % backoff.as_millis() as u64).max(500),
            );
            info!(delay = ?delay, "reconnecting to upstream");
            attempt = attempt.saturating_add(1);

            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.shutdown_notify.notified() => break,
            }
        }

        self.state
            .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
    }

    /// On an Open frame: fan-out restriction -> downstream routing (multi-hop) -> client tunnel routes (re-advertise) -> local direct connect.
    #[allow(clippy::too_many_arguments)]
    async fn handle_open(
        mux: Arc<MuxSession>,
        req: OpenRequest,
        peer_router: Option<Arc<RelayListener>>,
        client_router: Option<Arc<arc_swap::ArcSwap<ProxyRouter>>>,
        openers: Option<Arc<dashmap::DashMap<String, Arc<dyn ChannelOpener>>>>,
        acl: Option<Arc<PeerAcl>>,
        events: broadcast::Sender<PeerEvent>,
        transit: Option<(Arc<TransitMeter>, String)>,
        peer_label: String,
    ) -> Result<()> {
        let open_req: OpenChannel = serde_json::from_slice(&req.payload)
            .map_err(|e| Error::Protocol(format!("invalid open channel payload: {e}")))?;

        let target_addr = format!("{}:{}", open_req.target_addr, open_req.target_port);
        debug!(channel_id = req.channel_id, target = %target_addr, "handling open request");

        // bandwidth-diagnostic reserved address: intercept before the restriction check
        // (protocol-level diagnostic service, same tier as heartbeat; answered locally,
        // no routing capability, restricted nodes equally testable, not an ACL bypass)
        if crate::relay::bandwidth::intercept(&mux, &req, &open_req.target_addr).await {
            return Ok(());
        }

        // fan-out restriction: with a restriction table, reverse-initiated targets must hit the allowlist (None = unrestricted, allow all)
        if let Some(acl) = &acl
            && !acl.allowed(&target_addr)
        {
            warn!(upstream = %peer_label, target = %target_addr, "connector open denied by ACL");
            let _ = events.send(PeerEvent::AclDenied {
                peer_label,
                target: target_addr,
            });
            mux.send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                .await?;
            return Ok(());
        }

        let channel = mux.accept_channel(req.channel_id);

        // multi-hop chain: target belongs to a further-downstream node's advertised CIDR -> forward downstream
        if let Some(listener) = &peer_router
            && let Some(next_peer) = listener.resolve_peer(&open_req.target_addr)
        {
            match listener
                .open_channel(&next_peer, &open_req.target_addr, open_req.target_port)
                .await
            {
                Ok(peer_channel) => {
                    mux.send_frame(Frame::empty(FrameType::OpenOk, req.channel_id))
                        .await?;
                    // bridge(channel, peer): up = upstream->downstream peer (transit from=this connector)
                    let (up, down) = bridge(channel, peer_channel).await?;
                    if let Some((m, f)) = &transit {
                        m.record(f, &next_peer, up, down);
                    }
                    debug!(
                        channel_id = req.channel_id,
                        up, down, "chained channel closed"
                    );
                    mux.close_channel(req.channel_id);
                    return Ok(());
                }
                Err(e) => {
                    warn!(peer = %next_peer, error = %e, "chained open failed");
                    mux.send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                        .await?;
                    mux.close_channel(req.channel_id);
                    return Err(e);
                }
            }
        }

        // route re-advertise: target hits a client-tunnel merged rule -> forward via the matching client tunnel
        if let (Some(router), Some(openers)) = (&client_router, &openers) {
            let outbound = router.load().route_target(&target_addr).clone();
            if let Outbound::Tunnel { node_id } = outbound {
                let opener = openers.get(&node_id).map(|r| r.value().clone());
                match opener {
                    Some(opener) => {
                        match opener
                            .open(&node_id, &open_req.target_addr, open_req.target_port)
                            .await
                        {
                            Ok(tunnel_channel) => {
                                mux.send_frame(Frame::empty(FrameType::OpenOk, req.channel_id))
                                    .await?;
                                // bridge(channel, tunnel): up = upstream->client tunnel
                                let (up, down) = bridge(channel, tunnel_channel).await?;
                                if let Some((m, f)) = &transit {
                                    m.record(f, &node_id, up, down);
                                }
                                debug!(channel_id = req.channel_id, via = %node_id, up, down, "re-published channel closed");
                                mux.close_channel(req.channel_id);
                                return Ok(());
                            }
                            Err(e) => {
                                warn!(node = %node_id, error = %e, "re-published open via client tunnel failed");
                                mux.send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                                    .await?;
                                mux.close_channel(req.channel_id);
                                return Err(e);
                            }
                        }
                    }
                    None => {
                        warn!(node = %node_id, "route re-published but opener missing (tunnel down?)");
                        mux.send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                            .await?;
                        mux.close_channel(req.channel_id);
                        return Err(Error::Protocol("client tunnel opener missing".into()));
                    }
                }
            }
        }

        // local direct connect
        match TcpStream::connect(&target_addr).await {
            Ok(local_stream) => {
                mux.send_frame(Frame::empty(FrameType::OpenOk, req.channel_id))
                    .await?;
                // bridge(local, channel): bytes_ab = local->upstream, bytes_ba = upstream->local;
                // transit up = from(upstream)->to(local) direction, i.e. bytes_ba
                let (bytes_ab, bytes_ba) = bridge(local_stream, channel).await?;
                if let Some((m, f)) = &transit {
                    m.record(f, TO_LOCAL, bytes_ba, bytes_ab);
                }
                debug!(
                    channel_id = req.channel_id,
                    bytes_sent = bytes_ab,
                    bytes_recv = bytes_ba,
                    "channel bridge finished"
                );
                mux.close_channel(req.channel_id);
                Ok(())
            }
            Err(err) => {
                warn!(channel_id = req.channel_id, target = %target_addr, error = %err, "failed to connect local target");
                mux.send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                    .await?;
                mux.close_channel(req.channel_id);
                Err(err.into())
            }
        }
    }

    /// Disconnect (set the shutdown flag; the run loop exits accordingly)
    pub async fn disconnect(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
        self.state
            .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
    }
}

/// Next heartbeat interval: exponential distribution (mean ~30s, clamped to 5-90s).
/// A fixed interval + small-jitter heartbeat is a classic traffic-analysis fingerprint; the exponential distribution is closer to the natural shape of browser keep-alives.
fn next_ping_delay() -> Duration {
    let sample = -30.0 * (1.0 - rand::random::<f64>()).ln();
    Duration::from_secs_f64(sample.clamp(5.0, 90.0))
}
