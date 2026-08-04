//! Client tunnel (ClientTunnel)
//!
//! Client-to-node data-plane connection: TLS 1.3 + tunnel_token auth, multiplexing
//! logical channels over a single TLS connection, one channel per end-to-end TCP connection.
//! Supports heartbeat keepalive, idle timeout detection and exponential-backoff auto-reconnect.

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::{
    AuthKind, AuthRequest, OpenChannel, PROTOCOL_VERSION, PROTOCOL_VERSION_FLOW_CONTROL,
};
use crate::relay::connector::ConnectionState;
use crate::relay::listener::AUTH_TIMEOUT;
use crate::relay::mux::{MuxChannel, MuxSession};
use crate::tunnel::tls::TlsConfigBuilder;

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

/// Base heartbeat interval (actual: 25s + 0-10s random).
const PING_BASE_SECS: u64 = 25;
/// Idle timeout: no frame from the server for 90s means the connection is dead.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Reconnect backoff cap.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Client tunnel: data-plane connection to a single node.
pub struct ClientTunnel {
    upstream_addr: SocketAddr,
    account_id: String,
    /// tunnel_token (rotated by the server on login/refresh; reconnects must use the latest value)
    tunnel_token: std::sync::Arc<std::sync::RwLock<String>>,
    tls_connector: TlsConnector,
    sni_hostname: String,
    session: Arc<Mutex<Option<Arc<MuxSession>>>>,
    state: Arc<AtomicU8>,
    shutdown_notify: Arc<Notify>,
    shutdown_flag: Arc<AtomicBool>,
}

impl ClientTunnel {
    /// Create with a custom TLS config (cert pinning recommended in production).
    pub fn with_tls_builder(
        upstream_addr: SocketAddr,
        account_id: impl Into<String>,
        tunnel_token: impl Into<String>,
        tls_builder: TlsConfigBuilder,
    ) -> Result<Self> {
        let client_config = tls_builder.build_client()?;
        Ok(Self {
            upstream_addr,
            account_id: account_id.into(),
            tunnel_token: std::sync::Arc::new(std::sync::RwLock::new(tunnel_token.into())),
            tls_connector: TlsConnector::from(client_config),
            sni_hostname: tls_builder.sni_hostname,
            session: Arc::new(Mutex::new(None)),
            state: Arc::new(AtomicU8::new(ConnectionState::Disconnected as u8)),
            shutdown_notify: Arc::new(Notify::new()),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Create in dev mode (no server cert verification, debug only).
    pub fn new_insecure(
        upstream_addr: SocketAddr,
        account_id: impl Into<String>,
        tunnel_token: impl Into<String>,
    ) -> Result<Self> {
        Self::with_tls_builder(
            upstream_addr,
            account_id,
            tunnel_token,
            TlsConfigBuilder::new().allow_self_signed(true),
        )
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

    /// Data-plane traffic counters (up bytes, down bytes): up = to the node, down = from the node.
    /// Data frame payloads only (same as `MuxSession::traffic`).
    /// Current-session semantics: auto-reconnect creates a new MuxSession and counters restart at 0; (0, 0) when not connected.
    pub async fn traffic(&self) -> (u64, u64) {
        match self.session.lock().await.as_ref() {
            Some(mux) => mux.traffic(),
            None => (0, 0),
        }
    }

    /// Establish one connection (TLS + auth + session maintenance task).
    pub async fn connect(&self) -> Result<()> {
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

        *self.session.lock().await = Some(session);
        self.state
            .store(ConnectionState::Connected as u8, Ordering::Relaxed);
        info!(upstream = %self.upstream_addr, account = %self.account_id, "client tunnel established");
        Ok(())
    }

    async fn handshake(&self) -> Result<Arc<MuxSession>> {
        let tcp_stream = TcpStream::connect(self.upstream_addr).await?;
        let server_name = rustls::pki_types::ServerName::try_from(self.sni_hostname.clone())
            .map_err(|e| Error::Tls(e.to_string()))?;
        let mut tls_stream = self.tls_connector.connect(server_name, tcp_stream).await?;

        let auth_req = AuthRequest {
            node_id: self.account_id.clone(),
            token: self
                .tunnel_token
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            kind: AuthKind::Client,
            advertise: Vec::new(),
            groups: Vec::new(),
            version: PROTOCOL_VERSION,
        };
        let payload = serde_json::to_vec(&auth_req).map_err(|e| Error::Protocol(e.to_string()))?;
        Frame::new(FrameType::Auth, 0, Bytes::from(payload))
            .write_to(&mut tls_stream)
            .await?;

        let res_frame = Frame::read_from(&mut tls_stream).await?;
        let mut server_version = 1u32;
        match res_frame.frame_type {
            FrameType::AuthOk => {
                if !res_frame.payload.is_empty()
                    && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&res_frame.payload)
                {
                    server_version = v["version"].as_u64().unwrap_or(1) as u32;
                }
            }
            FrameType::AuthFail => {
                return Err(Error::Auth("node rejected tunnel token".into()));
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected frame during auth: {other:?}"
                )));
            }
        }

        // the client is the only side issuing Open on this session; use even channel_ids
        let flow_control = server_version >= PROTOCOL_VERSION_FLOW_CONTROL;
        // no session rate limit on the client side (if limited, the peer listener's injected bucket back-pressures at ingress)
        let (mux, reader_handle) = MuxSession::start(
            tls_stream,
            2,
            crate::relay::mux::SessionEvents::default(),
            flow_control,
            None,
        );

        // session maintenance task: heartbeat (with jitter) + idle timeout detection
        let shutdown_notify = self.shutdown_notify.clone();
        let shutdown_flag = self.shutdown_flag.clone();
        let state = self.state.clone();
        let session_slot = self.session.clone();
        let mux_task = mux.clone();

        tokio::spawn(async move {
            let mut ping_timeout = next_ping_delay();
            let mut last_ping = std::time::Instant::now();
            let mut ping_timer = tokio::time::interval(Duration::from_secs(5));
            ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = shutdown_notify.notified() => {
                        let _ = mux_task.send_frame(Frame::empty(FrameType::Close, 0)).await;
                        break;
                    }
                    _ = ping_timer.tick() => {
                        if shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        if mux_task.is_idle_beyond(IDLE_TIMEOUT) {
                            warn!("no frame from node for 90s, tunnel considered dead");
                            break;
                        }
                        if last_ping.elapsed() >= ping_timeout {
                            if let Err(e) = mux_task.send_frame(Frame::empty(FrameType::Ping, 0)).await {
                                warn!(error = %e, "failed to send ping");
                                break;
                            }
                            last_ping = std::time::Instant::now();
                            ping_timeout = next_ping_delay();
                        }
                    }
                    // exit when the reader task ends (connection dropped): await reader_handle
                    _ = futures_lite_wait(&reader_handle) => {
                        break;
                    }
                }
            }

            if !reader_handle.is_finished() {
                reader_handle.abort();
            }
            session_slot.lock().await.take();
            state.store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
        });

        Ok(mux)
    }

    /// Open a channel to a target address over the tunnel.
    pub async fn open_channel(&self, target_host: &str, target_port: u16) -> Result<MuxChannel> {
        let session = {
            let guard = self.session.lock().await;
            guard.clone()
        }
        .ok_or_else(|| Error::Other("tunnel not connected".into()))?;

        let payload = serde_json::to_vec(&OpenChannel::new(target_host, target_port))
            .map_err(|e| Error::Protocol(e.to_string()))?;

        session.open_channel(Bytes::from(payload)).await
    }

    /// Run forever: auto-reconnect on disconnect (exponential backoff + jitter) until shutdown.
    pub async fn run(&self) {
        let mut attempt: u32 = 0;

        loop {
            if self.shutdown_flag.load(Ordering::Relaxed) {
                break;
            }

            match self.connect().await {
                Ok(()) => {
                    attempt = 0;
                    while self.state() == ConnectionState::Connected {
                        if self.shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
                Err(e) => {
                    debug!(error = %e, "tunnel connect attempt failed");
                }
            }

            if self.shutdown_flag.load(Ordering::Relaxed) {
                break;
            }

            self.state
                .store(ConnectionState::Reconnecting as u8, Ordering::Relaxed);

            let backoff = Duration::from_secs(1)
                .saturating_mul(1u32 << attempt.min(6))
                .min(MAX_BACKOFF);
            let jitter = Duration::from_millis((rand::random::<u64>() % 3000) as u64);
            let delay = backoff + jitter;
            attempt = attempt.saturating_add(1);

            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.shutdown_notify.notified() => break,
            }
        }

        self.state
            .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
    }

    /// New tunnel_token after server rotation (call on refresh; used by the next reconnect).
    pub fn update_token(&self, new_token: String) {
        *self.tunnel_token.write().unwrap_or_else(|e| e.into_inner()) = new_token;
    }

    /// Disconnect the tunnel.
    pub async fn disconnect(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
        self.state
            .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
    }
}

/// Wait for a JoinHandle to finish (without consuming it).
async fn futures_lite_wait(handle: &tokio::task::JoinHandle<()>) {
    // a JoinHandle cannot be awaited by reference; poll is_finished (returns once the reader ends)
    while !handle.is_finished() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Next heartbeat interval: 25s + 0-10s random jitter.
fn next_ping_delay() -> Duration {
    Duration::from_secs(PING_BASE_SECS + rand::random::<u64>() % 10)
}
