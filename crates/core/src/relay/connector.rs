//! Relay Connector — 下游角色，主动连接上游
//!
//! 连接上游 Listener，完成 TLS 握手与 Auth 认证，维护心跳（30s ± 5s 随机抖动），
//! 90s 无响应判定断线，指数退避 + 抖动自动重连，响应 Open 帧建立转发。

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::{
    AuthKind, AuthRequest, OpenChannel, PROTOCOL_VERSION, PROTOCOL_VERSION_FLOW_CONTROL,
};
use crate::relay::bridge::bridge;
use crate::relay::listener::{AUTH_TIMEOUT, RelayListener};
use crate::relay::mux::{MuxSession, OpenRequest};
use crate::tunnel::tls::TlsConfigBuilder;

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

/// 心跳基础间隔（实际为 25s + 0~10s 随机，模拟自然 HTTPS 行为）。
const PING_BASE_SECS: u64 = 25;
/// 心跳超时：超过该时间未收到对端任何帧则判定断线。
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// 重连退避上限。
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// 连接状态。
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

/// Relay 连接器。
pub struct RelayConnector {
    upstream_addr: SocketAddr,
    node_id: String,
    token: String,
    tls_connector: TlsConnector,
    sni_hostname: String,
    /// 本节点向**下游**提供路由的 Listener（多级串联时用于链式转发）
    peer_router: Option<Arc<RelayListener>>,
    /// 向上游通告的可服务网段/域名
    advertise: Vec<String>,
    state: Arc<AtomicU8>,
    shutdown_notify: Arc<Notify>,
    shutdown_flag: Arc<AtomicBool>,
}

impl RelayConnector {
    /// 创建新的 RelayConnector（开发模式：不校验证书）。
    ///
    /// 生产环境请使用 `with_tls_builder` 配置 CA 或证书固定 (pinning)。
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

    /// 使用自定义 TLS 配置创建。
    pub fn with_tls_builder(
        upstream_addr: SocketAddr,
        node_id: impl Into<String>,
        token: impl Into<String>,
        tls_builder: TlsConfigBuilder,
    ) -> Result<Self> {
        let client_config = tls_builder.build_client()?;
        let tls_connector = TlsConnector::from(client_config);

        Ok(Self {
            upstream_addr,
            node_id: node_id.into(),
            token: token.into(),
            tls_connector,
            sni_hostname: tls_builder.sni_hostname,
            peer_router: None,
            advertise: Vec::new(),
            state: Arc::new(AtomicU8::new(ConnectionState::Disconnected as u8)),
            shutdown_notify: Arc::new(Notify::new()),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// 设置下游路由 Listener（多级串联时 Open 请求可继续向下游转发）。
    pub fn with_peer_router(mut self, listener: Arc<RelayListener>) -> Self {
        self.peer_router = Some(listener);
        self
    }

    /// 设置向上游通告的网段/域名列表。
    pub fn with_advertise(mut self, advertise: Vec<String>) -> Self {
        self.advertise = advertise;
        self
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

    /// 单次连接：TLS 握手 + 认证 + 启动会话维护任务。
    ///
    /// 连接建立后立即返回；会话断开后状态自动变为 Disconnected（不自动重连，
    /// 自动重连请使用 `run`）。
    pub async fn connect(&self) -> Result<()> {
        self.connect_once().await.map(|_| ())
    }

    /// 建立一次连接并启动后台维护任务，返回会话句柄。
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

        self.state
            .store(ConnectionState::Connected as u8, Ordering::Relaxed);
        Ok(session)
    }

    /// TLS 握手 + Auth 认证 + 启动会话维护任务。
    async fn handshake(&self) -> Result<Arc<MuxSession>> {
        let tcp_stream = TcpStream::connect(self.upstream_addr).await?;
        let server_name = rustls::pki_types::ServerName::try_from(self.sni_hostname.clone())
            .map_err(|e| Error::Tls(e.to_string()))?;

        let mut tls_stream = self.tls_connector.connect(server_name, tcp_stream).await?;
        debug!(upstream = %self.upstream_addr, "tls connected to upstream");

        // 发送 Auth 帧
        let auth_req = AuthRequest {
            node_id: self.node_id.clone(),
            token: self.token.clone(),
            kind: AuthKind::Node,
            advertise: self.advertise.clone(),
            version: PROTOCOL_VERSION,
        };
        let payload = serde_json::to_vec(&auth_req).map_err(|e| Error::Protocol(e.to_string()))?;
        Frame::new(FrameType::Auth, 0, Bytes::from(payload))
            .write_to(&mut tls_stream)
            .await?;

        // 读取 Auth 回复
        let res_frame = Frame::read_from(&mut tls_stream).await?;
        let mut server_version = 1u32;
        match res_frame.frame_type {
            FrameType::AuthOk => {
                info!(upstream = %self.upstream_addr, "authenticated successfully with upstream");
                // 服务端版本（AuthOk payload {"version":N}，缺省为 1）
                if !res_frame.payload.is_empty()
                    && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&res_frame.payload)
                {
                    server_version = v["version"].as_u64().unwrap_or(1) as u32;
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

        // 流控协商：双方都 >= v2 时启用 per-channel 窗口流控
        let flow_control = server_version >= PROTOCOL_VERSION_FLOW_CONTROL;
        debug!(server_version, flow_control, "mux session flow control negotiated");

        let (open_tx, mut open_rx) = mpsc::channel::<OpenRequest>(64);
        let (mux, reader_handle) = MuxSession::start(tls_stream, 2, Some(open_tx), flow_control);

        // 后台维护循环：心跳（带抖动）、空闲超时检测、Open 通道请求
        let shutdown_notify = self.shutdown_notify.clone();
        let shutdown_flag = self.shutdown_flag.clone();
        let state = self.state.clone();
        let peer_router = self.peer_router.clone();
        let mux_task = mux.clone();

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
                        // 兜底检查 shutdown 标志（防止 notify 竞态漏唤醒）
                        if shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        // 空闲超时：90s 未收到对端任何帧 → 判定断线
                        if mux_task.is_idle_beyond(IDLE_TIMEOUT) {
                            warn!("no frame from upstream for 90s, connection considered dead");
                            break;
                        }
                        // 到点发送心跳并重排下一次随机间隔
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
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_open(mux_inner, req, peer_router).await {
                                debug!(error = %e, "open channel handling finished with error");
                            }
                        });
                    }
                }
            }

            reader_handle.abort();
            state.store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
        });

        Ok(mux)
    }

    /// 永久运行：连接断开后指数退避 + 抖动自动重连，直到收到 shutdown。
    pub async fn run(&self) {
        let mut attempt: u32 = 0;

        loop {
            if self.shutdown_flag.load(Ordering::Relaxed) {
                break;
            }

            match self.connect_once().await {
                Ok(session) => {
                    attempt = 0;
                    // 等待会话断开（后台任务结束时把状态置为 Disconnected）
                    while self.state() == ConnectionState::Connected {
                        if self.shutdown_flag.load(Ordering::Relaxed) {
                            break;
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

            // 指数退避 1s → 2s → 4s → ... → 60s，加 0~3s 抖动
            let backoff = Duration::from_secs(1)
                .saturating_mul(1u32 << attempt.min(6))
                .min(MAX_BACKOFF);
            let jitter = Duration::from_millis((rand::random::<u64>() % 3000) as u64);
            let delay = backoff + jitter;
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

    /// 收到 Open 帧后：优先向下游路由（多级串联），否则连接本地真实服务。
    async fn handle_open(
        mux: Arc<MuxSession>,
        req: OpenRequest,
        peer_router: Option<Arc<RelayListener>>,
    ) -> Result<()> {
        let open_req: OpenChannel = serde_json::from_slice(&req.payload)
            .map_err(|e| Error::Protocol(format!("invalid open channel payload: {e}")))?;

        let target_addr = format!("{}:{}", open_req.target_addr, open_req.target_port);
        debug!(channel_id = req.channel_id, target = %target_addr, "handling open request");

        let channel = mux.accept_channel(req.channel_id);

        // 多级串联：目标属于更下游节点的通告网段 → 继续向下游转发
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
                        let (up, down) = bridge(channel, peer_channel).await?;
                        debug!(channel_id = req.channel_id, up, down, "chained channel closed");
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

        // 本机直连
        match TcpStream::connect(&target_addr).await {
            Ok(local_stream) => {
                mux.send_frame(Frame::empty(FrameType::OpenOk, req.channel_id))
                    .await?;
                let (bytes_ab, bytes_ba) = bridge(local_stream, channel).await?;
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

    /// 断开连接（置 shutdown 标志，run 循环随之退出）
    pub async fn disconnect(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
        self.state
            .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
    }
}

/// 下一次心跳间隔：25s + 0~10s 随机抖动。
fn next_ping_delay() -> Duration {
    Duration::from_secs(PING_BASE_SECS + rand::random::<u64>() % 10)
}
