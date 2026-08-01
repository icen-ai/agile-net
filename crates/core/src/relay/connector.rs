//! Relay Connector — 下游角色，主动连接上游
//!
//! 连接上游 Listener，完成 TLS 握手与 Auth 认证，维护心跳（30s ± 5s 随机抖动），
//! 90s 无响应判定断线，指数退避 + 抖动自动重连，响应 Open 帧建立转发。

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::{
    AuthKind, AuthRequest, ControlOffer, OpenChannel, PROTOCOL_VERSION,
    PROTOCOL_VERSION_FLOW_CONTROL,
};
use crate::proxy::router::{Outbound, ProxyRouter};
use crate::relay::acl::PeerAcl;
use crate::relay::bridge::bridge;
use crate::relay::listener::{AUTH_TIMEOUT, PeerEvent, RelayListener};
use crate::relay::mux::{MuxChannel, MuxSession, OpenRequest};
use crate::tunnel::opener::ChannelOpener;
use crate::tunnel::tls::TlsConfigBuilder;

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Notify, broadcast, mpsc};
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
    /// 向上游通告的可服务网段/域名（静态配置）
    advertise: Vec<String>,
    /// 握手 v2：上游暴露控制面时下发的管理端点
    control: Arc<arc_swap::ArcSwapOption<ControlOffer>>,
    /// 路由再发布：客户端隧道合并路由（规则转售给下游，via=客户端隧道）
    client_router: Option<Arc<arc_swap::ArcSwap<ProxyRouter>>>,
    /// 路由再发布：node_id → 客户端隧道开启器
    openers: Option<Arc<dashmap::DashMap<String, Arc<dyn ChannelOpener>>>>,
    /// 扇出收敛：对端反向发起的目标连接允许集合（None = 不收敛，放行一切）
    acl: Option<Arc<PeerAcl>>,
    /// 当前会话 mux 句柄（connected 期间可用；管理面诊断开流用）
    current_mux: Arc<arc_swap::ArcSwapOption<MuxSession>>,
    /// 收敛拒绝等可观测事件（供管理面订阅写审计）
    events: broadcast::Sender<PeerEvent>,
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
        let (events, _) = broadcast::channel(256);

        Ok(Self {
            upstream_addr,
            node_id: node_id.into(),
            token: token.into(),
            tls_connector,
            sni_hostname: tls_builder.sni_hostname,
            peer_router: None,
            advertise: Vec::new(),
            control: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
            client_router: None,
            openers: None,
            acl: None,
            current_mux: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
            events,
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

    /// 路由再发布：注入客户端引擎的合并路由与开启器注册表。
    ///
    /// 效果：握手时把客户端隧道规则并入通告集；Open 请求命中这些规则时
    /// 经对应客户端隧道转发（规则 via=客户端隧道）；规则集变化时自动重连
    /// 重新通告（reconnect 即刷新，无需新帧类型，旧上游完全兼容）。
    pub fn with_client_routes(
        mut self,
        router: Arc<arc_swap::ArcSwap<ProxyRouter>>,
        openers: Arc<dashmap::DashMap<String, Arc<dyn ChannelOpener>>>,
    ) -> Self {
        self.client_router = Some(router);
        self.openers = Some(openers);
        self
    }

    /// 握手 v2：上游暴露的控制面端点（未暴露/未连接时为 None）。
    pub fn control_offer(&self) -> Option<ControlOffer> {
        self.control.load_full().map(|a| (*a).clone())
    }

    /// 当前会话的 mux 句柄（未连接时为 None）。
    pub fn current_mux(&self) -> Option<Arc<MuxSession>> {
        self.current_mux.load_full()
    }

    /// 经当前隧道向对端发起一条到指定目标的流（管理面诊断用；未连接返回 NotFound）。
    pub async fn open_stream(&self, target_addr: &str, target_port: u16) -> Result<MuxChannel> {
        let mux = self
            .current_mux()
            .ok_or_else(|| Error::NotFound("connector not connected".into()))?;
        let payload = serde_json::to_vec(&OpenChannel {
            target_addr: target_addr.to_string(),
            target_port,
        })
        .map_err(|e| Error::Protocol(e.to_string()))?;
        mux.open_channel(Bytes::from(payload)).await
    }

    /// 扇出收敛：设置对端反向发起目标连接的允许集合（None = 不收敛，放行一切）。
    pub fn with_acl(mut self, acl: Option<Arc<PeerAcl>>) -> Self {
        self.acl = acl;
        self
    }

    /// 订阅收敛拒绝等可观测事件（供管理面写审计）。
    pub fn subscribe_events(&self) -> broadcast::Receiver<PeerEvent> {
        self.events.subscribe()
    }

    /// 当前有效通告集 = 静态配置 + 客户端隧道规则值（路由再发布）。
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

        // 发布当前会话句柄（管理面诊断开流用），再置 Connected
        self.current_mux.store(Some(session.clone()));
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

        // 发送 Auth 帧（通告集 = 静态 + 客户端隧道规则再发布）
        let auth_req = AuthRequest {
            node_id: self.node_id.clone(),
            token: self.token.clone(),
            kind: AuthKind::Node,
            advertise: self.effective_advertise(),
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
                // 服务端版本（AuthOk payload {"version":N}，缺省为 1）+ 可选控制面端点
                if !res_frame.payload.is_empty()
                    && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&res_frame.payload)
                {
                    server_version = v["version"].as_u64().unwrap_or(1) as u32;
                    if let Some(cv) = v.get("control") {
                        match serde_json::from_value::<ControlOffer>(cv.clone()) {
                            Ok(mut offer) => {
                                // 上游未报名时以 connector 配置的上游地址代替
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

        // 流控协商：双方都 >= v2 时启用 per-channel 窗口流控
        let flow_control = server_version >= PROTOCOL_VERSION_FLOW_CONTROL;
        debug!(
            server_version,
            flow_control, "mux session flow control negotiated"
        );

        let (open_tx, mut open_rx) = mpsc::channel::<OpenRequest>(64);
        let (mux, reader_handle) = MuxSession::start(tls_stream, 2, Some(open_tx), flow_control);

        // 后台维护循环：心跳（带抖动）、空闲超时检测、Open 通道请求
        let shutdown_notify = self.shutdown_notify.clone();
        let shutdown_flag = self.shutdown_flag.clone();
        let state = self.state.clone();
        let peer_router = self.peer_router.clone();
        let client_router = self.client_router.clone();
        let openers = self.openers.clone();
        let acl = self.acl.clone();
        let events = self.events.clone();
        let peer_label = self.upstream_addr.to_string();
        let mux_task = mux.clone();
        let current_mux = self.current_mux.clone();

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
                        let client_router = client_router.clone();
                        let openers = openers.clone();
                        let acl = acl.clone();
                        let events = events.clone();
                        let peer_label = peer_label.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_open(mux_inner, req, peer_router, client_router, openers, acl, events, peer_label).await {
                                debug!(error = %e, "open channel handling finished with error");
                            }
                        });
                    }
                }
            }

            reader_handle.abort();
            // 清空当前会话句柄（仅当仍指向本会话，防误清重连后的新会话）
            if let Some(cur) = current_mux.load_full()
                && Arc::ptr_eq(&cur, &mux_task)
            {
                current_mux.store(None);
            }
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
                    // 等待会话断开（后台任务结束时把状态置为 Disconnected）；
                    // 客户端隧道规则集变化时主动重连，向上游重新通告（路由再发布）
                    let mut last_router = self.client_router.as_ref().map(|r| r.load_full());
                    while self.state() == ConnectionState::Connected {
                        if self.shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
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

    /// 收到 Open 帧后：扇出收敛 → 下游路由（多级串联）→ 客户端隧道路由（再发布）→ 本机直连。
    #[allow(clippy::too_many_arguments)]
    async fn handle_open(
        mux: Arc<MuxSession>,
        req: OpenRequest,
        peer_router: Option<Arc<RelayListener>>,
        client_router: Option<Arc<arc_swap::ArcSwap<ProxyRouter>>>,
        openers: Option<Arc<dashmap::DashMap<String, Arc<dyn ChannelOpener>>>>,
        acl: Option<Arc<PeerAcl>>,
        events: broadcast::Sender<PeerEvent>,
        peer_label: String,
    ) -> Result<()> {
        let open_req: OpenChannel = serde_json::from_slice(&req.payload)
            .map_err(|e| Error::Protocol(format!("invalid open channel payload: {e}")))?;

        let target_addr = format!("{}:{}", open_req.target_addr, open_req.target_port);
        debug!(channel_id = req.channel_id, target = %target_addr, "handling open request");

        // 带宽诊断保留地址：收敛检查之前拦截（协议级诊断服务，与心跳同级，
        // 本地应答、无任何路由能力，收敛节点同样可测，不构成 ACL 旁路）
        if crate::relay::bandwidth::intercept(&mux, &req, &open_req.target_addr).await {
            return Ok(());
        }

        // 扇出收敛：带收敛表时反向来的目标必须命中允许集合（None = 不收敛，放行一切）
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

        // 路由再发布：目标命中客户端隧道合并规则 → 经对应客户端隧道转发
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
                                let (up, down) = bridge(channel, tunnel_channel).await?;
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
