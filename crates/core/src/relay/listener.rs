//! Relay Listener — 上游角色，接受下游节点与客户端连入
//!
//! 安全设计：
//! - TLS 握手与认证全程 10s 超时（防 Slowloris 半开连接耗尽）
//! - Token 常数时间比较（防时序侧信道）
//! - 认证失败随机延迟 + 按来源 IP 频率限制（防在线爆破）
//! - 并发连接数与待认证连接数上限（防连接洪泛）
//! - 客户端会话按权限组规则做目标 ACL 校验

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::{AuthKind, AuthRequest, OpenChannel};
use crate::proxy::router::{Outbound, ProxyRouter};
use crate::relay::mux::{MuxChannel, MuxSession, OpenRequest};
use crate::tunnel::tls::TlsConfigBuilder;

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
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// TLS 握手 + 认证必须在该时间内完成。
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// 最大并发连接数（含未认证）。
pub const MAX_CONNECTIONS: usize = 1024;
/// 最大待认证连接数。
pub const MAX_PENDING_AUTH: usize = 256;
/// 同一 IP 在 60s 窗口内允许的最大认证尝试次数。
pub const MAX_AUTH_ATTEMPTS_PER_MINUTE: u32 = 20;

/// 认证通过后的主体身份。
#[derive(Debug, Clone)]
pub enum AuthIdentity {
    /// 下游节点
    Node {
        node_id: String,
        /// 通告的可服务网段/域名
        advertise: Vec<String>,
    },
    /// 客户端账号，附带目标访问控制规则
    Client {
        account_id: String,
        /// ACL 规则（CIDR / 精确域名 / *.后缀域名）
        acl: Vec<String>,
    },
}

/// Token 校验器：由上层（node crate 的数据库或静态配置）实现。
pub trait TokenValidator: Send + Sync {
    /// 校验成功返回主体身份，失败返回 None。
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity>;
}

/// 静态单 Token 校验器（向后兼容 / 测试用），常数时间比较。
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
            })
        } else {
            None
        }
    }
}

/// 常数时间字节比较，避免时序侧信道。
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

/// 节点/客户端上下线事件（供管理面更新状态）。
#[derive(Debug, Clone)]
pub enum PeerEvent {
    NodeConnected { node_id: String },
    NodeDisconnected { node_id: String },
    ClientConnected { account_id: String },
    ClientDisconnected { account_id: String },
}

/// 已连入的节点会话
pub struct PeerSession {
    pub node_id: String,
    pub mux: Arc<MuxSession>,
}

/// 下游节点通告的路由表（target → peer node_id）。
#[derive(Default)]
struct AdvertisedRoutes {
    cidrs: IpNetworkTable<String>,
    hosts: HashMap<String, String>,
    suffixes: Vec<(String, String)>,
}

/// Relay 监听器。
pub struct RelayListener {
    listen_addr: SocketAddr,
    validator: Arc<dyn TokenValidator>,
    tls_acceptor: TlsAcceptor,
    peers: Arc<DashMap<String, PeerSession>>,
    /// 每个下游节点通告的原始路由条目
    peer_advertise: Arc<DashMap<String, Vec<String>>>,
    /// 汇总后的可查询路由表（RCU 热更新）
    routes: Arc<arc_swap::ArcSwap<AdvertisedRoutes>>,
    /// 在线客户端会话计数（account_id → 会话数）
    clients: Arc<DashMap<String, usize>>,
    events: broadcast::Sender<PeerEvent>,
    active_connections: Arc<AtomicUsize>,
    pending_auth: Arc<AtomicUsize>,
    auth_attempts: Arc<DashMap<IpAddr, (u32, Instant)>>,
}

impl RelayListener {
    /// 创建新的 RelayListener（静态 Token 校验，自动生成自签证书）。
    pub fn new(listen_addr: SocketAddr, expected_token: impl Into<String>) -> Result<Self> {
        let (server_config, _) = TlsConfigBuilder::new().build_server()?;
        let tls_acceptor = TlsAcceptor::from(server_config);
        Ok(Self::with_validator(
            listen_addr,
            Arc::new(StaticTokenValidator::new(expected_token)),
            tls_acceptor,
        ))
    }

    /// 使用自定义 TlsAcceptor + 静态 Token 创建（向后兼容）。
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

    /// 使用自定义 Token 校验器与 TlsAcceptor 创建。
    pub fn with_validator(
        listen_addr: SocketAddr,
        validator: Arc<dyn TokenValidator>,
        tls_acceptor: TlsAcceptor,
    ) -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            listen_addr,
            validator,
            tls_acceptor,
            peers: Arc::new(DashMap::new()),
            peer_advertise: Arc::new(DashMap::new()),
            routes: Arc::new(arc_swap::ArcSwap::from_pointee(AdvertisedRoutes::default())),
            clients: Arc::new(DashMap::new()),
            events,
            active_connections: Arc::new(AtomicUsize::new(0)),
            pending_auth: Arc::new(AtomicUsize::new(0)),
            auth_attempts: Arc::new(DashMap::new()),
        }
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 当前连入且认证成功的下游节点数。
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// 列出在线下游节点 ID。
    pub fn list_peers(&self) -> Vec<String> {
        self.peers.iter().map(|p| p.key().clone()).collect()
    }

    /// 在线客户端账号数。
    pub fn online_client_count(&self) -> usize {
        self.clients.len()
    }

    /// 指定客户端是否在线。
    pub fn is_client_online(&self, account_id: &str) -> bool {
        self.clients.get(account_id).map(|c| *c > 0).unwrap_or(false)
    }

    /// 订阅上下线事件。
    pub fn subscribe_events(&self) -> broadcast::Receiver<PeerEvent> {
        self.events.subscribe()
    }

    /// 解析目标地址对应的下游节点（基于通告路由表）。
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

    /// 启动监听服务
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!(addr = %self.listen_addr, "relay listener started");

        loop {
            let (stream, peer_addr) = listener.accept().await?;

            // 并发连接上限：超限直接丢弃
            let current = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
            if current > MAX_CONNECTIONS {
                self.active_connections.fetch_sub(1, Ordering::Relaxed);
                warn!(peer = %peer_addr, "connection limit reached, dropping");
                drop(stream);
                continue;
            }

            // 认证频率限制：窗口内尝试次数超限直接丢弃
            if self.is_auth_rate_limited(&peer_addr.ip()) {
                self.active_connections.fetch_sub(1, Ordering::Relaxed);
                warn!(peer = %peer_addr, "auth rate limit exceeded, dropping");
                drop(stream);
                continue;
            }

            let this = self.clone();
            tokio::spawn(async move {
                // 连接结束自动扣减计数
                let _guard = ConnGuard(this.active_connections.clone());
                if let Err(err) = this.handle_connection(stream, peer_addr).await {
                    debug!(peer = %peer_addr, error = %err, "relay connection closed with error");
                }
            });
        }
    }

    /// 检查并记录一次认证尝试；超限返回 true。
    fn is_auth_rate_limited(&self, ip: &IpAddr) -> bool {
        let mut entry = self.auth_attempts.entry(*ip).or_insert((0, Instant::now()));
        let (count, window_start) = entry.value_mut();
        if window_start.elapsed() > Duration::from_secs(60) {
            *count = 0;
            *window_start = Instant::now();
        }
        *count += 1;
        *count > MAX_AUTH_ATTEMPTS_PER_MINUTE
    }

    /// 处理单个 TCP 连接（TLS 握手 + 认证 + 控制循环）
    async fn handle_connection(self: &Arc<Self>, stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        // 待认证连接上限
        let pending = self.pending_auth.fetch_add(1, Ordering::Relaxed) + 1;
        if pending > MAX_PENDING_AUTH {
            self.pending_auth.fetch_sub(1, Ordering::Relaxed);
            return Err(Error::Protocol("too many pending auth connections".into()));
        }
        let _pending_guard = ConnGuard(self.pending_auth.clone());

        // TLS 握手 + 首帧认证全程限时，防 Slowloris
        let authed = tokio::time::timeout(AUTH_TIMEOUT, self.tls_handshake_and_auth(stream, peer_addr))
            .await
            .map_err(|_| Error::Timeout)??;

        let (tls_stream, identity) = match authed {
            Some(v) => v,
            None => return Err(Error::Auth("authentication failed".into())),
        };
        drop(_pending_guard);

        match identity {
            AuthIdentity::Node { node_id, advertise } => {
                self.serve_node_session(tls_stream, peer_addr, node_id, advertise).await
            }
            AuthIdentity::Client { account_id, acl } => {
                self.serve_client_session(tls_stream, peer_addr, account_id, acl).await
            }
        }
    }

    /// TLS 握手并校验 Auth 帧。失败时已发送 AuthFail 并做了延迟惩罚。
    async fn tls_handshake_and_auth(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<Option<(tokio_rustls::server::TlsStream<TcpStream>, AuthIdentity)>> {
        let mut tls_stream = self.tls_acceptor.accept(stream).await?;
        debug!(peer = %peer_addr, "tls handshake completed");

        let frame = Frame::read_from(&mut tls_stream).await?;
        if frame.frame_type != FrameType::Auth {
            let _ = Frame::empty(FrameType::AuthFail, 0)
                .write_to(&mut tls_stream)
                .await;
            return Err(Error::Protocol("expected Auth frame".into()));
        }

        let auth_req: AuthRequest = serde_json::from_slice(&frame.payload)
            .map_err(|e| Error::Protocol(format!("invalid auth payload: {e}")))?;

        // 节点 ID 长度约束，防止异常数据
        if auth_req.node_id.is_empty() || auth_req.node_id.len() > 128 {
            let _ = Frame::empty(FrameType::AuthFail, 0)
                .write_to(&mut tls_stream)
                .await;
            return Err(Error::Protocol("invalid node_id".into()));
        }

        match self.validator.validate(&auth_req) {
            Some(identity) => {
                Frame::empty(FrameType::AuthOk, 0)
                    .write_to(&mut tls_stream)
                    .await?;
                Ok(Some((tls_stream, identity)))
            }
            None => {
                warn!(peer = %peer_addr, node_id = %auth_req.node_id, "auth failed: bad token");
                // 随机延迟 150~400ms，拖慢在线爆破
                let delay_ms = 150 + rand::random::<u64>() % 250;
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let _ = Frame::empty(FrameType::AuthFail, 0)
                    .write_to(&mut tls_stream)
                    .await;
                Ok(None)
            }
        }
    }

    /// 节点会话：注册 peer、装载通告路由，等待断开。
    async fn serve_node_session(
        self: &Arc<Self>,
        tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        node_id: String,
        advertise: Vec<String>,
    ) -> Result<()> {
        info!(peer = %peer_addr, node_id = %node_id, "node authenticated successfully");

        let (mux, reader_handle) = MuxSession::start(tls_stream, 1, None);

        self.peers.insert(
            node_id.clone(),
            PeerSession {
                node_id: node_id.clone(),
                mux: mux.clone(),
            },
        );
        self.set_peer_routes(&node_id, advertise);
        let _ = self.events.send(PeerEvent::NodeConnected {
            node_id: node_id.clone(),
        });

        // 等待 reader 结束（连接断开）
        let _ = reader_handle.await;

        self.peers.remove(&node_id);
        self.set_peer_routes(&node_id, Vec::new());
        let _ = self.events.send(PeerEvent::NodeDisconnected {
            node_id: node_id.clone(),
        });
        info!(node_id = %node_id, "peer disconnected");
        Ok(())
    }

    /// 客户端会话：处理入站 Open 请求（ACL + 下游路由 + 直连）。
    async fn serve_client_session(
        self: &Arc<Self>,
        tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
        peer_addr: SocketAddr,
        account_id: String,
        acl: Vec<String>,
    ) -> Result<()> {
        info!(peer = %peer_addr, account = %account_id, "client authenticated successfully");

        let acl_router = build_acl_router(&acl);
        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<OpenRequest>(64);
        let (mux, reader_handle) = MuxSession::start(tls_stream, 1, Some(open_tx));

        *self.clients.entry(account_id.clone()).or_insert(0) += 1;
        let _ = self.events.send(PeerEvent::ClientConnected {
            account_id: account_id.clone(),
        });

        // 处理该客户端的 Open 请求直到连接断开
        // （reader 任务结束时 open_tx 被释放，recv 返回 None）
        while let Some(req) = open_rx.recv().await {
            let this = self.clone();
            let mux = mux.clone();
            let acl_router = acl_router.clone();
            tokio::spawn(async move {
                this.handle_client_open(mux, req, acl_router).await;
            });
        }

        let _ = reader_handle.await;
        if let Some(mut count) = self.clients.get_mut(&account_id) {
            *count = count.saturating_sub(1);
        }
        self.clients.remove_if(&account_id, |_, c| *c == 0);
        let _ = self.events.send(PeerEvent::ClientDisconnected {
            account_id: account_id.clone(),
        });
        info!(account = %account_id, "client disconnected");
        Ok(())
    }

    /// 处理客户端 Open：ACL 校验 → 下游路由 → 直连，随后桥接。
    async fn handle_client_open(
        self: &Arc<Self>,
        mux: Arc<MuxSession>,
        req: OpenRequest,
        acl_router: Arc<ProxyRouter>,
    ) {
        let open_req: OpenChannel = match serde_json::from_slice(&req.payload) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "invalid open payload from client");
                let _ = mux.send_frame(Frame::empty(FrameType::OpenFail, req.channel_id)).await;
                return;
            }
        };

        let target = format!("{}:{}", open_req.target_addr, open_req.target_port);

        // ACL：目标必须命中该账号权限组的规则
        if !acl_router.matches_target(&target) {
            warn!(target = %target, "client open denied by ACL");
            let _ = mux.send_frame(Frame::empty(FrameType::OpenFail, req.channel_id)).await;
            return;
        }

        let channel = mux.accept_channel(req.channel_id);

        // 优先走下游节点通告路由，否则本机直连
        let bridged = if let Some(peer_id) = self.resolve_peer(&open_req.target_addr) {
            match self.open_channel(&peer_id, &open_req.target_addr, open_req.target_port).await {
                Ok(peer_channel) => {
                    if mux.send_frame(Frame::empty(FrameType::OpenOk, req.channel_id)).await.is_err() {
                        return;
                    }
                    crate::relay::bridge::bridge(channel, peer_channel).await.ok();
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
                    if mux.send_frame(Frame::empty(FrameType::OpenOk, req.channel_id)).await.is_err() {
                        return;
                    }
                    crate::relay::bridge::bridge(channel, local).await.ok();
                    true
                }
                Err(e) => {
                    debug!(target = %target, error = %e, "direct connect failed");
                    false
                }
            }
        };

        if !bridged {
            let _ = mux.send_frame(Frame::empty(FrameType::OpenFail, req.channel_id)).await;
        }
        mux.close_channel(req.channel_id);
    }

    /// 更新某下游节点的通告路由并重建汇总表。
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
        // 最长后缀优先
        table.suffixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        self.routes.store(Arc::new(table));
    }

    /// 向指定节点发起新连接请求（Open Channel）
    pub async fn open_channel(
        &self,
        node_id: &str,
        target_addr: &str,
        target_port: u16,
    ) -> Result<MuxChannel> {
        let peer = self
            .peers
            .get(node_id)
            .ok_or_else(|| Error::NotFound(format!("peer node {node_id} not connected")))?;

        let payload = serde_json::to_vec(&OpenChannel {
            target_addr: target_addr.to_string(),
            target_port,
        })
        .map_err(|e| Error::Protocol(e.to_string()))?;

        peer.mux.open_channel(Bytes::from(payload)).await
    }
}

/// 连接计数守卫：drop 时自动扣减。
struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 把 ACL 规则字符串编译为 ProxyRouter（命中即允许）。
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
