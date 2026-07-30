//! Relay Listener — 上游角色，接受下游连入
//!
//! 监听 TLS 端口，验证连入的节点 Token，管理多路复用会话 (MuxSession)。

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::{AuthRequest, OpenChannel};
use crate::relay::mux::{MuxChannel, MuxSession};
use crate::tunnel::tls::TlsConfigBuilder;

use bytes::Bytes;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// 已连入的节点会话
pub struct PeerSession {
    pub node_id: String,
    pub mux: Arc<MuxSession>,
}

/// Relay 监听器。
pub struct RelayListener {
    listen_addr: SocketAddr,
    expected_token: String,
    tls_acceptor: TlsAcceptor,
    peers: Arc<DashMap<String, PeerSession>>,
}

impl RelayListener {
    /// 创建新的 RelayListener。如果未配置证书，将生成自签证书。
    pub fn new(listen_addr: SocketAddr, expected_token: impl Into<String>) -> Result<Self> {
        let (server_config, _) = TlsConfigBuilder::new().build_server()?;
        let tls_acceptor = TlsAcceptor::from(server_config);

        Ok(Self {
            listen_addr,
            expected_token: expected_token.into(),
            tls_acceptor,
            peers: Arc::new(DashMap::new()),
        })
    }

    /// 使用自定义 TlsAcceptor 创建
    pub fn with_tls_acceptor(
        listen_addr: SocketAddr,
        expected_token: impl Into<String>,
        tls_acceptor: TlsAcceptor,
    ) -> Self {
        Self {
            listen_addr,
            expected_token: expected_token.into(),
            tls_acceptor,
            peers: Arc::new(DashMap::new()),
        }
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 当前连入且认证成功的下游节点数。
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// 启动监听服务
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!(addr = %self.listen_addr, "relay listener started");

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!(peer = %peer_addr, "incoming tcp connection");

            let tls_acceptor = self.tls_acceptor.clone();
            let expected_token = self.expected_token.clone();
            let peers = self.peers.clone();

            tokio::spawn(async move {
                if let Err(err) =
                    Self::handle_connection(stream, peer_addr, tls_acceptor, expected_token, peers)
                        .await
                {
                    warn!(peer = %peer_addr, error = %err, "relay connection closed with error");
                }
            });
        }
    }

    /// 处理单个 TCP 连接（TLS 握手 + 认证 + 控制循环）
    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        tls_acceptor: TlsAcceptor,
        expected_token: String,
        peers: Arc<DashMap<String, PeerSession>>,
    ) -> Result<()> {
        let mut tls_stream = tls_acceptor.accept(stream).await?;
        debug!(peer = %peer_addr, "tls handshake completed");

        // 1. 读取首个 Auth 帧
        let frame = Frame::read_from(&mut tls_stream).await?;
        if frame.frame_type != FrameType::Auth {
            let _ = Frame::empty(FrameType::AuthFail, 0)
                .write_to(&mut tls_stream)
                .await;
            return Err(Error::Protocol("expected Auth frame".into()));
        }

        let auth_req: AuthRequest = serde_json::from_slice(&frame.payload)
            .map_err(|e| Error::Protocol(format!("invalid auth payload: {e}")))?;

        if auth_req.token != expected_token {
            warn!(peer = %peer_addr, node_id = %auth_req.node_id, "auth failed: token mismatch");
            let _ = Frame::empty(FrameType::AuthFail, 0)
                .write_to(&mut tls_stream)
                .await;
            return Err(Error::Auth("token mismatch".into()));
        }

        // 认证成功，响应 AuthOk
        Frame::empty(FrameType::AuthOk, 0)
            .write_to(&mut tls_stream)
            .await?;
        info!(peer = %peer_addr, node_id = %auth_req.node_id, "node authenticated successfully");

        let node_id = auth_req.node_id.clone();

        // 启动 MuxSession
        let (mux, reader_handle) = MuxSession::start(tls_stream, 1, None);

        peers.insert(
            node_id.clone(),
            PeerSession {
                node_id: node_id.clone(),
                mux: mux.clone(),
            },
        );

        // 等待 reader 结束（连接断开）
        let _ = reader_handle.await;

        peers.remove(&node_id);
        info!(node_id = %node_id, "peer disconnected");
        Ok(())
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
