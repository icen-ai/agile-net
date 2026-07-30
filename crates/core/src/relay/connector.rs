//! Relay Connector — 下游角色，主动连接上游
//!
//! 连接上游 Listener，完成 TLS 握手与 Auth 认证，维护心跳，响应 Open 帧建立本地 TCP 转发。

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::{AuthRequest, OpenChannel};
use crate::relay::bridge::bridge;
use crate::relay::mux::{MuxSession, OpenRequest};
use crate::tunnel::tls::TlsConfigBuilder;

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

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
    state: Arc<AtomicU8>,
    shutdown_notify: Arc<Notify>,
}

impl RelayConnector {
    /// 创建新的 RelayConnector。
    pub fn new(
        upstream_addr: SocketAddr,
        node_id: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self> {
        let tls_builder = TlsConfigBuilder::new().allow_self_signed(true);
        let client_config = tls_builder.build_client()?;
        let tls_connector = TlsConnector::from(client_config);

        Ok(Self {
            upstream_addr,
            node_id: node_id.into(),
            token: token.into(),
            tls_connector,
            sni_hostname: tls_builder.sni_hostname,
            state: Arc::new(AtomicU8::new(ConnectionState::Disconnected as u8)),
            shutdown_notify: Arc::new(Notify::new()),
        })
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

    /// 连接上游，自动发起 TLS 握手与 Auth 认证。
    pub async fn connect(&self) -> Result<()> {
        self.state
            .store(ConnectionState::Connecting as u8, Ordering::Relaxed);

        let tcp_stream = TcpStream::connect(self.upstream_addr).await?;
        let server_name = rustls::pki_types::ServerName::try_from(self.sni_hostname.clone())
            .map_err(|e| Error::Tls(e.to_string()))?;

        let mut tls_stream = self.tls_connector.connect(server_name, tcp_stream).await?;
        debug!(upstream = %self.upstream_addr, "tls connected to upstream");

        // 发送 Auth 帧
        let auth_req = AuthRequest {
            node_id: self.node_id.clone(),
            token: self.token.clone(),
        };
        let payload = serde_json::to_vec(&auth_req).map_err(|e| Error::Protocol(e.to_string()))?;
        Frame::new(FrameType::Auth, 0, Bytes::from(payload))
            .write_to(&mut tls_stream)
            .await?;

        // 读取 Auth 回复
        let res_frame = Frame::read_from(&mut tls_stream).await?;
        match res_frame.frame_type {
            FrameType::AuthOk => {
                info!(upstream = %self.upstream_addr, "authenticated successfully with upstream");
                self.state
                    .store(ConnectionState::Connected as u8, Ordering::Relaxed);
            }
            FrameType::AuthFail => {
                self.state
                    .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
                return Err(Error::Auth("upstream rejected authentication token".into()));
            }
            other => {
                self.state
                    .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
                return Err(Error::Protocol(format!(
                    "unexpected frame during auth: {other:?}"
                )));
            }
        }

        let (open_tx, mut open_rx) = mpsc::channel::<OpenRequest>(64);
        let (mux, reader_handle) = MuxSession::start(tls_stream, 2, Some(open_tx));

        // 开启后台处理循环（处理心跳与 Open 通道请求）
        let shutdown_notify = self.shutdown_notify.clone();
        let state = self.state.clone();

        tokio::spawn(async move {
            let mut ping_interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = shutdown_notify.notified() => {
                        info!("connector shutdown requested");
                        let _ = mux.send_frame(Frame::empty(FrameType::Close, 0)).await;
                        break;
                    }
                    _ = ping_interval.tick() => {
                        debug!("sending ping to upstream");
                        if let Err(e) = mux.send_frame(Frame::empty(FrameType::Ping, 0)).await {
                            warn!(error = %e, "failed to send ping frame");
                            break;
                        }
                    }
                    Some(req) = open_rx.recv() => {
                        let mux_inner = mux.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_open(mux_inner, req).await {
                                warn!(error = %e, "failed to handle open channel");
                            }
                        });
                    }
                }
            }

            let _ = reader_handle.await;
            state.store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
        });

        Ok(())
    }

    /// 收到 Open 帧后，连接本地真实服务并建立 bridge 数据转接
    async fn handle_open(mux: Arc<MuxSession>, req: OpenRequest) -> Result<()> {
        let open_req: OpenChannel = serde_json::from_slice(&req.payload)
            .map_err(|e| Error::Protocol(format!("invalid open channel payload: {e}")))?;

        let target_addr = format!("{}:{}", open_req.target_addr, open_req.target_port);
        debug!(channel_id = req.channel_id, target = %target_addr, "connecting to local target");

        let local_stream = match TcpStream::connect(&target_addr).await {
            Ok(s) => s,
            Err(err) => {
                warn!(channel_id = req.channel_id, target = %target_addr, error = %err, "failed to connect local target");
                mux.send_frame(Frame::empty(FrameType::OpenFail, req.channel_id))
                    .await?;
                return Err(err.into());
            }
        };

        mux.send_frame(Frame::empty(FrameType::OpenOk, req.channel_id))
            .await?;

        let mux_channel = mux.accept_channel(req.channel_id);

        let (bytes_ab, bytes_ba) = bridge(local_stream, mux_channel).await?;
        debug!(
            channel_id = req.channel_id,
            bytes_sent = bytes_ab,
            bytes_recv = bytes_ba,
            "channel bridge finished"
        );

        mux.close_channel(req.channel_id);
        Ok(())
    }

    /// 断开连接
    pub async fn disconnect(&self) {
        self.shutdown_notify.notify_one();
        self.state
            .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
    }
}
