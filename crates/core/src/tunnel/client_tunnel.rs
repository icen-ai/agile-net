//! 客户端隧道 (ClientTunnel)
//!
//! 客户端到节点的数据面连接：TLS 1.3 + tunnel_token 认证，
//! 在单条 TLS 连接上多路复用逻辑通道，每个通道对应一条端到端 TCP 连接。
//! 支持心跳保活、空闲超时检测与指数退避自动重连。

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::{AuthKind, AuthRequest, OpenChannel, PROTOCOL_VERSION};
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

/// 心跳基础间隔（实际为 25s + 0~10s 随机）。
const PING_BASE_SECS: u64 = 25;
/// 空闲超时：90s 未收到服务端任何帧则判定断线。
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// 重连退避上限。
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// 客户端隧道：到单个节点的数据面连接。
pub struct ClientTunnel {
    upstream_addr: SocketAddr,
    account_id: String,
    tunnel_token: String,
    tls_connector: TlsConnector,
    sni_hostname: String,
    session: Arc<Mutex<Option<Arc<MuxSession>>>>,
    state: Arc<AtomicU8>,
    shutdown_notify: Arc<Notify>,
    shutdown_flag: Arc<AtomicBool>,
}

impl ClientTunnel {
    /// 使用自定义 TLS 配置创建（生产推荐证书固定 pinning）。
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
            tunnel_token: tunnel_token.into(),
            tls_connector: TlsConnector::from(client_config),
            sni_hostname: tls_builder.sni_hostname,
            session: Arc::new(Mutex::new(None)),
            state: Arc::new(AtomicU8::new(ConnectionState::Disconnected as u8)),
            shutdown_notify: Arc::new(Notify::new()),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// 开发模式创建（不校验服务端证书，仅调试使用）。
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

    /// 建立一次连接（TLS + 认证 + 会话维护任务）。
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
            token: self.tunnel_token.clone(),
            kind: AuthKind::Client,
            advertise: Vec::new(),
            version: PROTOCOL_VERSION,
        };
        let payload = serde_json::to_vec(&auth_req).map_err(|e| Error::Protocol(e.to_string()))?;
        Frame::new(FrameType::Auth, 0, Bytes::from(payload))
            .write_to(&mut tls_stream)
            .await?;

        let res_frame = Frame::read_from(&mut tls_stream).await?;
        match res_frame.frame_type {
            FrameType::AuthOk => {}
            FrameType::AuthFail => {
                return Err(Error::Auth("node rejected tunnel token".into()));
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected frame during auth: {other:?}"
                )));
            }
        }

        // 客户端是会话中唯一发起 Open 的一方，使用偶数 channel_id
        let (mux, reader_handle) = MuxSession::start(tls_stream, 2, None);

        // 会话维护任务：心跳（带抖动）+ 空闲超时检测
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
                    // reader 任务结束（连接断开）时退出：通过等待 reader_handle 实现
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

    /// 在隧道上打开到目标地址的通道。
    pub async fn open_channel(&self, target_host: &str, target_port: u16) -> Result<MuxChannel> {
        let session = {
            let guard = self.session.lock().await;
            guard.clone()
        }
        .ok_or_else(|| Error::Other("tunnel not connected".into()))?;

        let payload = serde_json::to_vec(&OpenChannel {
            target_addr: target_host.to_string(),
            target_port,
        })
        .map_err(|e| Error::Protocol(e.to_string()))?;

        session.open_channel(Bytes::from(payload)).await
    }

    /// 永久运行：断线自动重连（指数退避 + 抖动），直到 shutdown。
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

    /// 断开隧道。
    pub async fn disconnect(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
        self.state
            .store(ConnectionState::Disconnected as u8, Ordering::Relaxed);
    }
}

/// 等待 JoinHandle 完成（不消耗它）。
async fn futures_lite_wait(handle: &tokio::task::JoinHandle<()>) {
    // JoinHandle 不能直接 & 等待；轮询 is_finished 即可（reader 结束即返回）
    while !handle.is_finished() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// 下一次心跳间隔：25s + 0~10s 随机抖动。
fn next_ping_delay() -> Duration {
    Duration::from_secs(PING_BASE_SECS + rand::random::<u64>() % 10)
}
