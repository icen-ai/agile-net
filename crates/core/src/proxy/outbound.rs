//! 出站策略实现
//!
//! 支持 DIRECT 直连出站 与 Tunnel 隧道转发出站。

use crate::error::Result;
use crate::relay::bridge::bridge;
use crate::relay::listener::RelayListener;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::debug;

/// 直连出站。
pub struct DirectOutbound;

impl DirectOutbound {
    /// 直接 TCP 连接到目标地址。
    pub async fn connect(target: SocketAddr) -> Result<TcpStream> {
        let stream = TcpStream::connect(target).await?;
        Ok(stream)
    }
}

/// Tunnel 隧道出站。
pub struct TunnelOutbound {
    listener: Arc<RelayListener>,
}

impl TunnelOutbound {
    pub fn new(listener: Arc<RelayListener>) -> Self {
        Self { listener }
    }

    /// 通过指定 Relay 节点的隧道发起端到端转发
    pub async fn proxy_stream<S>(
        &self,
        node_id: &str,
        target_host: &str,
        target_port: u16,
        client_stream: S,
    ) -> Result<(u64, u64)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        debug!(
            node_id,
            target_host, target_port, "initiating tunnel outbound"
        );
        let mux_channel = self
            .listener
            .open_channel(node_id, target_host, target_port)
            .await?;

        let (bytes_sent, bytes_recv) = bridge(client_stream, mux_channel).await?;
        Ok((bytes_sent, bytes_recv))
    }
}
