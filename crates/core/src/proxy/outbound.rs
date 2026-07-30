//! 出站策略实现
//!
//! 占位实现，M3 (DIRECT) + M4 (Tunnel) 里程碑完善。

use crate::error::Result;
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// 直连出站。
pub struct DirectOutbound;

impl DirectOutbound {
    /// 直接 TCP 连接到目标地址。
    pub async fn connect(target: SocketAddr) -> Result<TcpStream> {
        let stream = TcpStream::connect(target).await?;
        Ok(stream)
    }
}
