//! 出站策略实现
//!
//! 支持 DIRECT 直连出站、Tunnel 隧道转发出站与回环上游转发（mihomo sidecar）。

use crate::error::{Error, Result};
use crate::relay::bridge::bridge;
use crate::tunnel::opener::ChannelOpener;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

/// 回环上游转发（mihomo sidecar mixed 入站）：
/// 入站已完成与客户端的握手并解析出目标，此处作为 SOCKS5 客户端把目标转交上游内核。
pub struct Socks5ForwardOutbound;

impl Socks5ForwardOutbound {
    /// 连接上游并完成 SOCKS5 CONNECT（无认证），返回已就绪的上游流。
    pub async fn connect(
        upstream: SocketAddr,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream> {
        let mut up = TcpStream::connect(upstream).await?;

        // 方法协商：仅 NO AUTH
        up.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method_resp = [0u8; 2];
        up.read_exact(&mut method_resp).await?;
        if method_resp != [0x05, 0x00] {
            return Err(Error::Protocol("upstream proxy rejected no-auth".into()));
        }

        // CONNECT 请求
        let mut req = vec![0x05, 0x01, 0x00];
        if let Ok(ip4) = target_host.parse::<std::net::Ipv4Addr>() {
            req.push(0x01);
            req.extend_from_slice(&ip4.octets());
        } else if let Ok(ip6) = target_host.parse::<std::net::Ipv6Addr>() {
            req.push(0x04);
            req.extend_from_slice(&ip6.octets());
        } else {
            let domain = target_host.as_bytes();
            if domain.len() > 255 {
                return Err(Error::Protocol("target host too long".into()));
            }
            req.push(0x03);
            req.push(domain.len() as u8);
            req.extend_from_slice(domain);
        }
        req.extend_from_slice(&target_port.to_be_bytes());
        up.write_all(&req).await?;

        // 应答：VER REP RSV ATYP BND.ADDR BND.PORT
        let mut head = [0u8; 4];
        up.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err(Error::Protocol("invalid upstream socks5 reply".into()));
        }
        if head[1] != 0x00 {
            return Err(Error::Other(format!(
                "upstream connect failed (rep={})",
                head[1]
            )));
        }
        let skip = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                up.read_exact(&mut len).await?;
                len[0] as usize
            }
            other => {
                return Err(Error::Protocol(format!(
                    "invalid upstream socks5 atyp: {other}"
                )))
            }
        };
        let mut bound = vec![0u8; skip + 2];
        up.read_exact(&mut bound).await?;
        Ok(up)
    }

    /// 转发并桥接（SOCKS5 入站路径：握手已就绪后直接双向转发）。
    pub async fn proxy_stream<S>(
        upstream: SocketAddr,
        target_host: &str,
        target_port: u16,
        client_stream: S,
    ) -> Result<(u64, u64)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        debug!(%upstream, target_host, target_port, "forwarding via upstream proxy");
        let up = Self::connect(upstream, target_host, target_port).await?;
        Ok(bridge(client_stream, up).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// 最小 SOCKS5 服务端：校验 greeting 与 CONNECT 目标，回显目标后透传。
    async fn mock_socks5_server(listener: TcpListener, expect_host: String, expect_port: u16) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        stream.write_all(&[0x05, 0x00]).await.unwrap();

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..3], &[0x05, 0x01, 0x00]);
        let host = match head[3] {
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.unwrap();
                let mut domain = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain).await.unwrap();
                String::from_utf8(domain).unwrap()
            }
            other => panic!("unexpected atyp {other}"),
        };
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.unwrap();
        assert_eq!(host, expect_host);
        assert_eq!(u16::from_be_bytes(port), expect_port);

        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        // 回显一字节后关闭
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await.unwrap();
        stream.write_all(&b).await.unwrap();
    }

    #[tokio::test]
    async fn socks5_forward_handshake_and_relay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let server = tokio::spawn(mock_socks5_server(
            listener,
            "example.com".to_string(),
            443,
        ));

        let mut up = Socks5ForwardOutbound::connect(upstream, "example.com", 443)
            .await
            .unwrap();
        up.write_all(b"x").await.unwrap();
        let mut echo = [0u8; 1];
        up.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, *b"x");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_forward_rejects_failure_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            stream.read_exact(&mut head).await.unwrap();
            // 域名 + 端口读取后回 rep=0x05（连接被拒绝）
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await.unwrap();
            stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let err = Socks5ForwardOutbound::connect(upstream, "example.com", 443).await;
        assert!(err.is_err());
    }
}

/// Tunnel 隧道出站。
pub struct TunnelOutbound {
    opener: Arc<dyn ChannelOpener>,
}

impl TunnelOutbound {
    pub fn new(opener: Arc<dyn ChannelOpener>) -> Self {
        Self { opener }
    }

    /// 通过指定节点的隧道发起端到端转发
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
        let mux_channel = self.opener.open(node_id, target_host, target_port).await?;

        let (bytes_sent, bytes_recv) = bridge(client_stream, mux_channel).await?;
        Ok((bytes_sent, bytes_recv))
    }
}
