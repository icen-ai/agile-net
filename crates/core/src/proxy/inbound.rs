//! SOCKS5 / HTTP CONNECT 代理入站实现
//!
//! 支持自动识别首字节协议：
//! - `0x05`: SOCKS5 握手
//! - HTTP 动词 (G/P/C/H/O/D): HTTP CONNECT 代理

use crate::error::{Error, Result};
use crate::proxy::outbound::{DirectOutbound, TunnelOutbound};
use crate::proxy::router::{Outbound, ProxyRouter};
use crate::relay::listener::RelayListener;
use arc_swap::ArcSwap;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

/// 代理入站监听器
pub struct ProxyInbound {
    listen_addr: SocketAddr,
    router: Arc<ArcSwap<ProxyRouter>>,
    relay_listener: Option<Arc<RelayListener>>,
}

impl ProxyInbound {
    pub fn new(listen_addr: SocketAddr, router: Arc<ArcSwap<ProxyRouter>>) -> Self {
        Self {
            listen_addr,
            router,
            relay_listener: None,
        }
    }

    pub fn with_relay_listener(mut self, relay_listener: Arc<RelayListener>) -> Self {
        self.relay_listener = Some(relay_listener);
        self
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// 启动代理入站服务
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!(addr = %self.listen_addr, "proxy inbound started (SOCKS5/HTTP auto-detect)");

        loop {
            let (stream, client_addr) = listener.accept().await?;
            let router = self.router.clone();
            let relay_listener = self.relay_listener.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_connection(stream, client_addr, router, relay_listener).await
                {
                    debug!(client = %client_addr, error = %e, "proxy connection handled with error");
                }
            });
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        client_addr: SocketAddr,
        router: Arc<ArcSwap<ProxyRouter>>,
        relay_listener: Option<Arc<RelayListener>>,
    ) -> Result<()> {
        // 读取首字节判断协议
        let mut first_byte = [0u8; 1];
        stream.read_exact(&mut first_byte).await?;

        match first_byte[0] {
            0x05 => Self::handle_socks5(stream, client_addr, router, relay_listener).await,
            b'G' | b'P' | b'C' | b'H' | b'O' | b'D' => {
                Self::handle_http(stream, client_addr, first_byte[0], router, relay_listener).await
            }
            other => Err(Error::Protocol(format!(
                "unsupported proxy protocol first byte: {other:#x}"
            ))),
        }
    }

    /// 处理 SOCKS5 握手与请求
    async fn handle_socks5(
        mut stream: TcpStream,
        client_addr: SocketAddr,
        router: Arc<ArcSwap<ProxyRouter>>,
        relay_listener: Option<Arc<RelayListener>>,
    ) -> Result<()> {
        // 1. 协商认证方式
        let mut nmethods = [0u8; 1];
        stream.read_exact(&mut nmethods).await?;
        let mut methods = vec![0u8; nmethods[0] as usize];
        stream.read_exact(&mut methods).await?;

        // 响应 NO AUTHENTICATION REQUIRED (0x00)
        stream.write_all(&[0x05, 0x00]).await?;

        // 2. 读取请求头: VER(0x05), CMD(0x01=CONNECT), RSV(0x00), ATYP
        let mut req_header = [0u8; 4];
        stream.read_exact(&mut req_header).await?;

        if req_header[1] != 0x01 {
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(Error::Protocol("only SOCKS5 CONNECT is supported".into()));
        }

        let (target_host, target_port) = match req_header[3] {
            0x01 => {
                // IPv4
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let port_num = u16::from_be_bytes(port);
                (format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), port_num)
            }
            0x03 => {
                // Domain name
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let port_num = u16::from_be_bytes(port);
                (String::from_utf8_lossy(&domain).to_string(), port_num)
            }
            0x06 => {
                // IPv6
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let port_num = u16::from_be_bytes(port);
                let ip_addr = std::net::Ipv6Addr::from(ip);
                (ip_addr.to_string(), port_num)
            }
            atyp => {
                return Err(Error::Protocol(format!("unsupported SOCKS5 ATYP: {atyp}")));
            }
        };

        let target_str = format!("{target_host}:{target_port}");
        debug!(client = %client_addr, target = %target_str, "SOCKS5 request received");

        let router_ref = router.load();
        let outbound = router_ref.route_target(&target_str);

        match outbound {
            Outbound::Direct => {
                let target_addr: SocketAddr = match target_str.parse() {
                    Ok(a) => a,
                    Err(_) => tokio::net::lookup_host(&target_str)
                        .await?
                        .next()
                        .ok_or_else(|| Error::Other("dns resolution failed".into()))?,
                };

                match DirectOutbound::connect(target_addr).await {
                    Ok(mut target_stream) => {
                        stream
                            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await?;

                        let _ =
                            tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await;
                        Ok(())
                    }
                    Err(e) => {
                        let _ = stream
                            .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                        Err(e)
                    }
                }
            }
            Outbound::Tunnel { node_id } => {
                if let Some(relay_listener) = relay_listener {
                    stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;

                    let tunnel_outbound = TunnelOutbound::new(relay_listener);
                    tunnel_outbound
                        .proxy_stream(node_id, &target_host, target_port, stream)
                        .await?;
                    Ok(())
                } else {
                    let _ = stream
                        .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    Err(Error::Other(
                        "no relay listener configured for tunnel routing".into(),
                    ))
                }
            }
        }
    }

    /// 处理 HTTP CONNECT / Request
    async fn handle_http(
        mut stream: TcpStream,
        client_addr: SocketAddr,
        first_byte: u8,
        router: Arc<ArcSwap<ProxyRouter>>,
        relay_listener: Option<Arc<RelayListener>>,
    ) -> Result<()> {
        let mut req_buf = vec![first_byte];
        let mut line_buf = [0u8; 1024];

        let n = stream.read(&mut line_buf).await?;
        req_buf.extend_from_slice(&line_buf[..n]);

        let req_str = String::from_utf8_lossy(&req_buf);
        let first_line = req_str.lines().next().unwrap_or_default();

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(Error::Protocol("invalid HTTP request format".into()));
        }

        let method = parts[0];
        let uri = parts[1];

        let (target_host, target_port) = if method == "CONNECT" {
            let mut parts = uri.split(':');
            let host = parts.next().unwrap_or_default().to_string();
            let port = parts.next().and_then(|p| p.parse().ok()).unwrap_or(443);
            (host, port)
        } else {
            let mut host = "";
            for line in req_str.lines() {
                if line.to_lowercase().starts_with("host:") {
                    host = line[5..].trim();
                    break;
                }
            }
            if host.is_empty() {
                return Err(Error::Protocol(
                    "missing Host header in HTTP request".into(),
                ));
            }
            if let Some((h, p)) = host.split_once(':') {
                (h.to_string(), p.parse().unwrap_or(80))
            } else {
                (host.to_string(), 80)
            }
        };

        let target_str = format!("{target_host}:{target_port}");
        debug!(client = %client_addr, target = %target_str, "HTTP Proxy request received");

        let router_ref = router.load();
        let outbound = router_ref.route_target(&target_str);

        match outbound {
            Outbound::Direct => {
                let target_addr: SocketAddr = match target_str.parse() {
                    Ok(a) => a,
                    Err(_) => tokio::net::lookup_host(&target_str)
                        .await?
                        .next()
                        .ok_or_else(|| Error::Other("dns resolution failed".into()))?,
                };

                match DirectOutbound::connect(target_addr).await {
                    Ok(mut target_stream) => {
                        if method == "CONNECT" {
                            stream
                                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                                .await?;
                        } else {
                            target_stream.write_all(&req_buf).await?;
                        }

                        let _ =
                            tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await;
                        Ok(())
                    }
                    Err(e) => {
                        let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        Err(e)
                    }
                }
            }
            Outbound::Tunnel { node_id } => {
                if let Some(relay_listener) = relay_listener {
                    if method == "CONNECT" {
                        stream
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await?;
                    }

                    let tunnel_outbound = TunnelOutbound::new(relay_listener);
                    tunnel_outbound
                        .proxy_stream(node_id, &target_host, target_port, stream)
                        .await?;
                    Ok(())
                } else {
                    let _ = stream
                        .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                        .await;
                    Err(Error::Other(
                        "no relay listener configured for tunnel routing".into(),
                    ))
                }
            }
        }
    }
}
