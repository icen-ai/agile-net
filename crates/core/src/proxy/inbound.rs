//! SOCKS5 / HTTP CONNECT 代理入站实现
//!
//! 支持自动识别首字节协议：
//! - `0x05`: SOCKS5 握手（支持 NO AUTH 与 RFC 1929 用户名密码认证）
//! - HTTP 动词 (G/P/C/H/O/D/T): HTTP 代理（CONNECT 与普通请求，支持 Basic 代理认证）
//!
//! 安全设计：
//! - 可选用户名密码认证（强烈建议在非 loopback 绑定时启用）
//! - 握手阶段 10s 超时（防 Slowloris）
//! - 并发连接数上限（防连接洪泛）

use crate::error::{Error, Result};
use crate::proxy::outbound::{DirectOutbound, TunnelOutbound};
use crate::proxy::router::{Outbound, ProxyRouter};
use crate::relay::listener::RelayListener;
use crate::tunnel::opener::ChannelOpener;
use arc_swap::ArcSwap;

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// 握手（协议协商 + 认证 + 请求头读取）超时。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 最大并发入站连接数。
const MAX_INBOUND_CONNECTIONS: usize = 2048;
/// HTTP 请求头最大字节数。
const MAX_HTTP_HEADER: usize = 16 * 1024;

/// 代理入站运行统计。
#[derive(Default)]
pub struct ProxyStats {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

/// 代理入站监听器
pub struct ProxyInbound {
    listen_addr: SocketAddr,
    router: Arc<ArcSwap<ProxyRouter>>,
    /// 按 node_id 注册的通道开启器
    openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>,
    /// 兜底通道开启器（路由命中未注册 node_id 时使用）
    default_opener: Option<Arc<dyn ChannelOpener>>,
    /// 可选用户名密码认证
    auth: Option<(String, String)>,
    stats: Arc<ProxyStats>,
}

impl ProxyInbound {
    pub fn new(listen_addr: SocketAddr, router: Arc<ArcSwap<ProxyRouter>>) -> Self {
        Self {
            listen_addr,
            router,
            openers: Arc::new(DashMap::new()),
            default_opener: None,
            auth: None,
            stats: Arc::new(ProxyStats::default()),
        }
    }

    /// 注册 RelayListener 作为兜底通道开启器（向后兼容）。
    pub fn with_relay_listener(mut self, relay_listener: Arc<RelayListener>) -> Self {
        self.default_opener = Some(relay_listener);
        self
    }

    /// 注册指定节点的通道开启器。
    pub fn with_opener(self, node_id: impl Into<String>, opener: Arc<dyn ChannelOpener>) -> Self {
        self.openers.insert(node_id.into(), opener);
        self
    }

    /// 设置兜底通道开启器。
    pub fn with_default_opener(mut self, opener: Arc<dyn ChannelOpener>) -> Self {
        self.default_opener = Some(opener);
        self
    }

    /// 通道开启器注册表句柄（运行期动态注册/移除，如客户端节点上下线）。
    pub fn openers_handle(&self) -> Arc<DashMap<String, Arc<dyn ChannelOpener>>> {
        self.openers.clone()
    }

    /// 使用外部共享的开启器注册表（客户端引擎与入站共用一张表）。
    pub fn with_openers_map(mut self, openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>) -> Self {
        self.openers = openers;
        self
    }

    /// 运行期设置兜底通道开启器。
    pub fn set_default_opener(&mut self, opener: Arc<dyn ChannelOpener>) {
        self.default_opener = Some(opener);
    }

    /// 启用用户名密码认证（SOCKS5 RFC1929 / HTTP Basic）。
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn stats(&self) -> Arc<ProxyStats> {
        self.stats.clone()
    }

    /// 启动代理入站服务（自行绑定监听地址）
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        self.start_on(listener).await
    }

    /// 在已绑定的 TcpListener 上提供服务（调用方需要提前拿到确定端口时使用）。
    pub async fn start_on(&self, listener: TcpListener) -> Result<()> {
        // 安全提醒：无认证暴露在非 loopback 上是开放代理风险
        if self.auth.is_none() && !self.listen_addr.ip().is_loopback() {
            warn!(
                addr = %self.listen_addr,
                "proxy inbound listening on non-loopback WITHOUT authentication — open proxy risk!"
            );
        }

        info!(addr = %self.listen_addr, "proxy inbound started (SOCKS5/HTTP auto-detect)");

        loop {
            let (stream, client_addr) = listener.accept().await?;

            let active = self.stats.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
            if active > MAX_INBOUND_CONNECTIONS as u64 {
                self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                warn!(client = %client_addr, "inbound connection limit reached, dropping");
                drop(stream);
                continue;
            }
            self.stats.total_connections.fetch_add(1, Ordering::Relaxed);

            let this = InboundCtx {
                listen_addr: self.listen_addr,
                router: self.router.clone(),
                openers: self.openers.clone(),
                default_opener: self.default_opener.clone(),
                auth: self.auth.clone(),
                stats: self.stats.clone(),
            };

            tokio::spawn(async move {
                let _guard = ActiveGuard(this.stats.clone());
                if let Err(e) = handle_connection(stream, client_addr, this).await {
                    debug!(client = %client_addr, error = %e, "proxy connection handled with error");
                }
            });
        }
    }
}

/// 每连接上下文（避免过多参数传递）。
#[derive(Clone)]
struct InboundCtx {
    listen_addr: SocketAddr,
    router: Arc<ArcSwap<ProxyRouter>>,
    openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>,
    default_opener: Option<Arc<dyn ChannelOpener>>,
    auth: Option<(String, String)>,
    stats: Arc<ProxyStats>,
}

/// 自连环防护：目标是代理自身监听地址时拒绝（否则 CONNECT 自身会无限递归新建连接）。
fn is_self_connect(ctx: &InboundCtx, addr: &SocketAddr) -> bool {
    *addr == ctx.listen_addr
}

struct ActiveGuard(Arc<ProxyStats>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    ctx: InboundCtx,
) -> Result<()> {
    // 读取首字节判断协议（限时，防 Slowloris）
    let mut first_byte = [0u8; 1];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut first_byte))
        .await
        .map_err(|_| Error::Timeout)??;

    match first_byte[0] {
        0x05 => handle_socks5(stream, client_addr, ctx).await,
        b'G' | b'P' | b'C' | b'H' | b'O' | b'D' | b'T' => {
            handle_http(stream, client_addr, first_byte[0], ctx).await
        }
        other => Err(Error::Protocol(format!(
            "unsupported proxy protocol first byte: {other:#x}"
        ))),
    }
}

/// 解析 Tunnel 出站对应的通道开启器。
fn resolve_opener(ctx: &InboundCtx, node_id: &str) -> Option<Arc<dyn ChannelOpener>> {
    ctx.openers
        .get(node_id)
        .map(|o| o.clone())
        .or_else(|| ctx.default_opener.clone())
}

/// 处理 SOCKS5 握手与请求
async fn handle_socks5(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    ctx: InboundCtx,
) -> Result<()> {
    // 1. 协商认证方式
    let mut nmethods = [0u8; 1];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut nmethods))
        .await
        .map_err(|_| Error::Timeout)??;
    let mut methods = vec![0u8; nmethods[0] as usize];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut methods))
        .await
        .map_err(|_| Error::Timeout)??;

    if let Some((ref expect_user, ref expect_pass)) = ctx.auth {
        // 要求 RFC 1929 用户名密码认证 (0x02)
        if !methods.contains(&0x02) {
            stream.write_all(&[0x05, 0xFF]).await?;
            return Err(Error::Auth("client does not support username/password auth".into()));
        }
        stream.write_all(&[0x05, 0x02]).await?;

        // RFC 1929: VER(1) ULEN UNAME PLEN PASSWD
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver).await?;
        let mut ulen = [0u8; 1];
        stream.read_exact(&mut ulen).await?;
        let mut uname = vec![0u8; ulen[0] as usize];
        stream.read_exact(&mut uname).await?;
        let mut plen = [0u8; 1];
        stream.read_exact(&mut plen).await?;
        let mut passwd = vec![0u8; plen[0] as usize];
        stream.read_exact(&mut passwd).await?;

        let ok = crate::relay::listener::constant_time_eq(&uname, expect_user.as_bytes())
            && crate::relay::listener::constant_time_eq(&passwd, expect_pass.as_bytes());
        if !ok {
            let _ = stream.write_all(&[0x01, 0x01]).await;
            let _ = stream.shutdown().await;
            return Err(Error::Auth("invalid socks5 credentials".into()));
        }
        stream.write_all(&[0x01, 0x00]).await?;
    } else {
        // 响应 NO AUTHENTICATION REQUIRED (0x00)
        stream.write_all(&[0x05, 0x00]).await?;
    }

    // 2. 读取请求头: VER(0x05), CMD(0x01=CONNECT), RSV(0x00), ATYP
    let mut req_header = [0u8; 4];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut req_header))
        .await
        .map_err(|_| Error::Timeout)??;

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

    if target_port == 0 {
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(Error::Protocol("invalid target port 0".into()));
    }

    let target_str = format!("{target_host}:{target_port}");
    debug!(client = %client_addr, target = %target_str, "SOCKS5 request received");

    let outbound = {
        let router_ref = ctx.router.load();
        router_ref.route_target(&target_str).clone()
    };

    match outbound {
        Outbound::Direct => {
            let target_addr: SocketAddr = match target_str.parse() {
                Ok(a) => a,
                Err(_) => tokio::net::lookup_host(&target_str)
                    .await?
                    .next()
                    .ok_or_else(|| Error::Other("dns resolution failed".into()))?,
            };

            // 自连环防护
            if is_self_connect(&ctx, &target_addr) {
                let _ = stream
                    .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let _ = stream.shutdown().await;
                return Err(Error::Protocol("refused: target is the proxy itself".into()));
            }

            match DirectOutbound::connect(target_addr).await {
                Ok(mut target_stream) => {
                    stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;

                    let (up, down) =
                        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await?;
                    ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                    ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
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
            if let Some(opener) = resolve_opener(&ctx, &node_id) {
                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;

                let tunnel_outbound = TunnelOutbound::new(opener);
                let (up, down) = tunnel_outbound
                    .proxy_stream(&node_id, &target_host, target_port, stream)
                    .await?;
                ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
                Ok(())
            } else {
                let _ = stream
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                Err(Error::Other(
                    "no channel opener configured for tunnel routing".into(),
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
    ctx: InboundCtx,
) -> Result<()> {
    // 读取完整请求头（至 \r\n\r\n，上限 16KB，限时）
    let mut req_buf = vec![first_byte];
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| Error::Timeout)??;
        if n == 0 {
            return Err(Error::Protocol("connection closed during http header".into()));
        }
        req_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subsequence(&req_buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if req_buf.len() > MAX_HTTP_HEADER {
            let _ = stream
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n")
                .await;
            // 优雅关闭写端，确保客户端读到 431 而非 RST
            let _ = stream.shutdown().await;
            return Err(Error::Protocol("http header too large".into()));
        }
    };

    let req_str = String::from_utf8_lossy(&req_buf[..header_end]);
    let first_line = req_str.lines().next().unwrap_or_default();

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(Error::Protocol("invalid HTTP request format".into()));
    }

    let method = parts[0];
    let uri = parts[1];

    // 代理认证校验
    if let Some((ref expect_user, ref expect_pass)) = ctx.auth {
        let mut ok = false;
        for line in req_str.lines() {
            if line.len() > 20 && line[..20].eq_ignore_ascii_case("proxy-authorization:") {
                let value = line[20..].trim();
                if let Some(b64) = value
                    .strip_prefix("Basic ")
                    .or_else(|| value.strip_prefix("basic "))
                {
                    let expected = basic_auth_value(expect_user, expect_pass);
                    ok = crate::relay::listener::constant_time_eq(
                        b64.trim().as_bytes(),
                        expected.as_bytes(),
                    );
                }
            }
        }
        if !ok {
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"agile-net\"\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Err(Error::Auth("proxy authentication required".into()));
        }
    }

    let (target_host, target_port) = if method == "CONNECT" {
        parse_host_port(uri, 443)?
    } else {
        let mut host = "";
        for line in req_str.lines() {
            if line.len() > 5 && line[..5].eq_ignore_ascii_case("host:") {
                host = line[5..].trim();
                break;
            }
        }
        if host.is_empty() {
            return Err(Error::Protocol(
                "missing Host header in HTTP request".into(),
            ));
        }
        parse_host_port(host, 80)?
    };

    if target_port == 0 {
        return Err(Error::Protocol("invalid target port 0".into()));
    }

    let target_str = format!("{target_host}:{target_port}");
    debug!(client = %client_addr, target = %target_str, "HTTP Proxy request received");

    let outbound = {
        let router_ref = ctx.router.load();
        router_ref.route_target(&target_str).clone()
    };

    match outbound {
        Outbound::Direct => {
            let target_addr: SocketAddr = match target_str.parse() {
                Ok(a) => a,
                Err(_) => tokio::net::lookup_host(&target_str)
                    .await?
                    .next()
                    .ok_or_else(|| Error::Other("dns resolution failed".into()))?,
            };

            // 自连环防护
            if is_self_connect(&ctx, &target_addr) {
                let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                return Err(Error::Protocol("refused: target is the proxy itself".into()));
            }

            match DirectOutbound::connect(target_addr).await {
                Ok(mut target_stream) => {
                    if method == "CONNECT" {
                        stream
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await?;
                        // CONNECT 之后可能存在紧随的 TLS 字节，需要转发头部之后的多余数据
                        if req_buf.len() > header_end {
                            target_stream.write_all(&req_buf[header_end..]).await?;
                        }
                    } else {
                        target_stream.write_all(&req_buf).await?;
                    }

                    let (up, down) =
                        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await?;
                    ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                    ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
                    Ok(())
                }
                Err(e) => {
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    Err(e)
                }
            }
        }
        Outbound::Tunnel { node_id } => {
            if let Some(opener) = resolve_opener(&ctx, &node_id) {
                let channel = opener.open(&node_id, &target_host, target_port).await?;
                let mut channel = channel;

                if method == "CONNECT" {
                    stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    if req_buf.len() > header_end {
                        channel.write_all(&req_buf[header_end..]).await?;
                    }
                } else {
                    // 普通 HTTP 请求经隧道转发时必须带上原始请求
                    channel.write_all(&req_buf).await?;
                }

                let (up, down) = crate::relay::bridge::bridge(stream, channel).await?;
                ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
                Ok(())
            } else {
                let _ = stream
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                    .await;
                Err(Error::Other(
                    "no channel opener configured for tunnel routing".into(),
                ))
            }
        }
    }
}

/// 解析 host:port（兼容 IPv6 括号写法 [::1]:443）。
fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port 或 [v6]
        if let Some((host, port_part)) = rest.split_once(']') {
            let port = port_part
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return Ok((host.to_string(), port));
        }
        return Err(Error::Protocol(format!("invalid host:port: {s}")));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let port = p.parse().unwrap_or(default_port);
            Ok((h.to_string(), port))
        }
        // 无端口或多冒号未加括号（裸 IPv6）
        _ => Ok((s.trim_matches(|c| c == '[' || c == ']').to_string(), default_port)),
    }
}

/// 在字节串中查找子串位置。
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 计算 Basic 认证头期望值（base64(user:pass)）。
fn basic_auth_value(user: &str, pass: &str) -> String {
    base64_encode(format!("{user}:{pass}").as_bytes())
}

/// 最小化 base64 编码。
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}
