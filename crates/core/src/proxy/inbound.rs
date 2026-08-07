//! SOCKS5 / HTTP CONNECT proxy inbound
//!
//! Protocol auto-detection by first byte:
//! - `0x05`: SOCKS5 handshake (NO AUTH and RFC 1929 username/password auth)
//! - HTTP verb (G/P/C/H/O/D/T): HTTP proxy (CONNECT and plain requests, Basic proxy auth)
//!
//! Security design:
//! - optional username/password auth (strongly recommended on non-loopback binds)
//! - 10s handshake timeout (Slowloris protection)
//! - concurrent connection cap (flood protection)

use crate::error::{Error, Result};
use crate::proxy::conlog::{ActiveCounters, ConnLog, CountingIo, HitLayer, OutboundKind, Proto};
use crate::proxy::outbound::{DirectOutbound, Socks5ForwardOutbound, TunnelOutbound};
use crate::proxy::router::{Outbound, ProxyRouter};
use crate::relay::listener::RelayListener;
use crate::relay::transit::{FROM_PROXY, TO_LOCAL, TransitMeter};
use crate::tunnel::opener::ChannelOpener;
use crate::util::base64_encode;
use arc_swap::ArcSwap;

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// Handshake timeout (protocol negotiation + auth + request header read).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Max concurrent inbound connections.
const MAX_INBOUND_CONNECTIONS: usize = 2048;
/// Max HTTP request header bytes.
const MAX_HTTP_HEADER: usize = 16 * 1024;

/// Proxy inbound runtime stats.
#[derive(Default)]
pub struct ProxyStats {
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

/// Proxy inbound listener
pub struct ProxyInbound {
    listen_addr: SocketAddr,
    router: Arc<ArcSwap<ProxyRouter>>,
    /// Channel openers registered by node_id
    openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>,
    /// Fallback channel opener (used when a route hits an unregistered node_id)
    default_opener: Option<Arc<dyn ChannelOpener>>,
    /// Optional username/password auth
    auth: Option<(String, String)>,
    stats: Arc<ProxyStats>,
    /// Transit accounting (None = no metering; proxy inbound forwarding is booked as from="proxy")
    transit: Option<Arc<TransitMeter>>,
    /// Connection log (None = not attached; attached-but-disabled still short-circuits per connection)
    conlog: Option<Arc<ConnLog>>,
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
            transit: None,
            conlog: None,
        }
    }

    /// Register a RelayListener as fallback channel opener.
    pub fn with_relay_listener(mut self, relay_listener: Arc<RelayListener>) -> Self {
        self.default_opener = Some(relay_listener);
        self
    }

    /// Register a channel opener for a given node.
    pub fn with_opener(self, node_id: impl Into<String>, opener: Arc<dyn ChannelOpener>) -> Self {
        self.openers.insert(node_id.into(), opener);
        self
    }

    /// Set the fallback channel opener.
    pub fn with_default_opener(mut self, opener: Arc<dyn ChannelOpener>) -> Self {
        self.default_opener = Some(opener);
        self
    }

    /// Opener registry handle (runtime register/remove, e.g. client nodes going up/down).
    pub fn openers_handle(&self) -> Arc<DashMap<String, Arc<dyn ChannelOpener>>> {
        self.openers.clone()
    }

    /// Use an externally shared opener registry (client engine and inbound share one table).
    pub fn with_openers_map(
        mut self,
        openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>,
    ) -> Self {
        self.openers = openers;
        self
    }

    /// Set the fallback channel opener at runtime.
    pub fn set_default_opener(&mut self, opener: Arc<dyn ChannelOpener>) {
        self.default_opener = Some(opener);
    }

    /// Enable username/password auth (SOCKS5 RFC1929 / HTTP Basic).
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self
    }

    /// Attach the transit accounting table (proxy inbound forwarding booked as from="proxy";
    /// destination label: tunnel = opener transit_label, direct/forward = "local").
    pub fn with_transit_meter(mut self, meter: Arc<TransitMeter>) -> Self {
        self.transit = Some(meter);
        self
    }

    /// Attach the connection log (docs/todo/conn-log.md; enabled flag lives inside the log,
    /// attaching alone costs one atomic load per connection while disabled).
    pub fn with_conn_log(mut self, log: Arc<ConnLog>) -> Self {
        self.conlog = Some(log);
        self
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn stats(&self) -> Arc<ProxyStats> {
        self.stats.clone()
    }

    /// Start the proxy inbound service (binds the listen address itself)
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        self.start_on(listener).await
    }

    /// Serve on an already-bound TcpListener (when the caller needs the concrete port up front).
    pub async fn start_on(&self, listener: TcpListener) -> Result<()> {
        self.start_on_with_shutdown(listener, std::future::pending())
            .await
    }

    /// Serve until `shutdown` resolves, then force-close every accepted connection and wait for the
    /// connection tasks to die before returning. A lingering accepted socket keeps its local port
    /// occupied (on Windows the next bind then fails with EADDRINUSE), and a tunnel that outlives
    /// "stop" keeps relaying traffic the user asked to cut — so off must mean off, immediately.
    /// Dropping this future mid-flight still kills the tasks (JoinSet aborts on drop), just unawaited.
    pub async fn start_on_with_shutdown(
        &self,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> Result<()> {
        // security note: unauthenticated exposure on non-loopback is an open-proxy risk
        if self.auth.is_none() && !self.listen_addr.ip().is_loopback() {
            warn!(
                addr = %self.listen_addr,
                "proxy inbound listening on non-loopback WITHOUT authentication — open proxy risk!"
            );
        }

        info!(addr = %self.listen_addr, "proxy inbound started (SOCKS5/HTTP auto-detect)");

        // Accepted-connection tasks are tracked (not detached): shutdown aborts them and the drain
        // waits for the sockets to actually close, so the listen port is reusable right after return.
        let mut tasks = tokio::task::JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, client_addr) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            tasks.abort_all();
                            while tasks.join_next().await.is_some() {}
                            return Err(e.into());
                        }
                    };

                    let active = self
                        .stats
                        .active_connections
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    if active > MAX_INBOUND_CONNECTIONS as u64 {
                        self.stats
                            .active_connections
                            .fetch_sub(1, Ordering::Relaxed);
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
                        transit: self.transit.clone(),
                        conlog: self.conlog.clone(),
                    };

                    tasks.spawn(async move {
                        let _guard = ActiveGuard(this.stats.clone());
                        // Connection-log kill switch (强制打断): the guard registers the sender on begin;
                        // firing it unwinds the task, and the guard's Drop finalizes the row as Closed.
                        // Sender dropped without registration (log disabled/detached) must NOT resolve the race —
                        // pend forever in that case, otherwise the connection would be cut right after the decision.
                        let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
                        let kill = async move {
                            match kill_rx.await {
                                Ok(()) => (),
                                Err(_) => std::future::pending::<()>().await,
                            }
                        };
                        tokio::select! {
                            r = handle_connection(stream, client_addr, this, kill_tx) => {
                                if let Err(e) = r {
                                    debug!(client = %client_addr, error = %e, "proxy connection handled with error");
                                }
                            }
                            _ = kill => {},
                        }
                    });
                }
                // Reap finished connection tasks so the tracked set does not grow unbounded
                _ = tasks.join_next(), if !tasks.is_empty() => {}
                _ = &mut shutdown => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Ok(());
                }
            }
        }
    }
}

/// Per-connection context (avoids excessive parameter passing).
#[derive(Clone)]
struct InboundCtx {
    listen_addr: SocketAddr,
    router: Arc<ArcSwap<ProxyRouter>>,
    openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>,
    default_opener: Option<Arc<dyn ChannelOpener>>,
    auth: Option<(String, String)>,
    stats: Arc<ProxyStats>,
    transit: Option<Arc<TransitMeter>>,
    conlog: Option<Arc<ConnLog>>,
}

/// Connection-log guard (docs/todo/conn-log.md): one row per inbound connection when enabled.
/// Created right after the inbound decision; `attach` wraps the client stream with live counters
/// before the pump; drop finalizes Closed, `.fail(...)` (dial/handshake errors) marks Failed instead.
struct ConnRecGuard {
    log: Option<Arc<ConnLog>>,
    id: u64,
    failed: Option<String>,
}

/// Counter pair handed to the stream wrapper: per-connection (ring row) + per-target (aggregated cell).
type CounterPair = (Option<Arc<ActiveCounters>>, Option<Arc<ActiveCounters>>);

impl ConnRecGuard {
    #[allow(clippy::too_many_arguments)]
    fn new(
        ctx: &InboundCtx,
        proto: Proto,
        host: &str,
        port: u16,
        mapped_to: Option<String>,
        outbound: &Outbound,
        hit: HitLayer,
        kill_tx: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> (Self, CounterPair) {
        let kind = match outbound {
            Outbound::Direct => OutboundKind::Direct,
            Outbound::Tunnel { node_id } => OutboundKind::Tunnel { node: node_id.clone() },
            Outbound::Forward { .. } => OutboundKind::Forward,
        };
        let Some(log) = ctx.conlog.clone() else {
            return (Self { log: None, id: 0, failed: None }, (None, None));
        };
        match log.begin(proto, host, port, mapped_to, kind, hit) {
            Some(h) => {
                if let Some(tx) = kill_tx {
                    log.attach_kill(h.id, tx);
                }
                (
                    Self { log: Some(log), id: h.id, failed: None },
                    (Some(h.conn), Some(h.agg)),
                )
            }
            None => (Self { log: None, id: 0, failed: None }, (None, None)),
        }
    }

    fn fail(&mut self, e: impl std::fmt::Display) {
        self.failed = Some(e.to_string());
    }
}

impl Drop for ConnRecGuard {
    fn drop(&mut self) {
        if let Some(log) = &self.log {
            match self.failed.take() {
                Some(r) => log.end_failed(self.id, r),
                None => log.end(self.id),
            }
        }
    }
}

/// Transit accounting (from="proxy"); no-op without a meter.
fn record_transit(ctx: &InboundCtx, to: &str, up: u64, down: u64) {
    if let Some(m) = &ctx.transit {
        m.record(FROM_PROXY, to, up, down);
    }
}

/// Self-connect guard: refuse targets pointing at the proxy's own listen address
/// (otherwise CONNECT-to-self recurses into new connections forever).
/// Same port plus exact listen IP / any loopback / unspecified address counts as self-connect
/// (a 127.0.0.1 request must be intercepted when listening on 0.0.0.0).
fn is_self_connect(ctx: &InboundCtx, addr: &SocketAddr) -> bool {
    if addr.port() != ctx.listen_addr.port() {
        return false;
    }
    let ip = addr.ip();
    ip.is_loopback() || ip.is_unspecified() || *addr == ctx.listen_addr
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
    kill_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    // read the first byte to detect the protocol (time-limited, Slowloris protection)
    let mut first_byte = [0u8; 1];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut first_byte))
        .await
        .map_err(|_| Error::Timeout)??;

    match first_byte[0] {
        0x05 => handle_socks5(stream, client_addr, ctx, kill_tx).await,
        b'G' | b'P' | b'C' | b'H' | b'O' | b'D' | b'T' => {
            handle_http(stream, client_addr, first_byte[0], ctx, kill_tx).await
        }
        other => Err(Error::Protocol(format!(
            "unsupported proxy protocol first byte: {other:#x}"
        ))),
    }
}

/// Resolve the channel opener for a Tunnel outbound.
fn resolve_opener(ctx: &InboundCtx, node_id: &str) -> Option<Arc<dyn ChannelOpener>> {
    ctx.openers
        .get(node_id)
        .map(|o| o.clone())
        .or_else(|| ctx.default_opener.clone())
}

/// Handle SOCKS5 handshake and request
async fn handle_socks5(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    ctx: InboundCtx,
    kill_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    // 1. negotiate auth method
    let mut nmethods = [0u8; 1];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut nmethods))
        .await
        .map_err(|_| Error::Timeout)??;
    let mut methods = vec![0u8; nmethods[0] as usize];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut methods))
        .await
        .map_err(|_| Error::Timeout)??;

    if let Some((ref expect_user, ref expect_pass)) = ctx.auth {
        // require RFC 1929 username/password auth (0x02)
        if !methods.contains(&0x02) {
            stream.write_all(&[0x05, 0xFF]).await?;
            return Err(Error::Auth(
                "client does not support username/password auth".into(),
            ));
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
        // respond NO AUTHENTICATION REQUIRED (0x00)
        stream.write_all(&[0x05, 0x00]).await?;
    }

    // 2. read request header: VER(0x05), CMD(0x01=CONNECT), RSV(0x00), ATYP
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
        0x04 => {
            // IPv6 (RFC 1928: ATYP=0x04)
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

    // Custom rule layer (GUI custom rules): the hosts mapping rewrites the resolve target first,
    // then decide_inbound_hit applies the precedence (user bypass > narrower route > preset > default)
    // and surfaces the hit layer for the connection log;
    // zero cost when the layer is empty (map_host / custom_bypass_match short-circuit on empty tables)
    let orig_host = target_host;
    let (target_host, outbound, hit, mapped_to) = {
        let router_ref = ctx.router.load();
        let (host, mapped_to) = match router_ref.map_host(&orig_host) {
            Some(ip) => {
                let s = ip.to_string();
                (s.clone(), Some(s))
            }
            None => (orig_host.clone(), None),
        };
        let (outbound, hit) = router_ref.decide_inbound_hit(&host);
        (host, outbound.clone(), hit, mapped_to)
    };
    let (mut rec, ctrs) = ConnRecGuard::new(
        &ctx,
        Proto::Socks5,
        &orig_host,
        target_port,
        mapped_to,
        &outbound,
        hit,
        Some(kill_tx),
    );
    let target_str = format!("{target_host}:{target_port}");
    debug!(client = %client_addr, target = %target_str, "SOCKS5 request received");

    match outbound {
        Outbound::Direct => {
            let target_addr: SocketAddr = match target_str.parse() {
                Ok(a) => a,
                Err(_) => match tokio::net::lookup_host(&target_str).await {
                    Ok(mut addrs) => match addrs.next() {
                        Some(a) => a,
                        None => {
                            rec.fail("dns resolution failed");
                            return Err(Error::Other("dns resolution failed".into()));
                        }
                    },
                    Err(e) => {
                        rec.fail(&e);
                        return Err(e.into());
                    }
                },
            };

            // self-connect guard
            if is_self_connect(&ctx, &target_addr) {
                rec.fail("refused: target is the proxy itself");
                let _ = stream
                    .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let _ = stream.shutdown().await;
                return Err(Error::Protocol(
                    "refused: target is the proxy itself".into(),
                ));
            }

            match DirectOutbound::connect(target_addr).await {
                Ok(mut target_stream) => {
                    stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;

                    let mut stream = CountingIo::new(stream, ctrs.0.clone(), ctrs.1.clone());
                    let (up, down) =
                        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await?;
                    ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                    ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
                    record_transit(&ctx, TO_LOCAL, up, down);
                    Ok(())
                }
                Err(e) => {
                    let _ = stream
                        .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    rec.fail(&e);
                    Err(e)
                }
            }
        }
        Outbound::Tunnel { node_id } => {
            if let Some(opener) = resolve_opener(&ctx, &node_id) {
                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;

                // destination label resolved the same way as open (actual peer when auto-routing)
                let to_label = opener.transit_label(&node_id, &target_host);
                let tunnel_outbound = TunnelOutbound::new(opener);
                let (up, down) = tunnel_outbound
                    .proxy_stream(&node_id, &target_host, target_port, CountingIo::new(stream, ctrs.0.clone(), ctrs.1.clone()))
                    .await?;
                ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
                record_transit(&ctx, &to_label, up, down);
                Ok(())
            } else {
                let _ = stream
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                rec.fail("no channel opener configured for tunnel routing");
                Err(Error::Other(
                    "no channel opener configured for tunnel routing".into(),
                ))
            }
        }
        Outbound::Forward { addr } => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            // connect + manual pump (instead of proxy_stream) so dial failures mark the record Failed
            // while mid-pump resets stay Closed; the ok reply is already sent either way
            match Socks5ForwardOutbound::connect(addr, &target_host, target_port).await {
                Ok(mut upstream) => {
                    let mut stream = CountingIo::new(stream, ctrs.0.clone(), ctrs.1.clone());
                    let (up, down) =
                        tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
                    ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                    ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
                    // loopback upstream forwarding is initiated locally; booked as locally terminated
                    record_transit(&ctx, TO_LOCAL, up, down);
                    Ok(())
                }
                Err(e) => {
                    rec.fail(&e);
                    Err(e)
                }
            }
        }
    }
}

/// Handle HTTP CONNECT / plain request
async fn handle_http(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    first_byte: u8,
    ctx: InboundCtx,
    kill_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    // read the full request header (up to \r\n\r\n, 16KB cap, time-limited)
    let mut req_buf = vec![first_byte];
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| Error::Timeout)??;
        if n == 0 {
            return Err(Error::Protocol(
                "connection closed during http header".into(),
            ));
        }
        req_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subsequence(&req_buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if req_buf.len() > MAX_HTTP_HEADER {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
            // shut down the write side gracefully so the client reads the 431 instead of an RST
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

    // proxy auth check
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

    // Custom rule layer (GUI custom rules): the hosts mapping rewrites the resolve target first,
    // then decide_inbound_hit applies the precedence (user bypass > narrower route > preset > default)
    // and surfaces the hit layer for the connection log
    let orig_host = target_host;
    let (target_host, outbound, hit, mapped_to) = {
        let router_ref = ctx.router.load();
        let (host, mapped_to) = match router_ref.map_host(&orig_host) {
            Some(ip) => {
                let s = ip.to_string();
                (s.clone(), Some(s))
            }
            None => (orig_host.clone(), None),
        };
        let (outbound, hit) = router_ref.decide_inbound_hit(&host);
        (host, outbound.clone(), hit, mapped_to)
    };
    let (mut rec, ctrs) = ConnRecGuard::new(
        &ctx,
        Proto::Http,
        &orig_host,
        target_port,
        mapped_to,
        &outbound,
        hit,
        Some(kill_tx),
    );
    let target_str = format!("{target_host}:{target_port}");
    debug!(client = %client_addr, target = %target_str, "HTTP Proxy request received");

    match outbound {
        Outbound::Direct => {
            let target_addr: SocketAddr = match target_str.parse() {
                Ok(a) => a,
                Err(_) => match tokio::net::lookup_host(&target_str).await {
                    Ok(mut addrs) => match addrs.next() {
                        Some(a) => a,
                        None => {
                            rec.fail("dns resolution failed");
                            return Err(Error::Other("dns resolution failed".into()));
                        }
                    },
                    Err(e) => {
                        rec.fail(&e);
                        return Err(e.into());
                    }
                },
            };

            // self-connect guard
            if is_self_connect(&ctx, &target_addr) {
                rec.fail("refused: target is the proxy itself");
                let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                return Err(Error::Protocol(
                    "refused: target is the proxy itself".into(),
                ));
            }

            match DirectOutbound::connect(target_addr).await {
                Ok(mut target_stream) => {
                    if method == "CONNECT" {
                        stream
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await?;
                        // TLS bytes may follow right after CONNECT; forward any surplus past the header
                        if req_buf.len() > header_end {
                            target_stream.write_all(&req_buf[header_end..]).await?;
                        }
                    } else {
                        target_stream.write_all(&req_buf).await?;
                    }

                    let mut stream = CountingIo::new(stream, ctrs.0.clone(), ctrs.1.clone());
                    let (up, down) =
                        tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await?;
                    ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                    ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
                    record_transit(&ctx, TO_LOCAL, up, down);
                    Ok(())
                }
                Err(e) => {
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    rec.fail(&e);
                    Err(e)
                }
            }
        }
        Outbound::Tunnel { node_id } => {
            if let Some(opener) = resolve_opener(&ctx, &node_id) {
                // destination label resolved the same way as open (actual peer when auto-routing)
                let to_label = opener.transit_label(&node_id, &target_host);
                let mut channel = match opener.open(&node_id, &target_host, target_port).await {
                    Ok(c) => c,
                    Err(e) => {
                        rec.fail(&e);
                        return Err(e);
                    }
                };

                if method == "CONNECT" {
                    stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    if req_buf.len() > header_end {
                        channel.write_all(&req_buf[header_end..]).await?;
                    }
                } else {
                    // plain HTTP requests must carry the original request through the tunnel
                    channel.write_all(&req_buf).await?;
                }

                let (up, down) = crate::relay::bridge::bridge(CountingIo::new(stream, ctrs.0.clone(), ctrs.1.clone()), channel).await?;
                ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
                record_transit(&ctx, &to_label, up, down);
                Ok(())
            } else {
                let _ = stream
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                    .await;
                rec.fail("no channel opener configured for tunnel routing");
                Err(Error::Other(
                    "no channel opener configured for tunnel routing".into(),
                ))
            }
        }
        Outbound::Forward { addr } => {
            match Socks5ForwardOutbound::connect(addr, &target_host, target_port).await {
                Ok(mut upstream) => {
                    if method == "CONNECT" {
                        stream
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await?;
                        if req_buf.len() > header_end {
                            upstream.write_all(&req_buf[header_end..]).await?;
                        }
                    } else {
                        // plain HTTP requests must carry the original request when forwarded
                        upstream.write_all(&req_buf).await?;
                    }
                    let mut stream = CountingIo::new(stream, ctrs.0.clone(), ctrs.1.clone());
                    let (up, down) =
                        tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
                    ctx.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
                    ctx.stats.bytes_down.fetch_add(down, Ordering::Relaxed);
                    // loopback upstream forwarding is initiated locally; booked as locally terminated
                    record_transit(&ctx, TO_LOCAL, up, down);
                    Ok(())
                }
                Err(e) => {
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    rec.fail(&e);
                    Err(e)
                }
            }
        }
    }
}

/// Parse host:port (IPv6 bracket form [::1]:443 supported).
fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port or [v6]
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
        // no port, or multiple colons without brackets (bare IPv6)
        _ => Ok((
            s.trim_matches(|c| c == '[' || c == ']').to_string(),
            default_port,
        )),
    }
}

/// Find a subslice position in a byte string.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Compute the expected Basic auth header value (base64(user:pass)).
fn basic_auth_value(user: &str, pass: &str) -> String {
    base64_encode(format!("{user}:{pass}").as_bytes())
}
