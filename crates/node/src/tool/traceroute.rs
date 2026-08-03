//! traceroute — ICMP hop-by-hop TTL probing (P2, main path + permission guidance).
//!
//! Main path: ICMP echo with per-hop TTL (requires raw-socket permission, same as ping).
//! Implementation decision: Linux ping (DGRAM) sockets cannot receive ICMP TimeExceeded
//! (the error only lands in errqueue, so the hop address is unreadable), so we always use
//! SOCK_RAW — Unix builds the socket via libc directly (TTL via setsockopt), Windows uses
//! surge-ping AsyncSocket (unsupported DGRAM automatically falls back to RAW, TTL via Config).
//! Per the design doc §2 license there is no TCP fallback; without permission a clear
//! guidance is printed: "root/CAP_NET_RAW required, e.g. `sudo setcap cap_net_raw+ep anet-svc`".

use super::ToolOutcome;
use serde::Serialize;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// ICMP echo payload (padding only).
const ECHO_PAYLOAD: &[u8] = b"anet-tool-traceroute";

/// Actionable guidance when permission is restricted (shared by human output and the trace_inner
/// error string; diag depends on that string).
#[cfg(unix)]
const PRIV_HINT: &str =
    "需要 root 或 CAP_NET_RAW 权限：可执行 `sudo setcap cap_net_raw+ep anet-svc`，或改用 root 运行";
#[cfg(windows)]
const PRIV_HINT: &str = "请以管理员身份运行（Windows 下逐跳 TTL 探测基于 raw socket）";
#[cfg(not(any(unix, windows)))]
const PRIV_HINT: &str = "需要 raw socket 权限（root / CAP_NET_RAW）";

/// Structured result for a single hop (shared by traceroute/diag).
#[derive(Debug, Clone, Serialize)]
pub struct Hop {
    pub ttl: u8,
    /// Hop address (None on timeout)
    pub addr: Option<String>,
    pub rtt_ms: Option<f64>,
}

/// traceroute core (shared by traceroute/diag): returns the hop list or an error description (with permission guidance).
pub async fn trace_inner(host: &str, max_hops: u8, timeout: Duration) -> Result<Vec<Hop>, String> {
    let target = resolve_host(host).await?;
    Ok(trace_resolved(target, max_hops, timeout).await?.0)
}

/// `anet tool traceroute <host>` (equivalent to tracert/traceroute).
pub async fn trace(host: &str, max_hops: u8, timeout: Duration) -> ToolOutcome {
    let target = match resolve_host(host).await {
        Ok(t) => t,
        Err(e) => {
            return ToolOutcome::fail(
                format!("traceroute {host}：{e}"),
                serde_json::json!({ "host": host, "mode": "icmp", "error": e }),
            );
        }
    };
    match trace_resolved(target, max_hops, timeout).await {
        Ok((hops, reached)) => {
            let mut human = format!(
                "traceroute 到 {host}（{target}），mode=icmp，最大 {max_hops} 跳，单跳超时 {}s\n",
                timeout.as_secs()
            );
            for h in &hops {
                match (&h.addr, h.rtt_ms) {
                    (Some(addr), Some(rtt)) => {
                        human.push_str(&format!("{:>2}  {addr}  {rtt:.2} ms\n", h.ttl));
                    }
                    _ => human.push_str(&format!("{:>2}  *（超时无回应）\n", h.ttl)),
                }
            }
            let json = serde_json::json!({
                "host": host,
                "target": target.to_string(),
                "mode": "icmp",
                "max_hops": max_hops,
                "reached": reached,
                "hops": hops,
            });
            if reached {
                human.push_str(&format!("目标可达，共 {} 跳", hops.len()));
                ToolOutcome::ok(human, json)
            } else {
                human.push_str(&format!(
                    "{} 跳内未到达目标（中间跳或目标可能过滤 ICMP；若全部超时亦可能是本机权限受限：{PRIV_HINT}）",
                    hops.len()
                ));
                ToolOutcome::fail(human, json)
            }
        }
        Err(e) => ToolOutcome::fail(
            format!("traceroute 到 {host}（{target}）失败，mode=icmp：{e}"),
            serde_json::json!({
                "host": host,
                "target": target.to_string(),
                "mode": "icmp",
                "error": e,
            }),
        ),
    }
}

/// Host resolution: IP literals are used directly, domains go through the system resolver (IPv4 preferred).
async fn resolve_host(host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| format!("无法解析主机 {host}：{e}"))?;
    let mut v6 = None;
    for addr in addrs {
        match addr.ip() {
            v4 @ IpAddr::V4(_) => return Ok(v4),
            ip => v6 = Some(ip),
        }
    }
    v6.ok_or_else(|| format!("无法解析主机 {host}：无可用地址"))
}

/// Probe hop by hop against an already-resolved address; returns the hop list and whether the target was reached.
async fn trace_resolved(
    target: IpAddr,
    max_hops: u8,
    timeout: Duration,
) -> Result<(Vec<Hop>, bool), String> {
    let ident: u16 = rand::random();
    let mut hops = Vec::new();
    for ttl in 1..=max_hops.max(1) {
        let (hop, reached) = probe_hop(target, ttl, ident, timeout).await?;
        hops.push(hop);
        if reached {
            return Ok((hops, true));
        }
    }
    Ok((hops, false))
}

/// Single-hop probe: send one echo with TTL=ttl (seq=ttl) and wait for a matching reply until timeout.
/// Returns (Hop, reached-target?); per-hop timeout/recv errors are normal output, not Err.
async fn probe_hop(
    target: IpAddr,
    ttl: u8,
    ident: u16,
    timeout: Duration,
) -> Result<(Hop, bool), String> {
    let transport = open_transport(target, ttl)?;
    let seq = u16::from(ttl);
    let mut packet = match target {
        IpAddr::V4(_) => build_echo_v4(ident, seq, ECHO_PAYLOAD),
        IpAddr::V6(_) => build_echo_v6(ident, seq, ECHO_PAYLOAD),
    };
    let start = Instant::now();
    transport
        .send_to(&mut packet, &SocketAddr::new(target, 0))
        .await
        .map_err(|e| format!("发送 ICMP 探测失败（TTL={ttl}）：{e}"))?;

    let mut buf = [0u8; 1500];
    let wait = async {
        loop {
            match transport.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    if let Some(kind) = parse_reply(target, &buf[..n], ident, seq) {
                        return Some((src.ip(), kind));
                    }
                    // Reply not belonging to this probe (other local ICMP traffic); keep waiting
                }
                // ICMP errors returned locally on a raw socket may surface as recv errors; treat as no reply
                Err(_) => return None,
            }
        }
    };
    match tokio::time::timeout(timeout, wait).await {
        Ok(Some((src, kind))) => {
            let rtt_ms = (start.elapsed().as_secs_f64() * 100_000.0).round() / 100.0;
            let reached =
                src == target && matches!(kind, ReplyKind::EchoReply | ReplyKind::DestUnreach);
            Ok((
                Hop {
                    ttl,
                    addr: Some(src.to_string()),
                    rtt_ms: Some(rtt_ms),
                },
                reached,
            ))
        }
        Ok(None) | Err(_) => Ok((
            Hop {
                ttl,
                addr: None,
                rtt_ms: None,
            },
            false,
        )),
    }
}

// ==================== ICMP transport layer (per-platform dispatch) ====================

/// ICMP transport for hop probing: unified send_to/recv_from semantics.
enum Transport {
    /// Unix: SOCK_RAW via libc directly (TTL via setsockopt, no ping socket involved)
    #[cfg(unix)]
    Unix(tokio::net::UdpSocket),
    /// Windows: surge-ping AsyncSocket (TTL via Config)
    #[cfg(windows)]
    Surge(surge_ping::AsyncSocket),
    /// Placeholder for other platforms (open_transport errors out first; never reached)
    #[cfg(not(any(unix, windows)))]
    Unsupported,
}

impl Transport {
    /// buf is &mut only to match the surge-ping AsyncSocket signature (its internals never modify the content).
    async fn send_to(&self, buf: &mut [u8], target: &SocketAddr) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.send_to(buf, target).await,
            #[cfg(windows)]
            Self::Surge(s) => s.send_to(buf, target).await,
            #[cfg(not(any(unix, windows)))]
            Self::Unsupported => unreachable!(),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.recv_from(buf).await,
            #[cfg(windows)]
            Self::Surge(s) => s.recv_from(buf).await,
            #[cfg(not(any(unix, windows)))]
            Self::Unsupported => unreachable!(),
        }
    }
}

/// Open an ICMP raw socket towards target (ttl is this hop's TTL).
/// Without permission, returns an error string with actionable guidance (diag relies on it to inform the user).
#[cfg(unix)]
fn open_transport(target: IpAddr, ttl: u8) -> Result<Transport, String> {
    use std::os::unix::io::FromRawFd;

    let (domain, proto) = match target {
        IpAddr::V4(_) => (libc::AF_INET, libc::IPPROTO_ICMP),
        IpAddr::V6(_) => (libc::AF_INET6, libc::IPPROTO_ICMPV6),
    };
    // traceroute must receive ICMP TimeExceeded; Linux ping (DGRAM) sockets only deliver
    // echo replies, so we always use SOCK_RAW (same permission requirement as the ping main path)
    let fd = unsafe { libc::socket(domain, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(socket_open_hint(io::Error::last_os_error()));
    }
    // Immediately wrap into a std UdpSocket for ownership; every exit path then closes automatically
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let (level, opt) = match target {
        IpAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_TTL),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
    };
    let ttl_val: libc::c_int = libc::c_int::from(ttl);
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &ttl_val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "设置 TTL={ttl} 失败：{}",
            io::Error::last_os_error()
        ));
    }
    std_sock
        .set_nonblocking(true)
        .map_err(|e| format!("设置非阻塞失败：{e}"))?;
    let sock = tokio::net::UdpSocket::from_std(std_sock)
        .map_err(|e| format!("接入 tokio reactor 失败：{e}"))?;
    Ok(Transport::Unix(sock))
}

/// Windows: build the socket via surge-ping (unsupported DGRAM automatically falls back to RAW; TTL via Config).
#[cfg(windows)]
fn open_transport(target: IpAddr, ttl: u8) -> Result<Transport, String> {
    let kind = match target {
        IpAddr::V4(_) => surge_ping::ICMP::V4,
        IpAddr::V6(_) => surge_ping::ICMP::V6,
    };
    let config = surge_ping::Config::builder()
        .kind(kind)
        .ttl(u32::from(ttl))
        .build();
    surge_ping::AsyncSocket::new(&config)
        .map(Transport::Surge)
        .map_err(socket_open_hint)
}

/// Other platforms: honestly report unsupported.
#[cfg(not(any(unix, windows)))]
fn open_transport(_target: IpAddr, _ttl: u8) -> Result<Transport, String> {
    Err(format!("当前平台暂不支持 ICMP 逐跳探测（{PRIV_HINT}）"))
}

/// Unified wording for socket-creation failures: permission errors get actionable guidance
/// (Linux EPERM / Windows WSAEACCES both map to PermissionDenied).
fn socket_open_hint(err: io::Error) -> String {
    if err.kind() == io::ErrorKind::PermissionDenied {
        format!("无 ICMP raw socket 权限（{err}）。{PRIV_HINT}")
    } else {
        format!("创建 ICMP 套接字失败：{err}")
    }
}

// ==================== ICMP packet build & parse (pure functions, unit-testable) ====================

/// ICMPv4 echo request packet (with checksum; the kernel only fills in the IP header on raw sockets).
fn build_echo_v4(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.extend_from_slice(&[8, 0, 0, 0]); // type=8 echo request, code=0, checksum placeholder
    buf.extend_from_slice(&ident.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(payload);
    let sum = internet_checksum(&buf);
    buf[2..4].copy_from_slice(&sum.to_be_bytes());
    buf
}

/// ICMPv6 echo request packet (checksum is filled by the kernel per RFC 3542; leave 0).
fn build_echo_v6(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.extend_from_slice(&[128, 0, 0, 0]); // type=128 echo request, code=0
    buf.extend_from_slice(&ident.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// RFC 1071 internet checksum.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += u32::from(b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Big-endian u16 read (None on out of bounds).
fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

/// Reply types that match this probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyKind {
    /// Target echo reply (reached)
    EchoReply,
    /// Intermediate-hop TTL expiry (path profile)
    TimeExceeded,
    /// Destination unreachable (counts as reached when the source is the target, e.g. target replies unreachable instead of echo)
    DestUnreach,
}

/// Parse a received packet: only accept replies matching this probe's ident/seq; ignore everything else
/// (other processes' ICMP, etc.).
fn parse_reply(target: IpAddr, buf: &[u8], ident: u16, seq: u16) -> Option<ReplyKind> {
    match target {
        IpAddr::V4(_) => parse_reply_v4(buf, ident, seq),
        IpAddr::V6(_) => parse_reply_v6(buf, ident, seq),
    }
}

/// IPv4: packets received on a raw socket carry the IP header.
fn parse_reply_v4(buf: &[u8], ident: u16, seq: u16) -> Option<ReplyKind> {
    let ihl = usize::from(buf.first()? & 0x0f) * 4;
    let icmp = buf.get(ihl..)?;
    match *icmp.first()? {
        // echo reply: ident/seq are in this very packet
        0 if be16(icmp, 4) == Some(ident) && be16(icmp, 6) == Some(seq) => {
            Some(ReplyKind::EchoReply)
        }
        // time exceeded / dest unreach: ident/seq live in the original packet embedded in the payload
        t @ (11 | 3) => {
            let inner = icmp.get(8..)?;
            let inner_ihl = usize::from(inner.first()? & 0x0f) * 4;
            let inner_echo = inner.get(inner_ihl..)?;
            // The embedded packet must be an echo request whose ident/seq match this probe
            if inner_echo.first() == Some(&8)
                && be16(inner_echo, 4) == Some(ident)
                && be16(inner_echo, 6) == Some(seq)
            {
                Some(if t == 11 {
                    ReplyKind::TimeExceeded
                } else {
                    ReplyKind::DestUnreach
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// IPv6: packets received on a raw ICMPv6 socket carry no IPv6 header (RFC 3542).
fn parse_reply_v6(buf: &[u8], ident: u16, seq: u16) -> Option<ReplyKind> {
    match *buf.first()? {
        // echo reply
        129 if be16(buf, 4) == Some(ident) && be16(buf, 6) == Some(seq) => {
            Some(ReplyKind::EchoReply)
        }
        // time exceeded(3) / dest unreach(1): embedded IPv6 fixed 40-byte header + original echo
        t @ (3 | 1) => {
            let inner_echo = buf.get(8 + 40..)?;
            if inner_echo.first() == Some(&128)
                && be16(inner_echo, 4) == Some(ident)
                && be16(inner_echo, 6) == Some(seq)
            {
                Some(if t == 3 {
                    ReplyKind::TimeExceeded
                } else {
                    ReplyKind::DestUnreach
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ---------- Packet build & parse (pure functions, no network or permission needed) ----------

    /// v4 echo packet fields are correct and the checksum is self-consistent (whole packet sums to 0)
    #[test]
    fn build_echo_v4_fields_and_checksum() {
        let pkt = build_echo_v4(0x1234, 5, b"abcdefgh");
        assert_eq!(&pkt[..2], &[8, 0]);
        assert_eq!(be16(&pkt, 4), Some(0x1234));
        assert_eq!(be16(&pkt, 6), Some(5));
        assert_eq!(&pkt[8..], b"abcdefgh");
        assert_ne!(be16(&pkt, 2), Some(0), "校验和应已填充");
        assert_eq!(internet_checksum(&pkt), 0, "含校验和整体求和应为 0");
    }

    /// v6 echo packet fields are correct (checksum left 0 for the kernel)
    #[test]
    fn build_echo_v6_fields() {
        let pkt = build_echo_v6(0xabcd, 9, b"xy");
        assert_eq!(&pkt[..2], &[128, 0]);
        assert_eq!(be16(&pkt, 2), Some(0));
        assert_eq!(be16(&pkt, 4), Some(0xabcd));
        assert_eq!(be16(&pkt, 6), Some(9));
        assert_eq!(&pkt[8..], b"xy");
    }

    /// Build a test IPv4 header (only version/IHL=0x45 matters to the parser)
    fn ipv4_header() -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
        h.extend_from_slice(&[10, 0, 0, 1]); // src
        h.extend_from_slice(&[10, 0, 0, 2]); // dst
        h
    }

    /// Parse v4 echo reply: accepted only on ident/seq match
    #[test]
    fn parse_v4_echo_reply() {
        let mut buf = ipv4_header();
        buf.extend_from_slice(&build_echo_v4(0x1234, 7, b"p"));
        buf[20] = 0; // change type to echo reply
        assert_eq!(
            parse_reply_v4(&buf, 0x1234, 7),
            Some(ReplyKind::EchoReply)
        );
        assert_eq!(parse_reply_v4(&buf, 0x1234, 8), None, "seq 不匹配");
        assert_eq!(parse_reply_v4(&buf, 0x9999, 7), None, "ident 不匹配");
    }

    /// Parse v4 time exceeded: ident/seq come from the embedded original packet
    #[test]
    fn parse_v4_time_exceeded() {
        let mut buf = ipv4_header();
        buf.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]); // type=11 + unused
        buf.extend_from_slice(&ipv4_header()); // embedded original IP header
        buf.extend_from_slice(&build_echo_v4(0x1234, 3, b"p")); // embedded original echo
        assert_eq!(
            parse_reply_v4(&buf, 0x1234, 3),
            Some(ReplyKind::TimeExceeded)
        );
        assert_eq!(parse_reply_v4(&buf, 0x1234, 4), None);
    }

    /// Parse v4 dest unreach (counts as reached when the source is the target)
    #[test]
    fn parse_v4_dest_unreach() {
        let mut buf = ipv4_header();
        buf.extend_from_slice(&[3, 1, 0, 0, 0, 0, 0, 0]); // type=3
        buf.extend_from_slice(&ipv4_header());
        buf.extend_from_slice(&build_echo_v4(0x1234, 3, b"p"));
        assert_eq!(
            parse_reply_v4(&buf, 0x1234, 3),
            Some(ReplyKind::DestUnreach)
        );
    }

    /// Parse v6 echo reply / time exceeded
    #[test]
    fn parse_v6_replies() {
        let mut reply = build_echo_v6(0xabcd, 2, b"p");
        reply[0] = 129; // echo reply
        assert_eq!(
            parse_reply_v6(&reply, 0xabcd, 2),
            Some(ReplyKind::EchoReply)
        );
        assert_eq!(parse_reply_v6(&reply, 0xabcd, 1), None);

        let mut te = vec![3, 0, 0, 0, 0, 0, 0, 0]; // time exceeded
        te.extend_from_slice(&[0u8; 40]); // embedded IPv6 fixed header
        te.extend_from_slice(&build_echo_v6(0xabcd, 2, b"p"));
        assert_eq!(
            parse_reply_v6(&te, 0xabcd, 2),
            Some(ReplyKind::TimeExceeded)
        );
        assert_eq!(parse_reply_v6(&te, 0xabcd, 3), None);
    }

    /// Truncated/malformed packets never panic; always None
    #[test]
    fn parse_malformed_none() {
        for buf in [&[][..], &[0x45][..], &[0x45, 0, 0][..], &[0x60, 0][..]] {
            assert_eq!(parse_reply_v4(buf, 1, 1), None);
            assert_eq!(parse_reply_v6(buf, 1, 1), None);
        }
    }

    // ---------- Permission-guidance wording (deterministic assertions; diag depends on the error string) ----------

    /// Permission errors must render actionable guidance (diag relies on this string to inform the user)
    #[test]
    fn permission_error_hint() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "operation not permitted");
        let msg = socket_open_hint(err);
        assert!(msg.contains("权限"), "{msg}");
        #[cfg(unix)]
        assert!(msg.contains("sudo setcap cap_net_raw+ep anet-svc"), "{msg}");
        #[cfg(windows)]
        assert!(msg.contains("管理员"), "{msg}");
    }

    /// Non-permission errors carry no permission guidance
    #[test]
    fn non_permission_error_plain() {
        let err = io::Error::new(io::ErrorKind::AddrNotAvailable, "x");
        let msg = socket_open_hint(err);
        assert!(!msg.contains("setcap"), "{msg}");
    }

    // ---------- Resolution and loopback chain (loopback only, no external network) ----------

    /// Host resolution: literals are used directly; localhost resolves via the system resolver and must be loopback
    #[tokio::test]
    async fn resolve_host_literal_and_localhost() {
        assert_eq!(
            resolve_host("127.0.0.1").await.unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            resolve_host("::1").await.unwrap(),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        let lh = resolve_host("localhost").await.expect("localhost 应可解析");
        assert!(lh.is_loopback(), "localhost -> {lh}");
    }

    /// trace_inner on loopback: with permission, assert the structure (ttl increments per hop, addr/rtt
    /// come in pairs, a loopback reply must be 127.0.0.1 one hop away); without permission it must
    /// produce permission guidance, not panic
    #[tokio::test]
    async fn trace_inner_loopback() {
        match trace_inner("127.0.0.1", 5, Duration::from_millis(500)).await {
            Ok(hops) => {
                assert!(!hops.is_empty());
                assert!(hops.len() <= 5);
                for (i, h) in hops.iter().enumerate() {
                    assert_eq!(h.ttl, (i + 1) as u8, "ttl 应逐跳递增");
                    assert_eq!(h.addr.is_some(), h.rtt_ms.is_some(), "addr 与 rtt 成对");
                }
                if let Some(addr) = hops[0].addr.as_deref() {
                    assert_eq!(addr, "127.0.0.1", "回环回应只能来自本机");
                    assert_eq!(hops.len(), 1, "回环应一跳直达");
                }
            }
            Err(e) => {
                // CI unprivileged path: permission guidance is required
                assert!(
                    e.contains("权限") || e.contains("CAP_NET_RAW") || e.contains("管理员"),
                    "unexpected error: {e}"
                );
            }
        }
    }

    /// trace output contract: human/json both explicitly mark mode=icmp; success → exit 0,
    /// failure → exit 1 and human must contain permission guidance or an honest "target not reached" note
    #[tokio::test]
    async fn trace_outcome_contract() {
        let outcome = trace("127.0.0.1", 3, Duration::from_millis(500)).await;
        assert!(outcome.human.contains("mode=icmp"), "human: {}", outcome.human);
        assert_eq!(outcome.json["mode"], "icmp");
        if outcome.success {
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(outcome.json["reached"], true);
            assert!(outcome.human.contains("127.0.0.1"), "human: {}", outcome.human);
        } else {
            assert_eq!(outcome.exit_code, 1);
            let hinted = outcome.human.contains("setcap")
                || outcome.human.contains("管理员")
                || outcome.human.contains("权限")
                || outcome.human.contains("未到达目标");
            assert!(hinted, "human: {}", outcome.human);
        }
    }
}
