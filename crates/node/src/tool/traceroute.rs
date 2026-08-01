//! traceroute — ICMP 逐跳 TTL 探测（P2，主路径 + 权限指引）。
//!
//! 主路径：ICMP echo 逐跳 TTL 探测（需 raw socket 权限，同 ping）。
//! 实现决策：Linux ping（DGRAM）socket 收不到 ICMP TimeExceeded（错误只进
//! errqueue，读不到跳地址），因此固定走 SOCK_RAW——Unix 用 libc 直接建套接字
//! （TTL 走 setsockopt），Windows 用 surge-ping AsyncSocket（DGRAM 不受支持会
//! 自动回落 RAW，TTL 走 Config）。按设计文档 §2 的许可，不做 TCP 降级，无权限
//! 时输出明确指引：「需要 root/CAP_NET_RAW，可 `sudo setcap cap_net_raw+ep anet-svc`」。

use super::ToolOutcome;
use serde::Serialize;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// ICMP echo 负载（仅作填充）。
const ECHO_PAYLOAD: &[u8] = b"anet-tool-traceroute";

/// 权限受限时的操作指引（human 输出与 trace_inner 错误串共用，diag 依赖该串）。
#[cfg(unix)]
const PRIV_HINT: &str =
    "需要 root 或 CAP_NET_RAW 权限：可执行 `sudo setcap cap_net_raw+ep anet-svc`，或改用 root 运行";
#[cfg(windows)]
const PRIV_HINT: &str = "请以管理员身份运行（Windows 下逐跳 TTL 探测基于 raw socket）";
#[cfg(not(any(unix, windows)))]
const PRIV_HINT: &str = "需要 raw socket 权限（root / CAP_NET_RAW）";

/// 单跳的结构化结果（traceroute/diag 复用）。
#[derive(Debug, Clone, Serialize)]
pub struct Hop {
    pub ttl: u8,
    /// 该跳地址（超时为 None）
    pub addr: Option<String>,
    pub rtt_ms: Option<f64>,
}

/// traceroute 核心（traceroute/diag 复用）：返回逐跳列表或错误描述（含权限指引）。
pub async fn trace_inner(host: &str, max_hops: u8, timeout: Duration) -> Result<Vec<Hop>, String> {
    let target = resolve_host(host).await?;
    Ok(trace_resolved(target, max_hops, timeout).await?.0)
}

/// `anet tool traceroute <host>`（等同 tracert/traceroute）。
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

/// 主机解析：IP 字面量直连，域名走系统解析（优先 IPv4）。
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

/// 对已解析地址逐跳探测；返回跳表与是否到达目标。
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

/// 单跳探测：发一个 TTL=ttl 的 echo（seq=ttl），等待匹配应答直到 timeout。
/// 返回 (Hop, 是否到达目标)；单跳超时/recv 错误均为正常输出而非 Err。
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
                    // 非本探测的应答（本机其它 ICMP 流量），继续等
                }
                // raw socket 上本机即返的 ICMP 错误可能以 recv 错误形式出现，按无回应处理
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

// ==================== ICMP 传输层（按平台分派） ====================

/// 逐跳探测用的 ICMP 传输：统一 send_to/recv_from 语义。
enum Transport {
    /// Unix：libc 直接建 SOCK_RAW（TTL 走 setsockopt，不依赖 ping socket）
    #[cfg(unix)]
    Unix(tokio::net::UdpSocket),
    /// Windows：surge-ping AsyncSocket（TTL 走 Config）
    #[cfg(windows)]
    Surge(surge_ping::AsyncSocket),
    /// 其它平台占位（open_transport 直接报错，不会走到）
    #[cfg(not(any(unix, windows)))]
    Unsupported,
}

impl Transport {
    /// buf 取 &mut 仅为兼容 surge-ping AsyncSocket 的签名（其内部并不修改内容）。
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

/// 打开面向 target 的 ICMP raw 套接字（ttl 为本跳 TTL）。
/// 无权限时返回带操作指引的错误串（diag 依赖该串向用户传达降级信息）。
#[cfg(unix)]
fn open_transport(target: IpAddr, ttl: u8) -> Result<Transport, String> {
    use std::os::unix::io::FromRawFd;

    let (domain, proto) = match target {
        IpAddr::V4(_) => (libc::AF_INET, libc::IPPROTO_ICMP),
        IpAddr::V6(_) => (libc::AF_INET6, libc::IPPROTO_ICMPV6),
    };
    // traceroute 必须收到 ICMP TimeExceeded；Linux ping（DGRAM）socket 只回传
    // echo reply，因此固定走 SOCK_RAW（权限要求与 ping 主路径相同）
    let fd = unsafe { libc::socket(domain, libc::SOCK_RAW, proto) };
    if fd < 0 {
        return Err(socket_open_hint(io::Error::last_os_error()));
    }
    // 立即包成 std UdpSocket 持有所有权，此后任一路径退出都会自动 close
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

/// Windows：经 surge-ping 建套接字（DGRAM 不受支持自动回落 RAW；TTL 走 Config）。
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

/// 其它平台：如实报不支持。
#[cfg(not(any(unix, windows)))]
fn open_transport(_target: IpAddr, _ttl: u8) -> Result<Transport, String> {
    Err(format!("当前平台暂不支持 ICMP 逐跳探测（{PRIV_HINT}）"))
}

/// 建套接字失败的统一文案：权限类错误附操作指引（Linux EPERM /
/// Windows WSAEACCES 均映射 PermissionDenied）。
fn socket_open_hint(err: io::Error) -> String {
    if err.kind() == io::ErrorKind::PermissionDenied {
        format!("无 ICMP raw socket 权限（{err}）。{PRIV_HINT}")
    } else {
        format!("创建 ICMP 套接字失败：{err}")
    }
}

// ==================== ICMP 报文构造与解析（纯函数，便于单测） ====================

/// ICMPv4 回显请求报文（含校验和；raw socket 下内核只补 IP 头）。
fn build_echo_v4(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.extend_from_slice(&[8, 0, 0, 0]); // type=8 echo request，code=0，校验和占位
    buf.extend_from_slice(&ident.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(payload);
    let sum = internet_checksum(&buf);
    buf[2..4].copy_from_slice(&sum.to_be_bytes());
    buf
}

/// ICMPv6 回显请求报文（校验和按 RFC 3542 由内核填充，置 0 即可）。
fn build_echo_v6(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.extend_from_slice(&[128, 0, 0, 0]); // type=128 echo request，code=0
    buf.extend_from_slice(&ident.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// RFC 1071 互联网校验和。
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

/// 大端读取 u16（越界返回 None）。
fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

/// 与本探测匹配的应答类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyKind {
    /// 目标回显应答（到达）
    EchoReply,
    /// 中间跳 TTL 超时（路径画像）
    TimeExceeded,
    /// 目的不可达（源即目标时视同到达，如目标不回 echo 但回不可达）
    DestUnreach,
}

/// 解析收到的报文：仅认匹配本探测 ident/seq 的应答，其余（别进程的 ICMP 等）忽略。
fn parse_reply(target: IpAddr, buf: &[u8], ident: u16, seq: u16) -> Option<ReplyKind> {
    match target {
        IpAddr::V4(_) => parse_reply_v4(buf, ident, seq),
        IpAddr::V6(_) => parse_reply_v6(buf, ident, seq),
    }
}

/// IPv4：raw socket 收到的报文自带 IP 头。
fn parse_reply_v4(buf: &[u8], ident: u16, seq: u16) -> Option<ReplyKind> {
    let ihl = usize::from(buf.first()? & 0x0f) * 4;
    let icmp = buf.get(ihl..)?;
    match *icmp.first()? {
        // echo reply：ident/seq 就在本包
        0 if be16(icmp, 4) == Some(ident) && be16(icmp, 6) == Some(seq) => {
            Some(ReplyKind::EchoReply)
        }
        // time exceeded / dest unreach：ident/seq 在载荷内嵌的原始报文里
        t @ (11 | 3) => {
            let inner = icmp.get(8..)?;
            let inner_ihl = usize::from(inner.first()? & 0x0f) * 4;
            let inner_echo = inner.get(inner_ihl..)?;
            // 内嵌须为 echo request，且 ident/seq 与本探测一致
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

/// IPv6：raw ICMPv6 socket 收到的报文不含 IPv6 头（RFC 3542）。
fn parse_reply_v6(buf: &[u8], ident: u16, seq: u16) -> Option<ReplyKind> {
    match *buf.first()? {
        // echo reply
        129 if be16(buf, 4) == Some(ident) && be16(buf, 6) == Some(seq) => {
            Some(ReplyKind::EchoReply)
        }
        // time exceeded(3) / dest unreach(1)：内嵌 IPv6 定长 40 字节头 + 原始 echo
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

    // ---------- 报文构造与解析（纯函数，无网络无权限依赖） ----------

    /// v4 echo 报文字段正确，且全包校验和自洽（含校验和整体求和为 0）
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

    /// v6 echo 报文字段正确（校验和留 0 由内核填充）
    #[test]
    fn build_echo_v6_fields() {
        let pkt = build_echo_v6(0xabcd, 9, b"xy");
        assert_eq!(&pkt[..2], &[128, 0]);
        assert_eq!(be16(&pkt, 2), Some(0));
        assert_eq!(be16(&pkt, 4), Some(0xabcd));
        assert_eq!(be16(&pkt, 6), Some(9));
        assert_eq!(&pkt[8..], b"xy");
    }

    /// 构造测试用 IPv4 头（仅版本/IHL=0x45 与解析相关）
    fn ipv4_header() -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
        h.extend_from_slice(&[10, 0, 0, 1]); // src
        h.extend_from_slice(&[10, 0, 0, 2]); // dst
        h
    }

    /// 解析 v4 echo reply：ident/seq 匹配才认
    #[test]
    fn parse_v4_echo_reply() {
        let mut buf = ipv4_header();
        buf.extend_from_slice(&build_echo_v4(0x1234, 7, b"p"));
        buf[20] = 0; // type 改为 echo reply
        assert_eq!(
            parse_reply_v4(&buf, 0x1234, 7),
            Some(ReplyKind::EchoReply)
        );
        assert_eq!(parse_reply_v4(&buf, 0x1234, 8), None, "seq 不匹配");
        assert_eq!(parse_reply_v4(&buf, 0x9999, 7), None, "ident 不匹配");
    }

    /// 解析 v4 time exceeded：ident/seq 取自内嵌原始报文
    #[test]
    fn parse_v4_time_exceeded() {
        let mut buf = ipv4_header();
        buf.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]); // type=11 + unused
        buf.extend_from_slice(&ipv4_header()); // 内嵌原始 IP 头
        buf.extend_from_slice(&build_echo_v4(0x1234, 3, b"p")); // 内嵌原始 echo
        assert_eq!(
            parse_reply_v4(&buf, 0x1234, 3),
            Some(ReplyKind::TimeExceeded)
        );
        assert_eq!(parse_reply_v4(&buf, 0x1234, 4), None);
    }

    /// 解析 v4 dest unreach（源为目标时视同到达）
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

    /// 解析 v6 echo reply / time exceeded
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
        te.extend_from_slice(&[0u8; 40]); // 内嵌 IPv6 定长头
        te.extend_from_slice(&build_echo_v6(0xabcd, 2, b"p"));
        assert_eq!(
            parse_reply_v6(&te, 0xabcd, 2),
            Some(ReplyKind::TimeExceeded)
        );
        assert_eq!(parse_reply_v6(&te, 0xabcd, 3), None);
    }

    /// 截断/畸形报文不 panic，一律 None
    #[test]
    fn parse_malformed_none() {
        for buf in [&[][..], &[0x45][..], &[0x45, 0, 0][..], &[0x60, 0][..]] {
            assert_eq!(parse_reply_v4(buf, 1, 1), None);
            assert_eq!(parse_reply_v6(buf, 1, 1), None);
        }
    }

    // ---------- 权限指引文案（确定性断言，diag 依赖错误串） ----------

    /// 权限类错误必须渲染操作指引（diag 依赖该串向用户传达降级信息）
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

    /// 非权限类错误不附权限指引
    #[test]
    fn non_permission_error_plain() {
        let err = io::Error::new(io::ErrorKind::AddrNotAvailable, "x");
        let msg = socket_open_hint(err);
        assert!(!msg.contains("setcap"), "{msg}");
    }

    // ---------- 解析与回环链路（只打本机回环，不依赖外网） ----------

    /// 主机解析：字面量直连，localhost 走系统解析且必为回环
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

    /// trace_inner 打回环：有权限时结构断言（逐跳 ttl 递增、addr/rtt 成对、
    /// 回环回应必为 127.0.0.1 一跳直达）；无权限时必须给权限指引而非 panic
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
                // CI 无特权路径：必须输出权限指引
                assert!(
                    e.contains("权限") || e.contains("CAP_NET_RAW") || e.contains("管理员"),
                    "unexpected error: {e}"
                );
            }
        }
    }

    /// trace 输出契约：human/json 均显式标注 mode=icmp；成功 exit 0，
    /// 失败 exit 1 且 human 必含权限指引或「未到达目标」的如实说明
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
