//! dns / dnsconf — DNS queries and system DNS configuration (P0, zero new dependencies).
//!
//! Implementation notes: a hand-rolled minimal UDP DNS query (A/AAAA/PTR/CNAME/MX, with TCP
//! retry on 512-byte truncation); dnsconf parses /etc/resolv.conf on Linux and reads per-interface
//! DNS from the registry on Windows (`Tcpip\Parameters\Interfaces`, via `reg query`, no new dependencies).

use super::ToolOutcome;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Structured result for a single DNS record (shared by dns/diag).
#[derive(Debug, Clone, Serialize)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: String,
    pub value: String,
    pub ttl: u32,
}

/// Query timeout per server (shared by UDP and the TCP retry).
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Default DNS port.
const DNS_PORT: u16 = 53;

// ==================== Public entry points (fixed signatures; diag depends on them) ====================

/// DNS query core (shared by dns/diag): returns the record list or an error description.
pub async fn query(
    domain: &str,
    server: Option<&str>,
    rtype: &str,
) -> Result<Vec<DnsAnswer>, String> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Err("域名不能为空".into());
    }
    let qtype = parse_rtype(rtype)?;
    // PTR accepts IP literals directly (auto-converted to the reverse domain); other types encode the domain verbatim
    let name = if qtype == 12 {
        ptr_name(domain)
    } else {
        domain.trim_end_matches('.').to_string()
    };
    let servers = resolve_servers(server)?;
    let id: u16 = rand::random();
    let packet = build_query(id, &name, qtype)?;
    // Try each nameserver in turn; the first successful answer wins
    let mut last_err = String::from("无可用 DNS 服务器");
    for srv in &servers {
        match query_server(*srv, &packet, id).await {
            Ok(answers) => return Ok(answers),
            Err(e) => last_err = format!("{srv}：{e}"),
        }
    }
    Err(last_err)
}

/// `anet tool dns <domain> [@server] [type]` (equivalent to nslookup/dig).
pub async fn dns_query(domain: &str, server: Option<&str>, rtype: &str) -> ToolOutcome {
    // Argument-level errors → exit 2; probe failures (timeout/refused/empty answer) → exit 1
    if domain.trim().is_empty() {
        return ToolOutcome::usage_error("域名不能为空");
    }
    if let Err(e) = parse_rtype(rtype) {
        return ToolOutcome::usage_error(e);
    }
    if let Some(s) = server
        && let Err(e) = parse_server(s)
    {
        return ToolOutcome::usage_error(e);
    }
    let server_desc = server
        .map(|s| format!("@{s}"))
        .unwrap_or_else(|| "系统配置".to_string());
    let start = std::time::Instant::now();
    match query(domain, server, rtype).await {
        Ok(answers) => {
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            let mut human = format!(";; {domain} {rtype}（服务器：{server_desc}）\n");
            if answers.is_empty() {
                human.push_str(";; 无记录（NOERROR 空应答）\n");
            } else {
                for a in &answers {
                    human.push_str(&format!(
                        "{}\t{}\t{}\tTTL={}\n",
                        a.name, a.rtype, a.value, a.ttl
                    ));
                }
            }
            human.push_str(&format!(";; 共 {} 条记录，耗时 {elapsed_ms:.0} ms", answers.len()));
            ToolOutcome::ok(
                human,
                serde_json::json!({
                    "domain": domain,
                    "rtype": rtype.to_ascii_uppercase(),
                    "server": server,
                    "elapsed_ms": (elapsed_ms * 10.0).round() / 10.0,
                    "answers": answers,
                }),
            )
        }
        Err(e) => ToolOutcome::fail(
            format!("DNS 查询失败：{domain} {rtype}（服务器：{server_desc}）：{e}"),
            serde_json::json!({
                "domain": domain,
                "rtype": rtype.to_ascii_uppercase(),
                "server": server,
                "error": e,
            }),
        ),
    }
}

/// `anet tool dnsconf`: show the system DNS configuration.
pub fn dnsconf() -> ToolOutcome {
    match system_dns_config() {
        Ok(cfg) => {
            let mut human = format!("系统 DNS 配置（来源：{}）\n", cfg.source);
            if cfg.interfaces.is_empty() {
                for ns in &cfg.nameservers {
                    human.push_str(&format!("nameserver {ns}\n"));
                }
            } else {
                // Windows: group by interface (static first, DHCP marked)
                for ifs in &cfg.interfaces {
                    human.push_str(&format!("接口 {}\n", ifs.iface));
                    for ns in &ifs.nameservers {
                        human.push_str(&format!("  nameserver {ns}\n"));
                    }
                    for ns in &ifs.dhcp_nameservers {
                        human.push_str(&format!("  nameserver {ns}（DHCP）\n"));
                    }
                }
                human.push_str(&format!("生效 nameserver：{}\n", cfg.nameservers.join(", ")));
            }
            if !cfg.search.is_empty() {
                human.push_str(&format!("search {}\n", cfg.search.join(" ")));
            }
            if !cfg.options.is_empty() {
                human.push_str(&format!("options {}\n", cfg.options.join(" ")));
            }
            if cfg.nameservers.is_empty() {
                human.push_str("警告：未发现任何 nameserver 配置\n");
            }
            let json = serde_json::to_value(&cfg).unwrap_or_default();
            ToolOutcome::ok(human.trim_end(), json)
        }
        // Read failure is an environment error (exit 2)
        Err(e) => ToolOutcome::usage_error(format!("读取系统 DNS 配置失败：{e}")),
    }
}

// ==================== System DNS configuration (shared by dnsconf and query's default servers) ====================

/// System DNS configuration.
#[derive(Debug, Clone, Default, Serialize)]
struct SystemDns {
    /// Configuration source (/etc/resolv.conf or a registry path)
    source: String,
    /// Effective nameservers (deduplicated, order preserved, across sources)
    nameservers: Vec<String>,
    /// Search domains (Unix-like)
    search: Vec<String>,
    /// options directives (Unix-like)
    options: Vec<String>,
    /// Per-interface DNS (non-empty only on Windows)
    interfaces: Vec<IfaceDns>,
}

/// DNS of a single interface (Windows).
#[derive(Debug, Clone, Serialize)]
struct IfaceDns {
    iface: String,
    nameservers: Vec<String>,
    dhcp_nameservers: Vec<String>,
}

/// Read the system DNS configuration. Both branches are pure-std, cross-compiled, dispatched via cfg!.
fn system_dns_config() -> Result<SystemDns, String> {
    if cfg!(windows) {
        // Registry Tcpip\Parameters\Interfaces: per-interface NameServer / DhcpNameServer
        const KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
        let output = agile_net_core::util::silent_command("reg")
            .args(["query", KEY, "/s"])
            .output()
            .map_err(|e| format!("reg query 执行失败：{e}"))?;
        if !output.status.success() {
            return Err(format!(
                "reg query 读取网卡 DNS 失败（退出码 {:?}）",
                output.status.code()
            ));
        }
        // Key paths and IP values are ASCII; a non-UTF-8 local code page does not affect parsing
        let text = String::from_utf8_lossy(&output.stdout);
        let mut cfg = parse_windows_reg_dns(&text);
        cfg.source = r"注册表 Tcpip\Parameters\Interfaces".into();
        Ok(cfg)
    } else {
        const PATH: &str = "/etc/resolv.conf";
        let content =
            std::fs::read_to_string(PATH).map_err(|e| format!("读取 {PATH} 失败：{e}"))?;
        let mut cfg = parse_resolv_conf(&content);
        cfg.source = PATH.into();
        Ok(cfg)
    }
}

/// Parse /etc/resolv.conf: nameserver / search / domain / options; comments and other directives ignored.
fn parse_resolv_conf(content: &str) -> SystemDns {
    let mut cfg = SystemDns::default();
    for line in content.lines() {
        // Comments start with # or ; (including inline comments)
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut it = line.split_whitespace();
        let Some(kw) = it.next() else { continue };
        match kw {
            "nameserver" => {
                if let Some(ns) = it.next() {
                    cfg.nameservers.push(ns.to_string());
                }
            }
            // search and domain are mutually exclusive; the later one wins (matches resolver semantics)
            "search" => cfg.search = it.map(str::to_string).collect(),
            "domain" => cfg.search = it.next().map(|d| vec![d.to_string()]).unwrap_or_default(),
            "options" => cfg.options = it.map(str::to_string).collect(),
            _ => {}
        }
    }
    cfg
}

/// Parse `reg query <Interfaces> /s` output: NameServer / DhcpNameServer of each interface section.
fn parse_windows_reg_dns(text: &str) -> SystemDns {
    let mut cfg = SystemDns::default();
    let mut current: Option<IfaceDns> = None;
    // End of a section: merge into the totals (empty interfaces dropped, nameservers deduplicated in order)
    fn flush(cfg: &mut SystemDns, cur: &mut Option<IfaceDns>) {
        if let Some(ifs) = cur.take()
            && (!ifs.nameservers.is_empty() || !ifs.dhcp_nameservers.is_empty())
        {
            for ns in ifs.nameservers.iter().chain(&ifs.dhcp_nameservers) {
                if !cfg.nameservers.contains(ns) {
                    cfg.nameservers.push(ns.clone());
                }
            }
            cfg.interfaces.push(ifs);
        }
    }
    for line in text.lines() {
        let line = line.trim_end();
        if line.starts_with("HKEY_") {
            flush(&mut cfg, &mut current);
            let iface = line.rsplit('\\').next().unwrap_or(line).to_string();
            current = Some(IfaceDns {
                iface,
                nameservers: vec![],
                dhcp_nameservers: vec![],
            });
            continue;
        }
        let Some(cur) = current.as_mut() else { continue };
        // Value lines look like "    NameServer    REG_SZ    223.5.5.5,8.8.8.8"
        let line = line.trim();
        for (key, is_dhcp) in [("NameServer", false), ("DhcpNameServer", true)] {
            if let Some(rest) = line.strip_prefix(key)
                && let Some((_, val)) = rest.split_once("REG_SZ")
            {
                let list: Vec<String> = val
                    .split([',', ' '])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if is_dhcp {
                    cur.dhcp_nameservers = list;
                } else {
                    cur.nameservers = list;
                }
            }
        }
    }
    flush(&mut cfg, &mut current);
    cfg
}

/// Determine the server list to query: explicit @server or the system configuration (default port 53).
fn resolve_servers(server: Option<&str>) -> Result<Vec<SocketAddr>, String> {
    match server {
        Some(s) => Ok(vec![parse_server(s)?]),
        None => {
            let cfg = system_dns_config()
                .map_err(|e| format!("{e}（可用 @server 显式指定）"))?;
            let servers: Vec<SocketAddr> = cfg
                .nameservers
                .iter()
                .filter_map(|ns| parse_server(ns).ok())
                .collect();
            if servers.is_empty() {
                return Err("系统未配置 DNS 服务器（可用 @server 显式指定）".into());
            }
            Ok(servers)
        }
    }
}

/// Parse a server address: `IP` (port 53 added) or `IP:port` (for test injection).
fn parse_server(s: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DNS_PORT));
    }
    Err(format!("无效 DNS 服务器地址（形如 @223.5.5.5）: {s}"))
}

// ==================== Minimal DNS protocol (RFC 1035, no EDNS) ====================

/// Record-type string → qtype.
fn parse_rtype(rtype: &str) -> Result<u16, String> {
    match rtype.to_ascii_uppercase().as_str() {
        "A" => Ok(1),
        "AAAA" => Ok(28),
        "CNAME" => Ok(5),
        "MX" => Ok(15),
        "PTR" => Ok(12),
        other => Err(format!(
            "不支持的记录类型: {other}（支持 A/AAAA/CNAME/MX/PTR）"
        )),
    }
}

/// qtype → record-type string (unknown types shown as TYPE<n>, per dig convention).
fn rtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        other => format!("TYPE{other}"),
    }
}

/// rcode → readable description.
fn rcode_name(rcode: u16) -> String {
    match rcode {
        1 => "FORMERR（查询格式错误）".into(),
        2 => "SERVFAIL（服务器故障）".into(),
        3 => "NXDOMAIN（域名不存在）".into(),
        4 => "NOTIMP（不支持该查询）".into(),
        5 => "REFUSED（服务器拒绝）".into(),
        other => format!("RCODE={other}"),
    }
}

/// PTR query-name normalization: reverse domains pass through verbatim; IP literals convert to in-addr.arpa / ip6.arpa.
fn ptr_name(input: &str) -> String {
    let s = input.trim_end_matches('.');
    if s.ends_with(".in-addr.arpa") || s.ends_with(".ip6.arpa") {
        return s.to_string();
    }
    if let Ok(v4) = s.parse::<Ipv4Addr>() {
        let o = v4.octets();
        return format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    }
    if let Ok(v6) = s.parse::<Ipv6Addr>() {
        // 32 nibbles concatenated in reverse (low nibble first, then high, per byte)
        let mut out = String::new();
        for byte in v6.octets().iter().rev() {
            out.push_str(&format!("{:x}.{:x}.", byte & 0xF, byte >> 4));
        }
        out.push_str("ip6.arpa");
        return out;
    }
    s.to_string()
}

/// Build a query packet: RD flag + single question (QCLASS=IN).
fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&[0u8; 6]); // AN/NS/AR = 0
    encode_name(&mut buf, name)?;
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(buf)
}

/// Encode a domain name as a label sequence (label lengths validated; empty string encodes the root).
fn encode_name(buf: &mut Vec<u8>, name: &str) -> Result<(), String> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        buf.push(0); // root domain
        return Ok(());
    }
    if name.len() > 253 {
        return Err(format!("域名过长: {name}"));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("无效域名标签: {name}"));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    Ok(())
}

/// Parse a domain name (including 0xC0 compression pointers); returns (name, next read position).
fn read_name(buf: &[u8], mut pos: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next = pos;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos).ok_or("报文越界")?;
        if len & 0xC0 == 0xC0 {
            // Compression pointer: only the first pointer updates the returned position; jumps are capped against loops
            let b2 = *buf.get(pos + 1).ok_or("报文越界")?;
            let ptr = (((len & 0x3F) as usize) << 8) | b2 as usize;
            if !jumped {
                next = pos + 2;
            }
            jumped = true;
            jumps += 1;
            if jumps > 32 {
                return Err("压缩指针循环".into());
            }
            pos = ptr;
        } else if len == 0 {
            if !jumped {
                next = pos + 1;
            }
            break;
        } else if len & 0xC0 != 0 {
            return Err("非法标签长度字节".into());
        } else {
            let start = pos + 1;
            let label = buf
                .get(start..start + len as usize)
                .ok_or("报文越界")?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            pos = start + len as usize;
        }
    }
    Ok((labels.join("."), next))
}

fn be_u16(buf: &[u8], pos: usize) -> Result<u16, String> {
    let b = buf.get(pos..pos + 2).ok_or("报文越界")?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn be_u32(buf: &[u8], pos: usize) -> Result<u32, String> {
    let b = buf.get(pos..pos + 4).ok_or("报文越界")?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn hex_dump(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// TC truncation flag (set by the server when the answer exceeds 512 bytes; retry over TCP).
fn is_truncated(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[2] & 0x02 != 0
}

/// Parse a DNS response packet: validate ID/rcode, extract the answer-section records.
fn parse_response(buf: &[u8], expect_id: u16) -> Result<Vec<DnsAnswer>, String> {
    if buf.len() < 12 {
        return Err("响应报文过短".into());
    }
    if be_u16(buf, 0)? != expect_id {
        return Err("响应 ID 与查询不匹配".into());
    }
    let flags = be_u16(buf, 2)?;
    if flags & 0x8000 == 0 {
        return Err("收到非响应报文".into());
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(format!("服务器拒绝应答：{}", rcode_name(rcode)));
    }
    let qd = be_u16(buf, 4)? as usize;
    let an = be_u16(buf, 6)? as usize;
    let mut pos = 12;
    // Skip the question section
    for _ in 0..qd {
        let (_, n) = read_name(buf, pos)?;
        pos = n + 4;
        if pos > buf.len() {
            return Err("响应报文截断".into());
        }
    }
    let mut answers = Vec::with_capacity(an);
    for _ in 0..an {
        let (name, n) = read_name(buf, pos)?;
        pos = n;
        if pos + 10 > buf.len() {
            return Err("响应报文截断".into());
        }
        let rtype = be_u16(buf, pos)?;
        let ttl = be_u32(buf, pos + 4)?;
        let rdlen = be_u16(buf, pos + 8)? as usize;
        let rdata = pos + 10;
        let rend = rdata + rdlen;
        if rend > buf.len() {
            return Err("响应报文截断".into());
        }
        let value = match rtype {
            1 if rdlen == 4 => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&buf[rdata..rend]);
                Ipv4Addr::from(octets).to_string()
            }
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[rdata..rend]);
                Ipv6Addr::from(octets).to_string()
            }
            // NS/CNAME/PTR: rdata is a (possibly compressed) domain name
            2 | 5 | 12 => read_name(buf, rdata)?.0,
            15 if rdlen >= 3 => {
                let pref = be_u16(buf, rdata)?;
                let (exchange, _) = read_name(buf, rdata + 2)?;
                format!("{pref} {exchange}")
            }
            // Other types shown as \# <len> <hex>, per dig convention
            _ => format!("\\# {rdlen} {}", hex_dump(&buf[rdata..rend])),
        };
        answers.push(DnsAnswer {
            name,
            rtype: rtype_name(rtype),
            value,
            ttl,
        });
        pos = rend;
    }
    Ok(answers)
}

/// Query a single server: UDP first, automatic TCP retry on TC truncation.
async fn query_server(
    server: SocketAddr,
    packet: &[u8],
    expect_id: u16,
) -> Result<Vec<DnsAnswer>, String> {
    let resp = query_udp(server, packet).await?;
    if is_truncated(&resp) {
        // RFC 1035: a truncated UDP answer must be re-queried over TCP
        let resp = query_tcp(server, packet).await?;
        return parse_response(&resp, expect_id);
    }
    parse_response(&resp, expect_id)
}

/// UDP query: send from a fresh temporary socket and wait for a single response.
async fn query_udp(server: SocketAddr, packet: &[u8]) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("UDP socket 创建失败：{e}"))?;
    sock.send_to(packet, server)
        .await
        .map_err(|e| format!("发送失败：{e}"))?;
    // Buffer relaxed to 4K: some servers return over-512 packets even without EDNS
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .map_err(|_| format!("查询超时（{}s）", QUERY_TIMEOUT.as_secs()))?
        .map_err(|e| format!("接收失败：{e}"))?;
    buf.truncate(n);
    Ok(buf)
}

/// TCP query: 2-byte big-endian length prefix + packet (RFC 1035 §4.2.2).
async fn query_tcp(server: SocketAddr, packet: &[u8]) -> Result<Vec<u8>, String> {
    let fut = async {
        let mut stream = TcpStream::connect(server)
            .await
            .map_err(|e| format!("TCP 连接失败：{e}"))?;
        let len = (packet.len() as u16).to_be_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| format!("TCP 发送失败：{e}"))?;
        stream
            .write_all(packet)
            .await
            .map_err(|e| format!("TCP 发送失败：{e}"))?;
        let mut lb = [0u8; 2];
        stream
            .read_exact(&mut lb)
            .await
            .map_err(|e| format!("TCP 接收失败：{e}"))?;
        let n = u16::from_be_bytes(lb) as usize;
        let mut buf = vec![0u8; n];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| format!("TCP 接收失败：{e}"))?;
        Ok(buf)
    };
    tokio::time::timeout(QUERY_TIMEOUT, fut)
        .await
        .map_err(|_| format!("TCP 查询超时（{}s）", QUERY_TIMEOUT.as_secs()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Minimal packet-building helpers for tests ----

    /// A-record answer (owner name uses compression pointer 0xC00C into the question).
    fn ans_a(ttl: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0xC0, 0x0C];
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&ip);
        v
    }

    /// Answer whose rdata is a domain name (CNAME/PTR/NS).
    fn ans_name(rtype: u16, ttl: u32, target: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        encode_name(&mut rdata, target).unwrap();
        let mut v = vec![0xC0, 0x0C];
        v.extend_from_slice(&rtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(&rdata);
        v
    }

    /// MX-record answer.
    fn ans_mx(ttl: u32, pref: u16, exchange: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&pref.to_be_bytes());
        encode_name(&mut rdata, exchange).unwrap();
        let mut v = vec![0xC0, 0x0C];
        v.extend_from_slice(&15u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(&rdata);
        v
    }

    /// Build a response from a query: QR+RA flags + flags_extra (TC/rcode); question echoed verbatim.
    fn build_response(query: &[u8], flags_extra: u16, answers: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&query[0..2]); // id echo
        v.extend_from_slice(&(0x8080u16 | flags_extra).to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes()); // QD
        v.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // AN
        v.extend_from_slice(&[0u8; 4]); // NS/AR
        v.extend_from_slice(&query[12..]); // question verbatim
        for a in answers {
            v.extend_from_slice(a);
        }
        v
    }

    /// Loopback mock DNS UDP service: receive one query, send back the handler's response; returns the port.
    async fn spawn_mock<F>(handler: F) -> u16
    where
        F: Fn(Vec<u8>) -> Option<Vec<u8>> + Send + 'static,
    {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((n, peer)) = sock.recv_from(&mut buf).await
                && let Some(resp) = handler(buf[..n].to_vec())
            {
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        port
    }

    // ---- Pure-function tests ----

    #[test]
    fn parse_rtype_支持与拒绝() {
        assert_eq!(parse_rtype("A").unwrap(), 1);
        assert_eq!(parse_rtype("aaaa").unwrap(), 28);
        assert_eq!(parse_rtype("Ptr").unwrap(), 12);
        assert!(parse_rtype("TXT").is_err());
        assert!(parse_rtype("TXT").unwrap_err().contains("不支持"));
    }

    #[test]
    fn ptr_name_反向域转换() {
        assert_eq!(ptr_name("1.2.3.4"), "4.3.2.1.in-addr.arpa");
        assert_eq!(ptr_name("4.3.2.1.in-addr.arpa"), "4.3.2.1.in-addr.arpa");
        assert_eq!(
            ptr_name("::1"),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        );
        // Plain domains kept verbatim
        assert_eq!(ptr_name("example.com."), "example.com");
    }

    #[test]
    fn parse_server_各形式() {
        assert_eq!(
            parse_server("223.5.5.5").unwrap(),
            SocketAddr::from(([223, 5, 5, 5], 53))
        );
        assert_eq!(
            parse_server("127.0.0.1:5353").unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 5353))
        );
        assert_eq!(
            parse_server("::1").unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53)
        );
        assert_eq!(
            parse_server("[::1]:5353").unwrap(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353)
        );
        assert!(parse_server("not-an-ip").is_err());
    }

    #[test]
    fn encode_name_校验() {
        let mut buf = Vec::new();
        encode_name(&mut buf, "www.example.com").unwrap();
        assert_eq!(
            buf,
            b"\x03www\x07example\x03com\x00".to_vec()
        );
        assert!(encode_name(&mut Vec::new(), "a..b").is_err());
        assert!(encode_name(&mut Vec::new(), &"x".repeat(64)).is_err());
        // Root domain
        let mut root = Vec::new();
        encode_name(&mut root, "").unwrap();
        assert_eq!(root, vec![0u8]);
    }

    #[test]
    fn parse_resolv_conf_解析() {
        let content = r#"
# 注释行
nameserver 127.0.0.53
nameserver 223.5.5.5 # 行内注释
search lan example.com
options ndots:5 timeout:2
sortlist 130.155.160.0/255.255.240.0
"#;
        let cfg = parse_resolv_conf(content);
        assert_eq!(cfg.nameservers, vec!["127.0.0.53", "223.5.5.5"]);
        assert_eq!(cfg.search, vec!["lan", "example.com"]);
        assert_eq!(cfg.options, vec!["ndots:5", "timeout:2"]);
    }

    #[test]
    fn parse_resolv_conf_domain覆盖search() {
        // domain and search are mutually exclusive; the later one takes effect
        let cfg = parse_resolv_conf("search a.com b.com\ndomain c.com\n");
        assert_eq!(cfg.search, vec!["c.com"]);
        let cfg = parse_resolv_conf("; 注释\nnameserver 8.8.8.8\n");
        assert_eq!(cfg.nameservers, vec!["8.8.8.8"]);
        assert!(cfg.search.is_empty());
    }

    #[test]
    fn parse_windows_reg_dns_解析() {
        let text = r#"
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{AAA-1}
    NameServer    REG_SZ    223.5.5.5,223.6.6.6
    EnableDhcp    REG_DWORD    0x0

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{BBB-2}
    DhcpNameServer    REG_SZ    192.168.1.1 223.5.5.5

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{CCC-3}
    EnableDhcp    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
"#;
        let cfg = parse_windows_reg_dns(text);
        // Aggregated, deduplicated in order; empty interfaces dropped
        assert_eq!(
            cfg.nameservers,
            vec!["223.5.5.5", "223.6.6.6", "192.168.1.1"]
        );
        assert_eq!(cfg.interfaces.len(), 2);
        assert_eq!(cfg.interfaces[0].iface, "{AAA-1}");
        assert_eq!(cfg.interfaces[0].nameservers, vec!["223.5.5.5", "223.6.6.6"]);
        assert_eq!(cfg.interfaces[1].dhcp_nameservers, vec!["192.168.1.1", "223.5.5.5"]);
    }

    #[test]
    fn parse_response_各记录类型() {
        let q = build_query(0x1234, "example.com", 1).unwrap();
        // AAAA: ::1
        let mut v6 = vec![0xC0, 0x0C];
        v6.extend_from_slice(&28u16.to_be_bytes());
        v6.extend_from_slice(&1u16.to_be_bytes());
        v6.extend_from_slice(&60u32.to_be_bytes());
        v6.extend_from_slice(&16u16.to_be_bytes());
        v6.extend_from_slice(&[0u8; 15]);
        v6.push(1);
        let resp = build_response(
            &q,
            0,
            &[
                ans_a(300, [93, 184, 216, 34]),
                ans_name(5, 300, "target.example.com"),
                ans_name(12, 300, "ptr.example.com"),
                ans_mx(300, 10, "mail.example.com"),
                v6,
            ],
        );
        let answers = parse_response(&resp, 0x1234).unwrap();
        assert_eq!(answers.len(), 5);
        assert_eq!(answers[0].name, "example.com");
        assert_eq!(answers[0].rtype, "A");
        assert_eq!(answers[0].value, "93.184.216.34");
        assert_eq!(answers[0].ttl, 300);
        assert_eq!(answers[1].rtype, "CNAME");
        assert_eq!(answers[1].value, "target.example.com");
        assert_eq!(answers[2].rtype, "PTR");
        assert_eq!(answers[2].value, "ptr.example.com");
        assert_eq!(answers[3].rtype, "MX");
        assert_eq!(answers[3].value, "10 mail.example.com");
        assert_eq!(answers[4].rtype, "AAAA");
        assert_eq!(answers[4].value, "::1");
    }

    #[test]
    fn parse_response_异常报文() {
        let q = build_query(0x1234, "example.com", 1).unwrap();
        // ID mismatch
        let resp = build_response(&q, 0, &[ans_a(300, [1, 1, 1, 1])]);
        assert!(parse_response(&resp, 0x9999).unwrap_err().contains("不匹配"));
        // NXDOMAIN
        let resp = build_response(&q, 3, &[]);
        let err = parse_response(&resp, 0x1234).unwrap_err();
        assert!(err.contains("NXDOMAIN"), "实际: {err}");
        // SERVFAIL
        let resp = build_response(&q, 2, &[]);
        assert!(parse_response(&resp, 0x1234).unwrap_err().contains("SERVFAIL"));
        // Too short
        assert!(parse_response(&[0u8; 5], 0x1234).is_err());
    }

    #[test]
    fn read_name_压缩指针循环防护() {
        // Question name is a pointer to itself
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 12]);
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&[0u8; 4]);
        assert!(read_name(&buf, 12).unwrap_err().contains("循环"));
    }

    // ---- Loopback mock integration tests (no external network) ----

    #[tokio::test]
    async fn query_udp_mock_a记录() {
        let port = spawn_mock(|q| {
            Some(build_response(&q, 0, &[ans_a(300, [93, 184, 216, 34])]))
        })
        .await;
        let server = format!("127.0.0.1:{port}");
        let answers = query("example.com", Some(&server), "A").await.unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "example.com");
        assert_eq!(answers[0].rtype, "A");
        assert_eq!(answers[0].value, "93.184.216.34");
        assert_eq!(answers[0].ttl, 300);
    }

    #[tokio::test]
    async fn query_udp_mock_ptr反解() {
        let port = spawn_mock(|q| {
            // Verify the query name was auto-converted to the reverse domain
            let (name, _) = read_name(&q, 12).unwrap();
            assert_eq!(name, "4.3.2.1.in-addr.arpa");
            Some(build_response(&q, 0, &[ans_name(12, 600, "host.example.com")]))
        })
        .await;
        let server = format!("127.0.0.1:{port}");
        let answers = query("1.2.3.4", Some(&server), "PTR").await.unwrap();
        assert_eq!(answers[0].rtype, "PTR");
        assert_eq!(answers[0].value, "host.example.com");
    }

    #[tokio::test]
    async fn query_截断后自动重试tcp() {
        // UDP side: always answer with TC=1 and an empty body
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                let resp = build_response(&buf[..n], 0x0200, &[]);
                let _ = udp.send_to(&resp, peer).await;
            }
        });
        // TCP side (same port): read the query by length prefix, answer in full
        let tcp = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = tcp.accept().await {
                let mut lb = [0u8; 2];
                if s.read_exact(&mut lb).await.is_err() {
                    return;
                }
                let mut q = vec![0u8; u16::from_be_bytes(lb) as usize];
                if s.read_exact(&mut q).await.is_err() {
                    return;
                }
                let resp = build_response(&q, 0, &[ans_a(600, [10, 0, 0, 7])]);
                let len = (resp.len() as u16).to_be_bytes();
                let _ = s.write_all(&len).await;
                let _ = s.write_all(&resp).await;
            }
        });
        let server = format!("127.0.0.1:{port}");
        let answers = query("example.com", Some(&server), "A").await.unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].value, "10.0.0.7");
        assert_eq!(answers[0].ttl, 600);
    }

    #[tokio::test]
    async fn query_udp_mock_nxdomain() {
        let port = spawn_mock(|q| Some(build_response(&q, 3, &[]))).await;
        let server = format!("127.0.0.1:{port}");
        let err = query("no-such.example.com", Some(&server), "A")
            .await
            .unwrap_err();
        assert!(err.contains("NXDOMAIN"), "实际: {err}");
    }

    #[tokio::test]
    async fn dns_query_结果与退出码映射() {
        // Success: exit 0 + json records
        let port = spawn_mock(|q| Some(build_response(&q, 0, &[ans_a(60, [1, 2, 3, 4])]))).await;
        let server = format!("127.0.0.1:{port}");
        let out = dns_query("example.com", Some(&server), "A").await;
        assert!(out.success);
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.json["answers"][0]["value"], "1.2.3.4");
        assert!(out.human.contains("1.2.3.4"));

        // Probe failure (SERVFAIL): exit 1
        let port = spawn_mock(|q| Some(build_response(&q, 2, &[]))).await;
        let server = format!("127.0.0.1:{port}");
        let out = dns_query("example.com", Some(&server), "A").await;
        assert!(!out.success);
        assert_eq!(out.exit_code, 1);

        // Usage error: exit 2
        let out = dns_query("example.com", None, "TXT").await;
        assert_eq!(out.exit_code, 2);
        let out = dns_query("example.com", Some("bad::addr"), "A").await;
        assert_eq!(out.exit_code, 2);
    }

    #[test]
    fn dnsconf_冒烟() {
        // Read-only system config; success (0) or environment error (2) are both valid; never panic
        let out = dnsconf();
        assert!(out.exit_code == 0 || out.exit_code == 2);
        if out.exit_code == 0 {
            assert!(out.json["source"].is_string());
        }
    }
}
