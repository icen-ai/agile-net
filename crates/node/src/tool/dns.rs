//! dns / dnsconf — DNS 查询与系统 DNS 配置（P0，零新增依赖）。
//!
//! 实现要点：手写最小 UDP DNS 查询（A/AAAA/PTR/CNAME/MX，含 512 截断重试 TCP）；
//! dnsconf：Linux 解析 /etc/resolv.conf，Windows 读注册表各网卡 DNS
//! （`Tcpip\Parameters\Interfaces`，经 `reg query` 免新依赖）。

use super::ToolOutcome;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// 单条 DNS 记录的结构化结果（dns/diag 复用）。
#[derive(Debug, Clone, Serialize)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: String,
    pub value: String,
    pub ttl: u32,
}

/// 单台服务器的查询超时（UDP 与 TCP 重试共用）。
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// 缺省 DNS 端口。
const DNS_PORT: u16 = 53;

// ==================== 公开入口（签名固定，diag 依赖） ====================

/// DNS 查询核心（dns/diag 复用）：返回记录列表或错误描述。
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
    // PTR 支持直接传 IP 字面量（自动转反向域），其余类型按字面域名编码
    let name = if qtype == 12 {
        ptr_name(domain)
    } else {
        domain.trim_end_matches('.').to_string()
    };
    let servers = resolve_servers(server)?;
    let id: u16 = rand::random();
    let packet = build_query(id, &name, qtype)?;
    // 依次尝试各 nameserver，首个成功应答即返回
    let mut last_err = String::from("无可用 DNS 服务器");
    for srv in &servers {
        match query_server(*srv, &packet, id).await {
            Ok(answers) => return Ok(answers),
            Err(e) => last_err = format!("{srv}：{e}"),
        }
    }
    Err(last_err)
}

/// `anet tool dns <domain> [@server] [type]`（等同 nslookup/dig）。
pub async fn dns_query(domain: &str, server: Option<&str>, rtype: &str) -> ToolOutcome {
    // 参数级错误 exit 2；探测失败（超时/拒绝/空应答）exit 1
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

/// `anet tool dnsconf`：查看系统 DNS 配置。
pub fn dnsconf() -> ToolOutcome {
    match system_dns_config() {
        Ok(cfg) => {
            let mut human = format!("系统 DNS 配置（来源：{}）\n", cfg.source);
            if cfg.interfaces.is_empty() {
                for ns in &cfg.nameservers {
                    human.push_str(&format!("nameserver {ns}\n"));
                }
            } else {
                // Windows：按网卡分组展示（静态优先，DHCP 标注）
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
        // 读取失败属环境错误（exit 2）
        Err(e) => ToolOutcome::usage_error(format!("读取系统 DNS 配置失败：{e}")),
    }
}

// ==================== 系统 DNS 配置（dnsconf 与 query 缺省服务器共用） ====================

/// 系统 DNS 配置。
#[derive(Debug, Clone, Default, Serialize)]
struct SystemDns {
    /// 配置来源（/etc/resolv.conf 或注册表路径）
    source: String,
    /// 生效 nameserver（各来源去重保序）
    nameservers: Vec<String>,
    /// 搜索域（类 Unix）
    search: Vec<String>,
    /// options 指令（类 Unix）
    options: Vec<String>,
    /// 各网卡 DNS（仅 Windows 非空）
    interfaces: Vec<IfaceDns>,
}

/// 单块网卡的 DNS（Windows）。
#[derive(Debug, Clone, Serialize)]
struct IfaceDns {
    iface: String,
    nameservers: Vec<String>,
    dhcp_nameservers: Vec<String>,
}

/// 读取系统 DNS 配置。两个分支均为纯 std 实现，跨平台编译、按 cfg! 分流。
fn system_dns_config() -> Result<SystemDns, String> {
    if cfg!(windows) {
        // 注册表 Tcpip\Parameters\Interfaces：各网卡 NameServer / DhcpNameServer
        const KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
        let output = std::process::Command::new("reg")
            .args(["query", KEY, "/s"])
            .output()
            .map_err(|e| format!("reg query 执行失败：{e}"))?;
        if !output.status.success() {
            return Err(format!(
                "reg query 读取网卡 DNS 失败（退出码 {:?}）",
                output.status.code()
            ));
        }
        // 键路径与 IP 值均为 ASCII，非 UTF-8 本地码页不影响解析
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

/// 解析 /etc/resolv.conf：nameserver / search / domain / options，忽略注释与其余指令。
fn parse_resolv_conf(content: &str) -> SystemDns {
    let mut cfg = SystemDns::default();
    for line in content.lines() {
        // 注释以 # 或 ; 起始（含行内注释）
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut it = line.split_whitespace();
        let Some(kw) = it.next() else { continue };
        match kw {
            "nameserver" => {
                if let Some(ns) = it.next() {
                    cfg.nameservers.push(ns.to_string());
                }
            }
            // search 与 domain 互斥，后出现者覆盖（与 resolver 语义一致）
            "search" => cfg.search = it.map(str::to_string).collect(),
            "domain" => cfg.search = it.next().map(|d| vec![d.to_string()]).unwrap_or_default(),
            "options" => cfg.options = it.map(str::to_string).collect(),
            _ => {}
        }
    }
    cfg
}

/// 解析 `reg query <Interfaces> /s` 输出：每个接口小节的 NameServer / DhcpNameServer。
fn parse_windows_reg_dns(text: &str) -> SystemDns {
    let mut cfg = SystemDns::default();
    let mut current: Option<IfaceDns> = None;
    // 小节结束：合并进总表（空接口丢弃，nameserver 去重保序）
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
        // 值行形如 "    NameServer    REG_SZ    223.5.5.5,8.8.8.8"
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

/// 确定查询使用的服务器列表：显式 @server 或系统配置（缺省 53 端口）。
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

/// 解析服务器地址：`IP`（补 53 端口）或 `IP:port`（测试注入用）。
fn parse_server(s: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DNS_PORT));
    }
    Err(format!("无效 DNS 服务器地址（形如 @223.5.5.5）: {s}"))
}

// ==================== 最小 DNS 协议（RFC 1035，无 EDNS） ====================

/// 记录类型字串 → qtype。
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

/// qtype → 记录类型字串（未知类型按 dig 惯例显示 TYPE<n>）。
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

/// rcode → 可读描述。
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

/// PTR 查询名规范化：已是反向域则原样返回；IP 字面量转 in-addr.arpa / ip6.arpa。
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
        // 32 个半字节逆序拼接（每字节先低半字节后高半字节）
        let mut out = String::new();
        for byte in v6.octets().iter().rev() {
            out.push_str(&format!("{:x}.{:x}.", byte & 0xF, byte >> 4));
        }
        out.push_str("ip6.arpa");
        return out;
    }
    s.to_string()
}

/// 构造查询报文：RD 标志 + 单 question（QCLASS=IN）。
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

/// 域名编码为 label 序列（校验标签长度，空串编码为根域）。
fn encode_name(buf: &mut Vec<u8>, name: &str) -> Result<(), String> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        buf.push(0); // 根域
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

/// 解析域名（含 0xC0 压缩指针），返回 (name, 下一个读取位置)。
fn read_name(buf: &[u8], mut pos: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next = pos;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos).ok_or("报文越界")?;
        if len & 0xC0 == 0xC0 {
            // 压缩指针：仅首个指针更新返回位置，限制跳转次数防循环
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

/// TC 截断标志（应答超过 512 字节时服务器置位，需重试 TCP）。
fn is_truncated(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[2] & 0x02 != 0
}

/// 解析 DNS 响应报文：校验 ID/rcode，抽取 answer 段记录。
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
    // 跳过 question 段
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
            // NS/CNAME/PTR：rdata 为（可压缩）域名
            2 | 5 | 12 => read_name(buf, rdata)?.0,
            15 if rdlen >= 3 => {
                let pref = be_u16(buf, rdata)?;
                let (exchange, _) = read_name(buf, rdata + 2)?;
                format!("{pref} {exchange}")
            }
            // 其余类型按 dig 惯例 \# <len> <hex> 展示
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

/// 查询单台服务器：UDP 优先，TC 截断自动重试 TCP。
async fn query_server(
    server: SocketAddr,
    packet: &[u8],
    expect_id: u16,
) -> Result<Vec<DnsAnswer>, String> {
    let resp = query_udp(server, packet).await?;
    if is_truncated(&resp) {
        // RFC 1035：UDP 应答截断时必须以 TCP 重查
        let resp = query_tcp(server, packet).await?;
        return parse_response(&resp, expect_id);
    }
    parse_response(&resp, expect_id)
}

/// UDP 查询：新建临时 socket 发送并等待单个响应。
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
    // 缓冲放宽到 4K：个别服务器无 EDNS 也回超 512 的报文
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .map_err(|_| format!("查询超时（{}s）", QUERY_TIMEOUT.as_secs()))?
        .map_err(|e| format!("接收失败：{e}"))?;
    buf.truncate(n);
    Ok(buf)
}

/// TCP 查询：2 字节大端长度前缀 + 报文（RFC 1035 §4.2.2）。
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

    // ---- 测试用最小报文构造辅助 ----

    /// A 记录 answer（owner 名用压缩指针 0xC00C 指向 question）。
    fn ans_a(ttl: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0xC0, 0x0C];
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&ip);
        v
    }

    /// rdata 为域名的 answer（CNAME/PTR/NS）。
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

    /// MX 记录 answer。
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

    /// 由查询报文构造响应：QR+RA 标志 + flags_extra（TC/rcode），question 原样回显。
    fn build_response(query: &[u8], flags_extra: u16, answers: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&query[0..2]); // id 回显
        v.extend_from_slice(&(0x8080u16 | flags_extra).to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes()); // QD
        v.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // AN
        v.extend_from_slice(&[0u8; 4]); // NS/AR
        v.extend_from_slice(&query[12..]); // question 原样
        for a in answers {
            v.extend_from_slice(a);
        }
        v
    }

    /// 回环 mock DNS UDP 服务：收一个查询，handler 生成响应回送；返回端口。
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

    // ---- 纯函数测试 ----

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
        // 普通域名原样保留
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
        // 根域
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
        // domain 与 search 互斥，后出现者生效
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
        // 聚合去重保序，空接口被丢弃
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
        // AAAA：::1
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
        // ID 不匹配
        let resp = build_response(&q, 0, &[ans_a(300, [1, 1, 1, 1])]);
        assert!(parse_response(&resp, 0x9999).unwrap_err().contains("不匹配"));
        // NXDOMAIN
        let resp = build_response(&q, 3, &[]);
        let err = parse_response(&resp, 0x1234).unwrap_err();
        assert!(err.contains("NXDOMAIN"), "实际: {err}");
        // SERVFAIL
        let resp = build_response(&q, 2, &[]);
        assert!(parse_response(&resp, 0x1234).unwrap_err().contains("SERVFAIL"));
        // 过短
        assert!(parse_response(&[0u8; 5], 0x1234).is_err());
    }

    #[test]
    fn read_name_压缩指针循环防护() {
        // question 名为指向自身的指针
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 12]);
        buf.extend_from_slice(&[0xC0, 0x0C]);
        buf.extend_from_slice(&[0u8; 4]);
        assert!(read_name(&buf, 12).unwrap_err().contains("循环"));
    }

    // ---- 回环 mock 集成测试（不依赖外网） ----

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
            // 校验查询名已自动转为反向域
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
        // UDP 侧：一律回 TC=1 空应答
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                let resp = build_response(&buf[..n], 0x0200, &[]);
                let _ = udp.send_to(&resp, peer).await;
            }
        });
        // TCP 侧（同端口）：按长度前缀读查询，回完整应答
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
        // 成功：exit 0 + json 记录
        let port = spawn_mock(|q| Some(build_response(&q, 0, &[ans_a(60, [1, 2, 3, 4])]))).await;
        let server = format!("127.0.0.1:{port}");
        let out = dns_query("example.com", Some(&server), "A").await;
        assert!(out.success);
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.json["answers"][0]["value"], "1.2.3.4");
        assert!(out.human.contains("1.2.3.4"));

        // 探测失败（SERVFAIL）：exit 1
        let port = spawn_mock(|q| Some(build_response(&q, 2, &[]))).await;
        let server = format!("127.0.0.1:{port}");
        let out = dns_query("example.com", Some(&server), "A").await;
        assert!(!out.success);
        assert_eq!(out.exit_code, 1);

        // 用法错误：exit 2
        let out = dns_query("example.com", None, "TXT").await;
        assert_eq!(out.exit_code, 2);
        let out = dns_query("example.com", Some("bad::addr"), "A").await;
        assert_eq!(out.exit_code, 2);
    }

    #[test]
    fn dnsconf_冒烟() {
        // 只读系统配置，成功（0）或环境错误（2）均合法，绝不 panic
        let out = dnsconf();
        assert!(out.exit_code == 0 || out.exit_code == 2);
        if out.exit_code == 0 {
            assert!(out.json["source"].is_string());
        }
    }
}
