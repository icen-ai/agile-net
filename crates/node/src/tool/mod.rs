//! `anet tool` built-in network diagnostic toolkit (design: docs/todo/cli-tool.md).
//!
//! Contract (uniform across the toolkit; implementations must not deviate):
//! - Every command's public function returns a [`ToolOutcome`]: human self-rendered text + json
//!   structured data; this module handles printing (--json serializes the json field) and exit-code mapping.
//! - Exit codes: `0` success/reachable, `1` failure/unreachable, `2` usage/environment error;
//!   probe failures (timeout/refused/no permission) are normal output, not process errors.
//! - Everything except bandwidth is a local operation: no session check, no DB reads, no audit writes;
//!   bandwidth runs server-side via the admin API (login session required) and is normal diagnostic
//!   traffic that is not audited.
//! - doctor is a separate entry (`anet doctor`, not part of ToolSub): the self-diagnostics engine,
//!   sharing one implementation with the anet-gui "self-diagnostics".

pub mod bandwidth;
pub mod diag;
pub mod doctor;
pub mod dns;
pub mod fw;
pub mod http;
pub mod netif;
pub mod netstat;
pub mod ping;
pub mod selfcheck;
pub mod sysinfo;
pub mod tcping;
pub mod traceroute;

use clap::{Args, Subcommand};
use serde::Serialize;
use std::time::Duration;

/// Unified toolkit result: the only return type of command implementations.
#[derive(Debug, Clone, Serialize)]
pub struct ToolOutcome {
    /// Whether the probe succeeded (maps to exit code 0/1).
    pub success: bool,
    /// Exit code: 0 success/reachable, 1 failure/unreachable, 2 usage/environment error.
    pub exit_code: i32,
    /// Human-readable output (self-rendered by each module; not serialized or printed under --json).
    #[serde(skip_serializing)]
    pub human: String,
    /// Structured result (--json output carrier, reusable by a future GUI).
    pub json: serde_json::Value,
}

impl ToolOutcome {
    /// Probe succeeded (exit 0).
    pub fn ok(human: impl Into<String>, json: serde_json::Value) -> Self {
        Self {
            success: true,
            exit_code: 0,
            human: human.into(),
            json,
        }
    }

    /// Probe failed / target unreachable (exit 1; normal output, not a process error).
    pub fn fail(human: impl Into<String>, json: serde_json::Value) -> Self {
        Self {
            success: false,
            exit_code: 1,
            human: human.into(),
            json,
        }
    }

    /// Usage or environment error (exit 2).
    pub fn usage_error(human: impl Into<String>) -> Self {
        let human = human.into();
        Self {
            success: false,
            exit_code: 2,
            json: serde_json::json!({ "error": human }),
            human,
        }
    }

    /// Foundation-stage placeholder: command wired into dispatch but not implemented yet (exit 2, never panics).
    pub fn unimplemented(cmd: &str) -> Self {
        Self {
            success: false,
            exit_code: 2,
            human: format!("`anet tool {cmd}` 尚未实现（地基阶段占位）"),
            json: serde_json::json!({ "error": "not_implemented", "command": cmd }),
        }
    }
}

/// Unified entry: dispatch → print (human or --json) → return the exit code.
/// `api` is the global --api override (only consumed by the bandwidth arm; all other commands are local and ignore it).
pub async fn run(args: ToolArgs, json: bool, api: Option<String>) -> i32 {
    let outcome = dispatch(args, api).await;
    emit(&outcome, json);
    outcome.exit_code
}

/// Print the outcome: --json serializes the ToolOutcome (human field skipped), otherwise prints human.
pub fn emit(outcome: &ToolOutcome, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(outcome).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("{}", outcome.human);
    }
}

/// Subcommand dispatch (argument normalization is centralized here; implementation modules receive normalized, strongly-typed args).
/// `api` is consumed only by the bandwidth arm (all other commands are local operations).
pub async fn dispatch(args: ToolArgs, api: Option<String>) -> ToolOutcome {
    match args.command {
        ToolSub::Tcping(a) => {
            tcping::tcping(&a.host, a.port, a.count, Duration::from_secs(a.timeout)).await
        }
        ToolSub::Curl(a) => match parse_headers(&a.headers) {
            Ok(headers) => {
                http::curl(
                    &a.url,
                    &a.method,
                    &headers,
                    a.data.as_deref(),
                    a.insecure,
                    Duration::from_secs(a.max_time),
                )
                .await
            }
            Err(e) => ToolOutcome::usage_error(e),
        },
        ToolSub::Dns(a) => match normalize_dns_args(a.server, a.rtype) {
            Ok((server, rtype)) => dns::dns_query(&a.domain, server.as_deref(), &rtype).await,
            Err(e) => ToolOutcome::usage_error(e),
        },
        ToolSub::Dnsconf => dns::dnsconf(),
        ToolSub::Scan(a) => match parse_port_range(&a.range) {
            Ok((start, end)) => {
                tcping::scan(
                    &a.host,
                    start,
                    end,
                    a.concurrency,
                    Duration::from_secs(a.timeout),
                )
                .await
            }
            Err(e) => ToolOutcome::usage_error(e),
        },
        ToolSub::Diag(a) => diag::diag(&a.host, a.port.unwrap_or(443)).await,
        ToolSub::Selfcheck => selfcheck::selfcheck(),
        ToolSub::Psinfo(a) => sysinfo::psinfo(a.pid),
        ToolSub::Killport(a) => sysinfo::killport(a.port, a.force, a.yes),
        ToolSub::Listen(a) => netstat::listen(a.proto.as_deref()),
        ToolSub::Portof(a) => netstat::portof(a.port),
        ToolSub::Portsof(a) => netstat::portsof(a.pid),
        ToolSub::Lsof(a) => match parse_lsof_args(&a.args) {
            Ok(port) => netstat::portof(port),
            Err(e) => ToolOutcome::usage_error(e),
        },
        ToolSub::Ifconfig => netif::ifconfig(),
        ToolSub::Route => netif::route(),
        ToolSub::Mtu(a) => netif::mtu(a.iface.as_deref()),
        ToolSub::Ping(a) => {
            ping::ping(&a.host, a.count, Duration::from_secs(a.timeout), a.port).await
        }
        ToolSub::Traceroute(a) => {
            traceroute::trace(&a.host, a.max_hops, Duration::from_secs(a.timeout)).await
        }
        ToolSub::Fwstatus => fw::fwstatus(),
        ToolSub::Fwcheck(a) => fw::fwcheck(a.port),
        ToolSub::Bandwidth(a) => bandwidth::bandwidth(a.peer.as_deref(), api).await,
    }
}

// ==================== clap definitions (Wave B must not touch cli.rs/app.rs; the command surface is defined here) ====================

#[derive(Args, Debug)]
pub struct ToolArgs {
    #[command(subcommand)]
    pub command: ToolSub,
}

#[derive(Subcommand, Debug)]
pub enum ToolSub {
    /// TCP 连接探测（等同 telnet/nc 连通性检查；-c 多次输出 min/avg/max）
    #[command(visible_aliases = ["telnet", "nc"])]
    Tcping(TcpingArgs),
    /// HTTP 请求（等同 curl：状态码/响应头/响应体摘要/耗时）
    Curl(CurlArgs),
    /// DNS 查询（等同 nslookup/dig；A/AAAA/CNAME/MX/PTR）
    #[command(visible_alias = "nslookup")]
    Dns(DnsArgs),
    /// 查看系统 DNS 配置（/etc/resolv.conf、各网卡 DNS）
    Dnsconf,
    /// 端口 connect 扫描（只报开放端口 + 常见服务名猜测）
    Scan(ScanArgs),
    /// 组合诊断（DNS → ping → traceroute → tcping，给出「卡在哪一层」结论）
    Diag(DiagArgs),
    /// 巡检 PATH 常见网络命令，输出缺失清单与对应 anet tool 替代方案
    Selfcheck,
    /// 查看进程信息（等同 ps -p <pid>：命令行/用户/CPU/内存）
    Psinfo(PsinfoArgs),
    /// 终止占用指定端口的进程（默认 SIGTERM，-y 确认，--force 才 SIGKILL）
    Killport(KillportArgs),
    /// 列出监听/已连接 socket（等同 netstat -tunlp / ss -tulnp）
    #[command(
        visible_aliases = ["netstat", "ports"],
        long_about = "列出本机监听/已连接 socket 及所属进程（等同 netstat -tunlp / ss -tulnp）。\n\n权限：读全量进程 socket 需 root 或 CAP_NET_ADMIN；权限受限时只显示本用户进程，输出中标注「权限受限，列表可能不完整」。"
    )]
    Listen(ListenArgs),
    /// 按端口查进程（等同 lsof -i:<port>）
    Portof(PortofArgs),
    /// 按进程查端口（等同 lsof -i | grep <pid>）
    Portsof(PortsofArgs),
    /// lsof 兼容入口：`anet tool lsof -i:<port>`（等同 portof，仅此一种形式）
    #[command(trailing_var_arg = true, allow_hyphen_values = true)]
    Lsof(LsofArgs),
    /// 网卡列表（等同 ifconfig / ip a：IP/MAC/网关/MTU）
    #[command(visible_alias = "ip")]
    Ifconfig,
    /// 路由表与默认网关（等同 route print / ip route）
    Route,
    /// 查看网卡 MTU（缺省列出全部网卡）
    Mtu(MtuArgs),
    /// ping 探测（ICMP 主路径，无权限自动降级 TCP ping）
    #[command(
        long_about = "ICMP echo 探测。\n\n权限与降级：Linux 需 root / CAP_NET_RAW（可 `sudo setcap cap_net_raw+ep anet-svc` 授权）或内核开放 net.ipv4.ping_group_range；Windows 无需管理员。ICMP 不可用时自动降级为 TCP ping（--port 指定，默认 443），输出中显式标注 mode=icmp|tcp。"
    )]
    Ping(PingArgs),
    /// 路由追踪（等同 tracert/traceroute：ICMP 逐跳 TTL 探测）
    #[command(
        visible_alias = "tracert",
        long_about = "逐跳 TTL 路由追踪（ICMP）。\n\n需要 raw socket 权限：Linux 请 root 或 `sudo setcap cap_net_raw+ep anet-svc`；无权限时降级为 TCP 逐跳建连或输出明确的权限指引。"
    )]
    Traceroute(TracerouteArgs),
    /// 防火墙状态探测（firewall-cmd/iptables/nft/netsh 哪个存在用哪个）
    Fwstatus,
    /// 探测指定端口的防火墙放行状态（探测提示，不解析规则）
    Fwcheck(FwcheckArgs),
    /// 穿透链路吞吐测试（经 anet 隧道到指定对端的实际吞吐/RTT；需服务端在线且已登录，对端为扇出 connector）
    #[command(
        long_about = "穿透链路吞吐测试：经 anet 隧道到指定对端（扇出 connector）的实际吞吐与 RTT——直接回答「这条穿透链路实际能跑多快」。\n\n前提：服务端在线且已登录（anet login），对端 connector 处于 connected；当前仅支持上游对端。tool 集中唯一需要登录会话的命令（测量在服务端执行，经管理 API 触发）。"
    )]
    Bandwidth(BandwidthArgs),
}

#[derive(Args, Debug)]
pub struct TcpingArgs {
    /// 目标主机（IP 或域名）
    pub host: String,
    /// 目标端口
    pub port: u16,
    /// 探测次数
    #[arg(short = 'c', long, default_value = "4")]
    pub count: u32,
    /// 单次连接超时（秒）
    #[arg(short = 't', long, default_value = "3")]
    pub timeout: u64,
}

#[derive(Args, Debug)]
pub struct CurlArgs {
    /// 请求 URL
    pub url: String,
    /// HTTP 方法
    #[arg(short = 'X', long, default_value = "GET")]
    pub method: String,
    /// 请求头（可重复，形如 "Name: value"）
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,
    /// 请求体
    #[arg(short = 'd', long = "data")]
    pub data: Option<String>,
    /// 跳过 TLS 证书校验（仅调试用）
    #[arg(short = 'k', long)]
    pub insecure: bool,
    /// 整体超时（秒）
    #[arg(long, default_value = "10")]
    pub max_time: u64,
}

#[derive(Args, Debug)]
pub struct DnsArgs {
    /// 查询域名
    pub domain: String,
    /// DNS 服务器（@ 前缀，如 @223.5.5.5；缺省用系统配置）
    pub server: Option<String>,
    /// 记录类型（A/AAAA/CNAME/MX/PTR，默认 A）
    pub rtype: Option<String>,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// 目标主机（IP 或域名）
    pub host: String,
    /// 端口范围（如 1-1024，或单端口 80）
    pub range: String,
    /// 并发上限
    #[arg(long, default_value = "256")]
    pub concurrency: u32,
    /// 单端口超时（秒）
    #[arg(short = 't', long, default_value = "2")]
    pub timeout: u64,
}

#[derive(Args, Debug)]
pub struct DiagArgs {
    /// 目标主机（IP 或域名）
    pub host: String,
    /// 目标端口（tcping 层探测用，默认 443）
    pub port: Option<u16>,
}

#[derive(Args, Debug)]
pub struct PsinfoArgs {
    /// 进程 PID
    pub pid: u32,
}

#[derive(Args, Debug)]
pub struct KillportArgs {
    /// 被占用端口
    pub port: u16,
    /// 使用 SIGKILL（默认 SIGTERM）
    #[arg(long)]
    pub force: bool,
    /// 确认执行（非交互终端必须显式确认，防误杀）
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct ListenArgs {
    /// 协议过滤：tcp / udp（缺省全部）
    #[arg(long, value_parser = ["tcp", "udp"])]
    pub proto: Option<String>,
}

#[derive(Args, Debug)]
pub struct PortofArgs {
    /// 目标端口
    pub port: u16,
}

#[derive(Args, Debug)]
pub struct PortsofArgs {
    /// 进程 PID
    pub pid: u32,
}

#[derive(Args, Debug)]
pub struct LsofArgs {
    /// lsof 参数（仅支持 -i:<port> 形式）
    pub args: Vec<String>,
}

#[derive(Args, Debug)]
pub struct MtuArgs {
    /// 网卡名（缺省列出全部）
    pub iface: Option<String>,
}

#[derive(Args, Debug)]
pub struct PingArgs {
    /// 目标主机（IP 或域名）
    pub host: String,
    /// 探测次数
    #[arg(short = 'c', long, default_value = "4")]
    pub count: u32,
    /// 单次超时（秒）
    #[arg(short = 't', long, default_value = "2")]
    pub timeout: u64,
    /// ICMP 不可用时 TCP 降级的目标端口
    #[arg(long, default_value = "443")]
    pub port: u16,
}

#[derive(Args, Debug)]
pub struct TracerouteArgs {
    /// 目标主机（IP 或域名）
    pub host: String,
    /// 最大跳数
    #[arg(long, default_value = "30")]
    pub max_hops: u8,
    /// 单跳超时（秒）
    #[arg(short = 't', long, default_value = "3")]
    pub timeout: u64,
}

#[derive(Args, Debug)]
pub struct FwcheckArgs {
    /// 目标端口
    pub port: u16,
}

#[derive(Args, Debug)]
pub struct BandwidthArgs {
    /// 对端标识（connector 名称或上游地址；缺省 = 第一个已连接 connector）
    pub peer: Option<String>,
}

// ==================== Argument normalization (dispatch only) ====================

/// Parse the `-H "Name: value"` header list.
fn parse_headers(raw: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::with_capacity(raw.len());
    for h in raw {
        let (name, value) = h
            .split_once(':')
            .ok_or_else(|| format!("无效请求头（应为 \"Name: value\"）: {h}"))?;
        out.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(out)
}

/// DNS positional-arg normalization: `dns <domain> [@server] [type]`; a second arg without @ is treated as the record type.
fn normalize_dns_args(
    server: Option<String>,
    rtype: Option<String>,
) -> Result<(Option<String>, String), String> {
    match (server, rtype) {
        (Some(s), r) if s.starts_with('@') => {
            let server = s.trim_start_matches('@').to_string();
            if server.is_empty() {
                return Err("DNS 服务器不能为空（形如 @223.5.5.5）".into());
            }
            Ok((Some(server), r.unwrap_or_else(|| "A".into())))
        }
        (Some(t), None) => Ok((None, t)),
        (Some(_), Some(_)) => Err("DNS 服务器须以 @ 前缀（如 @223.5.5.5）".into()),
        (None, r) => Ok((None, r.unwrap_or_else(|| "A".into()))),
    }
}

/// Port range parsing: `1-1024` or a single port `80`.
fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    let invalid = || format!("无效端口范围（形如 1-1024 或 80）: {s}");
    if let Some((a, b)) = s.split_once('-') {
        let start: u16 = a.trim().parse().map_err(|_| invalid())?;
        let end: u16 = b.trim().parse().map_err(|_| invalid())?;
        if start == 0 || start > end {
            return Err(invalid());
        }
        Ok((start, end))
    } else {
        let port: u16 = s.trim().parse().map_err(|_| invalid())?;
        if port == 0 {
            return Err(invalid());
        }
        Ok((port, port))
    }
}

/// lsof compatibility parsing: only the `-i:<port>` form is supported.
fn parse_lsof_args(args: &[String]) -> Result<u16, String> {
    for a in args {
        if let Some(rest) = a.strip_prefix("-i:") {
            return rest
                .parse()
                .map_err(|_| format!("无效端口: {rest}"));
        }
    }
    Err("仅支持 `anet tool lsof -i:<port>` 形式（等同 portof）".into())
}
