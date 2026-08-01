//! ping — ICMP echo + TCP 降级链（P2，surge-ping）。
//!
//! 权限与降级：Linux 需 root / CAP_NET_RAW（`sudo setcap cap_net_raw+ep anet-svc`）
//! 或内核开放 net.ipv4.ping_group_range；Windows 无需管理员。ICMP 不可用时自动
//! 降级为 TCP ping（tcp_fallback_port，默认 443），输出显式标注 mode=icmp|tcp。

use super::tcping;
use super::ToolOutcome;
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;
use surge_ping::{Client, Config, PingIdentifier, PingSequence, SurgeError, ICMP};

/// ICMP echo 负载（内容无意义，仅为对齐系统 ping 的非空包体）。
const PAYLOAD: &[u8] = b"anet-tool-ping";

/// ping 探测的结构化报告（ping/diag 复用）。
#[derive(Debug, Clone, Serialize)]
pub struct PingReport {
    pub host: String,
    /// 探测方式："icmp" | "tcp"
    pub mode: String,
    /// TCP 降级时的目标端口（ICMP 模式为 None）
    pub port: Option<u16>,
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub error: Option<String>,
}

/// 单次探测样本（模块内部：逐次输出与统计的中间载体）。
#[derive(Debug, Clone)]
struct Sample {
    seq: u32,
    /// 本次往返延迟（丢包/失败为 None）
    rtt_ms: Option<f64>,
    /// 失败原因（超时/连接拒绝/权限等）
    err: Option<String>,
}

/// ping 的完整内部结果：聚合报告 + 逐次样本 + 降级说明（human 渲染用）。
struct PingDetail {
    report: PingReport,
    samples: Vec<Sample>,
    /// 降级原因（走 TCP 时必有值，ICMP 直通为 None）
    fallback_note: Option<String>,
}

/// ICMP 主路径的内部结果。
enum IcmpPath {
    /// ICMP 探测执行完毕（样本中可能含超时丢包）
    Done(Vec<Sample>),
    /// ICMP 不可用（socket 创建失败或发包即硬错），需降级 TCP
    Unavailable(String),
}

/// ping 探测核心（ping/diag 复用）：ICMP 主路径，不可用时降级 TCP。
pub async fn ping_inner(
    host: &str,
    count: u32,
    timeout: Duration,
    tcp_fallback_port: u16,
) -> PingReport {
    ping_collect(host, count, timeout, tcp_fallback_port)
        .await
        .report
}

/// `anet tool ping <host>`：输出逐次结果、统计与 mode 标注。
pub async fn ping(host: &str, count: u32, timeout: Duration, tcp_fallback_port: u16) -> ToolOutcome {
    let detail = ping_collect(host, count, timeout, tcp_fallback_port).await;
    let report = &detail.report;

    // 人类可读输出：逐次结果 + ping 风格统计 + mode/降级标注
    let mut human = format!(
        "PING {host}（{} 次，超时 {}s）mode={}",
        report.sent,
        timeout.as_secs(),
        report.mode
    );
    if let Some(note) = &detail.fallback_note {
        human.push_str(&format!("\n{note}"));
    }
    for s in &detail.samples {
        let n = s.seq + 1;
        match (report.mode.as_str(), s.rtt_ms) {
            ("icmp", Some(ms)) => human.push_str(&format!("\nicmp_seq={n} time={ms:.2}ms")),
            ("icmp", None) => human.push_str(&format!(
                "\nicmp_seq={n} {}",
                s.err.as_deref().unwrap_or("请求超时")
            )),
            (_, Some(ms)) => human.push_str(&format!(
                "\ntcp_seq={n} {}:{} 已连接 time={ms:.2}ms",
                report.host,
                report.port.unwrap_or(0)
            )),
            (_, None) => human.push_str(&format!(
                "\ntcp_seq={n} {}:{} 连接失败：{}",
                report.host,
                report.port.unwrap_or(0),
                s.err.as_deref().unwrap_or("未知错误")
            )),
        }
    }
    human.push_str(&format!(
        "\n--- {host} ping 统计（mode={}）---\n    已发送 = {}，已接收 = {}，丢包 = {:.1}%",
        report.mode, report.sent, report.received, report.loss_pct
    ));
    if let (Some(min), Some(avg), Some(max)) = (report.min_ms, report.avg_ms, report.max_ms) {
        human.push_str(&format!("\n    延迟 min/avg/max = {min:.2}/{avg:.2}/{max:.2} ms"));
    }
    if let Some(err) = &report.error {
        human.push_str(&format!("\n    错误：{err}"));
    }

    let json = serde_json::to_value(report).unwrap_or_else(|_| serde_json::json!({}));
    if report.error.is_none() {
        ToolOutcome::ok(human, json)
    } else {
        ToolOutcome::fail(human, json)
    }
}

/// 完整探测流程：解析地址 → ICMP 主路径 → 不可用时降级 TCP。
async fn ping_collect(
    host: &str,
    count: u32,
    timeout: Duration,
    tcp_fallback_port: u16,
) -> PingDetail {
    let count = count.max(1);

    // 解析地址：IP 字面量直接可用，域名仅在 ICMP 主路径前解析一次
    let addr = match resolve_host(host).await {
        Ok(addr) => addr,
        Err(e) => {
            let report = PingReport {
                host: host.to_string(),
                mode: "icmp".into(),
                port: None,
                sent: 0,
                received: 0,
                loss_pct: 100.0,
                min_ms: None,
                avg_ms: None,
                max_ms: None,
                error: Some(format!("无法解析主机 {host}：{e}")),
            };
            return PingDetail {
                report,
                samples: Vec::new(),
                fallback_note: None,
            };
        }
    };

    match icmp_path(addr, count, timeout).await {
        IcmpPath::Done(samples) => PingDetail {
            report: make_report(host, "icmp", None, &samples),
            samples,
            fallback_note: None,
        },
        IcmpPath::Unavailable(reason) => {
            // TCP 降级：复用 tcping 的 connect 探测核心（域名由 probe 自行解析）
            let samples = tcp_samples(host, tcp_fallback_port, count, timeout).await;
            let note = format!(
                "ICMP 不可用（{reason}），已降级 TCP ping 端口 {tcp_fallback_port}；\
                 如需 ICMP：Linux 请 root / `sudo setcap cap_net_raw+ep anet-svc`，\
                 或内核开放 net.ipv4.ping_group_range"
            );
            PingDetail {
                report: make_report(host, "tcp", Some(tcp_fallback_port), &samples),
                samples,
                fallback_note: Some(note),
            }
        }
    }
}

/// ICMP 主路径：socket 打不开 / 发包即硬错视为不可用，超时只是丢包。
async fn icmp_path(addr: IpAddr, count: u32, timeout: Duration) -> IcmpPath {
    let config = match addr {
        IpAddr::V4(_) => Config::default(),
        IpAddr::V6(_) => Config::builder().kind(ICMP::V6).build(),
    };
    // Client::new 内部先试 DGRAM 再退化 RAW，两者都失败即无 ICMP 权限
    let client = match Client::new(&config) {
        Ok(client) => client,
        Err(e) => return IcmpPath::Unavailable(format!("ICMP socket 创建失败：{e}")),
    };
    let mut pinger = client
        .pinger(addr, PingIdentifier(rand::random()))
        .await;
    pinger.timeout(timeout);

    let mut samples = Vec::with_capacity(count as usize);
    let mut hard_err: Option<String> = None;
    for seq in 0..count {
        match pinger.ping(PingSequence(seq as u16), PAYLOAD).await {
            Ok((_packet, rtt)) => samples.push(Sample {
                seq,
                rtt_ms: Some(rtt.as_secs_f64() * 1000.0),
                err: None,
            }),
            Err(SurgeError::Timeout { .. }) => samples.push(Sample {
                seq,
                rtt_ms: None,
                err: Some("请求超时".into()),
            }),
            Err(e) => {
                if hard_err.is_none() {
                    hard_err = Some(e.to_string());
                }
                samples.push(Sample {
                    seq,
                    rtt_ms: None,
                    err: Some(e.to_string()),
                });
            }
        }
    }
    // socket 建得起但逐次发包全是硬错（如沙箱 EPERM）：同样视为 ICMP 不可用
    let received = samples.iter().filter(|s| s.rtt_ms.is_some()).count();
    if received == 0
        && let Some(e) = hard_err
    {
        return IcmpPath::Unavailable(format!("ICMP 收发失败：{e}"));
    }
    IcmpPath::Done(samples)
}

/// TCP 降级路径：逐次调用 tcping 探测核心采集样本。
async fn tcp_samples(host: &str, port: u16, count: u32, timeout: Duration) -> Vec<Sample> {
    let mut samples = Vec::with_capacity(count as usize);
    for seq in 0..count {
        let p = tcping::probe(host, port, timeout).await;
        samples.push(Sample {
            seq,
            rtt_ms: p.latency_ms,
            err: p.error,
        });
    }
    samples
}

/// 由逐次样本聚合结构化报告（received=0 时汇总首个失败原因）。
fn make_report(host: &str, mode: &str, port: Option<u16>, samples: &[Sample]) -> PingReport {
    let sent = samples.len() as u32;
    let rtts: Vec<f64> = samples.iter().filter_map(|s| s.rtt_ms).collect();
    let received = rtts.len() as u32;
    let loss_pct = if sent == 0 {
        100.0
    } else {
        (sent - received) as f64 / sent as f64 * 100.0
    };
    let (min_ms, avg_ms, max_ms) = if rtts.is_empty() {
        (None, None, None)
    } else {
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        (Some(min), Some(avg), Some(max))
    };
    // 全部失败时汇总首个失败原因；有接收即视为可达，不置错误
    let error = if received == 0 {
        Some(
            samples
                .iter()
                .find_map(|s| s.err.clone())
                .unwrap_or_else(|| "全部超时".into()),
        )
    } else {
        None
    };
    PingReport {
        host: host.to_string(),
        mode: mode.to_string(),
        port,
        sent,
        received,
        loss_pct,
        min_ms,
        avg_ms,
        max_ms,
        error,
    }
}

/// 解析目标主机为 IP（域名走系统解析器，IP 字面量零开销）。
async fn resolve_host(host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| e.to_string())?;
    addrs
        .into_iter()
        .next()
        .map(|sa| sa.ip())
        .ok_or_else(|| "解析结果为空".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// 起临时 listener，返回其端口（listen backlog 即可 accept 连接，无需显式 accept 循环）。
    async fn bind_listener() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    /// 绑定后立即释放，拿到一个确定关闭的回环端口。
    async fn closed_port() -> u16 {
        let (listener, port) = bind_listener().await;
        drop(listener);
        port
    }

    #[tokio::test]
    async fn tcp_fallback_full_chain_against_listener() {
        // TCP 降级对临时 listener 全链路：逐次样本 → 聚合报告
        let (_listener, port) = bind_listener().await;
        let samples = tcp_samples("127.0.0.1", port, 3, Duration::from_secs(1)).await;
        assert_eq!(samples.len(), 3);
        assert!(samples.iter().all(|s| s.rtt_ms.is_some()));

        let report = make_report("127.0.0.1", "tcp", Some(port), &samples);
        assert_eq!(report.mode, "tcp");
        assert_eq!(report.port, Some(port));
        assert_eq!(report.sent, 3);
        assert_eq!(report.received, 3);
        assert_eq!(report.loss_pct, 0.0);
        assert!(report.error.is_none());
        let (min, avg, max) = (
            report.min_ms.unwrap(),
            report.avg_ms.unwrap(),
            report.max_ms.unwrap(),
        );
        assert!(min <= avg && avg <= max);
    }

    #[tokio::test]
    async fn tcp_fallback_reports_loss_on_closed_port() {
        let port = closed_port().await;
        let samples = tcp_samples("127.0.0.1", port, 2, Duration::from_millis(500)).await;
        let report = make_report("127.0.0.1", "tcp", Some(port), &samples);
        assert_eq!(report.received, 0);
        assert_eq!(report.loss_pct, 100.0);
        assert!(report.min_ms.is_none());
        assert!(report.error.is_some());
    }

    #[tokio::test]
    async fn icmp_path_gracefully_handles_permission() {
        // ICMP 主路径：有权限时回环应有结果；无权限时必须优雅返回 Unavailable 而非 panic
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        match icmp_path(addr, 1, Duration::from_millis(500)).await {
            IcmpPath::Done(samples) => assert_eq!(samples.len(), 1),
            IcmpPath::Unavailable(reason) => assert!(!reason.is_empty()),
        }
    }

    #[tokio::test]
    async fn ping_inner_loopback_succeeds_via_icmp_or_tcp() {
        // 全链路：ICMP 直通或降级 TCP 打临时 listener，两条路都必须可达
        let (_listener, port) = bind_listener().await;
        let report = ping_inner("127.0.0.1", 2, Duration::from_secs(1), port).await;
        assert!(report.mode == "icmp" || report.mode == "tcp");
        if report.mode == "tcp" {
            assert_eq!(report.port, Some(port));
        }
        assert!(report.received > 0, "回环两路均失败: {report:?}");
        assert!(report.error.is_none());
    }

    #[tokio::test]
    async fn ping_inner_unresolvable_host_is_fail_report() {
        // 含空格的非法主机名在本地解析即失败，不产生外网查询
        let report = ping_inner("not a valid hostname", 2, Duration::from_millis(200), 443).await;
        assert_eq!(report.sent, 0);
        assert_eq!(report.received, 0);
        assert_eq!(report.loss_pct, 100.0);
        assert!(report.error.is_some());
    }

    #[tokio::test]
    async fn ping_command_marks_mode_and_exit_code() {
        let (_listener, port) = bind_listener().await;
        let out = ping("127.0.0.1", 2, Duration::from_secs(1), port).await;
        assert!(out.success);
        assert_eq!(out.exit_code, 0);
        assert!(out.human.contains("mode="));
        assert!(out.human.contains("min/avg/max"));
        let mode = out.json["mode"].as_str().unwrap();
        assert!(mode == "icmp" || mode == "tcp");
        assert!(out.json["received"].as_u64().unwrap() > 0);
        // TCP 降级时 human 必须给出权限指引
        if mode == "tcp" {
            assert!(out.human.contains("已降级 TCP ping"));
            assert!(out.human.contains("cap_net_raw"));
        }
    }

    #[tokio::test]
    async fn ping_command_closed_fallback_port() {
        let port = closed_port().await;
        let out = ping("127.0.0.1", 2, Duration::from_millis(500), port).await;
        assert!(out.human.contains("mode="));
        if out.json["mode"] == "tcp" {
            // 无 ICMP 权限的环境：TCP 打关闭端口必须失败（exit 1，正常输出而非 Err）
            assert!(!out.success);
            assert_eq!(out.exit_code, 1);
            assert_eq!(out.json["received"], 0);
            assert!(out.human.contains("错误："));
        } else {
            // 有 ICMP 权限的环境：回环直通，丢包率不作硬性断言
            assert_eq!(out.json["mode"], "icmp");
        }
    }

    #[test]
    fn report_aggregates_min_avg_max() {
        let samples = vec![
            Sample {
                seq: 0,
                rtt_ms: Some(10.0),
                err: None,
            },
            Sample {
                seq: 1,
                rtt_ms: None,
                err: Some("请求超时".into()),
            },
            Sample {
                seq: 2,
                rtt_ms: Some(20.0),
                err: None,
            },
        ];
        let r = make_report("h", "icmp", None, &samples);
        assert_eq!(r.sent, 3);
        assert_eq!(r.received, 2);
        assert!((r.loss_pct - 100.0 / 3.0).abs() < 1e-9);
        assert_eq!(r.min_ms, Some(10.0));
        assert_eq!(r.avg_ms, Some(15.0));
        assert_eq!(r.max_ms, Some(20.0));
        // 部分丢包仍有接收：视为可达，不置错误
        assert!(r.error.is_none());
    }
}
