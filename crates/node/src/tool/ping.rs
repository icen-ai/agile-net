//! ping — ICMP echo + TCP fallback chain (P2, surge-ping).
//!
//! Permissions and fallback: Linux needs root / CAP_NET_RAW (`sudo setcap cap_net_raw+ep anet-svc`)
//! or a kernel-opened net.ipv4.ping_group_range; Windows needs no admin. When ICMP is unavailable
//! it falls back to TCP ping (tcp_fallback_port, default 443), and the output explicitly marks mode=icmp|tcp.

use super::tcping;
use super::ToolOutcome;
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;
use surge_ping::{Client, Config, PingIdentifier, PingSequence, SurgeError, ICMP};

/// ICMP echo payload (content is meaningless, just a non-empty body matching system ping).
const PAYLOAD: &[u8] = b"anet-tool-ping";

/// Structured ping report (shared by ping/diag).
#[derive(Debug, Clone, Serialize)]
pub struct PingReport {
    pub host: String,
    /// Probe mode: "icmp" | "tcp"
    pub mode: String,
    /// Target port on TCP fallback (None in ICMP mode)
    pub port: Option<u16>,
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub error: Option<String>,
}

/// A single probe sample (module-internal carrier between per-probe output and statistics).
#[derive(Debug, Clone)]
struct Sample {
    seq: u32,
    /// Round-trip latency of this probe (None on loss/failure)
    rtt_ms: Option<f64>,
    /// Failure reason (timeout/connection refused/permission etc.)
    err: Option<String>,
}

/// Full internal ping result: aggregate report + per-probe samples + fallback note (for human rendering).
struct PingDetail {
    report: PingReport,
    samples: Vec<Sample>,
    /// Fallback reason (always set when on TCP, None when ICMP works directly)
    fallback_note: Option<String>,
}

/// Internal result of the ICMP main path.
enum IcmpPath {
    /// ICMP probing finished (samples may include timeouts/loss)
    Done(Vec<Sample>),
    /// ICMP unavailable (socket creation failed or every send hard-errors); fall back to TCP
    Unavailable(String),
}

/// Ping probe core (shared by ping/diag): ICMP main path, TCP fallback when unavailable.
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

/// `anet tool ping <host>`: print per-probe results, statistics, and the mode marker.
pub async fn ping(host: &str, count: u32, timeout: Duration, tcp_fallback_port: u16) -> ToolOutcome {
    let detail = ping_collect(host, count, timeout, tcp_fallback_port).await;
    let report = &detail.report;

    // Human-readable output: per-probe results + ping-style statistics + mode/fallback markers
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

/// Full probe flow: resolve address → ICMP main path → TCP fallback when unavailable.
async fn ping_collect(
    host: &str,
    count: u32,
    timeout: Duration,
    tcp_fallback_port: u16,
) -> PingDetail {
    let count = count.max(1);

    // Resolve address: IP literals are used directly; domain names are resolved once before the ICMP path
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
            // TCP fallback: reuse tcping's connect-probe core (probe resolves domain names itself)
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

/// ICMP main path: an unopenable socket or per-send hard errors mean unavailable; timeouts are just loss.
async fn icmp_path(addr: IpAddr, count: u32, timeout: Duration) -> IcmpPath {
    let config = match addr {
        IpAddr::V4(_) => Config::default(),
        IpAddr::V6(_) => Config::builder().kind(ICMP::V6).build(),
    };
    // Client::new tries DGRAM first then degrades to RAW; if both fail there is no ICMP permission
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
    // Socket created but every send hard-errors (e.g. sandbox EPERM): also treat as ICMP unavailable
    let received = samples.iter().filter(|s| s.rtt_ms.is_some()).count();
    if received == 0
        && let Some(e) = hard_err
    {
        return IcmpPath::Unavailable(format!("ICMP 收发失败：{e}"));
    }
    IcmpPath::Done(samples)
}

/// TCP fallback path: collect samples by calling the tcping probe core per probe.
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

/// Aggregate per-probe samples into a structured report (with received=0, summarize the first failure reason).
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
    // On total failure summarize the first failure reason; any reception means reachable, so no error
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

/// Resolve the target host to an IP (domains go through the system resolver, IP literals cost nothing).
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

    /// Start a temporary listener and return its port (the listen backlog accepts connections, no explicit accept loop needed).
    async fn bind_listener() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    /// Bind then immediately release, yielding a loopback port that is definitely closed.
    async fn closed_port() -> u16 {
        let (listener, port) = bind_listener().await;
        drop(listener);
        port
    }

    #[tokio::test]
    async fn tcp_fallback_full_chain_against_listener() {
        // Full TCP-fallback chain against a temporary listener: per-probe samples → aggregate report
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
        // ICMP main path: with permission, loopback should yield results; without, it must return Unavailable gracefully, not panic
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        match icmp_path(addr, 1, Duration::from_millis(500)).await {
            IcmpPath::Done(samples) => assert_eq!(samples.len(), 1),
            IcmpPath::Unavailable(reason) => assert!(!reason.is_empty()),
        }
    }

    #[tokio::test]
    async fn ping_inner_loopback_succeeds_via_icmp_or_tcp() {
        // Full chain: ICMP direct or TCP fallback against a temporary listener — both paths must be reachable
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
        // A hostname containing spaces fails local resolution without issuing any external query
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
        // On TCP fallback the human output must include the permission guidance
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
            // Environments without ICMP permission: TCP against a closed port must fail (exit 1, normal output not Err)
            assert!(!out.success);
            assert_eq!(out.exit_code, 1);
            assert_eq!(out.json["received"], 0);
            assert!(out.human.contains("错误："));
        } else {
            // Environments with ICMP permission: loopback works directly; no hard assertion on loss rate
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
        // Partial loss with some reception: treated as reachable, no error set
        assert!(r.error.is_none());
    }
}
