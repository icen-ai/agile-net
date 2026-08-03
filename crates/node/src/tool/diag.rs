//! diag — layered diagnostic orchestration (P0, pure orchestration, zero new dependencies).
//!
//! DNS resolution → ping (fallback chain) → traceroute → tcping: layered report with a
//! "which layer is it stuck at" conclusion. Each layer reuses a structured core: [`super::dns::query`],
//! [`super::ping::ping_inner`], [`super::traceroute::trace_inner`],
//! [`super::tcping::probe`]. traceroute only profiles the path and never gates the conclusion —
//! its failures are usually raw-socket permission limits or intermediate-hop filtering, not connectivity loss.

use super::{dns, ping, tcping, traceroute, ToolOutcome};
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;

/// Ping count inside diag (fewer than the standalone ping command, to bound total runtime).
const DIAG_PING_COUNT: u32 = 3;
/// Per-probe timeout budget for each layer.
const DIAG_PING_TIMEOUT: Duration = Duration::from_secs(2);
const DIAG_TRACE_TIMEOUT: Duration = Duration::from_secs(2);
const DIAG_TCP_TIMEOUT: Duration = Duration::from_secs(3);
/// Hop limit for traceroute (lightweight path profile; for a full trace use `anet tool traceroute`, default 30 hops).
const DIAG_MAX_HOPS: u8 = 16;

/// One layer's diagnostic result (shared data source for human/json).
#[derive(Debug, Clone, Serialize)]
struct LayerReport {
    /// Layer name: dns / ping / traceroute / tcping
    name: &'static str,
    /// ok passed / fail failed / skip skipped / unknown cannot be determined (restricted)
    status: &'static str,
    /// One-line human-readable summary
    summary: String,
    /// The layer's raw structured report (embedded verbatim, for --json and future GUI reuse)
    detail: serde_json::Value,
}

/// `anet tool diag <host> [port]`: layered combined diagnosis.
pub async fn diag(host: &str, port: u16) -> ToolOutcome {
    if port == 0 {
        return ToolOutcome::usage_error("端口不能为 0");
    }

    // [1] DNS: skipped for IP literals; domains try A then AAAA, any record passes.
    //     On resolution failure every later layer must fail — mark them skipped and conclude directly.
    let dns_layer = dns_layer(host).await;
    if dns_layer.status == "fail" {
        let skipped = |name: &'static str| LayerReport {
            name,
            status: "skip",
            summary: "DNS 未解析，本层跳过".into(),
            detail: serde_json::json!({ "reason": "dns_failed" }),
        };
        let layers = vec![
            dns_layer,
            skipped("ping"),
            skipped("traceroute"),
            skipped("tcping"),
        ];
        let (code, text) = conclude(true, false, "icmp", false, host, port);
        return render(host, port, layers, code, text);
    }

    // [2] ping: ICMP main path with automatic TCP fallback without permission (fallback port reuses the diag port,
    //     making it share the same probe as the tcping layer — the conclusion text distinguishes this).
    let ping_report = ping::ping_inner(host, DIAG_PING_COUNT, DIAG_PING_TIMEOUT, port).await;
    let ping_ok = ping_report.received > 0;
    let ping_layer = LayerReport {
        name: "ping",
        status: if ping_ok { "ok" } else { "fail" },
        summary: ping_summary(&ping_report),
        detail: serde_json::to_value(&ping_report).unwrap_or_default(),
    };

    // [3] traceroute: only runs after ping succeeds (on ping failure a trace would just time out).
    //     Err is mostly permission-related (the trace_inner error string contains setcap guidance); never gates.
    let trace_layer = if ping_ok {
        match traceroute::trace_inner(host, DIAG_MAX_HOPS, DIAG_TRACE_TIMEOUT).await {
            Ok(hops) => LayerReport {
                name: "traceroute",
                status: "ok",
                summary: trace_summary(&hops),
                detail: serde_json::to_value(&hops).unwrap_or_default(),
            },
            Err(e) => LayerReport {
                name: "traceroute",
                status: "unknown",
                summary: format!("路由追踪不可用：{e}"),
                detail: serde_json::json!({ "error": e }),
            },
        }
    } else {
        LayerReport {
            name: "traceroute",
            status: "skip",
            summary: "ping 未通，追踪跳过（完整追踪：`anet tool traceroute`）".into(),
            detail: serde_json::json!({ "reason": "ping_failed" }),
        }
    };

    // [4] tcping: end-to-end port verification (the final gate).
    let probe = tcping::probe(host, port, DIAG_TCP_TIMEOUT).await;
    let tcp_layer = LayerReport {
        name: "tcping",
        status: if probe.connected { "ok" } else { "fail" },
        summary: tcp_summary(&probe),
        detail: serde_json::to_value(&probe).unwrap_or_default(),
    };

    let layers = vec![dns_layer, ping_layer, trace_layer, tcp_layer];
    let (code, text) = conclude(
        false,
        ping_ok,
        &ping_report.mode,
        probe.connected,
        host,
        port,
    );
    render(host, port, layers, code, text)
}

/// DNS layer: skipped for IP literals; domains try A then AAAA, any record counts as resolved.
async fn dns_layer(host: &str) -> LayerReport {
    if host.parse::<IpAddr>().is_ok() {
        return LayerReport {
            name: "dns",
            status: "skip",
            summary: "目标是 IP 字面量，无需解析".into(),
            detail: serde_json::json!({ "reason": "ip_literal" }),
        };
    }
    let mut errors = Vec::new();
    for rtype in ["A", "AAAA"] {
        match dns::query(host, None, rtype).await {
            Ok(answers) if !answers.is_empty() => {
                let values: Vec<&str> = answers.iter().map(|a| a.value.as_str()).collect();
                return LayerReport {
                    name: "dns",
                    status: "ok",
                    summary: format!("{rtype} 记录 {} 条：{}", answers.len(), values.join(", ")),
                    detail: serde_json::to_value(&answers).unwrap_or_default(),
                };
            }
            Ok(_) => errors.push(format!("{rtype} 无记录")),
            Err(e) => errors.push(format!("{rtype} {e}")),
        }
    }
    LayerReport {
        name: "dns",
        status: "fail",
        summary: format!("解析失败：{}", errors.join("；")),
        detail: serde_json::json!({ "errors": errors }),
    }
}

/// Derive the "which layer is it stuck at" conclusion from the gate layers (gated in dns → ping → tcping
/// order; traceroute never gates). Pure function, unit-tested branch by branch directly.
fn conclude(
    dns_failed: bool,
    ping_ok: bool,
    ping_mode: &str,
    tcp_ok: bool,
    host: &str,
    port: u16,
) -> (&'static str, String) {
    if dns_failed {
        return (
            "dns",
            "卡在 DNS 层：域名解析失败——检查系统 DNS 配置（`anet tool dnsconf`）、\
             换服务器验证（`anet tool dns <domain> @223.5.5.5`）或改用 IP 直连"
                .into(),
        );
    }
    if tcp_ok {
        if ping_ok {
            return ("ok", "全链路通畅".into());
        }
        // ICMP silent but TCP fine: the target or an intermediate device filters ICMP — common, harmless to traffic
        return (
            "ok",
            "全链路通畅（ICMP 不回应但 TCP 正常——目标或中间设备过滤 ICMP，属常见现象）".into(),
        );
    }
    if ping_ok {
        return (
            "tcping",
            format!(
                "卡在 tcping 层：主机可达但 {host}:{port} 未开放/被过滤——服务未监听或\
                 被防火墙拦截（`anet tool scan {host} 1-10000` 排查开放端口）"
            ),
        );
    }
    if ping_mode == "tcp" {
        // TCP fallback is equivalent to a tcping probe; both layers share the same failure
        (
            "ping",
            format!(
                "卡在 ping 层：TCP 降级探测（{host}:{port}）亦失败——目标主机不可达或端口未开放/被过滤"
            ),
        )
    } else {
        (
            "ping",
            "卡在 ping 层：主机不回应（丢包 100%）且端口不通——目标不可达或流量被全量过滤".into(),
        )
    }
}

/// Render the aggregate ToolOutcome: layered human report + structured json; conclusion code maps to ok/fail.
fn render(
    host: &str,
    port: u16,
    layers: Vec<LayerReport>,
    code: &'static str,
    text: String,
) -> ToolOutcome {
    let mut human = format!("组合诊断 {host}:{port}（DNS → ping → traceroute → tcping）\n\n");
    for (i, l) in layers.iter().enumerate() {
        human.push_str(&format!(
            "[{}] {:<11} {:<8} {}\n",
            i + 1,
            l.name,
            l.status,
            l.summary
        ));
    }
    human.push_str(&format!("\n结论：{text}（conclusion={code}）"));
    let json = serde_json::json!({
        "host": host,
        "port": port,
        "layers": layers,
        "conclusion": code,
        "conclusion_text": text,
    });
    if code == "ok" {
        ToolOutcome::ok(human, json)
    } else {
        ToolOutcome::fail(human, json)
    }
}

/// ping layer summary: explicit mode=icmp|tcp marker (TCP fallback adds the port), plus loss and latency stats.
fn ping_summary(r: &ping::PingReport) -> String {
    let mut s = format!("mode={}", r.mode);
    if let Some(p) = r.port {
        s.push_str(&format!(" port={p}"));
    }
    s.push_str(&format!(" 丢包{:.0}%（{}/{}）", r.loss_pct, r.received, r.sent));
    if let (Some(min), Some(avg), Some(max)) = (r.min_ms, r.avg_ms, r.max_ms) {
        s.push_str(&format!(" min/avg/max={min:.1}/{avg:.1}/{max:.1}ms"));
    }
    if r.received == 0
        && let Some(e) = &r.error
    {
        s.push_str(&format!("：{e}"));
    }
    s
}

/// traceroute layer summary: hop count and last-hop address; total silence reported honestly.
fn trace_summary(hops: &[traceroute::Hop]) -> String {
    let answered = hops.iter().filter(|h| h.addr.is_some()).count();
    match hops.iter().rev().find_map(|h| h.addr.as_deref()) {
        Some(addr) => format!(
            "{} 跳（{} 跳有回应），末跳 {addr}（仅前 {} 跳画像，完整追踪：`anet tool traceroute`）",
            hops.len(),
            answered,
            DIAG_MAX_HOPS
        ),
        None => format!("{} 跳均无回应（中间跳可能过滤 ICMP）", hops.len()),
    }
}

/// tcping layer summary: latency on connect, reason on failure.
fn tcp_summary(p: &tcping::TcpProbe) -> String {
    if p.connected {
        let latency = p
            .latency_ms
            .map(|v| format!("{v:.1}ms"))
            .unwrap_or_else(|| "?".into());
        format!("已连接 {}:{} 延迟 {latency}", p.host, p.port)
    } else {
        format!(
            "连接 {}:{} 失败：{}",
            p.host,
            p.port,
            p.error.as_deref().unwrap_or("未知原因")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Conclusion pure-function branches (no external dependencies) ----------

    /// DNS failure short-circuits: whatever the other layers do, the conclusion is the DNS layer
    #[test]
    fn conclude_dns_fail() {
        let (code, text) = conclude(true, false, "icmp", false, "example.com", 443);
        assert_eq!(code, "dns");
        assert!(text.contains("DNS"));
    }

    /// ping ok, port closed → stuck at the tcping layer (service not listening / firewall blocking the port)
    #[test]
    fn conclude_stuck_at_tcping() {
        let (code, text) = conclude(false, true, "icmp", false, "h", 8080);
        assert_eq!(code, "tcping");
        assert!(text.contains("tcping"));
        assert!(text.contains("8080"));
    }

    /// ICMP-mode ping failed and port closed → stuck at the ping layer
    #[test]
    fn conclude_stuck_at_ping_icmp() {
        let (code, _) = conclude(false, false, "icmp", false, "h", 443);
        assert_eq!(code, "ping");
    }

    /// TCP fallback also failed → stuck at the ping layer; text states the TCP-equivalent probe failed
    #[test]
    fn conclude_stuck_at_ping_tcp_fallback() {
        let (code, text) = conclude(false, false, "tcp", false, "h", 443);
        assert_eq!(code, "ping");
        assert!(text.contains("TCP 降级"));
    }

    /// ICMP filtered but TCP fine → conclusion stays ok; text notes the ICMP filtering
    #[test]
    fn conclude_icmp_filtered_tcp_ok() {
        let (code, text) = conclude(false, false, "icmp", true, "h", 443);
        assert_eq!(code, "ok");
        assert!(text.contains("ICMP"));
    }

    /// Everything passes → ok
    #[test]
    fn conclude_all_ok() {
        let (code, text) = conclude(false, true, "icmp", true, "h", 443);
        assert_eq!(code, "ok");
        assert!(text.contains("通畅"));
    }

    // ---------- DNS layer (IP-literal branch needs no network) ----------

    /// IP literals (v4/v6) skip the DNS layer and generate no network traffic
    #[tokio::test]
    async fn dns_layer_skips_ip_literal() {
        for ip in ["127.0.0.1", "::1", "192.168.0.1"] {
            let layer = dns_layer(ip).await;
            assert_eq!(layer.status, "skip", "{ip}");
            assert_eq!(layer.name, "dns");
        }
    }

    // ---------- Usage errors ----------

    /// Port 0 → usage error (exit 2)
    #[tokio::test]
    async fn diag_rejects_port_zero() {
        let outcome = diag("127.0.0.1", 0).await;
        assert_eq!(outcome.exit_code, 2);
        assert!(!outcome.success);
    }

    // ---------- Full-chain integration (loopback only) ----------

    /// Temporary loopback listener, all four layers: dns skipped, ping ok (icmp or tcp fallback),
    /// traceroute ok or unknown (permission-limited), tcping ok, conclusion ok, exit 0
    #[tokio::test]
    async fn diag_loopback_full_chain() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Keep accepting so connections don't pile up and fail later probes
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });

        let outcome = diag("127.0.0.1", port).await;
        assert_eq!(outcome.exit_code, 0, "human:\n{}", outcome.human);
        assert!(outcome.success);
        assert_eq!(outcome.json["conclusion"], "ok");

        let layers = outcome.json["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 4);
        assert_eq!(layers[0]["name"], "dns");
        assert_eq!(layers[0]["status"], "skip"); // IP literal
        assert_eq!(layers[1]["name"], "ping");
        assert_eq!(layers[1]["status"], "ok");
        assert_eq!(layers[2]["name"], "traceroute");
        // unknown is allowed when raw-socket permission is restricted; it never gates
        let trace_status = layers[2]["status"].as_str().unwrap();
        assert!(
            ["ok", "unknown"].contains(&trace_status),
            "traceroute status={trace_status}"
        );
        assert_eq!(layers[3]["name"], "tcping");
        assert_eq!(layers[3]["status"], "ok");
        // Privileged layers must mark the current probe mode in the human output
        assert!(outcome.human.contains("mode="), "human:\n{}", outcome.human);
        assert!(outcome.human.contains("结论"), "human:\n{}", outcome.human);
    }

    /// Idle loopback port: exit 1, conclusion stuck at ping or tcping (depends on local ICMP permission),
    /// tcping layer must fail; traceroute must be skipped rather than run pointlessly when ping fails
    #[tokio::test]
    async fn diag_loopback_closed_port() {
        // Bind then drop immediately to get a port that is definitely not listened on
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let outcome = diag("127.0.0.1", port).await;
        assert_eq!(outcome.exit_code, 1, "human:\n{}", outcome.human);
        assert!(!outcome.success);

        let c = outcome.json["conclusion"].as_str().unwrap();
        assert!(c == "ping" || c == "tcping", "conclusion={c}");

        let layers = outcome.json["layers"].as_array().unwrap();
        let tcp = layers.iter().find(|l| l["name"] == "tcping").unwrap();
        assert_eq!(tcp["status"], "fail");

        let ping_layer = layers.iter().find(|l| l["name"] == "ping").unwrap();
        let trace = layers.iter().find(|l| l["name"] == "traceroute").unwrap();
        if ping_layer["status"] == "fail" {
            assert_eq!(trace["status"], "skip");
        }
    }
}
