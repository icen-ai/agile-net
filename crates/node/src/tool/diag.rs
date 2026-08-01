//! diag — 组合诊断编排（P0，纯编排零新增依赖）。
//!
//! DNS 解析 → ping（降级链）→ traceroute → tcping，分层输出报告并给出
//! 「卡在哪一层」的结论。各层复用结构化核心：[`super::dns::query`]、
//! [`super::ping::ping_inner`]、[`super::traceroute::trace_inner`]、
//! [`super::tcping::probe`]。traceroute 只做路径画像、不进门禁结论——
//! 其失败多为 raw socket 权限受限或中间跳过滤，不代表连通性受损。

use super::{dns, ping, tcping, traceroute, ToolOutcome};
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;

/// diag 层内 ping 次数（比独立 ping 命令少，控制整体耗时）。
const DIAG_PING_COUNT: u32 = 3;
/// 各层单次超时预算。
const DIAG_PING_TIMEOUT: Duration = Duration::from_secs(2);
const DIAG_TRACE_TIMEOUT: Duration = Duration::from_secs(2);
const DIAG_TCP_TIMEOUT: Duration = Duration::from_secs(3);
/// 路由追踪跳数上限（路径画像从简；完整追踪用 `anet tool traceroute`，默认 30 跳）。
const DIAG_MAX_HOPS: u8 = 16;

/// 单层诊断结果（human/json 共用数据源）。
#[derive(Debug, Clone, Serialize)]
struct LayerReport {
    /// 层名：dns / ping / traceroute / tcping
    name: &'static str,
    /// ok 通过 / fail 失败 / skip 跳过 / unknown 受限无法判定
    status: &'static str,
    /// 单行人类可读摘要
    summary: String,
    /// 各层原始结构化报告（原样嵌入，供 --json 与未来 GUI 复用）
    detail: serde_json::Value,
}

/// `anet tool diag <host> [port]`：分层组合诊断。
pub async fn diag(host: &str, port: u16) -> ToolOutcome {
    if port == 0 {
        return ToolOutcome::usage_error("端口不能为 0");
    }

    // [1] DNS：IP 字面量跳过；域名先 A 后 AAAA，任一拿到记录即通过。
    //     解析失败时后续各层必然失败，标记跳过直接给结论。
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

    // [2] ping：ICMP 主路径，无权限自动降级 TCP（降级端口复用 diag 端口，
    //     此时与 tcping 层同源，结论文案据此区分）。
    let ping_report = ping::ping_inner(host, DIAG_PING_COUNT, DIAG_PING_TIMEOUT, port).await;
    let ping_ok = ping_report.received > 0;
    let ping_layer = LayerReport {
        name: "ping",
        status: if ping_ok { "ok" } else { "fail" },
        summary: ping_summary(&ping_report),
        detail: serde_json::to_value(&ping_report).unwrap_or_default(),
    };

    // [3] traceroute：仅 ping 通后执行（ping 失败时追踪只会空跑超时）。
    //     Err 多为权限受限（trace_inner 错误串内含 setcap 指引），不进门禁。
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

    // [4] tcping：端到端端口验证（最终门禁）。
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

/// DNS 层：IP 字面量跳过；域名先 A 后 AAAA，任一拿到记录即视为解析成功。
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

/// 由门禁层结果推导「卡在哪一层」结论（dns → ping → tcping 顺序门禁，
/// traceroute 不入门禁）。纯函数，供单测直接断言各分支。
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
        // ICMP 不回应但 TCP 通畅：目标或中间设备过滤 ICMP，属常见现象，不影响业务
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
        // TCP 降级已等价于 tcping 探测，两层同源失败
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

/// 汇总渲染 ToolOutcome：human 分层报告 + json 结构化，结论码映射 ok/fail。
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

/// ping 层摘要：显式标注 mode=icmp|tcp（TCP 降级附端口），附丢包与耗时统计。
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

/// traceroute 层摘要：跳数与末跳地址；全超时如实说明。
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

/// tcping 层摘要：连通给延迟，失败给原因。
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

    // ---------- 结论纯函数分支（不依赖任何外部实现） ----------

    /// DNS 失败短路：无论其余层如何，结论卡 DNS 层
    #[test]
    fn conclude_dns_fail() {
        let (code, text) = conclude(true, false, "icmp", false, "example.com", 443);
        assert_eq!(code, "dns");
        assert!(text.contains("DNS"));
    }

    /// ping 通、端口不通 → 卡 tcping 层（服务未监听/防火墙拦端口）
    #[test]
    fn conclude_stuck_at_tcping() {
        let (code, text) = conclude(false, true, "icmp", false, "h", 8080);
        assert_eq!(code, "tcping");
        assert!(text.contains("tcping"));
        assert!(text.contains("8080"));
    }

    /// ICMP 模式 ping 失败且端口不通 → 卡 ping 层
    #[test]
    fn conclude_stuck_at_ping_icmp() {
        let (code, _) = conclude(false, false, "icmp", false, "h", 443);
        assert_eq!(code, "ping");
    }

    /// TCP 降级亦失败 → 卡 ping 层，文案指明 TCP 等价探测失败
    #[test]
    fn conclude_stuck_at_ping_tcp_fallback() {
        let (code, text) = conclude(false, false, "tcp", false, "h", 443);
        assert_eq!(code, "ping");
        assert!(text.contains("TCP 降级"));
    }

    /// ICMP 被过滤但 TCP 通畅 → 结论仍 ok，文案标注 ICMP 过滤
    #[test]
    fn conclude_icmp_filtered_tcp_ok() {
        let (code, text) = conclude(false, false, "icmp", true, "h", 443);
        assert_eq!(code, "ok");
        assert!(text.contains("ICMP"));
    }

    /// 全通 → ok
    #[test]
    fn conclude_all_ok() {
        let (code, text) = conclude(false, true, "icmp", true, "h", 443);
        assert_eq!(code, "ok");
        assert!(text.contains("通畅"));
    }

    // ---------- DNS 层（IP 字面量分支无网络） ----------

    /// IP 字面量（v4/v6）跳过 DNS 层，不产生任何网络流量
    #[tokio::test]
    async fn dns_layer_skips_ip_literal() {
        for ip in ["127.0.0.1", "::1", "192.168.0.1"] {
            let layer = dns_layer(ip).await;
            assert_eq!(layer.status, "skip", "{ip}");
            assert_eq!(layer.name, "dns");
        }
    }

    // ---------- 用法错误 ----------

    /// 端口 0 → 用法错误（exit 2）
    #[tokio::test]
    async fn diag_rejects_port_zero() {
        let outcome = diag("127.0.0.1", 0).await;
        assert_eq!(outcome.exit_code, 2);
        assert!(!outcome.success);
    }

    // ---------- 全链路集成（仅打本机回环） ----------

    /// 起回环临时 listener，四层跑通：dns 跳过、ping 通（icmp 或 tcp 降级）、
    /// traceroute ok 或 unknown（权限受限）、tcping 通，结论 ok、exit 0
    #[tokio::test]
    async fn diag_loopback_full_chain() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // 保活 accept，避免连接堆积导致后续 probe 失败
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });

        let outcome = diag("127.0.0.1", port).await;
        assert_eq!(outcome.exit_code, 0, "human:\n{}", outcome.human);
        assert!(outcome.success);
        assert_eq!(outcome.json["conclusion"], "ok");

        let layers = outcome.json["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 4);
        assert_eq!(layers[0]["name"], "dns");
        assert_eq!(layers[0]["status"], "skip"); // IP 字面量
        assert_eq!(layers[1]["name"], "ping");
        assert_eq!(layers[1]["status"], "ok");
        assert_eq!(layers[2]["name"], "traceroute");
        // raw socket 权限受限时允许 unknown，不进门禁
        let trace_status = layers[2]["status"].as_str().unwrap();
        assert!(
            ["ok", "unknown"].contains(&trace_status),
            "traceroute status={trace_status}"
        );
        assert_eq!(layers[3]["name"], "tcping");
        assert_eq!(layers[3]["status"], "ok");
        // 需特权层在 human 输出中显式标注当前探测模式
        assert!(outcome.human.contains("mode="), "human:\n{}", outcome.human);
        assert!(outcome.human.contains("结论"), "human:\n{}", outcome.human);
    }

    /// 回环空闲端口：exit 1，结论卡在 ping 或 tcping（视本机 ICMP 权限），
    /// tcping 层必 fail；traceroute 在 ping 失败时须跳过不空跑
    #[tokio::test]
    async fn diag_loopback_closed_port() {
        // bind 取号后立刻 drop，得到一个确定未监听的端口
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
