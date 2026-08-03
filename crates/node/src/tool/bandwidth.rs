//! bandwidth — penetration-link throughput test (P3; the only toolkit command that depends on the server role and a login session).
//!
//! Not an iperf-style raw-network benchmark: it measures actual throughput/RTT over the anet
//! tunnel to a given peer. The CLI is a separate process and cannot reach the tunnel handles of a
//! running anet-svc, so measurement runs server-side, triggered via the admin API:
//! `POST /api/v1/admin/tool/bandwidth`.
//! Prerequisites: server online + logged in + the peer (fan-out connector) connected; currently only fan-out peers are supported.

use super::ToolOutcome;
use crate::cli::AnetClient;
use serde_json::{Value, json};

/// `anet tool bandwidth [peer]`: peer = connector name or upstream address (default = first connected connector).
pub async fn bandwidth(peer: Option<&str>, api: Option<String>) -> ToolOutcome {
    // Tool dispatch splits off before session validation; the bandwidth arm checks the session itself (the only toolkit command requiring login)
    let mut client = match AnetClient::from_session(api) {
        Ok(c) => c,
        Err(_) => {
            return ToolOutcome::usage_error("bandwidth 需要服务端在线且已登录（anet login）");
        }
    };
    let body = match peer {
        Some(p) => json!({ "peer": p }),
        None => json!({}),
    };
    match client
        .api("POST", "/api/v1/admin/tool/bandwidth", Some(body))
        .await
    {
        Ok(d) => ToolOutcome::ok(render(&d), d),
        Err(e) => ToolOutcome::fail(
            format!("带宽测试失败: {e:#}"),
            json!({ "error": format!("{e:#}") }),
        ),
    }
}

/// human rendering: peer / RTT / up/down throughput.
fn render(d: &Value) -> String {
    let peer = d["peer"].as_str().unwrap_or("-");
    let f = |v: &Value| v.as_f64().unwrap_or(0.0);
    let u = |v: &Value| v.as_u64().unwrap_or(0);
    let mib = |v: &Value| f(&v["bytes"]) / 1024.0 / 1024.0;
    let (rtt, up, down) = (&d["rtt"], &d["up"], &d["down"]);
    format!(
        "穿透链路带宽测试（经 anet 隧道）\n  对端:   {peer}\n  RTT:    min {:.3}ms · avg {:.3}ms · max {:.3}ms\n  上行:   {:.1} MiB / {} ms — {:.2} Mbps\n  下行:   {:.1} MiB / {} ms — {:.2} Mbps",
        f(&rtt["min_ms"]),
        f(&rtt["avg_ms"]),
        f(&rtt["max_ms"]),
        mib(up),
        u(&up["ms"]),
        f(&up["mbps"]),
        mib(down),
        u(&down["ms"]),
        f(&down["mbps"]),
    )
}
