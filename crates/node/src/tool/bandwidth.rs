//! bandwidth — 穿透链路吞吐测试（P3，tool 集中唯一依赖服务端角色与登录会话的命令）。
//!
//! 不做 iperf 式裸网吞吐；经 anet 穿透链路到指定对端的实际吞吐/RTT 测试。
//! CLI 是独立进程、拿不到运行中 anet-svc 的隧道句柄，测量在服务端执行，
//! 经管理 API 触发：`POST /api/v1/admin/tool/bandwidth`。
//! 前提：服务端在线 + 已登录 + 对端（扇出 connector）已连接；当前仅支持上游对端。

use super::ToolOutcome;
use crate::cli::AnetClient;
use serde_json::{Value, json};

/// `anet tool bandwidth [peer]`：peer = connector 名称或上游地址（缺省 = 第一个已连接 connector）。
pub async fn bandwidth(peer: Option<&str>, api: Option<String>) -> ToolOutcome {
    // tool 分发在会话校验之前分流，bandwidth 臂自行检查会话（tool 集中唯一需要登录的命令）
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

/// human 渲染：对端 / RTT / 上下行吞吐。
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
