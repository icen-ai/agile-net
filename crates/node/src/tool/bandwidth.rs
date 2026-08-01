//! bandwidth — 穿透链路吞吐测试（P3，唯一依赖服务端角色的命令）。
//!
//! 不做 iperf 式裸网吞吐；经 anet 穿透链路到指定对端的实际吞吐/RTT 测试
//! （复用现有隧道/mux 发测速流）。前提：对端在线。

use super::ToolOutcome;

/// `anet tool bandwidth [peer]`：peer 缺省时列出可用对端。
pub async fn bandwidth(peer: Option<&str>) -> ToolOutcome {
    let _ = peer;
    ToolOutcome::unimplemented("bandwidth")
}
