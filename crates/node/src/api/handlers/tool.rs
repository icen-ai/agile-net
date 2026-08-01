//! 诊断工具 API Handlers（cli-tool.md 批次四：bandwidth 链路吞吐测试）
//!
//! `anet tool bandwidth` 是 tool 集中唯一经 API 的命令：CLI 是独立进程，拿不到
//! 运行中 anet-svc 的隧道句柄，测量必须在服务端执行。带宽流属正常诊断流量：
//! 不写审计日志、不接触任何凭据明文（扇出 token 只在 ConnectorManager 建连时使用）。

use crate::api::extractors::AdminAuth;
use crate::api::{ApiState, codes, err, ok};
use crate::service::connectors::BandwidthPeerError;
use agile_net_core::relay::bandwidth;
use axum::{Json, extract::State, http::StatusCode, response::Response};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

/// 带宽测量整体超时（防对端异常挂死管理请求）。
const MEASURE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
pub struct BandwidthRequest {
    /// 对端（connector 名称或上游地址；缺省 = 第一个 connected connector）
    #[serde(default)]
    pub peer: Option<String>,
}

/// POST /api/v1/admin/tool/bandwidth
///
/// 经扇出隧道到指定对端的实际吞吐/RTT 测试（协议级 echo/sink/source 诊断流）。
/// data: {peer, rtt:{min_ms,avg_ms,max_ms}, up:{bytes,ms,mbps}, down:{bytes,ms,mbps}}
pub async fn bandwidth_test(
    AdminAuth(_): AdminAuth,
    State(state): State<ApiState>,
    Json(req): Json<BandwidthRequest>,
) -> Response {
    let peer = req.peer.as_deref().map(str::trim).filter(|p| !p.is_empty());
    let (label, connector) = match state.runtime.connector_manager.resolve_bandwidth_peer(peer) {
        Ok(v) => v,
        Err(BandwidthPeerError::NotFound(msg)) => {
            return err(StatusCode::NOT_FOUND, codes::NOT_FOUND, msg);
        }
        Err(BandwidthPeerError::NotConnected(msg)) => {
            return err(StatusCode::NOT_FOUND, codes::PEER_UNAVAILABLE, msg);
        }
    };
    let Some(mux) = connector.current_mux() else {
        return err(
            StatusCode::NOT_FOUND,
            codes::PEER_UNAVAILABLE,
            format!("对端未连接: {label}（无活动隧道会话）"),
        );
    };

    let sample = tokio::time::timeout(
        MEASURE_TIMEOUT,
        bandwidth::measure(
            &mux,
            bandwidth::DEFAULT_RTT_COUNT,
            bandwidth::DEFAULT_TRANSFER_BYTES,
        ),
    )
    .await;
    match sample {
        Ok(Ok(s)) => ok(json!({
            "peer": label,
            "rtt": s.rtt,
            "up": s.up,
            "down": s.down,
        })),
        Ok(Err(e)) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            format!("带宽测试执行失败（对端 {label}）: {e}"),
        ),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            format!(
                "带宽测试超时（{}s 未完成，对端 {label}）",
                MEASURE_TIMEOUT.as_secs()
            ),
        ),
    }
}
