//! Doctor tool API handlers (cli-tool.md batch 4: bandwidth link throughput test)
//!
//! `anet tool bandwidth` is the only tool command exposed via API: the CLI is a separate process
//! without the running anet-svc tunnel handles, so measurement must run server-side. Bandwidth
//! streams are normal doctor traffic: no audit log, no credential plaintext (fan-out tokens are
//! only used by ConnectorManager when connecting).

use crate::api::extractors::AdminAuth;
use crate::api::{ApiState, codes, err, ok};
use crate::service::connectors::BandwidthPeerError;
use agile_net_core::relay::bandwidth;
use axum::body::Bytes;
use axum::{Json, extract::State, http::StatusCode, response::Response};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

/// Overall bandwidth measurement timeout (prevents a stuck peer from hanging the admin request).
const MEASURE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
pub struct BandwidthRequest {
    /// Peer (connector name or upstream address; default = first connected connector)
    #[serde(default)]
    pub peer: Option<String>,
}

/// POST /api/v1/admin/tool/bandwidth
///
/// Real throughput/RTT test to the given peer over the fan-out tunnel (protocol-level echo/sink/source doctor streams).
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

/// POST /api/v1/admin/tool/qr-decode
///
/// Decode the first QR code in an uploaded image (raw PNG/JPEG body, ≤20MB) into its text.
/// Used by the universal import wizard (agimport.js) QR entry; local-only convenience, no audit.
/// data: {text}
pub async fn qr_decode(AdminAuth(_): AdminAuth, body: Bytes) -> Response {
    match crate::qr::decode_qr_image(&body) {
        Ok(text) => ok(json!({ "text": text })),
        Err(msg) => err(StatusCode::BAD_REQUEST, codes::VALIDATION_FAILED, msg),
    }
}
