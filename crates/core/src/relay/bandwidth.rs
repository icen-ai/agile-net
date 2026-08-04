//! Protocol-level bandwidth diagnostic service (echo / sink / source)
//!
//! Reserved magic address [`MAGIC_HOST`]: when either side (a fan-in peer session
//! on RelayListener, a fan-out tunnel on RelayConnector) receives an Open request
//! targeting this address, it intercepts **before** the ACL check and answers
//! locally — no routing, no egress capability, so ACL-restricted (PeerAcl) nodes
//! are equally testable and it is not an ACL bypass. Same tier as heartbeat: a
//! protocol built-in diagnostic plane, never routed; bandwidth streams are normal
//! diagnostic traffic, not recorded in audit details.
//!
//! First stream byte selects the mode:
//! - `e` echo: echo back verbatim (RTT / bidirectional path test)
//! - `s` sink: read and discard; after peer half-close reply an 8-byte BE total count as ack (uplink test)
//! - `g` source: read an 8-byte BE requested byte count, then stream that many bytes (downlink test)

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::OpenChannel;
use crate::relay::mux::{MuxChannel, MuxSession, OpenRequest};

use bytes::Bytes;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Reserved bandwidth-diagnostic address (never routed; case-insensitive).
pub const MAGIC_HOST: &str = "anet.bandwidth";

/// Mode byte: echo (verbatim echo).
pub const MODE_ECHO: u8 = b'e';
/// Mode byte: sink (read and discard; reply an 8-byte BE total count after EOF).
pub const MODE_SINK: u8 = b's';
/// Mode byte: source (read an 8-byte BE requested byte count, then stream that many bytes).
pub const MODE_SOURCE: u8 = b'g';

/// Per-request byte cap for source mode (guards against resource exhaustion).
pub const MAX_SOURCE_BYTES: u64 = 1 << 30;

/// Mode byte read timeout (prevents a peer from hanging the serve task after opening a stream).
const MODE_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Default RTT probe count (each a 64B echo round trip).
pub const DEFAULT_RTT_COUNT: u32 = 10;
/// Default per-direction throughput test bytes (8 MiB).
pub const DEFAULT_TRANSFER_BYTES: u64 = 8 * 1024 * 1024;

/// Whether the target address hits the bandwidth-diagnostic reserved address.
pub fn is_magic_target(addr: &str) -> bool {
    addr.eq_ignore_ascii_case(MAGIC_HOST)
}

/// Interception entry: answer locally and return true when the target is the
/// reserved address (the caller then skips ACL/routing).
///
/// Must be called before the ACL check (symmetric on fan-in listener / fan-out connector):
/// echo/sink/source have no routing capability, restricted nodes are equally testable, no ACL bypass.
pub async fn intercept(mux: &Arc<MuxSession>, req: &OpenRequest, target_addr: &str) -> bool {
    if !is_magic_target(target_addr) {
        return false;
    }
    let channel = mux.accept_channel(req.channel_id);
    if mux
        .send_frame(Frame::empty(FrameType::OpenOk, req.channel_id))
        .await
        .is_err()
    {
        mux.close_channel(req.channel_id);
        return true;
    }
    serve(mux, channel).await;
    true
}

/// Serve one bandwidth-diagnostic stream: read the mode byte, run echo/sink/source, close the channel when done.
async fn serve(mux: &Arc<MuxSession>, mut channel: MuxChannel) {
    let mode = match tokio::time::timeout(MODE_READ_TIMEOUT, channel.read_u8()).await {
        Ok(Ok(m)) => m,
        // read timeout / peer disconnected: close silently
        _ => {
            mux.close_channel(channel.channel_id);
            return;
        }
    };
    match mode {
        MODE_ECHO => serve_echo(&mut channel).await,
        MODE_SINK => serve_sink(&mut channel).await,
        MODE_SOURCE => serve_source(&mut channel).await,
        // unknown mode: close silently
        _ => {}
    }
    mux.close_channel(channel.channel_id);
}

/// echo: echo back verbatim until the peer half-closes/disconnects.
async fn serve_echo(channel: &mut MuxChannel) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match channel.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if channel.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// sink: read, discard and count; after peer half-close (EOF) reply an 8-byte BE total count as receive ack.
async fn serve_sink(channel: &mut MuxChannel) {
    let mut total: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match channel.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n as u64,
        }
    }
    let _ = channel.write_all(&total.to_be_bytes()).await;
}

/// source: read an 8-byte BE requested byte count (capped at MAX_SOURCE_BYTES), then stream that many bytes.
async fn serve_source(channel: &mut MuxChannel) {
    let Ok(count) = channel.read_u64().await else {
        return;
    };
    let mut remaining = count.min(MAX_SOURCE_BYTES);
    let chunk = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let n = chunk.len().min(remaining as usize);
        if channel.write_all(&chunk[..n]).await.is_err() {
            return;
        }
        remaining -= n as u64;
    }
}

// ==================== initiator side (measure the peer over the tunnel) ====================

/// RTT stats (millis).
#[derive(Debug, Clone, Serialize)]
pub struct RttStats {
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
}

/// Per-direction throughput stats (bytes / ms / Mbps).
#[derive(Debug, Clone, Serialize)]
pub struct TransferStats {
    pub bytes: u64,
    pub ms: u64,
    pub mbps: f64,
}

impl TransferStats {
    fn new(bytes: u64, elapsed: Duration) -> Self {
        // loopback can be so fast that elapsed is under 1ms; floor at 1ms to avoid division by zero
        let ms = (elapsed.as_millis() as u64).max(1);
        let mbps = round2(bytes as f64 * 8.0 / (ms as f64 / 1000.0) / 1_000_000.0);
        Self { bytes, ms, mbps }
    }
}

/// Bandwidth test summary (RTT + uplink + downlink).
#[derive(Debug, Clone, Serialize)]
pub struct BandwidthSample {
    pub rtt: RttStats,
    pub up: TransferStats,
    pub down: TransferStats,
}

/// Open a bandwidth-diagnostic stream to the peer (target = reserved address).
pub async fn open_stream(mux: &MuxSession) -> Result<MuxChannel> {
    let payload = serde_json::to_vec(&OpenChannel::new(MAGIC_HOST, 0))
        .map_err(|e| Error::Protocol(e.to_string()))?;
    mux.open_channel(Bytes::from(payload)).await
}

/// Full bandwidth test: RTT (`rtt_count` x 64B echo) -> uplink (sink) -> downlink (source).
pub async fn measure(
    mux: &MuxSession,
    rtt_count: u32,
    transfer_bytes: u64,
) -> Result<BandwidthSample> {
    let rtt = measure_rtt(mux, rtt_count).await?;
    let up = measure_upload(mux, transfer_bytes).await?;
    let down = measure_download(mux, transfer_bytes).await?;
    Ok(BandwidthSample { rtt, up, down })
}

/// RTT: `count` 64B echo round trips on one channel, outputs min/avg/max (millis).
pub async fn measure_rtt(mux: &MuxSession, count: u32) -> Result<RttStats> {
    if count == 0 {
        return Err(Error::Protocol("rtt count must be >= 1".into()));
    }
    let mut ch = open_stream(mux).await?;
    ch.write_u8(MODE_ECHO).await?;
    let payload = [0u8; 64];
    let mut buf = [0u8; 64];
    let mut samples = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let t = Instant::now();
        ch.write_all(&payload).await?;
        let _ = ch.read_exact(&mut buf).await?;
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = samples.iter().cloned().fold(0.0f64, f64::max);
    let avg = samples.iter().sum::<f64>() / samples.len() as f64;
    Ok(RttStats {
        min_ms: round3(min),
        avg_ms: round3(avg),
        max_ms: round3(max),
    })
}

/// Uplink: send `bytes` bytes in sink mode, half-close then wait for the peer's count ack (timed until the ack arrives).
pub async fn measure_upload(mux: &MuxSession, bytes: u64) -> Result<TransferStats> {
    let mut ch = open_stream(mux).await?;
    ch.write_u8(MODE_SINK).await?;
    let chunk = vec![0u8; 64 * 1024];
    let start = Instant::now();
    let mut remaining = bytes;
    while remaining > 0 {
        let n = chunk.len().min(remaining as usize);
        ch.write_all(&chunk[..n]).await?;
        remaining -= n as u64;
    }
    // DataFin signals end of send; wait for the peer's 8-byte BE count ack confirming all bytes arrived
    ch.shutdown().await?;
    let acked = ch.read_u64().await?;
    let elapsed = start.elapsed();
    if acked != bytes {
        return Err(Error::Protocol(format!(
            "sink ack mismatch: peer received {acked}/{bytes} bytes"
        )));
    }
    Ok(TransferStats::new(acked, elapsed))
}

/// Downlink: request `bytes` bytes in source mode, read until filled.
pub async fn measure_download(mux: &MuxSession, bytes: u64) -> Result<TransferStats> {
    let mut ch = open_stream(mux).await?;
    ch.write_u8(MODE_SOURCE).await?;
    ch.write_u64(bytes).await?;
    let start = Instant::now();
    let mut got: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    while got < bytes {
        let n = ch.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        got += n as u64;
    }
    let elapsed = start.elapsed();
    if got != bytes {
        return Err(Error::Protocol(format!(
            "source stream ended early: {got}/{bytes} bytes"
        )));
    }
    Ok(TransferStats::new(got, elapsed))
}

/// Round to 2 decimals (Mbps).
fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Round to 3 decimals (millis).
fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}
