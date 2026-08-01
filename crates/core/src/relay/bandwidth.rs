//! 协议级带宽诊断服务（echo / sink / source）
//!
//! 保留魔法地址 [`MAGIC_HOST`]：任一侧（RelayListener 的扇入对端会话、
//! RelayConnector 的扇出隧道）收到目标为该地址的 Open 请求时，在 ACL 检查
//! **之前** 拦截并本地应答——不走路由转发、不具备任何出网能力，因此对端收敛
//! （PeerAcl）的节点同样可测，且不构成 ACL 旁路。定位与心跳同级：协议内建的
//! 诊断面，永不被路由；带宽流属正常诊断流量，不落审计明细。
//!
//! 流首字节定模式：
//! - `e` echo：原样回显（测 RTT / 双向通路）
//! - `s` sink：读丢弃，对端半关后回 8 字节 BE 总计数确认（测上行）
//! - `g` source：随后 8 字节 BE 请求字节数，按数发流（测下行）

use crate::error::{Error, Result};
use crate::proto::frame::{Frame, FrameType};
use crate::proto::message::OpenChannel;
use crate::relay::mux::{MuxChannel, MuxSession, OpenRequest};

use bytes::Bytes;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 带宽诊断保留地址（永不被路由；大小写不敏感）。
pub const MAGIC_HOST: &str = "anet.bandwidth";

/// 模式字节：echo（原样回显）。
pub const MODE_ECHO: u8 = b'e';
/// 模式字节：sink（读丢弃，EOF 后回 8 字节 BE 总计数）。
pub const MODE_SINK: u8 = b's';
/// 模式字节：source（随后 8 字节 BE 请求字节数，按数发流）。
pub const MODE_SOURCE: u8 = b'g';

/// source 模式单次请求字节数上限（防异常请求耗尽资源）。
pub const MAX_SOURCE_BYTES: u64 = 1 << 30;

/// 模式字节读取超时（防对端开流后挂死服务任务）。
const MODE_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// 默认 RTT 探测次数（每次 64B echo 往返）。
pub const DEFAULT_RTT_COUNT: u32 = 10;
/// 默认单方向吞吐测试字节数（8 MiB）。
pub const DEFAULT_TRANSFER_BYTES: u64 = 8 * 1024 * 1024;

/// 目标地址是否命中带宽诊断保留地址。
pub fn is_magic_target(addr: &str) -> bool {
    addr.eq_ignore_ascii_case(MAGIC_HOST)
}

/// 拦截入口：目标为保留地址时本地应答并返回 true（调用方不再走 ACL/路由）。
///
/// 须在 ACL 检查之前调用（扇入 listener / 扇出 connector 两侧对称）：
/// echo/sink/source 均无路由能力，收敛节点同样可测，不构成 ACL 旁路。
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

/// 应答一条带宽诊断流：读模式字节后进入 echo/sink/source，结束关闭通道。
async fn serve(mux: &Arc<MuxSession>, mut channel: MuxChannel) {
    let mode = match tokio::time::timeout(MODE_READ_TIMEOUT, channel.read_u8()).await {
        Ok(Ok(m)) => m,
        // 读超时/对端断开：静默关闭
        _ => {
            mux.close_channel(channel.channel_id);
            return;
        }
    };
    match mode {
        MODE_ECHO => serve_echo(&mut channel).await,
        MODE_SINK => serve_sink(&mut channel).await,
        MODE_SOURCE => serve_source(&mut channel).await,
        // 未知模式：静默关闭
        _ => {}
    }
    mux.close_channel(channel.channel_id);
}

/// echo：原样回显直至对端半关/断开。
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

/// sink：读丢弃计数；对端半关（EOF）后回 8 字节 BE 总计数作接收确认。
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

/// source：读 8 字节 BE 请求字节数（封顶 MAX_SOURCE_BYTES），按数发流。
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

// ==================== 发起侧（经隧道测量对端） ====================

/// RTT 统计（毫秒）。
#[derive(Debug, Clone, Serialize)]
pub struct RttStats {
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
}

/// 单方向吞吐统计（bytes / ms / Mbps）。
#[derive(Debug, Clone, Serialize)]
pub struct TransferStats {
    pub bytes: u64,
    pub ms: u64,
    pub mbps: f64,
}

impl TransferStats {
    fn new(bytes: u64, elapsed: Duration) -> Self {
        // 回环极快时 elapsed 可能不足 1ms，保底 1ms 防除零
        let ms = (elapsed.as_millis() as u64).max(1);
        let mbps = round2(bytes as f64 * 8.0 / (ms as f64 / 1000.0) / 1_000_000.0);
        Self { bytes, ms, mbps }
    }
}

/// 带宽测试汇总（RTT + 上行 + 下行）。
#[derive(Debug, Clone, Serialize)]
pub struct BandwidthSample {
    pub rtt: RttStats,
    pub up: TransferStats,
    pub down: TransferStats,
}

/// 向对端打开一条带宽诊断流（目标 = 保留地址）。
pub async fn open_stream(mux: &MuxSession) -> Result<MuxChannel> {
    let payload = serde_json::to_vec(&OpenChannel {
        target_addr: MAGIC_HOST.to_string(),
        target_port: 0,
    })
    .map_err(|e| Error::Protocol(e.to_string()))?;
    mux.open_channel(Bytes::from(payload)).await
}

/// 完整带宽测试：RTT（`rtt_count`×64B echo）→ 上行（sink）→ 下行（source）。
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

/// RTT：单通道 `count` 次 64B echo 往返，输出 min/avg/max（毫秒）。
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

/// 上行：sink 模式发 `bytes` 字节，半关后等对端计数确认（计时至确认到达）。
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
    // DataFin 告知发送完毕，等对端回 8 字节 BE 计数确认全部字节已到达
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

/// 下行：source 模式请求 `bytes` 字节，读满为止。
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

/// 保留 2 位小数（Mbps）。
fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// 保留 3 位小数（毫秒）。
fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}
