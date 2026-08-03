//! 多路复用会话 (MuxSession & MuxChannel)
//!
//! 在单条 TLS 连接上复用多个逻辑通道。
//! `MuxChannel` 实现了 `AsyncRead` 和 `AsyncWrite`，可以直接用 `bridge` 双向转发数据。
//!
//! ## Per-channel 窗口流控（协议 v2）
//!
//! - 每条通道的写方持有一个额度信号量（初始 1 MiB），写数据即扣减
//! - 读方每消费 ≥ 512 KiB 即回发 `WindowUpdate` 帧补充额度
//! - 大流量通道耗尽额度后仅自身挂起，不阻塞同会话其他通道（消除队头阻塞）
//! - 会话级背压（mpsc 容量）仍然保留，作为最后一道防线
//! - 对端为 v1 协议时自动降级为无流控（版本协商见 connector/client_tunnel/listener）

use crate::error::{Error, Result};
use crate::proto::frame::{DATA_CHUNK_SIZE, Frame, FrameType};
use crate::relay::limit::TokenBucket;

use bytes::{Buf, Bytes};
use dashmap::DashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Semaphore, mpsc, oneshot};

/// 单个会话允许的最大并发通道数，防止对端 Open 洪泛导致资源耗尽。
pub const MAX_CHANNELS_PER_SESSION: usize = 1024;

/// 每通道初始接收窗口（字节）。
pub const CHANNEL_WINDOW: u32 = 1024 * 1024;

/// 窗口补充阈值：消费满该值即回发 WindowUpdate（窗口的一半）。
pub const WINDOW_UPDATE_THRESHOLD: u64 = (CHANNEL_WINDOW / 2) as u64;

/// 当前时间（UNIX epoch 毫秒）。
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 等待会话写通道容量的挂起 Future（OwnedPermit 为 'static，可存入结构体）。
type PermitFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<mpsc::OwnedPermit<Frame>, mpsc::error::SendError<()>>,
            > + Send,
    >,
>;

/// 等待流控额度的挂起 Future（OwnedSemaphorePermit 为 'static）。
type CreditFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<
                    tokio::sync::OwnedSemaphorePermit,
                    tokio::sync::AcquireError,
                >,
            > + Send,
    >,
>;

/// 多路复用通道，实现 `AsyncRead` + `AsyncWrite`
pub struct MuxChannel {
    pub channel_id: u32,
    tx_frames: mpsc::Sender<Frame>,
    rx_data: mpsc::Receiver<Bytes>,
    read_buf: Option<Bytes>,
    /// 背压挂起时缓存的容量预留 Future
    pending_permit: Option<PermitFuture>,
    /// 流控额度信号量（写方；None = 对端为 v1 协议，无流控）
    credit: Option<Arc<Semaphore>>,
    /// 流控额度挂起 Future
    pending_credit: Option<CreditFuture>,
    /// 读方：自上次 WindowUpdate 以来交付给应用的字节数
    consumed_since_update: u64,
    closed: bool,
}

impl MuxChannel {
    pub fn new(
        channel_id: u32,
        tx_frames: mpsc::Sender<Frame>,
        rx_data: mpsc::Receiver<Bytes>,
        credit: Option<Arc<Semaphore>>,
    ) -> Self {
        Self {
            channel_id,
            tx_frames,
            rx_data,
            read_buf: None,
            pending_permit: None,
            credit,
            pending_credit: None,
            consumed_since_update: 0,
            closed: false,
        }
    }
}

impl AsyncRead for MuxChannel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref mut current) = self.read_buf {
                if current.has_remaining() {
                    let to_read = usize::min(buf.remaining(), current.remaining());
                    buf.put_slice(&current[..to_read]);
                    current.advance(to_read);
                    if !current.has_remaining() {
                        self.read_buf = None;
                    }

                    // 流控：消费达到阈值即回发 WindowUpdate 补充对端写额度
                    if self.credit.is_some() {
                        self.consumed_since_update += to_read as u64;
                        if self.consumed_since_update >= WINDOW_UPDATE_THRESHOLD {
                            let n = self.consumed_since_update.min(u32::MAX as u64) as u32;
                            self.consumed_since_update = 0;
                            let frame = Frame::new(
                                FrameType::WindowUpdate,
                                self.channel_id,
                                Bytes::from(n.to_be_bytes().to_vec()),
                            );
                            let _ = self.tx_frames.try_send(frame);
                        }
                    }
                    return Poll::Ready(Ok(()));
                } else {
                    self.read_buf = None;
                }
            }

            match self.rx_data.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => {
                    if bytes.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    self.read_buf = Some(bytes);
                }
                Poll::Ready(None) => {
                    // 对端关闭通道
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MuxChannel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            )));
        }

        // 1. 流控额度（v2）：额度不足时挂起，等待对端 WindowUpdate
        // 分片长度加 0~2047B 随机扰动：定长 16KB 分片在 TLS record 长度分布上是私有 mux 的强指纹；
        // 分片边界对协议语义透明（接收端按流重组），向后兼容
        let mut chunk_len =
            buf.len().min(DATA_CHUNK_SIZE - ((rand::random::<u64>() % 2048) as usize));
        if self.credit.is_some() {
            let credit = self.credit.clone().expect("checked");
            // 快速路径：直接尝试按量获取
            if let Ok(permit) = credit.clone().try_acquire_many_owned(chunk_len as u32) {
                permit.forget(); // 额度由对端 WindowUpdate 补充，不归还
            } else {
                // 慢速路径：挂起等待额度
                if self.pending_credit.is_none() {
                    self.pending_credit =
                        Some(Box::pin(credit.acquire_many_owned(chunk_len as u32)));
                }
                let fut = self
                    .pending_credit
                    .as_mut()
                    .expect("credit future just set");
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        self.pending_credit = None;
                        permit.forget();
                    }
                    Poll::Ready(Err(_)) => {
                        self.pending_credit = None;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "flow credit closed",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        // 2. 大数据按 DATA_CHUNK_SIZE 分片（允许部分写）
        let frame = Frame::new(
            FrameType::Data,
            self.channel_id,
            Bytes::copy_from_slice(&buf[..chunk_len]),
        );
        chunk_len = frame.payload.len();

        // 3. 会话级背压：无可用容量时挂起 reserve_owned Future（waker 正确注册）
        if self.pending_permit.is_none() {
            self.pending_permit = Some(Box::pin(self.tx_frames.clone().reserve_owned()));
        }

        let permit_fut = self
            .pending_permit
            .as_mut()
            .expect("permit future just set");
        match permit_fut.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                self.pending_permit = None;
                permit.send(frame);
                Poll::Ready(Ok(chunk_len))
            }
            Poll::Ready(Err(_)) => {
                self.pending_permit = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "session write closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            let frame = Frame::empty(FrameType::DataFin, self.channel_id);
            let _ = self.tx_frames.try_send(frame);
        }
        Poll::Ready(Ok(()))
    }
}

/// 收到 Open 请求的回调事件
pub struct OpenRequest {
    pub channel_id: u32,
    pub payload: Bytes,
}

/// 通道注册项
struct ChannelEntry {
    data_tx: mpsc::Sender<Bytes>,
    /// 该通道写方的流控额度（对端 WindowUpdate 补充至此）
    credit: Option<Arc<Semaphore>>,
}

/// Mux 会话
pub struct MuxSession {
    tx_frames: mpsc::Sender<Frame>,
    channels: Arc<DashMap<u32, ChannelEntry>>,
    open_waiters: Arc<DashMap<u32, oneshot::Sender<Result<()>>>>,
    next_channel_id: AtomicU32,
    /// 最后一次收到任何帧的时间（epoch 毫秒），用于心跳超时检测
    last_activity: Arc<AtomicU64>,
    /// 读任务中止句柄（shutdown 用）
    reader_abort: tokio::task::AbortHandle,
    /// 是否启用 per-channel 流控（对端为协议 v2 时启用）
    flow_control: bool,
    /// 数据面流量计数（Data 帧 payload 字节）
    bytes_out: Arc<AtomicU64>,
    bytes_in: Arc<AtomicU64>,
}

impl MuxSession {
    /// 启动一个 Mux 会话，拆分流并启动后台读写任务。
    ///
    /// `flow_control`：是否启用 per-channel 窗口流控（要求对端为协议 v2）。
    /// `limiter`：会话级带宽限速桶（读写双方向共用，None = 不限速）；
    /// 纯数据面节流，不改帧格式，旧端完全兼容（设计见 relay::limit 模块头）。
    pub fn start<S>(
        stream: S,
        starting_id: u32,
        open_tx: Option<mpsc::Sender<OpenRequest>>,
        flow_control: bool,
        limiter: Option<Arc<TokenBucket>>,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx_frames, mut rx_frames) = mpsc::channel::<Frame>(1024);

        let channels: Arc<DashMap<u32, ChannelEntry>> = Arc::new(DashMap::new());
        let open_waiters: Arc<DashMap<u32, oneshot::Sender<Result<()>>>> = Arc::new(DashMap::new());
        let last_activity = Arc::new(AtomicU64::new(now_millis()));
        let bytes_out = Arc::new(AtomicU64::new(0));
        let bytes_in = Arc::new(AtomicU64::new(0));

        // 启动后台写任务
        let bytes_out_task = bytes_out.clone();
        let limiter_write = limiter.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx_frames.recv().await {
                if frame.frame_type == FrameType::Data {
                    bytes_out_task.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                    // 会话带宽限速（egress）：令牌不足时挂起本写任务，帧缓存在
                    // 会话 mpsc 中，自然向上游 MuxChannel::poll_write 施加背压；
                    // acquire 等待封顶 5s，不会阻止 session 关闭
                    if let Some(limiter) = &limiter_write {
                        limiter.acquire(frame.payload.len() as u64).await;
                    }
                }
                if frame.write_to(&mut writer).await.is_err() {
                    break;
                }
                // 队列排空时 flush：rustls 会合并 TLS 记录，不 flush 则会话静默前的
                // 尾部记录可能滞留在 rustls 缓冲区，要等下次无关流量才被带出去
                if rx_frames.is_empty() && writer.flush().await.is_err() {
                    break;
                }
            }
        });

        // 启动后台读任务（先拿中止句柄，再组装 session）
        let channels_task = channels.clone();
        let open_waiters_task = open_waiters.clone();
        let last_activity_task = last_activity.clone();
        let tx_frames_task = tx_frames.clone();
        let bytes_in_task = bytes_in.clone();
        let limiter_read = limiter;

        let reader_handle = tokio::spawn(async move {
            while let Ok(frame) = Frame::read_from(&mut reader).await {
                last_activity_task.store(now_millis(), Ordering::Relaxed);
                match frame.frame_type {
                    FrameType::Data | FrameType::DataFin => {
                        if frame.frame_type == FrameType::Data {
                            bytes_in_task.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                        }
                        // 会话带宽限速（ingress）：分发前扣令牌；令牌不足时本读任务
                        // 挂起、不再从 socket 读取，TCP 接收窗口耗尽后自然回压对端
                        // 发送方。与 egress 共用同一桶（双方向合并限额）
                        if let Some(limiter) = &limiter_read {
                            limiter.acquire(frame.payload.len() as u64).await;
                        }
                        if let Some(entry) = channels_task.get(&frame.channel_id) {
                            let _ = entry.data_tx.send(frame.payload).await;
                        }
                    }
                    FrameType::WindowUpdate => {
                        // 对端已消费 N 字节 → 补充本端写额度
                        if frame.payload.len() == 4 {
                            let n = u32::from_be_bytes([
                                frame.payload[0],
                                frame.payload[1],
                                frame.payload[2],
                                frame.payload[3],
                            ]);
                            if let Some(entry) = channels_task.get(&frame.channel_id)
                                && let Some(credit) = &entry.credit
                            {
                                credit.add_permits(n as usize);
                            }
                        }
                    }
                    FrameType::OpenOk => {
                        if let Some((_, waiter)) = open_waiters_task.remove(&frame.channel_id) {
                            let _ = waiter.send(Ok(()));
                        }
                    }
                    FrameType::OpenFail => {
                        if let Some((_, waiter)) = open_waiters_task.remove(&frame.channel_id) {
                            let _ = waiter.send(Err(Error::Protocol("open channel failed".into())));
                        }
                    }
                    FrameType::Open => {
                        if let Some(ref tx) = open_tx {
                            let _ = tx
                                .send(OpenRequest {
                                    channel_id: frame.channel_id,
                                    payload: frame.payload,
                                })
                                .await;
                        }
                    }
                    FrameType::Ping => {
                        let _ = tx_frames_task.send(Frame::empty(FrameType::Pong, 0)).await;
                    }
                    FrameType::Close => {
                        channels_task.remove(&frame.channel_id);
                    }
                    _ => {}
                }
            }
        });
        let reader_abort = reader_handle.abort_handle();

        let session = Arc::new(Self {
            tx_frames,
            channels,
            open_waiters,
            next_channel_id: AtomicU32::new(starting_id),
            last_activity,
            reader_abort,
            flow_control,
            bytes_out,
            bytes_in,
        });

        (session, reader_handle)
    }

    /// 发送帧
    pub async fn send_frame(&self, frame: Frame) -> Result<()> {
        self.tx_frames
            .send(frame)
            .await
            .map_err(|_| Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, "session closed")))
    }

    /// 是否启用 per-channel 流控。
    pub fn flow_control_enabled(&self) -> bool {
        self.flow_control
    }

    /// 数据面流量计数（出向字节, 入向字节）。
    pub fn traffic(&self) -> (u64, u64) {
        (
            self.bytes_out.load(Ordering::Relaxed),
            self.bytes_in.load(Ordering::Relaxed),
        )
    }

    fn new_credit(&self) -> Option<Arc<Semaphore>> {
        if self.flow_control {
            Some(Arc::new(Semaphore::new(CHANNEL_WINDOW as usize)))
        } else {
            None
        }
    }

    /// 打开新通道并等待对端 OpenOk
    pub async fn open_channel(&self, payload: Bytes) -> Result<MuxChannel> {
        if self.channels.len() >= MAX_CHANNELS_PER_SESSION {
            return Err(Error::PoolExhausted);
        }
        let channel_id = self.next_channel_id.fetch_add(2, Ordering::Relaxed);

        let credit = self.new_credit();
        let (tx_data, rx_data) = mpsc::channel(128);
        self.channels.insert(
            channel_id,
            ChannelEntry {
                data_tx: tx_data,
                credit: credit.clone(),
            },
        );

        let (waiter_tx, waiter_rx) = oneshot::channel();
        self.open_waiters.insert(channel_id, waiter_tx);

        self.send_frame(Frame::new(FrameType::Open, channel_id, payload))
            .await?;

        // 等待 OpenOk / OpenFail
        match tokio::time::timeout(std::time::Duration::from_secs(10), waiter_rx).await {
            Ok(Ok(Ok(()))) => Ok(MuxChannel::new(
                channel_id,
                self.tx_frames.clone(),
                rx_data,
                credit,
            )),
            Ok(Ok(Err(e))) => {
                self.channels.remove(&channel_id);
                Err(e)
            }
            _ => {
                self.channels.remove(&channel_id);
                self.open_waiters.remove(&channel_id);
                Err(Error::Timeout)
            }
        }
    }

    /// 接受对端发起的通道
    pub fn accept_channel(&self, channel_id: u32) -> MuxChannel {
        let credit = self.new_credit();
        let (tx_data, rx_data) = mpsc::channel(128);
        self.channels.insert(
            channel_id,
            ChannelEntry {
                data_tx: tx_data,
                credit: credit.clone(),
            },
        );
        MuxChannel::new(channel_id, self.tx_frames.clone(), rx_data, credit)
    }

    /// 关闭通道
    pub fn close_channel(&self, channel_id: u32) {
        self.channels.remove(&channel_id);
        let _ = self
            .tx_frames
            .try_send(Frame::empty(FrameType::Close, channel_id));
    }

    /// 强制关闭会话（管理面 kick）：中止读任务并清空全部通道。
    pub fn shutdown(&self) {
        self.reader_abort.abort();
        self.channels.clear();
        self.open_waiters.clear();
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// 最后一次收到对端任何帧的时间（epoch 毫秒）。
    pub fn last_activity_millis(&self) -> u64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    /// 距上次收到对端帧是否已超过 `timeout`（用于心跳超时判定）。
    pub fn is_idle_beyond(&self, timeout: std::time::Duration) -> bool {
        let last = self.last_activity_millis();
        let now = now_millis();
        now.saturating_sub(last) > timeout.as_millis() as u64
    }
}
