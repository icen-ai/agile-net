//! 多路复用会话 (MuxSession & MuxChannel)
//!
//! 在单条 TLS 连接上复用多个逻辑通道。
//! `MuxChannel` 实现了 `AsyncRead` 和 `AsyncWrite`，可以直接用 `bridge` 双向转发数据。

use crate::error::{Error, Result};
use crate::proto::frame::{DATA_CHUNK_SIZE, Frame, FrameType};

use bytes::{Buf, Bytes};
use dashmap::DashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

/// 单个会话允许的最大并发通道数，防止对端 Open 洪泛导致资源耗尽。
pub const MAX_CHANNELS_PER_SESSION: usize = 1024;

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
                Output = std::result::Result<
                    mpsc::OwnedPermit<Frame>,
                    mpsc::error::SendError<()>,
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
    closed: bool,
}

impl MuxChannel {
    pub fn new(
        channel_id: u32,
        tx_frames: mpsc::Sender<Frame>,
        rx_data: mpsc::Receiver<Bytes>,
    ) -> Self {
        Self {
            channel_id,
            tx_frames,
            rx_data,
            read_buf: None,
            pending_permit: None,
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

        // 大数据按 DATA_CHUNK_SIZE 分片，避免产生超大 Data 帧（允许部分写）
        let chunk_len = buf.len().min(DATA_CHUNK_SIZE);
        let frame = Frame::new(
            FrameType::Data,
            self.channel_id,
            Bytes::copy_from_slice(&buf[..chunk_len]),
        );

        // 背压：无可用容量时挂起 reserve_owned Future（waker 被正确注册），
        // 修复此前 try_send 失败后直接 Pending 导致的永久挂死问题。
        if self.pending_permit.is_none() {
            self.pending_permit = Some(Box::pin(self.tx_frames.clone().reserve_owned()));
        }

        let permit_fut = self.pending_permit.as_mut().expect("permit future just set");
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

/// Mux 会话
pub struct MuxSession {
    tx_frames: mpsc::Sender<Frame>,
    channels: Arc<DashMap<u32, mpsc::Sender<Bytes>>>,
    open_waiters: Arc<DashMap<u32, oneshot::Sender<Result<()>>>>,
    next_channel_id: AtomicU32,
    /// 最后一次收到任何帧的时间（epoch 毫秒），用于心跳超时检测
    last_activity: Arc<AtomicU64>,
    /// 读任务中止句柄（shutdown 用）
    reader_abort: tokio::task::AbortHandle,
}

impl MuxSession {
    /// 启动一个 Mux 会话，拆分流并启动后台读写任务。
    pub fn start<S>(
        stream: S,
        starting_id: u32,
        open_tx: Option<mpsc::Sender<OpenRequest>>,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx_frames, mut rx_frames) = mpsc::channel::<Frame>(1024);

        let channels: Arc<DashMap<u32, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());
        let open_waiters: Arc<DashMap<u32, oneshot::Sender<Result<()>>>> = Arc::new(DashMap::new());
        let last_activity = Arc::new(AtomicU64::new(now_millis()));

        // 启动后台写任务
        tokio::spawn(async move {
            while let Some(frame) = rx_frames.recv().await {
                if frame.write_to(&mut writer).await.is_err() {
                    break;
                }
            }
        });

        // 启动后台读任务（先拿中止句柄，再组装 session）
        let channels_task = channels.clone();
        let open_waiters_task = open_waiters.clone();
        let last_activity_task = last_activity.clone();
        let tx_frames_task = tx_frames.clone();

        let reader_handle = tokio::spawn(async move {
            while let Ok(frame) = Frame::read_from(&mut reader).await {
                last_activity_task.store(now_millis(), Ordering::Relaxed);
                match frame.frame_type {
                    FrameType::Data | FrameType::DataFin => {
                        if let Some(tx) = channels_task.get(&frame.channel_id) {
                            let _ = tx.send(frame.payload).await;
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
        });

        (session, reader_handle)
    }

    /// 强制关闭会话（管理面 kick）：中止读任务并清空全部通道。
    pub fn shutdown(&self) {
        self.reader_abort.abort();
        self.channels.clear();
        self.open_waiters.clear();
    }

    /// 发送帧
    pub async fn send_frame(&self, frame: Frame) -> Result<()> {
        self.tx_frames
            .send(frame)
            .await
            .map_err(|_| Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, "session closed")))
    }

    /// 打开新通道并等待对端 OpenOk
    pub async fn open_channel(&self, payload: Bytes) -> Result<MuxChannel> {
        if self.channels.len() >= MAX_CHANNELS_PER_SESSION {
            return Err(Error::PoolExhausted);
        }
        let channel_id = self.next_channel_id.fetch_add(2, Ordering::Relaxed);

        let (tx_data, rx_data) = mpsc::channel(128);
        self.channels.insert(channel_id, tx_data);

        let (waiter_tx, waiter_rx) = oneshot::channel();
        self.open_waiters.insert(channel_id, waiter_tx);

        self.send_frame(Frame::new(FrameType::Open, channel_id, payload))
            .await?;

        // 等待 OpenOk / OpenFail
        match tokio::time::timeout(std::time::Duration::from_secs(10), waiter_rx).await {
            Ok(Ok(Ok(()))) => Ok(MuxChannel::new(channel_id, self.tx_frames.clone(), rx_data)),
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
        let (tx_data, rx_data) = mpsc::channel(128);
        self.channels.insert(channel_id, tx_data);
        MuxChannel::new(channel_id, self.tx_frames.clone(), rx_data)
    }

    /// 关闭通道
    pub fn close_channel(&self, channel_id: u32) {
        self.channels.remove(&channel_id);
        let _ = self
            .tx_frames
            .try_send(Frame::empty(FrameType::Close, channel_id));
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
