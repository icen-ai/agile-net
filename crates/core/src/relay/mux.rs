//! Multiplexed session (MuxSession & MuxChannel)
//!
//! Multiplexes many logical channels over a single TLS connection.
//! `MuxChannel` implements `AsyncRead` and `AsyncWrite` and can be fed straight to `bridge` for bidirectional forwarding.
//!
//! ## Per-channel window flow control (protocol v2)
//!
//! - the writer of each channel holds a credit semaphore (initial 1 MiB), decremented per write
//! - the reader sends a `WindowUpdate` frame to replenish credit after consuming >= 512 KiB
//! - a high-volume channel that exhausts its credit suspends itself only, without blocking
//!   other channels on the session (no head-of-line blocking)
//! - session-level backpressure (mpsc capacity) remains as the last line of defense
//! - v1 peers degrade to no flow control automatically (version negotiation in connector/client_tunnel/listener)

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

/// Max concurrent channels per session; guards against resource exhaustion via Open floods.
pub const MAX_CHANNELS_PER_SESSION: usize = 1024;

/// Initial per-channel receive window (bytes).
pub const CHANNEL_WINDOW: u32 = 1024 * 1024;

/// Window replenish threshold: send a WindowUpdate once this much is consumed (half the window).
pub const WINDOW_UPDATE_THRESHOLD: u64 = (CHANNEL_WINDOW / 2) as u64;

/// Current time (UNIX epoch millis).
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Pending future waiting for session write-channel capacity (OwnedPermit is 'static, storable in the struct).
type PermitFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<mpsc::OwnedPermit<Frame>, mpsc::error::SendError<()>>,
            > + Send,
    >,
>;

/// Pending future waiting for flow-control credit (OwnedSemaphorePermit is 'static).
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

/// Multiplexed channel, implements `AsyncRead` + `AsyncWrite`
pub struct MuxChannel {
    pub channel_id: u32,
    tx_frames: mpsc::Sender<Frame>,
    rx_data: mpsc::Receiver<Bytes>,
    read_buf: Option<Bytes>,
    /// Cached capacity-reservation future while suspended on backpressure
    pending_permit: Option<PermitFuture>,
    /// Flow-control credit semaphore (writer side; None = v1 peer, no flow control)
    credit: Option<Arc<Semaphore>>,
    /// Pending flow-control credit future
    pending_credit: Option<CreditFuture>,
    /// Reader side: bytes delivered to the app since the last WindowUpdate
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

                    // flow control: on reaching the threshold, send WindowUpdate to replenish the peer's write credit
                    if self.credit.is_some() {
                        self.consumed_since_update += to_read as u64;
                        if self.consumed_since_update >= WINDOW_UPDATE_THRESHOLD {
                            let n = self.consumed_since_update.min(u32::MAX as u64) as u32;
                            self.consumed_since_update = 0;
                            let frame = Frame::new(
                                FrameType::WindowUpdate,
                                self.channel_id,
                                Bytes::copy_from_slice(&n.to_be_bytes()),
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
                    // peer closed the channel
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

        // 1. flow-control credit (v2): suspend when credit runs out, wait for the peer's WindowUpdate
        // chunk length gets a 0-2047B random perturbation: fixed 16KB chunks are a strong private-mux
        // fingerprint in the TLS record length distribution; chunk boundaries are transparent to
        // protocol semantics (the receiver reassembles the stream), backwards compatible
        let mut chunk_len =
            buf.len().min(DATA_CHUNK_SIZE - ((rand::random::<u64>() % 2048) as usize));
        if self.credit.is_some() {
            let credit = self.credit.clone().expect("checked");
            // fast path: try to acquire the amount directly
            if let Ok(permit) = credit.clone().try_acquire_many_owned(chunk_len as u32) {
                permit.forget(); // credit is replenished by the peer's WindowUpdate, never returned
            } else {
                // slow path: suspend waiting for credit
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

        // 2. chunk large data by DATA_CHUNK_SIZE (partial writes allowed)
        let frame = Frame::new(
            FrameType::Data,
            self.channel_id,
            Bytes::copy_from_slice(&buf[..chunk_len]),
        );
        chunk_len = frame.payload.len();

        // 3. session-level backpressure: suspend a reserve_owned future when no capacity (waker registered correctly)
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

/// Callback event for an incoming Open request
pub struct OpenRequest {
    pub channel_id: u32,
    pub payload: Bytes,
}

/// Inbound session-level event channels (control plane).
///
/// `open_tx` receives peer-initiated Open requests (data plane entry); `ctrl_tx` receives raw
/// Ctrl frame payloads (protocol v3 session control plane, JSON — decoded by the upper layer).
/// Both are optional: a pure client endpoint typically subscribes to neither, a relay/connector
/// subscribes to Open, and federation-aware endpoints additionally subscribe to Ctrl.
#[derive(Default)]
pub struct SessionEvents {
    pub open_tx: Option<mpsc::Sender<OpenRequest>>,
    pub ctrl_tx: Option<mpsc::Sender<Bytes>>,
}

impl SessionEvents {
    /// Subscribe to Open requests only.
    pub fn open(tx: mpsc::Sender<OpenRequest>) -> Self {
        Self {
            open_tx: Some(tx),
            ctrl_tx: None,
        }
    }

    /// Subscribe to both Open requests and Ctrl frames.
    pub fn open_and_ctrl(open: mpsc::Sender<OpenRequest>, ctrl: mpsc::Sender<Bytes>) -> Self {
        Self {
            open_tx: Some(open),
            ctrl_tx: Some(ctrl),
        }
    }
}

/// Channel registry entry
struct ChannelEntry {
    data_tx: mpsc::Sender<Bytes>,
    /// The channel writer's flow-control credit (replenished by the peer's WindowUpdate)
    credit: Option<Arc<Semaphore>>,
}

/// Mux session
pub struct MuxSession {
    tx_frames: mpsc::Sender<Frame>,
    channels: Arc<DashMap<u32, ChannelEntry>>,
    open_waiters: Arc<DashMap<u32, oneshot::Sender<Result<()>>>>,
    next_channel_id: AtomicU32,
    /// Time any frame was last received (epoch millis), for heartbeat timeout detection
    last_activity: Arc<AtomicU64>,
    /// Read-task abort handle (for shutdown)
    reader_abort: tokio::task::AbortHandle,
    /// Whether per-channel flow control is enabled (on when the peer speaks protocol v2)
    flow_control: bool,
    /// Data-plane traffic counters (Data frame payload bytes)
    bytes_out: Arc<AtomicU64>,
    bytes_in: Arc<AtomicU64>,
}

impl MuxSession {
    /// Start a mux session: split the stream and spawn the background read/write tasks.
    ///
    /// `events`: inbound event subscriptions (Open requests / v3 Ctrl frames), see `SessionEvents`.
    /// `flow_control`: enable per-channel window flow control (requires a protocol v2 peer).
    /// `limiter`: session-level bandwidth token bucket (shared by both directions, None = unlimited);
    /// pure data-plane throttling, no frame format change, fully compatible with old peers (see relay::limit module docs).
    pub fn start<S>(
        stream: S,
        starting_id: u32,
        events: SessionEvents,
        flow_control: bool,
        limiter: Option<Arc<TokenBucket>>,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx_frames, mut rx_frames) = mpsc::channel::<Frame>(1024);
        let SessionEvents { open_tx, ctrl_tx } = events;

        let channels: Arc<DashMap<u32, ChannelEntry>> = Arc::new(DashMap::new());
        let open_waiters: Arc<DashMap<u32, oneshot::Sender<Result<()>>>> = Arc::new(DashMap::new());
        let last_activity = Arc::new(AtomicU64::new(now_millis()));
        let bytes_out = Arc::new(AtomicU64::new(0));
        let bytes_in = Arc::new(AtomicU64::new(0));

        // spawn the background write task
        let bytes_out_task = bytes_out.clone();
        let limiter_write = limiter.clone();
        tokio::spawn(async move {
            while let Some(frame) = rx_frames.recv().await {
                if frame.frame_type == FrameType::Data {
                    bytes_out_task.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                    // session bandwidth limit (egress): on token shortfall suspend this
                    // write task; frames back up in the session mpsc, naturally
                    // backpressuring MuxChannel::poll_write upstream;
                    // acquire wait is capped at 5s, never blocks session close
                    if let Some(limiter) = &limiter_write {
                        limiter.acquire(frame.payload.len() as u64).await;
                    }
                }
                if frame.write_to(&mut writer).await.is_err() {
                    break;
                }
                // flush when the queue drains: rustls coalesces TLS records; without a
                // flush the tail records before the session goes idle may linger in the
                // rustls buffer until the next unrelated traffic carries them out
                if rx_frames.is_empty() && writer.flush().await.is_err() {
                    break;
                }
            }
        });

        // spawn the background read task (grab the abort handle first, then assemble the session)
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
                        // session bandwidth limit (ingress): take tokens before dispatch;
                        // on shortfall this read task suspends and stops reading from the
                        // socket, so once the TCP receive window drains the peer sender is
                        // naturally throttled. Shares one bucket with egress (both directions merged)
                        if let Some(limiter) = &limiter_read {
                            limiter.acquire(frame.payload.len() as u64).await;
                        }
                        if let Some(entry) = channels_task.get(&frame.channel_id) {
                            let _ = entry.data_tx.send(frame.payload).await;
                        }
                    }
                    FrameType::WindowUpdate => {
                        // peer consumed N bytes -> replenish our write credit
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
                    FrameType::Ctrl => {
                        // v3 session control plane: raw JSON payload handed to the upper layer
                        if let Some(ref tx) = ctrl_tx {
                            let _ = tx.send(frame.payload).await;
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

    /// Send a frame
    pub async fn send_frame(&self, frame: Frame) -> Result<()> {
        self.tx_frames
            .send(frame)
            .await
            .map_err(|_| Error::Io(io::Error::new(io::ErrorKind::BrokenPipe, "session closed")))
    }

    /// Whether per-channel flow control is enabled.
    pub fn flow_control_enabled(&self) -> bool {
        self.flow_control
    }

    /// Data-plane traffic counters (egress bytes, ingress bytes).
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

    /// Open a new channel and wait for the peer's OpenOk
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

        // wait for OpenOk / OpenFail
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

    /// Accept a peer-initiated channel
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

    /// Close a channel
    pub fn close_channel(&self, channel_id: u32) {
        self.channels.remove(&channel_id);
        let _ = self
            .tx_frames
            .try_send(Frame::empty(FrameType::Close, channel_id));
    }

    /// Force-close the session (control-plane kick): abort the read task and clear all channels.
    pub fn shutdown(&self) {
        self.reader_abort.abort();
        self.channels.clear();
        self.open_waiters.clear();
    }

    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Last time any frame was received from the peer (epoch millis).
    pub fn last_activity_millis(&self) -> u64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    /// Whether more than `timeout` has passed since the last peer frame (heartbeat timeout check).
    pub fn is_idle_beyond(&self, timeout: std::time::Duration) -> bool {
        let last = self.last_activity_millis();
        let now = now_millis();
        now.saturating_sub(last) > timeout.as_millis() as u64
    }
}
