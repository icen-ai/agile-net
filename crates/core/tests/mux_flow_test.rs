//! Per-channel window flow control tests (protocol v2)
//!
//! - large transfers crossing the window must not deadlock (WindowUpdate refills credit)
//! - a slow reader stalls only its own channel, no head-of-line blocking for others
//! - v1 fallback mode (no flow control) behavior unchanged

use agile_net_core::relay::mux::{CHANNEL_WINDOW, MuxSession, SessionEvents};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// TCP loopback mux pair (duplex has wakeup quirks with large buffers; real TCP is more reliable)
async fn mux_pair(flow_control: bool) -> (Arc<MuxSession>, Arc<MuxSession>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
    let (server, _) = listener.accept().await.unwrap();
    let client = connect.await.unwrap();
    let (a, _h1) = MuxSession::start(client, 1, SessionEvents::default(), flow_control, None);
    let (b, _h2) = MuxSession::start(server, 2, SessionEvents::default(), flow_control, None);
    (a, b)
}

/// Transferring 4 MiB (4x the window) must complete — proves WindowUpdate refills credit
#[tokio::test]
async fn large_transfer_crosses_window() {
    const TOTAL: usize = 4 * 1024 * 1024;
    let (a, b) = mux_pair(true).await;

    let b2 = b.clone();
    let acceptor = tokio::spawn(async move {
        let mut ch = b2.accept_channel(1);
        let mut received = Vec::with_capacity(TOTAL);
        while received.len() < TOTAL {
            let n = ch.read_buf(&mut received).await.unwrap();
            assert!(n > 0 || received.len() >= TOTAL, "提前 EOF");
            if n == 0 {
                break;
            }
        }
        received
    });

    let mut ch_a = a.accept_channel(1);
    ch_a.write_all(&vec![0xABu8; TOTAL]).await.unwrap();

    let received = tokio::time::timeout(std::time::Duration::from_secs(30), acceptor)
        .await
        .expect("4MiB 传输超时——流控死锁")
        .unwrap();
    assert_eq!(received.len(), TOTAL);
    assert!(received.iter().all(|&b| b == 0xAB));
}

/// Slow reader: channel 1 stalls once its window fills, channel 2 still flows (no head-of-line blocking)
#[tokio::test]
async fn slow_reader_does_not_block_other_channels() {
    let (a, b) = mux_pair(true).await;

    // channel 1: A writes, B never reads (backlog exceeds the window)
    let mut ch1_a = a.accept_channel(1);
    let _ch1_b = b.accept_channel(1);

    // channel 2: normal send/recv
    let mut ch2_a = a.accept_channel(3);
    let mut ch2_b = b.accept_channel(3);

    // A writes window+16KB on channel 1 (will stall at the window — expected)
    let writer = tokio::spawn(async move {
        let data = vec![0x01u8; CHANNEL_WINDOW as usize + 16384];
        let _ = ch1_a.write_all(&data).await;
    });

    // give the channel 1 write time to pile up to the window cap
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // channel 2 must stay clear
    ch2_a.write_all(b"independent").await.unwrap();
    let mut buf = [0u8; 11];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ch2_b.read_exact(&mut buf),
    )
    .await
    .expect("通道 2 被通道 1 的慢读者阻塞（队头阻塞！）")
    .unwrap();
    assert_eq!(&buf, b"independent");

    writer.abort();
}

/// v1 fallback (flow_control=false): large transfer proceeds as usual (no window limit)
#[tokio::test]
async fn v1_fallback_large_transfer() {
    const TOTAL: usize = 2 * 1024 * 1024;
    let (a, b) = mux_pair(false).await;

    let b2 = b.clone();
    let acceptor = tokio::spawn(async move {
        let mut ch = b2.accept_channel(1);
        let mut received = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        while received < TOTAL {
            let n = ch.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received += n;
        }
        received
    });

    let mut ch_a = a.accept_channel(1);
    ch_a.write_all(&vec![0xCDu8; TOTAL]).await.unwrap();

    let received = tokio::time::timeout(std::time::Duration::from_secs(30), acceptor)
        .await
        .expect("v1 大流量传输超时")
        .unwrap();
    assert_eq!(received, TOTAL);
}

/// flow control flag reported truthfully
#[tokio::test]
async fn flow_control_flag_reported() {
    let (a, _b) = mux_pair(true).await;
    assert!(a.flow_control_enabled());
    let (c, _d) = mux_pair(false).await;
    assert!(!c.flow_control_enabled());
}
