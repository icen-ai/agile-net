//! Per-channel 窗口流控测试（协议 v2）
//!
//! - 大流量跨窗口传输不死锁（WindowUpdate 补充额度）
//! - 慢读者仅自身通道挂起，不队头阻塞其他通道
//! - v1 降级模式（无流控）行为不变

use agile_net_core::relay::mux::{CHANNEL_WINDOW, MuxSession};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// TCP 回环 mux 对（duplex 在大缓冲场景下有唤醒怪癖，用真实 TCP 更可靠）
async fn mux_pair(flow_control: bool) -> (Arc<MuxSession>, Arc<MuxSession>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
    let (server, _) = listener.accept().await.unwrap();
    let client = connect.await.unwrap();
    let (a, _h1) = MuxSession::start(client, 1, None, flow_control);
    let (b, _h2) = MuxSession::start(server, 2, None, flow_control);
    (a, b)
}

/// 传输 4 MiB（4 倍于窗口）必须完成——证明 WindowUpdate 正常补充额度
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

/// 慢读者：通道 1 写满窗口后挂起，通道 2 仍可正常传输（无队头阻塞）
#[tokio::test]
async fn slow_reader_does_not_block_other_channels() {
    let (a, b) = mux_pair(true).await;

    // 通道 1：A 写、B 不读（积压超过窗口）
    let mut ch1_a = a.accept_channel(1);
    let _ch1_b = b.accept_channel(1);

    // 通道 2：正常收发
    let mut ch2_a = a.accept_channel(3);
    let mut ch2_b = b.accept_channel(3);

    // A 在通道 1 上写 窗口+16KB（将挂起在窗口处——预期行为）
    let writer = tokio::spawn(async move {
        let data = vec![0x01u8; CHANNEL_WINDOW as usize + 16384];
        let _ = ch1_a.write_all(&data).await;
    });

    // 给通道 1 的写操作一点时间堆积到窗口上限
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 通道 2 必须仍然畅通
    ch2_a.write_all(b"independent").await.unwrap();
    let mut buf = [0u8; 11];
    tokio::time::timeout(std::time::Duration::from_secs(5), ch2_b.read_exact(&mut buf))
        .await
        .expect("通道 2 被通道 1 的慢读者阻塞（队头阻塞！）")
        .unwrap();
    assert_eq!(&buf, b"independent");

    writer.abort();
}

/// v1 降级（flow_control=false）：大流量传输照常（无窗口限制）
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

/// 流控标志如实上报
#[tokio::test]
async fn flow_control_flag_reported() {
    let (a, _b) = mux_pair(true).await;
    assert!(a.flow_control_enabled());
    let (c, _d) = mux_pair(false).await;
    assert!(!c.flow_control_enabled());
}
