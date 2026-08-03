//! 会话级带宽限速（TokenBucket）端到端测试（mux 层）
//!
//! - egress：发送方挂限速桶 → 接收方收满耗时被节流
//! - ingress：接收方挂限速桶 → 读任务挂起形成 TCP 背压，收满耗时同样被节流
//! - 不限速对照组：同量数据快速完成
//!
//! 计时口径：limiter 64 KiB/s、burst 64 KiB，传 256 KiB。
//! 理论最短耗时 = (256 KiB - 64 KiB burst) / 64 KiB/s = 3.0s，
//! 断言取下界 2.8s（容忍 CI 调度抖动），上界 15s 防卡死。

use agile_net_core::relay::limit::TokenBucket;
use agile_net_core::relay::mux::MuxSession;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RATE: u64 = 64 * 1024; // 64 KiB/s
const TOTAL: usize = 256 * 1024; // 256 KiB
const MIN_ELAPSED: Duration = Duration::from_millis(2800);
const MAX_ELAPSED: Duration = Duration::from_secs(15);

/// TCP 回环 mux 对，各自可独立挂限速桶
async fn mux_pair(
    limiter_a: Option<Arc<TokenBucket>>,
    limiter_b: Option<Arc<TokenBucket>>,
) -> (Arc<MuxSession>, Arc<MuxSession>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
    let (server, _) = listener.accept().await.unwrap();
    let client = connect.await.unwrap();
    let (a, _h1) = MuxSession::start(client, 1, None, false, limiter_a);
    let (b, _h2) = MuxSession::start(server, 2, None, false, limiter_b);
    (a, b)
}

/// A → B 传 TOTAL 字节，返回 (收到耗时, 收到的数据)
async fn transfer(a: &Arc<MuxSession>, b: &Arc<MuxSession>) -> (Duration, Vec<u8>) {
    let b2 = b.clone();
    let receiver = tokio::spawn(async move {
        let mut ch = b2.accept_channel(1);
        let mut received = Vec::with_capacity(TOTAL);
        while received.len() < TOTAL {
            let n = ch.read_buf(&mut received).await.unwrap();
            assert!(n > 0, "提前 EOF: {}/{}", received.len(), TOTAL);
        }
        received
    });

    let mut ch_a = a.accept_channel(1);
    let data: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
    let t0 = Instant::now();
    ch_a.write_all(&data).await.unwrap();
    let received = tokio::time::timeout(MAX_ELAPSED, receiver)
        .await
        .expect("传输超时（限速卡死？）")
        .unwrap();
    (t0.elapsed(), received)
}

fn expected() -> Vec<u8> {
    (0..TOTAL).map(|i| (i % 251) as u8).collect()
}

/// egress 限速：发送方写任务节流，收满 256 KiB 耗时 >= 3s 量级且数据完整
#[tokio::test]
async fn egress_rate_limited() {
    let limiter = Arc::new(TokenBucket::new(RATE, RATE));
    let (a, b) = mux_pair(Some(limiter), None).await;

    let (elapsed, received) = transfer(&a, &b).await;
    assert!(
        elapsed >= MIN_ELAPSED,
        "egress 未生效: {elapsed:?} < {MIN_ELAPSED:?}"
    );
    assert_eq!(received, expected(), "数据不完整");
}

/// ingress 限速：接收方读任务分发前节流 → TCP 背压，收满耗时同样 >= 3s 量级
#[tokio::test]
async fn ingress_rate_limited() {
    let limiter = Arc::new(TokenBucket::new(RATE, RATE));
    let (a, b) = mux_pair(None, Some(limiter)).await;

    let (elapsed, received) = transfer(&a, &b).await;
    assert!(
        elapsed >= MIN_ELAPSED,
        "ingress 未生效: {elapsed:?} < {MIN_ELAPSED:?}"
    );
    assert_eq!(received, expected(), "数据不完整");
}

/// 不限速对照：同量数据远快于 3s 完成（证明上述耗时确实来自限速桶）
#[tokio::test]
async fn unlimited_baseline() {
    let (a, b) = mux_pair(None, None).await;

    let (elapsed, received) = transfer(&a, &b).await;
    assert!(
        elapsed < Duration::from_secs(2),
        "回环不限速传输异常缓慢: {elapsed:?}"
    );
    assert_eq!(received, expected(), "数据不完整");
}
