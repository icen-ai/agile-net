//! 会话级带宽限速（令牌桶）
//!
//! ## 设计
//!
//! - **读写共用一桶**：产品语义是「这条会话的带宽上限」，不区分上下行——付费配额
//!   按链路总量计费。`MuxSession` 的写任务（egress）与读任务（ingress）共享同一个
//!   `Arc<TokenBucket>`，双方向合并限额。
//! - **ingress 也 acquire = 背压**：读任务在把 Data/DataFin 分发给通道前取令牌，
//!   令牌不足时读任务挂起、不再从 socket 读取，TCP 接收窗口耗尽后对端发送方自然
//!   降速。无需任何协议字段，旧端完全兼容。
//! - **与 flow_control credit 正交**：per-channel 窗口流控（credit/WindowUpdate）
//!   管「对端应用缓冲不被撑爆」（端到端、按通道）；令牌桶管「本端给这条会话的
//!   付费配额」（按会话、双方向合并）。两者可同时生效，互不感知。
//! - **等待封顶放行**：单次 acquire 的 sleep 封顶 [`MAX_ACQUIRE_WAIT`]。限速是配额
//!   机制而非正确性机制：畸形配置（rate 极低、单帧需等数分钟）下宁可放行一帧，
//!   也不能让读任务永久挂起挡住 Ping/Pong 心跳、拖垮会话关闭。封顶只截断 sleep，
//!   时间债仍全额入账（见下），后续帧依旧排队，超发被限制在每 5s 一帧以内。
//!
//! ## 防惊群（时间债预订）
//!
//! 令牌不足时不按「先睡醒先抢」，而是把缺口折算成等待时长**预订**入账：推进
//! `last` 到未来，本笔睡到 `last` 所指向的时刻。随后并发的 acquire 基于推进后的
//! `last` 计算缺口与终点，自动排在前一笔之后，N 个并发者分别睡 1×、2×、3×… 的
//! 单位时长，总发放速率恒不超 `rate`。等待一律在锁外 sleep，`Mutex` 只保护
//! `{tokens, last}` 的瞬时读写，持锁期间不 await 其他future。

use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// 单次 acquire 的最长等待，超时放行（见模块头「等待封顶放行」）。
const MAX_ACQUIRE_WAIT: Duration = Duration::from_secs(5);

/// 桶内状态（仅持锁瞬时读写）。
struct BucketState {
    /// 当前可用令牌（字节），上限 burst
    tokens: f64,
    /// 上次补充令牌的时刻；存在未清偿时间债时被预订推进到未来
    last: Instant,
}

/// 令牌桶限速器：恒定速率 `rate_bps`（字节/秒）补充令牌，突发上限 `burst`（字节）。
///
/// 克隆语义：本身不实现 Clone，多任务共享用 `Arc<TokenBucket>`。
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    state: Mutex<BucketState>,
}

impl TokenBucket {
    /// 新建满令牌桶（初始即可用完全部 burst）。
    ///
    /// `rate_bps` 为 0 时按 1 字节/秒兜底（防除零；属于配置错误，等效近全停）。
    pub fn new(rate_bps: u64, burst: u64) -> Self {
        Self {
            rate: rate_bps.max(1) as f64,
            burst: burst as f64,
            state: Mutex::new(BucketState {
                tokens: burst as f64,
                last: Instant::now(),
            }),
        }
    }

    /// 扣除 `n` 字节额度；额度不足时按 缺口/速率 挂起等待（锁外 sleep）。
    ///
    /// `n` 可大于 burst（超大帧按全额缺口等待对应时长）。单次等待封顶
    /// [`MAX_ACQUIRE_WAIT`]，超时放行但时间债仍全额入账。
    pub async fn acquire(&self, n: u64) {
        if n == 0 {
            return;
        }
        let wait = {
            let mut g = self.state.lock().await;
            let now = Instant::now();
            // last 可能因前序预订而指向未来：仅当 now 越过 last 时才补充令牌
            if let Some(elapsed) = now.checked_duration_since(g.last) {
                g.tokens = (g.tokens + elapsed.as_secs_f64() * self.rate).min(self.burst);
                g.last = now;
            }
            if g.tokens >= n as f64 {
                g.tokens -= n as f64;
                return;
            }
            let deficit = n as f64 - g.tokens;
            g.tokens = 0.0;
            // 时间债预订：缺口折时长推进 last，本笔睡到 last 指向的终点；
            // 后续并发 acquire 在债务之后继续排队，自然串行、不超发
            g.last += Duration::from_secs_f64(deficit / self.rate);
            g.last.saturating_duration_since(now)
        };
        tokio::time::sleep(wait.min(MAX_ACQUIRE_WAIT)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 高速率 + 充足突发：立即通过，虚拟时钟不前进
    #[tokio::test(start_paused = true)]
    async fn high_rate_immediate() {
        let b = TokenBucket::new(10_000_000, 1_000_000);
        let t0 = Instant::now();
        b.acquire(65536).await;
        assert_eq!(t0.elapsed(), Duration::ZERO);
    }

    /// 低速率：突发耗尽后按 缺口/速率 节流
    #[tokio::test(start_paused = true)]
    async fn low_rate_throttled() {
        let b = TokenBucket::new(100_000, 10_000);
        b.acquire(10_000).await; // 吃光突发，不等待
        let t0 = Instant::now();
        b.acquire(20_000).await; // 缺口 20_000 → 等 200ms
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(200),
            "节流不足: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(250),
            "过度等待: {elapsed:?}"
        );
    }

    /// 突发额度一次性可用（哪怕速率很低）
    #[tokio::test(start_paused = true)]
    async fn burst_available_at_once() {
        let b = TokenBucket::new(1_000, 64 * 1024);
        let t0 = Instant::now();
        b.acquire(64 * 1024).await;
        assert_eq!(t0.elapsed(), Duration::ZERO);
    }

    /// 并发 acquire：时间债预订使并发者串行排队，总发放不超速率
    #[tokio::test(start_paused = true)]
    async fn concurrent_acquires_serialize_no_overissue() {
        let b = Arc::new(TokenBucket::new(10_000, 10_000));
        let t0 = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..5 {
            let b = b.clone();
            handles.push(tokio::spawn(async move {
                b.acquire(10_000).await;
                t0.elapsed()
            }));
        }
        let mut times = Vec::new();
        for h in handles {
            times.push(h.await.unwrap());
        }
        times.sort();
        // 第 1 笔吃突发立即返回；第 k 笔（k>=2）完成时刻 >= (k-1) × 10_000B / 10_000Bps
        assert_eq!(times[0], Duration::ZERO, "首笔应即时: {times:?}");
        for (i, t) in times.iter().enumerate().skip(1) {
            assert!(
                *t >= Duration::from_secs((i - 1) as u64),
                "第 {} 笔过早完成（超发）: {times:?}",
                i + 1
            );
        }
        assert_eq!(times.len(), 5);
    }

    /// 等待封顶：极低速率下单笔等待截断到 MAX_ACQUIRE_WAIT 后放行
    #[tokio::test(start_paused = true)]
    async fn wait_capped_then_pass() {
        // 缺口 1_000_000B / 1Bps ≈ 11.6 天 → 应截断为 5s 放行
        let b = TokenBucket::new(1, 0);
        let t0 = Instant::now();
        b.acquire(1_000_000).await;
        assert_eq!(t0.elapsed(), MAX_ACQUIRE_WAIT);
    }
}
