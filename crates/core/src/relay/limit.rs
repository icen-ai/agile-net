//! Session-level bandwidth limiting (token bucket)
//!
//! ## Design
//!
//! - **One bucket shared by reads and writes**: the product semantic is "this session's
//!   bandwidth cap", direction-agnostic — paid quota is billed on total link volume.
//!   The `MuxSession` write task (egress) and read task (ingress) share a single
//!   `Arc<TokenBucket>`; both directions draw from the same allowance.
//! - **ingress also acquires = backpressure**: the read task takes tokens before
//!   dispatching Data/DataFin to channels; when tokens run out it suspends and stops
//!   reading from the socket, so once the TCP receive window drains the peer sender
//!   naturally slows down. No protocol fields needed; old peers fully compatible.
//! - **Orthogonal to flow_control credit**: per-channel window flow control
//!   (credit/WindowUpdate) keeps "the peer's app buffer from overflowing" (end-to-end,
//!   per channel); the token bucket enforces "this session's paid quota on this end"
//!   (per session, both directions merged). Both can be active at once, mutually unaware.
//! - **Capped wait, then pass**: a single acquire sleeps at most [`MAX_ACQUIRE_WAIT`].
//!   Rate limiting is a quota mechanism, not a correctness one: under a pathological
//!   config (rate so low one frame would wait minutes) it is better to pass one frame
//!   than to park the read task forever, blocking Ping/Pong heartbeats and stalling
//!   session teardown. The cap only truncates the sleep; the time debt is still booked
//!   in full (see below), later frames keep queueing, and over-issuance stays bounded
//!   to one frame per 5s.
//!
//! ## Anti-thundering-herd (time-debt reservation)
//!
//! When tokens run short there is no "first woken, first served": the deficit is
//! converted into a wait duration and **reserved** on the books — `last` is advanced
//! into the future and this acquire sleeps until the instant `last` points to.
//! Concurrent acquires afterwards compute their deficit and deadline from the advanced
//! `last`, so they queue behind the previous one automatically: N contenders sleep 1x,
//! 2x, 3x... of the unit duration, and the aggregate issue rate never exceeds `rate`.
//! All waiting sleeps happen outside the lock; the `Mutex` only guards instantaneous
//! reads/writes of `{tokens, last}` and no other future is awaited while held.

use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Max wait for a single acquire; passing anyway on timeout (see "capped wait" in the module docs).
const MAX_ACQUIRE_WAIT: Duration = Duration::from_secs(5);

/// In-bucket state (touched only briefly under the lock).
struct BucketState {
    /// Currently available tokens (bytes), capped at burst
    tokens: f64,
    /// Last refill instant; advanced into the future while time debt is reserved
    last: Instant,
}

/// Token bucket rate limiter: refills tokens at a constant `rate_bps` (bytes/sec), burst cap `burst` (bytes).
///
/// Clone semantics: not Clone itself; share across tasks via `Arc<TokenBucket>`.
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    state: Mutex<BucketState>,
}

impl TokenBucket {
    /// Create a full bucket (the whole burst is available immediately).
    ///
    /// `rate_bps` of 0 falls back to 1 byte/sec (avoids division by zero; a config error, effectively a near-full stop).
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

    /// Deduct `n` bytes of allowance; on shortfall, suspend for deficit/rate (sleeps outside the lock).
    ///
    /// `n` may exceed burst (an oversized frame waits the full deficit's worth of time).
    /// Each wait is capped at [`MAX_ACQUIRE_WAIT`]; on timeout the frame passes but the time debt is still booked in full.
    pub async fn acquire(&self, n: u64) {
        if n == 0 {
            return;
        }
        let wait = {
            let mut g = self.state.lock().await;
            let now = Instant::now();
            // last may point into the future due to prior reservations: refill only once now passes last
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
            // time-debt reservation: convert the deficit to a duration and advance last;
            // this acquire sleeps until the instant last points to. Later concurrent
            // acquires queue behind the debt — naturally serialized, no over-issue
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

    /// High rate + ample burst: passes immediately, virtual clock does not advance
    #[tokio::test(start_paused = true)]
    async fn high_rate_immediate() {
        let b = TokenBucket::new(10_000_000, 1_000_000);
        let t0 = Instant::now();
        b.acquire(65536).await;
        assert_eq!(t0.elapsed(), Duration::ZERO);
    }

    /// Low rate: once the burst is drained, throttle at deficit/rate
    #[tokio::test(start_paused = true)]
    async fn low_rate_throttled() {
        let b = TokenBucket::new(100_000, 10_000);
        b.acquire(10_000).await; // drain the burst, no wait
        let t0 = Instant::now();
        b.acquire(20_000).await; // deficit 20_000 -> wait 200ms
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

    /// The burst allowance is available all at once (even at a very low rate)
    #[tokio::test(start_paused = true)]
    async fn burst_available_at_once() {
        let b = TokenBucket::new(1_000, 64 * 1024);
        let t0 = Instant::now();
        b.acquire(64 * 1024).await;
        assert_eq!(t0.elapsed(), Duration::ZERO);
    }

    /// Concurrent acquires: time-debt reservation serializes contenders; aggregate issue rate stays within limit
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
        // the 1st acquire eats the burst and returns at once; the k-th (k>=2) finishes at >= (k-1) x 10_000B / 10_000Bps
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

    /// Capped wait: at an extremely low rate a single wait is truncated to MAX_ACQUIRE_WAIT, then passes
    #[tokio::test(start_paused = true)]
    async fn wait_capped_then_pass() {
        // deficit 1_000_000B / 1Bps ≈ 11.6 days -> truncated to 5s and passed
        let b = TokenBucket::new(1, 0);
        let t0 = Instant::now();
        b.acquire(1_000_000).await;
        assert_eq!(t0.elapsed(), MAX_ACQUIRE_WAIT);
    }
}
