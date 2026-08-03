//! Shared small utilities, kept in one place to avoid verbatim copies.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// SHA-256 hex digest (token storage hash, kicking sessions by hash, etc.).
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    format!("{:x}", digest)
}

/// Minimal base64 encoder (core avoids a base64 dependency; single hand-rolled copy project-wide).
pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Login rate limiter: 5 attempts/min/IP by default, 15-minute lock after 5 consecutive failures.
///
/// Shared by the node admin API and the client web remote plane (previously two
/// verbatim copies); no new dependencies, built on a sharded dashmap.
#[derive(Clone)]
pub struct LoginRateLimiter {
    inner: Arc<DashMap<IpAddr, LoginAttempts>>,
    max_per_minute: u32,
    lock_threshold: u32,
    lock_duration: Duration,
}

struct LoginAttempts {
    window_start: Instant,
    attempts: u32,
    failures: u32,
    locked_until: Option<Instant>,
}

/// Why a login attempt was blocked.
pub enum LoginBlockReason {
    /// Rate limit hit (too many attempts per minute)
    RateLimited,
    /// Locked after consecutive failures (remaining lock time)
    Locked(Duration),
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            max_per_minute: 5,
            lock_threshold: 5,
            lock_duration: Duration::from_secs(15 * 60),
        }
    }

    /// Override default limits (maps to agile-net.toml [limits]).
    pub fn with_config(
        mut self,
        max_per_minute: u32,
        lock_threshold: u32,
        lock_minutes: u32,
    ) -> Self {
        self.max_per_minute = max_per_minute.max(1);
        self.lock_threshold = lock_threshold.max(1);
        self.lock_duration = Duration::from_secs(lock_minutes.max(1) as u64 * 60);
        self
    }

    /// Check whether a login attempt is allowed (rate limit + lock check).
    /// Lazy sweep included: above 1024 entries, failure records idle for 30 min are evicted (bounds memory growth).
    pub fn check(&self, ip: IpAddr) -> Result<(), LoginBlockReason> {
        if self.inner.len() > 1024 {
            self.inner
                .retain(|_, e| e.window_start.elapsed() < Duration::from_secs(30 * 60));
        }
        let mut entry = self.inner.entry(ip).or_insert(LoginAttempts {
            window_start: Instant::now(),
            attempts: 0,
            failures: 0,
            locked_until: None,
        });
        let e = entry.value_mut();

        if let Some(until) = e.locked_until {
            if until > Instant::now() {
                return Err(LoginBlockReason::Locked(until - Instant::now()));
            }
            e.locked_until = None;
            e.failures = 0;
        }

        if e.window_start.elapsed() > Duration::from_secs(60) {
            e.window_start = Instant::now();
            e.attempts = 0;
        }
        e.attempts += 1;
        if e.attempts > self.max_per_minute {
            return Err(LoginBlockReason::RateLimited);
        }
        Ok(())
    }

    /// Record a login failure (locks once consecutive failures reach the threshold).
    pub fn record_failure(&self, ip: IpAddr) {
        let mut entry = self.inner.entry(ip).or_insert(LoginAttempts {
            window_start: Instant::now(),
            attempts: 0,
            failures: 0,
            locked_until: None,
        });
        let e = entry.value_mut();
        e.failures += 1;
        if e.failures >= self.lock_threshold {
            e.locked_until = Some(Instant::now() + self.lock_duration);
        }
    }

    /// Login succeeded; reset the failure count.
    pub fn record_success(&self, ip: IpAddr) {
        self.inner.remove(&ip);
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc_vectors() {
        // RFC 4648 test vectors
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn limiter_rate_limit_and_recovery() {
        let lim = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..5 {
            assert!(lim.check(ip).is_ok());
        }
        assert!(matches!(lim.check(ip), Err(LoginBlockReason::RateLimited)));
        // another IP is unaffected
        let other: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(lim.check(other).is_ok());
    }

    #[test]
    fn limiter_lock_and_success_reset() {
        let lim = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..5 {
            lim.record_failure(ip);
        }
        assert!(matches!(lim.check(ip), Err(LoginBlockReason::Locked(_))));
        lim.record_success(ip);
        assert!(lim.check(ip).is_ok());
    }

    #[test]
    fn limiter_with_config_overrides() {
        let lim = LoginRateLimiter::new().with_config(2, 2, 1);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(lim.check(ip).is_ok());
        assert!(lim.check(ip).is_ok());
        assert!(matches!(lim.check(ip), Err(LoginBlockReason::RateLimited)));
        lim.record_failure(ip);
        lim.record_failure(ip);
        assert!(matches!(lim.check(ip), Err(LoginBlockReason::Locked(_))));
    }
}
