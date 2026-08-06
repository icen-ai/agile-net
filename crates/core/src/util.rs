//! Shared small utilities, kept in one place to avoid verbatim copies.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

// ---------------------------------------------------------------------------
// Brand data directory layout (~/.anet/{svc,gui,root})
// ---------------------------------------------------------------------------

/// Brand directory name under `$HOME`. Short form `anet` — long display name
/// `AgileNet` is reserved for end-user-facing surfaces (productName, window
/// titles, installer metadata). Single source of truth for the project.
pub const BRAND_DIR: &str = ".anet";

/// Resolve `$HOME` (USERPROFILE on Windows, HOME elsewhere). Falls back to `.`
/// so tests and edge cases don't panic — same behavior as the prior local
/// copies in client/node/desktop, now unified here.
pub fn home_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Brand root: `~/.anet`. Hosts cross-tool shared files (`credentials.json`,
/// `cache/`, `session.json`) plus the `svc/` and `gui/` subdirectories.
pub fn brand_root() -> PathBuf {
    home_dir().join(BRAND_DIR)
}

/// Server process data directory: `~/.anet/svc`. Holds the PID file and the
/// default config path for `anet init`. The server's own SQLite/certs/logs
/// still follow whatever path the loaded config declares — only the PID file
/// and init defaults are bound here.
pub fn svc_data_dir() -> PathBuf {
    brand_root().join("svc")
}

/// GUI process data directory: `~/.anet/gui`. Holds GUI-only state
/// (settings/audit/web-auth/custom-rules), the embedded-node sandbox
/// (`embedded-node/`, isolated from a bare `anet-svc` run), the mihomo
/// sidecar (`mihomo/`), and sync state. The client library's
/// `credentials.json` and `cache/` are deliberately left at the brand root
/// so the CLI `anet client` subcommand shares them with the GUI.
pub fn gui_data_dir() -> PathBuf {
    brand_root().join("gui")
}

/// Default config filename for `anet init` and bare `anet start`. The path
/// prefix is `~/.anet/svc/`, but a bare filename is returned so callers can
/// resolve it against CWD or the brand root as appropriate.
pub const DEFAULT_CONFIG_FILENAME: &str = "agile-net.toml";

/// Default config path: `~/.anet/svc/agile-net.toml`. Used by `anet init` for
/// single-machine demo setups. Production deployments override with
/// `--config /etc/...` (or any absolute path) — `anet-svc start` then follows
/// the explicit path.
pub fn default_config_path() -> PathBuf {
    svc_data_dir().join(DEFAULT_CONFIG_FILENAME)
}

/// Resolve the default config for `anet-svc start` (no `--config` arg): prefer
/// `~/.anet/svc/agile-net.toml` (brand default), fall back to `./agile-net.toml`
/// in the CWD (config kept next to the binary). Returns the chosen path whether
/// or not it exists.
pub fn resolve_default_config() -> PathBuf {
    let brand = default_config_path();
    if brand.exists() {
        return brand;
    }
    PathBuf::from(DEFAULT_CONFIG_FILENAME)
}

/// SHA-256 hex digest (token storage hash, kicking sessions by hash, etc.).
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    format!("{:x}", digest)
}

/// Spawn a console program without ever flashing a console window (GUI context).
/// Windows GUI apps spawning console tools (netsh/reg/route/powershell/…) otherwise flash a console
/// per call and can hit 0xc0000142 (console subsystem init failure). CREATE_NO_WINDOW never allocates
/// one; captured stdout/stderr pipes are unaffected. Single source project-wide — every Command::new
/// for a console program goes through this.
pub fn silent_command(prog: &str) -> std::process::Command {
    #[allow(unused_mut)]
    let mut c = std::process::Command::new(prog);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
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

/// Minimal base64 decoder (standard alphabet, padding required; pairs with `base64_encode`
/// so core still avoids a base64 dependency). None on any invalid character or truncation.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let last = i == bytes.len() / 4 - 1;
        let pad = if last && chunk[3] == b'=' {
            if chunk[2] == b'=' { 2 } else { 1 }
        } else {
            0
        };
        // '=' may only appear as trailing padding in the last chunk
        for (j, &c) in chunk.iter().enumerate() {
            if c == b'=' && !(last && j >= 4 - pad) {
                return None;
            }
        }
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = if pad >= 2 { 0 } else { val(chunk[2])? };
        let v3 = if pad >= 1 { 0 } else { val(chunk[3])? };
        let n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
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
