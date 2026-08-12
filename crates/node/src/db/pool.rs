//! Split from db/mod.rs: connection pool and shared helpers (pure move, no logic change)

use agile_net_core::error::{Error, Result};
use r2d2_sqlite::SqliteConnectionManager;
use std::path::Path;

#[derive(Clone)]
pub struct Database {
    pool: r2d2::Pool<SqliteConnectionManager>,
}

impl Database {
    /// Open the database and run migrations (WAL mode + read pool; writes serialized via busy_timeout).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let manager = SqliteConnectionManager::file(path.as_ref()).with_init(|conn| {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            conn.pragma_update(None, "busy_timeout", 5000)?;
            Ok(())
        });
        let pool = r2d2::Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| Error::Other(e.to_string()))?;
        let db = Self { pool };
        db.migrate()?;
        Ok(db)
    }

    /// In-memory database (test-only; single connection to share state)
    pub fn in_memory() -> Result<Self> {
        let manager = SqliteConnectionManager::memory().with_init(|conn| {
            conn.pragma_update(None, "foreign_keys", "ON")?;
            Ok(())
        });
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(|e| Error::Other(e.to_string()))?;
        let db = Self { pool };
        db.migrate()?;
        Ok(db)
    }

    /// Fallible connection borrow. Data-plane auth paths use this so a poisoned/exhausted pool
    /// fails closed (the validator rejects as unknown token) instead of panicking the task.
    pub(crate) fn try_conn(&self) -> Result<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.pool
            .get()
            .map_err(|e| Error::Other(format!("db pool unavailable: {e}")))
    }

    pub(crate) fn conn(&self) -> r2d2::PooledConnection<SqliteConnectionManager> {
        self.try_conn().expect("db pool exhausted")
    }
}

pub(crate) fn db_err(e: rusqlite::Error) -> Error {
    Error::Other(e.to_string())
}

pub(crate) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Normalize a user-supplied expiry to the canonical UTC `...Z` second-precision form
/// (token lifecycle, docs/todo/e2e.md §8). Accepts RFC 3339 (any offset) and the browser
/// `datetime-local` shape `YYYY-MM-DDTHH:MM` (interpreted as UTC). Empty input is rejected
/// by the caller before this (None = never expires).
pub fn normalize_expiry(input: &str) -> std::result::Result<String, String> {
    let s = input.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }
    for fmt in ["%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            let dt = naive.and_utc();
            return Ok(dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        }
    }
    Err(format!("无法解析的过期时间: {s}（支持 RFC3339 或 YYYY-MM-DDTHH:MM）"))
}

/// Whether an expiry timestamp (canonical form) is still in the future. None = never expires.
/// Unparseable stored values fail closed (treated as expired).
pub fn expiry_active(expires_at: Option<&str>) -> bool {
    let Some(s) = expires_at else { return true };
    match chrono::DateTime::parse_from_rfc3339(s.trim()) {
        Ok(dt) => dt.with_timezone(&chrono::Utc) > chrono::Utc::now(),
        Err(_) => false,
    }
}

/// Whether a usage cap is already exhausted (None = unlimited).
pub fn uses_exhausted(max_uses: Option<i64>, used_count: i64) -> bool {
    max_uses.is_some_and(|cap| used_count >= cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_expiry_forms() {
        // RFC3339 with an offset normalizes to UTC Z seconds
        let v = normalize_expiry("2026-08-06T01:24:00+08:00").unwrap();
        assert_eq!(v, "2026-08-05T17:24:00Z");
        // datetime-local (browser) is interpreted as UTC
        let v = normalize_expiry("2026-08-05T17:24").unwrap();
        assert_eq!(v, "2026-08-05T17:24:00Z");
        // garbage rejected
        assert!(normalize_expiry("next week").is_err());
    }

    #[test]
    fn expiry_active_semantics() {
        assert!(expiry_active(None));
        assert!(!expiry_active(Some("2020-01-01T00:00:00Z")));
        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert!(expiry_active(Some(&future)));
        // unparseable stored value fails closed
        assert!(!expiry_active(Some("garbage")));
    }

    #[test]
    fn uses_exhausted_semantics() {
        assert!(!uses_exhausted(None, i64::MAX));
        assert!(uses_exhausted(Some(2), 2));
        assert!(!uses_exhausted(Some(2), 1));
    }
}
