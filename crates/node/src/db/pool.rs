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

    pub(crate) fn conn(&self) -> r2d2::PooledConnection<SqliteConnectionManager> {
        self.pool.get().expect("db pool exhausted")
    }
}

pub(crate) fn db_err(e: rusqlite::Error) -> Error {
    Error::Other(e.to_string())
}

pub(crate) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
