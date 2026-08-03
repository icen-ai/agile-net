//! 从 db/mod.rs 拆分：连接池与共享基础（纯搬运，零逻辑变更）

use agile_net_core::error::{Error, Result};
use r2d2_sqlite::SqliteConnectionManager;
use std::path::Path;

#[derive(Clone)]
pub struct Database {
    pool: r2d2::Pool<SqliteConnectionManager>,
}

impl Database {
    /// 打开数据库并执行迁移（WAL 模式 + 读连接池，写操作经 busy_timeout 串行）。
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

    /// 内存数据库（测试专用，单连接保证共享状态）
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
