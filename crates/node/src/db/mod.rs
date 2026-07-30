//! SQLite 数据库模块
//!
//! 基于 rusqlite 提供数据库建表、Schema 迁移与异步安全的 CRUD 操作。

pub mod models;

use agile_net_core::error::{Error, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use models::*;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::info;

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// 打开或在内存中新建数据库
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| Error::Other(e.to_string()))?;

        // 启用 WAL 模式以获得更好的并发性能
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| Error::Other(e.to_string()))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| Error::Other(e.to_string()))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.migrate()?;
        Ok(db)
    }

    /// 内存数据库（测试专用）
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| Error::Other(e.to_string()))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.migrate()?;
        Ok(db)
    }

    /// 执行 Schema 建表与初始数据填充
    pub fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                token TEXT NOT NULL,
                status TEXT NOT NULL,
                last_seen TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS routes (
                id TEXT PRIMARY KEY,
                pattern TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                outbound_type TEXT NOT NULL,
                node_id TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS system_configs (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT,
                updated_at TEXT NOT NULL
            );
            ",
        )
        .map_err(|e| Error::Other(e.to_string()))?;

        // 插入默认 admin 用户 (如果不存在, 密码: admin123)
        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM users WHERE username = ?1")
            .map_err(|e| Error::Other(e.to_string()))?;
        let count: i64 = stmt
            .query_row(params!["admin"], |r| r.get(0))
            .map_err(|e| Error::Other(e.to_string()))?;

        if count == 0 {
            let password_hash = hash_password("admin123")?;
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![uuid::Uuid::new_v4().to_string(), "admin", password_hash, "admin", now, now],
            )
            .map_err(|e| Error::Other(e.to_string()))?;
            info!("default admin user created (admin / admin123)");
        }

        Ok(())
    }

    // --- 用户 CRUD ---

    pub fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, username, password_hash, role, created_at, updated_at FROM users WHERE username = ?1")
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut rows = stmt
            .query(params![username])
            .map_err(|e| Error::Other(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| Error::Other(e.to_string()))? {
            let role_str: String = row.get(3).unwrap_or_default();
            Ok(Some(User {
                id: row.get(0).unwrap_or_default(),
                username: row.get(1).unwrap_or_default(),
                password_hash: row.get(2).unwrap_or_default(),
                role: UserRole::parse(&role_str),
                created_at: row.get(4).unwrap_or_default(),
                updated_at: row.get(5).unwrap_or_default(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_user_by_id(&self, id: &str) -> Result<Option<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, username, password_hash, role, created_at, updated_at FROM users WHERE id = ?1")
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut rows = stmt
            .query(params![id])
            .map_err(|e| Error::Other(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| Error::Other(e.to_string()))? {
            let role_str: String = row.get(3).unwrap_or_default();
            Ok(Some(User {
                id: row.get(0).unwrap_or_default(),
                username: row.get(1).unwrap_or_default(),
                password_hash: row.get(2).unwrap_or_default(),
                role: UserRole::parse(&role_str),
                created_at: row.get(4).unwrap_or_default(),
                updated_at: row.get(5).unwrap_or_default(),
            }))
        } else {
            Ok(None)
        }
    }

    // --- 节点 CRUD ---

    pub fn list_nodes(&self) -> Result<Vec<NodeRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, name, token, status, last_seen, created_at, updated_at FROM nodes ORDER BY created_at DESC")
            .map_err(|e| Error::Other(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                let status_str: String = row.get(3)?;
                Ok(NodeRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    token: row.get(2)?,
                    status: NodeStatus::parse(&status_str),
                    last_seen: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| Error::Other(e.to_string()))?);
        }
        Ok(result)
    }

    pub fn get_node(&self, id: &str) -> Result<Option<NodeRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, name, token, status, last_seen, created_at, updated_at FROM nodes WHERE id = ?1")
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut rows = stmt
            .query(params![id])
            .map_err(|e| Error::Other(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| Error::Other(e.to_string()))? {
            let status_str: String = row.get(3).unwrap_or_default();
            Ok(Some(NodeRecord {
                id: row.get(0).unwrap_or_default(),
                name: row.get(1).unwrap_or_default(),
                token: row.get(2).unwrap_or_default(),
                status: NodeStatus::parse(&status_str),
                last_seen: row.get(4).ok(),
                created_at: row.get(5).unwrap_or_default(),
                updated_at: row.get(6).unwrap_or_default(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn create_node(&self, name: &str, token: &str) -> Result<NodeRecord> {
        let conn = self.conn.lock().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO nodes (id, name, token, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, name, token, NodeStatus::Offline.as_str(), now, now],
        )
        .map_err(|e| Error::Other(e.to_string()))?;

        Ok(NodeRecord {
            id,
            name: name.to_string(),
            token: token.to_string(),
            status: NodeStatus::Offline,
            last_seen: None,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn update_node_status(&self, id: &str, status: NodeStatus) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "UPDATE nodes SET status = ?1, last_seen = ?2, updated_at = ?2 WHERE id = ?3",
            params![status.as_str(), now, id],
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        Ok(())
    }

    pub fn delete_node(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM nodes WHERE id = ?1", params![id])
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(())
    }

    // --- 路由 CRUD ---

    pub fn list_routes(&self) -> Result<Vec<RouteRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, pattern, pattern_type, outbound_type, node_id, enabled, created_at, updated_at FROM routes ORDER BY created_at DESC")
            .map_err(|e| Error::Other(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                let pattern_type_str: String = row.get(2)?;
                let enabled_int: i32 = row.get(5)?;
                Ok(RouteRecord {
                    id: row.get(0)?,
                    pattern: row.get(1)?,
                    pattern_type: RoutePatternType::parse(&pattern_type_str),
                    outbound_type: row.get(3)?,
                    node_id: row.get(4)?,
                    enabled: enabled_int != 0,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut result = Vec::new();
        for r in rows {
            result.push(r.map_err(|e| Error::Other(e.to_string()))?);
        }
        Ok(result)
    }

    pub fn create_route(
        &self,
        pattern: &str,
        pattern_type: RoutePatternType,
        outbound_type: &str,
        node_id: Option<&str>,
    ) -> Result<RouteRecord> {
        let conn = self.conn.lock().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO routes (id, pattern, pattern_type, outbound_type, node_id, enabled, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7)",
            params![id, pattern, pattern_type.as_str(), outbound_type, node_id, now, now],
        )
        .map_err(|e| Error::Other(e.to_string()))?;

        Ok(RouteRecord {
            id,
            pattern: pattern.to_string(),
            pattern_type,
            outbound_type: outbound_type.to_string(),
            node_id: node_id.map(|s| s.to_string()),
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn delete_route(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM routes WHERE id = ?1", params![id])
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(())
    }

    // --- 系统配置 CRUD ---

    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT value FROM system_configs WHERE key = ?1")
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut rows = stmt
            .query(params![key])
            .map_err(|e| Error::Other(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| Error::Other(e.to_string()))? {
            Ok(Some(row.get(0).unwrap_or_default()))
        } else {
            Ok(None)
        }
    }

    pub fn set_config(&self, key: &str, value: &str, description: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO system_configs (key, value, description, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(key) DO UPDATE SET value=?2, description=COALESCE(?3, description), updated_at=?4",
            params![key, value, description, now],
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        Ok(())
    }
}

/// 密码 Hash 辅助方法 (Argon2)
pub fn hash_password(password: &str) -> Result<String> {
    let random_bytes: [u8; 16] = rand::random();
    let salt = SaltString::encode_b64(&random_bytes).map_err(|e| Error::Other(e.to_string()))?;
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::Other(e.to_string()))?
        .to_string();
    Ok(password_hash)
}

/// 验证密码 (Argon2)
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|e| Error::Other(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
