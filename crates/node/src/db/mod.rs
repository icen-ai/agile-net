//! SQLite 数据库模块（对应 docs/database/schema.md）
//!
//! 基于 rusqlite，启动时执行版本化迁移；全部敏感字段（密码、Token）
//! 以 Argon2id / SHA-256 哈希存储，严禁明文落库。

pub mod models;

use agile_net_core::error::{Error, Result};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use models::*;
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::info;

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

/// 当前 Schema 版本（递增，新迁移追加到 MIGRATIONS 尾部）。
const MIGRATIONS: &[(u32, &str, &str)] = &[(
    1,
    "initial_schema",
    r#"
    CREATE TABLE admin (
        id         TEXT PRIMARY KEY,
        username   TEXT NOT NULL UNIQUE,
        password   TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE rule (
        id         TEXT PRIMARY KEY,
        type       TEXT NOT NULL CHECK(type IN ('ip-cidr','host')),
        value      TEXT NOT NULL,
        resolve    INTEGER NOT NULL DEFAULT 0,
        remark     TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(type, value)
    );
    CREATE INDEX idx_rule_type ON rule(type);

    CREATE TABLE "group" (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE,
        remark     TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE group_rule (
        group_id TEXT NOT NULL REFERENCES "group"(id) ON DELETE CASCADE,
        rule_id  TEXT NOT NULL REFERENCES rule(id) ON DELETE CASCADE,
        PRIMARY KEY (group_id, rule_id)
    );
    CREATE INDEX idx_group_rule_rule ON group_rule(rule_id);

    CREATE TABLE account (
        id                TEXT PRIMARY KEY,
        username          TEXT NOT NULL UNIQUE,
        password          TEXT NOT NULL,
        group_id          TEXT NOT NULL REFERENCES "group"(id),
        enabled           INTEGER NOT NULL DEFAULT 1,
        remark            TEXT NOT NULL DEFAULT '',
        tunnel_token_hash TEXT,
        last_seen_at      TEXT,
        created_at        TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_account_group ON account(group_id);
    CREATE INDEX idx_account_enabled ON account(enabled);

    CREATE TABLE relay_token (
        id           TEXT PRIMARY KEY,
        token_hash   TEXT NOT NULL UNIQUE,
        token_prefix TEXT NOT NULL,
        remark       TEXT NOT NULL DEFAULT '',
        last_used_at TEXT,
        created_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE node_config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE audit_log (
        id         TEXT PRIMARY KEY,
        admin_id   TEXT,
        operator   TEXT NOT NULL DEFAULT '',
        action     TEXT NOT NULL,
        target     TEXT,
        detail     TEXT,
        ip         TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_audit_action ON audit_log(action);
    CREATE INDEX idx_audit_time ON audit_log(created_at);

    CREATE TABLE traffic_log (
        id          TEXT PRIMARY KEY,
        account_id  TEXT REFERENCES account(id) ON DELETE SET NULL,
        hour        TEXT NOT NULL,
        bytes_tx    INTEGER NOT NULL DEFAULT 0,
        bytes_rx    INTEGER NOT NULL DEFAULT 0,
        connections INTEGER NOT NULL DEFAULT 0,
        UNIQUE(account_id, hour)
    );
    CREATE INDEX idx_traffic_hour ON traffic_log(hour);
    CREATE INDEX idx_traffic_account ON traffic_log(account_id);

    CREATE TABLE refresh_token (
        jti_hash   TEXT PRIMARY KEY,
        subject    TEXT NOT NULL,
        role       TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked    INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    "#,
)];

impl Database {
    /// 打开数据库并执行迁移
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).map_err(db_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db_err)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(db_err)?;
        conn.pragma_update(None, "busy_timeout", 5000)
            .map_err(db_err)?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate()?;
        Ok(db)
    }

    /// 内存数据库（测试专用）
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(db_err)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(db_err)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate()?;
        Ok(db)
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 执行版本化迁移
    pub fn migrate(&self) -> Result<()> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _migration (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .map_err(db_err)?;

        let mut stmt = conn.prepare("SELECT version FROM _migration").map_err(db_err)?;
        let applied: std::collections::HashSet<u32> = stmt
            .query_map([], |r| r.get(0))
            .map_err(db_err)?
            .filter_map(|r| r.ok())
            .collect();

        for (version, name, sql) in MIGRATIONS {
            if !applied.contains(version) {
                conn.execute_batch(sql).map_err(db_err)?;
                conn.execute(
                    "INSERT INTO _migration (version, name) VALUES (?1, ?2)",
                    params![version, name],
                )
                .map_err(db_err)?;
                info!(version, name, "database migration applied");
            }
        }
        Ok(())
    }

    // ==================== Admin ====================

    pub fn has_admin(&self) -> Result<bool> {
        let conn = self.conn();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM admin", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(count > 0)
    }

    pub fn create_admin(&self, username: &str, password_hash: &str) -> Result<AdminRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO admin (id, username, password, created_at, updated_at) VALUES (?1,?2,?3,?4,?4)",
            params![id, username, password_hash, now],
        )
        .map_err(db_err)?;
        Ok(AdminRecord {
            id,
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn get_admin_by_username(&self, username: &str) -> Result<Option<AdminRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, username, password, created_at, updated_at FROM admin WHERE username = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![username]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(AdminRecord {
                id: r.get(0).map_err(db_err)?,
                username: r.get(1).map_err(db_err)?,
                password_hash: r.get(2).map_err(db_err)?,
                created_at: r.get(3).map_err(db_err)?,
                updated_at: r.get(4).map_err(db_err)?,
            }),
            None => None,
        })
    }

    pub fn update_admin_password(&self, admin_id: &str, password_hash: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE admin SET password = ?1, updated_at = ?2 WHERE id = ?3",
            params![password_hash, now_rfc3339(), admin_id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    // ==================== Rule ====================

    pub fn list_rules(
        &self,
        page: u32,
        page_size: u32,
        type_filter: Option<&str>,
        q: Option<&str>,
    ) -> Result<(Vec<RuleRecord>, i64)> {
        let conn = self.conn();
        let mut where_clauses = Vec::new();
        let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(t) = type_filter {
            where_clauses.push("r.type = ?");
            bind.push(Box::new(t.to_string()));
        }
        if let Some(q) = q {
            where_clauses.push("(r.value LIKE ? OR r.remark LIKE ?)");
            bind.push(Box::new(format!("%{q}%")));
            bind.push(Box::new(format!("%{q}%")));
        }
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let total: i64 = {
            let sql = format!("SELECT COUNT(*) FROM rule r {where_sql}");
            let mut stmt = conn.prepare(&sql).map_err(db_err)?;
            let params = rusqlite::params_from_iter(bind.iter().map(|b| b.as_ref()));
            stmt.query_row(params, |r| r.get(0)).map_err(db_err)?
        };

        let offset = (page.saturating_sub(1)) * page_size;
        let sql = format!(
            "SELECT r.id, r.type, r.value, r.resolve, r.remark, r.created_at, r.updated_at,
                    (SELECT COUNT(*) FROM group_rule gr WHERE gr.rule_id = r.id) AS group_count
             FROM rule r {where_sql} ORDER BY r.created_at DESC LIMIT ? OFFSET ?"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let mut bind_refs: Vec<&dyn rusqlite::types::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
        let limit = page_size as i64;
        let off = offset as i64;
        bind_refs.push(&limit);
        bind_refs.push(&off);
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind_refs), |r| {
                Ok(RuleRecord {
                    id: r.get(0)?,
                    rule_type: r.get(1)?,
                    value: r.get(2)?,
                    resolve: r.get::<_, i32>(3)? != 0,
                    remark: r.get(4)?,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                    group_count: r.get(7)?,
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok((items, total))
    }

    pub fn get_rule(&self, id: &str) -> Result<Option<RuleRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, type, value, resolve, remark, created_at, updated_at, 0 FROM rule WHERE id = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(RuleRecord {
                id: r.get(0).map_err(db_err)?,
                rule_type: r.get(1).map_err(db_err)?,
                value: r.get(2).map_err(db_err)?,
                resolve: r.get::<_, i32>(3).map_err(db_err)? != 0,
                remark: r.get(4).map_err(db_err)?,
                created_at: r.get(5).map_err(db_err)?,
                updated_at: r.get(6).map_err(db_err)?,
                group_count: r.get(7).map_err(db_err)?,
            }),
            None => None,
        })
    }

    pub fn rule_exists(&self, rule_type: &str, value: &str) -> Result<bool> {
        let conn = self.conn();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM rule WHERE type = ?1 AND value = ?2",
                params![rule_type, value],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        Ok(count > 0)
    }

    pub fn create_rule(
        &self,
        rule_type: &str,
        value: &str,
        resolve: bool,
        remark: &str,
    ) -> Result<RuleRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO rule (id, type, value, resolve, remark, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6)",
            params![id, rule_type, value, resolve as i32, remark, now],
        )
        .map_err(db_err)?;
        Ok(RuleRecord {
            id,
            rule_type: rule_type.to_string(),
            value: value.to_string(),
            resolve,
            remark: remark.to_string(),
            group_count: 0,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn update_rule(
        &self,
        id: &str,
        value: Option<&str>,
        resolve: Option<bool>,
        remark: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn();
        let now = now_rfc3339();
        if let Some(v) = value {
            conn.execute(
                "UPDATE rule SET value = ?1, updated_at = ?2 WHERE id = ?3",
                params![v, now, id],
            )
            .map_err(db_err)?;
        }
        if let Some(r) = resolve {
            conn.execute(
                "UPDATE rule SET resolve = ?1, updated_at = ?2 WHERE id = ?3",
                params![r as i32, now, id],
            )
            .map_err(db_err)?;
        }
        if let Some(rm) = remark {
            conn.execute(
                "UPDATE rule SET remark = ?1, updated_at = ?2 WHERE id = ?3",
                params![rm, now, id],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    /// 引用该规则的权限组名称列表
    pub fn rule_referencing_groups(&self, rule_id: &str) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.name FROM \"group\" g JOIN group_rule gr ON g.id = gr.group_id WHERE gr.rule_id = ?1",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![rule_id], |r| r.get(0))
            .map_err(db_err)?;
        let mut names = Vec::new();
        for n in rows {
            names.push(n.map_err(db_err)?);
        }
        Ok(names)
    }

    pub fn delete_rule(&self, id: &str, force: bool) -> Result<()> {
        let conn = self.conn();
        if force {
            conn.execute("DELETE FROM group_rule WHERE rule_id = ?1", params![id])
                .map_err(db_err)?;
        }
        conn.execute("DELETE FROM rule WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    /// 查询某权限组关联的全部规则
    pub fn rules_of_group(&self, group_id: &str) -> Result<Vec<RuleRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT r.id, r.type, r.value, r.resolve, r.remark, r.created_at, r.updated_at, 0
                 FROM rule r JOIN group_rule gr ON r.id = gr.rule_id WHERE gr.group_id = ?1",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![group_id], |r| {
                Ok(RuleRecord {
                    id: r.get(0)?,
                    rule_type: r.get(1)?,
                    value: r.get(2)?,
                    resolve: r.get::<_, i32>(3)? != 0,
                    remark: r.get(4)?,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                    group_count: r.get(7)?,
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok(items)
    }

    /// 查询某账号（经其权限组）可访问的全部规则
    pub fn rules_of_account(&self, account_id: &str) -> Result<Vec<RuleRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT r.id, r.type, r.value, r.resolve, r.remark, r.created_at, r.updated_at, 0
                 FROM rule r
                 JOIN group_rule gr ON r.id = gr.rule_id
                 JOIN account a ON a.group_id = gr.group_id
                 WHERE a.id = ?1",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![account_id], |r| {
                Ok(RuleRecord {
                    id: r.get(0)?,
                    rule_type: r.get(1)?,
                    value: r.get(2)?,
                    resolve: r.get::<_, i32>(3)? != 0,
                    remark: r.get(4)?,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                    group_count: r.get(7)?,
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok(items)
    }

    // ==================== Group ====================

    pub fn list_groups(
        &self,
        page: u32,
        page_size: u32,
        q: Option<&str>,
    ) -> Result<(Vec<GroupRecord>, i64)> {
        let conn = self.conn();
        let (where_sql, pattern) = match q {
            Some(q) => ("WHERE g.name LIKE ?1 OR g.remark LIKE ?1", format!("%{q}%")),
            None => ("", String::new()),
        };

        let total: i64 = if pattern.is_empty() {
            conn.query_row("SELECT COUNT(*) FROM \"group\"", [], |r| r.get(0))
                .map_err(db_err)?
        } else {
            conn.query_row(
                &format!("SELECT COUNT(*) FROM \"group\" g {where_sql}"),
                params![pattern],
                |r| r.get(0),
            )
            .map_err(db_err)?
        };

        let offset = (page.saturating_sub(1)) * page_size;
        let sql = format!(
            "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at,
                    (SELECT COUNT(*) FROM group_rule gr WHERE gr.group_id = g.id),
                    (SELECT COUNT(*) FROM account a WHERE a.group_id = g.id)
             FROM \"group\" g {where_sql} ORDER BY g.created_at DESC LIMIT {page_size} OFFSET {offset}"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = if pattern.is_empty() {
            stmt.query_map([], map_group_row).map_err(db_err)?
        } else {
            stmt.query_map(params![pattern], map_group_row)
                .map_err(db_err)?
        };
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok((items, total))
    }

    pub fn get_group(&self, id: &str) -> Result<Option<GroupRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at,
                        (SELECT COUNT(*) FROM group_rule gr WHERE gr.group_id = g.id),
                        (SELECT COUNT(*) FROM account a WHERE a.group_id = g.id)
                 FROM \"group\" g WHERE g.id = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_group_row(r).map_err(db_err)?),
            None => None,
        })
    }

    pub fn get_group_by_name(&self, name: &str) -> Result<Option<GroupRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at, 0, 0 FROM \"group\" g WHERE g.name = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![name]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_group_row(r).map_err(db_err)?),
            None => None,
        })
    }

    pub fn create_group(&self, name: &str, remark: &str) -> Result<GroupRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO \"group\" (id, name, remark, created_at, updated_at) VALUES (?1,?2,?3,?4,?4)",
            params![id, name, remark, now],
        )
        .map_err(db_err)?;
        Ok(GroupRecord {
            id,
            name: name.to_string(),
            remark: remark.to_string(),
            rule_count: 0,
            account_count: 0,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn update_group(&self, id: &str, name: Option<&str>, remark: Option<&str>) -> Result<()> {
        let conn = self.conn();
        let now = now_rfc3339();
        if let Some(n) = name {
            conn.execute(
                "UPDATE \"group\" SET name = ?1, updated_at = ?2 WHERE id = ?3",
                params![n, now, id],
            )
            .map_err(db_err)?;
        }
        if let Some(r) = remark {
            conn.execute(
                "UPDATE \"group\" SET remark = ?1, updated_at = ?2 WHERE id = ?3",
                params![r, now, id],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    /// 全量设置权限组关联的规则
    pub fn set_group_rules(&self, group_id: &str, rule_ids: &[String]) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM group_rule WHERE group_id = ?1", params![group_id])
            .map_err(db_err)?;
        for rid in rule_ids {
            conn.execute(
                "INSERT OR IGNORE INTO group_rule (group_id, rule_id) VALUES (?1, ?2)",
                params![group_id, rid],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    pub fn count_accounts_in_group(&self, group_id: &str) -> Result<i64> {
        let conn = self.conn();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM account WHERE group_id = ?1",
                params![group_id],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        Ok(count)
    }

    pub fn delete_group(&self, id: &str, force: bool) -> Result<()> {
        let conn = self.conn();
        if force {
            conn.execute("DELETE FROM account WHERE group_id = ?1", params![id])
                .map_err(db_err)?;
        }
        conn.execute("DELETE FROM \"group\" WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    // ==================== Account ====================

    #[allow(clippy::too_many_arguments)]
    pub fn list_accounts(
        &self,
        page: u32,
        page_size: u32,
        group_id: Option<&str>,
        enabled: Option<bool>,
        q: Option<&str>,
    ) -> Result<(Vec<AccountRecord>, i64)> {
        let conn = self.conn();
        let mut where_clauses = Vec::new();
        let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(g) = group_id {
            where_clauses.push("a.group_id = ?");
            bind.push(Box::new(g.to_string()));
        }
        if let Some(e) = enabled {
            where_clauses.push("a.enabled = ?");
            bind.push(Box::new(e as i32));
        }
        if let Some(q) = q {
            where_clauses.push("(a.username LIKE ? OR a.remark LIKE ?)");
            bind.push(Box::new(format!("%{q}%")));
            bind.push(Box::new(format!("%{q}%")));
        }
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let total: i64 = {
            let sql = format!("SELECT COUNT(*) FROM account a {where_sql}");
            let mut stmt = conn.prepare(&sql).map_err(db_err)?;
            stmt.query_row(rusqlite::params_from_iter(bind.iter().map(|b| b.as_ref())), |r| r.get(0))
                .map_err(db_err)?
        };

        let offset = (page.saturating_sub(1)) * page_size;
        let sql = format!(
            "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at
             FROM account a LEFT JOIN \"group\" g ON a.group_id = g.id
             {where_sql} ORDER BY a.created_at DESC LIMIT ? OFFSET ?"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let mut bind_refs: Vec<&dyn rusqlite::types::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
        let limit = page_size as i64;
        let off = offset as i64;
        bind_refs.push(&limit);
        bind_refs.push(&off);
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind_refs), map_account_row)
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok((items, total))
    }

    pub fn get_account(&self, id: &str) -> Result<Option<AccountRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at
                 FROM account a LEFT JOIN \"group\" g ON a.group_id = g.id WHERE a.id = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_account_row(r).map_err(db_err)?),
            None => None,
        })
    }

    pub fn get_account_by_username(&self, username: &str) -> Result<Option<(AccountRecord, String)>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.password
                 FROM account a LEFT JOIN \"group\" g ON a.group_id = g.id WHERE a.username = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![username]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => {
                let rec = map_account_row(r).map_err(db_err)?;
                let password_hash: String = r.get(9).map_err(db_err)?;
                Some((rec, password_hash))
            }
            None => None,
        })
    }

    pub fn get_account_password_hash(&self, id: &str) -> Result<Option<String>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT password FROM account WHERE id = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(r.get(0).map_err(db_err)?),
            None => None,
        })
    }

    pub fn create_account(
        &self,
        username: &str,
        password_hash: &str,
        group_id: &str,
        remark: &str,
    ) -> Result<AccountRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO account (id, username, password, group_id, enabled, remark, created_at, updated_at)
             VALUES (?1,?2,?3,?4,1,?5,?6,?6)",
            params![id, username, password_hash, group_id, remark, now],
        )
        .map_err(db_err)?;
        Ok(AccountRecord {
            id,
            username: username.to_string(),
            group_id: group_id.to_string(),
            group_name: None,
            enabled: true,
            online: false,
            last_seen_at: None,
            remark: remark.to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn update_account(
        &self,
        id: &str,
        group_id: Option<&str>,
        enabled: Option<bool>,
        remark: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn();
        let now = now_rfc3339();
        if let Some(g) = group_id {
            conn.execute(
                "UPDATE account SET group_id = ?1, updated_at = ?2 WHERE id = ?3",
                params![g, now, id],
            )
            .map_err(db_err)?;
        }
        if let Some(e) = enabled {
            conn.execute(
                "UPDATE account SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
                params![e as i32, now, id],
            )
            .map_err(db_err)?;
        }
        if let Some(r) = remark {
            conn.execute(
                "UPDATE account SET remark = ?1, updated_at = ?2 WHERE id = ?3",
                params![r, now, id],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    pub fn set_account_password(&self, id: &str, password_hash: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE account SET password = ?1, updated_at = ?2 WHERE id = ?3",
            params![password_hash, now_rfc3339(), id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn set_account_tunnel_token(&self, id: &str, token_hash: Option<&str>) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE account SET tunnel_token_hash = ?1 WHERE id = ?2",
            params![token_hash, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 按 tunnel_token 哈希查找账号（数据面认证）
    pub fn find_account_by_tunnel_hash(&self, token_hash: &str) -> Result<Option<AccountRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at
                 FROM account a LEFT JOIN \"group\" g ON a.group_id = g.id
                 WHERE a.tunnel_token_hash = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![token_hash]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_account_row(r).map_err(db_err)?),
            None => None,
        })
    }

    pub fn touch_account_seen(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE account SET last_seen_at = ?1 WHERE id = ?2",
            params![now_rfc3339(), id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn delete_account(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM account WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    pub fn account_stats(&self) -> Result<(i64, i64)> {
        let conn = self.conn();
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM account", [], |r| r.get(0))
            .map_err(db_err)?;
        let disabled: i64 = conn
            .query_row("SELECT COUNT(*) FROM account WHERE enabled = 0", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok((total, disabled))
    }

    // ==================== Relay Token ====================

    pub fn create_relay_token(&self, token_hash: &str, token_prefix: &str, remark: &str) -> Result<RelayTokenRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO relay_token (id, token_hash, token_prefix, remark, created_at) VALUES (?1,?2,?3,?4,?5)",
            params![id, token_hash, token_prefix, remark, now],
        )
        .map_err(db_err)?;
        Ok(RelayTokenRecord {
            id,
            token_prefix: token_prefix.to_string(),
            remark: remark.to_string(),
            last_used_at: None,
            created_at: now,
        })
    }

    pub fn list_relay_tokens(&self) -> Result<Vec<RelayTokenRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, token_prefix, remark, last_used_at, created_at FROM relay_token ORDER BY created_at DESC")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(RelayTokenRecord {
                    id: r.get(0)?,
                    token_prefix: r.get(1)?,
                    remark: r.get(2)?,
                    last_used_at: r.get(3)?,
                    created_at: r.get(4)?,
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok(items)
    }

    /// 校验 relay token 哈希是否存在；命中时更新 last_used_at
    pub fn check_relay_token(&self, token_hash: &str) -> Result<bool> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id FROM relay_token WHERE token_hash = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![token_hash]).map_err(db_err)?;
        if let Some(r) = rows.next().map_err(db_err)? {
            let id: String = r.get(0).map_err(db_err)?;
            conn.execute(
                "UPDATE relay_token SET last_used_at = ?1 WHERE id = ?2",
                params![now_rfc3339(), id],
            )
            .map_err(db_err)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn delete_relay_token(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM relay_token WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    // ==================== Node Config ====================

    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT value FROM node_config WHERE key = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![key]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(r.get(0).map_err(db_err)?),
            None => None,
        })
    }

    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO node_config (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 配置版本号递增（规则/权限组/账号组变更时调用）
    pub fn bump_config_version(&self) -> Result<u64> {
        let current = self.get_config("config_version")?;
        let next = current
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            + 1;
        self.set_config("config_version", &next.to_string())?;
        Ok(next)
    }

    pub fn config_version(&self) -> Result<u64> {
        Ok(self
            .get_config("config_version")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    // ==================== Audit Log ====================

    pub fn record_audit_log(
        &self,
        admin_id: Option<&str>,
        operator: &str,
        action: &str,
        target: Option<&str>,
        detail: Option<&str>,
        ip: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO audit_log (id, admin_id, operator, action, target, detail, ip, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                uuid::Uuid::new_v4().to_string(),
                admin_id,
                operator,
                action,
                target,
                detail,
                ip,
                now_rfc3339()
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn list_audit_logs(
        &self,
        page: u32,
        page_size: u32,
        action: Option<&str>,
    ) -> Result<(Vec<AuditLogRecord>, i64)> {
        let conn = self.conn();
        let (where_sql, pattern) = match action {
            Some(a) => ("WHERE action = ?1", a.to_string()),
            None => ("", String::new()),
        };

        let total: i64 = if pattern.is_empty() {
            conn.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
                .map_err(db_err)?
        } else {
            conn.query_row(
                &format!("SELECT COUNT(*) FROM audit_log {where_sql}"),
                params![pattern],
                |r| r.get(0),
            )
            .map_err(db_err)?
        };

        let offset = (page.saturating_sub(1)) * page_size;
        let sql = format!(
            "SELECT id, admin_id, operator, action, target, detail, ip, created_at FROM audit_log {where_sql} ORDER BY created_at DESC LIMIT {page_size} OFFSET {offset}"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let map_row = |r: &rusqlite::Row| -> rusqlite::Result<AuditLogRecord> {
            Ok(AuditLogRecord {
                id: r.get(0)?,
                admin_id: r.get(1)?,
                operator: r.get(2)?,
                action: r.get(3)?,
                target: r.get(4)?,
                detail: r.get(5)?,
                ip: r.get(6)?,
                created_at: r.get(7)?,
            })
        };
        let rows = if pattern.is_empty() {
            stmt.query_map([], map_row).map_err(db_err)?
        } else {
            stmt.query_map(params![pattern], map_row).map_err(db_err)?
        };
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok((items, total))
    }

    // ==================== Traffic Log ====================

    /// 按小时聚合 upsert 流量统计
    pub fn add_traffic(&self, account_id: &str, bytes_tx: i64, bytes_rx: i64, connections: i64) -> Result<()> {
        let conn = self.conn();
        let hour = current_hour_bucket();
        conn.execute(
            "INSERT INTO traffic_log (id, account_id, hour, bytes_tx, bytes_rx, connections)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(account_id, hour) DO UPDATE SET
                bytes_tx = bytes_tx + ?4,
                bytes_rx = bytes_rx + ?5,
                connections = connections + ?6",
            params![uuid::Uuid::new_v4().to_string(), account_id, hour, bytes_tx, bytes_rx, connections],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 按账号聚合流量（period 小时窗口）
    pub fn traffic_by_account(&self, hours: i64) -> Result<(Vec<TrafficStatRecord>, i64, i64)> {
        let conn = self.conn();
        let since = hours_ago(hours);
        let mut stmt = conn
            .prepare(
                "SELECT t.account_id, a.username, SUM(t.bytes_tx), SUM(t.bytes_rx), SUM(t.connections)
                 FROM traffic_log t LEFT JOIN account a ON t.account_id = a.id
                 WHERE t.hour >= ?1
                 GROUP BY t.account_id ORDER BY SUM(t.bytes_rx) DESC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![since], |r| {
                Ok(TrafficStatRecord {
                    account_id: r.get(0)?,
                    username: r.get(1)?,
                    bytes_tx: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    bytes_rx: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    connections: r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        let mut total_tx = 0i64;
        let mut total_rx = 0i64;
        for r in rows {
            let rec = r.map_err(db_err)?;
            total_tx += rec.bytes_tx;
            total_rx += rec.bytes_rx;
            items.push(rec);
        }
        Ok((items, total_tx, total_rx))
    }

    /// 按时间序列聚合流量（每小时一个点）
    pub fn traffic_by_time(&self, hours: i64) -> Result<Vec<TrafficPoint>> {
        let conn = self.conn();
        let since = hours_ago(hours);
        let mut stmt = conn
            .prepare(
                "SELECT hour, SUM(bytes_tx), SUM(bytes_rx) FROM traffic_log
                 WHERE hour >= ?1 GROUP BY hour ORDER BY hour ASC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![since], |r| {
                Ok(TrafficPoint {
                    time: r.get(0)?,
                    bytes_tx: r.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    bytes_rx: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok(items)
    }

    // ==================== Refresh Token ====================

    pub fn store_refresh_token(&self, jti_hash: &str, subject: &str, role: &str, expires_at: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO refresh_token (jti_hash, subject, role, expires_at) VALUES (?1,?2,?3,?4)",
            params![jti_hash, subject, role, expires_at],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 校验 refresh token 未吊销且未过期
    pub fn is_refresh_token_valid(&self, jti_hash: &str) -> Result<bool> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT revoked, expires_at FROM refresh_token WHERE jti_hash = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![jti_hash]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => {
                let revoked: i32 = r.get(0).map_err(db_err)?;
                let expires_at: String = r.get(1).map_err(db_err)?;
                revoked == 0 && expires_at > now_rfc3339()
            }
            None => false,
        })
    }

    pub fn revoke_refresh_token(&self, jti_hash: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE refresh_token SET revoked = 1 WHERE jti_hash = ?1",
            params![jti_hash],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 吊销某主体的全部 refresh token（禁用账号/改密码时）
    pub fn revoke_all_refresh_tokens(&self, subject: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE refresh_token SET revoked = 1 WHERE subject = ?1",
            params![subject],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 清理过期的 refresh token（启动时调用）
    pub fn cleanup_expired_refresh_tokens(&self) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM refresh_token WHERE expires_at < ?1",
            params![now_rfc3339()],
        )
        .map_err(db_err)?;
        Ok(())
    }
}

fn map_group_row(r: &rusqlite::Row) -> rusqlite::Result<GroupRecord> {
    Ok(GroupRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        remark: r.get(2)?,
        created_at: r.get(3)?,
        updated_at: r.get(4)?,
        rule_count: r.get(5)?,
        account_count: r.get(6)?,
    })
}

fn map_account_row(r: &rusqlite::Row) -> rusqlite::Result<AccountRecord> {
    Ok(AccountRecord {
        id: r.get(0)?,
        username: r.get(1)?,
        group_id: r.get(2)?,
        group_name: r.get(3)?,
        enabled: r.get::<_, i32>(4)? != 0,
        remark: r.get(5)?,
        last_seen_at: r.get(6)?,
        created_at: r.get(7)?,
        updated_at: r.get(8)?,
        online: false,
    })
}

fn db_err(e: rusqlite::Error) -> Error {
    Error::Other(e.to_string())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// 当前小时桶 'YYYY-MM-DDTHH:00:00Z'
fn current_hour_bucket() -> String {
    let now = chrono::Utc::now();
    now.format("%Y-%m-%dT%H:00:00Z").to_string()
}

fn hours_ago(hours: i64) -> String {
    let t = chrono::Utc::now() - chrono::Duration::hours(hours);
    t.format("%Y-%m-%dT%H:00:00Z").to_string()
}

// ==================== 密码与令牌 ====================

/// Argon2id 密码哈希（OWASP 推荐参数：64MB / t=3 / p=4）
pub fn hash_password(password: &str) -> Result<String> {
    let random_bytes: [u8; 16] = rand::random();
    let salt = SaltString::encode_b64(&random_bytes).map_err(|e| Error::Other(e.to_string()))?;
    let params = Params::new(65536, 3, 4, None).map_err(|e| Error::Other(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::Other(e.to_string()))?
        .to_string();
    Ok(hash)
}

/// 验证密码（Argon2id）
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(password_hash).map_err(|e| Error::Other(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// 生成强密码（sk 风格：`sk-` + 48 位混合字符，约 286 bits 熵）
pub fn generate_password() -> String {
    format!("sk-{}", random_alnum(48))
}

/// 生成 Relay PSK Token（`psk_` + 48 位）
pub fn generate_relay_token() -> String {
    format!("psk_{}", random_alnum(48))
}

/// 生成 Tunnel Token（`tun_` + 48 位）
pub fn generate_tunnel_token() -> String {
    format!("tun_{}", random_alnum(48))
}

/// 生成随机密钥（hex 64 字符，用于 JWT secret 等）
pub fn generate_secret_hex() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 hex（Token 落库哈希）
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_alnum(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
