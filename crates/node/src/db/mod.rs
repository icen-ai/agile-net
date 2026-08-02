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
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use std::path::Path;
use tracing::info;

#[derive(Clone)]
pub struct Database {
    pool: r2d2::Pool<SqliteConnectionManager>,
}

/// 当前 Schema 版本（递增，新迁移追加到 MIGRATIONS 尾部）。
const MIGRATIONS: &[(u32, &str, &str)] = &[
    (
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
    ),
    (
        2,
        "admin_console_and_tickets",
        r#"
    -- 管理版接入链接：账号可被授予「管理此节点」权限
    ALTER TABLE account ADD COLUMN admin_console INTEGER NOT NULL DEFAULT 0;

    -- 管理引导票据：控制台通道/中继暴露场景换取管理会话的一次性（或限期）凭据。
    -- 仅存 SHA-256 哈希，明文随签发返回一次。
    CREATE TABLE admin_ticket (
        id          TEXT PRIMARY KEY,
        ticket_hash TEXT NOT NULL UNIQUE,
        kind        TEXT NOT NULL CHECK(kind IN ('account','relay')),
        subject     TEXT NOT NULL,
        scope       TEXT NOT NULL DEFAULT 'full' CHECK(scope IN ('ro','rules','full')),
        uses        INTEGER NOT NULL DEFAULT 0,
        max_uses    INTEGER NOT NULL DEFAULT 1,
        expires_at  TEXT NOT NULL,
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_admin_ticket_exp ON admin_ticket(expires_at);
    "#,
    ),
    (
        3,
        "relay_token_expose_control",
        r#"
    -- Relay 链接的「暴露控制面」开关：允许该下游中继管理本节点（默认关）
    ALTER TABLE relay_token ADD COLUMN expose_control INTEGER NOT NULL DEFAULT 0;
    -- 管理授权档位：ro（只读）/ rules（只读+规则写）/ full（全权）
    ALTER TABLE relay_token ADD COLUMN control_scope TEXT NOT NULL DEFAULT 'full';
    "#,
    ),
    (
        4,
        "peer_acl_connector",
        r#"
    -- 扇入对端的收敛挂载点（NULL = 不收敛，放行一切）
    ALTER TABLE relay_token ADD COLUMN group_id TEXT REFERENCES "group"(id);

    -- 扇出 connector 入库（一等资源；token_enc 加密存储，见 docs/todo/peer-acl.md §4/§5）
    CREATE TABLE connector (
        id           TEXT PRIMARY KEY,
        name         TEXT NOT NULL UNIQUE,
        upstream_addr TEXT NOT NULL,
        token_enc    TEXT NOT NULL,
        sni_hostname TEXT NOT NULL DEFAULT '',
        insecure     INTEGER NOT NULL DEFAULT 0,
        advertise    TEXT NOT NULL DEFAULT '',
        group_id     TEXT REFERENCES "group"(id),
        enabled      INTEGER NOT NULL DEFAULT 1,
        remark       TEXT NOT NULL DEFAULT '',
        created_at   TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_connector_group ON connector(group_id);
    "#,
    ),
    (
        5,
        "connector_cert_paths",
        r#"
    -- 扇出 connector 证书固定能力对齐 core ConnectorConfig（设计文档 §4 遗漏补列；
    -- 空串 = 不使用，优先级 pinned > ca > insecure 与 TOML 装配逻辑一致）
    ALTER TABLE connector ADD COLUMN ca_cert_path TEXT NOT NULL DEFAULT '';
    ALTER TABLE connector ADD COLUMN pinned_cert_path TEXT NOT NULL DEFAULT '';
    "#,
    ),
    (
        6,
        "node_traffic_log",
        r#"
    -- 节点级流量小时序列（扇入对端/扇出/中继途径三维；按账号流量仍在 traffic_log，互不影响）
    -- dim: fanin=扇入对端(src=对端 node_id) / fanout=扇出(src=connector name)
    --      / transit=中继途径(src=起始端, dst=结束端)
    -- hour 为本地时间桶 'YYYY-MM-DD HH:00'（status traffic_24h 契约格式）
    CREATE TABLE node_traffic_log (
        id         TEXT PRIMARY KEY,
        dim        TEXT NOT NULL CHECK(dim IN ('fanin','fanout','transit')),
        src        TEXT NOT NULL DEFAULT '',
        dst        TEXT NOT NULL DEFAULT '',
        hour       TEXT NOT NULL,
        bytes_up   INTEGER NOT NULL DEFAULT 0,
        bytes_down INTEGER NOT NULL DEFAULT 0,
        UNIQUE(dim, src, dst, hour)
    );
    CREATE INDEX idx_node_traffic_hour ON node_traffic_log(hour);
    "#,
    ),
];

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

    fn conn(&self) -> r2d2::PooledConnection<SqliteConnectionManager> {
        self.pool.get().expect("db pool exhausted")
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

        let mut stmt = conn
            .prepare("SELECT version FROM _migration")
            .map_err(db_err)?;
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

    pub fn list_admins(&self) -> Result<Vec<AdminRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, username, password, created_at, updated_at FROM admin ORDER BY created_at ASC")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AdminRecord {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    password_hash: r.get(2)?,
                    created_at: r.get(3)?,
                    updated_at: r.get(4)?,
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok(items)
    }

    pub fn count_admins(&self) -> Result<i64> {
        let conn = self.conn();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM admin", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(count)
    }

    pub fn get_admin_by_id(&self, id: &str) -> Result<Option<AdminRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, username, password, created_at, updated_at FROM admin WHERE id = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
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

    pub fn delete_admin(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM admin WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    /// 清理 N 天前的审计日志，返回删除条数。
    pub fn cleanup_audit_log(&self, days: i64) -> Result<usize> {
        let conn = self.conn();
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let n = conn
            .execute(
                "DELETE FROM audit_log WHERE created_at < ?1",
                params![cutoff],
            )
            .map_err(db_err)?;
        Ok(n)
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
        let mut bind_refs: Vec<&dyn rusqlite::types::ToSql> =
            bind.iter().map(|b| b.as_ref()).collect();
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
        conn.execute(
            "DELETE FROM group_rule WHERE group_id = ?1",
            params![group_id],
        )
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
            stmt.query_row(
                rusqlite::params_from_iter(bind.iter().map(|b| b.as_ref())),
                |r| r.get(0),
            )
            .map_err(db_err)?
        };

        let offset = (page.saturating_sub(1)) * page_size;
        let sql = format!(
            "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console
             FROM account a LEFT JOIN \"group\" g ON a.group_id = g.id
             {where_sql} ORDER BY a.created_at DESC LIMIT ? OFFSET ?"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let mut bind_refs: Vec<&dyn rusqlite::types::ToSql> =
            bind.iter().map(|b| b.as_ref()).collect();
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
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console
                 FROM account a LEFT JOIN \"group\" g ON a.group_id = g.id WHERE a.id = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_account_row(r).map_err(db_err)?),
            None => None,
        })
    }

    pub fn get_account_by_username(
        &self,
        username: &str,
    ) -> Result<Option<(AccountRecord, String)>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console, a.password
                 FROM account a LEFT JOIN \"group\" g ON a.group_id = g.id WHERE a.username = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![username]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => {
                let rec = map_account_row(r).map_err(db_err)?;
                let password_hash: String = r.get(10).map_err(db_err)?;
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
        self.create_account_with_admin(username, password_hash, group_id, remark, false)
    }

    /// 创建账号（可授予「管理此节点」权限，对应管理版接入链接）。
    pub fn create_account_with_admin(
        &self,
        username: &str,
        password_hash: &str,
        group_id: &str,
        remark: &str,
        admin_console: bool,
    ) -> Result<AccountRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO account (id, username, password, group_id, enabled, remark, admin_console, created_at, updated_at)
             VALUES (?1,?2,?3,?4,1,?5,?6,?7,?7)",
            params![id, username, password_hash, group_id, remark, admin_console as i32, now],
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
            admin_console,
        })
    }

    pub fn update_account(
        &self,
        id: &str,
        group_id: Option<&str>,
        enabled: Option<bool>,
        remark: Option<&str>,
    ) -> Result<()> {
        self.update_account_full(id, group_id, enabled, remark, None)
    }

    /// 更新账号（含「管理此节点」权限变更）。
    pub fn update_account_full(
        &self,
        id: &str,
        group_id: Option<&str>,
        enabled: Option<bool>,
        remark: Option<&str>,
        admin_console: Option<bool>,
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
        if let Some(ac) = admin_console {
            conn.execute(
                "UPDATE account SET admin_console = ?1, updated_at = ?2 WHERE id = ?3",
                params![ac as i32, now, id],
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
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console
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
            .query_row("SELECT COUNT(*) FROM account WHERE enabled = 0", [], |r| {
                r.get(0)
            })
            .map_err(db_err)?;
        Ok((total, disabled))
    }

    // ==================== Relay Token ====================

    pub fn create_relay_token(
        &self,
        token_hash: &str,
        token_prefix: &str,
        remark: &str,
    ) -> Result<RelayTokenRecord> {
        self.create_relay_token_full(token_hash, token_prefix, remark, false, "full")
    }

    /// 创建 Relay Token（可勾选「允许该下游中继管理本节点」+ 授权档位）。
    pub fn create_relay_token_full(
        &self,
        token_hash: &str,
        token_prefix: &str,
        remark: &str,
        expose_control: bool,
        control_scope: &str,
    ) -> Result<RelayTokenRecord> {
        self.create_relay_token_with_group(
            token_hash,
            token_prefix,
            remark,
            expose_control,
            control_scope,
            None,
        )
    }

    /// 创建 Relay Token 并挂载收敛权限组（group_id 为 None = 不收敛）。
    pub fn create_relay_token_with_group(
        &self,
        token_hash: &str,
        token_prefix: &str,
        remark: &str,
        expose_control: bool,
        control_scope: &str,
        group_id: Option<&str>,
    ) -> Result<RelayTokenRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO relay_token (id, token_hash, token_prefix, remark, expose_control, control_scope, group_id, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, token_hash, token_prefix, remark, expose_control as i32, control_scope, group_id, now],
        )
        .map_err(db_err)?;
        Ok(RelayTokenRecord {
            id,
            token_prefix: token_prefix.to_string(),
            remark: remark.to_string(),
            expose_control,
            control_scope: control_scope.to_string(),
            group_id: group_id.map(|g| g.to_string()),
            group_name: None,
            last_used_at: None,
            created_at: now,
        })
    }

    /// 设置 relay token 的收敛权限组（None = 不收敛，放行一切）。
    pub fn set_relay_token_group(&self, id: &str, group_id: Option<&str>) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE relay_token SET group_id = ?1 WHERE id = ?2",
            params![group_id, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 更新暴露控制面开关与授权档位（开关变更走 relay_token.expose_control 审计）。
    pub fn update_relay_token_control(
        &self,
        id: &str,
        expose_control: bool,
        control_scope: &str,
    ) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE relay_token SET expose_control = ?1, control_scope = ?2 WHERE id = ?3",
            params![expose_control as i32, control_scope, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 按哈希查暴露标记与档位（握手 v2 下发判定）。
    pub fn get_relay_token_control(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, bool, String)>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT token_prefix, expose_control, control_scope FROM relay_token WHERE token_hash = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![token_hash]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some((
                r.get(0).map_err(db_err)?,
                r.get::<_, i32>(1).map_err(db_err)? != 0,
                r.get(2).map_err(db_err)?,
            )),
            None => None,
        })
    }

    pub fn list_relay_tokens(&self) -> Result<Vec<RelayTokenRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT t.id, t.token_prefix, t.remark, t.expose_control, t.control_scope, t.last_used_at, t.created_at, t.group_id, g.name
                      FROM relay_token t LEFT JOIN \"group\" g ON t.group_id = g.id ORDER BY t.created_at DESC")
            .map_err(db_err)?;
        let rows = stmt.query_map([], map_relay_token_row).map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok(items)
    }

    /// 按 ID 查 relay token 详情（带出收敛组 ID 与组名）
    pub fn get_relay_token(&self, id: &str) -> Result<Option<RelayTokenRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT t.id, t.token_prefix, t.remark, t.expose_control, t.control_scope, t.last_used_at, t.created_at, t.group_id, g.name
                      FROM relay_token t LEFT JOIN \"group\" g ON t.group_id = g.id WHERE t.id = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_relay_token_row(r).map_err(db_err)?),
            None => None,
        })
    }

    /// 按哈希查 relay token 的收敛权限组（数据面扇入收敛用）。
    /// 外层 None = token 不存在；内层 None = 不收敛（放行一切）。
    pub fn get_relay_token_group(&self, token_hash: &str) -> Result<Option<Option<String>>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT group_id FROM relay_token WHERE token_hash = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![token_hash]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(r.get(0).map_err(db_err)?),
            None => None,
        })
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

    // ==================== Connector（扇出，一等资源） ====================

    /// 创建扇出 connector（token 加密落库，创建后亦不回显，只允许重置）。
    #[allow(clippy::too_many_arguments)]
    pub fn create_connector(
        &self,
        name: &str,
        upstream_addr: &str,
        token_plain: &str,
        sni_hostname: &str,
        insecure: bool,
        ca_cert_path: &str,
        pinned_cert_path: &str,
        advertise: &str,
        group_id: Option<&str>,
        remark: &str,
    ) -> Result<ConnectorRecord> {
        let token_enc = self.encrypt_secret(token_plain)?;
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO connector (id, name, upstream_addr, token_enc, sni_hostname, insecure, ca_cert_path, pinned_cert_path, advertise, group_id, enabled, remark, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?12,?12)",
            params![id, name, upstream_addr, token_enc, sni_hostname, insecure as i32, ca_cert_path, pinned_cert_path, advertise, group_id, remark, now],
        )
        .map_err(db_err)?;
        Ok(ConnectorRecord {
            id,
            name: name.to_string(),
            upstream_addr: upstream_addr.to_string(),
            token_enc,
            sni_hostname: sni_hostname.to_string(),
            insecure,
            ca_cert_path: ca_cert_path.to_string(),
            pinned_cert_path: pinned_cert_path.to_string(),
            advertise: advertise.to_string(),
            group_id: group_id.map(|g| g.to_string()),
            enabled: true,
            remark: remark.to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// 列出全部扇出 connector（展示视图，绝不含 token 明文/密文）。
    pub fn list_connectors(&self) -> Result<Vec<ConnectorView>> {
        // 先取出全部行并归还连接（内存库连接池为 1，解密需再次取连接）
        let recs = {
            let conn = self.conn();
            let mut stmt = conn
                .prepare(
                    "SELECT c.id, c.name, c.upstream_addr, c.token_enc, c.sni_hostname, c.insecure, c.ca_cert_path, c.pinned_cert_path, c.advertise,
                            c.group_id, g.name, c.enabled, c.remark, c.created_at, c.updated_at
                     FROM connector c LEFT JOIN \"group\" g ON c.group_id = g.id ORDER BY c.created_at DESC",
                )
                .map_err(db_err)?;
            let mut rows = stmt.query([]).map_err(db_err)?;
            let mut recs = Vec::new();
            while let Some(r) = rows.next().map_err(db_err)? {
                let rec = ConnectorRecord {
                    id: r.get(0).map_err(db_err)?,
                    name: r.get(1).map_err(db_err)?,
                    upstream_addr: r.get(2).map_err(db_err)?,
                    token_enc: r.get(3).map_err(db_err)?,
                    sni_hostname: r.get(4).map_err(db_err)?,
                    insecure: r.get::<_, i32>(5).map_err(db_err)? != 0,
                    ca_cert_path: r.get(6).map_err(db_err)?,
                    pinned_cert_path: r.get(7).map_err(db_err)?,
                    advertise: r.get(8).map_err(db_err)?,
                    group_id: r.get(9).map_err(db_err)?,
                    enabled: r.get::<_, i32>(11).map_err(db_err)? != 0,
                    remark: r.get(12).map_err(db_err)?,
                    created_at: r.get(13).map_err(db_err)?,
                    updated_at: r.get(14).map_err(db_err)?,
                };
                let group_name: Option<String> = r.get(10).map_err(db_err)?;
                recs.push((rec, group_name));
            }
            recs
        };
        let mut items = Vec::new();
        for (rec, group_name) in recs {
            // 前缀展示位：解密取前 8 字符仅用于辨认；解密失败（密钥轮换等）留空
            let token_prefix = self
                .decrypt_secret(&rec.token_enc)
                .map(|t| token_prefix_of(&t))
                .unwrap_or_default();
            items.push(ConnectorView {
                id: rec.id,
                name: rec.name,
                upstream_addr: rec.upstream_addr,
                token_prefix,
                sni_hostname: rec.sni_hostname,
                insecure: rec.insecure,
                ca_cert_path: rec.ca_cert_path,
                pinned_cert_path: rec.pinned_cert_path,
                advertise: rec.advertise,
                group_id: rec.group_id,
                group_name,
                enabled: rec.enabled,
                remark: rec.remark,
                created_at: rec.created_at,
                updated_at: rec.updated_at,
            });
        }
        Ok(items)
    }

    /// 按 ID 取 connector 记录（含密文，仅供内部使用，严禁日志/审计输出）。
    pub fn get_connector(&self, id: &str) -> Result<Option<ConnectorRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, upstream_addr, token_enc, sni_hostname, insecure, ca_cert_path, pinned_cert_path, advertise, group_id, enabled, remark, created_at, updated_at
                 FROM connector WHERE id = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(ConnectorRecord {
                id: r.get(0).map_err(db_err)?,
                name: r.get(1).map_err(db_err)?,
                upstream_addr: r.get(2).map_err(db_err)?,
                token_enc: r.get(3).map_err(db_err)?,
                sni_hostname: r.get(4).map_err(db_err)?,
                insecure: r.get::<_, i32>(5).map_err(db_err)? != 0,
                ca_cert_path: r.get(6).map_err(db_err)?,
                pinned_cert_path: r.get(7).map_err(db_err)?,
                advertise: r.get(8).map_err(db_err)?,
                group_id: r.get(9).map_err(db_err)?,
                enabled: r.get::<_, i32>(10).map_err(db_err)? != 0,
                remark: r.get(11).map_err(db_err)?,
                created_at: r.get(12).map_err(db_err)?,
                updated_at: r.get(13).map_err(db_err)?,
            }),
            None => None,
        })
    }

    /// 按 ID 取 connector 的扇出 token 明文（解密，仅供运行时连接用；严禁日志/审计输出）。
    pub fn get_connector_secret(&self, id: &str) -> Result<String> {
        let rec = self
            .get_connector(id)?
            .ok_or_else(|| Error::Other("connector not found".into()))?;
        self.decrypt_secret(&rec.token_enc)
    }

    /// 更新 connector（token_plain 为 None = 保留原 token）。
    #[allow(clippy::too_many_arguments)]
    pub fn update_connector(
        &self,
        id: &str,
        name: &str,
        upstream_addr: &str,
        token_plain: Option<&str>,
        sni_hostname: &str,
        insecure: bool,
        ca_cert_path: &str,
        pinned_cert_path: &str,
        advertise: &str,
        group_id: Option<&str>,
        remark: &str,
    ) -> Result<()> {
        let token_enc = match token_plain {
            Some(t) => self.encrypt_secret(t)?,
            None => {
                self.get_connector(id)?
                    .ok_or_else(|| Error::Other("connector not found".into()))?
                    .token_enc
            }
        };
        let conn = self.conn();
        conn.execute(
            "UPDATE connector SET name = ?1, upstream_addr = ?2, token_enc = ?3, sni_hostname = ?4,
                    insecure = ?5, ca_cert_path = ?6, pinned_cert_path = ?7, advertise = ?8, group_id = ?9, remark = ?10, updated_at = ?11
             WHERE id = ?12",
            params![name, upstream_addr, token_enc, sni_hostname, insecure as i32, ca_cert_path, pinned_cert_path, advertise, group_id, remark, now_rfc3339(), id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn set_connector_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE connector SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            params![enabled as i32, now_rfc3339(), id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn delete_connector(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM connector WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    /// TOML `[[connectors]]` 初始导入：同名已存在则跳过（运行时以 DB 为准）。
    #[allow(clippy::too_many_arguments)]
    pub fn import_connector_if_absent(
        &self,
        name: &str,
        upstream_addr: &str,
        token_plain: &str,
        sni_hostname: &str,
        insecure: bool,
        ca_cert_path: &str,
        pinned_cert_path: &str,
        advertise: &str,
        group_id: Option<&str>,
        remark: &str,
    ) -> Result<bool> {
        let conn = self.conn();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM connector WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        if count > 0 {
            return Ok(false);
        }
        drop(conn);
        self.create_connector(
            name,
            upstream_addr,
            token_plain,
            sni_hostname,
            insecure,
            ca_cert_path,
            pinned_cert_path,
            advertise,
            group_id,
            remark,
        )?;
        Ok(true)
    }

    // ==================== 扇出 token 加密存储（全库唯一可逆例外，§5） ====================

    /// AES-256-GCM 加密敏感凭据，落库格式 `v1:nonce_b64:ct_b64`。
    /// 机器密钥首用生成（32 随机字节 hex），存 node_config.connector_token_key。
    pub fn encrypt_secret(&self, plain: &str) -> Result<String> {
        let key = self.connector_token_key()?;
        let nonce_bytes: [u8; 12] = rand::random();
        let mut in_out = plain.as_bytes().to_vec();
        key.seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
            ring::aead::Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| Error::Other("encrypt_secret failed".into()))?;
        Ok(format!(
            "v1:{}:{}",
            b64_encode(&nonce_bytes),
            b64_encode(&in_out)
        ))
    }

    /// 解密 `v1:` 格式密文（版本不符/密钥错误均报错；错误信息不含明文/密文）。
    pub fn decrypt_secret(&self, enc: &str) -> Result<String> {
        let mut parts = enc.splitn(3, ':');
        let (ver, nonce_b64, ct_b64) = match (parts.next(), parts.next(), parts.next()) {
            (Some(v), Some(n), Some(c)) => (v, n, c),
            _ => return Err(Error::Other("secret format invalid".into())),
        };
        if ver != "v1" {
            return Err(Error::Other("secret version unsupported".into()));
        }
        let nonce_raw = b64_decode(nonce_b64)?;
        let nonce_bytes: [u8; 12] = nonce_raw
            .try_into()
            .map_err(|_| Error::Other("secret nonce invalid".into()))?;
        let mut in_out = b64_decode(ct_b64)?;
        let key = self.connector_token_key()?;
        let plain = key
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
                ring::aead::Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| Error::Other("secret decrypt failed".into()))?;
        String::from_utf8(plain.to_vec()).map_err(|e| Error::Other(e.to_string()))
    }

    /// 装载或生成扇出 token 机器密钥（与 jwt_secret 同机制）。
    fn connector_token_key(&self) -> Result<ring::aead::LessSafeKey> {
        let hex_key = match self.get_config("connector_token_key")? {
            Some(k) if !k.is_empty() => k,
            _ => {
                let k = generate_secret_hex();
                self.set_config("connector_token_key", &k)?;
                k
            }
        };
        let bytes = hex_decode(&hex_key)?;
        let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &bytes)
            .map_err(|_| Error::Other("connector_token_key invalid".into()))?;
        Ok(ring::aead::LessSafeKey::new(unbound))
    }

    // ==================== Admin Ticket（管理引导票据） ====================

    /// 签发管理引导票据：明文返回一次，库中只存 SHA-256 哈希。
    ///
    /// kind: account（管理版接入链接）/ relay（中继暴露控制面）；
    /// subject: account_id 或 "psk_前缀@下游节点名"；max_uses > 1 时限期多次用（relay 场景）。
    pub fn create_admin_ticket(
        &self,
        kind: &str,
        subject: &str,
        scope: &str,
        max_uses: i32,
        ttl_secs: i64,
    ) -> Result<String> {
        let ticket = format!("adt_{}", random_alnum(48));
        let hash = sha256_hex(ticket.as_bytes());
        let expires = (chrono::Utc::now() + chrono::Duration::seconds(ttl_secs))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let conn = self.conn();
        conn.execute(
            "INSERT INTO admin_ticket (id, ticket_hash, kind, subject, scope, uses, max_uses, expires_at, created_at)
             VALUES (?1,?2,?3,?4,?5,0,?6,?7,?8)",
            params![
                uuid::Uuid::new_v4().to_string(),
                hash,
                kind,
                subject,
                scope,
                max_uses,
                expires,
                now_rfc3339()
            ],
        )
        .map_err(db_err)?;
        Ok(ticket)
    }

    /// 核销管理引导票据（原子计次防重放；过期/超次返回 None）。
    pub fn redeem_admin_ticket(&self, ticket: &str) -> Result<Option<AdminTicketRecord>> {
        let hash = sha256_hex(ticket.as_bytes());
        let now = now_rfc3339();
        let conn = self.conn();
        let changed = conn
            .execute(
                "UPDATE admin_ticket SET uses = uses + 1
                 WHERE ticket_hash = ?1 AND uses < max_uses AND expires_at > ?2",
                params![hash, now],
            )
            .map_err(db_err)?;
        if changed == 0 {
            return Ok(None);
        }
        let mut stmt = conn
            .prepare(
                "SELECT kind, subject, scope, expires_at FROM admin_ticket WHERE ticket_hash = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![hash]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(AdminTicketRecord {
                kind: r.get(0).map_err(db_err)?,
                subject: r.get(1).map_err(db_err)?,
                scope: r.get(2).map_err(db_err)?,
                expires_at: r.get(3).map_err(db_err)?,
            }),
            None => None,
        })
    }

    /// 清理过期票据（随每日留存任务执行）。
    pub fn cleanup_admin_tickets(&self) -> Result<usize> {
        let conn = self.conn();
        let n = conn
            .execute(
                "DELETE FROM admin_ticket WHERE expires_at <= ?1",
                params![now_rfc3339()],
            )
            .map_err(db_err)?;
        Ok(n)
    }

    /// 按 ID 取 relay token 哈希（删除联动踢会话用）。
    pub fn get_relay_token_hash(&self, id: &str) -> Result<Option<String>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT token_hash FROM relay_token WHERE id = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(r.get(0).map_err(db_err)?),
            None => None,
        })
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
        let next = current.and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) + 1;
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
    pub fn add_traffic(
        &self,
        account_id: &str,
        bytes_tx: i64,
        bytes_rx: i64,
        connections: i64,
    ) -> Result<()> {
        let conn = self.conn();
        let hour = current_hour_bucket();
        conn.execute(
            "INSERT INTO traffic_log (id, account_id, hour, bytes_tx, bytes_rx, connections)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(account_id, hour) DO UPDATE SET
                bytes_tx = bytes_tx + ?4,
                bytes_rx = bytes_rx + ?5,
                connections = connections + ?6",
            params![
                uuid::Uuid::new_v4().to_string(),
                account_id,
                hour,
                bytes_tx,
                bytes_rx,
                connections
            ],
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

    // ==================== Node Traffic Log（节点级三维流量序列） ====================

    /// 节点级流量差分入库（dim+src+dst+小时桶 upsert 累加；双零增量直接跳过）
    pub fn add_node_traffic(
        &self,
        dim: &str,
        src: &str,
        dst: &str,
        bytes_up: i64,
        bytes_down: i64,
    ) -> Result<()> {
        if bytes_up <= 0 && bytes_down <= 0 {
            return Ok(());
        }
        let conn = self.conn();
        let hour = local_hour_bucket();
        conn.execute(
            "INSERT INTO node_traffic_log (id, dim, src, dst, hour, bytes_up, bytes_down)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(dim, src, dst, hour) DO UPDATE SET
                bytes_up = bytes_up + ?6,
                bytes_down = bytes_down + ?7",
            params![
                uuid::Uuid::new_v4().to_string(),
                dim,
                src,
                dst,
                hour,
                bytes_up,
                bytes_down
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 最近 24h 节点级流量序列（按小时聚合；fanin/fanout 跨标识汇总，transit 跨途径对汇总）
    pub fn node_traffic_24h(&self) -> Result<NodeTraffic24h> {
        let conn = self.conn();
        let since = local_hours_ago(24);
        let mut stmt = conn
            .prepare(
                "SELECT dim, hour, SUM(bytes_up), SUM(bytes_down) FROM node_traffic_log
                 WHERE hour >= ?1 GROUP BY dim, hour ORDER BY hour ASC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![since], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    NodeTrafficPoint {
                        hour: r.get(1)?,
                        up: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                        down: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    },
                ))
            })
            .map_err(db_err)?;
        let mut out = NodeTraffic24h::default();
        for r in rows {
            let (dim, point) = r.map_err(db_err)?;
            match dim.as_str() {
                "fanin" => out.fanin.push(point),
                "fanout" => out.fanout.push(point),
                "transit" => out.transit.push(point),
                _ => {}
            }
        }
        Ok(out)
    }

    /// 清理过期的节点级流量序列（保留 days 天；随日级留存任务调用）
    pub fn cleanup_node_traffic(&self, days: i64) -> Result<usize> {
        let conn = self.conn();
        let cutoff = local_hours_ago(days * 24);
        let n = conn
            .execute(
                "DELETE FROM node_traffic_log WHERE hour < ?1",
                params![cutoff],
            )
            .map_err(db_err)?;
        Ok(n)
    }

    // ==================== Refresh Token ====================

    pub fn store_refresh_token(
        &self,
        jti_hash: &str,
        subject: &str,
        role: &str,
        expires_at: &str,
    ) -> Result<()> {
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

fn map_relay_token_row(r: &rusqlite::Row) -> rusqlite::Result<RelayTokenRecord> {
    Ok(RelayTokenRecord {
        id: r.get(0)?,
        token_prefix: r.get(1)?,
        remark: r.get(2)?,
        expose_control: r.get::<_, i32>(3)? != 0,
        control_scope: r.get(4)?,
        last_used_at: r.get(5)?,
        created_at: r.get(6)?,
        group_id: r.get(7)?,
        group_name: r.get(8)?,
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
        admin_console: r.get::<_, i32>(9)? != 0,
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

/// 当前本地小时桶 'YYYY-MM-DD HH:00'（node_traffic_log / traffic_24h 契约格式）
fn local_hour_bucket() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:00").to_string()
}

/// hours 前的本地小时桶（24h 窗口过滤用）
fn local_hours_ago(hours: i64) -> String {
    let t = chrono::Local::now() - chrono::Duration::hours(hours);
    t.format("%Y-%m-%d %H:00").to_string()
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

/// hex 解码（connector 机器密钥用）
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Other("hex length invalid".into()));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| Error::Other(e.to_string()))
        })
        .collect()
}

fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| Error::Other(e.to_string()))
}

/// token 前缀展示位（前 8 字符，仅用于列表辨认）
fn token_prefix_of(plain: &str) -> String {
    plain.chars().take(8).collect()
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

// ==================== 测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    /// 建一个权限组，返回 id
    fn mk_group(db: &Database, name: &str) -> String {
        db.create_group(name, "").expect("create group").id
    }

    #[test]
    fn migration_v4_upgrades_old_db() {
        // 构造一个只应用过 v1~v3 的旧库文件
        let path = std::env::temp_dir().join(format!("anet-db-mig-test-{}.db", uuid::Uuid::new_v4()));
        {
            let conn = rusqlite::Connection::open(&path).expect("open raw conn");
            conn.execute_batch(
                "CREATE TABLE _migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
                );",
            )
            .unwrap();
            for (version, name, sql) in MIGRATIONS.iter().take(3) {
                conn.execute_batch(sql).unwrap();
                conn.execute(
                    "INSERT INTO _migration (version, name) VALUES (?1, ?2)",
                    params![version, name],
                )
                .unwrap();
            }
            // 旧 schema 下插入一条 relay_token（无 group_id 列）
            conn.execute(
                "INSERT INTO relay_token (id, token_hash, token_prefix, remark, expose_control, control_scope, created_at)
                 VALUES ('tok-old', 'hash-old', 'psk_abcd', 'legacy', 0, 'full', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // 打开即触发 v4 迁移：旧行保留、新列为 NULL（不收敛）、connector 表可用
        {
            let db = Database::open(&path).expect("open migrated db");
            let tok = db
                .get_relay_token("tok-old")
                .expect("get")
                .expect("old token exists");
            assert_eq!(tok.token_prefix, "psk_abcd");
            assert_eq!(tok.group_id, None);
            assert_eq!(tok.group_name, None);
            assert!(db.list_connectors().expect("connector table").is_empty());

            // 迁移后旧行可直接挂组
            let gid = mk_group(&db, "g1");
            db.set_relay_token_group("tok-old", Some(&gid)).expect("set group");
            let tok = db.get_relay_token("tok-old").expect("get2").unwrap();
            assert_eq!(tok.group_id.as_deref(), Some(gid.as_str()));
            assert_eq!(tok.group_name.as_deref(), Some("g1"));
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn secret_encrypt_decrypt_roundtrip() {
        let db = Database::in_memory().unwrap();
        let plain = "psk_0123456789abcdef0123456789abcdef0123456789abcdef";
        let enc1 = db.encrypt_secret(plain).unwrap();
        let enc2 = db.encrypt_secret(plain).unwrap();
        // 随机 nonce：同明文两次密文不同，且带版本前缀
        assert_ne!(enc1, enc2);
        assert!(enc1.starts_with("v1:"));
        assert_eq!(db.decrypt_secret(&enc1).unwrap(), plain);
        assert_eq!(db.decrypt_secret(&enc2).unwrap(), plain);
        // 机器密钥已持久化到 node_config
        assert!(
            db.get_config("connector_token_key")
                .unwrap()
                .is_some_and(|k| k.len() == 64)
        );
        // 非法格式/版本/密文均报错
        assert!(db.decrypt_secret("garbage").is_err());
        assert!(db.decrypt_secret("v2:AAAA:BBBB").is_err());
        assert!(db.decrypt_secret("v1:AAAA:BBBB").is_err());
        // 密钥不同则无法解密（另一库实例）
        let db2 = Database::in_memory().unwrap();
        assert!(db2.decrypt_secret(&enc1).is_err());
    }

    #[test]
    fn connector_crud_full_path() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "peers");
        let token = "psk_connector-token-0123456789abcdef";

        // create
        let rec = db
            .create_connector(
                "site-a",
                "1.2.3.4:54430",
                token,
                "a.example.com",
                false,
                "/etc/anet/ca.pem",
                "",
                "10.0.0.0/8",
                Some(&gid),
                "站点 A",
            )
            .expect("create connector");
        assert!(rec.enabled);
        assert_eq!(rec.group_id.as_deref(), Some(gid.as_str()));
        assert_eq!(rec.ca_cert_path, "/etc/anet/ca.pem");
        assert_eq!(rec.pinned_cert_path, "");
        // 密文落库：不是明文、带版本前缀
        assert!(rec.token_enc.starts_with("v1:"));
        assert!(!rec.token_enc.contains(token));

        // get / get_connector_secret（解密回明文）
        let got = db.get_connector(&rec.id).unwrap().expect("get connector");
        assert_eq!(got.name, "site-a");
        assert_eq!(db.get_connector_secret(&rec.id).unwrap(), token);

        // list（视图带组名与前缀展示位，不含明文/密文）
        let views = db.list_connectors().unwrap();
        assert_eq!(views.len(), 1);
        let v = &views[0];
        assert_eq!(v.group_name.as_deref(), Some("peers"));
        assert_eq!(v.token_prefix, "psk_conn");
        let json = serde_json::to_string(v).unwrap();
        assert!(!json.contains(token));
        assert!(!json.contains("token_enc"));

        // update：token None = 保留原 token，其余字段全改
        db.update_connector(
            &rec.id,
            "site-a2",
            "5.6.7.8:54430",
            None,
            "",
            true,
            "",
            "/etc/anet/pinned.pem",
            "",
            None,
            "改名",
        )
        .expect("update keep token");
        let got = db.get_connector(&rec.id).unwrap().unwrap();
        assert_eq!(got.name, "site-a2");
        assert!(got.insecure);
        assert_eq!(got.ca_cert_path, "");
        assert_eq!(got.pinned_cert_path, "/etc/anet/pinned.pem");
        assert_eq!(got.group_id, None);
        assert_eq!(db.get_connector_secret(&rec.id).unwrap(), token);

        // update：显式重置 token
        let token2 = "psk_rotated-token-abcdef0123456789";
        db.update_connector(
            &rec.id,
            "site-a2",
            "5.6.7.8:54430",
            Some(token2),
            "",
            true,
            "",
            "",
            "",
            None,
            "",
        )
        .expect("update rotate token");
        assert_eq!(db.get_connector_secret(&rec.id).unwrap(), token2);

        // set_enabled / delete
        db.set_connector_enabled(&rec.id, false).expect("disable");
        assert!(!db.get_connector(&rec.id).unwrap().unwrap().enabled);
        db.delete_connector(&rec.id).expect("delete");
        assert!(db.get_connector(&rec.id).unwrap().is_none());
        assert!(db.list_connectors().unwrap().is_empty());
    }

    #[test]
    fn import_connector_if_absent_skips_existing() {
        let db = Database::in_memory().unwrap();
        let first = db
            .import_connector_if_absent(
                "site-a",
                "1.2.3.4:54430",
                "psk_first",
                "",
                false,
                "",
                "",
                "",
                None,
                "toml 导入",
            )
            .expect("first import");
        assert!(first);
        // 同名存在则跳过，且原记录不被覆盖
        let second = db
            .import_connector_if_absent(
                "site-a",
                "9.9.9.9:54430",
                "psk_second",
                "",
                false,
                "",
                "",
                "",
                None,
                "",
            )
            .expect("second import");
        assert!(!second);
        let views = db.list_connectors().unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].upstream_addr, "1.2.3.4:54430");
    }

    #[test]
    fn relay_token_group_mount() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "peers");
        let hash = sha256_hex(b"tok-plain");

        // 带组创建
        let rec = db
            .create_relay_token_with_group(&hash, "psk_abcd", "带组", false, "full", Some(&gid))
            .expect("create with group");
        assert_eq!(rec.group_id.as_deref(), Some(gid.as_str()));

        // list / 详情带出组 ID 与组名
        let list = db.list_relay_tokens().unwrap();
        assert_eq!(list[0].group_id.as_deref(), Some(gid.as_str()));
        assert_eq!(list[0].group_name.as_deref(), Some("peers"));
        let detail = db.get_relay_token(&rec.id).unwrap().unwrap();
        assert_eq!(detail.group_name.as_deref(), Some("peers"));

        // 按哈希查收敛组（数据面）：Some(Some(gid))
        assert_eq!(
            db.get_relay_token_group(&hash).unwrap().flatten().as_deref(),
            Some(gid.as_str())
        );

        // 改为不收敛：Some(None)
        db.set_relay_token_group(&rec.id, None).expect("clear group");
        let g = db.get_relay_token_group(&hash).unwrap();
        assert!(matches!(g, Some(None)));
        assert_eq!(db.get_relay_token(&rec.id).unwrap().unwrap().group_id, None);

        // 旧方法委托：默认不收敛
        let rec2 = db
            .create_relay_token_full(&sha256_hex(b"tok2"), "psk_efgh", "", false, "full")
            .expect("create full");
        assert_eq!(rec2.group_id, None);
        // 不存在的哈希：None
        assert_eq!(db.get_relay_token_group("no-such-hash").unwrap(), None);
    }

    #[test]
    fn migration_v5_upgrades_old_db() {
        // 构造一个只应用过 v1~v4 的旧库文件（connector 表无证书路径列）
        let path = std::env::temp_dir().join(format!("anet-db-mig5-test-{}.db", uuid::Uuid::new_v4()));
        {
            let conn = rusqlite::Connection::open(&path).expect("open raw conn");
            conn.execute_batch(
                "CREATE TABLE _migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
                );",
            )
            .unwrap();
            for (version, name, sql) in MIGRATIONS.iter().take(4) {
                conn.execute_batch(sql).unwrap();
                conn.execute(
                    "INSERT INTO _migration (version, name) VALUES (?1, ?2)",
                    params![version, name],
                )
                .unwrap();
            }
            // 旧 schema 下插入一条 connector（无 ca_cert_path / pinned_cert_path 列）
            conn.execute(
                "INSERT INTO connector (id, name, upstream_addr, token_enc, sni_hostname, insecure, advertise, group_id, enabled, remark, created_at, updated_at)
                 VALUES ('conn-old', 'site-old', '1.2.3.4:54430', 'v1:AAAA:BBBB', '', 1, '', NULL, 1, 'legacy', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // 打开即触发 v5 迁移：旧行保留、新列默认为空串
        {
            let db = Database::open(&path).expect("open migrated db");
            let rec = db
                .get_connector("conn-old")
                .expect("get")
                .expect("old connector exists");
            assert_eq!(rec.name, "site-old");
            assert_eq!(rec.ca_cert_path, "");
            assert_eq!(rec.pinned_cert_path, "");

            // 迁移后可直接写入证书路径
            db.update_connector(
                "conn-old",
                "site-old",
                "1.2.3.4:54430",
                None,
                "",
                false,
                "/etc/anet/ca.pem",
                "",
                "",
                None,
                "",
            )
            .expect("update cert path");
            let rec = db.get_connector("conn-old").unwrap().unwrap();
            assert_eq!(rec.ca_cert_path, "/etc/anet/ca.pem");
            // list 视图同样带出新列
            let views = db.list_connectors().unwrap();
            assert_eq!(views.len(), 1);
            assert_eq!(views[0].ca_cert_path, "/etc/anet/ca.pem");
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn node_traffic_add_aggregate_and_cleanup() {
        let db = Database::in_memory().unwrap();

        // 双零增量跳过（不落库）
        db.add_node_traffic("fanin", "n1", "", 0, 0).unwrap();
        assert!(db.node_traffic_24h().unwrap().fanin.is_empty());

        // 同桶累加 + 跨标识/途径对写入
        db.add_node_traffic("fanin", "n1", "", 100, 200).unwrap();
        db.add_node_traffic("fanin", "n1", "", 1, 2).unwrap();
        db.add_node_traffic("fanin", "n2", "", 50, 60).unwrap();
        db.add_node_traffic("fanout", "up-a", "", 7, 8).unwrap();
        db.add_node_traffic("transit", "n1", "n2", 3, 4).unwrap();
        db.add_node_traffic("transit", "proxy", "local", 5, 6).unwrap();

        let agg = db.node_traffic_24h().unwrap();
        // fanin 跨对端汇总为同一小时桶
        assert_eq!(agg.fanin.len(), 1);
        assert_eq!(agg.fanin[0].up, 151);
        assert_eq!(agg.fanin[0].down, 262);
        // 小时桶为本地时间格式 'YYYY-MM-DD HH:00'
        assert_eq!(agg.fanin[0].hour.len(), 16);
        assert!(agg.fanin[0].hour.ends_with(":00"));
        assert_eq!(&agg.fanin[0].hour[10..11], " ");
        assert_eq!(agg.fanout.len(), 1);
        assert_eq!(agg.fanout[0].up, 7);
        // transit 跨途径对汇总
        assert_eq!(agg.transit.len(), 1);
        assert_eq!(agg.transit[0].up, 8);
        assert_eq!(agg.transit[0].down, 10);

        // 留存清理：40 天前的旧行删除，当前行保留
        let old_hour = (chrono::Local::now() - chrono::Duration::days(40))
            .format("%Y-%m-%d %H:00")
            .to_string();
        db.conn()
            .execute(
                "INSERT INTO node_traffic_log (id, dim, src, dst, hour, bytes_up, bytes_down)
                 VALUES (?1, 'fanin', 'old-peer', '', ?2, 9, 9)",
                params![uuid::Uuid::new_v4().to_string(), old_hour],
            )
            .unwrap();
        let removed = db.cleanup_node_traffic(30).unwrap();
        assert_eq!(removed, 1);
        // 24h 聚合不含旧行
        let agg = db.node_traffic_24h().unwrap();
        assert_eq!(agg.fanin.len(), 1);
        assert_eq!(agg.fanin[0].up, 151);
    }
}
