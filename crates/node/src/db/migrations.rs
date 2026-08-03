//! 从 db/mod.rs 拆分：版本化迁移（纯搬运，零逻辑变更）

use super::pool::{Database, db_err};
use agile_net_core::error::Result;
use rusqlite::params;
use tracing::info;

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
    (
        7,
        "relay_token_rate_limit",
        r#"
    -- Relay Token 带宽配额（KB/s；NULL = 不限）。扇入会话限速由 core TokenBucket 执行。
    ALTER TABLE relay_token ADD COLUMN rate_limit_kbps INTEGER;
    "#,
    ),
];

impl Database {
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
}

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
    fn migration_v7_upgrades_old_db() {
        // 构造一个只应用过 v1~v6 的旧库文件（relay_token 无 rate_limit_kbps 列）
        let path = std::env::temp_dir().join(format!("anet-db-mig7-test-{}.db", uuid::Uuid::new_v4()));
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
            for (version, name, sql) in MIGRATIONS.iter().take(6) {
                conn.execute_batch(sql).unwrap();
                conn.execute(
                    "INSERT INTO _migration (version, name) VALUES (?1, ?2)",
                    params![version, name],
                )
                .unwrap();
            }
            // 旧 schema 下插入一条 relay_token（无 rate_limit_kbps 列）
            conn.execute(
                "INSERT INTO relay_token (id, token_hash, token_prefix, remark, expose_control, control_scope, created_at)
                 VALUES ('tok-old', 'hash-old', 'psk_abcd', 'legacy', 0, 'full', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // 打开即触发 v7 迁移：旧行保留、新列为 NULL（不限速）
        {
            let db = Database::open(&path).expect("open migrated db");
            let tok = db
                .get_relay_token("tok-old")
                .expect("get")
                .expect("old token exists");
            assert_eq!(tok.token_prefix, "psk_abcd");
            assert_eq!(tok.rate_limit_kbps, None);
            assert_eq!(db.get_relay_token_rate_limit("hash-old").unwrap(), None);

            // 迁移后旧行可直接设置/清除配额
            db.set_relay_token_rate_limit("tok-old", Some(10240))
                .expect("set rate limit");
            let tok = db.get_relay_token("tok-old").unwrap().unwrap();
            assert_eq!(tok.rate_limit_kbps, Some(10240));
            assert_eq!(
                db.get_relay_token_rate_limit("hash-old").unwrap(),
                Some(10240)
            );
            db.set_relay_token_rate_limit("tok-old", None)
                .expect("clear rate limit");
            assert_eq!(
                db.get_relay_token("tok-old").unwrap().unwrap().rate_limit_kbps,
                None
            );
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }
}
