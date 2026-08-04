//! Split from db/mod.rs: versioned migrations (pure move, no logic change)

use super::pool::{Database, db_err};
use agile_net_core::error::Result;
use rusqlite::params;
use tracing::info;

/// Current schema version (monotonic; append new migrations to the end of MIGRATIONS).
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
    -- Admin connect URL: an account may be granted the "manage this node" permission
    ALTER TABLE account ADD COLUMN admin_console INTEGER NOT NULL DEFAULT 0;

    -- Admin bootstrap ticket: one-time (or time-limited) credential exchanged for an admin
    -- session via the console channel / relay exposure. Only the SHA-256 hash is stored;
    -- the plaintext is returned once at issuance.
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
    -- "Expose control plane" switch for relay links: allow this fan-in relay to manage this node (default off)
    ALTER TABLE relay_token ADD COLUMN expose_control INTEGER NOT NULL DEFAULT 0;
    -- Admin grant scope: ro (read-only) / rules (read-only + rule write) / full (full access)
    ALTER TABLE relay_token ADD COLUMN control_scope TEXT NOT NULL DEFAULT 'full';
    "#,
    ),
    (
        4,
        "peer_acl_connector",
        r#"
    -- ACL mount point for fan-in peers (NULL = no restriction, allow all)
    ALTER TABLE relay_token ADD COLUMN group_id TEXT REFERENCES "group"(id);

    -- Fan-out connectors in DB (first-class resource; token_enc stored encrypted, see docs/todo/peer-acl.md §4/§5)
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
    -- Align fan-out connector cert-pinning capability with core ConnectorConfig (columns missed in design doc §4;
    -- empty string = unused; precedence pinned > ca > insecure matches the TOML assembly logic)
    ALTER TABLE connector ADD COLUMN ca_cert_path TEXT NOT NULL DEFAULT '';
    ALTER TABLE connector ADD COLUMN pinned_cert_path TEXT NOT NULL DEFAULT '';
    "#,
    ),
    (
        6,
        "node_traffic_log",
        r#"
    -- Node-level hourly traffic series (3 dims: fan-in peer / fan-out / relay transit; per-account traffic stays in traffic_log, unaffected)
    -- dim: fanin=fan-in peer (src=peer node_id) / fanout=fan-out (src=connector name)
    --      / transit=relay transit (src=origin, dst=terminus)
    -- hour is a local-time bucket 'YYYY-MM-DD HH:00' (status traffic_24h contract format)
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
    -- Relay token bandwidth quota (KB/s; NULL = unlimited). Fan-in session rate limiting enforced by core TokenBucket.
    ALTER TABLE relay_token ADD COLUMN rate_limit_kbps INTEGER;
    "#,
    ),
    (
        8,
        "connector_pinned_fingerprint",
        r#"
    -- Fan-out cert fingerprint pinning (SHA-256 hex, distributed out-of-band; empty = unused).
    -- Lets connectors verify self-signed mimicry certs without insecure or cert files.
    ALTER TABLE connector ADD COLUMN pinned_fingerprint TEXT NOT NULL DEFAULT '';
    "#,
    ),
    (
        9,
        "connector_push_groups",
        r#"
    -- Policy upload (federation P1): local group IDs pushed upstream with the fan-out handshake
    -- (comma-separated; empty = no upload). The upstream pools them source-tagged for one-click adoption.
    ALTER TABLE connector ADD COLUMN push_groups TEXT NOT NULL DEFAULT '';
    "#,
    ),
];

impl Database {
    /// Run versioned migrations
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

    /// Create a group, return its id
    fn mk_group(db: &Database, name: &str) -> String {
        db.create_group(name, "").expect("create group").id
    }

    #[test]
    fn migration_v4_upgrades_old_db() {
        // Build a legacy DB file with only v1~v3 applied
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
            // Insert a relay_token under the old schema (no group_id column)
            conn.execute(
                "INSERT INTO relay_token (id, token_hash, token_prefix, remark, expose_control, control_scope, created_at)
                 VALUES ('tok-old', 'hash-old', 'psk_abcd', 'legacy', 0, 'full', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // Opening triggers v4 migration: old rows kept, new columns NULL (unrestricted), connector table usable
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

            // After migration, old rows can be attached to a group directly
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
        // Build a legacy DB file with only v1~v4 applied (connector table without cert path columns)
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
            // Insert a connector under the old schema (no ca_cert_path / pinned_cert_path columns)
            conn.execute(
                "INSERT INTO connector (id, name, upstream_addr, token_enc, sni_hostname, insecure, advertise, group_id, enabled, remark, created_at, updated_at)
                 VALUES ('conn-old', 'site-old', '1.2.3.4:54430', 'v1:AAAA:BBBB', '', 1, '', NULL, 1, 'legacy', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // Opening triggers v5 migration: old rows kept, new columns default to empty string
        {
            let db = Database::open(&path).expect("open migrated db");
            let rec = db
                .get_connector("conn-old")
                .expect("get")
                .expect("old connector exists");
            assert_eq!(rec.name, "site-old");
            assert_eq!(rec.ca_cert_path, "");
            assert_eq!(rec.pinned_cert_path, "");
            assert_eq!(rec.pinned_fingerprint, "");

            // After migration, cert paths can be written directly
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
                "",
                None,
                "",
            )
            .expect("update cert path");
            let rec = db.get_connector("conn-old").unwrap().unwrap();
            assert_eq!(rec.ca_cert_path, "/etc/anet/ca.pem");
            // The list view also carries the new columns
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
        // Build a legacy DB file with only v1~v6 applied (relay_token without rate_limit_kbps column)
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
            // Insert a relay_token under the old schema (no rate_limit_kbps column)
            conn.execute(
                "INSERT INTO relay_token (id, token_hash, token_prefix, remark, expose_control, control_scope, created_at)
                 VALUES ('tok-old', 'hash-old', 'psk_abcd', 'legacy', 0, 'full', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();
        }

        // Opening triggers v7 migration: old rows kept, new column NULL (unlimited)
        {
            let db = Database::open(&path).expect("open migrated db");
            let tok = db
                .get_relay_token("tok-old")
                .expect("get")
                .expect("old token exists");
            assert_eq!(tok.token_prefix, "psk_abcd");
            assert_eq!(tok.rate_limit_kbps, None);
            assert_eq!(db.get_relay_token_rate_limit("hash-old").unwrap(), None);

            // After migration, quota can be set/cleared on old rows directly
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
