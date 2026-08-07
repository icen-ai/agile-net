//! Split from db/mod.rs: versioned migrations (pure move, no logic change)
//!
//! The pre-release migration chain (v1~v15) is collapsed into a single baseline v1 holding the
//! final schema; the version-table mechanism stays in place for post-release upgrades (append
//! new entries to the end of MIGRATIONS, never edit the baseline).

use super::pool::{Database, db_err};
use agile_net_core::error::Result;
use rusqlite::params;
use tracing::info;

/// Current schema version (monotonic; append new migrations to the end of MIGRATIONS).
const MIGRATIONS: &[(u32, &str, &str)] = &[(
    1,
    "baseline",
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
        id           TEXT PRIMARY KEY,
        name         TEXT NOT NULL,
        remark       TEXT NOT NULL DEFAULT '',
        e2e_required INTEGER NOT NULL DEFAULT 0,
        adopted_node TEXT NOT NULL DEFAULT '',
        adopted_name TEXT NOT NULL DEFAULT '',
        created_at   TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );
    -- Naming sovereignty: the name stays clean (source name); the adoption source rides the
    -- adopted_node lineage, never the name. Uniqueness needs two PARTIAL indexes — SQLite
    -- treats NULLs as distinct, and adopted_node is '' (not NULL) for local groups, so a single
    -- UNIQUE(name, adopted_node) would not work: local groups unique by name alone, adopted
    -- mirrors unique per (name, source node); a local and an adopted group may share a name
    -- (the UI distinguishes them with a source badge).
    CREATE UNIQUE INDEX idx_group_name_local ON "group"(name) WHERE adopted_node = '';
    CREATE UNIQUE INDEX idx_group_name_adopted ON "group"(name, adopted_node) WHERE adopted_node != '';

    CREATE TABLE group_rule (
        group_id TEXT NOT NULL REFERENCES "group"(id) ON DELETE CASCADE,
        rule_id  TEXT NOT NULL REFERENCES rule(id) ON DELETE CASCADE,
        PRIMARY KEY (group_id, rule_id)
    );
    CREATE INDEX idx_group_rule_rule ON group_rule(rule_id);

    -- Fan-in relay token. group_id holds a comma-separated group set (multi-group ACL; no FK —
    -- dangling ids converge to deny-all in the ACL registry). Lifecycle: expires_at / max_uses /
    -- used_count (NULL = never expires / unlimited).
    CREATE TABLE relay_token (
        id              TEXT PRIMARY KEY,
        token_hash      TEXT NOT NULL UNIQUE,
        token_prefix    TEXT NOT NULL,
        remark          TEXT NOT NULL DEFAULT '',
        last_used_at    TEXT,
        expose_control  INTEGER NOT NULL DEFAULT 0,
        control_scope   TEXT NOT NULL DEFAULT 'full',
        group_id        TEXT,
        rate_limit_kbps INTEGER,
        expires_at      TEXT,
        max_uses        INTEGER,
        used_count      INTEGER NOT NULL DEFAULT 0,
        created_at      TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE node_config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
    );
    -- Unified issuance: default session cap snapshotted into delegated_token.max_sessions at issue time
    INSERT INTO node_config (key, value) VALUES ('delegation_max_sessions', '8');

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

    CREATE TABLE refresh_token (
        jti_hash   TEXT PRIMARY KEY,
        subject    TEXT NOT NULL,
        role       TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked    INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Admin bootstrap ticket: one-time (or time-limited) credential exchanged for an admin
    -- session via the relay-exposed control plane / delegation admin channel. Only the
    -- SHA-256 hash is stored; the plaintext is returned once at issuance.
    CREATE TABLE admin_ticket (
        id          TEXT PRIMARY KEY,
        ticket_hash TEXT NOT NULL UNIQUE,
        kind        TEXT NOT NULL CHECK(kind IN ('relay')),
        subject     TEXT NOT NULL,
        scope       TEXT NOT NULL DEFAULT 'full' CHECK(scope IN ('ro','rules','full')),
        uses        INTEGER NOT NULL DEFAULT 0,
        max_uses    INTEGER NOT NULL DEFAULT 1,
        expires_at  TEXT NOT NULL,
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_admin_ticket_exp ON admin_ticket(expires_at);

    -- Fan-out connectors (first-class resource; token_enc stored encrypted). group_id holds a
    -- comma-separated group set (same multi-group ACL semantics as relay_token; no FK).
    CREATE TABLE connector (
        id                 TEXT PRIMARY KEY,
        name               TEXT NOT NULL UNIQUE,
        my_name            TEXT NOT NULL DEFAULT '', -- self-declared name uploaded to the peer at auth (empty = node_id)
        upstream_addr      TEXT NOT NULL,
        token_enc          TEXT NOT NULL,
        sni_hostname       TEXT NOT NULL DEFAULT '',
        insecure           INTEGER NOT NULL DEFAULT 0,
        advertise          TEXT NOT NULL DEFAULT '',
        group_id           TEXT,
        enabled            INTEGER NOT NULL DEFAULT 1,
        remark             TEXT NOT NULL DEFAULT '',
        ca_cert_path       TEXT NOT NULL DEFAULT '',
        pinned_cert_path   TEXT NOT NULL DEFAULT '',
        pinned_fingerprint TEXT NOT NULL DEFAULT '',
        push_groups        TEXT NOT NULL DEFAULT '',
        cert_relay         INTEGER NOT NULL DEFAULT 0, -- transitive certification opt-in (node.md M6,双向开关)
        created_at         TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_connector_group ON connector(group_id);

    -- Node-level hourly traffic series (3 dims: fan-in peer / fan-out / relay transit)
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

    -- Delegated tokens (unified issuance): the resource owner issues consumer credentials
    -- directly. entry_mode: 'direct' (consumer dials this issuer's own listener, local
    -- registration) | 'relay' (registered upstream over the fan-out session, disaster set).
    -- concurrency: 'single' (a new session kicks the old) | 'multi' (up to max_sessions).
    -- max_sessions snapshots node_config.delegation_max_sessions at issue time.
    -- groups = JSON array of local group IDs; hint_map = JSON array of {hint, groups}
    -- (entrust words only; empty for the transparent tier); e2e_key_enc = E2E channel master
    -- key, AES-256-GCM encrypted like connector tokens.
    -- visibility (node.md M6): topology disclosure tier of this grant — 'domain' (default:
    -- only the domain principal is visible upstream) | 'disclose' | 'approve'.
    CREATE TABLE delegated_token (
        id           TEXT PRIMARY KEY,
        token_hash   TEXT NOT NULL UNIQUE,
        token_prefix TEXT NOT NULL,
        label        TEXT NOT NULL DEFAULT '',
        groups       TEXT NOT NULL DEFAULT '[]',
        hint_map     TEXT NOT NULL DEFAULT '[]',
        e2e_key_enc  TEXT NOT NULL DEFAULT '',
        mode         TEXT NOT NULL DEFAULT 'dedicated',
        admin_scope  TEXT NOT NULL DEFAULT '',
        entry_mode   TEXT NOT NULL DEFAULT 'relay' CHECK(entry_mode IN ('direct','relay')),
        concurrency  TEXT NOT NULL DEFAULT 'single' CHECK(concurrency IN ('single','multi')),
        max_sessions INTEGER NOT NULL DEFAULT 8,
        visibility   TEXT NOT NULL DEFAULT 'domain' CHECK(visibility IN ('domain','disclose','approve')),
        expires_at   TEXT,
        max_uses     INTEGER,
        used_count   INTEGER NOT NULL DEFAULT 0,
        created_at   TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Disaster-set registration of relay-entry tokens: one row per upstream connector
    -- (is_primary=1 marks the primary entry); re-registered on every fan-out (re)connect.
    CREATE TABLE delegated_token_reg (
        token_id     TEXT NOT NULL REFERENCES delegated_token(id) ON DELETE CASCADE,
        connector_id TEXT NOT NULL REFERENCES connector(id) ON DELETE CASCADE,
        is_primary   INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (token_id, connector_id)
    );

    -- Device registry (node.md M2): every device that proved itself at the handshake
    -- (device_fp = sha256 of the device ed25519 pubkey, derived by us at auth — never trusted
    -- from the wire). Devices bind at certification to a logical HOLDER (subject): one subject
    -- may hold several devices (加绑) and stats follow the subject across device replacement
    -- (换绑 = certify new + migrate subject/remark + revoke old). state: pending (default,
    -- awaiting certification) / certified / revoked (terminal, never reusable).
    CREATE TABLE device_registry (
        id           TEXT PRIMARY KEY,
        device_fp    TEXT NOT NULL UNIQUE,
        pubkey       TEXT NOT NULL,              -- raw ed25519 pubkey (base64; OpenSSH export at UI)
        token_hash   TEXT NOT NULL DEFAULT '',   -- credential of the latest session
        subject      TEXT NOT NULL DEFAULT '',   -- logical holder (assigned at certification)
        my_name      TEXT NOT NULL DEFAULT '',   -- device's self-declared name (decorative)
        remark       TEXT NOT NULL DEFAULT '',   -- admin certification remark (the capsule title)
        state        TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','certified','revoked')),
        certified_by TEXT NOT NULL DEFAULT '',   -- ''=local admin, else origin node id (M6 transitive)
        certified_at TEXT,
        -- M6 transitive lineage: kept verbatim so middle hops can forward the ORIGINAL
        -- origin-signed record (blind relay — a middle hop cannot re-sign for the origin)
        origin_pubkey TEXT NOT NULL DEFAULT '',
        cert_sig     TEXT NOT NULL DEFAULT '',
        cert_ts      TEXT NOT NULL DEFAULT '',
        first_seen   TEXT NOT NULL DEFAULT (datetime('now')),
        last_seen    TEXT NOT NULL DEFAULT (datetime('now')),
        bytes_up     INTEGER NOT NULL DEFAULT 0, -- cumulative traffic (B 口径, flushed at session close)
        bytes_down   INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX idx_device_registry_state ON device_registry(state);
    CREATE INDEX idx_device_registry_subject ON device_registry(subject);

    -- Approval center (node.md M3): every human-adjudication event funnels here; types are
    -- pluggable (device_certify / device_rebind / ref_cert_adopt / topo_approve ...).
    CREATE TABLE approval (
        id          TEXT PRIMARY KEY,
        type        TEXT NOT NULL,
        state       TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','approved','rejected')),
        object_ref  TEXT NOT NULL DEFAULT '',  -- device_fp / token id / cert hash ...
        requester   TEXT NOT NULL DEFAULT '',  -- who asked (device_fp / node_id)
        detail      TEXT NOT NULL DEFAULT '',  -- type-specific JSON payload
        decided_by  TEXT NOT NULL DEFAULT '',
        decided_at  TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_approval_state ON approval(state);

    -- Appeal/decision messages of an approval item: applicant appeals (≤3 per session,
    -- Ctrl PendingNote uplink) + the final one-time operator notice (immutable once sent).
    CREATE TABLE approval_message (
        id          TEXT PRIMARY KEY,
        approval_id TEXT NOT NULL REFERENCES approval(id) ON DELETE CASCADE,
        direction   TEXT NOT NULL CHECK(direction IN ('appeal','notice')),
        body        TEXT NOT NULL,
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_approval_msg ON approval_message(approval_id);

    -- Per-session device traffic ledger (node.md M5): one row flushed at session close —
    -- traffic time series, session history and the 7x24 activity heatmap all read this table.
    CREATE TABLE device_session (
        id           TEXT PRIMARY KEY,
        device_fp    TEXT NOT NULL,
        token_hash   TEXT NOT NULL DEFAULT '',
        entry        TEXT NOT NULL DEFAULT '',   -- direct / relay·<node>
        ip           TEXT NOT NULL DEFAULT '',
        started_at   TEXT NOT NULL,
        ended_at     TEXT NOT NULL DEFAULT (datetime('now')),
        bytes_in     INTEGER NOT NULL DEFAULT 0,
        bytes_out    INTEGER NOT NULL DEFAULT 0,
        close_reason TEXT NOT NULL DEFAULT ''    -- M2 reason_code (kicked / revoked / ...)
    );
    CREATE INDEX idx_device_session_fp ON device_session(device_fp, started_at);
    CREATE INDEX idx_device_session_time ON device_session(started_at);

    -- Topology-visibility grant receipts (node.md M6): disclosure records of granted artifacts,
    -- signed by the origin node's relay key and blindly relayed by intermediates.
    CREATE TABLE grant_receipt (
        id           TEXT PRIMARY KEY,
        artifact_ref TEXT NOT NULL,              -- token_hash / group id / cert hash
        holder       TEXT NOT NULL,              -- holder node_id / device_fp
        lineage      TEXT NOT NULL DEFAULT '[]', -- JSON lineage segments (relay path)
        visibility   TEXT NOT NULL DEFAULT 'domain' CHECK(visibility IN ('domain','disclose','approve')),
        origin_sig   TEXT NOT NULL DEFAULT '',   -- origin signature over the record
        state        TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','confirmed','stopped')),
        created_at   TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(artifact_ref, holder)
    );
    "#,
)];

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

    /// Names of every user table in the database (migration bookkeeping excluded).
    fn table_names(db: &Database) -> Vec<String> {
        let conn = db.conn();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_migration' ESCAPE '\\' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    /// Column names of one table (PRAGMA table_info; quoted — `group` is a SQL keyword).
    fn column_names(db: &Database, table: &str) -> Vec<String> {
        let conn = db.conn();
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(1)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    #[test]
    fn baseline_creates_final_schema() {
        let db = Database::in_memory().expect("in-memory db");
        let mut tables = table_names(&db);
        tables.sort();
        assert_eq!(
            tables,
            vec![
                "admin",
                "admin_ticket",
                "approval",
                "approval_message",
                "audit_log",
                "connector",
                "delegated_token",
                "delegated_token_reg",
                "device_registry",
                "device_session",
                "grant_receipt",
                "group",
                "group_rule",
                "node_config",
                "node_traffic_log",
                "refresh_token",
                "relay_token",
                "rule",
            ],
            "baseline table set (no account / traffic_log)"
        );

        // relay_token / connector are created directly in their final (post-v14/v15) shape
        for col in [
            "expose_control",
            "control_scope",
            "group_id",
            "rate_limit_kbps",
            "expires_at",
            "max_uses",
            "used_count",
        ] {
            assert!(
                column_names(&db, "relay_token").contains(&col.to_string()),
                "relay_token.{col}"
            );
        }
        for col in [
            "ca_cert_path",
            "pinned_cert_path",
            "pinned_fingerprint",
            "push_groups",
            "my_name",
        ] {
            assert!(
                column_names(&db, "connector").contains(&col.to_string()),
                "connector.{col}"
            );
        }

        // delegated_token carries the unified-issuance columns
        let cols = column_names(&db, "delegated_token");
        for col in [
            "mode",
            "admin_scope",
            "entry_mode",
            "concurrency",
            "max_sessions",
            "visibility",
            "expires_at",
            "max_uses",
            "used_count",
        ] {
            assert!(cols.contains(&col.to_string()), "delegated_token.{col}");
        }

        // device identity + approval + device-traffic baseline tables (node.md M2/M5/M6)
        let cols = column_names(&db, "device_registry");
        for col in [
            "device_fp",
            "pubkey",
            "subject",
            "my_name",
            "state",
            "certified_by",
            "bytes_up",
            "bytes_down",
        ] {
            assert!(cols.contains(&col.to_string()), "device_registry.{col}");
        }
        for col in ["type", "state", "object_ref", "requester", "decided_by"] {
            assert!(
                column_names(&db, "approval").contains(&col.to_string()),
                "approval.{col}"
            );
        }
        assert!(
            column_names(&db, "device_session").contains(&"close_reason".to_string()),
            "device_session.close_reason"
        );
        assert!(
            column_names(&db, "connector").contains(&"cert_relay".to_string()),
            "connector.cert_relay"
        );

        // group carries the e2e flag + adoption lineage
        let cols = column_names(&db, "group");
        for col in ["e2e_required", "adopted_node", "adopted_name"] {
            assert!(cols.contains(&col.to_string()), "group.{col}");
        }

        // unified-issuance default: session cap source for issuance snapshots
        assert_eq!(
            db.get_config("delegation_max_sessions").unwrap().as_deref(),
            Some("8")
        );
    }

    #[test]
    fn baseline_migrate_is_idempotent() {
        let path = std::env::temp_dir().join(format!("anet-db-baseline-test-{}.db", uuid::Uuid::new_v4()));
        {
            let db = Database::open(&path).expect("first open");
            db.set_config("sentinel", "1").unwrap();
        }
        // second open: baseline already applied, no error, data kept
        {
            let db = Database::open(&path).expect("second open");
            assert_eq!(db.get_config("sentinel").unwrap().as_deref(), Some("1"));
            assert_eq!(
                db.get_config("delegation_max_sessions").unwrap().as_deref(),
                Some("8")
            );
            let conn = db.conn();
            let applied: i64 = conn
                .query_row("SELECT COUNT(*) FROM _migration", [], |r| r.get(0))
                .unwrap();
            assert_eq!(applied, 1);
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }
}
