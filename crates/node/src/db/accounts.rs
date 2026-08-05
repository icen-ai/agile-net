//! Split from db/mod.rs: account/relay_token tables (pure move, no logic change)

use super::models::*;
use super::pool::{Database, db_err, now_rfc3339};
use agile_net_core::error::Result;
use rusqlite::params;

impl Database {
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
        super::paginate::paged_query(
            &conn,
            "a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console, a.tunnel_expires_at",
            "account a LEFT JOIN \"group\" g ON a.group_id = g.id",
            &where_clauses,
            &bind,
            "a.created_at DESC",
            page,
            page_size,
            map_account_row,
        )
    }

    pub fn get_account(&self, id: &str) -> Result<Option<AccountRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console, a.tunnel_expires_at
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
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console, a.password, a.tunnel_expires_at
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

    /// Create an account (may grant the "manage this node" permission, i.e. an admin connect URL).
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
            tunnel_expires_at: None,
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

    /// Update an account (including the "manage this node" permission).
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

    /// Look up an account by tunnel_token hash (data-plane auth)
    pub fn find_account_by_tunnel_hash(&self, token_hash: &str) -> Result<Option<AccountRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console, a.tunnel_expires_at
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

    /// Create a relay token (with bandwidth quota; rate_limit_kbps in KB/s, None = unlimited).
    /// Invalid-value defense: `<= 0` normalizes to NULL (API already rejects with 400; this is the backstop).
    #[allow(clippy::too_many_arguments)]
    pub fn create_relay_token_with_quota(
        &self,
        token_hash: &str,
        token_prefix: &str,
        remark: &str,
        expose_control: bool,
        control_scope: &str,
        group_id: Option<&str>,
        rate_limit_kbps: Option<i64>,
    ) -> Result<RelayTokenRecord> {
        let rate_limit_kbps = rate_limit_kbps.filter(|v| *v > 0);
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO relay_token (id, token_hash, token_prefix, remark, expose_control, control_scope, group_id, rate_limit_kbps, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![id, token_hash, token_prefix, remark, expose_control as i32, control_scope, group_id, rate_limit_kbps, now],
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
            rate_limit_kbps,
            expires_at: None,
            max_uses: None,
            used_count: 0,
            last_used_at: None,
            created_at: now,
        })
    }

    /// Set the ACL group of a relay token (None = no restriction, allow all).
    pub fn set_relay_token_group(&self, id: &str, group_id: Option<&str>) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE relay_token SET group_id = ?1 WHERE id = ?2",
            params![group_id, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Set the bandwidth quota of a relay token (KB/s; None = unlimited).
    /// Invalid-value defense: `<= 0` normalizes to NULL (same backstop as create).
    pub fn set_relay_token_rate_limit(&self, id: &str, rate_limit_kbps: Option<i64>) -> Result<()> {
        let rate_limit_kbps = rate_limit_kbps.filter(|v| *v > 0);
        let conn = self.conn();
        conn.execute(
            "UPDATE relay_token SET rate_limit_kbps = ?1 WHERE id = ?2",
            params![rate_limit_kbps, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Look up a relay token's bandwidth quota by hash (KB/s; data-plane rate limiting).
    /// None = token missing or no quota set (unlimited).
    pub fn get_relay_token_rate_limit(&self, token_hash: &str) -> Result<Option<i64>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT rate_limit_kbps FROM relay_token WHERE token_hash = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![token_hash]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => r.get(0).map_err(db_err)?,
            None => None,
        })
    }

    /// Update the control-plane exposure flag and grant scope (flag changes audited as relay_token.expose_control).
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

    /// Look up the exposure flag and scope by hash (for handshake v2 decisions).
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
        // Fetch all rows and release the connection first (memory pool size is 1; the name-map
        // fixup below needs another conn)
        let mut items = {
            let conn = self.conn();
            let mut stmt = conn
                .prepare("SELECT t.id, t.token_prefix, t.remark, t.expose_control, t.control_scope, t.last_used_at, t.created_at, t.group_id, g.name, t.rate_limit_kbps, t.expires_at, t.max_uses, t.used_count
                          FROM relay_token t LEFT JOIN \"group\" g ON t.group_id = g.id ORDER BY t.created_at DESC")
                .map_err(db_err)?;
            let rows = stmt.query_map([], map_relay_token_row).map_err(db_err)?;
            let mut items = Vec::new();
            for r in rows {
                items.push(r.map_err(db_err)?);
            }
            items
        };
        // Display names of multi-group sets resolve per member in Rust (the SQL join only
        // covers the legacy single-id case)
        self.fixup_group_set_names(&mut items);
        Ok(items)
    }

    /// Look up relay token detail by ID (with ACL group ID and group name)
    pub fn get_relay_token(&self, id: &str) -> Result<Option<RelayTokenRecord>> {
        let mut rec = {
            let conn = self.conn();
            let mut stmt = conn
                .prepare("SELECT t.id, t.token_prefix, t.remark, t.expose_control, t.control_scope, t.last_used_at, t.created_at, t.group_id, g.name, t.rate_limit_kbps, t.expires_at, t.max_uses, t.used_count
                          FROM relay_token t LEFT JOIN \"group\" g ON t.group_id = g.id WHERE t.id = ?1")
                .map_err(db_err)?;
            let mut rows = stmt.query(params![id]).map_err(db_err)?;
            match rows.next().map_err(db_err)? {
                Some(r) => Some(map_relay_token_row(r).map_err(db_err)?),
                None => None,
            }
        };
        if let Some(recs) = rec.as_mut() {
            self.fixup_group_set_names(std::slice::from_mut(recs));
        }
        Ok(rec)
    }

    /// Resolve comma-separated group sets to per-member display names (dangling ids echo verbatim).
    fn fixup_group_set_names(&self, items: &mut [RelayTokenRecord]) {
        let mut name_map = None;
        for it in items.iter_mut() {
            let Some(set) = &it.group_id else { continue };
            if !set.contains(',') {
                continue;
            }
            let names = name_map.get_or_insert_with(|| self.group_name_map().unwrap_or_default());
            it.group_name = Some(
                set.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| names.get(s).cloned().unwrap_or_else(|| s.to_string()))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
    }

    /// Look up a relay token's ACL group by hash (data-plane fan-in restriction).
    /// Outer None = token missing; inner None = no restriction (allow all).
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

    /// Check a relay token hash exists and is alive (token lifecycle: not expired, usage cap
    /// not reached); updates last_used_at and increments used_count on a live hit.
    /// An expired/exhausted token reports as a miss (auth rejects it like an unknown token).
    pub fn check_relay_token(&self, token_hash: &str) -> Result<bool> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, expires_at, max_uses, used_count FROM relay_token WHERE token_hash = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![token_hash]).map_err(db_err)?;
        if let Some(r) = rows.next().map_err(db_err)? {
            let id: String = r.get(0).map_err(db_err)?;
            let expires_at: Option<String> = r.get(1).map_err(db_err)?;
            let max_uses: Option<i64> = r.get(2).map_err(db_err)?;
            let used_count: i64 = r.get(3).map_err(db_err)?;
            if !super::pool::expiry_active(expires_at.as_deref())
                || super::pool::uses_exhausted(max_uses, used_count)
            {
                return Ok(false);
            }
            conn.execute(
                "UPDATE relay_token SET last_used_at = ?1, used_count = used_count + 1 WHERE id = ?2",
                params![now_rfc3339(), id],
            )
            .map_err(db_err)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Set the lifecycle window of a relay token (None = never expires / unlimited).
    pub fn set_relay_token_lifecycle(
        &self,
        id: &str,
        expires_at: Option<&str>,
        max_uses: Option<i64>,
    ) -> Result<()> {
        let max_uses = max_uses.filter(|v| *v > 0);
        let conn = self.conn();
        conn.execute(
            "UPDATE relay_token SET expires_at = ?1, max_uses = ?2 WHERE id = ?3",
            params![expires_at, max_uses, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Set the tunnel token validity window of an account (None = never expires).
    pub fn set_account_tunnel_expiry(&self, id: &str, expires_at: Option<&str>) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE account SET tunnel_expires_at = ?1 WHERE id = ?2",
            params![expires_at, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn delete_relay_token(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM relay_token WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    /// Get a relay token's hash by ID (to kick sessions on delete).
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
        rate_limit_kbps: r.get(9)?,
        expires_at: r.get("expires_at")?,
        max_uses: r.get("max_uses")?,
        used_count: r.get("used_count")?,
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
        tunnel_expires_at: r.get("tunnel_expires_at")?,
        online: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sha256_hex;

    /// Create a group, return its id
    fn mk_group(db: &Database, name: &str) -> String {
        db.create_group(name, "").expect("create group").id
    }

    #[test]
    fn relay_token_group_mount() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "peers");
        let hash = sha256_hex(b"tok-plain");

        // Create with group
        let rec = db
            .create_relay_token_with_quota(&hash, "psk_abcd", "带组", false, "full", Some(&gid), None)
            .expect("create with group");
        assert_eq!(rec.group_id.as_deref(), Some(gid.as_str()));

        // list / detail carry group ID and group name
        let list = db.list_relay_tokens().unwrap();
        assert_eq!(list[0].group_id.as_deref(), Some(gid.as_str()));
        assert_eq!(list[0].group_name.as_deref(), Some("peers"));
        let detail = db.get_relay_token(&rec.id).unwrap().unwrap();
        assert_eq!(detail.group_name.as_deref(), Some("peers"));

        // ACL group lookup by hash (data plane): Some(Some(gid))
        assert_eq!(
            db.get_relay_token_group(&hash).unwrap().flatten().as_deref(),
            Some(gid.as_str())
        );

        // Switch to unrestricted: Some(None)
        db.set_relay_token_group(&rec.id, None).expect("clear group");
        let g = db.get_relay_token_group(&hash).unwrap();
        assert!(matches!(g, Some(None)));
        assert_eq!(db.get_relay_token(&rec.id).unwrap().unwrap().group_id, None);

        // Create without group: unrestricted by default
        let rec2 = db
            .create_relay_token_with_quota(&sha256_hex(b"tok2"), "psk_efgh", "", false, "full", None, None)
            .expect("create without group");
        assert_eq!(rec2.group_id, None);
        // Missing hash: None
        assert_eq!(db.get_relay_token_group("no-such-hash").unwrap(), None);
    }

    #[test]
    fn relay_token_rate_limit_crud() {
        let db = Database::in_memory().unwrap();
        let hash = sha256_hex(b"tok-rl");

        // Create with quota (10 MB/s = 10240 KB/s)
        let rec = db
            .create_relay_token_with_quota(&hash, "psk_rl", "限速", false, "full", None, Some(10240))
            .expect("create with quota");
        assert_eq!(rec.rate_limit_kbps, Some(10240));

        // list / detail / by-hash all carry the quota
        assert_eq!(db.list_relay_tokens().unwrap()[0].rate_limit_kbps, Some(10240));
        assert_eq!(
            db.get_relay_token(&rec.id).unwrap().unwrap().rate_limit_kbps,
            Some(10240)
        );
        assert_eq!(db.get_relay_token_rate_limit(&hash).unwrap(), Some(10240));

        // Update and clear
        db.set_relay_token_rate_limit(&rec.id, Some(1024)).unwrap();
        assert_eq!(db.get_relay_token_rate_limit(&hash).unwrap(), Some(1024));
        db.set_relay_token_rate_limit(&rec.id, None).unwrap();
        assert_eq!(db.get_relay_token_rate_limit(&hash).unwrap(), None);

        // Invalid-value defense: <=0 normalizes to NULL (unlimited)
        db.set_relay_token_rate_limit(&rec.id, Some(0)).unwrap();
        assert_eq!(db.get_relay_token_rate_limit(&hash).unwrap(), None);
        let rec2 = db
            .create_relay_token_with_quota(
                &sha256_hex(b"tok-rl-neg"),
                "psk_neg",
                "",
                false,
                "full",
                None,
                Some(-5),
            )
            .expect("create with invalid quota");
        assert_eq!(rec2.rate_limit_kbps, None);
        assert_eq!(
            db.get_relay_token_rate_limit(&sha256_hex(b"tok-rl-neg"))
                .unwrap(),
            None
        );

        // Create without quota: unlimited by default
        let rec3 = db
            .create_relay_token_with_quota(&sha256_hex(b"tok3"), "psk_x", "", false, "full", None, None)
            .unwrap();
        assert_eq!(rec3.rate_limit_kbps, None);
        // Missing hash: None
        assert_eq!(db.get_relay_token_rate_limit("no-such").unwrap(), None);
    }
}
