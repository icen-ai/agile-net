//! Delegated tokens (unified issuance): the resource owner issues consumer credentials directly.
//!
//! Storage rules mirror relay tokens: plaintext is returned once at issuance, only the SHA-256
//! hash is queryable afterwards. The single exception is `e2e_key_enc` — the E2E channel master
//! key (federation P3, HKDF(token) derived at issuance) must stay recoverable for the issuer to
//! unwrap E2E envelopes, so it is AES-256-GCM encrypted with the same machine key as connector
//! tokens (the second and last reversible-storage exception).

use super::models::{DelegatedTokenRecord, DelegatedTokenReg};
use super::pool::{Database, db_err, now_rfc3339};
use agile_net_core::error::Result;
use rusqlite::params;

/// Column list shared by every delegated_token query (positional row mapping).
const DELEGATED_COLS: &str = "id, token_hash, token_prefix, label, groups, hint_map, e2e_key_enc, mode, admin_scope, entry_mode, concurrency, max_sessions, expires_at, max_uses, used_count, created_at";

impl Database {
    /// Insert a delegated token (hash + prefix + encrypted E2E key prepared by the caller).
    /// `groups_json` = JSON array of local group IDs; `hint_map_json` = JSON array of {hint, groups};
    /// `mode` = consumer mode (`dedicated` 专线 / `split` 分流);
    /// `entry_mode` = `direct` (dial the issuer directly) / `relay` (via the disaster set);
    /// `concurrency` = `single` (kick-old) / `multi`; `max_sessions` = session cap snapshot;
    /// `expires_at`/`max_uses` = token lifecycle window (None = never expires / unlimited).
    #[allow(clippy::too_many_arguments)]
    pub fn create_delegated_token(
        &self,
        token_hash: &str,
        token_prefix: &str,
        label: &str,
        groups_json: &str,
        hint_map_json: &str,
        e2e_key_enc: &str,
        mode: &str,
        admin_scope: &str,
        entry_mode: &str,
        concurrency: &str,
        max_sessions: i64,
        expires_at: Option<&str>,
        max_uses: Option<i64>,
    ) -> Result<DelegatedTokenRecord> {
        let max_uses = max_uses.filter(|v| *v > 0);
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO delegated_token (id, token_hash, token_prefix, label, groups, hint_map, e2e_key_enc, mode, admin_scope, entry_mode, concurrency, max_sessions, expires_at, max_uses, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![id, token_hash, token_prefix, label, groups_json, hint_map_json, e2e_key_enc, mode, admin_scope, entry_mode, concurrency, max_sessions, expires_at, max_uses, now],
        )
        .map_err(db_err)?;
        Ok(DelegatedTokenRecord {
            id,
            token_hash: token_hash.to_string(),
            token_prefix: token_prefix.to_string(),
            label: label.to_string(),
            groups: groups_json.to_string(),
            hint_map: hint_map_json.to_string(),
            e2e_key_enc: e2e_key_enc.to_string(),
            mode: mode.to_string(),
            admin_scope: admin_scope.to_string(),
            entry_mode: entry_mode.to_string(),
            concurrency: concurrency.to_string(),
            max_sessions,
            expires_at: expires_at.map(|s| s.to_string()),
            max_uses,
            used_count: 0,
            created_at: now,
            regs: Vec::new(),
        })
    }

    /// Count one data-plane open against the token's usage cap (issuer-side, best effort).
    pub fn bump_delegated_token_use(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE delegated_token SET used_count = used_count + 1 WHERE id = ?1",
            params![id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Set the lifecycle window of a delegated token (None = never expires / unlimited).
    pub fn set_delegated_token_lifecycle(
        &self,
        id: &str,
        expires_at: Option<&str>,
        max_uses: Option<i64>,
    ) -> Result<()> {
        let max_uses = max_uses.filter(|v| *v > 0);
        let conn = self.conn();
        conn.execute(
            "UPDATE delegated_token SET expires_at = ?1, max_uses = ?2 WHERE id = ?3",
            params![expires_at, max_uses, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Persist the usage counter (absolute set; the engine flushes on cache rebuild).
    pub fn set_delegated_token_used(&self, id: &str, used_count: i64) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE delegated_token SET used_count = ?1 WHERE id = ?2",
            params![used_count, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// All delegated tokens with their disaster-set registration rows (creation order, newest first).
    pub fn list_delegated_tokens(&self) -> Result<Vec<DelegatedTokenRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DELEGATED_COLS} FROM delegated_token ORDER BY created_at DESC"
            ))
            .map_err(db_err)?;
        let mut rows = stmt.query([]).map_err(db_err)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(db_err)? {
            out.push(map_delegated_row(r).map_err(db_err)?);
        }
        drop(rows);
        drop(stmt);
        drop(conn); // memory pool size is 1: release before the per-token regs queries below
        for rec in &mut out {
            rec.regs = self.delegated_regs_of(&rec.id)?;
        }
        Ok(out)
    }

    /// One delegated token by ID (with registration rows).
    pub fn get_delegated_token(&self, id: &str) -> Result<Option<DelegatedTokenRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DELEGATED_COLS} FROM delegated_token WHERE id = ?1"
            ))
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        let mut rec = match rows.next().map_err(db_err)? {
            Some(r) => Some(map_delegated_row(r).map_err(db_err)?),
            None => None,
        };
        drop(rows);
        drop(stmt);
        drop(conn); // memory pool size is 1: release before the regs query below
        if let Some(rec) = &mut rec {
            rec.regs = self.delegated_regs_of(&rec.id)?;
        }
        Ok(rec)
    }

    /// Delete a delegated token (registration rows cascade).
    pub fn delete_delegated_token(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM delegated_token WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    /// Replace the disaster set of a token (delete + re-insert; at most one primary is kept —
    /// the first primary entry wins, later ones are demoted defensively).
    pub fn set_delegated_token_regs(&self, token_id: &str, regs: &[(String, bool)]) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM delegated_token_reg WHERE token_id = ?1",
            params![token_id],
        )
        .map_err(db_err)?;
        let mut primary_seen = false;
        for (connector_id, is_primary) in regs {
            let primary = *is_primary && !primary_seen;
            primary_seen |= primary;
            conn.execute(
                "INSERT OR REPLACE INTO delegated_token_reg (token_id, connector_id, is_primary)
                 VALUES (?1, ?2, ?3)",
                params![token_id, connector_id, primary as i64],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    /// Registration rows of one token (primary first, then insertion order).
    pub fn delegated_regs_of(&self, token_id: &str) -> Result<Vec<DelegatedTokenReg>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT connector_id, is_primary FROM delegated_token_reg
                 WHERE token_id = ?1 ORDER BY is_primary DESC, rowid ASC",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![token_id]).map_err(db_err)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(db_err)? {
            out.push(DelegatedTokenReg {
                connector_id: r.get(0).map_err(db_err)?,
                is_primary: r.get::<_, i64>(1).map_err(db_err)? != 0,
            });
        }
        Ok(out)
    }

    /// All tokens registered on one upstream connector (re-registration source after reconnect).
    pub fn delegated_tokens_of_connector(&self, connector_id: &str) -> Result<Vec<DelegatedTokenRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DELEGATED_COLS} FROM delegated_token t
                 JOIN delegated_token_reg r ON r.token_id = t.id
                 WHERE r.connector_id = ?1
                 ORDER BY t.created_at ASC"
            ))
            .map_err(db_err)?;
        let mut rows = stmt.query(params![connector_id]).map_err(db_err)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(db_err)? {
            out.push(map_delegated_row(r).map_err(db_err)?);
        }
        Ok(out)
    }

    /// Resolve a token by the E2E key id (federation P3): the kid is exactly the first 12 hex
    /// chars of the token hash (protocol v4; shorter legacy prefixes no longer resolve).
    /// Ambiguity fails closed (None).
    pub fn find_delegated_token_by_kid(&self, kid: &str) -> Result<Option<DelegatedTokenRecord>> {
        if kid.len() != 12 || !kid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(None);
        }
        let conn = self.conn();
        // prefix match in SQL (LIKE with an anchored pattern — hex chars carry no wildcards)
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {DELEGATED_COLS} FROM delegated_token WHERE token_hash LIKE ?1 || '%'"
            ))
            .map_err(db_err)?;
        let mut rows = stmt.query(params![kid]).map_err(db_err)?;
        let mut hits = Vec::new();
        while let Some(r) = rows.next().map_err(db_err)? {
            hits.push(map_delegated_row(r).map_err(db_err)?);
        }
        Ok(if hits.len() == 1 { hits.pop() } else { None })
    }
}

fn map_delegated_row(r: &rusqlite::Row) -> rusqlite::Result<DelegatedTokenRecord> {
    Ok(DelegatedTokenRecord {
        id: r.get(0)?,
        token_hash: r.get(1)?,
        token_prefix: r.get(2)?,
        label: r.get(3)?,
        groups: r.get(4)?,
        hint_map: r.get(5)?,
        e2e_key_enc: r.get(6)?,
        mode: r.get(7)?,
        admin_scope: r.get(8)?,
        entry_mode: r.get(9)?,
        concurrency: r.get(10)?,
        max_sessions: r.get(11)?,
        expires_at: r.get("expires_at")?,
        max_uses: r.get("max_uses")?,
        used_count: r.get("used_count")?,
        created_at: r.get("created_at")?,
        regs: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sha256_hex;

    fn mk_connector(db: &Database, name: &str) -> String {
        db.create_connector(name, "", "1.2.3.4:54430", "psk_x", "", true, "", "", "", "", None, "")
            .expect("create connector")
            .id
    }

    fn mk_token(db: &Database, hash: &str, label: &str) -> DelegatedTokenRecord {
        db.create_delegated_token(hash, "psk_test01", label, "[\"g1\",\"g2\"]", "[{\"hint\":\"en_abcd\",\"groups\":[\"git\"]}]", "v1:AAAA:BBBB", "split", "full", "relay", "multi", 8, None, None)
            .expect("create delegated token")
    }

    #[test]
    fn delegated_token_crud_roundtrip() {
        let db = Database::in_memory().unwrap();
        let rec = mk_token(&db, &"ab".repeat(32), "alice-laptop");
        assert_eq!(rec.label, "alice-laptop");
        assert!(rec.regs.is_empty());

        let got = db.get_delegated_token(&rec.id).unwrap().expect("found");
        assert_eq!(got.token_hash, "ab".repeat(32));
        assert_eq!(got.groups, "[\"g1\",\"g2\"]");
        assert_eq!(got.e2e_key_enc, "v1:AAAA:BBBB");
        assert_eq!(got.mode, "split");
        // unified-issuance columns round-trip
        assert_eq!(got.entry_mode, "relay");
        assert_eq!(got.concurrency, "multi");
        assert_eq!(got.max_sessions, 8);

        let list = db.list_delegated_tokens().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].entry_mode, "relay");

        db.delete_delegated_token(&rec.id).unwrap();
        assert!(db.get_delegated_token(&rec.id).unwrap().is_none());
        assert!(db.list_delegated_tokens().unwrap().is_empty());
    }

    #[test]
    fn disaster_set_regs_and_primary_uniqueness() {
        let db = Database::in_memory().unwrap();
        let c1 = mk_connector(&db, "up-1");
        let c2 = mk_connector(&db, "up-2");
        let tok = mk_token(&db, &"cd".repeat(32), "bob");

        // two entries both flagged primary -> the first one wins, the second is demoted
        db.set_delegated_token_regs(&tok.id, &[(c1.clone(), true), (c2.clone(), true)])
            .unwrap();
        let regs = db.delegated_regs_of(&tok.id).unwrap();
        assert_eq!(regs.len(), 2);
        assert_eq!(regs[0].connector_id, c1);
        assert!(regs[0].is_primary);
        assert!(!regs[1].is_primary);

        // replace the set: keep c2 only, as primary
        db.set_delegated_token_regs(&tok.id, &[(c2.clone(), true)]).unwrap();
        let regs = db.delegated_regs_of(&tok.id).unwrap();
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].connector_id, c2);
        assert!(regs[0].is_primary);

        // per-connector re-registration source
        let of_c2 = db.delegated_tokens_of_connector(&c2).unwrap();
        assert_eq!(of_c2.len(), 1);
        assert_eq!(of_c2[0].id, tok.id);
        assert!(db.delegated_tokens_of_connector(&c1).unwrap().is_empty());

        // deleting the token cascades the registration rows
        db.delete_delegated_token(&tok.id).unwrap();
        assert!(db.delegated_regs_of(&tok.id).unwrap().is_empty());
        assert!(db.delegated_tokens_of_connector(&c2).unwrap().is_empty());
    }

    #[test]
    fn find_by_kid_exact_12_hex_only() {
        let db = Database::in_memory().unwrap();
        let hash = "ef".repeat(32);
        mk_token(&db, &hash, "carol");
        let kid = &hash[..12];

        let hit = db.find_delegated_token_by_kid(kid).unwrap().expect("unique hit");
        assert_eq!(hit.token_hash, hash);
        assert!(db.find_delegated_token_by_kid("000000000000").unwrap().is_none());
        assert!(db.find_delegated_token_by_kid("not-hex-not!").unwrap().is_none());
        // legacy 8-char prefixes no longer resolve
        assert!(db.find_delegated_token_by_kid(&hash[..8]).unwrap().is_none());
    }

    #[test]
    fn group_e2e_flag_guards_attached_groups() {
        let db = Database::in_memory().unwrap();
        let gid = db.create_group("db-prod", "").unwrap().id;
        assert_eq!(db.group_e2e_required(&gid).unwrap(), Some(false));

        // free group: can be marked
        db.set_group_e2e_required(&gid, true).unwrap();
        assert_eq!(db.group_e2e_required(&gid).unwrap(), Some(true));
        assert!(db.get_group(&gid).unwrap().unwrap().e2e_required);
        db.set_group_e2e_required(&gid, false).unwrap();

        // attach a relay token -> marking must fail closed
        db.create_relay_token_with_quota(&sha256_hex(b"tok-att"), "psk_att", "", false, "full", Some(&gid), None)
            .unwrap();
        assert_eq!(db.group_attachment_count(&gid).unwrap(), 1);
        assert!(db.set_group_e2e_required(&gid, true).is_err());
        assert_eq!(db.group_e2e_required(&gid).unwrap(), Some(false));
    }
}
