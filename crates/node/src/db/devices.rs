//! Device registry + approval center + device session ledger (node.md M2/M3/M5).
//!
//! Device identity arrives proven from the handshake (device_fp = sha256 of the device ed25519
//! pubkey, derived by the listener — never trusted from the wire). Certification binds a device
//! to a logical HOLDER (`subject`): several devices may share one subject (加绑), and stats
//! follow the subject across device replacement (换绑 = certify the new device, migrate
//! subject/remark/traffic, revoke the old — terminal, never reusable).

use super::pool::{Database, db_err, now_rfc3339};
use agile_net_core::error::{Error, Result};
use rusqlite::params;

/// Device registry row (device-level trust; per this node).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceRecord {
    pub id: String,
    pub device_fp: String,
    pub pubkey: String,
    pub token_hash: String,
    /// Logical holder assigned at certification (加绑/换绑 aggregate key)
    pub subject: String,
    /// Device's self-declared name (decorative)
    pub my_name: String,
    /// Admin certification remark (the capsule title)
    pub remark: String,
    /// pending / certified / revoked (terminal)
    pub state: String,
    /// '' = local admin, else the origin node id (M6 transitive certification)
    pub certified_by: String,
    pub certified_at: Option<String>,
    /// M6 transitive lineage (verbatim for blind forwarding): origin pubkey / signature / ts
    #[serde(default)]
    pub origin_pubkey: String,
    #[serde(default)]
    pub cert_sig: String,
    #[serde(default)]
    pub cert_ts: String,
    pub first_seen: String,
    pub last_seen: String,
    pub bytes_up: i64,
    pub bytes_down: i64,
}

/// Approval center row (pluggable human-adjudication events).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApprovalRecord {
    pub id: String,
    /// device_certify / device_rebind / ref_cert_adopt / topo_approve ...
    pub r#type: String,
    /// pending / approved / rejected
    pub state: String,
    pub object_ref: String,
    pub requester: String,
    /// Type-specific JSON payload
    pub detail: String,
    pub decided_by: String,
    pub decided_at: Option<String>,
    pub created_at: String,
}

/// One appeal/notice message of an approval item.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApprovalMessage {
    pub id: String,
    pub approval_id: String,
    /// 'appeal' (applicant → admin) | 'notice' (final one-time operator notice)
    pub direction: String,
    pub body: String,
    pub created_at: String,
}

/// One closed session's traffic ledger row (M5: series/history/heatmap all read this table).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceSessionRow {
    pub id: String,
    pub device_fp: String,
    pub token_hash: String,
    /// direct / relay·<node>
    pub entry: String,
    pub ip: String,
    pub started_at: String,
    pub ended_at: String,
    pub bytes_in: i64,
    pub bytes_out: i64,
    /// M2 reason_code (kicked / revoked_by_admin / session_takeover / ...)
    pub close_reason: String,
}

fn map_device(r: &rusqlite::Row) -> rusqlite::Result<DeviceRecord> {
    Ok(DeviceRecord {
        id: r.get(0)?,
        device_fp: r.get(1)?,
        pubkey: r.get(2)?,
        token_hash: r.get(3)?,
        subject: r.get(4)?,
        my_name: r.get(5)?,
        remark: r.get(6)?,
        state: r.get(7)?,
        certified_by: r.get(8)?,
        certified_at: r.get(9)?,
        first_seen: r.get(10)?,
        last_seen: r.get(11)?,
        bytes_up: r.get(12)?,
        bytes_down: r.get(13)?,
        origin_pubkey: r.get(14).unwrap_or_default(),
        cert_sig: r.get(15).unwrap_or_default(),
        cert_ts: r.get(16).unwrap_or_default(),
    })
}

const DEVICE_COLS: &str =
    "id, device_fp, pubkey, token_hash, subject, my_name, remark, state, certified_by, certified_at, first_seen, last_seen, bytes_up, bytes_down, origin_pubkey, cert_sig, cert_ts";

fn map_approval(r: &rusqlite::Row) -> rusqlite::Result<ApprovalRecord> {
    Ok(ApprovalRecord {
        id: r.get(0)?,
        r#type: r.get(1)?,
        state: r.get(2)?,
        object_ref: r.get(3)?,
        requester: r.get(4)?,
        detail: r.get(5)?,
        decided_by: r.get(6)?,
        decided_at: r.get(7)?,
        created_at: r.get(8)?,
    })
}

const APPROVAL_COLS: &str =
    "id, type, state, object_ref, requester, detail, decided_by, decided_at, created_at";

impl Database {
    // ==================== Device registry ====================

    /// Handshake hook: record a proven device sighting. First sight inserts a `pending` row
    /// (returns true); later sightings only refresh last_seen / latest credential / self-declared
    /// name (returns false). Certification state is NEVER touched here.
    pub fn touch_device(
        &self,
        device_fp: &str,
        pubkey_b64: &str,
        token_hash: &str,
        my_name: &str,
    ) -> Result<bool> {
        let conn = self.conn();
        let now = now_rfc3339();
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(1) FROM device_registry WHERE device_fp = ?1",
                params![device_fp],
                |r| r.get::<_, i64>(0),
            )
            .map_err(db_err)?
            > 0;
        conn.execute(
            "INSERT INTO device_registry (id, device_fp, pubkey, token_hash, my_name, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(device_fp) DO UPDATE SET
                token_hash = ?4, my_name = ?5, last_seen = ?6,
                pubkey = CASE WHEN device_registry.pubkey = '' THEN ?3 ELSE device_registry.pubkey END",
            params![uuid::Uuid::new_v4().to_string(), device_fp, pubkey_b64, token_hash, my_name, now],
        )
        .map_err(db_err)?;
        Ok(!exists)
    }

    pub fn get_device(&self, device_fp: &str) -> Result<Option<DeviceRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(&format!("SELECT {DEVICE_COLS} FROM device_registry WHERE device_fp = ?1"))
            .map_err(db_err)?;
        let mut rows = stmt.query(params![device_fp]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_device(r).map_err(db_err)?),
            None => None,
        })
    }

    /// List devices, optionally filtered by state and/or a search term (fp / subject / name /
    /// remark). Ordered: pending first (needs adjudication), then by last_seen desc.
    pub fn list_devices(&self, state: Option<&str>, q: Option<&str>) -> Result<Vec<DeviceRecord>> {
        let conn = self.conn();
        let mut sql = format!("SELECT {DEVICE_COLS} FROM device_registry WHERE 1=1");
        let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(s) = state.filter(|s| !s.is_empty()) {
            sql.push_str(" AND state = ?");
            bind.push(Box::new(s.to_string()));
        }
        if let Some(q) = q.filter(|q| !q.is_empty()) {
            sql.push_str(" AND (device_fp LIKE ? OR subject LIKE ? OR my_name LIKE ? OR remark LIKE ?)");
            let like = format!("%{q}%");
            for _ in 0..4 {
                bind.push(Box::new(like.clone()));
            }
        }
        sql.push_str(" ORDER BY CASE state WHEN 'pending' THEN 0 WHEN 'certified' THEN 1 ELSE 2 END, last_seen DESC");
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let params = rusqlite::params_from_iter(bind.iter().map(|b| b.as_ref()));
        let rows = stmt
            .query_map(params, |r| map_device(r))
            .map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows)
    }

    /// Certify a device onto a logical holder (subject + remark form the badge capsule).
    /// certified_by: '' = local admin (M6: origin node id for transitive certification).
    pub fn certify_device(
        &self,
        device_fp: &str,
        subject: &str,
        remark: &str,
        certified_by: &str,
    ) -> Result<()> {
        let conn = self.conn();
        let n = conn
            .execute(
                "UPDATE device_registry SET state = 'certified', subject = ?2, remark = ?3,
                    certified_by = ?4, certified_at = ?5 WHERE device_fp = ?1 AND state != 'revoked'",
                params![device_fp, subject, remark, certified_by, now_rfc3339()],
            )
            .map_err(db_err)?;
        if n == 0 {
            return Err(Error::NotFound(format!("device {device_fp} missing or revoked")));
        }
        Ok(())
    }

    /// Certify transitively (M6): like certify_device but carries the origin lineage verbatim
    /// so a middle hop can forward the ORIGINAL origin-signed record (blind relay).
    #[allow(clippy::too_many_arguments)]
    pub fn certify_device_transitive(
        &self,
        device_fp: &str,
        subject: &str,
        remark: &str,
        origin_fp: &str,
        origin_pubkey: &str,
        cert_sig: &str,
        cert_ts: &str,
    ) -> Result<()> {
        let conn = self.conn();
        let n = conn
            .execute(
                "UPDATE device_registry SET state = 'certified', subject = ?2, remark = ?3,
                    certified_by = ?4, certified_at = ?5, origin_pubkey = ?6, cert_sig = ?7, cert_ts = ?8
                 WHERE device_fp = ?1 AND state != 'revoked'",
                params![device_fp, subject, remark, origin_fp, cert_ts, origin_pubkey, cert_sig, cert_ts],
            )
            .map_err(db_err)?;
        if n == 0 {
            return Err(Error::NotFound(format!("device {device_fp} missing or revoked")));
        }
        Ok(())
    }

    /// Update only the M6 lineage fields (used when adopting a signed revocation — the row's
    /// state changes but the origin's latest record stays forwardable).
    pub fn store_cert_lineage(&self, device_fp: &str, origin_pubkey: &str, cert_sig: &str, cert_ts: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE device_registry SET origin_pubkey = ?2, cert_sig = ?3, cert_ts = ?4 WHERE device_fp = ?1",
            params![device_fp, origin_pubkey, cert_sig, cert_ts],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Revoke a device (terminal state, never reusable). Live sessions are kicked by the caller.
    pub fn revoke_device(&self, device_fp: &str) -> Result<()> {        let conn = self.conn();
        let n = conn
            .execute(
                "UPDATE device_registry SET state = 'revoked' WHERE device_fp = ?1",
                params![device_fp],
            )
            .map_err(db_err)?;
        if n == 0 {
            return Err(Error::NotFound(format!("device {device_fp} not found")));
        }
        Ok(())
    }

    /// Rebind (换机): move the holder identity (subject + remark) and cumulative traffic from
    /// the old device to the new one, then revoke the old (terminal). The new device must exist
    /// (already sighted) and not be revoked. All-or-nothing.
    pub fn rebind_device(&self, old_fp: &str, new_fp: &str) -> Result<()> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction().map_err(db_err)?;
        let old = tx
            .query_row(
                &format!("SELECT {DEVICE_COLS} FROM device_registry WHERE device_fp = ?1"),
                params![old_fp],
                |r| map_device(r),
            )
            .map_err(|_| Error::NotFound(format!("device {old_fp} not found")))?;
        if old.state == "revoked" {
            return Err(Error::Other(format!("device {old_fp} is revoked (terminal)")));
        }
        let now = now_rfc3339();
        let n = tx
            .execute(
                "UPDATE device_registry SET state = 'certified', subject = ?2, remark = ?3,
                    certified_by = ?4, certified_at = ?5,
                    bytes_up = bytes_up + ?6, bytes_down = bytes_down + ?7
                 WHERE device_fp = ?1 AND state != 'revoked'",
                params![
                    new_fp,
                    old.subject,
                    old.remark,
                    if old.certified_by.is_empty() { "" } else { &old.certified_by },
                    now,
                    old.bytes_up,
                    old.bytes_down
                ],
            )
            .map_err(db_err)?;
        if n == 0 {
            return Err(Error::NotFound(format!("device {new_fp} missing or revoked")));
        }
        tx.execute(
            "UPDATE device_registry SET state = 'revoked', subject = '', remark = '' WHERE device_fp = ?1",
            params![old_fp],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(())
    }

    /// Cumulative-traffic flush (B 口径): called at session close with that session's counters.
    pub fn add_device_traffic(&self, device_fp: &str, up: u64, down: u64) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE device_registry SET bytes_up = bytes_up + ?2, bytes_down = bytes_down + ?3 WHERE device_fp = ?1",
            params![device_fp, up as i64, down as i64],
        )
        .map_err(db_err)?;
        Ok(())
    }

    // ==================== Approval center ====================

    /// File an approval item (pluggable type). Returns the created record.
    pub fn create_approval(
        &self,
        r#type: &str,
        object_ref: &str,
        requester: &str,
        detail: &str,
    ) -> Result<ApprovalRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO approval (id, type, object_ref, requester, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, r#type, object_ref, requester, detail],
        )
        .map_err(db_err)?;
        Ok(ApprovalRecord {
            id,
            r#type: r#type.to_string(),
            state: "pending".into(),
            object_ref: object_ref.to_string(),
            requester: requester.to_string(),
            detail: detail.to_string(),
            decided_by: String::new(),
            decided_at: None,
            created_at: now_rfc3339(),
        })
    }

    /// Decide an approval (approved/rejected); only pending items are decidable.
    pub fn decide_approval(&self, id: &str, approve: bool, decided_by: &str) -> Result<()> {
        let conn = self.conn();
        let n = conn
            .execute(
                "UPDATE approval SET state = ?2, decided_by = ?3, decided_at = ?4 WHERE id = ?1 AND state = 'pending'",
                params![
                    id,
                    if approve { "approved" } else { "rejected" },
                    decided_by,
                    now_rfc3339()
                ],
            )
            .map_err(db_err)?;
        if n == 0 {
            return Err(Error::NotFound(format!("approval {id} missing or already decided")));
        }
        Ok(())
    }

    pub fn list_approvals(&self, state: Option<&str>) -> Result<Vec<ApprovalRecord>> {
        let conn = self.conn();
        let (sql, bind): (String, Vec<String>) = match state.filter(|s| !s.is_empty()) {
            Some(s) => (
                format!("SELECT {APPROVAL_COLS} FROM approval WHERE state = ?1 ORDER BY created_at DESC"),
                vec![s.to_string()],
            ),
            None => (
                format!("SELECT {APPROVAL_COLS} FROM approval ORDER BY CASE state WHEN 'pending' THEN 0 ELSE 1 END, created_at DESC"),
                vec![],
            ),
        };
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind.iter()), |r| map_approval(r))
            .map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows)
    }

    /// Attach an appeal/notice message. Appeals are capped at
    /// `agile_net_core::proto::message::MAX_PENDING_NOTES` per approval item (fail closed);
    /// notices are single-shot (one final operator message, never editable).
    pub fn add_approval_message(&self, approval_id: &str, direction: &str, body: &str) -> Result<()> {
        let conn = self.conn();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM approval_message WHERE approval_id = ?1 AND direction = ?2",
                params![approval_id, direction],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        let cap = if direction == "appeal" {
            agile_net_core::proto::message::MAX_PENDING_NOTES as i64
        } else {
            1
        };
        if count >= cap {
            return Err(Error::Other(format!("approval message cap reached ({direction})")));
        }
        conn.execute(
            "INSERT INTO approval_message (id, approval_id, direction, body) VALUES (?1, ?2, ?3, ?4)",
            params![uuid::Uuid::new_v4().to_string(), approval_id, direction, body],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn approval_messages(&self, approval_id: &str) -> Result<Vec<ApprovalMessage>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, approval_id, direction, body, created_at FROM approval_message WHERE approval_id = ?1 ORDER BY created_at")
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![approval_id], |r| {
                Ok(ApprovalMessage {
                    id: r.get(0)?,
                    approval_id: r.get(1)?,
                    direction: r.get(2)?,
                    body: r.get(3)?,
                    created_at: r.get(4)?,
                })
            })
            .map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows)
    }

    // ==================== Device session ledger (M5) ====================

    /// Flush one closed session into the ledger (called exactly once per session close) and fold
    /// the counters into the device's cumulative totals in the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn flush_device_session(
        &self,
        device_fp: &str,
        token_hash: &str,
        entry: &str,
        ip: &str,
        started_at: &str,
        bytes_in: u64,
        bytes_out: u64,
        close_reason: &str,
    ) -> Result<()> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction().map_err(db_err)?;
        tx.execute(
            "INSERT INTO device_session (id, device_fp, token_hash, entry, ip, started_at, bytes_in, bytes_out, close_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                uuid::Uuid::new_v4().to_string(),
                device_fp,
                token_hash,
                entry,
                ip,
                started_at,
                bytes_in as i64,
                bytes_out as i64,
                close_reason
            ],
        )
        .map_err(db_err)?;
        // device-perspective totals: the device uploads what the session received (bytes_in)
        tx.execute(
            "UPDATE device_registry SET bytes_up = bytes_up + ?2, bytes_down = bytes_down + ?3 WHERE device_fp = ?1",
            params![device_fp, bytes_in as i64, bytes_out as i64],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(())
    }

    /// Raw session rows since a cutoff (RFC3339/datetime), oldest first — the device traffic
    /// series / activity heatmap aggregate these in Rust (M5).
    pub fn device_traffic_rows(
        &self,
        device_fp: &str,
        since: &str,
    ) -> Result<Vec<(String, i64, i64)>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT started_at, bytes_in, bytes_out FROM device_session
                 WHERE device_fp = ?1 AND started_at >= ?2 ORDER BY started_at",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![device_fp, since], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
            })
            .map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows)
    }

    /// Session history of one device (newest first, capped).
    pub fn device_sessions(&self, device_fp: &str, limit: u32) -> Result<Vec<DeviceSessionRow>> {        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, device_fp, token_hash, entry, ip, started_at, ended_at, bytes_in, bytes_out, close_reason
                 FROM device_session WHERE device_fp = ?1 ORDER BY started_at DESC LIMIT ?2",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![device_fp, limit], |r| {
                Ok(DeviceSessionRow {
                    id: r.get(0)?,
                    device_fp: r.get(1)?,
                    token_hash: r.get(2)?,
                    entry: r.get(3)?,
                    ip: r.get(4)?,
                    started_at: r.get(5)?,
                    ended_at: r.get(6)?,
                    bytes_in: r.get(7)?,
                    bytes_out: r.get(8)?,
                    close_reason: r.get(9)?,
                })
            })
            .map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_lifecycle_and_rebind() {
        let db = Database::in_memory().unwrap();
        // first sight: pending (touch returns true on insert)
        assert!(db.touch_device("fp1", "pk1", "th1", "小明-MacBook").unwrap());
        assert!(!db.touch_device("fp1", "pk1", "th1", "小明-MacBook").unwrap());
        let d = db.get_device("fp1").unwrap().unwrap();
        assert_eq!(d.state, "pending");
        assert_eq!(d.my_name, "小明-MacBook");
        // certify onto a holder
        db.certify_device("fp1", "小明", "前端 MacBook", "").unwrap();
        // sight again: state untouched, last_seen/fields refreshed
        db.touch_device("fp1", "pk1", "th2", "小明-MacBook").unwrap();
        let d = db.get_device("fp1").unwrap().unwrap();
        assert_eq!(d.state, "certified");
        assert_eq!(d.token_hash, "th2");
        db.add_device_traffic("fp1", 100, 200).unwrap();

        // 换机: new device sighted, rebind migrates holder + stats, old revoked
        db.touch_device("fp2", "pk2", "th2", "小明-新台式机").unwrap();
        db.rebind_device("fp1", "fp2").unwrap();
        let old = db.get_device("fp1").unwrap().unwrap();
        assert_eq!(old.state, "revoked");
        assert_eq!(old.subject, "");
        let new = db.get_device("fp2").unwrap().unwrap();
        assert_eq!(new.state, "certified");
        assert_eq!(new.subject, "小明");
        assert_eq!(new.remark, "前端 MacBook");
        assert_eq!((new.bytes_up, new.bytes_down), (100, 200));
        // revoked is terminal: re-certify and rebind-from both fail
        assert!(db.certify_device("fp1", "x", "y", "").is_err());
        assert!(db.rebind_device("fp1", "fp2").is_err());
        // 加绑: a second live device can join the same holder
        db.touch_device("fp3", "pk3", "th2", "小明-iPhone").unwrap();
        db.certify_device("fp3", "小明", "手机", "").unwrap();
        // certified devices under holder 小明 = 2 (the revoked one keeps its history but is out)
        let holders = db.list_devices(Some("certified"), Some("小明")).unwrap();
        assert_eq!(holders.len(), 2);
    }

    #[test]
    fn approval_flow_and_message_caps() {
        let db = Database::in_memory().unwrap();
        let a = db.create_approval("device_certify", "fp1", "fp1", "{}").unwrap();
        assert_eq!(a.state, "pending");
        for i in 0..3 {
            db.add_approval_message(&a.id, "appeal", &format!("note {i}")).unwrap();
        }
        assert!(db.add_approval_message(&a.id, "appeal", "one too many").is_err());
        db.decide_approval(&a.id, false, "admin").unwrap();
        // decided items are final
        assert!(db.decide_approval(&a.id, true, "admin").is_err());
        // notice is single-shot
        db.add_approval_message(&a.id, "notice", "拒绝了").unwrap();
        assert!(db.add_approval_message(&a.id, "notice", "again").is_err());
        let msgs = db.approval_messages(&a.id).unwrap();
        assert_eq!(msgs.len(), 4);
        assert_eq!(db.list_approvals(Some("pending")).unwrap().len(), 0);
    }

    #[test]
    fn device_session_flush_folds_cumulative() {
        let db = Database::in_memory().unwrap();
        db.touch_device("fp1", "pk1", "th1", "").unwrap();
        db.flush_device_session("fp1", "th1", "direct", "1.2.3.4", "2026-08-01 10:00:00", 1000, 2000, "kicked")
            .unwrap();
        db.flush_device_session("fp1", "th1", "relay·peer-c", "1.2.3.4", "2026-08-02 11:00:00", 500, 700, "")
            .unwrap();
        let d = db.get_device("fp1").unwrap().unwrap();
        assert_eq!((d.bytes_up, d.bytes_down), (1000 + 500, 2000 + 700));
        let rows = db.device_sessions("fp1", 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].close_reason, ""); // newest first
        assert_eq!(rows[1].entry, "direct");
    }
}
