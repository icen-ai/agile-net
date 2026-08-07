//! grant_receipt table (node.md M6-T3): topology-visibility disclosure records of granted
//! artifacts (delegated tokens re-shared onward over relay entries).

use super::pool::{Database, db_err, now_rfc3339};
use agile_net_core::error::Result;
use rusqlite::params;

#[derive(Debug, Clone, serde::Serialize)]
pub struct GrantReceiptRow {
    pub id: String,
    pub artifact_ref: String,
    pub holder: String,
    pub lineage: String,
    pub visibility: String,
    pub state: String,
    pub created_at: String,
}

impl Database {
    /// Record one disclosure receipt (idempotent per artifact+holder).
    pub fn record_grant_receipt(
        &self,
        artifact_ref: &str,
        holder: &str,
        lineage: &str,
        visibility: &str,
        state: &str,
    ) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR IGNORE INTO grant_receipt (id, artifact_ref, holder, lineage, visibility, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                uuid::Uuid::new_v4().to_string(),
                artifact_ref,
                holder,
                lineage,
                visibility,
                state,
                now_rfc3339()
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Mark a receipt confirmed (registration acked upstream).
    pub fn confirm_grant_receipt(&self, artifact_ref: &str, holder: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE grant_receipt SET state = 'confirmed' WHERE artifact_ref = ?1 AND holder = ?2 AND state = 'pending'",
            params![artifact_ref, holder],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn list_grant_receipts(&self) -> Result<Vec<GrantReceiptRow>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, artifact_ref, holder, lineage, visibility, state, created_at FROM grant_receipt ORDER BY created_at DESC")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(GrantReceiptRow {
                    id: r.get(0)?,
                    artifact_ref: r.get(1)?,
                    holder: r.get(2)?,
                    lineage: r.get(3)?,
                    visibility: r.get(4)?,
                    state: r.get(5)?,
                    created_at: r.get(6)?,
                })
            })
            .map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows)
    }
}
