//! Split from db/mod.rs: audit_log/node_traffic_log/refresh_token tables (pure move, no logic change)

use super::models::*;
use super::pool::{Database, db_err, now_rfc3339};
use agile_net_core::error::Result;
use rusqlite::params;

impl Database {
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
        sort: Option<&str>,
    ) -> Result<(Vec<AuditLogRecord>, i64)> {
        let conn = self.conn();
        let mut where_clauses = Vec::new();
        let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        // Empty-string filter = no filter (matches the old pattern.is_empty() branch)
        if let Some(a) = action.filter(|a| !a.is_empty()) {
            where_clauses.push("action = ?");
            bind.push(Box::new(a.to_string()));
        }
        let order = super::paginate::order_clause(sort, &[("time", "created_at")], "created_at DESC");
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
        super::paginate::paged_query(
            &conn,
            "id, admin_id, operator, action, target, detail, ip, created_at",
            "audit_log",
            &where_clauses,
            &bind,
            &order,
            page,
            page_size,
            map_row,
        )
    }

    /// Delete audit logs older than N days; returns rows deleted.
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

    // ==================== Node Traffic Log (node-level 3-dim traffic series) ====================

    /// Record node-level traffic delta (upsert-accumulate by dim+src+dst+hour bucket; skip zero deltas)
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

    /// Last 24h node-level traffic series (hourly; fanin/fanout summed across ids, transit across route pairs)
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

    /// Delete node-level traffic series older than `days` days (called by the daily retention task)
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

    /// Check a refresh token is neither revoked nor expired
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

    /// Revoke all refresh tokens of a subject (on account disable / password change)
    pub fn revoke_all_refresh_tokens(&self, subject: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE refresh_token SET revoked = 1 WHERE subject = ?1",
            params![subject],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Delete expired refresh tokens (called at startup)
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

/// Current local hour bucket 'YYYY-MM-DD HH:00' (node_traffic_log / traffic_24h contract format)
fn local_hour_bucket() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:00").to_string()
}

/// Local hour bucket `hours` ago (for the 24h window filter)
fn local_hours_ago(hours: i64) -> String {
    let t = chrono::Local::now() - chrono::Duration::hours(hours);
    t.format("%Y-%m-%d %H:00").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_traffic_add_aggregate_and_cleanup() {
        let db = Database::in_memory().unwrap();

        // Zero delta skipped (not persisted)
        db.add_node_traffic("fanin", "n1", "", 0, 0).unwrap();
        assert!(db.node_traffic_24h().unwrap().fanin.is_empty());

        // Same-bucket accumulate + write across ids / route pairs
        db.add_node_traffic("fanin", "n1", "", 100, 200).unwrap();
        db.add_node_traffic("fanin", "n1", "", 1, 2).unwrap();
        db.add_node_traffic("fanin", "n2", "", 50, 60).unwrap();
        db.add_node_traffic("fanout", "up-a", "", 7, 8).unwrap();
        db.add_node_traffic("transit", "n1", "n2", 3, 4).unwrap();
        db.add_node_traffic("transit", "proxy", "local", 5, 6).unwrap();

        let agg = db.node_traffic_24h().unwrap();
        // fanin summed across peers into the same hour bucket
        assert_eq!(agg.fanin.len(), 1);
        assert_eq!(agg.fanin[0].up, 151);
        assert_eq!(agg.fanin[0].down, 262);
        // Hour bucket uses local-time format 'YYYY-MM-DD HH:00'
        assert_eq!(agg.fanin[0].hour.len(), 16);
        assert!(agg.fanin[0].hour.ends_with(":00"));
        assert_eq!(&agg.fanin[0].hour[10..11], " ");
        assert_eq!(agg.fanout.len(), 1);
        assert_eq!(agg.fanout[0].up, 7);
        // transit summed across route pairs
        assert_eq!(agg.transit.len(), 1);
        assert_eq!(agg.transit[0].up, 8);
        assert_eq!(agg.transit[0].down, 10);

        // Retention cleanup: rows older than 40 days deleted, current rows kept
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
        // 24h aggregate excludes old rows
        let agg = db.node_traffic_24h().unwrap();
        assert_eq!(agg.fanin.len(), 1);
        assert_eq!(agg.fanin[0].up, 151);
    }
}
