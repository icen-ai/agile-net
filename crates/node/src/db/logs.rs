//! 从 db/mod.rs 拆分：audit_log/traffic_log/node_traffic_log/refresh_token 表（纯搬运，零逻辑变更）

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

#[cfg(test)]
mod tests {
    use super::*;

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
