//! 从 db/mod.rs 拆分：admin 表与管理引导票据（纯搬运，零逻辑变更）

use super::models::*;
use super::pool::{Database, db_err, now_rfc3339};
use super::{random_alnum, sha256_hex};
use agile_net_core::error::Result;
use rusqlite::params;

impl Database {
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
}
