//! 从 db/mod.rs 拆分：account/relay_token 表（纯搬运，零逻辑变更）

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
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let total: i64 = {
            let sql = format!("SELECT COUNT(*) FROM account a {where_sql}");
            let mut stmt = conn.prepare(&sql).map_err(db_err)?;
            stmt.query_row(
                rusqlite::params_from_iter(bind.iter().map(|b| b.as_ref())),
                |r| r.get(0),
            )
            .map_err(db_err)?
        };

        let offset = (page.saturating_sub(1)) * page_size;
        let sql = format!(
            "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console
             FROM account a LEFT JOIN \"group\" g ON a.group_id = g.id
             {where_sql} ORDER BY a.created_at DESC LIMIT ? OFFSET ?"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let mut bind_refs: Vec<&dyn rusqlite::types::ToSql> =
            bind.iter().map(|b| b.as_ref()).collect();
        let limit = page_size as i64;
        let off = offset as i64;
        bind_refs.push(&limit);
        bind_refs.push(&off);
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind_refs), map_account_row)
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok((items, total))
    }

    pub fn get_account(&self, id: &str) -> Result<Option<AccountRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console
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
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console, a.password
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

    /// 创建账号（可授予「管理此节点」权限，对应管理版接入链接）。
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

    /// 更新账号（含「管理此节点」权限变更）。
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

    /// 按 tunnel_token 哈希查找账号（数据面认证）
    pub fn find_account_by_tunnel_hash(&self, token_hash: &str) -> Result<Option<AccountRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT a.id, a.username, a.group_id, g.name, a.enabled, a.remark, a.last_seen_at, a.created_at, a.updated_at, a.admin_console
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

    pub fn create_relay_token(
        &self,
        token_hash: &str,
        token_prefix: &str,
        remark: &str,
    ) -> Result<RelayTokenRecord> {
        self.create_relay_token_full(token_hash, token_prefix, remark, false, "full")
    }

    /// 创建 Relay Token（可勾选「允许该下游中继管理本节点」+ 授权档位）。
    pub fn create_relay_token_full(
        &self,
        token_hash: &str,
        token_prefix: &str,
        remark: &str,
        expose_control: bool,
        control_scope: &str,
    ) -> Result<RelayTokenRecord> {
        self.create_relay_token_with_group(
            token_hash,
            token_prefix,
            remark,
            expose_control,
            control_scope,
            None,
        )
    }

    /// 创建 Relay Token 并挂载收敛权限组（group_id 为 None = 不收敛）。
    pub fn create_relay_token_with_group(
        &self,
        token_hash: &str,
        token_prefix: &str,
        remark: &str,
        expose_control: bool,
        control_scope: &str,
        group_id: Option<&str>,
    ) -> Result<RelayTokenRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO relay_token (id, token_hash, token_prefix, remark, expose_control, control_scope, group_id, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id, token_hash, token_prefix, remark, expose_control as i32, control_scope, group_id, now],
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
            last_used_at: None,
            created_at: now,
        })
    }

    /// 设置 relay token 的收敛权限组（None = 不收敛，放行一切）。
    pub fn set_relay_token_group(&self, id: &str, group_id: Option<&str>) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE relay_token SET group_id = ?1 WHERE id = ?2",
            params![group_id, id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// 更新暴露控制面开关与授权档位（开关变更走 relay_token.expose_control 审计）。
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

    /// 按哈希查暴露标记与档位（握手 v2 下发判定）。
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
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT t.id, t.token_prefix, t.remark, t.expose_control, t.control_scope, t.last_used_at, t.created_at, t.group_id, g.name
                      FROM relay_token t LEFT JOIN \"group\" g ON t.group_id = g.id ORDER BY t.created_at DESC")
            .map_err(db_err)?;
        let rows = stmt.query_map([], map_relay_token_row).map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok(items)
    }

    /// 按 ID 查 relay token 详情（带出收敛组 ID 与组名）
    pub fn get_relay_token(&self, id: &str) -> Result<Option<RelayTokenRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT t.id, t.token_prefix, t.remark, t.expose_control, t.control_scope, t.last_used_at, t.created_at, t.group_id, g.name
                      FROM relay_token t LEFT JOIN \"group\" g ON t.group_id = g.id WHERE t.id = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_relay_token_row(r).map_err(db_err)?),
            None => None,
        })
    }

    /// 按哈希查 relay token 的收敛权限组（数据面扇入收敛用）。
    /// 外层 None = token 不存在；内层 None = 不收敛（放行一切）。
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

    /// 校验 relay token 哈希是否存在；命中时更新 last_used_at
    pub fn check_relay_token(&self, token_hash: &str) -> Result<bool> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id FROM relay_token WHERE token_hash = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![token_hash]).map_err(db_err)?;
        if let Some(r) = rows.next().map_err(db_err)? {
            let id: String = r.get(0).map_err(db_err)?;
            conn.execute(
                "UPDATE relay_token SET last_used_at = ?1 WHERE id = ?2",
                params![now_rfc3339(), id],
            )
            .map_err(db_err)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn delete_relay_token(&self, id: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM relay_token WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    /// 按 ID 取 relay token 哈希（删除联动踢会话用）。
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
        online: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sha256_hex;

    /// 建一个权限组，返回 id
    fn mk_group(db: &Database, name: &str) -> String {
        db.create_group(name, "").expect("create group").id
    }

    #[test]
    fn relay_token_group_mount() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group(&db, "peers");
        let hash = sha256_hex(b"tok-plain");

        // 带组创建
        let rec = db
            .create_relay_token_with_group(&hash, "psk_abcd", "带组", false, "full", Some(&gid))
            .expect("create with group");
        assert_eq!(rec.group_id.as_deref(), Some(gid.as_str()));

        // list / 详情带出组 ID 与组名
        let list = db.list_relay_tokens().unwrap();
        assert_eq!(list[0].group_id.as_deref(), Some(gid.as_str()));
        assert_eq!(list[0].group_name.as_deref(), Some("peers"));
        let detail = db.get_relay_token(&rec.id).unwrap().unwrap();
        assert_eq!(detail.group_name.as_deref(), Some("peers"));

        // 按哈希查收敛组（数据面）：Some(Some(gid))
        assert_eq!(
            db.get_relay_token_group(&hash).unwrap().flatten().as_deref(),
            Some(gid.as_str())
        );

        // 改为不收敛：Some(None)
        db.set_relay_token_group(&rec.id, None).expect("clear group");
        let g = db.get_relay_token_group(&hash).unwrap();
        assert!(matches!(g, Some(None)));
        assert_eq!(db.get_relay_token(&rec.id).unwrap().unwrap().group_id, None);

        // 旧方法委托：默认不收敛
        let rec2 = db
            .create_relay_token_full(&sha256_hex(b"tok2"), "psk_efgh", "", false, "full")
            .expect("create full");
        assert_eq!(rec2.group_id, None);
        // 不存在的哈希：None
        assert_eq!(db.get_relay_token_group("no-such-hash").unwrap(), None);
    }
}
