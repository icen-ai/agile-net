//! 从 db/mod.rs 拆分：rule/group/group_rule 表（纯搬运，零逻辑变更）

use super::models::*;
use super::pool::{Database, db_err, now_rfc3339};
use agile_net_core::error::Result;
use rusqlite::params;

impl Database {
    // ==================== Rule ====================

    pub fn list_rules(
        &self,
        page: u32,
        page_size: u32,
        type_filter: Option<&str>,
        q: Option<&str>,
    ) -> Result<(Vec<RuleRecord>, i64)> {
        let conn = self.conn();
        let mut where_clauses = Vec::new();
        let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(t) = type_filter {
            where_clauses.push("r.type = ?");
            bind.push(Box::new(t.to_string()));
        }
        if let Some(q) = q {
            where_clauses.push("(r.value LIKE ? OR r.remark LIKE ?)");
            bind.push(Box::new(format!("%{q}%")));
            bind.push(Box::new(format!("%{q}%")));
        }
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let total: i64 = {
            let sql = format!("SELECT COUNT(*) FROM rule r {where_sql}");
            let mut stmt = conn.prepare(&sql).map_err(db_err)?;
            let params = rusqlite::params_from_iter(bind.iter().map(|b| b.as_ref()));
            stmt.query_row(params, |r| r.get(0)).map_err(db_err)?
        };

        let offset = (page.saturating_sub(1)) * page_size;
        let sql = format!(
            "SELECT r.id, r.type, r.value, r.resolve, r.remark, r.created_at, r.updated_at,
                    (SELECT COUNT(*) FROM group_rule gr WHERE gr.rule_id = r.id) AS group_count
             FROM rule r {where_sql} ORDER BY r.created_at DESC LIMIT ? OFFSET ?"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let mut bind_refs: Vec<&dyn rusqlite::types::ToSql> =
            bind.iter().map(|b| b.as_ref()).collect();
        let limit = page_size as i64;
        let off = offset as i64;
        bind_refs.push(&limit);
        bind_refs.push(&off);
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind_refs), |r| {
                Ok(RuleRecord {
                    id: r.get(0)?,
                    rule_type: r.get(1)?,
                    value: r.get(2)?,
                    resolve: r.get::<_, i32>(3)? != 0,
                    remark: r.get(4)?,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                    group_count: r.get(7)?,
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok((items, total))
    }

    pub fn get_rule(&self, id: &str) -> Result<Option<RuleRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, type, value, resolve, remark, created_at, updated_at, 0 FROM rule WHERE id = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(RuleRecord {
                id: r.get(0).map_err(db_err)?,
                rule_type: r.get(1).map_err(db_err)?,
                value: r.get(2).map_err(db_err)?,
                resolve: r.get::<_, i32>(3).map_err(db_err)? != 0,
                remark: r.get(4).map_err(db_err)?,
                created_at: r.get(5).map_err(db_err)?,
                updated_at: r.get(6).map_err(db_err)?,
                group_count: r.get(7).map_err(db_err)?,
            }),
            None => None,
        })
    }

    pub fn rule_exists(&self, rule_type: &str, value: &str) -> Result<bool> {
        let conn = self.conn();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM rule WHERE type = ?1 AND value = ?2",
                params![rule_type, value],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        Ok(count > 0)
    }

    pub fn create_rule(
        &self,
        rule_type: &str,
        value: &str,
        resolve: bool,
        remark: &str,
    ) -> Result<RuleRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO rule (id, type, value, resolve, remark, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6)",
            params![id, rule_type, value, resolve as i32, remark, now],
        )
        .map_err(db_err)?;
        Ok(RuleRecord {
            id,
            rule_type: rule_type.to_string(),
            value: value.to_string(),
            resolve,
            remark: remark.to_string(),
            group_count: 0,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn update_rule(
        &self,
        id: &str,
        value: Option<&str>,
        resolve: Option<bool>,
        remark: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn();
        let now = now_rfc3339();
        if let Some(v) = value {
            conn.execute(
                "UPDATE rule SET value = ?1, updated_at = ?2 WHERE id = ?3",
                params![v, now, id],
            )
            .map_err(db_err)?;
        }
        if let Some(r) = resolve {
            conn.execute(
                "UPDATE rule SET resolve = ?1, updated_at = ?2 WHERE id = ?3",
                params![r as i32, now, id],
            )
            .map_err(db_err)?;
        }
        if let Some(rm) = remark {
            conn.execute(
                "UPDATE rule SET remark = ?1, updated_at = ?2 WHERE id = ?3",
                params![rm, now, id],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    /// 引用该规则的权限组名称列表
    pub fn rule_referencing_groups(&self, rule_id: &str) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.name FROM \"group\" g JOIN group_rule gr ON g.id = gr.group_id WHERE gr.rule_id = ?1",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![rule_id], |r| r.get(0))
            .map_err(db_err)?;
        let mut names = Vec::new();
        for n in rows {
            names.push(n.map_err(db_err)?);
        }
        Ok(names)
    }

    pub fn delete_rule(&self, id: &str, force: bool) -> Result<()> {
        let conn = self.conn();
        if force {
            conn.execute("DELETE FROM group_rule WHERE rule_id = ?1", params![id])
                .map_err(db_err)?;
        }
        conn.execute("DELETE FROM rule WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    /// 查询某权限组关联的全部规则
    pub fn rules_of_group(&self, group_id: &str) -> Result<Vec<RuleRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT r.id, r.type, r.value, r.resolve, r.remark, r.created_at, r.updated_at, 0
                 FROM rule r JOIN group_rule gr ON r.id = gr.rule_id WHERE gr.group_id = ?1",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![group_id], |r| {
                Ok(RuleRecord {
                    id: r.get(0)?,
                    rule_type: r.get(1)?,
                    value: r.get(2)?,
                    resolve: r.get::<_, i32>(3)? != 0,
                    remark: r.get(4)?,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                    group_count: r.get(7)?,
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok(items)
    }

    /// 查询某账号（经其权限组）可访问的全部规则
    pub fn rules_of_account(&self, account_id: &str) -> Result<Vec<RuleRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT r.id, r.type, r.value, r.resolve, r.remark, r.created_at, r.updated_at, 0
                 FROM rule r
                 JOIN group_rule gr ON r.id = gr.rule_id
                 JOIN account a ON a.group_id = gr.group_id
                 WHERE a.id = ?1",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![account_id], |r| {
                Ok(RuleRecord {
                    id: r.get(0)?,
                    rule_type: r.get(1)?,
                    value: r.get(2)?,
                    resolve: r.get::<_, i32>(3)? != 0,
                    remark: r.get(4)?,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                    group_count: r.get(7)?,
                })
            })
            .map_err(db_err)?;
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok(items)
    }

    // ==================== Group ====================

    pub fn list_groups(
        &self,
        page: u32,
        page_size: u32,
        q: Option<&str>,
    ) -> Result<(Vec<GroupRecord>, i64)> {
        let conn = self.conn();
        let (where_sql, pattern) = match q {
            Some(q) => ("WHERE g.name LIKE ?1 OR g.remark LIKE ?1", format!("%{q}%")),
            None => ("", String::new()),
        };

        let total: i64 = if pattern.is_empty() {
            conn.query_row("SELECT COUNT(*) FROM \"group\"", [], |r| r.get(0))
                .map_err(db_err)?
        } else {
            conn.query_row(
                &format!("SELECT COUNT(*) FROM \"group\" g {where_sql}"),
                params![pattern],
                |r| r.get(0),
            )
            .map_err(db_err)?
        };

        let offset = (page.saturating_sub(1)) * page_size;
        let sql = format!(
            "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at,
                    (SELECT COUNT(*) FROM group_rule gr WHERE gr.group_id = g.id),
                    (SELECT COUNT(*) FROM account a WHERE a.group_id = g.id)
             FROM \"group\" g {where_sql} ORDER BY g.created_at DESC LIMIT {page_size} OFFSET {offset}"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = if pattern.is_empty() {
            stmt.query_map([], map_group_row).map_err(db_err)?
        } else {
            stmt.query_map(params![pattern], map_group_row)
                .map_err(db_err)?
        };
        let mut items = Vec::new();
        for r in rows {
            items.push(r.map_err(db_err)?);
        }
        Ok((items, total))
    }

    pub fn get_group(&self, id: &str) -> Result<Option<GroupRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at,
                        (SELECT COUNT(*) FROM group_rule gr WHERE gr.group_id = g.id),
                        (SELECT COUNT(*) FROM account a WHERE a.group_id = g.id)
                 FROM \"group\" g WHERE g.id = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_group_row(r).map_err(db_err)?),
            None => None,
        })
    }

    pub fn get_group_by_name(&self, name: &str) -> Result<Option<GroupRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at, 0, 0 FROM \"group\" g WHERE g.name = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![name]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_group_row(r).map_err(db_err)?),
            None => None,
        })
    }

    pub fn create_group(&self, name: &str, remark: &str) -> Result<GroupRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO \"group\" (id, name, remark, created_at, updated_at) VALUES (?1,?2,?3,?4,?4)",
            params![id, name, remark, now],
        )
        .map_err(db_err)?;
        Ok(GroupRecord {
            id,
            name: name.to_string(),
            remark: remark.to_string(),
            rule_count: 0,
            account_count: 0,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn update_group(&self, id: &str, name: Option<&str>, remark: Option<&str>) -> Result<()> {
        let conn = self.conn();
        let now = now_rfc3339();
        if let Some(n) = name {
            conn.execute(
                "UPDATE \"group\" SET name = ?1, updated_at = ?2 WHERE id = ?3",
                params![n, now, id],
            )
            .map_err(db_err)?;
        }
        if let Some(r) = remark {
            conn.execute(
                "UPDATE \"group\" SET remark = ?1, updated_at = ?2 WHERE id = ?3",
                params![r, now, id],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    /// 全量设置权限组关联的规则
    pub fn set_group_rules(&self, group_id: &str, rule_ids: &[String]) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM group_rule WHERE group_id = ?1",
            params![group_id],
        )
        .map_err(db_err)?;
        for rid in rule_ids {
            conn.execute(
                "INSERT OR IGNORE INTO group_rule (group_id, rule_id) VALUES (?1, ?2)",
                params![group_id, rid],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    pub fn count_accounts_in_group(&self, group_id: &str) -> Result<i64> {
        let conn = self.conn();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM account WHERE group_id = ?1",
                params![group_id],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        Ok(count)
    }

    pub fn delete_group(&self, id: &str, force: bool) -> Result<()> {
        let conn = self.conn();
        if force {
            conn.execute("DELETE FROM account WHERE group_id = ?1", params![id])
                .map_err(db_err)?;
        }
        conn.execute("DELETE FROM \"group\" WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }
}

fn map_group_row(r: &rusqlite::Row) -> rusqlite::Result<GroupRecord> {
    Ok(GroupRecord {
        id: r.get(0)?,
        name: r.get(1)?,
        remark: r.get(2)?,
        created_at: r.get(3)?,
        updated_at: r.get(4)?,
        rule_count: r.get(5)?,
        account_count: r.get(6)?,
    })
}
