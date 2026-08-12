//! Split from db/mod.rs: rule/group/group_rule tables (pure move, no logic change)

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
        sort: Option<&str>,
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
        let order = super::paginate::order_clause(
            sort,
            &[("type", "r.type"), ("value", "r.value"), ("groups", "group_count"), ("created", "r.created_at")],
            "r.created_at DESC",
        );
        super::paginate::paged_query(
            &conn,
            "r.id, r.type, r.value, r.resolve, r.remark, r.created_at, r.updated_at,
             (SELECT COUNT(*) FROM group_rule gr WHERE gr.rule_id = r.id) AS group_count",
            "rule r",
            &where_clauses,
            &bind,
            &order,
            page,
            page_size,
            |r| {
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
            },
        )
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

    /// Find a rule's ID by its unique (type, value) pair (adoption dedup: reuse existing rules).
    pub fn find_rule_id(&self, rule_type: &str, value: &str) -> Result<Option<String>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id FROM rule WHERE type = ?1 AND value = ?2")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![rule_type, value]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(r.get(0).map_err(db_err)?),
            None => None,
        })
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

    /// Names of groups referencing this rule
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

    /// List all rules bound to a group
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

    /// All group→rules bindings in one query (group_id -> values). Used by the enforcement-cache
    /// rebuilds (refresh_groups) to avoid an N+1 per-group round-trip on startup and every
    /// group/rule change.
    pub fn rules_by_group_all(&self) -> Result<std::collections::HashMap<String, Vec<String>>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT gr.group_id, r.value FROM rule r JOIN group_rule gr ON r.id = gr.rule_id ORDER BY gr.group_id, r.value",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(db_err)?;
        let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for r in rows {
            let (gid, value) = r.map_err(db_err)?;
            map.entry(gid).or_default().push(value);
        }
        Ok(map)
    }

    // ==================== Group ====================

    pub fn list_groups(
        &self,
        page: u32,
        page_size: u32,
        q: Option<&str>,
        sort: Option<&str>,
    ) -> Result<(Vec<GroupRecord>, i64)> {
        let conn = self.conn();
        let mut where_clauses = Vec::new();
        let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(q) = q {
            where_clauses.push("(g.name LIKE ? OR g.remark LIKE ?)");
            bind.push(Box::new(format!("%{q}%")));
            bind.push(Box::new(format!("%{q}%")));
        }
        let order = super::paginate::order_clause(
            sort,
            &[("name", "g.name"), ("rules", "rule_count"), ("created", "g.created_at")],
            "g.created_at DESC",
        );
        super::paginate::paged_query(
            &conn,
            "g.id, g.name, g.remark, g.created_at, g.updated_at,
             (SELECT COUNT(*) FROM group_rule gr WHERE gr.group_id = g.id) AS rule_count,
             g.e2e_required, g.adopted_node, g.adopted_name",
            "\"group\" g",
            &where_clauses,
            &bind,
            &order,
            page,
            page_size,
            map_group_row,
        )
    }

    pub fn get_group(&self, id: &str) -> Result<Option<GroupRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at,
                        (SELECT COUNT(*) FROM group_rule gr WHERE gr.group_id = g.id),
                        g.e2e_required, g.adopted_node, g.adopted_name
                 FROM \"group\" g WHERE g.id = ?1",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_group_row(r).map_err(db_err)?),
            None => None,
        })
    }

    /// Group id -> name in one query (for cache rebuilds resolving token group ids en masse;
    /// avoids a per-id get_group round-trip on startup and every issuance/rule change).
    pub fn group_names_by_id(&self) -> Result<std::collections::HashMap<String, String>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT id, name FROM \"group\"")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(db_err)?;
        let mut map = std::collections::HashMap::new();
        for r in rows {
            let (id, name) = r.map_err(db_err)?;
            map.insert(id, name);
        }
        Ok(map)
    }

    /// Look up a LOCAL group by name (adopted mirrors excluded — name uniqueness is per-tier:
    /// local names are unique, adopted names are unique per source node).
    pub fn get_local_group_by_name(&self, name: &str) -> Result<Option<GroupRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at, 0, g.e2e_required, g.adopted_node, g.adopted_name FROM \"group\" g WHERE g.name = ?1 AND g.adopted_node = ''",
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
            e2e_required: false,
            rule_count: 0,
            adopted_node: String::new(),
            adopted_name: String::new(),
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

    /// Replace all rules bound to a group
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

    /// Create an adopted mirror group with lineage stamped at INSERT time (naming sovereignty):
    /// the name is the pure source name — uniqueness for adopted groups is (name, adopted_node),
    /// so a two-step create-then-stamp would wrongly hit the LOCAL unique index when a local
    /// group already carries the same name.
    pub fn create_adopted_group(
        &self,
        name: &str,
        remark: &str,
        node: &str,
        src_name: &str,
    ) -> Result<GroupRecord> {
        let conn = self.conn();
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_rfc3339();
        conn.execute(
            "INSERT INTO \"group\" (id, name, remark, adopted_node, adopted_name, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6)",
            params![id, name, remark, node, src_name, now],
        )
        .map_err(db_err)?;
        Ok(GroupRecord {
            id,
            name: name.to_string(),
            remark: remark.to_string(),
            e2e_required: false,
            rule_count: 0,
            adopted_node: node.to_string(),
            adopted_name: src_name.to_string(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// Every adopted (mirrored) group — the sync engine's working set.
    pub fn list_adopted_groups(&self) -> Result<Vec<GroupRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at,
                        (SELECT COUNT(*) FROM group_rule gr WHERE gr.group_id = g.id),
                        g.e2e_required, g.adopted_node, g.adopted_name
                 FROM \"group\" g WHERE g.adopted_node != ''",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query([]).map_err(db_err)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(db_err)? {
            out.push(map_group_row(r).map_err(db_err)?);
        }
        Ok(out)
    }

    /// The local mirror of one pushed group (adoption idempotence + the offered-pool status flag).
    pub fn find_adopted_group(&self, node: &str, src_name: &str) -> Result<Option<GroupRecord>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT g.id, g.name, g.remark, g.created_at, g.updated_at, 0, g.e2e_required, g.adopted_node, g.adopted_name
                 FROM \"group\" g WHERE g.adopted_node = ?1 AND g.adopted_name = ?2",
            )
            .map_err(db_err)?;
        let mut rows = stmt.query(params![node, src_name]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(map_group_row(r).map_err(db_err)?),
            None => None,
        })
    }

    pub fn delete_group(&self, id: &str, _force: bool) -> Result<()> {
        // group_rule bindings cascade via FK; token/connector CSV sets dangle on purpose
        // (the ACL registry converges them to deny-all, fail-closed)
        let conn = self.conn();
        conn.execute("DELETE FROM \"group\" WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(())
    }

    /// id -> display-ref map of all groups (naming sovereignty: name + adoption lineage).
    pub fn group_ref_map(&self) -> Result<std::collections::HashMap<String, super::models::GroupRef>> {
        let (groups, _) = self.list_groups(1, 10000, None, None)?;
        Ok(groups
            .into_iter()
            .map(|g| {
                (
                    g.id.clone(),
                    super::models::GroupRef {
                        id: g.id,
                        name: g.name,
                        adopted_node: g.adopted_node,
                    },
                )
            })
            .collect())
    }

    /// Resolve a stored group id set (None/single/comma-separated) to display refs
    /// (dangling ids echo verbatim with no lineage).
    pub fn group_refs_of(&self, group_id: Option<&str>) -> Vec<super::models::GroupRef> {
        let Some(set) = group_id else { return Vec::new() };
        let ids: Vec<&str> = set
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if ids.is_empty() {
            return Vec::new();
        }
        let map = self.group_ref_map().unwrap_or_default();
        ids.into_iter()
            .map(|id| {
                map.get(id).cloned().unwrap_or_else(|| super::models::GroupRef {
                    id: id.to_string(),
                    name: id.to_string(),
                    adopted_node: String::new(),
                })
            })
            .collect()
    }

    /// Total references from principals without an E2E key (relay tokens + connectors).
    /// An e2e_required group must stay attachable to delegated tokens only (federation P3 §1.4).
    /// relay_token / connector store a comma-separated group set (multi-group ACL) — membership
    /// is checked in Rust.
    pub fn group_attachment_count(&self, group_id: &str) -> Result<i64> {
        let conn = self.conn();
        let mut count: i64 = 0;
        for table in ["relay_token", "connector"] {
            let mut stmt = conn
                .prepare(&format!("SELECT group_id FROM {table} WHERE group_id IS NOT NULL"))
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(db_err)?;
            for v in rows {
                let csv = v.map_err(db_err)?;
                if csv.split(',').any(|s| s.trim() == group_id) {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Set the E2E enforcement flag (federation P3). Refuses to mark a group still referenced by
    /// relay tokens / connectors (those principals have no E2E key — fail closed).
    pub fn set_group_e2e_required(&self, id: &str, required: bool) -> Result<()> {
        if required && self.group_attachment_count(id)? > 0 {
            return Err(agile_net_core::error::Error::Other(
                "该组仍被扇入令牌/扇出连接引用，不可标记端到端加密".into(),
            ));
        }
        let conn = self.conn();
        conn.execute(
            "UPDATE \"group\" SET e2e_required = ?1, updated_at = ?2 WHERE id = ?3",
            params![required as i64, now_rfc3339(), id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Whether the group carries the E2E enforcement flag (None = group missing).
    pub fn group_e2e_required(&self, id: &str) -> Result<Option<bool>> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare("SELECT e2e_required FROM \"group\" WHERE id = ?1")
            .map_err(db_err)?;
        let mut rows = stmt.query(params![id]).map_err(db_err)?;
        Ok(match rows.next().map_err(db_err)? {
            Some(r) => Some(r.get::<_, i64>(0).map_err(db_err)? != 0),
            None => None,
        })
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
        e2e_required: r.get::<_, i64>(6)? != 0,
        adopted_node: r.get(7)?,
        adopted_name: r.get(8)?,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_name_uniqueness_is_split_local_vs_adopted() {
        let db = Database::in_memory().unwrap();

        // local names unique
        db.create_group("git", "").unwrap();
        assert!(db.create_group("git", "").is_err(), "local name dup must fail");

        // adopted mirrors may share the local name (source shown as a badge, not in the name)
        let a = db.create_adopted_group("git", "", "peer-c", "git").unwrap();
        assert_eq!(a.adopted_node, "peer-c");
        // same name from a different source node also coexists
        db.create_adopted_group("git", "", "peer-d", "git").unwrap();
        // but the same (name, source node) pair is unique
        assert!(
            db.create_adopted_group("git", "", "peer-c", "git").is_err(),
            "same name from the same node must fail"
        );

        // name lookups are local-only: the adopted mirrors stay invisible to conflict checks
        let local = db.get_local_group_by_name("git").unwrap().unwrap();
        assert_eq!(local.adopted_node, "");
        assert!(db.find_adopted_group("peer-c", "git").unwrap().is_some());
    }
}
