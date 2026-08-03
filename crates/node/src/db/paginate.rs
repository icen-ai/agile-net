//! 分页列表查询公共 helper：归一 accounts/rules/logs 三处逐字复制的
//! 「where_clauses 构建 + bind_refs + COUNT + LIMIT/OFFSET」骨架。
//! 行为与原实现完全一致：绑定顺序 = where 绑定在前、末尾追加 (limit, offset)；
//! 无过滤条件时不加 WHERE；SQL 语义不变、查询结果不变。

use super::pool::db_err;
use agile_net_core::error::Result;

/// 分页查询：返回 (当前页条目, 符合条件的总数)。
///
/// - `select`：SELECT 列清单；`from`：FROM 片段（含表别名与 JOIN）；
/// - `where_clauses` 以 AND 拼接，为空时不加 WHERE；
/// - `bind` 与 where_clauses 中的 `?` 占位按序一一对应；
/// - `order_by`：排序片段（不含 `ORDER BY` 关键字）。
#[allow(clippy::too_many_arguments)]
pub(super) fn paged_query<T>(
    conn: &rusqlite::Connection,
    select: &str,
    from: &str,
    where_clauses: &[&str],
    bind: &[Box<dyn rusqlite::types::ToSql>],
    order_by: &str,
    page: u32,
    page_size: u32,
    map_row: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<(Vec<T>, i64)> {
    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let total: i64 = {
        let sql = format!("SELECT COUNT(*) FROM {from} {where_sql}");
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        stmt.query_row(
            rusqlite::params_from_iter(bind.iter().map(|b| b.as_ref())),
            |r| r.get(0),
        )
        .map_err(db_err)?
    };

    let offset = (page.saturating_sub(1)) * page_size;
    let sql =
        format!("SELECT {select} FROM {from} {where_sql} ORDER BY {order_by} LIMIT ? OFFSET ?");
    let mut stmt = conn.prepare(&sql).map_err(db_err)?;
    let mut bind_refs: Vec<&dyn rusqlite::types::ToSql> =
        bind.iter().map(|b| b.as_ref()).collect();
    let limit = page_size as i64;
    let off = offset as i64;
    bind_refs.push(&limit);
    bind_refs.push(&off);
    let rows = stmt
        .query_map(rusqlite::params_from_iter(bind_refs), map_row)
        .map_err(db_err)?;
    let mut items = Vec::new();
    for r in rows {
        items.push(r.map_err(db_err)?);
    }
    Ok((items, total))
}
