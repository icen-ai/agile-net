//! Shared helper for paged list queries: unifies the verbatim-duplicated
//! "where_clauses build + bind_refs + COUNT + LIMIT/OFFSET" skeleton in relay_tokens/rules/logs.
//! Behavior identical to the original: bind order = where binds first, then (limit, offset);
//! no WHERE when there are no filters; SQL semantics and results unchanged.

use super::pool::db_err;
use agile_net_core::error::Result;

/// Whitelisted ORDER BY for the paged list endpoints: `sort` arrives as "col:dir"; the map pairs the
/// public column id with its SQL fragment, so no raw input ever reaches the SQL text.
pub(super) fn order_clause(sort: Option<&str>, map: &[(&str, &str)], default: &str) -> String {
    if let Some(s) = sort {
        if let Some((col, dir)) = s.split_once(':') {
            if let Some((_, frag)) = map.iter().find(|(k, _)| *k == col) {
                return format!("{} {}", frag, if dir == "asc" { "ASC" } else { "DESC" });
            }
        }
    }
    default.to_string()
}

/// Paged query: returns (page items, total count matching filters).
///
/// - `select`: SELECT column list; `from`: FROM fragment (with table alias and JOIN);
/// - `where_clauses` joined with AND; no WHERE when empty;
/// - `bind` maps 1:1 in order to the `?` placeholders in where_clauses;
/// - `order_by`: sort fragment (without the `ORDER BY` keyword).
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
