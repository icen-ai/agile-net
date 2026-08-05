//! Handler collection

pub mod accounts;
pub mod admins;
pub mod audit;
pub mod auth;
pub mod client;
pub mod connectors;
pub mod delegation;
pub mod federation;
pub mod groups;
pub mod node;
pub mod relay_tokens;
pub mod rules;
pub mod tool;

use crate::api::ApiState;
use crate::auth::jwt::Claims;

/// Audit log recording (single entry point for sensitive ops; DB write offloaded via db_call, never blocks a worker).
pub(crate) async fn audit(
    state: &ApiState,
    claims: &Claims,
    ip: &std::net::IpAddr,
    action: &str,
    target: Option<&str>,
    detail: &str,
) {
    let (sub, username, action, target, detail, ip) = (
        claims.sub.clone(),
        claims.username.clone(),
        action.to_string(),
        target.map(str::to_string),
        if detail.is_empty() {
            None
        } else {
            Some(detail.to_string())
        },
        ip.to_string(),
    );
    let _ = state
        .db_call(move |db| {
            db.record_audit_log(
                Some(&sub),
                &username,
                &action,
                target.as_deref(),
                detail.as_deref(),
                Some(&ip),
            )
        })
        .await;
}

/// Token lifecycle status for list rendering (docs/todo/e2e.md §8):
/// "expired" | "exhausted" | "expiring" (< 72h remaining) | "active".
pub(crate) fn lifecycle_status(
    expires_at: Option<&str>,
    max_uses: Option<i64>,
    used_count: i64,
) -> &'static str {
    if !crate::db::expiry_active(expires_at) {
        return "expired";
    }
    if crate::db::uses_exhausted(max_uses, used_count) {
        return "exhausted";
    }
    if let Some(s) = expires_at
        && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s)
    {
        let remain = dt.with_timezone(&chrono::Utc) - chrono::Utc::now();
        if remain < chrono::Duration::hours(72) {
            return "expiring";
        }
    }
    "active"
}
