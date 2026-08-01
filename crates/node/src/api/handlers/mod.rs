//! Handlers 集合

pub mod accounts;
pub mod admins;
pub mod audit;
pub mod auth;
pub mod client;
pub mod connectors;
pub mod groups;
pub mod node;
pub mod relay_tokens;
pub mod rules;

use crate::api::ApiState;
use crate::auth::jwt::Claims;

/// 审计日志记录（敏感操作统一调用）。
pub(crate) fn audit(
    state: &ApiState,
    claims: &Claims,
    ip: &std::net::IpAddr,
    action: &str,
    target: Option<&str>,
    detail: &str,
) {
    let _ = state.db.record_audit_log(
        Some(&claims.sub),
        &claims.username,
        action,
        target,
        if detail.is_empty() {
            None
        } else {
            Some(detail)
        },
        Some(&ip.to_string()),
    );
}
