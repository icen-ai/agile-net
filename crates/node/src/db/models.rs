//! 数据库模型定义（对应 docs/database/schema.md）

use serde::{Deserialize, Serialize};

/// 管理员记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRecord {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: String,
    pub updated_at: String,
}

/// 路由规则记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRecord {
    pub id: String,
    /// "ip-cidr" | "host"
    #[serde(rename = "type")]
    pub rule_type: String,
    pub value: String,
    pub resolve: bool,
    pub remark: String,
    #[serde(default)]
    pub group_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// 权限组记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecord {
    pub id: String,
    pub name: String,
    pub remark: String,
    #[serde(default)]
    pub rule_count: i64,
    #[serde(default)]
    pub account_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// 客户端账号记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub id: String,
    pub username: String,
    pub group_id: String,
    #[serde(default)]
    pub group_name: Option<String>,
    pub enabled: bool,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub last_seen_at: Option<String>,
    pub remark: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Relay Token 记录（列表展示用，不含明文）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTokenRecord {
    pub id: String,
    pub token_prefix: String,
    pub remark: String,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

/// 审计日志记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub id: String,
    pub admin_id: Option<String>,
    pub operator: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub ip: Option<String>,
    pub created_at: String,
}

/// 流量统计记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStatRecord {
    pub account_id: Option<String>,
    pub username: Option<String>,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
    pub connections: i64,
}

/// 流量时间序列点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPoint {
    pub time: String,
    pub bytes_tx: i64,
    pub bytes_rx: i64,
}
