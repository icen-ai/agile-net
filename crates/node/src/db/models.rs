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
    /// 「管理此节点」权限（管理版接入链接）
    #[serde(default)]
    pub admin_console: bool,
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
    /// 允许该下游中继管理本节点（默认关）
    #[serde(default)]
    pub expose_control: bool,
    /// 管理授权档位：ro / rules / full
    #[serde(default = "default_control_scope")]
    pub control_scope: String,
    /// 收敛挂载点：权限组 ID（None = 不收敛，放行一切）
    #[serde(default)]
    pub group_id: Option<String>,
    /// 组名（联查展示用）
    #[serde(default)]
    pub group_name: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

fn default_control_scope() -> String {
    "full".into()
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

/// 管理引导票据核销结果（不含哈希/明文）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminTicketRecord {
    pub kind: String,
    pub subject: String,
    pub scope: String,
    pub expires_at: String,
}

/// 扇出 Connector 记录（DB 行；token_enc 为密文，严禁日志/审计输出）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorRecord {
    pub id: String,
    /// 对端显示名（管理端列表/审计用）
    pub name: String,
    pub upstream_addr: String,
    /// 扇出 token 密文（`v1:nonce_b64:ct_b64`，见 docs/todo/peer-acl.md §5）
    #[serde(skip_serializing, default)]
    pub token_enc: String,
    pub sni_hostname: String,
    pub insecure: bool,
    /// 自定义 CA 证书路径（PEM；空 = 不使用）
    #[serde(default)]
    pub ca_cert_path: String,
    /// 证书固定：上游服务端证书路径（PEM；空 = 不使用）
    #[serde(default)]
    pub pinned_cert_path: String,
    /// 原 ConnectorConfig.advertise 序列化
    pub advertise: String,
    /// 收敛挂载点：权限组 ID（None = 不收敛，放行一切）
    #[serde(default)]
    pub group_id: Option<String>,
    pub enabled: bool,
    pub remark: String,
    pub created_at: String,
    pub updated_at: String,
}

/// 扇出 Connector 展示视图（含组名联查；绝不含 token 明文/密文）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorView {
    pub id: String,
    pub name: String,
    pub upstream_addr: String,
    /// token 前缀展示位（仅用于辨认，非完整凭据）
    pub token_prefix: String,
    pub sni_hostname: String,
    pub insecure: bool,
    #[serde(default)]
    pub ca_cert_path: String,
    #[serde(default)]
    pub pinned_cert_path: String,
    pub advertise: String,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub group_name: Option<String>,
    pub enabled: bool,
    pub remark: String,
    pub created_at: String,
    pub updated_at: String,
}
