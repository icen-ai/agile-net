//! Database model definitions (see docs/database/schema.md)

use serde::{Deserialize, Serialize};

/// Admin record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRecord {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Route rule record
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

/// Group record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecord {
    pub id: String,
    pub name: String,
    pub remark: String,
    /// E2E enforcement (federation P3): targets under this group require end-to-end encryption;
    /// such groups may only hang on delegated tokens, never on relay tokens/connectors.
    #[serde(default)]
    pub e2e_required: bool,
    #[serde(default)]
    pub rule_count: i64,
    /// Adoption lineage (federation P1): fan-in peer node_id + pushed group name of the source
    /// this group mirrors (both empty = plain local group). Mirrored groups are read-only and
    /// follow the source automatically; editing requires a copy.
    #[serde(default)]
    pub adopted_node: String,
    #[serde(default)]
    pub adopted_name: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Group reference embedded in list views (naming sovereignty: the name stays clean, the
/// adoption lineage rides `adopted_node` — empty = plain local group).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRef {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub adopted_node: String,
}

/// Relay token record (for list display; no plaintext)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTokenRecord {
    pub id: String,
    pub token_prefix: String,
    pub remark: String,
    /// Allow this fan-in relay to manage this node (default off)
    #[serde(default)]
    pub expose_control: bool,
    /// Admin grant scope: ro / rules / full
    #[serde(default = "default_control_scope")]
    pub control_scope: String,
    /// ACL mount point: group ID (None = no restriction, allow all)
    #[serde(default)]
    pub group_id: Option<String>,
    /// Resolved ACL group set (empty = unrestricted)
    #[serde(default)]
    pub groups: Vec<GroupRef>,
    /// Bandwidth quota (KB/s; None = unlimited)
    #[serde(default)]
    pub rate_limit_kbps: Option<i64>,
    /// Validity window (None = never expires)
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Usage cap: max successful fan-in auths (None = unlimited)
    #[serde(default)]
    pub max_uses: Option<i64>,
    /// Successful auths so far
    #[serde(default)]
    pub used_count: i64,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

fn default_control_scope() -> String {
    "full".into()
}

/// Audit log record
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

/// Node-level hourly traffic point (traffic_24h contract: hour is local time "YYYY-MM-DD HH:00")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTrafficPoint {
    pub hour: String,
    pub up: i64,
    pub down: i64,
}

/// Node-level 24h traffic aggregate across three dimensions (fan-in / fan-out / relay transit)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeTraffic24h {
    pub fanin: Vec<NodeTrafficPoint>,
    pub fanout: Vec<NodeTrafficPoint>,
    pub transit: Vec<NodeTrafficPoint>,
}

/// Admin bootstrap ticket redemption result (no hash/plaintext).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminTicketRecord {
    pub kind: String,
    pub subject: String,
    pub scope: String,
    pub expires_at: String,
}

/// Fan-out connector record (DB row; token_enc is ciphertext, never log/audit it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorRecord {
    pub id: String,
    /// Peer display name (for admin list / audit)
    pub name: String,
    pub upstream_addr: String,
    /// Fan-out token ciphertext (`v1:nonce_b64:ct_b64`, see docs/todo/peer-acl.md §5)
    #[serde(skip_serializing, default)]
    pub token_enc: String,
    pub sni_hostname: String,
    pub insecure: bool,
    /// Custom CA cert path (PEM; empty = unused)
    #[serde(default)]
    pub ca_cert_path: String,
    /// Cert pinning: upstream server cert path (PEM; empty = unused)
    #[serde(default)]
    pub pinned_cert_path: String,
    /// Cert fingerprint pinning (SHA-256 hex, out-of-band distribution; empty = unused)
    #[serde(default)]
    pub pinned_fingerprint: String,
    /// Serialized former ConnectorConfig.advertise
    pub advertise: String,
    /// ACL mount point: group ID (None = no restriction, allow all)
    #[serde(default)]
    pub group_id: Option<String>,
    /// Policy upload: comma-separated local group IDs pushed upstream at auth (empty = no upload; federation P1)
    #[serde(default)]
    pub push_groups: String,
    pub enabled: bool,
    pub remark: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Fan-out connector display view (with resolved group set; never contains token plaintext/ciphertext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorView {
    pub id: String,
    pub name: String,
    pub upstream_addr: String,
    /// Token prefix for identification only (not a full credential)
    pub token_prefix: String,
    pub sni_hostname: String,
    pub insecure: bool,
    #[serde(default)]
    pub ca_cert_path: String,
    #[serde(default)]
    pub pinned_cert_path: String,
    #[serde(default)]
    pub pinned_fingerprint: String,
    pub advertise: String,
    #[serde(default)]
    pub group_id: Option<String>,
    /// Resolved ACL group set (empty = unrestricted)
    #[serde(default)]
    pub groups: Vec<GroupRef>,
    /// Policy upload: comma-separated local group IDs pushed upstream at auth (empty = no upload; federation P1)
    #[serde(default)]
    pub push_groups: String,
    pub enabled: bool,
    pub remark: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Delegated token record (unified issuance; DB row — e2e_key_enc is ciphertext, never log/audit it).
///
/// Issued by the resource owner directly to a consumer. `entry_mode` = 'direct' (the consumer
/// dials this issuer's own listener; local registration) or 'relay' (registered upstream over
/// the fan-out session, disaster set, revoke-by-disconnect). `concurrency` = 'single' (a new
/// session kicks the old) or 'multi' (up to `max_sessions` concurrent sessions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedTokenRecord {
    pub id: String,
    /// SHA-256 of the token plaintext (the relay compares hashes; not a secret by itself)
    pub token_hash: String,
    pub token_prefix: String,
    pub label: String,
    /// JSON array of local group IDs (resolved to names when building the registration frame)
    pub groups: String,
    /// JSON array of {hint, groups} — entrust routing vocabulary (en_ words only; empty = transparent tier)
    pub hint_map: String,
    /// E2E channel master key ciphertext (`v1:nonce_b64:ct_b64`; same mechanism as connector tokens)
    #[serde(skip_serializing, default)]
    pub e2e_key_enc: String,
    /// Consumer mode: `dedicated` (专线, default) or `split` (分流 — E2E rule delivery)
    #[serde(default = "default_delegated_mode")]
    pub mode: String,
    /// Admin capability: '' = data-plane only; ro/rules/full = manage this issuer over the
    /// E2E admin channel (full additionally unlocks transit management of upstreams)
    #[serde(default)]
    pub admin_scope: String,
    /// Entry mode: 'direct' (dial the issuer directly) | 'relay' (via the disaster set)
    pub entry_mode: String,
    /// Concurrency tier: 'single' (kick-old) | 'multi' (bounded by max_sessions)
    pub concurrency: String,
    /// Session cap for the multi tier (snapshot of node_config.delegation_max_sessions at issue time)
    pub max_sessions: i64,
    /// Validity window (None = never expires)
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Usage cap: max data-plane opens (None = unlimited; counted on the issuer)
    #[serde(default)]
    pub max_uses: Option<i64>,
    /// Opens served so far
    #[serde(default)]
    pub used_count: i64,
    pub created_at: String,
    /// Disaster-set registration rows (one per upstream connector; empty for direct-entry tokens)
    #[serde(default)]
    pub regs: Vec<DelegatedTokenReg>,
}

/// Default consumer mode of a delegated token (the 专线 tier).
fn default_delegated_mode() -> String {
    "dedicated".to_string()
}

/// Disaster-set registration row: one upstream connector of a delegated token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedTokenReg {
    pub connector_id: String,
    pub is_primary: bool,
}
