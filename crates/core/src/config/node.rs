//! Node config model

use serde::{Deserialize, Serialize};

/// Top-level node config, corresponding to `agile-net.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node display name
    #[serde(default = "default_node_name")]
    pub name: String,

    /// Database file path
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Public access address shown to clients (for connect_url, without port)
    #[serde(default)]
    pub public_host: Option<String>,

    /// HTTP API listener config
    #[serde(default)]
    pub api: ApiConfig,

    /// Relay listener config (fan-in role: accepts fan-in endpoints connecting in)
    pub listener: Option<ListenerConfig>,

    /// Relay connector config (fan-out role: `[[connectors]]` array, multi-target fan-out/failover)
    #[serde(default)]
    pub connectors: Vec<ConnectorConfig>,

    /// Local proxy inbound config
    pub proxy: Option<ProxyConfig>,

    /// ACME auto-cert config (Let's Encrypt, TLS-ALPN-01)
    pub acme: Option<AcmeConfig>,

    /// File log config
    pub log: Option<LogConfig>,

    /// Security rate-limit config
    pub limits: Option<LimitsConfig>,
}

/// File log config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log directory (enables daily rolling file logs when set)
    #[serde(default = "default_log_dir")]
    pub dir: String,
    /// File name prefix
    #[serde(default = "default_log_prefix")]
    pub prefix: String,
}

/// Security rate-limit config (data plane and API plane).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Relay max concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Relay max pending-auth connections
    #[serde(default = "default_max_pending_auth")]
    pub max_pending_auth: usize,
    /// Relay auth failure rate limit (per minute per IP)
    #[serde(default = "default_auth_failures")]
    pub auth_failures_per_minute: u32,
    /// Login rate limit (per minute per IP)
    #[serde(default = "default_login_per_minute")]
    pub login_per_minute: u32,
    /// Consecutive-failure lock threshold
    #[serde(default = "default_lock_threshold")]
    pub login_lock_threshold: u32,
    /// Lock duration (minutes)
    #[serde(default = "default_lock_minutes")]
    pub login_lock_minutes: u32,
}

/// ACME auto-cert config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Cert domain (must resolve to this node's relay port)
    pub domain: String,

    /// Account contact email
    pub email: String,

    /// Use Let's Encrypt Staging (for testing)
    #[serde(default)]
    pub staging: bool,

    /// Days before expiry to renew (default 30)
    #[serde(default = "default_renew_days")]
    pub renew_days: u32,

    /// Custom CA directory URL (default Let's Encrypt)
    #[serde(default)]
    pub directory_url: Option<String>,

    /// Issued cert storage path
    #[serde(default = "default_acme_cert_path")]
    pub cert_path: String,

    /// Issued private key storage path
    #[serde(default = "default_acme_key_path")]
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Listen address
    #[serde(default = "default_api_addr")]
    pub addr: String,

    /// API HTTPS cert path (admin API is served over HTTPS when set)
    #[serde(default)]
    pub tls_cert_path: Option<String>,

    /// API HTTPS private key path
    #[serde(default)]
    pub tls_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Listen address (e.g. "0.0.0.0:443")
    pub addr: String,

    /// TLS cert path (a self-signed cert is generated and persisted if absent)
    #[serde(default = "default_cert_path")]
    pub cert_path: String,

    /// TLS private key path
    #[serde(default = "default_key_path")]
    pub key_path: String,

    /// Self-signed cert SAN / public SNI hostname
    #[serde(default = "default_sni")]
    pub sni_hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    /// Fan-in address (e.g. "1.2.3.4:443")
    pub upstream_addr: String,

    /// Auth token (relay PSK)
    pub token: String,

    /// TLS SNI hostname (camouflage)
    #[serde(default = "default_sni")]
    pub sni_hostname: String,

    /// Servable CIDRs/domains advertised to the fan-in side
    #[serde(default)]
    pub advertise: Vec<String>,

    /// Custom CA cert path (PEM)
    #[serde(default)]
    pub ca_cert_path: Option<String>,

    /// Cert pinning: fan-in server cert path (PEM, pinned trust)
    #[serde(default)]
    pub pinned_cert_path: Option<String>,

    /// Skip cert verification (dev/debug only, forbidden in production)
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Listen address (loopback only by default; auth is required when exposing beyond loopback)
    #[serde(default = "default_proxy_addr")]
    pub addr: String,

    /// Optional auth username
    #[serde(default)]
    pub username: Option<String>,

    /// Optional auth password
    #[serde(default)]
    pub password: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: default_node_name(),
            db_path: default_db_path(),
            public_host: None,
            api: ApiConfig::default(),
            listener: None,
            connectors: Vec::new(),
            proxy: None,
            acme: None,
            log: None,
            limits: None,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            addr: default_api_addr(),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

fn default_node_name() -> String {
    "AgileNet Node".into()
}

fn default_db_path() -> String {
    "agile-net.db".into()
}

fn default_api_addr() -> String {
    "0.0.0.0:59090".into()
}

fn default_proxy_addr() -> String {
    "127.0.0.1:1080".into()
}

fn default_cert_path() -> String {
    "certs/relay-cert.pem".into()
}

fn default_key_path() -> String {
    "certs/relay-key.pem".into()
}

fn default_sni() -> String {
    "cdn.cloudflare.com".into()
}

fn default_renew_days() -> u32 {
    30
}

fn default_acme_cert_path() -> String {
    "certs/acme-cert.pem".into()
}

fn default_acme_key_path() -> String {
    "certs/acme-key.pem".into()
}

fn default_log_dir() -> String {
    "logs".into()
}

fn default_log_prefix() -> String {
    "agile-net".into()
}

fn default_max_connections() -> usize {
    1024
}

fn default_max_pending_auth() -> usize {
    256
}

fn default_auth_failures() -> u32 {
    20
}

fn default_login_per_minute() -> u32 {
    5
}

fn default_lock_threshold() -> u32 {
    5
}

fn default_lock_minutes() -> u32 {
    15
}
