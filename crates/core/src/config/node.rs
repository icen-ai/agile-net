//! 节点配置模型

use serde::{Deserialize, Serialize};

/// 节点总配置，对应 `agile-net.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// 节点显示名称
    #[serde(default = "default_node_name")]
    pub name: String,

    /// 数据库文件路径
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// 对外展示的公网接入地址（connect_url 用，不含端口）
    #[serde(default)]
    pub public_host: Option<String>,

    /// HTTP API 监听配置
    #[serde(default)]
    pub api: ApiConfig,

    /// Relay listener 配置（上游角色）
    pub listener: Option<ListenerConfig>,

    /// Relay connector 配置（下游角色）
    pub connector: Option<ConnectorConfig>,

    /// 本地代理入站配置
    pub proxy: Option<ProxyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// 监听地址
    #[serde(default = "default_api_addr")]
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// 监听地址 (e.g. "0.0.0.0:443")
    pub addr: String,

    /// TLS 证书路径（不存在时自动生成自签证书并持久化）
    #[serde(default = "default_cert_path")]
    pub cert_path: String,

    /// TLS 私钥路径
    #[serde(default = "default_key_path")]
    pub key_path: String,

    /// 自签证书 SAN / 对外 SNI 域名
    #[serde(default = "default_sni")]
    pub sni_hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    /// 上游地址 (e.g. "1.2.3.4:443")
    pub upstream_addr: String,

    /// 认证 token（relay PSK）
    pub token: String,

    /// TLS SNI 域名（伪装用）
    #[serde(default = "default_sni")]
    pub sni_hostname: String,

    /// 向上游通告的可服务网段/域名
    #[serde(default)]
    pub advertise: Vec<String>,

    /// 自定义 CA 证书路径（PEM）
    #[serde(default)]
    pub ca_cert_path: Option<String>,

    /// 证书固定：上游服务端证书路径（PEM，钉入信任）
    #[serde(default)]
    pub pinned_cert_path: Option<String>,

    /// 跳过证书校验（仅开发调试，生产严禁）
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// 监听地址（默认仅 loopback；暴露到非 loopback 必须配置认证）
    #[serde(default = "default_proxy_addr")]
    pub addr: String,

    /// 可选认证用户名
    #[serde(default)]
    pub username: Option<String>,

    /// 可选认证密码
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
            connector: None,
            proxy: None,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            addr: default_api_addr(),
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
    "0.0.0.0:9090".into()
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
