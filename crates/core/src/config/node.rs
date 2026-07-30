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

    /// HTTP API 监听配置
    #[serde(default)]
    pub api: ApiConfig,

    /// Relay listener 配置（上游角色）
    pub listener: Option<ListenerConfig>,

    /// Relay connector 配置（下游角色）
    pub connector: Option<ConnectorConfig>,
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

    /// TLS 证书路径
    pub cert_path: String,

    /// TLS 私钥路径
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    /// 上游地址 (e.g. "1.2.3.4:443")
    pub upstream_addr: String,

    /// 认证 token
    pub token: String,

    /// TLS SNI 域名（伪装用）
    #[serde(default = "default_sni")]
    pub sni_hostname: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: default_node_name(),
            db_path: default_db_path(),
            api: ApiConfig::default(),
            listener: None,
            connector: None,
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

fn default_sni() -> String {
    "cdn.cloudflare.com".into()
}
