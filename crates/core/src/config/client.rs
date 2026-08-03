//! Client config model

use serde::{Deserialize, Serialize};

/// Routing config the client pulls from the node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Config version, for incremental updates
    pub version: u64,

    /// Routing rule list
    pub rules: Vec<RuleEntry>,

    /// Node name
    pub node_name: String,
}

/// A single routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    /// Rule type: "ip-cidr" | "host"
    pub rule_type: String,

    /// Value: CIDR like "10.12.0.0/16" or a domain like "git.internal.com"
    pub value: String,

    /// Whether to resolve the domain to an IP (host rules only)
    #[serde(default)]
    pub resolve: bool,
}
