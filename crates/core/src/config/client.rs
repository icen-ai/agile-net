//! 客户端配置模型

use serde::{Deserialize, Serialize};

/// Client 从 Node 拉取的路由配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// 配置版本号，用于增量更新
    pub version: u64,

    /// 路由规则列表
    pub rules: Vec<RuleEntry>,

    /// 节点名称
    pub node_name: String,
}

/// 单条路由规则。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    /// 规则类型："ip-cidr" | "host"
    pub rule_type: String,

    /// 值：CIDR 如 "10.12.0.0/16" 或域名如 "git.internal.com"
    pub value: String,

    /// 是否解析域名到 IP（仅 host 类型有效）
    #[serde(default)]
    pub resolve: bool,
}
