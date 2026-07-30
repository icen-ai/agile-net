//! 数据库模型定义

use serde::{Deserialize, Serialize};

/// 用户角色
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]

pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "admin" => UserRole::Admin,
            _ => UserRole::User,
        }
    }
}

/// 用户记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: String,
    pub updated_at: String,
}

/// 节点状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeStatus {
    Online,
    Offline,
    Disabled,
}

impl NodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeStatus::Online => "online",
            NodeStatus::Offline => "offline",
            NodeStatus::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "online" => NodeStatus::Online,
            "disabled" => NodeStatus::Disabled,
            _ => NodeStatus::Offline,
        }
    }
}

/// 节点记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: String,
    pub name: String,
    pub token: String,
    pub status: NodeStatus,
    pub last_seen: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// 路由匹配规则类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RoutePatternType {
    Cidr,
    ExactHost,
    WildcardHost,
}

impl RoutePatternType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RoutePatternType::Cidr => "cidr",
            RoutePatternType::ExactHost => "exact_host",
            RoutePatternType::WildcardHost => "wildcard_host",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "cidr" => RoutePatternType::Cidr,
            "wildcard_host" => RoutePatternType::WildcardHost,
            _ => RoutePatternType::ExactHost,
        }
    }
}

/// 路由规则记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRecord {
    pub id: String,
    pub pattern: String,
    pub pattern_type: RoutePatternType,
    pub outbound_type: String, // "direct" 或 "tunnel"
    pub node_id: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// 系统配置键值项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfigItem {
    pub key: String,
    pub value: String,
    pub description: Option<String>,
    pub updated_at: String,
}

/// 权限组记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecord {
    pub id: String,
    pub name: String,
    pub remark: String,
    pub created_at: String,
    pub updated_at: String,
}

/// 客户端账号记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub id: String,
    pub username: String,
    pub group_id: String,
    pub group_name: Option<String>,
    pub enabled: bool,
    pub remark: String,
    pub created_at: String,
    pub updated_at: String,
}

