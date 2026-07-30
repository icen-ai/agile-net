//! 控制消息定义（帧 payload 的结构化数据）

use serde::{Deserialize, Serialize};

/// 认证主体类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    /// 下游节点（PSK token 认证）
    Node,
    /// 客户端账号（tunnel_token 认证）
    Client,
}

/// Auth 帧 payload：connector / client 发给 listener。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub node_id: String,
    pub token: String,
    /// 认证主体类型，默认为节点（兼容旧实现）
    #[serde(default = "default_kind")]
    pub kind: AuthKind,
    /// 节点通告的可服务网段/域名（仅 kind = Node 有效）
    #[serde(default)]
    pub advertise: Vec<String>,
    /// 协议版本号，便于后续协商
    #[serde(default = "default_version")]
    pub version: u32,
}

fn default_kind() -> AuthKind {
    AuthKind::Node
}

fn default_version() -> u32 {
    1
}

/// 当前协议版本。
pub const PROTOCOL_VERSION: u32 = 1;

/// Open 帧 payload：listener 发给 connector，要求打开到目标的数据通道。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenChannel {
    pub target_addr: String,
    pub target_port: u16,
}

/// OpenFail 帧 payload。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFailed {
    pub reason: String,
}

/// 控制消息枚举，方便统一处理。
#[derive(Debug, Clone)]
pub enum ControlMessage {
    Auth(AuthRequest),
    AuthOk,
    AuthFail(String),
    Open(OpenChannel),
    OpenOk,
    OpenFail(OpenFailed),
    Ping,
    Pong,
    Close,
}
