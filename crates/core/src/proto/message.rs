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

/// 握手 v2：上游在 AuthOk 中向暴露控制面的下游下发的管理端点。
///
/// 安全边界：票据安全等同中继令牌本身（psK 持有者随时可重连换新票），
/// TTL 仅约束泄露窗口；吊销令牌 + 踢会话即全线回收。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlOffer {
    pub exposed: bool,
    /// 上游 API 主机（public_host；缺省时下游以 connector 配置的上游地址代替）
    #[serde(default)]
    pub api_host: Option<String>,
    /// 上游管理 API 端口
    pub api_port: u16,
    /// 上游节点显示名（可管理节点自动发现）
    #[serde(default)]
    pub node_name: String,
    /// 管理引导票据（/api/v1/auth/admin-bootstrap 换取 scoped 管理会话）
    pub ticket: String,
    /// 管理授权档位：ro / rules / full
    #[serde(default = "default_control_scope")]
    pub scope: String,
}

fn default_control_scope() -> String {
    "full".into()
}

/// 当前协议版本（v2：per-channel 窗口流控；AuthOk 可选 control 扩展向后兼容）。
pub const PROTOCOL_VERSION: u32 = 2;

/// 支持 per-channel 窗口流控的最低协议版本。
pub const PROTOCOL_VERSION_FLOW_CONTROL: u32 = 2;

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
