//! 控制消息定义（帧 payload 的结构化数据）

use serde::{Deserialize, Serialize};

/// Auth 帧 payload：connector 发给 listener。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub node_id: String,
    pub token: String,
}

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
