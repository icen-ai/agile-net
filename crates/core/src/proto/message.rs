//! Control message definitions (structured data in frame payloads)

use serde::{Deserialize, Serialize};

/// Auth principal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    /// Fan-out endpoint (PSK token auth)
    Node,
    /// Client account (tunnel_token auth)
    Client,
}

/// Policy group pushed by a fan-out endpoint at auth (federation P1: policy upload).
///
/// The listener tags it with the session's node_id (source tag, namespace isolation) and
/// offers it in the upstream authorizable pool; the upstream admin adopts it into a local
/// group in one click. Old upstreams ignore this field (serde default, backwards compatible).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedGroupMsg {
    pub name: String,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub rules: Vec<String>,
}

/// Auth frame payload: connector / client -> listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub node_id: String,
    pub token: String,
    /// Auth principal type; defaults to node (backwards compatible)
    #[serde(default = "default_kind")]
    pub kind: AuthKind,
    /// CIDRs/domains the node advertises as servable (only for kind = Node)
    #[serde(default)]
    pub advertise: Vec<String>,
    /// Policy groups pushed upstream for the authorizable pool (only for kind = Node; federation P1)
    #[serde(default)]
    pub groups: Vec<PushedGroupMsg>,
    /// Protocol version, for future negotiation
    #[serde(default = "default_version")]
    pub version: u32,
}

fn default_kind() -> AuthKind {
    AuthKind::Node
}

fn default_version() -> u32 {
    1
}

/// Handshake v2: admin endpoint the fan-in side sends in AuthOk to a fan-out
/// endpoint that exposes its control plane.
///
/// Security boundary: a ticket is only as safe as the relay token itself (a PSK
/// holder can reconnect anytime for a fresh one); the TTL only bounds the leak
/// window. Revoking the token + kicking the session retracts everything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlOffer {
    pub exposed: bool,
    /// Fan-in API host (public_host; if absent the fan-out side falls back to the connector's configured address)
    #[serde(default)]
    pub api_host: Option<String>,
    /// Fan-in admin API port
    pub api_port: u16,
    /// Fan-in node display name (manageable-node auto-discovery)
    #[serde(default)]
    pub node_name: String,
    /// Admin bootstrap ticket (redeemed at /api/v1/auth/admin-bootstrap for a scoped admin session)
    pub ticket: String,
    /// Admin scope tier: ro / rules / full
    #[serde(default = "default_control_scope")]
    pub scope: String,
}

fn default_control_scope() -> String {
    "full".into()
}

/// Current protocol version (v2: per-channel window flow control; the optional
/// AuthOk control extension is backwards compatible).
pub const PROTOCOL_VERSION: u32 = 2;

/// Minimum protocol version supporting per-channel window flow control.
pub const PROTOCOL_VERSION_FLOW_CONTROL: u32 = 2;

/// Open frame payload: listener -> connector, asking to open a data channel to the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenChannel {
    pub target_addr: String,
    pub target_port: u16,
}

/// OpenFail frame payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenFailed {
    pub reason: String,
}

/// Control message enum for uniform handling.
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
