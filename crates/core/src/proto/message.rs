//! Control message definitions (structured data in frame payloads)

use serde::{Deserialize, Serialize};

/// Auth principal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthKind {
    /// Fan-out endpoint (PSK token auth)
    Node,
    /// Delegated consumer client (unified-issuance delegated token auth)
    Client,
}

/// Policy group pushed by a fan-out endpoint at auth (federation P1: policy upload).
///
/// The listener tags it with the session's node_id (source tag, namespace isolation) and
/// offers it in the upstream authorizable pool; the upstream admin adopts it into a local
/// group in one click. `e2e_required` rides the push (federation P3): adoption inherits the
/// flag, and the pool UI shows it — enforcement itself always happens on the issuer side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedGroupMsg {
    pub name: String,
    #[serde(default)]
    pub remark: String,
    #[serde(default)]
    pub rules: Vec<String>,
    /// E2E enforcement flag (federation P3; informational upstream — the issuer enforces)
    #[serde(default)]
    pub e2e_required: bool,
}

/// Auth frame payload: connector / consumer client -> listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub node_id: String,
    pub token: String,
    /// Auth principal type (fan-out node vs delegated consumer client)
    pub kind: AuthKind,
    /// CIDRs/domains the node advertises as servable (only for kind = Node)
    #[serde(default)]
    pub advertise: Vec<String>,
    /// Policy groups pushed upstream for the authorizable pool (only for kind = Node; federation P1)
    #[serde(default)]
    pub groups: Vec<PushedGroupMsg>,
    /// Protocol version of the peer
    pub version: u32,
    /// Self-declared display name ("我的名称", uploaded to the peer; decorative — never part of
    /// any auth/routing decision, the far side shows it next to its own certification remark)
    #[serde(default)]
    pub my_name: String,
    /// Device identity proof (node.md M2, mandatory): raw ed25519 public key, base64.
    /// `device_fp = sha256(pubkey)` is derived by the listener — never trusted from the wire.
    #[serde(default)]
    pub device_pubkey: String,
    /// Signature (base64) over the per-session challenge derived from the TLS exporter secret
    /// (RFC 5705, `device::DEVICE_PROOF_LABEL`): zero extra RTT, replay-bound to this session.
    #[serde(default)]
    pub device_sig: String,
}

impl AuthRequest {
    /// Attach the device identity proof: sign the session challenge and fill both wire fields.
    pub fn attach_device_proof(&mut self, challenge: &[u8], identity: &crate::device::DeviceIdentity) {
        self.device_pubkey = crate::util::base64_encode(identity.pubkey());
        self.device_sig = crate::util::base64_encode(&identity.sign(challenge));
    }

    /// Verify the attached proof against the per-session challenge; returns the derived
    /// device_fp and the canonical base64 pubkey on success. Fails closed on missing/malformed
    /// fields or a bad signature.
    pub fn verify_device_proof(&self, challenge: &[u8]) -> Option<(String, String)> {
        let pubkey = crate::util::base64_decode(&self.device_pubkey)?;
        let sig = crate::util::base64_decode(&self.device_sig)?;
        if pubkey.len() != 32 || !crate::device::DeviceIdentity::verify(&pubkey, challenge, &sig) {
            return None;
        }
        Some((crate::device::fp_of(&pubkey), crate::util::base64_encode(&pubkey)))
    }
}

/// Standard reason codes for session teardown / auth rejection (node.md M2; carried by
/// AuthFail / Close / SessionNotice frames, rendered by clients with localized fallbacks).
pub mod reason {
    /// Token or device revoked by the administrator (optional one-time message attached)
    pub const REVOKED_BY_ADMIN: &str = "revoked_by_admin";
    /// Device replaced by a newer certified device (rebind flow)
    pub const DEVICE_REPLACED: &str = "device_replaced";
    /// This device was revoked (terminal state, never reusable)
    pub const DEVICE_REVOKED: &str = "device_revoked";
    /// Token expired or usage exhausted
    pub const TOKEN_EXPIRED: &str = "token_expired";
    /// Kicked by the administrator (or single-concurrency takeover)
    pub const KICKED: &str = "kicked";
    /// Single-concurrency token: a newer session took over (this session was the stale one)
    pub const SESSION_TAKEOVER: &str = "session_takeover";
    /// The issuer's fan-out session dropped (revoke-by-disconnect)
    pub const ISSUER_OFFLINE: &str = "issuer_offline";
    /// The relay/server is shutting down (clean teardown, reconnect immediately)
    pub const SERVER_SHUTDOWN: &str = "server_shutdown";
    /// Bad credentials (unknown/expired/exhausted token)
    pub const BAD_CREDENTIALS: &str = "bad_credentials";
    /// Device awaiting administrator certification (pending session, appeals allowed)
    pub const PENDING_APPROVAL: &str = "pending_approval";
    /// Device proof missing/invalid (mandatory since protocol v4 device identity)
    pub const DEVICE_PROOF_INVALID: &str = "device_proof_invalid";
}

/// AuthFail / Close frame payload: structured rejection reason (empty payload = legacy-style
/// plain failure; clients fall back to a generic message).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailReason {
    pub reason_code: String,
    /// Optional one-time human message from the admin (final at send time, never editable)
    #[serde(default)]
    pub message: String,
}

impl FailReason {
    /// Parse an AuthFail payload (None on empty/malformed payloads).
    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        serde_json::from_slice(payload).ok()
    }

    /// Render into a one-line error/notification message.
    pub fn render(&self) -> String {
        if self.message.is_empty() {
            format!("auth rejected: {}", self.reason_code)
        } else {
            format!("auth rejected: {} ({})", self.reason_code, self.message)
        }
    }
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

/// Current protocol version (v4: session control plane + E2E envelope + entrust mode — opaque
/// en_xxx routing words in token_register hint_map, zero-disclosure delegation). v4 behavior is
/// the only behavior: no version-gated feature branches exist anywhere.
pub const PROTOCOL_VERSION: u32 = 4;

/// Minimum protocol version supporting per-channel window flow control.
pub const PROTOCOL_VERSION_FLOW_CONTROL: u32 = 2;

/// Open frame payload: listener -> connector, asking to open a data channel to the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenChannel {
    pub target_addr: String,
    pub target_port: u16,
    /// Delegated-session group tags (federation P2): stamped by the listener when forwarding a
    /// delegated consumer's Open; the connector enforces the target against its local same-named
    /// group rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// E2E envelope (federation P3): when present, `target_addr` carries the coarse routing hint
    /// and the real target lives encrypted inside `blob` (only issuer and client can read it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2e: Option<E2eOpen>,
}

impl OpenChannel {
    /// Plain (transparent) Open, no group tags, no E2E envelope.
    pub fn new(target_addr: impl Into<String>, target_port: u16) -> Self {
        Self {
            target_addr: target_addr.into(),
            target_port,
            groups: Vec::new(),
            e2e: None,
        }
    }
}

/// E2E envelope carried in an Open frame (federation P3).
///
/// `kid` identifies the delegated token (first 12 hex chars of its SHA-256 hash, exact match
/// only) so the issuer can look up the unwrap key; `hint` is the coarse routing word the relay
/// enforces/blindly forwards on; `blob` is the AES-256-GCM sealed JSON `{target_addr,
/// target_port, groups, chan_salt}` under `e2e_key = HKDF-SHA256(ikm=token, salt="anet/e2e/v1")`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eOpen {
    pub kid: String,
    pub hint: String,
    pub blob: String,
}

/// One coarse routing word of a delegated token (federation P2/P3): the relay enforces that an
/// E2E Open's hint stays within this vocabulary; `groups` records which issuer groups it covers
/// (display/audit only — enforcement uses the hint itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HintEntry {
    pub hint: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Session concurrency policy of a delegated token (unified issuance): carried by the Ctrl
/// token_register/revoke frames, enforced by the relay at consumer-session auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Concurrency {
    /// One active session per token: a new session kicks every older one
    Single,
    /// Sessions coexist, capped at `max_sessions` per token
    Multi,
}

/// Session control-plane message (Ctrl frame payload, JSON; protocol v4, federation P2).
///
/// Flow: the fan-out endpoint (issuer) registers/revokes delegated tokens on its session; the
/// listener (relay) answers with an ack. Lifetimes follow the session — a dropped session
/// invalidates every token it registered (revoke-by-disconnect).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CtrlMessage {
    /// Issuer -> relay: register a delegated token on this session.
    /// `groups` = issuer-local group names the token may use (empty = all pushed groups);
    /// `hint_map` = coarse routing vocabulary for E2E traffic of this token;
    /// `concurrency`/`max_sessions` = consumer-session policy the relay enforces at auth.
    TokenRegister {
        token_hash: String,
        #[serde(default)]
        label: String,
        #[serde(default)]
        groups: Vec<String>,
        #[serde(default)]
        hint_map: Vec<HintEntry>,
        concurrency: Concurrency,
        max_sessions: u32,
    },
    /// Issuer -> relay: revoke a delegated token (kick its sessions, drop the registration).
    /// Carries the same policy snapshot as the registration (audit symmetry), plus an optional
    /// structured reason + one-time message forwarded to the kicked consumer sessions.
    TokenRevoke {
        token_hash: String,
        concurrency: Concurrency,
        max_sessions: u32,
        #[serde(default)]
        reason_code: String,
        #[serde(default)]
        message: String,
    },
    /// Relay -> issuer: registration/revocation outcome (`error` empty on success).
    TokenAck {
        token_hash: String,
        ok: bool,
        #[serde(default)]
        error: String,
    },
    /// Any side -> session peer: session-level notice sent right before teardown (revoke /
    /// kick / reject). `message` is a one-time human note (final at send time). E2E-tier
    /// consumers receive it inside their encrypted envelope when a channel context exists;
    /// otherwise it rides this plain Ctrl frame (reason_code is always safe to show).
    SessionNotice {
        reason_code: String,
        #[serde(default)]
        message: String,
    },
    /// Consumer -> issuer (pending session only): appeal note attached to the approval item.
    /// The server counts per session and rejects beyond `MAX_PENDING_NOTES` (≤3).
    PendingNote { body: String },
    // M6 reserved op names (do NOT implement before M6; schemas are defined there):
    // "cert_push" (transitive certification record, origin-signed), "cert_revoke" (signed
    // revocation propagation), "grant_receipt" (topology visibility receipt).
}

/// Pending-session appeal cap (server-side enforcement, per session).
pub const MAX_PENDING_NOTES: u32 = 3;

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
