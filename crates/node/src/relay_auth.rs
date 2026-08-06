//! Relay data-plane token validator (bridges the database and core::relay::listener).
//!
//! Node auth only: relay_token table (SHA-256 hash match); a token flagged to expose
//! the control plane gets an admin bootstrap ticket plus the control endpoint sent
//! with AuthOk (handshake v2); a token bound to a group mounts the group's
//! `PeerAcl` (fan-in peer traffic restricted by group rules).
//!
//! Delegated consumer auth (AuthKind::Client) never reaches this validator's tables:
//! the listener resolves it against its own delegated registries (persistent local
//! first, then session-scoped) and enforces the token's concurrency policy.

use crate::db::{Database, sha256_hex};
use crate::service::acl::PeerAclRegistry;
use agile_net_core::proto::message::{AuthKind, AuthRequest, ControlOffer};
use agile_net_core::relay::listener::{AuthIdentity, TokenValidator};
use std::sync::Arc;

/// Manageable fan-out registry: upstream node name → control endpoint (handshake v2 discovery, maintained by the connector sync task).
pub type ManageableRegistry = Arc<dashmap::DashMap<String, ControlOffer>>;

/// Admin bootstrap ticket parameters: TTL 1 hour, max 100 uses.
///
/// Security boundary equals the relay token itself: a psk holder can reconnect
/// for a fresh ticket anytime; TTL only bounds the leak window. Revoking the
/// token and kicking sessions recovers everything (refresh tokens revocable separately).
///
/// docs/todo/e2e.md §7.2.2: tickets are minted per handshake / per config pull and consumed
/// immediately (the E2E config channel), so a 1-hour window is
/// operationally invisible while shrinking the post-compromise admin-API exposure from 7 days.
pub(crate) const RELAY_TICKET_TTL_SECS: i64 = 3600;
pub(crate) const RELAY_TICKET_MAX_USES: i32 = 100;

pub struct DbTokenValidator {
    db: Database,
    /// This node's admin API endpoint (public_host, api_port), backfilled after NodeServer assembly.
    control_api: Arc<arc_swap::ArcSwapOption<(String, u16)>>,
    /// Peer ACL registry (relay_token.group_id → PeerAcl; None group = unrestricted).
    acl: Arc<PeerAclRegistry>,
}

impl DbTokenValidator {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            control_api: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
            acl: Arc::new(PeerAclRegistry::new()),
        }
    }

    /// Backfill this node's admin API endpoint (handshake v2 payload).
    pub fn with_control_api(mut self, slot: Arc<arc_swap::ArcSwapOption<(String, u16)>>) -> Self {
        self.control_api = slot;
        self
    }

    /// Inject the peer ACL registry (fan-in token group restriction).
    pub fn with_acl_registry(mut self, registry: Arc<PeerAclRegistry>) -> Self {
        self.acl = registry;
        self
    }

    /// This node's display name (manageable node card sent to fan-in endpoints).
    fn node_name(&self) -> String {
        self.db
            .get_config("node_name")
            .ok()
            .flatten()
            .unwrap_or_else(|| "AgileNet Node".into())
    }
}

impl TokenValidator for DbTokenValidator {
    fn validate(&self, auth: &AuthRequest) -> Option<AuthIdentity> {
        let token_hash = sha256_hex(auth.token.as_bytes());
        match auth.kind {
            AuthKind::Node => {
                if !self.db.check_relay_token(&token_hash).ok()? {
                    return None;
                }
                // Handshake v2: token flagged to expose → mint admin bootstrap ticket + send control endpoint.
                let control = match self.db.get_relay_token_control(&token_hash) {
                    Ok(Some((prefix, true, scope))) => {
                        let (host, port) = self.control_api.load_full().map(|a| (*a).clone())?;
                        let subject = format!("{}@{}", prefix, auth.node_id);
                        match self.db.create_admin_ticket(
                            "relay",
                            &subject,
                            &scope,
                            RELAY_TICKET_MAX_USES,
                            RELAY_TICKET_TTL_SECS,
                        ) {
                            Ok(ticket) => {
                                tracing::info!(
                                    token = %prefix,
                                    downstream = %auth.node_id,
                                    scope = %scope,
                                    "control plane exposed to downstream (handshake v2)"
                                );
                                Some(ControlOffer {
                                    exposed: true,
                                    api_host: Some(host),
                                    api_port: port,
                                    node_name: self.node_name(),
                                    ticket,
                                    scope,
                                })
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "mint relay admin ticket failed");
                                None
                            }
                        }
                    }
                    _ => None,
                };
                // Fan-in restriction: token's bound group → shared PeerAcl (None = unrestricted, allow all).
                // Query failure / token deleted mid-race both fail closed (auth rejected).
                let acl = match self.db.get_relay_token_group(&token_hash) {
                    Ok(Some(group_id)) => self.acl.handle(group_id.as_deref(), &self.db),
                    Ok(None) => return None,
                    Err(_) => return None,
                };
                Some(AuthIdentity::Node {
                    node_id: auth.node_id.clone(),
                    advertise: auth.advertise.clone(),
                    groups: auth.groups.clone(),
                    control,
                    acl,
                    // issuer-assigned display name for admin peer lists (the peer's self-reported
                    // node name is decorative — often a default like "AgileNet 内嵌端点")
                    display: self.db.get_relay_token_remark(&token_hash).ok().flatten(),
                })
            }
            // Delegated consumers: resolved by the listener itself (persistent local registry
            // first, then session-scoped) with the token's concurrency policy enforced there.
            AuthKind::Client => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_auth(token: &str) -> AuthRequest {
        AuthRequest {
            node_id: "peer-a".to_string(),
            token: token.to_string(),
            kind: AuthKind::Node,
            advertise: Vec::new(),
            groups: Vec::new(),
            version: 1,
        }
    }

    /// Create a group with one CIDR rule attached, return group id.
    fn mk_group_with_rule(db: &Database, name: &str, cidr: &str) -> String {
        let gid = db.create_group(name, "").unwrap().id;
        let rid = db.create_rule("ip-cidr", cidr, false, "").unwrap().id;
        db.set_group_rules(&gid, &[rid]).unwrap();
        gid
    }

    #[test]
    fn node_token_with_group_gets_group_acl() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group_with_rule(&db, "peers", "10.12.0.0/16");
        let token = "psk_test-token-with-group";
        db.create_relay_token_with_quota(
            &sha256_hex(token.as_bytes()),
            "psk_test",
            "",
            false,
            "full",
            Some(&gid),
            None,
        )
        .unwrap();

        let registry = Arc::new(PeerAclRegistry::new());
        registry.rebuild(&db);
        let validator = DbTokenValidator::new(db).with_acl_registry(registry);

        let identity = validator.validate(&node_auth(token)).expect("auth ok");
        let AuthIdentity::Node { acl, .. } = identity else {
            panic!("expected node identity");
        };
        let acl = acl.expect("group acl mounted");
        assert!(acl.allowed("10.12.1.1:8080"));
        assert!(!acl.allowed("8.8.8.8:443"));
    }

    #[test]
    fn node_token_without_group_stays_unrestricted() {
        let db = Database::in_memory().unwrap();
        let token = "psk_test-token-no-group";
        db.create_relay_token_with_quota(
            &sha256_hex(token.as_bytes()),
            "psk_test",
            "",
            false,
            "full",
            None,
            None,
        )
        .unwrap();

        let validator = DbTokenValidator::new(db);
        let identity = validator.validate(&node_auth(token)).expect("auth ok");
        let AuthIdentity::Node { acl, .. } = identity else {
            panic!("expected node identity");
        };
        assert!(acl.is_none(), "不挂组 = 不收敛");
    }

    #[test]
    fn unknown_token_still_rejected() {
        let db = Database::in_memory().unwrap();
        let validator = DbTokenValidator::new(db);
        assert!(
            validator
                .validate(&node_auth("psk_no-such-token"))
                .is_none()
        );
    }

    #[test]
    fn client_kind_defers_to_listener_registries() {
        // consumer auth is never answered by this validator — the listener resolves the
        // delegated registries itself (local first, then session-scoped)
        let db = Database::in_memory().unwrap();
        let validator = DbTokenValidator::new(db);
        let auth = AuthRequest {
            node_id: "consumer-a".to_string(),
            token: "psk_any".to_string(),
            kind: AuthKind::Client,
            advertise: Vec::new(),
            groups: Vec::new(),
            version: 4,
        };
        assert!(validator.validate(&auth).is_none());
    }

    #[test]
    fn relay_token_lifecycle_rejected() {
        let db = Database::in_memory().unwrap();
        let token = "psk_lifecycle-token";
        let rec = db
            .create_relay_token_with_quota(
                &sha256_hex(token.as_bytes()),
                "psk_life",
                "",
                false,
                "full",
                None,
                None,
            )
            .unwrap();

        // expired window -> auth rejects it like an unknown token
        db.set_relay_token_lifecycle(&rec.id, Some("2020-01-01T00:00:00Z"), None)
            .unwrap();
        assert!(
            DbTokenValidator::new(db.clone())
                .validate(&node_auth(token))
                .is_none()
        );

        // future window -> alive again
        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        db.set_relay_token_lifecycle(&rec.id, Some(&future), None)
            .unwrap();
        assert!(
            DbTokenValidator::new(db.clone())
                .validate(&node_auth(token))
                .is_some()
        );

        // usage cap: max_uses = 1 with one auth already counted -> exhausted
        db.set_relay_token_lifecycle(&rec.id, None, Some(1))
            .unwrap();
        assert!(
            DbTokenValidator::new(db.clone())
                .validate(&node_auth(token))
                .is_none()
        );

        // cleared window + higher cap -> alive (one use remains, then exhausts)
        db.set_relay_token_lifecycle(&rec.id, None, Some(2))
            .unwrap();
        assert!(
            DbTokenValidator::new(db.clone())
                .validate(&node_auth(token))
                .is_some()
        );
        assert!(
            DbTokenValidator::new(db.clone())
                .validate(&node_auth(token))
                .is_none()
        );
    }
}
