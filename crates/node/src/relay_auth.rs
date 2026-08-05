//! Relay data-plane token validator (bridges the database and core::relay::listener).
//!
//! - Node auth: relay_token table (SHA-256 hash match); a token flagged to expose
//!   the control plane gets an admin bootstrap ticket plus the control endpoint sent
//!   with AuthOk (handshake v2); a token bound to a group mounts the group's
//!   `PeerAcl` (fan-in peer traffic restricted by group rules)
//! - Client auth: account.tunnel_token_hash (SHA-256), with group rules loaded as ACL;
//!   "manage this node" accounts implicitly open the local loopback API and
//!   manageable fan-out endpoints

use crate::db::{Database, sha256_hex};
use crate::service::acl::PeerAclRegistry;
use agile_net_core::proto::message::{AuthKind, AuthRequest, ControlOffer};
use agile_net_core::relay::listener::{
    AuthIdentity, DelegatedRegistry, DelegatedStamp, TokenValidator, delegated_session_key,
};
use std::sync::Arc;

/// Manageable fan-out registry: upstream node name → control endpoint (handshake v2 discovery, maintained by the connector sync task).
pub type ManageableRegistry = Arc<dashmap::DashMap<String, ControlOffer>>;

/// Admin bootstrap ticket parameters: TTL 7 days, max 10000 uses.
///
/// Security boundary equals the relay token itself: a psk holder can reconnect
/// for a fresh ticket anytime; TTL only bounds the leak window. Revoking the
/// token and kicking sessions recovers everything (refresh tokens revocable separately).
pub(crate) const RELAY_TICKET_TTL_SECS: i64 = 7 * 24 * 3600;
pub(crate) const RELAY_TICKET_MAX_USES: i32 = 10000;

pub struct DbTokenValidator {
    db: Database,
    /// This node's admin API endpoint (public_host, api_port), backfilled after NodeServer assembly.
    control_api: Arc<arc_swap::ArcSwapOption<(String, u16)>>,
    /// Manageable fan-out registry (for implicit ACL; always empty without connectors).
    manageable: ManageableRegistry,
    /// Peer ACL registry (relay_token.group_id → PeerAcl; None group = unrestricted).
    acl: Arc<PeerAclRegistry>,
    /// Federation P2: delegated token registry shared with the relay listener (client auth
    /// falls through to it when no local account matches the tunnel token hash).
    delegated: Option<DelegatedRegistry>,
}

impl DbTokenValidator {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            control_api: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
            manageable: Arc::new(dashmap::DashMap::new()),
            acl: Arc::new(PeerAclRegistry::new()),
            delegated: None,
        }
    }

    /// Backfill this node's admin API endpoint (handshake v2 payload).
    pub fn with_control_api(mut self, slot: Arc<arc_swap::ArcSwapOption<(String, u16)>>) -> Self {
        self.control_api = slot;
        self
    }

    /// Inject the manageable fan-out registry (for admin_console account implicit ACL).
    pub fn with_manageable(mut self, registry: ManageableRegistry) -> Self {
        self.manageable = registry;
        self
    }

    /// Inject the peer ACL registry (fan-in token group restriction).
    pub fn with_acl_registry(mut self, registry: Arc<PeerAclRegistry>) -> Self {
        self.acl = registry;
        self
    }

    /// Inject the delegated token registry (federation P2; share the listener's instance so
    /// registrations/revocations take effect for auth immediately).
    pub fn with_delegated_registry(mut self, registry: DelegatedRegistry) -> Self {
        self.delegated = Some(registry);
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
                })
            }
            AuthKind::Client => match self.db.find_account_by_tunnel_hash(&token_hash) {
                Ok(Some(account)) => {
                    if !account.enabled {
                        return None;
                    }
                    // token lifecycle: a tunnel token past its validity window is rejected like
                    // an unknown token (the password login path is unaffected; the client learns
                    // on its next API login and re-auths)
                    if !crate::db::expiry_active(account.tunnel_expires_at.as_deref()) {
                        return None;
                    }
                    // Load all rules of the account's group as the data-plane ACL.
                    let rules = self.db.rules_of_account(&account.id).ok()?;
                    let mut acl: Vec<String> = rules.into_iter().map(|r| r.value).collect();
                    // "Manage this node" permission: implicitly open the node's own loopback API
                    // and manageable fan-out endpoints (revoking it drops the path on next tunnel auth).
                    if account.admin_console {
                        acl.push("127.0.0.1/32".to_string());
                        for item in self.manageable.iter() {
                            let offer = item.value();
                            if let Some(host) = &offer.api_host {
                                acl.push(acl_rule_for_host(host));
                            }
                        }
                    }
                    let _ = self.db.touch_account_seen(&account.id);
                    Some(AuthIdentity::Client {
                        account_id: account.id,
                        acl,
                        delegated: None,
                    })
                }
                Ok(None) => {
                    // federation P2: no local account — fall through to the delegated registry
                    // (tokens registered by an online fan-out endpoint on its session)
                    let entry = self.delegated.as_ref()?.get(&token_hash)?.clone();
                    let mut acl = entry.acl_rules.clone();
                    acl.extend(entry.hint_map.iter().map(|h| h.hint.clone()));
                    Some(AuthIdentity::Client {
                        account_id: delegated_session_key(&token_hash),
                        acl,
                        delegated: Some(DelegatedStamp {
                            issuer: entry.issuer.clone(),
                            groups: entry.groups.clone(),
                            hints: entry.hint_map.iter().map(|h| h.hint.clone()).collect(),
                        }),
                    })
                }
                Err(_) => None, // database errors fail closed
            },
        }
    }
}

/// Hostname/IP → ACL rule literal (/32 for IPs, exact host for domains).
fn acl_rule_for_host(host: &str) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() {
        format!("{host}/32")
    } else {
        host.to_string()
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
        db.create_relay_token_with_quota(&sha256_hex(token.as_bytes()), "psk_test", "", false, "full", None, None)
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
        assert!(validator.validate(&node_auth("psk_no-such-token")).is_none());
    }

    fn client_auth(token: &str) -> AuthRequest {
        AuthRequest {
            node_id: "consumer-a".to_string(),
            token: token.to_string(),
            kind: AuthKind::Client,
            advertise: Vec::new(),
            groups: Vec::new(),
            version: 3,
        }
    }

    #[test]
    fn delegated_token_falls_through_to_registry() {
        use agile_net_core::proto::message::HintEntry;
        use agile_net_core::relay::listener::DelegatedToken;

        let db = Database::in_memory().unwrap();
        let token = "psk_delegated-alice";
        let hash = sha256_hex(token.as_bytes());
        let registry: DelegatedRegistry = Arc::new(dashmap::DashMap::new());
        registry.insert(
            hash.clone(),
            DelegatedToken {
                issuer: "issuer-c".into(),
                label: "alice".into(),
                groups: vec!["git".into()],
                acl_rules: vec!["10.0.0.0/8".into()],
                hint_map: vec![HintEntry {
                    hint: "relay.internal".into(),
                    groups: vec!["git".into()],
                }],
            },
        );
        let validator = DbTokenValidator::new(db).with_delegated_registry(registry.clone());

        // no local account with this hash -> the delegated registry answers
        let identity = validator.validate(&client_auth(token)).expect("delegated auth ok");
        let AuthIdentity::Client {
            account_id,
            acl,
            delegated,
        } = identity
        else {
            panic!("expected client identity");
        };
        assert_eq!(account_id, delegated_session_key(&hash));
        assert!(acl.contains(&"10.0.0.0/8".to_string()));
        assert!(acl.contains(&"relay.internal".to_string()), "hints join the ACL vocabulary");
        let stamp = delegated.expect("delegated stamp");
        assert_eq!(stamp.issuer, "issuer-c");
        assert_eq!(stamp.groups, vec!["git".to_string()]);
        assert_eq!(stamp.hints, vec!["relay.internal".to_string()]);

        // after the registration is dropped (revoke / issuer disconnect) auth fails closed
        registry.remove(&hash);
        assert!(validator.validate(&client_auth(token)).is_none());
    }

    #[test]
    fn local_account_wins_over_delegated_registry() {
        use agile_net_core::relay::listener::DelegatedToken;

        let db = Database::in_memory().unwrap();
        let gid = mk_group_with_rule(&db, "peers", "10.12.0.0/16");
        let token = "psk_dual-identity";
        let hash = sha256_hex(token.as_bytes());
        // a local account with this tunnel token hash
        let acc = db.create_account("u-local", &crate::db::hash_password("Passw0rd!ab").unwrap(), &gid, "").unwrap();
        db.set_account_tunnel_token(&acc.id, Some(&hash)).unwrap();
        // and a delegated registration under the same hash
        let registry: DelegatedRegistry = Arc::new(dashmap::DashMap::new());
        registry.insert(
            hash.clone(),
            DelegatedToken {
                issuer: "issuer-c".into(),
                label: "alice".into(),
                groups: vec![],
                acl_rules: vec![],
                hint_map: vec![],
            },
        );
        let validator = DbTokenValidator::new(db).with_delegated_registry(registry);

        // local account takes precedence (no delegated stamp)
        let identity = validator.validate(&client_auth(token)).expect("auth ok");
        let AuthIdentity::Client {
            account_id,
            delegated,
            ..
        } = identity
        else {
            panic!("expected client identity");
        };
        assert_eq!(account_id, acc.id);
        assert!(delegated.is_none());
    }

    #[test]
    fn relay_token_lifecycle_rejected() {
        let db = Database::in_memory().unwrap();
        let token = "psk_lifecycle-token";
        let rec = db
            .create_relay_token_with_quota(&sha256_hex(token.as_bytes()), "psk_life", "", false, "full", None, None)
            .unwrap();

        // expired window -> auth rejects it like an unknown token
        db.set_relay_token_lifecycle(&rec.id, Some("2020-01-01T00:00:00Z"), None)
            .unwrap();
        assert!(DbTokenValidator::new(db.clone()).validate(&node_auth(token)).is_none());

        // future window -> alive again
        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        db.set_relay_token_lifecycle(&rec.id, Some(&future), None).unwrap();
        assert!(DbTokenValidator::new(db.clone()).validate(&node_auth(token)).is_some());

        // usage cap: max_uses = 1 with one auth already counted -> exhausted
        db.set_relay_token_lifecycle(&rec.id, None, Some(1)).unwrap();
        assert!(DbTokenValidator::new(db.clone()).validate(&node_auth(token)).is_none());

        // cleared window + higher cap -> alive (one use remains, then exhausts)
        db.set_relay_token_lifecycle(&rec.id, None, Some(2)).unwrap();
        assert!(DbTokenValidator::new(db.clone()).validate(&node_auth(token)).is_some());
        assert!(DbTokenValidator::new(db.clone()).validate(&node_auth(token)).is_none());
    }

    #[test]
    fn account_tunnel_expiry_rejected() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group_with_rule(&db, "peers", "10.12.0.0/16");
        let token = "tun_lifecycle-token";
        let hash = sha256_hex(token.as_bytes());
        let acc = db
            .create_account("u-expiry", &crate::db::hash_password("Passw0rd!ab").unwrap(), &gid, "")
            .unwrap();
        db.set_account_tunnel_token(&acc.id, Some(&hash)).unwrap();

        // no window -> alive
        assert!(DbTokenValidator::new(db.clone()).validate(&client_auth(token)).is_some());

        // expired window -> rejected (password login path unaffected — data plane only)
        db.set_account_tunnel_expiry(&acc.id, Some("2020-01-01T00:00:00Z")).unwrap();
        assert!(DbTokenValidator::new(db.clone()).validate(&client_auth(token)).is_none());

        // future window -> alive again
        let future = (chrono::Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        db.set_account_tunnel_expiry(&acc.id, Some(&future)).unwrap();
        assert!(DbTokenValidator::new(db.clone()).validate(&client_auth(token)).is_some());
    }
}
