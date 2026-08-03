//! Peer ACL registry (PeerAclRegistry): group_id -> shared `PeerAcl` handle.
//!
//! Fan-in (relay_token.group_id) and fan-out (connector.group_id) share the same ACL tables:
//! the data plane takes a group handle via `handle` at auth/connect time; the control plane
//! hot-swaps the group's routes in place via `rebuild` (arc_swap) — established tunnels see
//! rule changes with zero downtime.
//!
//! ACL semantics: group rules compile into a `ProxyRouter` (hit = allow); empty group =
//! empty router = deny all; `handle(None)` = unrestricted (allow everything, compatible with
//! legacy tokens/connectors).

use crate::db::Database;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::PeerAcl;
use dashmap::DashMap;
use std::sync::Arc;

/// Peer ACL registry (per-group, shared by fan-in and fan-out).
#[derive(Default)]
pub struct PeerAclRegistry {
    acls: DashMap<String, Arc<PeerAcl>>,
}

impl PeerAclRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a group's ACL handle: `None` = unrestricted; unknown groups lazily get an empty
    /// table (deny all, fail-closed) — a later rebuild fills in that group's rules.
    pub fn handle(&self, group_id: Option<&str>) -> Option<Arc<PeerAcl>> {
        let gid = group_id?;
        Some(
            self.acls
                .entry(gid.to_string())
                .or_insert_with(|| Arc::new(PeerAcl::new(ProxyRouter::new())))
                .clone(),
        )
    }

    /// Full rebuild: groups in DB plus groups already held in the registry (deleted groups /
    /// dangling references converge to deny-all). Issued handles are `update`d in place and
    /// take effect in the data plane immediately.
    pub fn rebuild(&self, db: &Database) {
        let mut gids: std::collections::HashSet<String> =
            self.acls.iter().map(|e| e.key().clone()).collect();
        if let Ok((groups, _)) = db.list_groups(1, 1000, None) {
            gids.extend(groups.into_iter().map(|g| g.id));
        }
        for gid in gids {
            let router = build_group_router(db, &gid);
            let routes = router.route_count();
            match self.acls.get(&gid) {
                Some(acl) => acl.update(router),
                None => {
                    self.acls.insert(gid.clone(), Arc::new(PeerAcl::new(router)));
                }
            }
            tracing::debug!(group_id = %gid, routes, "peer acl rebuilt");
        }
    }
}

/// Compile group rules into an ACL router (sentinel Outbound: only hit-or-miss matters, no real routing).
fn build_group_router(db: &Database, group_id: &str) -> ProxyRouter {
    let mut router = ProxyRouter::new();
    if let Ok(rules) = db.rules_of_group(group_id) {
        for r in rules {
            let outbound = Outbound::tunnel("");
            match r.rule_type.as_str() {
                "ip-cidr" => {
                    let _ = router.add_cidr(&r.value, outbound);
                }
                "host" => {
                    if r.value.contains('*') {
                        router.add_host_suffix(&r.value, outbound);
                    } else {
                        router.add_host_exact(&r.value, outbound);
                    }
                }
                _ => {}
            }
        }
    }
    router
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a group with one CIDR rule; returns the group id.
    fn mk_group_with_rule(db: &Database, name: &str, cidr: &str) -> String {
        let gid = db.create_group(name, "").unwrap().id;
        let rid = db.create_rule("ip-cidr", cidr, false, "").unwrap().id;
        db.set_group_rules(&gid, &[rid]).unwrap();
        gid
    }

    #[test]
    fn handle_none_means_unrestricted() {
        let registry = PeerAclRegistry::new();
        assert!(registry.handle(None).is_none());
    }

    #[test]
    fn empty_group_denies_all() {
        let db = Database::in_memory().unwrap();
        let gid = db.create_group("empty", "").unwrap().id;
        let registry = PeerAclRegistry::new();
        registry.rebuild(&db);

        let acl = registry.handle(Some(&gid)).expect("acl handle");
        assert!(!acl.allowed("10.0.0.1:80"));
        assert!(!acl.allowed("example.com:443"));
    }

    #[test]
    fn group_with_rule_allows_hit_and_hot_updates() {
        let db = Database::in_memory().unwrap();
        let gid = db.create_group("g1", "").unwrap().id;
        let rid1 = db.create_rule("ip-cidr", "10.12.0.0/16", false, "").unwrap().id;
        db.set_group_rules(&gid, std::slice::from_ref(&rid1)).unwrap();
        let registry = PeerAclRegistry::new();
        registry.rebuild(&db);

        let acl = registry.handle(Some(&gid)).expect("acl handle");
        assert!(acl.allowed("10.12.1.1:8080"));
        assert!(!acl.allowed("8.8.8.8:443"));

        // rebuild after rule change: same handle updated in place
        let rid2 = db.create_rule("host", "git.internal", false, "").unwrap().id;
        db.set_group_rules(&gid, &[rid1, rid2]).unwrap();
        registry.rebuild(&db);
        assert!(acl.allowed("git.internal:22"));
        assert!(acl.allowed("10.12.1.1:8080"));

        // rules cleared -> deny all
        db.set_group_rules(&gid, &[]).unwrap();
        registry.rebuild(&db);
        assert!(!acl.allowed("10.12.1.1:8080"));
    }

    #[test]
    fn unknown_group_fails_closed_then_picks_up_rules() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group_with_rule(&db, "g1", "172.16.0.0/12");
        let registry = PeerAclRegistry::new();
        // handle fetched before rebuild: lazily created empty table (deny all)
        let acl = registry.handle(Some(&gid)).expect("acl handle");
        assert!(!acl.allowed("172.16.0.1:80"));
        registry.rebuild(&db);
        assert!(acl.allowed("172.16.0.1:80"));
    }
}
