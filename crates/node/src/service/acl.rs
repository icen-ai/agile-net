//! Peer ACL registry (PeerAclRegistry): group set -> shared `PeerAcl` handle.
//!
//! Fan-in (relay_token.group_id) and fan-out (connector.group_id) share the same ACL tables:
//! the data plane takes a group handle via `handle` at auth/connect time; the control plane
//! hot-swaps the group's routes in place via `rebuild` (arc_swap) — established tunnels see
//! rule changes with zero downtime.
//!
//! The stored group_id is a comma-separated group set (a bare single id is a one-element set):
//! the ACL is the union of every member group's rules.
//!
//! ACL semantics: group rules compile into a `ProxyRouter` (hit = allow); empty set =
//! empty router = deny all; `handle(None)` = unrestricted (allow everything — the shape for
//! tokens/connectors without a group binding).

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

    /// Get a group's ACL handle: `None` = unrestricted. Unknown sets are compiled from the DB
    /// right here (not left as a deny-all placeholder until the next rebuild sweep): a freshly
    /// created token/connector must converge on first connect, not on the next config bump.
    /// The key is the stored group set verbatim (comma-separated multi-group sets allowed).
    pub fn handle(&self, group_id: Option<&str>, db: &Database) -> Option<Arc<PeerAcl>> {
        let gid = group_id?;
        Some(
            self.acls
                .entry(gid.to_string())
                .or_insert_with(|| Arc::new(PeerAcl::new(build_group_router(db, gid))))
                .clone(),
        )
    }

    /// Full rebuild: groups in DB plus groups already held in the registry (deleted groups /
    /// dangling references converge to deny-all). Issued handles are `update`d in place and
    /// take effect in the data plane immediately.
    pub fn rebuild(&self, db: &Database) {
        let mut gids: std::collections::HashSet<String> =
            self.acls.iter().map(|e| e.key().clone()).collect();
        if let Ok((groups, _)) = db.list_groups(1, 1000, None, None) {
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

/// Compile a group set into an ACL router (comma-separated ids union their rules; unknown ids
/// contribute nothing — fail-closed per member; sentinel Outbound: only hit-or-miss matters).
fn build_group_router(db: &Database, group_set: &str) -> ProxyRouter {
    let mut router = ProxyRouter::new();
    for gid in group_set.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(rules) = db.rules_of_group(gid) {
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
        let db = Database::in_memory().unwrap();
        assert!(registry.handle(None, &db).is_none());
    }

    #[test]
    fn empty_group_denies_all() {
        let db = Database::in_memory().unwrap();
        let gid = db.create_group("empty", "").unwrap().id;
        let registry = PeerAclRegistry::new();
        registry.rebuild(&db);

        let acl = registry.handle(Some(&gid), &db).expect("acl handle");
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

        let acl = registry.handle(Some(&gid), &db).expect("acl handle");
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
    fn first_handle_compiles_immediately_and_dangling_fails_closed() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group_with_rule(&db, "g1", "172.16.0.0/12");
        let registry = PeerAclRegistry::new();
        // no rebuild yet: the first handle compiles the set straight from the DB
        let acl = registry.handle(Some(&gid), &db).expect("acl handle");
        assert!(acl.allowed("172.16.0.1:80"));
        // dangling set (deleted group): compiles to an empty table, deny all
        let dead = registry.handle(Some("gone-1,gone-2"), &db).expect("acl handle");
        assert!(!dead.allowed("172.16.0.1:80"));
        // a later rebuild converges the dangling handle in place (stays deny all)
        registry.rebuild(&db);
        assert!(!dead.allowed("172.16.0.1:80"));
        assert!(acl.allowed("172.16.0.1:80"));
    }

    #[test]
    fn multi_group_set_unions_member_rules() {
        let db = Database::in_memory().unwrap();
        let g1 = mk_group_with_rule(&db, "g1", "10.12.0.0/16");
        let g2 = mk_group_with_rule(&db, "g2", "172.16.0.0/12");
        let set = format!("{g1},{g2}");
        let registry = PeerAclRegistry::new();
        registry.rebuild(&db);
        let acl = registry.handle(Some(&set), &db).expect("acl handle");
        assert!(acl.allowed("10.12.1.1:80"));
        assert!(acl.allowed("172.16.1.1:80"));
        assert!(!acl.allowed("192.168.1.1:80"));

        // one member cleared -> its routes drop out of the union on rebuild
        db.set_group_rules(&g1, &[]).unwrap();
        registry.rebuild(&db);
        assert!(!acl.allowed("10.12.1.1:80"));
        assert!(acl.allowed("172.16.1.1:80"));
    }
}
