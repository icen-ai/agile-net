//! Peer traffic restriction primitive (PeerAcl)
//!
//! Restriction semantics: traffic from a peer's tunnel is allowed only when its target
//! hits that peer's allow set, otherwise rejected.
//! Callers hold an `Option<Arc<PeerAcl>>` — `None` = unrestricted (allow everything).

use crate::proxy::router::ProxyRouter;
use std::sync::Arc;

/// Peer access restriction table: holds a hot-swappable `ProxyRouter` (hit = allow).
///
/// On group rule changes the control plane calls `update` to swap in a whole new
/// routing table; the data plane picks it up with zero downtime.
pub struct PeerAcl {
    router: arc_swap::ArcSwap<ProxyRouter>,
}

impl PeerAcl {
    /// Create a restriction table from the given routing table (route hit = allow).
    pub fn new(router: ProxyRouter) -> Self {
        Self {
            router: arc_swap::ArcSwap::from_pointee(router),
        }
    }

    /// Whether the target is allowed (any non-default route hit passes).
    pub fn allowed(&self, target: &str) -> bool {
        self.router.load().matches(target)
    }

    /// Hot-swap the restriction rules.
    pub fn update(&self, router: ProxyRouter) {
        self.router.store(Arc::new(router));
    }
}

impl std::fmt::Debug for PeerAcl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerAcl")
            .field("routes", &self.router.load().route_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::router::Outbound;

    fn sample_acl() -> PeerAcl {
        let mut router = ProxyRouter::new();
        router.add_cidr("10.12.0.0/16", Outbound::Direct).unwrap();
        router.add_host_exact("git.internal", Outbound::Direct);
        PeerAcl::new(router)
    }

    #[test]
    fn allow_hit_and_deny_miss() {
        let acl = sample_acl();
        assert!(acl.allowed("10.12.1.1:8080"));
        assert!(acl.allowed("git.internal:22"));
        assert!(!acl.allowed("8.8.8.8:443"));
        assert!(!acl.allowed("google.com:443"));
    }

    #[test]
    fn update_takes_effect_immediately() {
        let acl = sample_acl();
        assert!(!acl.allowed("172.16.0.1:80"));

        let mut router = ProxyRouter::new();
        router.add_cidr("172.16.0.0/12", Outbound::Direct).unwrap();
        acl.update(router);

        assert!(acl.allowed("172.16.0.1:80"));
        // old rules lapse with the wholesale swap
        assert!(!acl.allowed("10.12.1.1:8080"));
    }
}
