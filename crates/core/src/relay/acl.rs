//! 对端收敛原语 (PeerAcl)
//!
//! 收敛语义：对端隧道来的流量，目标命中该对端的允许集合才放行，否则拒绝。
//! 调用方以 `Option<Arc<PeerAcl>>` 持有——`None` = 不收敛（放行一切）。

use crate::proxy::router::ProxyRouter;
use std::sync::Arc;

/// 对端访问收敛表：内部持有可热替换的 `ProxyRouter`（命中即允许）。
///
/// 组规则变更时由控制面调用 `update` 整体换入新路由表，数据面零停机生效。
pub struct PeerAcl {
    router: arc_swap::ArcSwap<ProxyRouter>,
}

impl PeerAcl {
    /// 以给定路由表创建收敛表（路由命中 = 允许）。
    pub fn new(router: ProxyRouter) -> Self {
        Self {
            router: arc_swap::ArcSwap::from_pointee(router),
        }
    }

    /// 目标是否被允许（命中任意非默认路由即放行）。
    pub fn allowed(&self, target: &str) -> bool {
        self.router.load().matches(target)
    }

    /// 热替换收敛规则。
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
        // 旧规则随整体替换失效
        assert!(!acl.allowed("10.12.1.1:8080"));
    }
}
