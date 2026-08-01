//! 对端收敛注册表（PeerAclRegistry）：group_id → 共享 `PeerAcl` 句柄。
//!
//! 扇入（relay_token.group_id）与扇出（connector.group_id）共用同一份收敛表：
//! 数据面在认证/建连时经 `handle` 取组句柄，控制面在组规则变更时经 `rebuild`
//! 原地热替换组内路由（arc_swap），已建立的隧道零停机生效。
//!
//! 收敛语义：组规则编成 `ProxyRouter`（命中即放行）；空组 = 空路由表 = 全拒；
//! `handle(None)` = 不收敛（放行一切，兼容存量令牌/connector）。

use crate::db::Database;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::relay::PeerAcl;
use dashmap::DashMap;
use std::sync::Arc;

/// 对端收敛注册表（组维度，扇入扇出共享）。
#[derive(Default)]
pub struct PeerAclRegistry {
    acls: DashMap<String, Arc<PeerAcl>>,
}

impl PeerAclRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 取组收敛句柄：`None` = 不收敛；未知组惰性创建空表（全拒，fail-closed），
    /// 后续 rebuild 会把该组规则补进来。
    pub fn handle(&self, group_id: Option<&str>) -> Option<Arc<PeerAcl>> {
        let gid = group_id?;
        Some(
            self.acls
                .entry(gid.to_string())
                .or_insert_with(|| Arc::new(PeerAcl::new(ProxyRouter::new())))
                .clone(),
        )
    }

    /// 全量重建：DB 现存组 + 注册表已持有的组（组被删/引用残留时收敛为全拒）。
    /// 已发出的句柄原地 `update`，数据面实时生效。
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

/// 把组规则编成收敛路由表（哨兵 Outbound：只看命中与否，不做真实选路）。
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

    /// 建组并挂一条 CIDR 规则，返回组 id
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

        // 组规则变更后 rebuild：同一句柄原地生效
        let rid2 = db.create_rule("host", "git.internal", false, "").unwrap().id;
        db.set_group_rules(&gid, &[rid1, rid2]).unwrap();
        registry.rebuild(&db);
        assert!(acl.allowed("git.internal:22"));
        assert!(acl.allowed("10.12.1.1:8080"));

        // 规则清空 → 全拒
        db.set_group_rules(&gid, &[]).unwrap();
        registry.rebuild(&db);
        assert!(!acl.allowed("10.12.1.1:8080"));
    }

    #[test]
    fn unknown_group_fails_closed_then_picks_up_rules() {
        let db = Database::in_memory().unwrap();
        let gid = mk_group_with_rule(&db, "g1", "172.16.0.0/12");
        let registry = PeerAclRegistry::new();
        // rebuild 前取句柄：惰性创建空表（全拒）
        let acl = registry.handle(Some(&gid)).expect("acl handle");
        assert!(!acl.allowed("172.16.0.1:80"));
        registry.rebuild(&db);
        assert!(acl.allowed("172.16.0.1:80"));
    }
}
