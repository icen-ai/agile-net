//! 自定义规则（GUI：放行 / hosts 映射）。

use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// 自定义放行规则（通配；评估优先于合并路由与回落，语义见 wildcard_match）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomBypassRule {
    pub pattern: String,
    /// 命中后经订阅内核（回落上游）而非直连；订阅未接管回落时退化为直连
    #[serde(default)]
    pub via_subscription: bool,
}

/// 自定义规则快照（引擎热更；GUI 计算「单条启停 ∪ 启用组合成员」后整体下发，
/// 引擎只消费生效集合，不感知组合与启停来源）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomRules {
    #[serde(default)]
    pub bypass: Vec<CustomBypassRule>,
    /// hosts 映射（hostname → IP 字符串；命中先改写解析目标再路由与拨号）
    #[serde(default)]
    pub hosts: Vec<(String, String)>,
}

/// 把自定义规则烘焙进路由表自定义层（rebuild_merged_router 决策点调用；独立函数便于单测）。
pub(crate) fn apply_custom_rules(
    router: &mut ProxyRouter,
    custom: &CustomRules,
    fallback: Option<SocketAddr>,
) {
    if !custom.hosts.is_empty() {
        let map: std::collections::HashMap<String, std::net::IpAddr> = custom
            .hosts
            .iter()
            .filter_map(|(h, ip)| ip.parse().ok().map(|addr| (h.to_lowercase(), addr)))
            .collect();
        router.set_hosts_map(map);
    }
    for b in &custom.bypass {
        let outbound = if b.via_subscription {
            fallback.map(Outbound::forward).unwrap_or(Outbound::Direct)
        } else {
            Outbound::Direct
        };
        router.add_custom_bypass(&b.pattern, outbound);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bypass(pattern: &str, via_subscription: bool) -> CustomBypassRule {
        CustomBypassRule {
            pattern: pattern.into(),
            via_subscription,
        }
    }

    #[test]
    fn custom_rules_baked_into_router_layer() {
        let mut router = ProxyRouter::new();
        // 模拟合并路由：同名目标已有端点隧道路由
        router.add_host_exact("api.corp.internal", Outbound::tunnel("n1@x:1"));
        let custom = CustomRules {
            bypass: vec![bypass("*.corp.internal", false)],
            hosts: vec![("git.corp.internal".into(), "10.9.9.9".into())],
        };
        apply_custom_rules(&mut router, &custom, None);

        // 放行命中 → Direct（入站评估顺序：custom_bypass_match 先于 route_target，
        // 因此自定义放行优先于既有隧道路由）
        assert!(matches!(
            router.custom_bypass_match("api.corp.internal"),
            Some(Outbound::Direct)
        ));
        // hosts 映射改写目标（map_host 先行，随后按改写结果继续路由）
        assert_eq!(
            router.map_host("git.corp.internal"),
            Some("10.9.9.9".parse().unwrap())
        );
        // 非法 IP 的映射被过滤，不进入映射层
        let mut router2 = ProxyRouter::new();
        apply_custom_rules(
            &mut router2,
            &CustomRules {
                bypass: vec![],
                hosts: vec![("bad.internal".into(), "not-an-ip".into())],
            },
            None,
        );
        assert_eq!(router2.map_host("bad.internal"), None);
    }

    #[test]
    fn custom_bypass_via_subscription_uses_fallback() {
        let fallback: SocketAddr = "127.0.0.1:57891".parse().unwrap();
        let custom = CustomRules {
            bypass: vec![
                bypass("*.via-sub.com", true),
                bypass("*.plain.com", false),
            ],
            hosts: vec![],
        };
        // 有回落上游：经过订阅 → Forward(回落)，普通放行 → Direct
        let mut router = ProxyRouter::new();
        apply_custom_rules(&mut router, &custom, Some(fallback));
        assert!(matches!(
            router.custom_bypass_match("a.via-sub.com"),
            Some(Outbound::Forward { addr }) if *addr == fallback
        ));
        assert!(matches!(
            router.custom_bypass_match("a.plain.com"),
            Some(Outbound::Direct)
        ));
        // 无回落上游：经过订阅退化为 Direct
        let mut router2 = ProxyRouter::new();
        apply_custom_rules(&mut router2, &custom, None);
        assert!(matches!(
            router2.custom_bypass_match("a.via-sub.com"),
            Some(Outbound::Direct)
        ));
    }
}
