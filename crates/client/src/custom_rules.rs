//! Custom rules (GUI: bypass / hosts mapping).

use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Custom bypass rule (wildcard; evaluated before merged routes and fallback; see wildcard_match semantics).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomBypassRule {
    pub pattern: String,
    /// Route matches via the subscription kernel (fallback upstream) instead of direct; degrades to direct when no subscription fallback
    #[serde(default)]
    pub via_subscription: bool,
}

/// Custom rules snapshot (engine hot reload; the GUI computes "per-rule toggles ∪ enabled combo members"
/// and pushes the whole set; the engine only consumes the effective set, unaware of combos/toggles).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomRules {
    #[serde(default)]
    pub bypass: Vec<CustomBypassRule>,
    /// hosts mapping (hostname → IP string; on match, rewrite the resolve target before routing and dialing)
    #[serde(default)]
    pub hosts: Vec<(String, String)>,
}

/// Bake custom rules into the router's custom layer (called at the rebuild_merged_router decision point; standalone fn for unit tests).
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
        // Simulate merged routes: an endpoint tunnel route already exists for the same target
        router.add_host_exact("api.corp.internal", Outbound::tunnel("n1@x:1"));
        let custom = CustomRules {
            bypass: vec![bypass("*.corp.internal", false)],
            hosts: vec![("git.corp.internal".into(), "10.9.9.9".into())],
        };
        apply_custom_rules(&mut router, &custom, None);

        // Bypass hit → Direct (inbound evaluation order: custom_bypass_match runs before route_target,
        // so custom bypass wins over an existing tunnel route)
        assert!(matches!(
            router.custom_bypass_match("api.corp.internal"),
            Some(Outbound::Direct)
        ));
        // hosts mapping rewrites the target (map_host runs first, routing continues with the rewritten result)
        assert_eq!(
            router.map_host("git.corp.internal"),
            Some("10.9.9.9".parse().unwrap())
        );
        // Mappings with invalid IPs are filtered out and never enter the map layer
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
        // With fallback upstream: via-subscription → Forward(fallback), plain bypass → Direct
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
        // Without fallback upstream: via-subscription degrades to Direct
        let mut router2 = ProxyRouter::new();
        apply_custom_rules(&mut router2, &custom, None);
        assert!(matches!(
            router2.custom_bypass_match("a.via-sub.com"),
            Some(Outbound::Direct)
        ));
    }
}
