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
    /// Tier key (0 = user rule: beats every merged route; 1 = built-in preset: beats only catch-all
    /// routes and the default outbound — see ProxyRouter::decide_inbound).
    #[serde(default)]
    pub sort: u8,
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
        // Two tiers (see ProxyRouter::decide_inbound): user rules (sort 0) beat every merged route;
        // built-in presets (sort 1, the direct LAN/loopback defaults) beat only catch-all routes
        // and the default outbound — an account/adopted tunnel rule (10.12.0.0/16) is never
        // shadowed by a wide preset (10.*). Intra-tier first-match keeps the incoming list order
        // (the caller sorts ascending by `sort`, stable within a key, in effective_rules).
        if b.sort == 0 {
            router.add_custom_bypass(&b.pattern, outbound);
        } else {
            router.add_preset_bypass(&b.pattern, outbound);
        }
    }
    // Core-side sort_custom_bypass_precedence is defense-in-depth for Direct vs non-Direct inside
    // the user tier only; the authoritative precedence is the tier split above plus list order.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bypass(pattern: &str, via_subscription: bool) -> CustomBypassRule {
        CustomBypassRule {
            pattern: pattern.into(),
            via_subscription,
            sort: 0,
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

    /// Tier split (the adopted-group-unreachable fix): sort 1 presets bake into the preset layer,
    /// which yields to any narrower explicit route; sort 0 user rules keep beating everything.
    #[test]
    fn preset_tier_never_shadows_tunnel_routes() {
        fn preset(pattern: &str) -> CustomBypassRule {
            CustomBypassRule {
                pattern: pattern.into(),
                via_subscription: false,
                sort: 1,
            }
        }
        let custom = CustomRules {
            bypass: vec![preset("10.*"), preset("127.*")],
            hosts: vec![],
        };
        let mut router = ProxyRouter::new();
        // adopted-group / account rule merged as a tunnel route (what the server pushed)
        router
            .add_cidr("10.12.0.0/16", Outbound::tunnel("b@rendezvous"))
            .unwrap();
        apply_custom_rules(&mut router, &custom, None);

        // the regression: the 10.* preset must NOT shadow the adopted tunnel route
        assert!(matches!(
            router.decide_inbound("10.12.3.4"),
            Outbound::Tunnel { .. }
        ));
        // presets still catch the rest of their range (LAN stays direct)
        assert!(matches!(router.decide_inbound("10.99.0.1"), Outbound::Direct));
        assert!(matches!(router.decide_inbound("127.0.0.1"), Outbound::Direct));
        // a narrower USER bypass (sort 0) still wins its own prefix over the tunnel route
        router
            .add_cidr("10.13.0.0/16", Outbound::tunnel("b@rendezvous"))
            .unwrap();
        let custom2 = CustomRules {
            bypass: vec![bypass("10.13.*", false), preset("10.*")],
            hosts: vec![],
        };
        apply_custom_rules(&mut router, &custom2, None);
        assert!(matches!(router.decide_inbound("10.13.1.1"), Outbound::Direct));
    }
}
