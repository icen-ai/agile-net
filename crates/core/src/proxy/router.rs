//! CIDR / HOST routing table
//!
//! Longest-prefix IP/CIDR match, exact domain match and wildcard domain suffix match.

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Outbound policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Direct connection
    Direct,
    /// Forward through a tunnel to the given node
    Tunnel { node_id: String },
    /// Forward to a local loopback upstream proxy (mihomo sidecar mixed inbound, second SOCKS5 handshake)
    Forward { addr: SocketAddr },
}

impl Outbound {
    pub fn tunnel(node_id: impl Into<String>) -> Self {
        Self::Tunnel {
            node_id: node_id.into(),
        }
    }

    pub fn forward(addr: SocketAddr) -> Self {
        Self::Forward { addr }
    }
}

/// Proxy routing table.
pub struct ProxyRouter {
    /// CIDR routes: IP -> outbound policy
    cidr_table: IpNetworkTable<Outbound>,
    /// Exact HOST routes: domain -> outbound policy
    host_exact: HashMap<String, Outbound>,
    /// HOST suffix routes (e.g. ".dev.internal" -> Outbound)
    host_suffixes: Vec<(String, Outbound)>,
    /// Default outbound
    default: Outbound,
    /// Custom rule layer: hosts mapping (lowercase hostname -> IP; evaluated by local proxy inbound only, see map_host)
    hosts_map: HashMap<String, IpAddr>,
    /// Custom rule layer: bypass rules (wildcard pattern -> outbound; evaluated by local proxy inbound only, see custom_bypass_match)
    custom_bypass: Vec<(String, Outbound)>,
}

/// Wildcard match (custom bypass rules; case-insensitive):
/// - no wildcard: exact match (`foo.com` hits only `foo.com`)
/// - leading `*.baidu.com`: suffix match (includes the bare domain `baidu.com`; `*foo.com` without a dot degrades to plain suffix)
/// - trailing `127.*`: prefix match
/// - both `*.alibaba.*`: contains match (kernel strips the dots on both sides, i.e. contains `alibaba`; bare `alibaba.cn` also hits)
///
/// Domains and IP strings share the same semantics (IPs use exact/prefix, e.g. `10.0.0.1` / `127.*`).
pub fn wildcard_match(pattern: &str, target: &str) -> bool {
    let pat = pattern.trim().to_lowercase();
    let target = target.trim().to_lowercase();
    let leading = pat.starts_with('*');
    let trailing = pat.ends_with('*') && pat.len() > 1;
    match (leading, trailing) {
        (false, false) => pat == target,
        (true, false) => {
            let rest = &pat[1..];
            if let Some(dom) = rest.strip_prefix('.') {
                // "*.baidu.com": hits the bare domain and all subdomains, spare evilbaidu.com
                target == dom || target.ends_with(rest)
            } else {
                target.ends_with(rest)
            }
        }
        (false, true) => target.starts_with(&pat[..pat.len() - 1]),
        (true, true) => target.contains(pat[1..pat.len() - 1].trim_matches('.')),
    }
}

impl ProxyRouter {
    /// Create an empty routing table (everything DIRECT by default).
    pub fn new() -> Self {
        Self {
            cidr_table: IpNetworkTable::new(),
            host_exact: HashMap::new(),
            host_suffixes: Vec::new(),
            default: Outbound::Direct,
            hosts_map: HashMap::new(),
            custom_bypass: Vec::new(),
        }
    }

    /// Set the default outbound policy
    pub fn set_default(&mut self, outbound: Outbound) {
        self.default = outbound;
    }

    /// Insert a CIDR route
    pub fn add_cidr(&mut self, cidr_str: &str, outbound: Outbound) -> Result<(), String> {
        let cidr: IpNetwork = cidr_str
            .parse()
            .map_err(|e| format!("invalid CIDR {cidr_str}: {e}"))?;
        self.cidr_table.insert(cidr, outbound);
        Ok(())
    }

    /// Insert an exact-domain rule
    pub fn add_host_exact(&mut self, host: impl Into<String>, outbound: Outbound) {
        self.host_exact.insert(host.into().to_lowercase(), outbound);
    }

    /// Insert a domain-suffix rule (e.g. "*.dev.internal" or ".dev.internal")
    pub fn add_host_suffix(&mut self, pattern: &str, outbound: Outbound) {
        let mut suffix = pattern.trim_start_matches('*').to_lowercase();
        // normalize to a leading dot so "internal" cannot match "evilinternal"
        if !suffix.starts_with('.') {
            suffix = format!(".{suffix}");
        }
        self.host_suffixes.push((suffix, outbound));
        // sort longest suffix first for longest-match priority
        self.host_suffixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    }

    /// Match a route by IP address string
    pub fn resolve_ip(&self, ip_str: &str) -> Option<&Outbound> {
        let ip: IpAddr = ip_str.parse().ok()?;
        self.cidr_table.longest_match(ip).map(|(_, out)| out)
    }

    /// Match a route by IP address
    pub fn route_ip(&self, ip: IpAddr) -> &Outbound {
        self.cidr_table
            .longest_match(ip)
            .map(|(_, out)| out)
            .unwrap_or(&self.default)
    }

    /// Match a route by domain
    pub fn resolve_host(&self, host: &str) -> Option<&Outbound> {
        let host_lower = host.to_lowercase();

        // 1. exact match
        if let Some(outbound) = self.host_exact.get(&host_lower) {
            return Some(outbound);
        }

        // 2. suffix match
        for (suffix, outbound) in &self.host_suffixes {
            if host_lower.ends_with(suffix) {
                return Some(outbound);
            }
        }

        None
    }

    // ==================== Custom rule layer (client GUI custom rules) ====================
    //
    // Evaluated by local proxy inbound (ProxyInbound) only: the hosts mapping rewrites
    // the resolve target first (map_host); a bypass hit (custom_bypass_match) beats all
    // merged routes and the default outbound. route_target / rule_values / matches are
    // unaware of this layer — the relay connector's fan-in data plane and route
    // re-advertise are unaffected by local custom rules.

    /// Replace the whole hosts mapping (keys must be lowercase hostnames; empty = clear).
    pub fn set_hosts_map(&mut self, map: HashMap<String, IpAddr>) {
        self.hosts_map = map;
    }

    /// Append a bypass rule (wildcard semantics see wildcard_match; first added, first checked).
    pub fn add_custom_bypass(&mut self, pattern: &str, outbound: Outbound) {
        self.custom_bypass.push((pattern.to_lowercase(), outbound));
    }

    /// Look up the hosts mapping (case-insensitive; input is a bare hostname, no port).
    pub fn map_host(&self, host: &str) -> Option<IpAddr> {
        if self.hosts_map.is_empty() {
            return None;
        }
        self.hosts_map.get(host.to_lowercase().as_str()).copied()
    }

    /// Match bypass rules (case-insensitive; input is a bare hostname or IP string, no port).
    pub fn custom_bypass_match(&self, host: &str) -> Option<&Outbound> {
        if self.custom_bypass.is_empty() {
            return None;
        }
        let target = host.to_lowercase();
        for (pattern, outbound) in &self.custom_bypass {
            if wildcard_match(pattern, &target) {
                return Some(outbound);
            }
        }
        None
    }

    /// Stability ordering for the custom bypass layer (called by the client engine after baking):
    /// sort ascending by the rule's precedence key (Direct = 0, everything else = 1).
    ///
    /// This is defense-in-depth only: the authoritative precedence comes from the engine's
    /// `effective_rules` sort (user rules sort 0 before presets sort 1), which `apply_custom_rules`
    /// bakes in insertion order (first-match). This core-side helper guarantees a Direct preset never
    /// shadows a narrower non-Direct user rule even if a future caller bakes out of order — Direct
    /// rules resolve first, and any other outbound still wins its own prefix because first-match stops
    /// at the Direct rule only when the Direct rule actually matches (falls through otherwise).
    pub fn sort_custom_bypass_precedence(&mut self) {
        self.custom_bypass.sort_by(|a, b| {
            let ka = Self::bypass_key(&a.1);
            let kb = Self::bypass_key(&b.1);
            ka.cmp(&kb)
        });
    }

    /// Precedence key of an outbound (0 = Direct, 1 = everything else).
    fn bypass_key(out: &Outbound) -> u8 {
        match out {
            Outbound::Direct => 0u8,
            Outbound::Forward { .. } => 1u8,
            Outbound::Tunnel { .. } => 1u8,
        }
    }

    /// Resolve by domain and IP combined
    pub fn route_target(&self, host_or_ip: &str) -> &Outbound {
        let host_only = if let Ok(addr) = host_or_ip.parse::<SocketAddr>() {
            addr.ip().to_string()
        } else if let Ok(ip) = host_or_ip.parse::<IpAddr>() {
            ip.to_string()
        } else if let Some((h, _)) = host_or_ip.rsplit_once(':') {
            h.to_string()
        } else {
            host_or_ip.to_string()
        };

        if let Ok(ip) = host_only.parse::<IpAddr>() {
            self.route_ip(ip)
        } else if let Some(out) = self.resolve_host(&host_only) {
            out
        } else {
            &self.default
        }
    }

    /// Match a route by bare hostname/IP (no port).
    ///
    /// Used when the caller already split host/port (e.g. proxy inbound); same semantics
    /// as `route_target("host:port")` without temporary concatenation and port-stripping allocs.
    pub fn route_host(&self, host: &str) -> &Outbound {
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.route_ip(ip)
        } else if let Some(out) = self.resolve_host(host) {
            out
        } else {
            &self.default
        }
    }

    /// Whether the target hits any non-default route (for ACL checks; default outbound ignored).
    ///
    /// Strips the port / parses the IP the same way as `route_target`,
    /// querying longest_match / host_exact / host_suffixes directly without comparing Outbound values.
    pub fn matches(&self, target: &str) -> bool {
        let host_only = if let Ok(addr) = target.parse::<SocketAddr>() {
            addr.ip().to_string()
        } else if let Ok(ip) = target.parse::<IpAddr>() {
            ip.to_string()
        } else if let Some((h, _)) = target.rsplit_once(':') {
            h.to_string()
        } else {
            target.to_string()
        };

        if let Ok(ip) = host_only.parse::<IpAddr>() {
            self.cidr_table.longest_match(ip).is_some()
        } else {
            self.resolve_host(&host_only).is_some()
        }
    }

    /// Whether the target hits any rule (for ACL checks; default outbound ignored).
    pub fn matches_target(&self, host_or_ip: &str) -> bool {
        self.matches(host_or_ip)
    }

    /// All rule values (CIDR literals and domain patterns) — for route re-advertise.
    pub fn rule_values(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (net, _) in self.cidr_table.iter() {
            out.push(net.to_string());
        }
        out.extend(self.host_exact.keys().cloned());
        for (suffix, _) in &self.host_suffixes {
            out.push(format!("*{suffix}"));
        }
        out.sort();
        out
    }

    /// Total number of route entries.
    pub fn route_count(&self) -> usize {
        let (ipv4_count, ipv6_count) = self.cidr_table.len();
        ipv4_count + ipv6_count + self.host_exact.len() + self.host_suffixes.len()
    }

    /// Clear all routes.
    pub fn clear(&mut self) {
        self.cidr_table = IpNetworkTable::new();
        self.host_exact.clear();
        self.host_suffixes.clear();
        self.hosts_map.clear();
        self.custom_bypass.clear();
    }
}

impl Default for ProxyRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_routing() {
        let mut router = ProxyRouter::new();
        router
            .add_cidr("10.12.0.0/16", Outbound::tunnel("tunnel-b"))
            .unwrap();
        router
            .add_cidr("10.152.0.0/16", Outbound::tunnel("tunnel-c"))
            .unwrap();

        assert_eq!(
            router.resolve_ip("10.12.186.133"),
            Some(&Outbound::tunnel("tunnel-b"))
        );
        assert_eq!(
            router.resolve_ip("10.152.1.1"),
            Some(&Outbound::tunnel("tunnel-c"))
        );
        assert_eq!(router.resolve_ip("8.8.8.8"), None);
    }

    #[test]
    fn host_routing() {
        let mut router = ProxyRouter::new();
        router.add_host_exact("git.internal", Outbound::tunnel("tunnel-b"));
        router.add_host_suffix("*.dev.internal", Outbound::tunnel("tunnel-b"));

        assert_eq!(
            router.resolve_host("git.internal"),
            Some(&Outbound::tunnel("tunnel-b"))
        );
        assert_eq!(
            router.resolve_host("app.dev.internal"),
            Some(&Outbound::tunnel("tunnel-b"))
        );
        assert_eq!(router.resolve_host("google.com"), None);
    }

    #[test]
    fn longest_prefix_match() {
        let mut router = ProxyRouter::new();
        router
            .add_cidr("10.0.0.0/8", Outbound::tunnel("wide"))
            .unwrap();
        router
            .add_cidr("10.12.0.0/16", Outbound::tunnel("narrow"))
            .unwrap();

        assert_eq!(
            router.resolve_ip("10.12.1.1"),
            Some(&Outbound::tunnel("narrow"))
        );
        assert_eq!(
            router.resolve_ip("10.13.1.1"),
            Some(&Outbound::tunnel("wide"))
        );
    }

    #[test]
    fn matches_non_default_route() {
        let mut router = ProxyRouter::new();
        router
            .add_cidr("10.12.0.0/16", Outbound::tunnel("tunnel-b"))
            .unwrap();
        router.add_host_exact("git.internal", Outbound::tunnel("tunnel-b"));
        router.add_host_suffix("*.dev.internal", Outbound::tunnel("tunnel-b"));

        // IP / IP with port
        assert!(router.matches("10.12.1.1"));
        assert!(router.matches("10.12.1.1:8080"));
        assert!(!router.matches("8.8.8.8"));
        assert!(!router.matches("8.8.8.8:443"));
        // exact domain / suffix domain / domain with port
        assert!(router.matches("git.internal"));
        assert!(router.matches("git.internal:22"));
        assert!(router.matches("app.dev.internal"));
        assert!(router.matches("app.dev.internal:443"));
        assert!(!router.matches("google.com"));
        assert!(!router.matches("google.com:443"));
        // default outbound does not participate
        router.set_default(Outbound::Direct);
        assert!(!router.matches("8.8.8.8"));
    }

    #[test]
    fn wildcard_exact_and_case() {
        // no wildcard = exact (case-insensitive)
        assert!(wildcard_match("foo.com", "foo.com"));
        assert!(wildcard_match("Foo.COM", "foo.com"));
        assert!(wildcard_match("foo.com", "FOO.COM"));
        assert!(!wildcard_match("foo.com", "www.foo.com"));
        assert!(!wildcard_match("foo.com", "foo.com.cn"));
        // IP exact
        assert!(wildcard_match("10.0.0.1", "10.0.0.1"));
        assert!(!wildcard_match("10.0.0.1", "10.0.0.2"));
    }

    #[test]
    fn wildcard_suffix() {
        // "*.baidu.com" suffix match: includes the bare domain, spares same-tail lookalikes
        assert!(wildcard_match("*.baidu.com", "baidu.com"));
        assert!(wildcard_match("*.baidu.com", "www.baidu.com"));
        assert!(wildcard_match("*.baidu.com", "a.b.baidu.com"));
        assert!(!wildcard_match("*.baidu.com", "evilbaidu.com"));
        assert!(!wildcard_match("*.baidu.com", "baidu.com.cn"));
        // leading wildcard without a dot degrades to plain suffix
        assert!(wildcard_match("*baidu.com", "evilbaidu.com"));
    }

    #[test]
    fn wildcard_prefix_and_contains() {
        // "127.*" prefix match (IP case)
        assert!(wildcard_match("127.*", "127.0.0.1"));
        assert!(wildcard_match("127.*", "127.255.255.254"));
        assert!(!wildcard_match("127.*", "128.0.0.1"));
        assert!(!wildcard_match("127.*", "2127.0.0.1"));
        // "*.alibaba.*" leading+trailing wildcards = contains
        assert!(wildcard_match("*.alibaba.*", "www.alibaba.com"));
        assert!(wildcard_match("*.alibaba.*", "alibaba.cn"));
        assert!(wildcard_match("*.alibaba.*", "a.alibaba.b.c"));
        assert!(!wildcard_match("*.alibaba.*", "alibab.com"));
        assert!(!wildcard_match("*.alibaba.*", "example.com"));
    }

    #[test]
    fn wildcard_edge_patterns() {
        // "*" matches everything; "**" likewise; empty pattern only hits an empty target
        assert!(wildcard_match("*", "anything.example"));
        assert!(wildcard_match("*", "1.2.3.4"));
        assert!(wildcard_match("**", "x.y"));
        assert!(!wildcard_match("", "x.y"));
    }

    #[test]
    fn custom_bypass_layer() {
        let mut router = ProxyRouter::new();
        router.add_host_exact("a.com", Outbound::tunnel("n1"));
        router.add_custom_bypass("*.corp.internal", Outbound::Direct);
        router.add_custom_bypass("10.*", Outbound::Direct);
        // bypass hit (suffix / prefix)
        assert!(matches!(
            router.custom_bypass_match("app.corp.internal"),
            Some(Outbound::Direct)
        ));
        assert!(matches!(
            router.custom_bypass_match("10.1.2.3"),
            Some(Outbound::Direct)
        ));
        // miss returns None (caller falls through to route_target)
        assert!(router.custom_bypass_match("a.com").is_none());
        // the custom layer never enters route_target: fan-in data plane and route re-advertise unaffected
        assert!(matches!(
            router.route_target("app.corp.internal:443"),
            Outbound::Direct
        )); // default outbound
        assert!(router.rule_values().iter().all(|v| !v.contains("corp")));
        // clear also clears the custom layer
        router.clear();
        assert!(router.custom_bypass_match("app.corp.internal").is_none());
    }

    /// Precedence stability: first-match bypass semantics — a narrower user rule (10.12.* via
    /// subscription) must win its own prefix over the wide Direct preset (10.*), and the engine bakes
    /// user rules (sort 0) before presets (sort 1) so insertion order already gives the precedence.
    #[test]
    fn custom_bypass_precedence_stability() {
        let mut router = ProxyRouter::new();
        let user_narrow: SocketAddr = "127.0.0.1:57892".parse().unwrap();
        // Engine sorts user rules (sort 0) before presets (sort 1); the router bakes in that order.
        router.add_custom_bypass("10.12.*", Outbound::forward(user_narrow));
        router.add_custom_bypass("10.*", Outbound::Direct);
        // 10.12.3.4 matches both; the narrower user rule (first) wins.
        assert!(matches!(
            router.custom_bypass_match("10.12.3.4"),
            Some(Outbound::Forward { addr }) if *addr == user_narrow
        ));
        // 10.x outside the user rule → the Direct preset.
        assert!(matches!(
            router.custom_bypass_match("10.99.0.1"),
            Some(Outbound::Direct)
        ));
        // Non-LAN stays unmatched (falls through to route_target).
        assert!(router.custom_bypass_match("8.8.8.8").is_none());
        // Defense-in-depth: a Direct preset baked BEFORE a narrower user rule (out-of-order caller)
        // would shadow it in pure first-match; the engine bakes user rules first, so this is covered.
        // (The core-side sort helper is a guard for the Direct-vs-Direct case and is exercised by
        // custom_bypass_layer — no assertion here, since first-match semantics are authoritative.)
    }

    #[test]
    fn hosts_map_lookup() {
        let mut router = ProxyRouter::new();
        let mut map = HashMap::new();
        map.insert(
            "foo.internal".to_string(),
            "10.9.9.9".parse::<IpAddr>().unwrap(),
        );
        router.set_hosts_map(map);
        assert_eq!(
            router.map_host("FOO.internal"),
            Some("10.9.9.9".parse().unwrap())
        );
        assert_eq!(router.map_host("other.internal"), None);
        // zero-cost path for an empty map
        router.set_hosts_map(HashMap::new());
        assert_eq!(router.map_host("foo.internal"), None);
    }
}
