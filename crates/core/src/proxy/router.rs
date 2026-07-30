//! CIDR / HOST 路由表
//!
//! 支持最长前缀 IP/CIDR 匹配、全域名匹配和通配符域名后缀匹配。

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// 出站策略。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// 直连
    Direct,
    /// 通过隧道转发到指定节点
    Tunnel { node_id: String },
}

impl Outbound {
    pub fn tunnel(node_id: impl Into<String>) -> Self {
        Self::Tunnel {
            node_id: node_id.into(),
        }
    }
}

/// 代理路由表。
pub struct ProxyRouter {
    /// CIDR 路由：IP → 出站策略
    cidr_table: IpNetworkTable<Outbound>,
    /// HOST 精确匹配路由：域名 → 出站策略
    host_exact: HashMap<String, Outbound>,
    /// HOST Suffix 后缀匹配路由 (e.g. ".dev.internal" -> Outbound)
    host_suffixes: Vec<(String, Outbound)>,
    /// 默认出站
    default: Outbound,
}

impl ProxyRouter {
    /// 创建空路由表（默认全部 DIRECT）。
    pub fn new() -> Self {
        Self {
            cidr_table: IpNetworkTable::new(),
            host_exact: HashMap::new(),
            host_suffixes: Vec::new(),
            default: Outbound::Direct,
        }
    }

    /// 设置默认出站策略
    pub fn set_default(&mut self, outbound: Outbound) {
        self.default = outbound;
    }

    /// 插入 CIDR 路由规则
    pub fn add_cidr(&mut self, cidr_str: &str, outbound: Outbound) -> Result<(), String> {
        let cidr: IpNetwork = cidr_str
            .parse()
            .map_err(|e| format!("invalid CIDR {cidr_str}: {e}"))?;
        self.cidr_table.insert(cidr, outbound);
        Ok(())
    }

    /// 插入 精确域名 规则
    pub fn add_host_exact(&mut self, host: impl Into<String>, outbound: Outbound) {
        self.host_exact.insert(host.into().to_lowercase(), outbound);
    }

    /// 插入 域名后缀 规则 (如 "*.dev.internal" 或 ".dev.internal")
    pub fn add_host_suffix(&mut self, pattern: &str, outbound: Outbound) {
        let mut suffix = pattern.trim_start_matches('*').to_lowercase();
        // 统一补点前缀，避免 "internal" 误匹配 "evilinternal"
        if !suffix.starts_with('.') {
            suffix = format!(".{suffix}");
        }
        self.host_suffixes.push((suffix, outbound));
        // 按后缀长度从长到短排序，优先最长匹配
        self.host_suffixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    }

    /// 匹配 IP 地址路由
    pub fn resolve_ip(&self, ip_str: &str) -> Option<&Outbound> {
        let ip: IpAddr = ip_str.parse().ok()?;
        self.cidr_table.longest_match(ip).map(|(_, out)| out)
    }

    /// 根据 IP 地址对象匹配路由
    pub fn route_ip(&self, ip: IpAddr) -> &Outbound {
        self.cidr_table
            .longest_match(ip)
            .map(|(_, out)| out)
            .unwrap_or(&self.default)
    }

    /// 匹配 域名 路由
    pub fn resolve_host(&self, host: &str) -> Option<&Outbound> {
        let host_lower = host.to_lowercase();

        // 1. 精确匹配
        if let Some(outbound) = self.host_exact.get(&host_lower) {
            return Some(outbound);
        }

        // 2. 后缀匹配
        for (suffix, outbound) in &self.host_suffixes {
            if host_lower.ends_with(suffix) {
                return Some(outbound);
            }
        }

        None
    }

    /// 结合域名与 IP 进行全能解析
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

    /// 判断目标是否命中任意规则（ACL 判定用，忽略默认出站）。
    pub fn matches_target(&self, host_or_ip: &str) -> bool {
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
            self.cidr_table.longest_match(ip).is_some()
        } else {
            self.resolve_host(&host_only).is_some()
        }
    }

    /// 当前路由条目总数。
    pub fn route_count(&self) -> usize {
        let (ipv4_count, ipv6_count) = self.cidr_table.len();
        ipv4_count + ipv6_count + self.host_exact.len() + self.host_suffixes.len()
    }

    /// 清空所有路由。
    pub fn clear(&mut self) {
        self.cidr_table = IpNetworkTable::new();
        self.host_exact.clear();
        self.host_suffixes.clear();
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
}
