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
    /// 转发到本地回环上游代理（mihomo sidecar mixed 入站，SOCKS5 二次握手）
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
    /// 自定义规则层：hosts 映射（hostname 小写 → IP；仅本地代理入站评估，见 map_host）
    hosts_map: HashMap<String, IpAddr>,
    /// 自定义规则层：放行（通配 pattern → 出站；仅本地代理入站评估，见 custom_bypass_match）
    custom_bypass: Vec<(String, Outbound)>,
}

/// 通配匹配（自定义放行规则；大小写不敏感）：
/// - 无通配符：精确匹配（`foo.com` 仅命中 `foo.com`）
/// - 前通配 `*.baidu.com`：后缀匹配（含裸域 `baidu.com` 本身；不带点的 `*foo.com` 退化为纯后缀）
/// - 后通配 `127.*`：前缀匹配
/// - 前后通配 `*.alibaba.*`：包含匹配（内核去掉两侧 `.`，即包含 `alibaba`，裸串 `alibaba.cn` 亦命中）
///
/// 域名与 IP 字符串同口径（IP 场景用精确/前缀，如 `10.0.0.1` / `127.*`）。
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
                // "*.baidu.com"：命中裸域与全部子域，不误伤 evilbaidu.com
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
    /// 创建空路由表（默认全部 DIRECT）。
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

    // ==================== 自定义规则层（客户端 GUI 自定义规则） ====================
    //
    // 仅本地代理入站（ProxyInbound）评估：hosts 映射先改写解析目标（map_host），
    // 放行命中（custom_bypass_match）优先于一切合并路由与默认出站。
    // route_target / rule_values / matches 均不感知本层——中继 connector 的
    // 扇入数据面与路由再发布不受本机自定义规则影响。

    /// 整体替换 hosts 映射（键须为小写 hostname；空表 = 清除）。
    pub fn set_hosts_map(&mut self, map: HashMap<String, IpAddr>) {
        self.hosts_map = map;
    }

    /// 追加一条放行规则（pattern 通配语义见 wildcard_match；先加先判）。
    pub fn add_custom_bypass(&mut self, pattern: &str, outbound: Outbound) {
        self.custom_bypass.push((pattern.to_lowercase(), outbound));
    }

    /// 查询 hosts 映射（大小写不敏感；入参为纯主机名，不含端口）。
    pub fn map_host(&self, host: &str) -> Option<IpAddr> {
        if self.hosts_map.is_empty() {
            return None;
        }
        self.hosts_map.get(host.to_lowercase().as_str()).copied()
    }

    /// 放行规则匹配（大小写不敏感；入参为纯主机名或 IP 字符串，不含端口）。
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

    /// 按纯主机名/IP（不含端口）匹配路由。
    ///
    /// 调用方已解析出 host/port 时使用（如代理入站），与 `route_target("host:port")`
    /// 判定口径一致，但免去临时串拼接与端口剥离分配。
    pub fn route_host(&self, host: &str) -> &Outbound {
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.route_ip(ip)
        } else if let Some(out) = self.resolve_host(host) {
            out
        } else {
            &self.default
        }
    }

    /// 判断目标是否命中任意非默认路由（ACL 判定用，忽略默认出站）。
    ///
    /// 与 `route_target` 同样的方式剥离端口 / 解析 IP，
    /// 直接查 longest_match / host_exact / host_suffixes，不比较 Outbound 值。
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

    /// 判断目标是否命中任意规则（ACL 判定用，忽略默认出站）。
    pub fn matches_target(&self, host_or_ip: &str) -> bool {
        self.matches(host_or_ip)
    }

    /// 全部规则值（CIDR 字面值与域名模式）——路由再发布（re-advertise）用。
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

        // IP / 带端口 IP
        assert!(router.matches("10.12.1.1"));
        assert!(router.matches("10.12.1.1:8080"));
        assert!(!router.matches("8.8.8.8"));
        assert!(!router.matches("8.8.8.8:443"));
        // 精确域名 / 后缀域名 / 带端口域名
        assert!(router.matches("git.internal"));
        assert!(router.matches("git.internal:22"));
        assert!(router.matches("app.dev.internal"));
        assert!(router.matches("app.dev.internal:443"));
        assert!(!router.matches("google.com"));
        assert!(!router.matches("google.com:443"));
        // 默认出站不参与判定
        router.set_default(Outbound::Direct);
        assert!(!router.matches("8.8.8.8"));
    }

    #[test]
    fn wildcard_exact_and_case() {
        // 无通配 = 精确（大小写不敏感）
        assert!(wildcard_match("foo.com", "foo.com"));
        assert!(wildcard_match("Foo.COM", "foo.com"));
        assert!(wildcard_match("foo.com", "FOO.COM"));
        assert!(!wildcard_match("foo.com", "www.foo.com"));
        assert!(!wildcard_match("foo.com", "foo.com.cn"));
        // IP 精确
        assert!(wildcard_match("10.0.0.1", "10.0.0.1"));
        assert!(!wildcard_match("10.0.0.1", "10.0.0.2"));
    }

    #[test]
    fn wildcard_suffix() {
        // "*.baidu.com" 后缀匹配：含裸域，不误伤同尾异名
        assert!(wildcard_match("*.baidu.com", "baidu.com"));
        assert!(wildcard_match("*.baidu.com", "www.baidu.com"));
        assert!(wildcard_match("*.baidu.com", "a.b.baidu.com"));
        assert!(!wildcard_match("*.baidu.com", "evilbaidu.com"));
        assert!(!wildcard_match("*.baidu.com", "baidu.com.cn"));
        // 不带点的前通配退化为纯后缀
        assert!(wildcard_match("*baidu.com", "evilbaidu.com"));
    }

    #[test]
    fn wildcard_prefix_and_contains() {
        // "127.*" 前缀匹配（IP 场景）
        assert!(wildcard_match("127.*", "127.0.0.1"));
        assert!(wildcard_match("127.*", "127.255.255.254"));
        assert!(!wildcard_match("127.*", "128.0.0.1"));
        assert!(!wildcard_match("127.*", "2127.0.0.1"));
        // "*.alibaba.*" 前后通配 = 包含
        assert!(wildcard_match("*.alibaba.*", "www.alibaba.com"));
        assert!(wildcard_match("*.alibaba.*", "alibaba.cn"));
        assert!(wildcard_match("*.alibaba.*", "a.alibaba.b.c"));
        assert!(!wildcard_match("*.alibaba.*", "alibab.com"));
        assert!(!wildcard_match("*.alibaba.*", "example.com"));
    }

    #[test]
    fn wildcard_edge_patterns() {
        // "*" 匹配一切；"**" 同理；空 pattern 仅命中空目标
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

        // 放行命中（后缀 / 前缀）
        assert!(matches!(
            router.custom_bypass_match("app.corp.internal"),
            Some(Outbound::Direct)
        ));
        assert!(matches!(
            router.custom_bypass_match("10.1.2.3"),
            Some(Outbound::Direct)
        ));
        // 未命中返回 None（调用方继续走 route_target）
        assert!(router.custom_bypass_match("a.com").is_none());
        // 自定义层不进 route_target：扇入数据面与路由再发布不受影响
        assert!(matches!(
            router.route_target("app.corp.internal:443"),
            Outbound::Direct
        )); // 默认出站
        assert!(router.rule_values().iter().all(|v| !v.contains("corp")));
        // clear 一并清空自定义层
        router.clear();
        assert!(router.custom_bypass_match("app.corp.internal").is_none());
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
        // 空映射零开销路径
        router.set_hosts_map(HashMap::new());
        assert_eq!(router.map_host("foo.internal"), None);
    }
}
