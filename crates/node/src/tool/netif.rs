//! ifconfig / route / mtu — interfaces and routing (P1, default-net).
//!
//! default-net provides the interface list (IP/MAC/type/speed/default gateway); MTU and the full
//! routing table are not covered by default-net 0.22 and are filled in per platform. Parsers are
//! separated from data sources (text injection), so unit tests do not depend on the host environment:
//! - Linux/Android: `/sys/class/net/*/mtu`, `/proc/net/route` (procfs/sysfs always exist,
//!   no private dependencies even on trimmed domestic OS images);
//! - Windows: `netsh interface ipv4/ipv6 show interfaces`, `route print -4`
//!   (output is in the OEM code page; after lossy decoding only numeric/IPv4 columns are parsed,
//!   independent of the display language);
//! - macOS/BSD: `ifconfig`, `netstat -rn -f inet`.
//!
//! The routing table covers IPv4 only (the main ops-diagnostic scenario); the default gateway
//! (including IPv6) comes from default-net.

use super::ToolOutcome;
use serde::Serialize;
use std::collections::HashMap;

/// Structured interface info (the json unit of ifconfig / mtu).
#[derive(Debug, Clone, Serialize)]
struct IfaceInfo {
    index: u32,
    name: String,
    friendly_name: Option<String>,
    description: Option<String>,
    if_type: String,
    is_up: bool,
    is_loopback: bool,
    is_default: bool,
    mac: Option<String>,
    mtu: Option<u32>,
    ipv4: Vec<String>,
    ipv6: Vec<String>,
    gateway: Option<String>,
    gateway_mac: Option<String>,
    receive_bps: Option<u64>,
    transmit_bps: Option<u64>,
}

/// A single IPv4 route (the json unit of route).
#[derive(Debug, Clone, Serialize)]
struct RouteEntry {
    /// Destination network (e.g. 0.0.0.0/0; may be "default" or a host address on macOS/BSD)
    destination: String,
    /// Next-hop gateway; None means directly connected (on-link)
    gateway: Option<String>,
    /// Outgoing interface (Windows route print only has the interface IP, presented verbatim)
    iface: String,
    metric: Option<u32>,
}

/// MTU lookup table: by interface name on Linux/macOS/BSD, by interface index on Windows (netsh Idx is the IfIndex).
#[derive(Default)]
struct MtuTable {
    by_name: HashMap<String, u32>,
    by_index: HashMap<u32, u32>,
}

impl MtuTable {
    fn of(&self, iface: &default_net::Interface) -> Option<u32> {
        self.by_index
            .get(&iface.index)
            .or_else(|| self.by_name.get(&iface.name))
            .copied()
    }
}

/// Aggregate the current platform's MTU data source; read failure only drops the MTU column
/// (displayed as "-"), never blocks the main output.
fn mtu_table() -> MtuTable {
    let mut t = MtuTable::default();
    load_mtu_table(&mut t);
    t
}

/// Linux/Android: read the mtu file per interface from sysfs.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn load_mtu_table(t: &mut MtuTable) {
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(s) = std::fs::read_to_string(entry.path().join("mtu")) {
                if let Ok(v) = s.trim().parse::<u32>() {
                    t.by_name.insert(name, v);
                }
            }
        }
    }
}

/// Windows: netsh show interfaces (queried once each for IPv4/IPv6; first hit wins).
#[cfg(target_os = "windows")]
fn load_mtu_table(t: &mut MtuTable) {
    for family in ["ipv4", "ipv6"] {
        if let Some(out) = shell_out("netsh", &["interface", family, "show", "interfaces"]) {
            for (idx, mtu) in parse_netsh_show_interfaces(&out) {
                t.by_index.entry(idx).or_insert(mtu);
            }
        }
    }
}

/// macOS/BSD: parse the mtu field from the first line of each interface block in ifconfig.
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn load_mtu_table(t: &mut MtuTable) {
    if let Some(out) = shell_out("ifconfig", &[]) {
        for (name, mtu) in parse_ifconfig_mtu(&out) {
            t.by_name.insert(name, mtu);
        }
    }
}

/// Other platforms: no MTU data source yet (column shows "-").
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
fn load_mtu_table(_t: &mut MtuTable) {}

/// Run a system command and take stdout (lossy-decoded in the local code page; parsing only relies on numeric/ASCII columns).
#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn shell_out(program: &str, args: &[&str]) -> Option<String> {
    let out = agile_net_core::util::silent_command(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse netsh show interfaces: the first three columns of data rows are all numeric (Idx/Met/MTU);
/// header/separator rows are skipped naturally (language-independent); returns (IfIndex, MTU).
#[cfg(any(test, target_os = "windows"))]
fn parse_netsh_show_interfaces(text: &str) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        if let (Ok(idx), Ok(_met), Ok(mtu)) = (
            f[0].parse::<u32>(),
            f[1].parse::<u32>(),
            f[2].parse::<u32>(),
        ) {
            out.push((idx, mtu));
        }
    }
    out
}

/// Parse ifconfig output: an interface block's first line looks like "en0: flags=... mtu 1500"; extract (name, MTU).
#[cfg(any(
    test,
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn parse_ifconfig_mtu(text: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for line in text.lines() {
        // Continuation lines start with whitespace; block headers contain "name: ... mtu N"
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let mut tokens = rest.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok == "mtu" {
                if let Some(Ok(v)) = tokens.next().map(|s| s.parse::<u32>()) {
                    out.push((name.trim().to_string(), v));
                }
                break;
            }
        }
    }
    out
}

/// Parse /proc/net/route: destination/gateway/mask are little-endian hex; an all-zero gateway means directly connected.
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn parse_proc_net_route(text: &str) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (Some(dest), Some(mask)) = (hex_le_ipv4(f[1]), hex_le_ipv4(f[7])) else {
            continue;
        };
        out.push(RouteEntry {
            destination: format!("{dest}/{}", mask.to_bits().count_ones()),
            gateway: hex_le_ipv4(f[2])
                .filter(|g| !g.is_unspecified())
                .map(|g| g.to_string()),
            iface: f[0].to_string(),
            metric: f[6].parse().ok(),
        });
    }
    out
}

/// /proc little-endian hex → IPv4 ("0102A8C0" → 192.168.2.1).
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn hex_le_ipv4(s: &str) -> Option<std::net::Ipv4Addr> {
    let v = u32::from_str_radix(s, 16).ok()?;
    Some(std::net::Ipv4Addr::from(v.to_le_bytes()))
}

/// Parse route print -4: data rows are five columns "destination mask gateway interface metric",
/// the first two must be IPv4 (header/separator/localized rows skip naturally); a non-IPv4 gateway
/// column (e.g. On-link) is recorded as directly connected.
/// The Persistent Routes section is four columns (no interface column) and is excluded by the
/// five-column rule, avoiding duplicates with active routes.
#[cfg(any(test, target_os = "windows"))]
fn parse_route_print_ipv4(text: &str) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 5 {
            continue;
        }
        let (Ok(dest), Ok(mask)) = (
            f[0].parse::<std::net::Ipv4Addr>(),
            f[1].parse::<std::net::Ipv4Addr>(),
        ) else {
            continue;
        };
        out.push(RouteEntry {
            destination: format!("{dest}/{}", mask.to_bits().count_ones()),
            gateway: f[2]
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(|g| g.to_string()),
            iface: f[3].to_string(),
            metric: f[4].parse().ok(),
        });
    }
    out
}

/// Parse netstat -rn -f inet: Destination Gateway Flags Netif [Expire];
/// the destination column may be default/CIDR/host address/BSD shorthand (e.g. 127); a non-IP
/// gateway (link#x etc.) is recorded as directly connected.
#[cfg(any(
    test,
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn parse_netstat_rn_inet(text: &str) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        // Destination column looks like default / 127 / 127.0.0.1 / 192.168.1.0/24; header rows skip naturally
        let dest = f[0];
        let looks_like_dest = dest == "default"
            || (dest.chars().any(|c| c.is_ascii_digit())
                && dest.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '/'));
        if !looks_like_dest {
            continue;
        }
        out.push(RouteEntry {
            destination: dest.to_string(),
            gateway: f[1].parse::<std::net::IpAddr>().ok().map(|g| g.to_string()),
            iface: f[3].to_string(),
            metric: None,
        });
    }
    out
}

/// Read the local IPv4 routing table (data source chosen per platform).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_ipv4_routes() -> Result<Vec<RouteEntry>, String> {
    let text = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| format!("读取 /proc/net/route 失败: {e}"))?;
    Ok(parse_proc_net_route(&text))
}

/// Read the local IPv4 routing table (data source chosen per platform).
#[cfg(target_os = "windows")]
fn read_ipv4_routes() -> Result<Vec<RouteEntry>, String> {
    let out = shell_out("route", &["print", "-4"]).ok_or("route 命令不可用")?;
    Ok(parse_route_print_ipv4(&out))
}

/// Read the local IPv4 routing table (data source chosen per platform).
#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn read_ipv4_routes() -> Result<Vec<RouteEntry>, String> {
    let out = shell_out("netstat", &["-rn", "-f", "inet"]).ok_or("netstat 命令不可用")?;
    Ok(parse_netstat_rn_inet(&out))
}

/// Read the local IPv4 routing table (data source chosen per platform).
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
)))]
fn read_ipv4_routes() -> Result<Vec<RouteEntry>, String> {
    Err("当前平台暂不支持读取路由表".to_string())
}

/// Collect interface info (with MTU and the default-interface marker; failure of either only
/// drops fields, never blocks the main output).
fn collect_ifaces() -> Vec<IfaceInfo> {
    let mtus = mtu_table();
    // Internally a UDP connect for route selection, no real packets; fails without a default route → no default marker
    let default_gw = default_net::get_default_gateway().ok();
    default_net::get_interfaces()
        .iter()
        .map(|i| {
            let gateway_mac = i
                .gateway
                .as_ref()
                .filter(|g| g.mac_addr.octets() != [0; 6])
                .map(|g| g.mac_addr.to_string());
            IfaceInfo {
                index: i.index,
                name: i.name.clone(),
                friendly_name: i.friendly_name.clone(),
                description: i.description.clone(),
                if_type: i.if_type.name(),
                is_up: i.is_up(),
                is_loopback: i.is_loopback(),
                is_default: default_gw.as_ref().is_some_and(|dg| {
                    i.gateway.as_ref().is_some_and(|g| g.ip_addr == dg.ip_addr)
                }),
                mac: i.mac_addr.as_ref().map(|m| m.to_string()),
                mtu: mtus.of(i),
                ipv4: i.ipv4.iter().map(|n| n.to_string()).collect(),
                ipv6: i.ipv6.iter().map(|n| n.to_string()).collect(),
                gateway: i.gateway.as_ref().map(|g| g.ip_addr.to_string()),
                gateway_mac,
                // Windows reports unknown speed as u64::MAX (-1 sentinel); treat as missing
                receive_bps: i.receive_speed.filter(|&v| v != u64::MAX),
                transmit_bps: i.transmit_speed.filter(|&v| v != u64::MAX),
            }
        })
        .collect()
}

/// Display name: prefer friendly_name (Windows interface names are GUIDs, not readable).
fn display_name(i: &IfaceInfo) -> &str {
    i.friendly_name.as_deref().unwrap_or(&i.name)
}

/// Human-friendly speed (default-net gives bps).
fn fmt_bps(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.2} Gbps", bps as f64 / 1e9)
    } else if bps >= 1_000_000 {
        format!("{:.1} Mbps", bps as f64 / 1e6)
    } else if bps >= 1_000 {
        format!("{:.1} Kbps", bps as f64 / 1e3)
    } else {
        format!("{bps} bps")
    }
}

/// `anet tool ifconfig` (equivalent to ifconfig / ip a): interface list, IP, MAC, gateway, MTU.
pub fn ifconfig() -> ToolOutcome {
    let ifaces = collect_ifaces();
    if ifaces.is_empty() {
        return ToolOutcome::fail(
            "未检测到任何网卡（含回环）",
            serde_json::json!({ "count": 0, "interfaces": [] }),
        );
    }

    let mut human = format!("网卡列表（共 {} 块）：", ifaces.len());
    for i in &ifaces {
        human.push_str(&format!(
            "\n[{}] {}{}",
            i.index,
            display_name(i),
            if i.is_default { "（默认）" } else { "" }
        ));
        // Windows interface names are GUIDs; print the real name on its own line (usable for mtu filtering)
        if i.friendly_name.as_deref().is_some_and(|f| f != i.name) {
            human.push_str(&format!("\n    名称: {}", i.name));
        }
        if let Some(d) = &i.description {
            human.push_str(&format!("\n    描述: {d}"));
        }
        human.push_str(&format!(
            "\n    类型: {}    状态: {}    MTU: {}",
            i.if_type,
            if i.is_up { "UP" } else { "DOWN" },
            i.mtu.map(|m| m.to_string()).unwrap_or_else(|| "-".into())
        ));
        if let Some(mac) = &i.mac {
            human.push_str(&format!("\n    MAC : {mac}"));
        }
        for ip in &i.ipv4 {
            human.push_str(&format!("\n    IPv4: {ip}"));
        }
        for ip in &i.ipv6 {
            human.push_str(&format!("\n    IPv6: {ip}"));
        }
        if let Some(gw) = &i.gateway {
            human.push_str(&format!("\n    网关: {gw}"));
            if let Some(m) = &i.gateway_mac {
                human.push_str(&format!("（MAC {m}）"));
            }
        }
        if let (Some(rx), Some(tx)) = (i.receive_bps, i.transmit_bps) {
            human.push_str(&format!(
                "\n    速率: RX {} / TX {}",
                fmt_bps(rx),
                fmt_bps(tx)
            ));
        }
    }

    ToolOutcome::ok(
        human,
        serde_json::json!({ "count": ifaces.len(), "interfaces": ifaces }),
    )
}

/// `anet tool route` (equivalent to route print / ip route): default gateway + routing table.
pub fn route() -> ToolOutcome {
    let ifaces = collect_ifaces();
    // Default interface first; when unavailable (no default route), fall back to any up interface holding a gateway
    let default = ifaces
        .iter()
        .find(|i| i.is_default)
        .or_else(|| ifaces.iter().find(|i| i.gateway.is_some() && i.is_up && !i.is_loopback));
    let routes = read_ipv4_routes();

    let mut human = String::new();
    if let Some(i) = default {
        human.push_str(&format!(
            "默认网关: {}（经 {}",
            i.gateway.as_deref().unwrap_or("-"),
            display_name(i)
        ));
        if let Some(m) = &i.gateway_mac {
            human.push_str(&format!("，MAC {m}"));
        }
        human.push('）');
    } else {
        human.push_str("默认网关: 未检测到（无默认路由或本机未联网）");
    }
    match &routes {
        Ok(rs) => {
            human.push_str(&format!("\n\nIPv4 路由表（{} 条）：", rs.len()));
            if rs.is_empty() {
                human.push_str("\n  （空）");
            } else {
                human.push_str(&format!("\n  {:<20}{:<18}{:<24}{}", "目标", "网关", "网卡", "跃点"));
                for r in rs {
                    human.push_str(&format!(
                        "\n  {:<20}{:<18}{:<24}{}",
                        r.destination,
                        r.gateway.as_deref().unwrap_or("直连"),
                        r.iface,
                        r.metric.map(|m| m.to_string()).unwrap_or_else(|| "-".into())
                    ));
                }
            }
        }
        Err(e) => human.push_str(&format!("\n\nIPv4 路由表: 读取失败（{e}）")),
    }

    let default_gw_json = default.map(|i| {
        serde_json::json!({
            "ip": i.gateway.as_deref(),
            "iface": display_name(i),
            "iface_name": i.name.as_str(),
            "mac": i.gateway_mac.as_deref(),
        })
    });
    let (routes_json, routes_error) = match &routes {
        Ok(rs) => (serde_json::json!(rs), serde_json::Value::Null),
        Err(e) => (serde_json::Value::Null, serde_json::json!(e)),
    };
    let json = serde_json::json!({
        "default_gateway": default_gw_json,
        "family": "ipv4",
        "routes": routes_json,
        "routes_error": routes_error,
    });
    // Getting at least one of gateway / routing table counts as a successful query
    if default.is_some() || routes.is_ok() {
        ToolOutcome::ok(human, json)
    } else {
        ToolOutcome::fail(human, json)
    }
}

/// `anet tool mtu [iface]`: interface MTU (lists all interfaces by default).
pub fn mtu(iface: Option<&str>) -> ToolOutcome {
    let ifaces = collect_ifaces();
    match iface {
        Some(name) => {
            // Match both the real name and friendly_name (Windows users are more familiar with the latter)
            let hit = ifaces
                .iter()
                .find(|i| i.name == name || i.friendly_name.as_deref() == Some(name));
            match hit {
                None => ToolOutcome::usage_error(format!(
                    "网卡不存在: {name}（`anet tool ifconfig` 查看可用网卡名）"
                )),
                Some(i) => {
                    let human = format!(
                        "[{}] {} MTU: {}（状态 {}）",
                        i.index,
                        display_name(i),
                        i.mtu.map(|m| m.to_string()).unwrap_or_else(|| "未知".into()),
                        if i.is_up { "UP" } else { "DOWN" }
                    );
                    ToolOutcome::ok(
                        human,
                        serde_json::json!({
                            "index": i.index,
                            "name": i.name.as_str(),
                            "friendly_name": i.friendly_name.as_deref(),
                            "mtu": i.mtu,
                            "is_up": i.is_up,
                            "is_loopback": i.is_loopback,
                        }),
                    )
                }
            }
        }
        None => {
            if ifaces.is_empty() {
                return ToolOutcome::fail(
                    "未检测到任何网卡（含回环）",
                    serde_json::json!({ "count": 0, "interfaces": [] }),
                );
            }
            let mut human = format!("网卡 MTU（共 {} 块）：", ifaces.len());
            human.push_str(&format!("\n  {:<24}{:<10}{}", "网卡", "MTU", "状态"));
            for i in &ifaces {
                human.push_str(&format!(
                    "\n  {:<24}{:<10}{}",
                    display_name(i),
                    i.mtu.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
                    if i.is_up { "UP" } else { "DOWN" }
                ));
            }
            let list: Vec<serde_json::Value> = ifaces
                .iter()
                .map(|i| {
                    serde_json::json!({
                        "index": i.index,
                        "name": i.name.as_str(),
                        "friendly_name": i.friendly_name.as_deref(),
                        "mtu": i.mtu,
                        "is_up": i.is_up,
                        "is_loopback": i.is_loopback,
                    })
                })
                .collect();
            ToolOutcome::ok(
                human,
                serde_json::json!({ "count": ifaces.len(), "interfaces": list }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Real environment (local queries, no external network) ====================

    #[test]
    fn ifconfig_lists_at_least_loopback() {
        let out = ifconfig();
        assert!(out.success, "{}", out.human);
        assert_eq!(out.exit_code, 0);
        let list = out.json["interfaces"].as_array().unwrap();
        assert!(!list.is_empty());
        assert!(
            list.iter().any(|i| i["is_loopback"] == true),
            "至少应存在一块回环网卡:\n{}",
            out.human
        );
        assert!(out.human.contains("网卡列表"));
    }

    #[test]
    fn route_reads_table_on_supported_platforms() {
        let out = route();
        assert!(out.success, "{}", out.human);
        assert!(out.human.contains("默认网关"));
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "windows",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        assert!(out.json["routes"].is_array(), "{}", out.human);
    }

    #[test]
    fn mtu_lists_all_ifaces() {
        let out = mtu(None);
        assert!(out.success, "{}", out.human);
        let list = out.json["interfaces"].as_array().unwrap();
        assert!(!list.is_empty());
        assert!(list.iter().all(|i| i["name"].is_string()));
        assert!(list.iter().any(|i| i["is_loopback"] == true));
        assert!(out.human.contains("MTU"));
    }

    #[test]
    fn mtu_single_iface_by_name() {
        let ifaces = collect_ifaces();
        let lo = ifaces.iter().find(|i| i.is_loopback).expect("应有回环网卡");
        let out = mtu(Some(lo.name.as_str()));
        assert!(out.success, "{}", out.human);
        assert_eq!(out.json["name"], lo.name);
    }

    #[test]
    fn mtu_unknown_iface_is_usage_error() {
        let out = mtu(Some("anet-no-such-iface-0"));
        assert!(!out.success);
        assert_eq!(out.exit_code, 2);
        assert!(out.human.contains("网卡不存在"));
    }

    #[test]
    fn mtu_available_on_supported_platforms() {
        let ifaces = collect_ifaces();
        // Linux(sysfs)/Windows(netsh)/macOS/BSD(ifconfig) should all yield the MTU of at least one interface
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "windows",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        assert!(
            ifaces.iter().any(|i| i.mtu.is_some()),
            "当前平台应能取到 MTU: {ifaces:?}"
        );
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "windows",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        let _ = ifaces;
    }

    // ==================== Parsers (text injection, machine-independent) ====================

    #[test]
    fn parses_proc_net_route() {
        let text = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                    eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                    eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
                    broken\tline\n";
        let rs = parse_proc_net_route(text);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].destination, "0.0.0.0/0");
        assert_eq!(rs[0].gateway.as_deref(), Some("192.168.2.1"));
        assert_eq!(rs[0].metric, Some(100));
        assert_eq!(rs[1].destination, "192.168.2.0/24");
        assert_eq!(rs[1].gateway, None); // all-zero gateway → directly connected
        assert_eq!(rs[1].iface, "eth0");
    }

    #[test]
    fn parses_route_print_ipv4_locale_independent() {
        // Chinese Windows output fragment: header and on-link text are localized, data columns unchanged
        let text = "===========================================================================\n\
                    IPv4 Route Table\n\
                    ===========================================================================\n\
                    Active Routes:\n\
                    Network Destination        Netmask          Gateway       Interface  Metric\n\
                              0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.10     25\n\
                            127.0.0.0        255.0.0.0         在链路上         127.0.0.1    331\n\
                    ===========================================================================\n\
                    Persistent Routes:\n\
                      Network Address          Netmask  Gateway Address  Metric\n\
                            0.0.0.0          0.0.0.0      192.168.1.1     Default\n";
        let rs = parse_route_print_ipv4(text);
        // Four-column persistent-route rows are excluded; only active routes remain
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].destination, "0.0.0.0/0");
        assert_eq!(rs[0].gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(rs[0].iface, "192.168.1.10");
        assert_eq!(rs[0].metric, Some(25));
        assert_eq!(rs[1].destination, "127.0.0.0/8");
        assert_eq!(rs[1].gateway, None); // on-link → directly connected
    }

    #[test]
    fn parses_netsh_interfaces_numeric_columns() {
        // Chinese header; names contain spaces; Loopback MTU is u32::MAX
        let text = "Idx     Met         MTU          状态                名称\n\
                    ---  ----------  ----------  ------------  ---------------------------\n\
                      1          75  4294967295  connected     Loopback Pseudo-Interface 1\n\
                      6          25        1500  connected     以太网\n";
        let m = parse_netsh_show_interfaces(text);
        assert_eq!(m.len(), 2);
        assert!(m.contains(&(1, u32::MAX)));
        assert!(m.contains(&(6, 1500)));
    }

    #[test]
    fn parses_ifconfig_mtu_header_lines() {
        let text = "en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
                    \tether 00:11:22:33:44:55\n\
                    \tinet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255\n\
                    lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
                    \tinet 127.0.0.1 netmask 0xff000000\n";
        let m = parse_ifconfig_mtu(text);
        assert_eq!(m, vec![("en0".to_string(), 1500), ("lo0".to_string(), 16384)]);
    }

    #[test]
    fn parses_netstat_rn_inet() {
        let text = "Routing tables\n\n\
                    Internet:\n\
                    Destination        Gateway            Flags               Netif Expire\n\
                    default            192.168.1.1        UGScg               en0\n\
                    127                127.0.0.1          UCS                 lo0\n\
                    127.0.0.1          link#0             UH                  lo0\n\
                    192.168.1.0/24     link#8             UCS                 en0\n";
        let rs = parse_netstat_rn_inet(text);
        assert_eq!(rs.len(), 4);
        assert_eq!(rs[0].destination, "default");
        assert_eq!(rs[0].gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(rs[0].iface, "en0");
        assert_eq!(rs[0].metric, None);
        // BSD shorthand destinations kept verbatim
        assert_eq!(rs[1].destination, "127");
        // link# gateway → directly connected
        assert_eq!(rs[2].gateway, None);
        assert_eq!(rs[3].destination, "192.168.1.0/24");
    }

    #[test]
    fn fmt_bps_humanizes() {
        assert_eq!(fmt_bps(500), "500 bps");
        assert_eq!(fmt_bps(100_000_000), "100.0 Mbps");
        assert_eq!(fmt_bps(1_000_000_000), "1.00 Gbps");
    }
}
