//! ifconfig / route / mtu — 网卡与路由（P1，default-net）。
//!
//! default-net 提供网卡清单（IP/MAC/类型/速率/默认网关）；MTU 与完整路由表
//! default-net 0.22 未覆盖，按平台补齐。解析函数与数据源分离（注入文本），
//! 单测不依赖具体机器环境：
//! - Linux/Android：`/sys/class/net/*/mtu`、`/proc/net/route`（procfs/sysfs 必有，
//!   国产化裁剪环境亦无私有依赖）；
//! - Windows：`netsh interface ipv4/ipv6 show interfaces`、`route print -4`
//!   （输出为 OEM 码页，有损解码后仅按数字/IPv4 列解析，与界面语言无关）；
//! - macOS/BSD：`ifconfig`、`netstat -rn -f inet`。
//!
//! 路由表仅覆盖 IPv4（运维诊断主场景）；默认网关（含 IPv6）由 default-net 给出。

use super::ToolOutcome;
use serde::Serialize;
use std::collections::HashMap;

/// 网卡结构化信息（ifconfig / mtu 的 json 单元）。
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

/// 单条 IPv4 路由（route 的 json 单元）。
#[derive(Debug, Clone, Serialize)]
struct RouteEntry {
    /// 目的网段（如 0.0.0.0/0；macOS/BSD 可能为 default 或主机地址）
    destination: String,
    /// 下一跳网关；None 表示直连（on-link）
    gateway: Option<String>,
    /// 出接口（Windows route print 只有接口 IP，原样呈现）
    iface: String,
    metric: Option<u32>,
}

/// MTU 查询表：Linux/macOS/BSD 按网卡名，Windows 按网卡 index（netsh Idx 即 IfIndex）。
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

/// 汇总当前平台 MTU 数据源；读取失败仅导致 MTU 列缺失（显示「-」），不阻塞主输出。
fn mtu_table() -> MtuTable {
    let mut t = MtuTable::default();
    load_mtu_table(&mut t);
    t
}

/// Linux/Android：sysfs 逐网卡读 mtu 文件。
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

/// Windows：netsh show interfaces（IPv4/IPv6 各查一次，先得的优先）。
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

/// macOS/BSD：解析 ifconfig 各网卡块首行的 mtu 字段。
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

/// 其它平台：暂无 MTU 数据源（列显示「-」）。
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

/// 执行系统命令并取 stdout（按本地码页有损解码；解析只依赖数字/ASCII 列）。
#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn shell_out(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 解析 netsh show interfaces：数据行前三列均为数字（Idx/Met/MTU），
/// 表头/分隔行自然跳过（与界面语言无关）；返回 (IfIndex, MTU)。
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

/// 解析 ifconfig 输出：网卡块首行形如 "en0: flags=... mtu 1500"，取 (名称, MTU)。
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
        // 续行以空白开头，块首行含 "名称: ... mtu N"
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

/// 解析 /proc/net/route：目的/网关/掩码为小端 hex；网关全零表示直连。
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

/// /proc 小端 hex → IPv4（"0102A8C0" → 192.168.2.1）。
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn hex_le_ipv4(s: &str) -> Option<std::net::Ipv4Addr> {
    let v = u32::from_str_radix(s, 16).ok()?;
    Some(std::net::Ipv4Addr::from(v.to_le_bytes()))
}

/// 解析 route print -4：数据行为「目的 掩码 网关 接口 跃点」五列，前两列须为 IPv4
/// （表头/分隔/本地化行自然跳过）；网关列非 IPv4（如 On-link/在链路上）记为直连。
/// Persistent Routes 段为四列（无接口列），被五列规则排除，避免与活动路由重复。
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

/// 解析 netstat -rn -f inet：Destination Gateway Flags Netif [Expire]；
/// 目的列可能是 default/CIDR/主机地址/BSD 简写（如 127）；网关非 IP（link#x 等）记为直连。
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
        // 目的列形如 default / 127 / 127.0.0.1 / 192.168.1.0/24，表头行自然跳过
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

/// 读取本机 IPv4 路由表（按平台选择数据源）。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_ipv4_routes() -> Result<Vec<RouteEntry>, String> {
    let text = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| format!("读取 /proc/net/route 失败: {e}"))?;
    Ok(parse_proc_net_route(&text))
}

/// 读取本机 IPv4 路由表（按平台选择数据源）。
#[cfg(target_os = "windows")]
fn read_ipv4_routes() -> Result<Vec<RouteEntry>, String> {
    let out = shell_out("route", &["print", "-4"]).ok_or("route 命令不可用")?;
    Ok(parse_route_print_ipv4(&out))
}

/// 读取本机 IPv4 路由表（按平台选择数据源）。
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

/// 读取本机 IPv4 路由表（按平台选择数据源）。
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

/// 汇总网卡信息（附带 MTU 与默认网卡标记；两者失败仅缺字段，不阻塞主输出）。
fn collect_ifaces() -> Vec<IfaceInfo> {
    let mtus = mtu_table();
    // 内部为 UDP connect 选路，无实际报文；无默认路由时失败 → 不标记默认网卡
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
                // Windows 未知速率报 u64::MAX（-1 哨兵），视为缺失
                receive_bps: i.receive_speed.filter(|&v| v != u64::MAX),
                transmit_bps: i.transmit_speed.filter(|&v| v != u64::MAX),
            }
        })
        .collect()
}

/// 展示名：优先 friendly_name（Windows 网卡名为 GUID，不具可读性）。
fn display_name(i: &IfaceInfo) -> &str {
    i.friendly_name.as_deref().unwrap_or(&i.name)
}

/// 速率人性化（default-net 给出 bps）。
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

/// `anet tool ifconfig`（等同 ifconfig / ip a）：网卡列表、IP、MAC、网关、MTU。
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
        // Windows 网卡名为 GUID，单独给一行真实名称（mtu 过滤时可用）
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

/// `anet tool route`（等同 route print / ip route）：默认网关 + 路由表。
pub fn route() -> ToolOutcome {
    let ifaces = collect_ifaces();
    // 默认网卡优先；取不到（无默认路由）时回退到任一持网关的在用网卡
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
    // 网关与路由表至少取得其一即视为查询成功
    if default.is_some() || routes.is_ok() {
        ToolOutcome::ok(human, json)
    } else {
        ToolOutcome::fail(human, json)
    }
}

/// `anet tool mtu [iface]`：网卡 MTU（缺省列出全部网卡）。
pub fn mtu(iface: Option<&str>) -> ToolOutcome {
    let ifaces = collect_ifaces();
    match iface {
        Some(name) => {
            // 同时按真实名与 friendly_name 匹配（Windows 用户更熟悉后者）
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

    // ==================== 真实环境（本机查询，无外网依赖） ====================

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
        // Linux(sysfs)/Windows(netsh)/macOS/BSD(ifconfig) 均应至少取到一块网卡的 MTU
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

    // ==================== 解析器（注入文本，与机器无关） ====================

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
        assert_eq!(rs[1].gateway, None); // 网关全零 → 直连
        assert_eq!(rs[1].iface, "eth0");
    }

    #[test]
    fn parses_route_print_ipv4_locale_independent() {
        // 中文 Windows 输出片段：表头/「在链路上」本地化，数据列不变
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
        // 四列的持久路由行被排除，只保留活动路由
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].destination, "0.0.0.0/0");
        assert_eq!(rs[0].gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(rs[0].iface, "192.168.1.10");
        assert_eq!(rs[0].metric, Some(25));
        assert_eq!(rs[1].destination, "127.0.0.0/8");
        assert_eq!(rs[1].gateway, None); // 在链路上 → 直连
    }

    #[test]
    fn parses_netsh_interfaces_numeric_columns() {
        // 中文表头；名称含空格；Loopback MTU 为 u32 最大值
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
        // BSD 简写目的原样保留
        assert_eq!(rs[1].destination, "127");
        // link# 网关 → 直连
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
