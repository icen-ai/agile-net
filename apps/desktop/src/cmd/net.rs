//! Split from lib.rs: network probes (exit IP / LAN IP) (pure move, zero logic change)

use crate::{map_err, subscription, AppState};
use serde::Serialize;
use tauri::State;

// ==================== Network probes (exit IP / LAN IP) ====================

/// Exit probe result: location shown as text only (country code/name), no flag icons
#[derive(Debug, Clone, Serialize)]
pub struct ExitIpInfo {
    pub ip: String,
    pub country: String,
    pub country_code: String,
}

/// Parse ipwho.is response ({success, ip, country, country_code})
pub(crate) fn parse_ipwho(v: &serde_json::Value) -> Option<ExitIpInfo> {
    if v["success"].as_bool() != Some(true) {
        return None;
    }
    Some(ExitIpInfo {
        ip: v["ip"].as_str()?.to_string(),
        country: v["country"].as_str().unwrap_or_default().to_string(),
        country_code: v["country_code"].as_str().unwrap_or_default().to_string(),
    })
}

/// Parse ip-api.com response ({status, query, country, countryCode})
pub(crate) fn parse_ip_api(v: &serde_json::Value) -> Option<ExitIpInfo> {
    if v["status"].as_str() != Some("success") {
        return None;
    }
    Some(ExitIpInfo {
        ip: v["query"].as_str()?.to_string(),
        country: v["country"].as_str().unwrap_or_default().to_string(),
        country_code: v["countryCode"].as_str().unwrap_or_default().to_string(),
    })
}

/// Exit IP probe: HTTPS endpoint first, fallback endpoint on failure; with via_proxy goes through the
/// mihomo mixed exit (verifies the real exit of subscription traffic). 5s timeout; total failure is shown by the frontend as "probe failed".
#[tauri::command]
pub(crate) async fn fetch_exit_ip(state: State<'_, AppState>, via_proxy: bool) -> Result<ExitIpInfo, String> {
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!("anet-gui/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(5));
    if via_proxy {
        // Egress probe path, in order: TUN → subscription exit socks (57893; mixed port is disabled by the
        // anti-loop design); kernel running → mixed port http; otherwise the anet local proxy (57890) —
        // mihomo only owns the subscription mechanism; with the kernel off the anet inbound still routes
        // (direct/tunnel per its rules), so the probe keeps working and reflects the real egress.
        let tun = state.roles.lock().await.tun_mode;
        let kernel_on = state.kernel.running().await;
        let proxy_port = state.client.proxy_port();
        let proxy = if tun {
            reqwest::Proxy::all(format!(
                "socks5h://127.0.0.1:{}",
                subscription::MIHOMO_SOCKS_PORT
            ))
        } else if kernel_on {
            reqwest::Proxy::all(format!(
                "http://127.0.0.1:{}",
                subscription::MIHOMO_MIXED_PORT
            ))
        } else if proxy_port > 0 {
            reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}"))
        } else {
            return Err("代理未启动，无法经代理探测".into());
        }
        .map_err(map_err)?;
        builder = builder.proxy(proxy);
    }
    let client = builder.build().map_err(map_err)?;

    // Preferred: ipwho.is (HTTPS, no key required)
    if let Ok(resp) = client.get("https://ipwho.is/").send().await {
        if let Ok(v) = resp.json::<serde_json::Value>().await {
            if let Some(info) = parse_ipwho(&v) {
                return Ok(info);
            }
        }
    }
    // Fallback: ip-api.com (free tier is HTTP only)
    let resp = client
        .get("http://ip-api.com/json")
        .send()
        .await
        .map_err(map_err)?;
    let v = resp.json::<serde_json::Value>().await.map_err(map_err)?;
    parse_ip_api(&v).ok_or_else(|| "出口探测失败".into())
}

/// LAN IP probe result (first IPv4 of the default interface)
#[derive(Debug, Clone, Serialize)]
pub struct LanIpInfo {
    pub ip: String,
    pub iface: String,
}

/// Pick a LAN IPv4 from the ifconfig interface list: default interface first, then the first UP non-loopback interface.
pub(crate) fn pick_lan_ip(ifaces: &[serde_json::Value]) -> Option<LanIpInfo> {
    let pick = |pred: &dyn Fn(&serde_json::Value) -> bool| -> Option<LanIpInfo> {
        ifaces.iter().filter(|i| pred(i)).find_map(|i| {
            // ipv4 entries carry a prefix length (e.g. 192.168.1.5/24); display keeps only the address part
            let raw = i["ipv4"].as_array()?.first()?.as_str()?;
            let ip = raw.split('/').next()?.to_string();
            let iface = i["friendly_name"]
                .as_str()
                .or_else(|| i["name"].as_str())
                .unwrap_or_default()
                .to_string();
            Some(LanIpInfo { ip, iface })
        })
    };
    pick(&|i| i["is_default"].as_bool() == Some(true)).or_else(|| {
        pick(&|i| i["is_up"].as_bool() == Some(true) && i["is_loopback"].as_bool() != Some(true))
    })
}

/// LAN IP: reuses anet tool ifconfig interface enumeration (Windows involves a netsh subprocess, so run on the blocking pool).
#[tauri::command]
pub(crate) async fn lan_ip() -> Result<LanIpInfo, String> {
    tokio::task::spawn_blocking(|| {
        let out = agile_net_node::tool::netif::ifconfig();
        let ifaces = out.json["interfaces"].as_array().cloned().unwrap_or_default();
        pick_lan_ip(&ifaces).ok_or_else(|| "未检测到内网 IPv4".to_string())
    })
    .await
    .map_err(map_err)?
}

/// Local-proxy cumulative traffic (anet ProxyStats). The hero card rates/connections fall back to this
/// when the subscription kernel is off — mihomo only ever owned the subscription mechanism.
#[derive(Debug, Clone, Serialize)]
pub struct ProxyTrafficInfo {
    pub running: bool,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub active: u64,
    pub total: u64,
}

#[tauri::command]
pub(crate) async fn proxy_traffic(state: State<'_, AppState>) -> Result<ProxyTrafficInfo, String> {
    use std::sync::atomic::Ordering;
    match state.client.proxy_stats() {
        Some(s) => Ok(ProxyTrafficInfo {
            running: true,
            bytes_up: s.bytes_up.load(Ordering::Relaxed),
            bytes_down: s.bytes_down.load(Ordering::Relaxed),
            active: s.active_connections.load(Ordering::Relaxed),
            total: s.total_connections.load(Ordering::Relaxed),
        }),
        None => Ok(ProxyTrafficInfo {
            running: false,
            bytes_up: 0,
            bytes_down: 0,
            active: 0,
            total: 0,
        }),
    }
}

/// App-side recent logs (anet's own tracing ring buffer; 实时日志 tab's fallback when the kernel is off).
/// Output shape matches sub_logs ({time: epoch secs, level, payload}) so the frontend renderer is shared.
#[tauri::command]
pub(crate) async fn app_logs(
    state: State<'_, AppState>,
    limit: Option<usize>,
    level: Option<String>,
) -> Result<Vec<serde_json::Value>, String> {
    let mut entries = state
        .app_logs
        .query(limit.unwrap_or(500).clamp(1, 1000), level.as_deref(), None);
    entries.reverse(); // buffer is newest-first; the incremental renderer wants oldest→newest
    Ok(entries
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "time": e.ts / 1000,
                "level": e.level,
                "payload": format!("[{}] {}", e.module, e.message),
            })
        })
        .collect())
}

/// Clear the app-side log ring (实时日志 tab's 清空 when showing the anet source).
#[tauri::command]
pub(crate) async fn app_logs_clear(state: State<'_, AppState>) -> Result<(), String> {
    state.app_logs.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_ipwho_response() {
        let v = serde_json::json!({"success": true, "ip": "203.0.113.7", "country": "China", "country_code": "CN"});
        let info = parse_ipwho(&v).expect("应解析成功");
        assert_eq!(info.ip, "203.0.113.7");
        assert_eq!(info.country, "China");
        assert_eq!(info.country_code, "CN");
        // success=false / missing ip are both rejected
        assert!(parse_ipwho(&serde_json::json!({"success": false, "message": "invalid"})).is_none());
        assert!(parse_ipwho(&serde_json::json!({"success": true})).is_none());
    }

    #[test]
    fn parses_ip_api_response() {
        let v = serde_json::json!({"status": "success", "query": "198.51.100.9", "country": "United States", "countryCode": "US"});
        let info = parse_ip_api(&v).expect("应解析成功");
        assert_eq!(info.ip, "198.51.100.9");
        assert_eq!(info.country, "United States");
        assert_eq!(info.country_code, "US");
        assert!(parse_ip_api(&serde_json::json!({"status": "fail"})).is_none());
    }

    #[test]
    fn picks_default_iface_ipv4_and_strips_prefix() {
        let ifaces = vec![
            serde_json::json!({"name": "lo", "is_up": true, "is_loopback": true, "is_default": false, "ipv4": ["127.0.0.1/8"]}),
            serde_json::json!({"name": "eth0", "is_up": true, "is_loopback": false, "is_default": true, "ipv4": ["192.168.1.5/24"]}),
        ];
        let info = pick_lan_ip(&ifaces).expect("应选中默认网卡");
        assert_eq!(info.ip, "192.168.1.5");
        assert_eq!(info.iface, "eth0");
    }

    #[test]
    fn falls_back_to_first_up_non_loopback() {
        let ifaces = vec![
            serde_json::json!({"name": "lo", "is_up": true, "is_loopback": true, "is_default": false, "ipv4": ["127.0.0.1/8"]}),
            serde_json::json!({"friendly_name": "WLAN", "name": "{GUID}", "is_up": true, "is_loopback": false, "is_default": false, "ipv4": ["10.0.0.8/24"]}),
        ];
        let info = pick_lan_ip(&ifaces).expect("应回落到首块可用网卡");
        assert_eq!(info.ip, "10.0.0.8");
        // friendly_name wins (Windows interface names are unreadable GUIDs)
        assert_eq!(info.iface, "WLAN");
        assert!(pick_lan_ip(&[]).is_none());
    }
}
