//! 第 5 节：网络连通（DNS 解析 / HTTPS 出站 / 默认网关 ping）。

use super::{DoctorSection, DoctorStatus, item, section};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub(super) async fn section_network() -> DoctorSection {
    let mut items = Vec::new();

    // DNS 解析
    match tokio::net::lookup_host(("www.cloudflare.com", 443)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            match addrs.first() {
                Some(first) => items.push(item(
                    "dns",
                    "DNS 解析",
                    DoctorStatus::Ok,
                    format!(
                        "www.cloudflare.com → {}（共 {} 个地址）",
                        first.ip(),
                        addrs.len()
                    ),
                    None,
                )),
                None => items.push(item(
                    "dns",
                    "DNS 解析",
                    DoctorStatus::Err,
                    "www.cloudflare.com 解析结果为空",
                    Some("检查系统 DNS 配置（`anet tool dnsconf`）".into()),
                )),
            }
        }
        Err(e) => items.push(item(
            "dns",
            "DNS 解析",
            DoctorStatus::Err,
            format!("www.cloudflare.com 解析失败：{e}"),
            Some("检查系统 DNS 配置（`anet tool dnsconf` / `anet tool dns www.cloudflare.com`）".into()),
        )),
    }

    // HTTPS 出站
    let https_start = Instant::now();
    let https = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string());
    match https {
        Err(e) => items.push(item(
            "https",
            "HTTPS 出站",
            DoctorStatus::Err,
            format!("HTTP 客户端构建失败：{e}"),
            None,
        )),
        Ok(client) => match client.get("https://ipwho.is/").send().await {
            Ok(resp) if resp.status().is_success() => items.push(item(
                "https",
                "HTTPS 出站",
                DoctorStatus::Ok,
                format!(
                    "ipwho.is 可达（HTTP {}，{}ms）",
                    resp.status(),
                    https_start.elapsed().as_millis()
                ),
                None,
            )),
            Ok(resp) => items.push(item(
                "https",
                "HTTPS 出站",
                DoctorStatus::Err,
                format!("ipwho.is 返回 HTTP {}", resp.status()),
                Some("出站 HTTPS 异常：检查网关/防火墙（`anet tool diag ipwho.is 443`）".into()),
            )),
            Err(e) => items.push(item(
                "https",
                "HTTPS 出站",
                DoctorStatus::Err,
                format!("ipwho.is 不可达：{e}"),
                Some("出站 HTTPS 不通：检查网关/防火墙（`anet tool diag ipwho.is 443`）".into()),
            )),
        },
    }

    // 默认网关 ping（失败仅提示——很多网关禁 ICMP）
    match default_net::get_default_gateway() {
        Ok(gw) => match ping_once(gw.ip_addr, Duration::from_secs(1)).await {
            Ok(ms) => items.push(item(
                "gateway",
                "默认网关",
                DoctorStatus::Ok,
                format!("{} 可达（{ms:.1}ms）", gw.ip_addr),
                None,
            )),
            Err(e) => items.push(item(
                "gateway",
                "默认网关",
                DoctorStatus::Info,
                format!("{} ping 不通（{e}；网关常禁 ICMP，仅提示）", gw.ip_addr),
                None,
            )),
        },
        Err(_) => items.push(item(
            "gateway",
            "默认网关",
            DoctorStatus::Info,
            "未找到默认网关（可能仅本地网络）",
            None,
        )),
    }
    section("network", "网络连通", items)
}

/// 单发 ICMP ping（surge-ping；无权限/超时均为 Err 由调用方降级为提示）。
async fn ping_once(addr: IpAddr, timeout: Duration) -> Result<f64, String> {
    use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};
    let config = match addr {
        IpAddr::V4(_) => Config::default(),
        IpAddr::V6(_) => Config::builder().kind(ICMP::V6).build(),
    };
    let client = Client::new(&config).map_err(|e| format!("ICMP socket 创建失败：{e}"))?;
    let mut pinger = client.pinger(addr, PingIdentifier(rand::random())).await;
    pinger.timeout(timeout);
    pinger
        .ping(PingSequence(0), b"anet-doctor")
        .await
        .map(|(_, rtt)| rtt.as_secs_f64() * 1000.0)
        .map_err(|e| e.to_string())
}
