//! tcping / scan — TCP connect 探测核心（P0，零新增依赖）。
//!
//! 实现要点：tokio `TcpStream::connect` + 计时；tcping 多次探测输出 min/avg/max；
//! scan 为并发受限的 tcping 循环，只输出开放端口 + 常见服务名猜测。

use super::ToolOutcome;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// 单次 TCP 连接探测的结构化结果（tcping/scan/diag 复用）。
#[derive(Debug, Clone, Serialize)]
pub struct TcpProbe {
    pub host: String,
    pub port: u16,
    pub connected: bool,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
}

/// 单次 TCP connect 探测核心（tcping/scan/diag 共用）。
pub async fn probe(host: &str, port: u16, timeout: Duration) -> TcpProbe {
    let started = Instant::now();
    let result = tokio::time::timeout(timeout, TcpStream::connect((host, port))).await;
    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
    match result {
        Ok(Ok(_stream)) => TcpProbe {
            host: host.to_string(),
            port,
            connected: true,
            latency_ms: Some(latency_ms),
            error: None,
        },
        Ok(Err(e)) => TcpProbe {
            host: host.to_string(),
            port,
            connected: false,
            latency_ms: None,
            error: Some(e.to_string()),
        },
        Err(_) => TcpProbe {
            host: host.to_string(),
            port,
            connected: false,
            latency_ms: None,
            error: Some(format!("连接超时（{}ms）", timeout.as_millis())),
        },
    }
}

/// `anet tool tcping <host> <port>`：多次探测，输出逐次结果与 min/avg/max。
pub async fn tcping(host: &str, port: u16, count: u32, timeout: Duration) -> ToolOutcome {
    let count = count.max(1);
    let mut probes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        probes.push(probe(host, port, timeout).await);
    }

    let ok: Vec<f64> = probes.iter().filter_map(|p| p.latency_ms).collect();
    let connected = ok.len();
    let failed = probes.len() - connected;
    let (min, avg, max) = if ok.is_empty() {
        (None, None, None)
    } else {
        let min = ok.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = ok.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = ok.iter().sum::<f64>() / ok.len() as f64;
        (Some(min), Some(avg), Some(max))
    };

    // 人类可读输出：逐次结果 + ping 风格统计
    let mut human = format!(
        "正在探测 {host}:{port}（{count} 次，超时 {}s）...",
        timeout.as_secs()
    );
    for (i, p) in probes.iter().enumerate() {
        if let Some(ms) = p.latency_ms {
            human.push_str(&format!(
                "\n#{} 来自 {}:{} 的响应：已连接 time={:.2}ms",
                i + 1,
                p.host,
                p.port,
                ms
            ));
        } else {
            human.push_str(&format!(
                "\n#{} {}:{} 连接失败：{}",
                i + 1,
                p.host,
                p.port,
                p.error.as_deref().unwrap_or("未知错误")
            ));
        }
    }
    human.push_str(&format!(
        "\n--- {host}:{port} tcping 统计 ---\n    已发送 = {}，成功 = {}，失败 = {}",
        probes.len(),
        connected,
        failed
    ));
    if let (Some(min), Some(avg), Some(max)) = (min, avg, max) {
        human.push_str(&format!(
            "\n    延迟 min/avg/max = {min:.2}/{avg:.2}/{max:.2} ms"
        ));
    }

    let json = serde_json::json!({
        "host": host,
        "port": port,
        "count": probes.len(),
        "connected": connected,
        "failed": failed,
        "min_ms": min,
        "avg_ms": avg,
        "max_ms": max,
        "probes": probes,
    });
    if connected > 0 {
        ToolOutcome::ok(human, json)
    } else {
        ToolOutcome::fail(human, json)
    }
}

/// `anet tool scan <host> <port-range>`：并发受限的 connect 扫描（复用 [`probe`]）。
pub async fn scan(
    host: &str,
    start: u16,
    end: u16,
    concurrency: u32,
    timeout: Duration,
) -> ToolOutcome {
    let sem = Arc::new(Semaphore::new(concurrency.max(1) as usize));
    let mut set = tokio::task::JoinSet::new();
    for port in start..=end {
        // 信号量背压：在途任务数受 concurrency 限制
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let host = host.to_string();
        set.spawn(async move {
            let _permit = permit;
            probe(&host, port, timeout).await
        });
    }

    let mut open = Vec::new();
    while let Some(Ok(p)) = set.join_next().await {
        if p.connected {
            open.push(p);
        }
    }
    open.sort_by_key(|p| p.port);

    let scanned = (end - start) as usize + 1;
    let mut human = format!(
        "正在扫描 {host} 端口 {start}-{end}（并发 {}，超时 {}s）...",
        concurrency.max(1),
        timeout.as_secs()
    );
    if open.is_empty() {
        human.push_str(&format!("\n未检测到开放端口（共扫描 {scanned} 个）"));
    } else {
        human.push_str(&format!("\n开放端口 {} 个：", open.len()));
        human.push_str(&format!(
            "\n  {:<7}{:<16}{}",
            "端口", "服务猜测", "延迟"
        ));
        for p in &open {
            human.push_str(&format!(
                "\n  {:<7}{:<16}{:.2}ms",
                p.port,
                service_name(p.port),
                p.latency_ms.unwrap_or(0.0)
            ));
        }
    }

    let open_json: Vec<serde_json::Value> = open
        .iter()
        .map(|p| {
            serde_json::json!({
                "port": p.port,
                "service": service_name(p.port),
                "latency_ms": p.latency_ms,
            })
        })
        .collect();
    let json = serde_json::json!({
        "host": host,
        "range": format!("{start}-{end}"),
        "scanned": scanned,
        "open_count": open.len(),
        "open": open_json,
    });
    if open.is_empty() {
        ToolOutcome::fail(human, json)
    } else {
        ToolOutcome::ok(human, json)
    }
}

/// 常见端口服务名猜测（仅供扫端口时参考，非指纹识别）。
fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        587 => "submission",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        2181 => "zookeeper",
        2375 => "docker",
        2376 => "docker-tls",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5672 => "amqp",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        9092 => "kafka",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        // AgileNet 默认端口（见 AGENTS.md 端口规范）
        54430 => "anet-relay",
        57890 => "anet-proxy",
        59090 => "anet-api",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// 起临时 listener，返回其端口（listener 随调用方持有）。
    async fn bind_listener() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    /// 绑定后立即释放端口，拿到一个确定关闭的回环端口。
    async fn closed_port() -> u16 {
        let (listener, port) = bind_listener().await;
        drop(listener);
        port
    }

    #[tokio::test]
    async fn probe_connects_to_open_port() {
        let (_listener, port) = bind_listener().await;
        let p = probe("127.0.0.1", port, Duration::from_secs(2)).await;
        assert!(p.connected);
        assert!(p.latency_ms.is_some());
        assert!(p.error.is_none());
    }

    #[tokio::test]
    async fn probe_fails_on_closed_port() {
        let port = closed_port().await;
        let p = probe("127.0.0.1", port, Duration::from_secs(2)).await;
        assert!(!p.connected);
        assert!(p.latency_ms.is_none());
        assert!(p.error.is_some());
    }

    #[tokio::test]
    async fn tcping_reports_min_avg_max_on_open_port() {
        let (_listener, port) = bind_listener().await;
        let out = tcping("127.0.0.1", port, 3, Duration::from_secs(2)).await;
        assert!(out.success);
        assert_eq!(out.exit_code, 0);
        let json = &out.json;
        assert_eq!(json["connected"], 3);
        let min = json["min_ms"].as_f64().unwrap();
        let avg = json["avg_ms"].as_f64().unwrap();
        let max = json["max_ms"].as_f64().unwrap();
        assert!(min <= avg && avg <= max);
        assert!(out.human.contains("min/avg/max"));
    }

    #[tokio::test]
    async fn tcping_fails_on_closed_port() {
        let port = closed_port().await;
        let out = tcping("127.0.0.1", port, 2, Duration::from_secs(1)).await;
        assert!(!out.success);
        assert_eq!(out.exit_code, 1);
        assert_eq!(out.json["connected"], 0);
        assert!(out.json["min_ms"].is_null());
    }

    #[tokio::test]
    async fn scan_finds_open_port() {
        let (_listener, port) = bind_listener().await;
        // 单端口范围：不受并行测试临时 listener 干扰
        let out = scan("127.0.0.1", port, port, 8, Duration::from_secs(2)).await;
        assert!(out.success);
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.json["scanned"], 1);
        let open = out.json["open"].as_array().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0]["port"], port);
        assert!(out.human.contains(&port.to_string()));
    }

    #[tokio::test]
    async fn scan_range_counts_and_covers_open_port() {
        let (_listener, port) = bind_listener().await;
        // 多端口范围：只断言扫描计数与目标端口必在开放清单（listener 存活期间），
        // 不断言其它端口状态（回环相邻端口可能被并行测试/系统占用）
        let start = port.saturating_sub(2).max(1);
        let end = port.saturating_add(2);
        let out = scan("127.0.0.1", start, end, 8, Duration::from_secs(2)).await;
        assert_eq!(out.json["scanned"], (end - start) as u64 + 1);
        assert!(out.success);
        let open = out.json["open"].as_array().unwrap();
        assert!(open.iter().any(|o| o["port"] == port));
    }

    #[tokio::test]
    async fn scan_fails_when_nothing_open() {
        let port = closed_port().await;
        // 单端口扫描一个已关闭端口
        let out = scan("127.0.0.1", port, port, 4, Duration::from_secs(1)).await;
        assert!(!out.success);
        assert_eq!(out.exit_code, 1);
        assert_eq!(out.json["open_count"], 0);
        assert!(out.human.contains("未检测到开放端口"));
    }

    #[tokio::test]
    async fn scan_respects_zero_concurrency() {
        let (_listener, port) = bind_listener().await;
        // concurrency=0 防御性钳制为 1，不应挂死
        let out = scan("127.0.0.1", port, port, 0, Duration::from_secs(2)).await;
        assert!(out.success);
    }

    #[test]
    fn service_name_guesses_common_ports() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(443), "https");
        assert_eq!(service_name(54430), "anet-relay");
        assert_eq!(service_name(19999), "unknown");
    }
}
