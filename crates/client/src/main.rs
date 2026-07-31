//! AgileNet Client 守护进程
//!
//! 用法：agile-net-client [config.toml]
//! 配置文件缺省为 ./agile-net-client.toml，示例：
//! ```toml
//! proxy_port = 7890
//! manage_hosts = true
//!
//! [[nodes]]
//! addr = "https://node-a.example.com:9090"
//! username = "zhangsan"
//! password = "sk-..."
//! insecure = false
//! # pinned_cert_path = "certs/node-a.pem"
//! ```

use agile_net_client::{AgileNetClient, ConnectParams};
use anyhow::Result;
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Deserialize)]
struct ClientFileConfig {
    #[serde(default = "default_proxy_port")]
    proxy_port: u16,
    #[serde(default)]
    proxy_auth: Option<ProxyAuth>,
    #[serde(default)]
    manage_hosts: bool,
    #[serde(default)]
    nodes: Vec<NodeEntry>,
}

#[derive(Debug, Deserialize)]
struct ProxyAuth {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct NodeEntry {
    addr: String,
    username: String,
    password: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default)]
    pinned_cert_path: Option<String>,
    #[serde(default)]
    pinned_fingerprint: Option<String>,
}

fn default_proxy_port() -> u16 {
    7890
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("agile-net-client {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let config_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "agile-net-client.toml".into());
    let content = std::fs::read_to_string(&config_path)
        .map_err(|e| anyhow::anyhow!("read config {config_path}: {e}"))?;
    let config: ClientFileConfig = toml::from_str(&content)?;

    let client = AgileNetClient::new();

    // 连接全部节点（失败不阻塞其他节点）
    for node in &config.nodes {
        let params = ConnectParams {
            addr: node.addr.clone(),
            username: node.username.clone(),
            password: node.password.clone(),
            insecure: node.insecure,
            pinned_cert_path: node.pinned_cert_path.clone(),
            pinned_fingerprint: node.pinned_fingerprint.clone(),
            manage_hosts: config.manage_hosts,
        };
        match client.connect(params).await {
            Ok(state) => tracing::info!(node = %state.node_id, rules = state.rules.len(), "node connected"),
            Err(e) => tracing::error!(addr = %node.addr, error = %e, "node connect failed"),
        }
    }

    // 启动本地代理
    let auth = config
        .proxy_auth
        .map(|a| (a.username, a.password));
    client.start_proxy_with_auth(config.proxy_port, auth).await?;
    tracing::info!(
        "⚡ local proxy listening on 127.0.0.1:{} (SOCKS5/HTTP)",
        client.proxy_port()
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down agile-net-client");
    client.disconnect_all().await;
    client.stop_proxy().await;
    Ok(())
}
