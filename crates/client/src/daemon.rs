//! Client role daemon (`anet-svc client [config.toml]`).
//!
//! Config file defaults to ./agile-net-client.toml, example:
//! ```toml
//! proxy_port = 57890
//! manage_hosts = true
//!
//! # One delegated connect link per node (anet://connect?...&account=d:<label>&password=psk_...)
//! nodes = [
//!   "anet://connect?server=b1.example.com&port=54430&account=d:alice-laptop&password=psk_...&fp=aa11",
//! ]
//! ```

use crate::{AgileNetClient, ConnectParams};
use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ClientFileConfig {
    #[serde(default = "default_proxy_port")]
    proxy_port: u16,
    #[serde(default)]
    proxy_auth: Option<ProxyAuth>,
    #[serde(default)]
    manage_hosts: bool,
    /// Delegated connect links (anet://connect?...), one per node
    #[serde(default)]
    nodes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProxyAuth {
    username: String,
    password: String,
}

fn default_proxy_port() -> u16 {
    57890
}

/// Run in client role: connect all configured nodes + local proxy, until Ctrl-C.
pub async fn run(config_path: &str) -> Result<()> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("read config {config_path}: {e}"))?;
    let config: ClientFileConfig = toml::from_str(&content)?;

    let client = AgileNetClient::new();

    // Connect all nodes (a failure does not block other nodes)
    for link in &config.nodes {
        let parsed = match crate::parse_connect_url(link) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "invalid node link, skipped");
                continue;
            }
        };
        let params = ConnectParams {
            addr: parsed.addr.clone(),
            label: parsed.label,
            token: parsed.token,
            insecure: parsed.insecure,
            pinned_fingerprint: parsed.pinned_fingerprint,
            manage_hosts: config.manage_hosts,
            entries: parsed.entries,
            entry_fps: parsed.entry_fps,
            en: parsed.en,
            emode: parsed.emode,
            eadmin: parsed.eadmin,
        };
        match client.connect(params).await {
            Ok(state) => {
                tracing::info!(node = %state.node_id, rules = state.rules.len(), "node connected")
            }
            Err(e) => tracing::error!(error = %e, "node connect failed"),
        }
    }

    // Start local proxy
    let auth = config.proxy_auth.map(|a| (a.username, a.password));
    client
        .start_proxy_with_auth(config.proxy_port, auth)
        .await?;
    tracing::info!(
        "local proxy listening on 127.0.0.1:{} (SOCKS5/HTTP)",
        client.proxy_port()
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down client role");
    client.disconnect_all().await;
    client.stop_proxy().await;
    Ok(())
}
