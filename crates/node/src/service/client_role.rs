//! Embedded client role: the svc `[client]` config section runs an `AgileNetClient` in-process
//! (delegated node connections + local proxy), sharing the node API port (single-port unified
//! web plane). The standalone `anet-svc client` subcommand stays a separate process and is
//! untouched; both reuse the same client-crate engine.

use crate::service::{ClientProxyInfo, ClientProxySlot};
use agile_net_client::{AgileNetClient, ConnectParams};
use anyhow::Result;
use serde::Deserialize;
use std::sync::Arc;

/// `[client]` section of the svc config (client role embedding).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientRoleConfig {
    /// Delegated connect links (anet://connect?...&account=d:<label>&password=psk_...), one per node
    #[serde(default)]
    pub nodes: Vec<String>,
    /// Local proxy listen port (127.0.0.1; SOCKS5/HTTP)
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// Optional local proxy auth
    #[serde(default)]
    pub proxy_auth: Option<ClientProxyAuth>,
    /// Auto-maintain system hosts from resolve rules
    #[serde(default)]
    pub manage_hosts: bool,
}

/// `[client.proxy_auth]` local proxy credentials.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientProxyAuth {
    pub username: String,
    pub password: String,
}

fn default_proxy_port() -> u16 {
    57890
}

/// Parse just the optional `[client]` section of a svc config file (missing file/section = None).
///
/// `NodeConfig` lives in core and knows nothing about this section; `load_config` keeps its
/// signature, and hosts embedding the client role (CLI `run_server`, GUI) call this alongside
/// and pass the result via `NodeServerOptions::client_role`.
pub fn load_client_role_config(path: &str) -> Result<Option<ClientRoleConfig>> {
    #[derive(Deserialize)]
    struct ClientSection {
        client: Option<ClientRoleConfig>,
    }
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(toml::from_str::<ClientSection>(&content)?.client),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Start the embedded client role: connect every configured node (a failure does not block
/// the others, same as the standalone daemon), then start the local proxy and publish its
/// state to the node status slot.
pub(crate) async fn run(engine: &AgileNetClient, cfg: &ClientRoleConfig, slot: &ClientProxySlot) {
    for link in &cfg.nodes {
        let parsed = match agile_net_client::parse_connect_url(link) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "invalid [client] node link, skipped");
                continue;
            }
        };
        let params = ConnectParams {
            addr: parsed.addr.clone(),
            label: parsed.label,
            token: parsed.token,
            insecure: parsed.insecure,
            pinned_fingerprint: parsed.pinned_fingerprint,
            manage_hosts: cfg.manage_hosts,
            entries: parsed.entries,
            entry_fps: parsed.entry_fps,
            en: parsed.en,
            emode: parsed.emode,
            eadmin: parsed.eadmin,
        };
        match engine.connect(params).await {
            Ok(state) => tracing::info!(node = %state.node_id, "[client] node connected"),
            Err(e) => tracing::error!(error = %e, "[client] node connect failed"),
        }
    }

    let auth = cfg
        .proxy_auth
        .as_ref()
        .map(|a| (a.username.clone(), a.password.clone()));
    match engine.start_proxy_with_auth(cfg.proxy_port, auth).await {
        Ok(()) => {
            let listen = format!("127.0.0.1:{}", engine.proxy_port());
            slot.store(Arc::new(Some(ClientProxyInfo {
                enabled: true,
                mode: "local".into(),
                listen: listen.clone(),
            })));
            tracing::info!(addr = %listen, "[client] local proxy listening (SOCKS5/HTTP)");
        }
        Err(e) => tracing::error!(error = %e, "[client] local proxy start failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[client]` TOML section parsing: full shape / missing file / absent section
    #[test]
    fn load_client_role_config_parses_section() {
        let dir = std::env::temp_dir().join(format!("anet-client-role-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("svc.toml");
        std::fs::write(
            &path,
            r#"
name = "n1"

[client]
proxy_port = 57901
manage_hosts = true
nodes = ["anet://connect?server=b1.example.com&port=54430&account=d:alice&password=psk_x"]

[client.proxy_auth]
username = "u"
password = "p"
"#,
        )
        .unwrap();
        let cfg = load_client_role_config(path.to_str().unwrap())
            .unwrap()
            .expect("section present");
        assert_eq!(cfg.proxy_port, 57901);
        assert!(cfg.manage_hosts);
        assert_eq!(cfg.nodes.len(), 1);
        assert_eq!(cfg.proxy_auth.as_ref().unwrap().username, "u");

        // A config without the section parses to None
        std::fs::write(&path, "name = \"n1\"\n").unwrap();
        assert!(load_client_role_config(path.to_str().unwrap()).unwrap().is_none());

        // Missing file is not an error
        let missing = dir.join("nope.toml");
        assert!(load_client_role_config(missing.to_str().unwrap()).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Embedded run: local proxy starts on a dynamic port and the status slot is published
    #[tokio::test]
    async fn run_starts_proxy_and_publishes_slot() {
        let engine = AgileNetClient::new();
        let slot = crate::service::new_client_proxy_slot();
        let cfg = ClientRoleConfig {
            nodes: Vec::new(),
            proxy_port: 0, // dynamic
            proxy_auth: None,
            manage_hosts: false,
        };
        run(&engine, &cfg, &slot).await;
        assert!(engine.proxy_port() > 0);
        let info = slot.load().as_ref().clone().expect("slot published");
        assert!(info.enabled);
        assert_eq!(info.listen, format!("127.0.0.1:{}", engine.proxy_port()));
        engine.stop_proxy().await;
    }
}
