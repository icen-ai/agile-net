//! AgileNet Client 核心功能模块实现

use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};

use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeStatus {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectParams {
    pub addr: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRule {
    pub pattern: String,
    pub pattern_type: String,
    pub outbound_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node_id: String,
    pub addr: String,
    pub status: NodeStatus,
    pub rules: Vec<ClientRule>,
    pub access_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub addr: String,
    pub username: String,
    pub password: String,
}

pub struct CredentialStore {
    path: PathBuf,
    credentials: DashMap<String, Credential>,
}

impl CredentialStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let store = Self {
            path: path.clone(),
            credentials: DashMap::new(),
        };
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, Credential>>(&data) {
                for (k, v) in map {
                    store.credentials.insert(k, v);
                }
            }
        }
        Ok(store)
    }

    pub fn open_temp() -> Result<Self> {
        let temp = std::env::temp_dir().join(format!("agile-net-cred-{}.json", uuid::Uuid::new_v4()));
        Self::open(temp)
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub async fn save(&self, key: &str, cred: &Credential) {
        self.credentials.insert(key.to_string(), cred.clone());
        let map: std::collections::HashMap<String, Credential> =
            self.credentials.iter().map(|r| (r.key().clone(), r.value().clone())).collect();
        if let Ok(data) = serde_json::to_string_pretty(&map) {
            let _ = std::fs::write(&self.path, data);
        }
    }

    pub async fn get(&self, key: &str) -> Option<Credential> {
        self.credentials.get(key).map(|r| r.value().clone())
    }
}

pub struct AgileNetClient {
    nodes: DashMap<String, NodeState>,
    shared_router: Arc<ArcSwap<ProxyRouter>>,
    proxy_port: ArcSwap<u16>,
    http_client: reqwest::Client,
    inbound_shutdown_tx: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl AgileNetClient {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
            shared_router: Arc::new(ArcSwap::from_pointee(ProxyRouter::new())),
            proxy_port: ArcSwap::from_pointee(0),
            http_client: reqwest::Client::new(),
            inbound_shutdown_tx: tokio::sync::Mutex::new(None),
        }
    }

    pub fn proxy_router(&self) -> Arc<ProxyRouter> {
        self.shared_router.load_full()
    }

    pub fn proxy_port(&self) -> u16 {
        **self.proxy_port.load()
    }

    pub async fn connect(&self, params: ConnectParams) -> Result<NodeState> {
        let base_url = if params.addr.starts_with("http://") || params.addr.starts_with("https://") {
            params.addr.clone()
        } else {
            format!("http://{}", params.addr)
        };

        let login_url = format!("{base_url}/api/v1/auth/login");
        let login_body = serde_json::json!({
            "username": params.username,
            "password": params.password,
        });

        let resp = self.http_client.post(&login_url).json(&login_body).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Login failed with status {}", resp.status()));
        }

        let login_json: serde_json::Value = resp.json().await?;
        let token = login_json["token"]
            .as_str()
            .ok_or_else(|| anyhow!("Invalid token in login response"))?
            .to_string();

        let node_id = format!("node-{}", uuid::Uuid::new_v4());

        // 拉取配置与路由规则
        let routes_url = format!("{base_url}/api/v1/routes");
        let mut client_rules = Vec::new();
        if let Ok(routes_resp) = self.http_client.get(&routes_url).bearer_auth(&token).send().await {
            if routes_resp.status().is_success() {
                if let Ok(routes_val) = routes_resp.json::<serde_json::Value>().await {
                    if let Some(arr) = routes_val.as_array() {
                        for r in arr {
                            if let (Some(pat), Some(ptype), Some(otype)) = (
                                r["pattern"].as_str(),
                                r["pattern_type"].as_str(),
                                r["outbound_type"].as_str(),
                            ) {
                                client_rules.push(ClientRule {
                                    pattern: pat.to_string(),
                                    pattern_type: ptype.to_string(),
                                    outbound_type: otype.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        let state = NodeState {
            node_id: node_id.clone(),
            addr: params.addr,
            status: NodeStatus::Connected,
            rules: client_rules,
            access_token: token,
        };

        self.nodes.insert(node_id.clone(), state.clone());
        self.rebuild_merged_router();

        Ok(state)
    }

    pub async fn disconnect(&self, node_id: &str) {
        if self.nodes.remove(node_id).is_some() {
            self.rebuild_merged_router();
        }
    }

    pub async fn get_node(&self, node_id: &str) -> Option<NodeState> {
        self.nodes.get(node_id).map(|r| r.value().clone())
    }

    pub fn node_status(&self, node_id: &str) -> NodeStatus {
        self.nodes.get(node_id).map(|r| r.status.clone()).unwrap_or(NodeStatus::Disconnected)
    }

    pub fn set_node_status(&self, node_id: &str, status: NodeStatus) {
        if let Some(mut n) = self.nodes.get_mut(node_id) {
            n.status = status;
        }
    }

    pub fn rebuild_merged_router(&self) {
        let mut new_router = ProxyRouter::new();
        for item in self.nodes.iter() {
            let state = item.value();
            if state.status != NodeStatus::Connected {
                continue;
            }
            for rule in &state.rules {
                let outbound = if rule.outbound_type == "tunnel" {
                    Outbound::tunnel(state.node_id.clone())
                } else {
                    Outbound::Direct
                };

                match rule.pattern_type.as_str() {
                    "cidr" => {
                        let _ = new_router.add_cidr(&rule.pattern, outbound);
                    }
                    "exact_host" | "exact" => {
                        new_router.add_host_exact(&rule.pattern, outbound);
                    }
                    "wildcard_host" | "suffix" | "wildcard" => {
                        new_router.add_host_suffix(&rule.pattern, outbound);
                    }
                    _ => {}
                }
            }
        }
        self.shared_router.store(Arc::new(new_router));
    }

    pub async fn start_proxy(&self, port: u16) -> Result<()> {
        let listen_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        let actual_addr = listener.local_addr()?;
        let actual_port = actual_addr.port();
        drop(listener);
        self.proxy_port.store(Arc::new(actual_port));

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        *self.inbound_shutdown_tx.lock().await = Some(tx);

        let inbound = ProxyInbound::new(actual_addr, self.shared_router.clone());

        tokio::spawn(async move {
            tokio::select! {
                _ = inbound.start() => {},
                _ = rx => {},
            }
        });

        Ok(())
    }

    pub async fn stop_proxy(&self) {
        if let Some(tx) = self.inbound_shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        self.proxy_port.store(Arc::new(0));
    }
}

impl Default for AgileNetClient {
    fn default() -> Self {
        Self::new()
    }
}
