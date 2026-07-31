//! AgileNet Client 核心引擎
//!
//! 完整数据面实现：
//! 1. 登录节点 API（access + refresh + tunnel_token）
//! 2. 拉取路由配置并建立 ClientTunnel（TLS 1.3 + tunnel_token 数据面认证）
//! 3. 多节点路由合并 + 本地 SOCKS5/HTTP 代理入站
//! 4. 长轮询配置热更新 + 心跳上报 + 断线自动重连
//! 5. resolve 规则自动维护系统 hosts（可选）

use agile_net_core::proxy::inbound::ProxyInbound;
use agile_net_core::proxy::router::{Outbound, ProxyRouter};
use agile_net_core::tunnel::client_tunnel::ClientTunnel;
use agile_net_core::tunnel::opener::ChannelOpener;
use agile_net_core::tunnel::tls::TlsConfigBuilder;

use anyhow::{Context as _, Result, anyhow};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeStatus {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectParams {
    /// 节点 API 地址（host:port 或 http(s)://...）
    pub addr: String,
    pub username: String,
    pub password: String,
    /// 跳过 TLS 证书校验（仅开发调试）
    #[serde(default)]
    pub insecure: bool,
    /// 证书固定：节点证书 PEM 路径（生产推荐）
    #[serde(default)]
    pub pinned_cert_path: Option<String>,
    /// 是否自动维护系统 hosts（resolve 规则）
    #[serde(default)]
    pub manage_hosts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRule {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub value: String,
    #[serde(default)]
    pub resolve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node_id: String,
    pub addr: String,
    pub node_name: String,
    pub status: NodeStatus,
    pub rules: Vec<ClientRule>,
    pub config_version: u64,
}

/// 单个节点连接的运行时句柄。
struct NodeHandle {
    state: NodeState,
    tunnel: Arc<ClientTunnel>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    manage_hosts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub addr: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub insecure: bool,
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
            if let Ok(map) =
                serde_json::from_str::<std::collections::HashMap<String, Credential>>(&data)
            {
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

    /// 默认存储路径（~/.agile-net/credentials.json）
    pub fn open_default() -> Result<Self> {
        let dir = home_dir().join(".agile-net");
        std::fs::create_dir_all(&dir)?;
        Self::open(dir.join("credentials.json"))
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub async fn save(&self, key: &str, cred: &Credential) {
        self.credentials.insert(key.to_string(), cred.clone());
        self.persist();
    }

    pub async fn get(&self, key: &str) -> Option<Credential> {
        self.credentials.get(key).map(|r| r.value().clone())
    }

    pub async fn remove(&self, key: &str) {
        self.credentials.remove(key);
        self.persist();
    }

    pub async fn keys(&self) -> Vec<String> {
        self.credentials.iter().map(|r| r.key().clone()).collect()
    }

    fn persist(&self) {
        let map: std::collections::HashMap<String, Credential> = self
            .credentials
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();
        if let Ok(data) = serde_json::to_string_pretty(&map) {
            let _ = std::fs::write(&self.path, data);
            // 凭据文件权限收紧（Unix 0600）
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

fn home_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

// ==================== 客户端引擎 ====================

/// 共享内部状态（后台任务通过 Arc 安全访问）。
struct ClientInner {
    nodes: DashMap<String, NodeHandle>,
    shared_router: Arc<ArcSwap<ProxyRouter>>,
    proxy_port: ArcSwap<u16>,
    http_client: reqwest::Client,
    inbound_shutdown_tx: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>,
    hosts_manager: HostsManager,
    /// 代理入站统计（代理启动后可用）
    proxy_stats: Arc<arc_swap::ArcSwapOption<agile_net_core::proxy::inbound::ProxyStats>>,
}

impl ClientInner {
    /// 合并全部已连接节点的路由规则。
    fn rebuild_merged_router(&self) {
        let mut new_router = ProxyRouter::new();
        for item in self.nodes.iter() {
            let state = &item.value().state;
            if state.status != NodeStatus::Connected {
                continue;
            }
            for rule in &state.rules {
                let outbound = Outbound::tunnel(state.node_id.clone());
                match rule.rule_type.as_str() {
                    "ip-cidr" => {
                        let _ = new_router.add_cidr(&rule.value, outbound);
                    }
                    "host" => {
                        if rule.value.contains('*') {
                            new_router.add_host_suffix(&rule.value, outbound);
                        } else {
                            new_router.add_host_exact(&rule.value, outbound);
                        }
                    }
                    _ => {}
                }
            }
        }
        self.shared_router.store(Arc::new(new_router));
        self.apply_hosts();
    }

    /// 维护系统 hosts（连接参数中 manage_hosts=true 的节点的 resolve 规则）。
    fn apply_hosts(&self) {
        let mut hosts = Vec::new();
        let mut any_managed = false;
        for item in self.nodes.iter() {
            let handle = item.value();
            if !handle.manage_hosts {
                continue;
            }
            any_managed = true;
            let state = &handle.state;
            if state.status != NodeStatus::Connected {
                continue;
            }
            for rule in &state.rules {
                if rule.rule_type == "host" && rule.resolve && !rule.value.contains('*') {
                    hosts.push(rule.value.clone());
                }
            }
        }
        if !any_managed {
            return;
        }
        if let Err(e) = self.hosts_manager.apply(&hosts) {
            warn!(error = %e, "failed to update system hosts (need admin/root?)");
        }
    }
}

#[derive(Clone)]
pub struct AgileNetClient {
    inner: Arc<ClientInner>,
}

impl AgileNetClient {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ClientInner {
                nodes: DashMap::new(),
                shared_router: Arc::new(ArcSwap::from_pointee(ProxyRouter::new())),
                proxy_port: ArcSwap::from_pointee(0),
                http_client: reqwest::Client::new(),
                inbound_shutdown_tx: tokio::sync::Mutex::new(None),
                openers: Arc::new(DashMap::new()),
                hosts_manager: HostsManager::new(),
                proxy_stats: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
            }),
        }
    }

    pub fn proxy_router(&self) -> Arc<ProxyRouter> {
        self.inner.shared_router.load_full()
    }

    pub fn proxy_port(&self) -> u16 {
        **self.inner.proxy_port.load()
    }

    pub fn node_count(&self) -> usize {
        self.inner.nodes.len()
    }

    /// 连接节点：登录 → 拉取配置 → 建立隧道 → 合并路由 → 后台维护任务。
    pub async fn connect(&self, params: ConnectParams) -> Result<NodeState> {
        let base_url = api_base_url(&params.addr);

        // 1. 登录
        let resp = self
            .inner
            .http_client
            .post(format!("{base_url}/api/v1/auth/login"))
            .json(&serde_json::json!({
                "username": params.username,
                "password": params.password,
            }))
            .send()
            .await
            .context("login request failed")?;
        if !resp.status().is_success() {
            return Err(anyhow!("login failed: HTTP {}", resp.status()));
        }
        let login_json: serde_json::Value = resp.json().await?;
        let data = &login_json["data"];
        let access_token = data["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("missing access_token"))?
            .to_string();
        let refresh_token = data["refresh_token"]
            .as_str()
            .ok_or_else(|| anyhow!("missing refresh_token"))?
            .to_string();
        let tunnel_token = data["tunnel_token"]
            .as_str()
            .ok_or_else(|| anyhow!("missing tunnel_token (not a client account?)"))?
            .to_string();

        // 2. 拉取配置
        let config = pull_config(&self.inner.http_client, &base_url, &access_token, 0).await?;
        let node_name = config["node_name"].as_str().unwrap_or("node").to_string();
        let tunnel_server = config["tunnel"]["server"].as_str().unwrap_or("").to_string();
        let tunnel_port = config["tunnel"]["port"].as_u64().unwrap_or(443) as u16;
        let version = config["version"].as_u64().unwrap_or(0);
        let rules = parse_rules(&config);

        // 3. 建立数据面隧道
        let tunnel_addr: SocketAddr = resolve_addr(&tunnel_server, tunnel_port).await?;
        let tls_builder = build_tls(&params)?;
        let account_id = claims_sub(&access_token).unwrap_or_else(|| params.username.clone());
        let tunnel = Arc::new(ClientTunnel::with_tls_builder(
            tunnel_addr,
            account_id,
            tunnel_token,
            tls_builder,
        )?);
        tunnel.connect().await?;

        // 节点唯一键：node_name@addr
        let node_id = format!("{node_name}@{}", params.addr);

        // 注册通道开启器
        self.inner
            .openers
            .insert(node_id.clone(), tunnel.clone() as Arc<dyn ChannelOpener>);

        let state = NodeState {
            node_id: node_id.clone(),
            addr: params.addr.clone(),
            node_name: node_name.clone(),
            status: NodeStatus::Connected,
            rules,
            config_version: version,
        };

        // 4. 后台任务：隧道自动重连 + 心跳 + 配置长轮询
        let mut tasks = Vec::new();
        {
            let t = tunnel.clone();
            tasks.push(tokio::spawn(async move {
                t.run().await;
            }));
        }
        tasks.push(spawn_heartbeat(
            self.inner.http_client.clone(),
            self.inner.proxy_stats.clone(),
            node_id.clone(),
            base_url.clone(),
            access_token.clone(),
        ));
        tasks.push(spawn_config_watcher(
            self.inner.clone(),
            node_id.clone(),
            base_url.clone(),
            access_token.clone(),
            refresh_token.clone(),
            version,
        ));

        let handle = NodeHandle {
            state: state.clone(),
            tunnel,
            tasks,
            manage_hosts: params.manage_hosts,
        };
        self.inner.nodes.insert(node_id.clone(), handle);
        self.inner.rebuild_merged_router();

        info!(node = %node_id, "node connected");
        Ok(state)
    }

    /// 断开节点：停止任务、断开隧道、移除路由与 hosts。
    pub async fn disconnect(&self, node_id: &str) {
        if let Some((_, handle)) = self.inner.nodes.remove(node_id) {
            for t in &handle.tasks {
                t.abort();
            }
            handle.tunnel.disconnect().await;
            self.inner.openers.remove(node_id);
            self.inner.rebuild_merged_router();
            info!(node = %node_id, "node disconnected");
        }
    }

    pub async fn disconnect_all(&self) {
        let ids: Vec<String> = self.inner.nodes.iter().map(|r| r.key().clone()).collect();
        for id in ids {
            self.disconnect(&id).await;
        }
        self.inner.hosts_manager.cleanup();
    }

    pub async fn get_node(&self, node_id: &str) -> Option<NodeState> {
        self.inner.nodes.get(node_id).map(|r| r.state.clone())
    }

    pub async fn list_nodes(&self) -> Vec<NodeState> {
        self.inner.nodes.iter().map(|r| r.state.clone()).collect()
    }

    pub fn node_status(&self, node_id: &str) -> NodeStatus {
        self.inner
            .nodes
            .get(node_id)
            .map(|r| {
                if r.tunnel.is_connected() {
                    NodeStatus::Connected
                } else {
                    match r.tunnel.state() {
                        agile_net_core::relay::ConnectionState::Reconnecting => NodeStatus::Reconnecting,
                        agile_net_core::relay::ConnectionState::Connecting => NodeStatus::Connecting,
                        _ => NodeStatus::Disconnected,
                    }
                }
            })
            .unwrap_or(NodeStatus::Disconnected)
    }

    pub fn set_node_status(&self, node_id: &str, status: NodeStatus) {
        if let Some(mut n) = self.inner.nodes.get_mut(node_id) {
            n.state.status = status;
        }
    }

    /// 重建合并路由表（供外部/测试调用）。
    pub fn rebuild_merged_router(&self) {
        self.inner.rebuild_merged_router();
    }

    /// 启动本地代理入站（127.0.0.1）。
    pub async fn start_proxy(&self, port: u16) -> Result<()> {
        self.start_proxy_with_auth(port, None).await
    }

    /// 启动本地代理入站（可选认证）。
    pub async fn start_proxy_with_auth(
        &self,
        port: u16,
        auth: Option<(String, String)>,
    ) -> Result<()> {
        let listen_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        // 入站与引擎共用同一张开启器注册表（节点上下线即时生效）
        let mut inbound = ProxyInbound::new(listen_addr, self.inner.shared_router.clone())
            .with_openers_map(self.inner.openers.clone());
        if let Some((u, p)) = auth {
            inbound = inbound.with_auth(u, p);
        }

        // 先绑定拿到实际端口（支持 port=0），再交给 inbound（消除启动竞态）
        let bound = tokio::net::TcpListener::bind(listen_addr).await?;
        let actual_port = bound.local_addr()?.port();
        self.inner.proxy_port.store(Arc::new(actual_port));

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        *self.inner.inbound_shutdown_tx.lock().await = Some(tx);

        let inbound = Arc::new(inbound);
        self.inner.proxy_stats.store(Some(inbound.stats()));
        tokio::spawn(async move {
            tokio::select! {
                _ = inbound.start_on(bound) => {},
                _ = rx => {},
            }
        });

        Ok(())
    }

    pub async fn stop_proxy(&self) {
        if let Some(tx) = self.inner.inbound_shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        self.inner.proxy_stats.store(None);
        self.inner.proxy_port.store(Arc::new(0));
    }
}

impl Default for AgileNetClient {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== 后台任务 ====================

async fn pull_config(
    http: &reqwest::Client,
    base_url: &str,
    access_token: &str,
    current_version: u64,
) -> Result<serde_json::Value> {
    let url = if current_version > 0 {
        format!("{base_url}/api/v1/client/config?version={current_version}")
    } else {
        format!("{base_url}/api/v1/client/config")
    };
    let resp = http.get(&url).bearer_auth(access_token).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!("config pull failed: HTTP {}", resp.status()));
    }
    let json: serde_json::Value = resp.json().await?;
    Ok(json["data"].clone())
}

fn spawn_heartbeat(
    http: reqwest::Client,
    stats_slot: Arc<arc_swap::ArcSwapOption<agile_net_core::proxy::inbound::ProxyStats>>,
    node_id: String,
    base_url: String,
    access_token: String,
) -> tokio::task::JoinHandle<()> {
    let started = std::time::Instant::now();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_tx: u64 = 0;
        let mut last_rx: u64 = 0;
        loop {
            interval.tick().await;

            // 真实流量统计（增量：自上次上报以来）
            let (delta_tx, delta_rx, active) = match stats_slot.load().as_ref() {
                Some(stats) => {
                    let tx = stats.bytes_up.load(std::sync::atomic::Ordering::Relaxed);
                    let rx = stats.bytes_down.load(std::sync::atomic::Ordering::Relaxed);
                    let active = stats.active_connections.load(std::sync::atomic::Ordering::Relaxed);
                    let d_tx = tx.saturating_sub(last_tx);
                    let d_rx = rx.saturating_sub(last_rx);
                    last_tx = tx;
                    last_rx = rx;
                    (d_tx as i64, d_rx as i64, active as i64)
                }
                None => (0, 0, 0),
            };

            let body = serde_json::json!({
                "uptime": started.elapsed().as_secs(),
                "bytes_tx": delta_tx,
                "bytes_rx": delta_rx,
                "active_connections": active,
            });
            let resp = http
                .post(format!("{base_url}/api/v1/client/heartbeat"))
                .bearer_auth(&access_token)
                .json(&body)
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    if let Ok(json) = r.json::<serde_json::Value>().await
                        && json["data"]["force_disconnect"].as_bool() == Some(true)
                    {
                        info!(node = %node_id, "force disconnected by server");
                        break;
                    }
                }
                Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    debug!(node = %node_id, "heartbeat unauthorized (token rotated by watcher)");
                }
                _ => {}
            }
        }
    })
}

fn spawn_config_watcher(
    inner: Arc<ClientInner>,
    node_id: String,
    base_url: String,
    access_token: String,
    refresh_token: String,
    initial_version: u64,
) -> tokio::task::JoinHandle<()> {
    let http = inner.http_client.clone();
    tokio::spawn(async move {
        let mut version = initial_version;
        let mut access = access_token;
        let mut refresh = refresh_token;
        loop {
            // 长轮询等待新版本
            let url = format!("{base_url}/api/v1/client/config?wait=true&version={version}");
            let resp = http.get(&url).bearer_auth(&access).send().await;

            let resp = match resp {
                Ok(r) => r,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
                continue;
            }
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                // 刷新 token
                let refresh_resp = http
                    .post(format!("{base_url}/api/v1/auth/refresh"))
                    .json(&serde_json::json!({ "refresh_token": refresh }))
                    .send()
                    .await;
                match refresh_resp {
                    Ok(r) if r.status().is_success() => {
                        if let Ok(json) = r.json::<serde_json::Value>().await {
                            access = json["data"]["access_token"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string();
                            refresh = json["data"]["refresh_token"]
                                .as_str()
                                .unwrap_or(refresh.as_str())
                                .to_string();
                        }
                    }
                    _ => {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                }
                continue;
            }
            if !resp.status().is_success() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let data = &json["data"];
                let new_version = data["version"].as_u64().unwrap_or(version);
                let rules = parse_rules(data);
                version = new_version;
                info!(node = %node_id, version, "config updated");

                if let Some(mut h) = inner.nodes.get_mut(&node_id) {
                    h.state.rules = rules;
                    h.state.config_version = version;
                }
                inner.rebuild_merged_router();
            }
        }
    })
}

// ==================== 辅助函数 ====================

fn api_base_url(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.trim_end_matches('/').to_string()
    } else {
        format!("http://{}", addr.trim_end_matches('/'))
    }
}

fn parse_rules(config: &serde_json::Value) -> Vec<ClientRule> {
    config["rules"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    Some(ClientRule {
                        id: r["id"].as_str().unwrap_or_default().to_string(),
                        rule_type: r["type"].as_str()?.to_string(),
                        value: r["value"].as_str()?.to_string(),
                        resolve: r["resolve"].as_bool().unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn build_tls(params: &ConnectParams) -> Result<TlsConfigBuilder> {
    let builder = TlsConfigBuilder::new();
    if let Some(pinned_path) = &params.pinned_cert_path {
        let data = std::fs::read(pinned_path)?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut data.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("parse pinned cert: {e}"))?;
        if certs.is_empty() {
            return Err(anyhow!("no certificates in pinned cert file"));
        }
        Ok(builder.pinned_certs(certs))
    } else if params.insecure {
        Ok(builder.allow_self_signed(true))
    } else {
        Ok(builder)
    }
}

async fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    let direct = format!("{host}:{port}");
    if let Ok(a) = direct.parse::<SocketAddr>() {
        return Ok(a);
    }
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(&direct).await?.collect();
    // IPv4 优先（规避双栈环境中 IPv6 不可达的连接失败）
    resolved
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| resolved.first())
        .copied()
        .ok_or_else(|| anyhow!("cannot resolve tunnel server: {direct}"))
}

/// 从 JWT 中提取 sub（不验签，仅用于本地标识）。
fn claims_sub(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64_url_decode(payload)?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json["sub"].as_str().map(|s| s.to_string())
}

fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table_map = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        table_map[c as usize] = i as u8;
    }
    table_map[b'-' as usize] = 62;
    table_map[b'_' as usize] = 63;

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut nbits = 0u32;
    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let v = table_map[b as usize];
        if v == 255 {
            return None;
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

// ==================== Hosts 管理 ====================

/// 系统 hosts 文件管理（BEGIN/END AGILE-NET 标记块）。
pub struct HostsManager {
    path: PathBuf,
}

impl HostsManager {
    pub fn new() -> Self {
        let path = if cfg!(windows) {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            PathBuf::from(root)
                .join("System32")
                .join("drivers")
                .join("etc")
                .join("hosts")
        } else {
            PathBuf::from("/etc/hosts")
        };
        Self { path }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// 写入托管 hosts（127.0.0.1 指向，流量经本地代理转发）。
    pub fn apply(&self, hosts: &[String]) -> Result<()> {
        let content = std::fs::read_to_string(&self.path).unwrap_or_default();
        let cleaned = strip_managed_block(&content);

        if hosts.is_empty() {
            if cleaned != content {
                std::fs::write(&self.path, cleaned)?;
            }
            return Ok(());
        }

        let mut block = String::from("# BEGIN AGILE-NET\n");
        for h in hosts {
            block.push_str(&format!("127.0.0.1 {h}\n"));
        }
        block.push_str("# END AGILE-NET\n");

        let mut new_content = cleaned;
        if !new_content.ends_with('\n') && !new_content.is_empty() {
            new_content.push('\n');
        }
        new_content.push_str(&block);
        std::fs::write(&self.path, new_content)?;
        Ok(())
    }

    /// 清理全部托管条目。
    pub fn cleanup(&self) {
        if let Ok(content) = std::fs::read_to_string(&self.path) {
            let cleaned = strip_managed_block(&content);
            if cleaned != content {
                let _ = std::fs::write(&self.path, cleaned);
            }
        }
    }
}

impl Default for HostsManager {
    fn default() -> Self {
        Self::new()
    }
}

fn strip_managed_block(content: &str) -> String {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "# BEGIN AGILE-NET" {
            in_block = true;
            continue;
        }
        if trimmed == "# END AGILE-NET" {
            in_block = false;
            continue;
        }
        if !in_block {
            out.push(line);
        }
    }
    let mut s = out.join("\n");
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s
}
