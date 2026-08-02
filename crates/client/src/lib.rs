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

use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod api;
pub mod daemon;

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
    /// 证书指纹固定：节点证书 SHA-256（connect_url 一键分发，抗 MITM）
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
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

// ==================== 自定义规则（GUI：放行 / hosts 映射） ====================

pub use agile_net_core::proxy::router::wildcard_match;

/// 自定义放行规则（通配；评估优先于合并路由与回落，语义见 wildcard_match）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomBypassRule {
    pub pattern: String,
    /// 命中后经订阅内核（回落上游）而非直连；订阅未接管回落时退化为直连
    #[serde(default)]
    pub via_subscription: bool,
}

/// 自定义规则快照（引擎热更；GUI 计算「单条启停 ∪ 启用组合成员」后整体下发，
/// 引擎只消费生效集合，不感知组合与启停来源）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomRules {
    #[serde(default)]
    pub bypass: Vec<CustomBypassRule>,
    /// hosts 映射（hostname → IP 字符串；命中先改写解析目标再路由与拨号）
    #[serde(default)]
    pub hosts: Vec<(String, String)>,
}

/// 把自定义规则烘焙进路由表自定义层（rebuild_merged_router 决策点调用；独立函数便于单测）。
fn apply_custom_rules(
    router: &mut ProxyRouter,
    custom: &CustomRules,
    fallback: Option<SocketAddr>,
) {
    if !custom.hosts.is_empty() {
        let map: std::collections::HashMap<String, std::net::IpAddr> = custom
            .hosts
            .iter()
            .filter_map(|(h, ip)| ip.parse().ok().map(|addr| (h.to_lowercase(), addr)))
            .collect();
        router.set_hosts_map(map);
    }
    for b in &custom.bypass {
        let outbound = if b.via_subscription {
            fallback.map(Outbound::forward).unwrap_or(Outbound::Direct)
        } else {
            Outbound::Direct
        };
        router.add_custom_bypass(&b.pattern, outbound);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node_id: String,
    pub addr: String,
    pub node_name: String,
    /// 登录账号（端点列表展示「端点名称 · 用户名」）
    #[serde(default)]
    pub username: String,
    pub status: NodeStatus,
    pub rules: Vec<ClientRule>,
    pub config_version: u64,
    /// 该账号被授予「管理此节点」权限（管理版接入链接）
    #[serde(default)]
    pub admin_console: bool,
    /// 可管理上游（握手 v2 自动发现；仅管理版账号下发）
    #[serde(default)]
    pub manageable: Vec<ManageableNode>,
    /// 隧道流量：上行字节（发往节点；当前会话计数，重连归零，未连接为 0）
    #[serde(default)]
    pub bytes_up: u64,
    /// 隧道流量：下行字节（来自节点；当前会话计数，重连归零，未连接为 0）
    #[serde(default)]
    pub bytes_down: u64,
}

/// 可管理节点（本机/已连节点/上游链自动发现）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManageableNode {
    pub node_name: String,
    /// 管理 API 端点（host:port，经隧道可达）
    pub api: String,
    /// 管理授权档位：ro / rules / full
    #[serde(default = "default_manageable_scope")]
    pub scope: String,
    /// 发现路径：relay（上游链）
    #[serde(default)]
    pub via: String,
}

fn default_manageable_scope() -> String {
    "full".into()
}

/// 单个节点连接的运行时句柄。
struct NodeHandle {
    state: NodeState,
    tunnel: Arc<ClientTunnel>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    manage_hosts: bool,
    /// 原始连接参数（断网降级后重试登录用）
    params: ConnectParams,
    /// 当前 access token（配置长轮询刷新后同步；控制台票据签发用）
    access_token: Arc<ArcSwap<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub addr: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
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
        let temp =
            std::env::temp_dir().join(format!("agile-net-cred-{}.json", uuid::Uuid::new_v4()));
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
                let _ =
                    std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
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

// ==================== 接入链接（agilenet://connect?...） ====================

/// 解析后的接入参数（桌面 IPC 与 Web REST 共用同一形状）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedConnect {
    pub addr: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub pinned_cert_path: Option<String>,
    #[serde(default)]
    pub pinned_fingerprint: Option<String>,
    #[serde(default)]
    pub manage_hosts: bool,
    /// 连接成功后是否保存凭据
    #[serde(default)]
    pub save_credential: bool,
    /// 管理版接入链接标记（admin=1：持链接者可管理该节点，导入时强警示）
    #[serde(default)]
    pub admin: Option<String>,
}

/// 解析 agilenet://connect?... 接入链接。
pub fn parse_connect_url(url: &str) -> std::result::Result<ParsedConnect, String> {
    let rest = url
        .strip_prefix("agilenet://connect?")
        .ok_or_else(|| "无效的接入链接前缀".to_string())?;
    let mut server = String::new();
    let mut port: Option<u16> = None;
    let mut account = String::new();
    let mut password = String::new();
    let mut fp: Option<String> = None;
    let mut insecure = false;
    let mut admin: Option<String> = None;
    for pair in rest.split('&') {
        let mut kv = pair.splitn(2, '=');
        let (k, v) = (kv.next().unwrap_or(""), kv.next().unwrap_or(""));
        let v = url_decode(v);
        match k {
            "server" => server = v,
            "port" => port = v.parse().ok(),
            "account" => account = v,
            "password" => password = v,
            "fp" => fp = Some(v),
            "insecure" => insecure = v == "1" || v.eq_ignore_ascii_case("true"),
            "admin" => admin = Some(v),
            _ => {}
        }
    }
    if server.is_empty() || account.is_empty() || password.is_empty() {
        return Err("接入链接缺少必要参数 (server/account/password)".into());
    }
    // server 未含端口时用 port 参数补全
    let addr = if server.contains(':') {
        server
    } else {
        format!("{}:{}", server, port.unwrap_or(59090))
    };
    Ok(ParsedConnect {
        addr,
        username: account,
        password,
        insecure,
        pinned_cert_path: None,
        pinned_fingerprint: fp,
        manage_hosts: false,
        save_credential: true,
        admin,
    })
}

/// 由已保存凭据生成 agilenet://connect 接入链接（含明文密码，谨慎分享）。
pub fn connect_url_of(c: &Credential) -> String {
    let stripped = c
        .addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let (host, port) = match stripped.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.to_string()),
        _ => (stripped.to_string(), "59090".to_string()),
    };
    let mut url = format!(
        "agilenet://connect?server={host}&port={port}&account={}&password={}",
        c.username, c.password
    );
    if let Some(fp) = &c.pinned_fingerprint {
        url.push_str(&format!("&tls=1&fp={fp}"));
    }
    if c.insecure {
        url.push_str("&insecure=1");
    }
    url
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

// ==================== 配置离线缓存 ====================

/// 节点配置缓存（断网沿用旧规则：docs/architecture/config-file.md 承诺）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedNodeConfig {
    pub addr: String,
    pub username: String,
    pub node_name: String,
    pub rules: Vec<ClientRule>,
    pub config_version: u64,
    pub tunnel_server: String,
    pub tunnel_port: u16,
    pub tunnel_token: String,
    pub refresh_token: String,
    pub insecure: bool,
    pub pinned_fingerprint: Option<String>,
    pub updated_at: String,
}

/// 缓存目录（~/.agile-net/cache/），文件权限 0600。
pub struct ConfigCache {
    dir: PathBuf,
}

impl ConfigCache {
    pub fn new() -> Result<Self> {
        let dir = home_dir().join(".agile-net").join("cache");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// 指定缓存目录（主要用于测试与降级兜底）
    pub fn with_dir(dir: PathBuf) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn key_for(addr: &str, username: &str) -> String {
        let raw = format!("{addr}|{username}");
        raw.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn path_for(&self, addr: &str, username: &str) -> PathBuf {
        self.dir
            .join(format!("{}.json", Self::key_for(addr, username)))
    }

    pub fn save(&self, cfg: &CachedNodeConfig) {
        let path = self.path_for(&cfg.addr, &cfg.username);
        if let Ok(data) = serde_json::to_string_pretty(cfg) {
            let _ = std::fs::write(&path, data);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }

    pub fn load(&self, addr: &str, username: &str) -> Option<CachedNodeConfig> {
        let path = self.path_for(addr, username);
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    pub fn remove(&self, addr: &str, username: &str) {
        let _ = std::fs::remove_file(self.path_for(addr, username));
    }
}

impl Default for ConfigCache {
    fn default() -> Self {
        Self::new().expect("create config cache dir")
    }
}

// ==================== 客户端引擎 ====================

/// 共享内部状态（后台任务通过 Arc 安全访问）。
struct ClientInner {
    nodes: DashMap<String, NodeHandle>,
    /// 节点连接顺序（路由冲突按先连优先）
    node_order: std::sync::Mutex<Vec<String>>,
    shared_router: Arc<ArcSwap<ProxyRouter>>,
    proxy_port: ArcSwap<u16>,
    http_client: reqwest::Client,
    inbound_shutdown_tx: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    openers: Arc<DashMap<String, Arc<dyn ChannelOpener>>>,
    hosts_manager: HostsManager,
    /// 代理入站统计（代理启动后可用）
    proxy_stats: Arc<arc_swap::ArcSwapOption<agile_net_core::proxy::inbound::ProxyStats>>,
    /// 节点配置离线缓存
    cache: Arc<ConfigCache>,
    /// 用户暂停的规则（node_id → "type:value" 小写集合），重建合并路由时跳过
    paused_rules: DashMap<String, std::collections::HashSet<String>>,
    /// 代理回落上游（订阅内核 mixed 入站；None = 未命中规则直连）
    proxy_fallback: arc_swap::ArcSwapOption<SocketAddr>,
    /// 自定义规则（GUI 放行/hosts 映射；ArcSwap 热更，rebuild 时烘焙进路由自定义层）
    custom_rules: ArcSwap<CustomRules>,
}

impl ClientInner {
    /// 合并全部已连接节点的路由规则。
    ///
    /// 冲突语义（确定性）：按节点连接顺序，**先连优先**——
    /// 相同 CIDR/域名模式以先连接的节点为准（标准最长前缀匹配仍优先于顺序）。
    fn rebuild_merged_router(&self) {
        let mut new_router = ProxyRouter::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        let order = self
            .node_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for node_id in &order {
            let Some(item) = self.nodes.get(node_id) else {
                continue;
            };
            let state = &item.value().state;
            if state.status != NodeStatus::Connected {
                continue;
            }
            let paused = self.paused_rules.get(node_id);
            for rule in &state.rules {
                let key = format!("{}:{}", rule.rule_type, rule.value.to_lowercase());
                if paused.as_ref().is_some_and(|s| s.contains(&key)) {
                    continue; // 用户已暂停：不占用冲突位次，允许其他节点同名规则接管
                }
                if !seen.insert(key) {
                    continue; // 冲突：后连节点让位于先连节点
                }
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
            // 管理面隐式路由：可管理上游 API 端点经该节点隧道可达
            // （ACL 统一：收回权限即失去管理通路；冲突位次与显式规则一致，先连优先）
            if state.admin_console {
                add_manageable_routes(
                    &mut new_router,
                    &state.node_id,
                    &state.manageable,
                    &mut seen,
                );
            }
        }
        // 回落上游（订阅内核）：未命中任何规则的流量转发至 loopback 上游代理
        if let Some(addr) = self.proxy_fallback.load().as_ref() {
            new_router.set_default(Outbound::forward(**addr));
        }
        // 自定义规则层（放行/hosts 映射）：本地代理入站评估时优先于合并路由与回落
        let custom = self.custom_rules.load();
        apply_custom_rules(
            &mut new_router,
            &custom,
            self.proxy_fallback.load().as_deref().copied(),
        );
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
                node_order: std::sync::Mutex::new(Vec::new()),
                shared_router: Arc::new(ArcSwap::from_pointee(ProxyRouter::new())),
                proxy_port: ArcSwap::from_pointee(0),
                http_client: reqwest::Client::new(),
                inbound_shutdown_tx: tokio::sync::Mutex::new(None),
                openers: Arc::new(DashMap::new()),
                hosts_manager: HostsManager::new(),
                proxy_stats: Arc::new(arc_swap::ArcSwapOption::from_pointee(None)),
                cache: Arc::new(
                    ConfigCache::new()
                        .unwrap_or_else(|_| ConfigCache::with_dir(std::env::temp_dir())),
                ),
                paused_rules: DashMap::new(),
                proxy_fallback: arc_swap::ArcSwapOption::from_pointee(None),
                custom_rules: ArcSwap::from_pointee(CustomRules::default()),
            }),
        }
    }

    pub fn proxy_router(&self) -> Arc<ProxyRouter> {
        self.inner.shared_router.load_full()
    }

    /// 合并路由表共享句柄（路由再发布：注入内嵌节点 connector）。
    pub fn shared_router_handle(&self) -> Arc<ArcSwap<ProxyRouter>> {
        self.inner.shared_router.clone()
    }

    /// 设置代理回落上游（订阅内核 mixed 入站；None 恢复未命中直连）。
    pub fn set_proxy_fallback(&self, addr: Option<SocketAddr>) {
        self.inner.proxy_fallback.store(addr.map(Arc::new));
        self.inner.rebuild_merged_router();
    }

    /// 热更自定义规则（GUI 放行/hosts 映射；立即重建合并路由，无需重启代理）。
    pub fn set_custom_rules(&self, rules: CustomRules) {
        self.inner.custom_rules.store(Arc::new(rules));
        self.inner.rebuild_merged_router();
    }

    /// 通道开启器注册表共享句柄（路由再发布：注入内嵌节点 connector）。
    pub fn openers_handle(&self) -> Arc<DashMap<String, Arc<dyn ChannelOpener>>> {
        self.inner.openers.clone()
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

        // 1. 登录（网络不可达时尝试离线缓存降级）
        let resp = match self
            .inner
            .http_client
            .post(format!("{base_url}/api/v1/auth/login"))
            .json(&serde_json::json!({
                "username": params.username,
                "password": params.password,
            }))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // 网络错误 → 离线缓存降级（断网沿用旧规则 + 后台重试）
                return self.connect_offline(params, e).await;
            }
        };
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
        let tunnel_server = config["tunnel"]["server"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let tunnel_port = config["tunnel"]["port"].as_u64().unwrap_or(443) as u16;
        let version = config["version"].as_u64().unwrap_or(0);
        let admin_console = config["admin_console"].as_bool().unwrap_or(false);
        let manageable = parse_manageable(&config);
        let rules = parse_rules(&config);

        // 3. 建立数据面隧道
        let tunnel_addr: SocketAddr = resolve_addr(&tunnel_server, tunnel_port).await?;
        let tls_builder = build_tls(&params)?;
        let account_id = claims_sub(&access_token).unwrap_or_else(|| params.username.clone());
        let tunnel = Arc::new(ClientTunnel::with_tls_builder(
            tunnel_addr,
            account_id,
            tunnel_token.clone(),
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
            username: params.username.clone(),
            status: NodeStatus::Connected,
            rules,
            config_version: version,
            admin_console,
            manageable,
            bytes_up: 0,
            bytes_down: 0,
        };

        // 4. 后台任务：隧道自动重连 + 心跳 + 配置长轮询
        let access_shared = Arc::new(ArcSwap::from_pointee(access_token.clone()));
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
            access_shared.clone(),
            refresh_token.clone(),
            version,
        ));

        // 5. 写入离线缓存（断网时沿用）
        self.inner.cache.save(&CachedNodeConfig {
            addr: params.addr.clone(),
            username: params.username.clone(),
            node_name: node_name.clone(),
            rules: state.rules.clone(),
            config_version: version,
            tunnel_server,
            tunnel_port,
            tunnel_token: tunnel_token.clone(),
            refresh_token: refresh_token.clone(),
            insecure: params.insecure,
            pinned_fingerprint: params.pinned_fingerprint.clone(),
            updated_at: chrono_now(),
        });

        let handle = NodeHandle {
            state: state.clone(),
            tunnel,
            tasks,
            manage_hosts: params.manage_hosts,
            params: params.clone(),
            access_token: access_shared,
        };
        self.inner.nodes.insert(node_id.clone(), handle);
        self.inner
            .node_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node_id.clone());
        self.inner.rebuild_merged_router();

        info!(node = %node_id, admin_console, "node connected");
        Ok(state)
    }

    /// 离线降级：网络不可达时沿用缓存规则组网，后台周期重试登录。
    async fn connect_offline(
        &self,
        params: ConnectParams,
        net_err: reqwest::Error,
    ) -> Result<NodeState> {
        let cached = self
            .inner
            .cache
            .load(&params.addr, &params.username)
            .ok_or_else(|| anyhow!("无法连接节点且无离线缓存: {net_err}"))?;

        warn!(
            addr = %params.addr,
            "节点不可达，启用离线缓存（{} 条规则，缓存于 {}）",
            cached.rules.len(),
            cached.updated_at
        );

        let node_id = format!("{}@{}", cached.node_name, params.addr);
        let tunnel_addr: SocketAddr =
            resolve_addr(&cached.tunnel_server, cached.tunnel_port).await?;
        let tls_builder = build_tls(&params)?;
        let account_id = cached.username.clone();
        let tunnel = Arc::new(ClientTunnel::with_tls_builder(
            tunnel_addr,
            account_id,
            cached.tunnel_token.clone(),
            tls_builder,
        )?);
        // 隧道重连任务（token 可能已过期，但服务端未轮换前仍可用）
        tunnel.connect().await.ok();

        self.inner
            .openers
            .insert(node_id.clone(), tunnel.clone() as Arc<dyn ChannelOpener>);

        let state = NodeState {
            node_id: node_id.clone(),
            addr: params.addr.clone(),
            node_name: cached.node_name.clone(),
            username: cached.username.clone(),
            status: NodeStatus::Reconnecting,
            rules: cached.rules.clone(),
            config_version: cached.config_version,
            admin_console: false,
            manageable: Vec::new(),
            bytes_up: 0,
            bytes_down: 0,
        };

        let mut tasks = Vec::new();
        {
            let t = tunnel.clone();
            tasks.push(tokio::spawn(async move {
                t.run().await;
            }));
        }
        // 后台登录重试：恢复在线后无缝升级
        tasks.push(spawn_offline_retry(
            self.inner.clone(),
            node_id.clone(),
            params.clone(),
        ));

        let handle = NodeHandle {
            state: state.clone(),
            tunnel,
            tasks,
            manage_hosts: params.manage_hosts,
            params: params.clone(),
            access_token: Arc::new(ArcSwap::from_pointee(String::new())),
        };
        self.inner.nodes.insert(node_id.clone(), handle);
        self.inner
            .node_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node_id.clone());
        self.inner.rebuild_merged_router();

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
            self.inner
                .node_order
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|id| id != node_id);
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
        // 先同步修正状态并取出隧道句柄，再异步读流量（避免持 dashmap 守卫跨 await）
        let mut states = Vec::with_capacity(self.inner.nodes.len());
        let mut tunnels = Vec::with_capacity(self.inner.nodes.len());
        for mut r in self.inner.nodes.iter_mut() {
            // 以隧道实时状态为准修正缓存状态：
            // 对端关闭/断网时缓存的 Connected 不会自动回写（管理面按钮据此显隐）
            let live = if r.tunnel.is_connected() {
                NodeStatus::Connected
            } else {
                match r.tunnel.state() {
                    agile_net_core::relay::ConnectionState::Reconnecting => {
                        NodeStatus::Reconnecting
                    }
                    agile_net_core::relay::ConnectionState::Connecting => NodeStatus::Connecting,
                    _ => NodeStatus::Disconnected,
                }
            };
            if r.state.status != live {
                r.state.status = live;
            }
            states.push(r.state.clone());
            tunnels.push(r.tunnel.clone());
        }
        for (state, tunnel) in states.iter_mut().zip(tunnels) {
            let (up, down) = tunnel.traffic().await;
            state.bytes_up = up;
            state.bytes_down = down;
        }
        states
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
                        agile_net_core::relay::ConnectionState::Reconnecting => {
                            NodeStatus::Reconnecting
                        }
                        agile_net_core::relay::ConnectionState::Connecting => {
                            NodeStatus::Connecting
                        }
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

    /// 暂停/恢复某节点的一条规则（rule_key 格式 "type:value"，立即重建合并路由）。
    pub fn set_rule_paused(&self, node_id: &str, rule_key: &str, paused: bool) {
        if paused {
            self.inner
                .paused_rules
                .entry(node_id.to_string())
                .or_default()
                .insert(rule_key.to_string());
        } else if let Some(mut set) = self.inner.paused_rules.get_mut(node_id) {
            set.remove(rule_key);
        }
        self.inner.rebuild_merged_router();
    }

    /// 某节点当前被暂停的规则 key 列表。
    pub fn get_paused_rules(&self, node_id: &str) -> Vec<String> {
        self.inner
            .paused_rules
            .get(node_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// 整体恢复某节点的暂停集合（前端启动时从本地持久化恢复）。
    pub fn set_paused_rules(&self, node_id: &str, keys: Vec<String>) {
        if keys.is_empty() {
            self.inner.paused_rules.remove(node_id);
        } else {
            self.inner
                .paused_rules
                .insert(node_id.to_string(), keys.into_iter().collect());
        }
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

    /// 节点的数据面通道开启器（控制台 loopback 转发器用）。
    pub fn opener(&self, node_id: &str) -> Option<Arc<dyn ChannelOpener>> {
        self.inner.openers.get(node_id).map(|r| r.value().clone())
    }

    /// 申请可管理上游的控制台票据（中继令牌换取，scoped；握手 v2 发现的当前票据）。
    ///
    /// 返回 (ticket, api_host, api_port, scope)：控制台经本节点隧道访问上游管理面。
    pub async fn upstream_console_ticket(
        &self,
        node_id: &str,
        upstream: &str,
    ) -> Result<(String, String, u16, String)> {
        let handle = self
            .inner
            .nodes
            .get(node_id)
            .ok_or_else(|| anyhow!("节点未连接: {node_id}"))?;
        if !handle.state.admin_console {
            return Err(anyhow!("该节点未授予管理权限"));
        }
        let base_url = api_base_url(&handle.params.addr);
        let token = handle.access_token.load().as_ref().clone();
        drop(handle);

        let resp = self
            .inner
            .http_client
            .post(format!("{base_url}/api/v1/client/console-ticket"))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "upstream": upstream }))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "上游 console-ticket 签发失败: HTTP {}",
                resp.status()
            ));
        }
        let json: serde_json::Value = resp.json().await?;
        let data = &json["data"];
        let ticket = data["ticket"]
            .as_str()
            .ok_or_else(|| anyhow!("响应缺少 ticket"))?
            .to_string();
        let api = data["api"]
            .as_str()
            .ok_or_else(|| anyhow!("响应缺少 api"))?
            .to_string();
        let scope = data["scope"].as_str().unwrap_or("full").to_string();
        let (host, port) = match api.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse().map_err(|_| anyhow!("api 端点端口非法: {api}"))?,
            ),
            None => return Err(anyhow!("api 端点格式非法: {api}")),
        };
        Ok((ticket, host, port, scope))
    }

    /// 申请控制台引导票据（仅被授予「管理此节点」权限的账号可用）。
    ///
    /// 返回 (ticket, api_port)：控制台窗口经 loopback 转发器加载节点管理 SPA，
    /// 以 #boot=ticket 换取管理会话；api_port 即节点 API 端口（隧道对端 loopback 目标）。
    pub async fn console_ticket(&self, node_id: &str) -> Result<(String, u16)> {
        let handle = self
            .inner
            .nodes
            .get(node_id)
            .ok_or_else(|| anyhow!("节点未连接: {node_id}"))?;
        if !handle.state.admin_console {
            return Err(anyhow!("该节点未授予管理权限"));
        }
        let base_url = api_base_url(&handle.params.addr);
        let token = handle.access_token.load().as_ref().clone();
        let api_port = api_port_of(&handle.params.addr);
        drop(handle);

        let resp = self
            .inner
            .http_client
            .post(format!("{base_url}/api/v1/client/console-ticket"))
            .bearer_auth(&token)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("console-ticket 签发失败: HTTP {}", resp.status()));
        }
        let json: serde_json::Value = resp.json().await?;
        let ticket = json["data"]["ticket"]
            .as_str()
            .ok_or_else(|| anyhow!("console-ticket 响应缺少 ticket"))?
            .to_string();
        Ok((ticket, api_port))
    }
}

/// 从连接地址提取 API 端口（host:port 或 http(s)://host[:port]，缺省 59090）。
fn api_port_of(addr: &str) -> u16 {
    let stripped = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    match stripped.rsplit_once(':') {
        Some((_, p)) => p.parse().unwrap_or(59090),
        None => 59090,
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

/// 离线降级后的登录重试：恢复在线后无缝升级为完整连接。
fn spawn_offline_retry(
    inner: Arc<ClientInner>,
    node_id: String,
    params: ConnectParams,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let jitter = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_millis()
                % 10000) as u64;
            tokio::time::sleep(
                std::time::Duration::from_secs(30) + std::time::Duration::from_millis(jitter),
            )
            .await;

            match offline_relogin_once(&inner, &node_id, &params).await {
                Ok(()) => {
                    info!(node = %node_id, "offline node reconnected, upgraded to full connection");
                    break;
                }
                Err(e) => {
                    debug!(node = %node_id, error = %e, "offline relogin attempt failed");
                }
            }
        }
    })
}

/// 离线状态下的一次完整重登：成功则更新令牌/规则/缓存/状态。
async fn offline_relogin_once(
    inner: &Arc<ClientInner>,
    node_id: &str,
    params: &ConnectParams,
) -> Result<()> {
    let base_url = api_base_url(&params.addr);
    let http = &inner.http_client;

    let resp = http
        .post(format!("{base_url}/api/v1/auth/login"))
        .json(&serde_json::json!({
            "username": params.username,
            "password": params.password,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("login failed: HTTP {}", resp.status()));
    }
    let login_json: serde_json::Value = resp.json().await?;
    let data = &login_json["data"];
    let access_token = data["access_token"]
        .as_str()
        .ok_or_else(|| anyhow!("no access_token"))?
        .to_string();
    let refresh_token = data["refresh_token"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let tunnel_token = data["tunnel_token"]
        .as_str()
        .ok_or_else(|| anyhow!("no tunnel_token"))?
        .to_string();

    let config = pull_config(http, &base_url, &access_token, 0).await?;
    let version = config["version"].as_u64().unwrap_or(0);
    let rules = parse_rules(&config);

    // 更新句柄：令牌轮换 + 规则 + 状态 + 缓存
    let Some(mut handle) = inner.nodes.get_mut(node_id) else {
        return Err(anyhow!("node gone"));
    };
    handle.tunnel.update_token(tunnel_token.clone());
    handle.state.rules = rules.clone();
    handle.state.config_version = version;
    handle.state.status = NodeStatus::Connected;
    handle.state.admin_console = config["admin_console"].as_bool().unwrap_or(false);
    handle.access_token.store(Arc::new(access_token.clone()));
    let node_name = handle.state.node_name.clone();
    let (tunnel_server, tunnel_port) = (
        config["tunnel"]["server"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        config["tunnel"]["port"].as_u64().unwrap_or(443) as u16,
    );
    drop(handle);

    inner.cache.save(&CachedNodeConfig {
        addr: params.addr.clone(),
        username: params.username.clone(),
        node_name,
        rules,
        config_version: version,
        tunnel_server,
        tunnel_port,
        tunnel_token,
        refresh_token,
        insecure: params.insecure,
        pinned_fingerprint: params.pinned_fingerprint.clone(),
        updated_at: chrono_now(),
    });
    inner.rebuild_merged_router();
    Ok(())
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
                    let active = stats
                        .active_connections
                        .load(std::sync::atomic::Ordering::Relaxed);
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
    access_shared: Arc<ArcSwap<String>>,
    refresh_token: String,
    initial_version: u64,
) -> tokio::task::JoinHandle<()> {
    let http = inner.http_client.clone();
    tokio::spawn(async move {
        let mut version = initial_version;
        let mut access = access_shared.load().as_ref().clone();
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
                            access_shared.store(Arc::new(access.clone()));
                            refresh = json["data"]["refresh_token"]
                                .as_str()
                                .unwrap_or(refresh.as_str())
                                .to_string();
                            // 服务端轮换了 tunnel_token → 同步给隧道供下次重连
                            if let Some(new_tun) = json["data"]["tunnel_token"].as_str()
                                && let Some(h) = inner.nodes.get(&node_id)
                            {
                                h.tunnel.update_token(new_tun.to_string());
                            }
                            // 刷新缓存中的 refresh_token
                            if let Some(h) = inner.nodes.get(&node_id) {
                                let p = &h.params;
                                if let Some(mut cached) = inner.cache.load(&p.addr, &p.username) {
                                    cached.refresh_token = refresh.clone();
                                    cached.updated_at = chrono_now();
                                    inner.cache.save(&cached);
                                }
                            }
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
                    h.state.admin_console = data["admin_console"].as_bool().unwrap_or(false);
                    h.state.manageable = parse_manageable(data);
                }
                inner.rebuild_merged_router();
            }
        }
    })
}

// ==================== 辅助函数 ====================

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

fn api_base_url(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.trim_end_matches('/').to_string()
    } else {
        // 默认 HTTP 是节点 API 的出厂形态（内置 HTTPS 需在节点侧配置证书）；
        // 非 loopback 明文场景给出显式告警，生产应配置 HTTPS 或证书固定
        let host = addr.trim_end_matches('/');
        let is_loopback = host
            .split(':')
            .next()
            .map(|h| h == "127.0.0.1" || h == "localhost" || h == "::1")
            .unwrap_or(false);
        if !is_loopback {
            tracing::warn!(addr = %addr, "节点 API 使用明文 HTTP：生产环境请为节点配置内置 HTTPS，或使用证书固定");
        }
        format!("http://{host}")
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

/// 把可管理上游的 API 端点并入路由表（隐式隧道路由）。
///
/// 仅处理上游链（via=relay）端点；本机管理走 loopback 转发器不占路由位。
/// IP 给 /32 CIDR，域名给精确主机；占用冲突位次（先连优先）。
fn add_manageable_routes(
    router: &mut ProxyRouter,
    node_id: &str,
    manageable: &[ManageableNode],
    seen: &mut std::collections::HashSet<String>,
) {
    for m in manageable {
        let Some(host) = m
            .api
            .rsplit_once(':')
            .map(|(h, _)| h)
            .filter(|h| !h.is_empty())
        else {
            continue;
        };
        let outbound = Outbound::tunnel(node_id.to_string());
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            let value = format!("{ip}/32");
            if seen.insert(format!("ip-cidr:{}", value.to_lowercase())) {
                let _ = router.add_cidr(&value, outbound);
            }
        } else if seen.insert(format!("host:{}", host.to_lowercase())) {
            router.add_host_exact(host, outbound);
        }
    }
}

fn parse_manageable(config: &serde_json::Value) -> Vec<ManageableNode> {
    config["manageable"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    Some(ManageableNode {
                        node_name: m["node_name"].as_str()?.to_string(),
                        api: m["api"].as_str()?.to_string(),
                        scope: m["scope"].as_str().unwrap_or("full").to_string(),
                        via: m["via"].as_str().unwrap_or("relay").to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn build_tls(params: &ConnectParams) -> Result<TlsConfigBuilder> {
    let builder = TlsConfigBuilder::new();
    if let Some(fp) = &params.pinned_fingerprint {
        // 指纹固定最优先（connect_url 一键分发，抗 MITM）
        Ok(builder.pinned_fingerprint(fp.clone()))
    } else if let Some(pinned_path) = &params.pinned_cert_path {
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

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn m(node_name: &str, api: &str) -> ManageableNode {
        ManageableNode {
            node_name: node_name.into(),
            api: api.into(),
            scope: "rules".into(),
            via: "relay".into(),
        }
    }

    #[test]
    fn manageable_routes_ip_and_host() {
        let mut router = ProxyRouter::new();
        let mut seen = std::collections::HashSet::new();
        let list = vec![
            m("root", "172.28.0.10:59090"),
            m("ops", "ops.internal:59090"),
        ];
        add_manageable_routes(&mut router, "n1@x:1", &list, &mut seen);

        // IP 端点 → /32 CIDR 命中
        assert!(matches!(
            router.route_target("172.28.0.10:59090"),
            Outbound::Tunnel { node_id } if node_id == "n1@x:1"
        ));
        // 域名端点 → 精确主机命中
        assert!(matches!(
            router.route_target("ops.internal:59090"),
            Outbound::Tunnel { node_id } if node_id == "n1@x:1"
        ));
        // 同主机其他端口也命中（按主机路由）
        assert!(matches!(
            router.route_target("ops.internal:443"),
            Outbound::Tunnel { .. }
        ));
        // 无关目标不受影响（默认直连）
        assert!(matches!(
            router.route_target("other.net:80"),
            Outbound::Direct
        ));
    }

    #[test]
    fn manageable_routes_respect_first_wins() {
        let mut router = ProxyRouter::new();
        let mut seen = std::collections::HashSet::new();
        // 先占位的显式规则（host:ops.internal 属于另一个节点）
        seen.insert("host:ops.internal".to_string());
        router.add_host_exact("ops.internal", Outbound::tunnel("n0@a:1"));

        let list = vec![m("ops", "ops.internal:59090")];
        add_manageable_routes(&mut router, "n1@x:1", &list, &mut seen);
        // 隐式路由不抢占已占用位次
        assert!(matches!(
            router.route_target("ops.internal:59090"),
            Outbound::Tunnel { node_id } if node_id == "n0@a:1"
        ));
    }

    // ==================== 自定义规则（放行 / hosts 映射） ====================

    fn bypass(pattern: &str, via_subscription: bool) -> CustomBypassRule {
        CustomBypassRule {
            pattern: pattern.into(),
            via_subscription,
        }
    }

    #[test]
    fn custom_rules_baked_into_router_layer() {
        let mut router = ProxyRouter::new();
        // 模拟合并路由：同名目标已有端点隧道路由
        router.add_host_exact("api.corp.internal", Outbound::tunnel("n1@x:1"));
        let custom = CustomRules {
            bypass: vec![bypass("*.corp.internal", false)],
            hosts: vec![("git.corp.internal".into(), "10.9.9.9".into())],
        };
        apply_custom_rules(&mut router, &custom, None);

        // 放行命中 → Direct（入站评估顺序：custom_bypass_match 先于 route_target，
        // 因此自定义放行优先于既有隧道路由）
        assert!(matches!(
            router.custom_bypass_match("api.corp.internal"),
            Some(Outbound::Direct)
        ));
        // hosts 映射改写目标（map_host 先行，随后按改写结果继续路由）
        assert_eq!(
            router.map_host("git.corp.internal"),
            Some("10.9.9.9".parse().unwrap())
        );
        // 非法 IP 的映射被过滤，不进入映射层
        let mut router2 = ProxyRouter::new();
        apply_custom_rules(
            &mut router2,
            &CustomRules {
                bypass: vec![],
                hosts: vec![("bad.internal".into(), "not-an-ip".into())],
            },
            None,
        );
        assert_eq!(router2.map_host("bad.internal"), None);
    }

    #[test]
    fn custom_bypass_via_subscription_uses_fallback() {
        let fallback: SocketAddr = "127.0.0.1:57891".parse().unwrap();
        let custom = CustomRules {
            bypass: vec![
                bypass("*.via-sub.com", true),
                bypass("*.plain.com", false),
            ],
            hosts: vec![],
        };
        // 有回落上游：经过订阅 → Forward(回落)，普通放行 → Direct
        let mut router = ProxyRouter::new();
        apply_custom_rules(&mut router, &custom, Some(fallback));
        assert!(matches!(
            router.custom_bypass_match("a.via-sub.com"),
            Some(Outbound::Forward { addr }) if *addr == fallback
        ));
        assert!(matches!(
            router.custom_bypass_match("a.plain.com"),
            Some(Outbound::Direct)
        ));
        // 无回落上游：经过订阅退化为 Direct
        let mut router2 = ProxyRouter::new();
        apply_custom_rules(&mut router2, &custom, None);
        assert!(matches!(
            router2.custom_bypass_match("a.via-sub.com"),
            Some(Outbound::Direct)
        ));
    }

    #[test]
    fn engine_set_custom_rules_hot_update() {
        let client = AgileNetClient::new();
        let fallback: SocketAddr = "127.0.0.1:57891".parse().unwrap();
        client.set_proxy_fallback(Some(fallback));
        client.set_custom_rules(CustomRules {
            bypass: vec![bypass("*.corp.internal", true)],
            hosts: vec![("git.corp.internal".into(), "10.9.9.9".into())],
        });
        let router = client.proxy_router();
        assert!(matches!(
            router.custom_bypass_match("app.corp.internal"),
            Some(Outbound::Forward { addr }) if *addr == fallback
        ));
        assert_eq!(
            router.map_host("git.corp.internal"),
            Some("10.9.9.9".parse().unwrap())
        );
        // 清空即恢复（热更语义）
        client.set_custom_rules(CustomRules::default());
        let router = client.proxy_router();
        assert!(router.custom_bypass_match("app.corp.internal").is_none());
        assert_eq!(router.map_host("git.corp.internal"), None);
    }

    #[test]
    fn custom_rules_do_not_alter_merged_routes() {
        // 自定义层不进 route_target / route_count / rule_values：
        // 扇入 connector 与路由再发布维持既有口径
        let client = AgileNetClient::new();
        client.set_custom_rules(CustomRules {
            bypass: vec![bypass("*.corp.internal", false)],
            hosts: vec![("git.corp.internal".into(), "10.9.9.9".into())],
        });
        let router = client.proxy_router();
        assert_eq!(router.route_count(), 0);
        assert!(router.rule_values().is_empty());
        assert!(matches!(
            router.route_target("app.corp.internal:443"),
            Outbound::Direct
        ));
    }
}
