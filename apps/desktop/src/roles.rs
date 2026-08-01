//! 三路角色开关（客户端 / 服务端 / Web 远程面）与内嵌节点管理。
//!
//! - 角色状态持久化于 `~/.agile-net/gui-settings.json`
//! - 内嵌节点数据（SQLite / 证书）位于 `~/.agile-net/embedded-node/`，
//!   默认端口避让本地独立节点（API 59290）与 Docker 演示链宿主机映射（59290）→ API 59293 / Relay 54431
//! - 开关变更与 Web 面暴露变更写入 `~/.agile-net/gui-audit.jsonl`（审计）
//! - Web 远程面管理密码以 argon2id 哈希存于 `~/.agile-net/web-auth.json`

use agile_net_core::config::node::{ApiConfig, ConnectorConfig, ListenerConfig};
use agile_net_core::config::NodeConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 内嵌节点默认监听（避让独立节点 59090 / 54430 与 Docker 演示链宿主机映射 59290）
pub const EMBEDDED_API_ADDR: &str = "127.0.0.1:59293";
pub const EMBEDDED_RELAY_ADDR: &str = "0.0.0.0:54431";
/// Web 远程面默认监听（仅 loopback）
pub const DEFAULT_WEB_LISTEN: &str = "127.0.0.1:59291";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleSettings {
    /// 开关A：客户端角色（连上游、本地代理、路由组合）
    pub client: bool,
    /// 开关B：服务端角色（内嵌完整节点）
    pub server: bool,
    /// 开关C：Web 远程面（管理 UI 经 HTTP 暴露）
    pub web: bool,
    /// Web 面监听地址（127.0.0.1 / LAN，显式可配）
    #[serde(default = "default_web_listen")]
    pub web_listen: String,
    /// 服务端角色作为下游中继接入上游（路由再发布：客户端隧道规则转售给下游）
    #[serde(default)]
    pub server_connector: Option<ServerConnectorConfig>,
    /// 开关D：订阅代理角色（mihomo sidecar，anet-gui 独享附加服务）
    #[serde(default)]
    pub subscription: bool,
    /// 订阅功能已安装激活（侧栏「订阅/代理」入口可见；安装内核成功后由用户显式激活）
    #[serde(default)]
    pub subscription_feature: bool,
    /// 订阅流量经统一出口（ProxyRouter 回落到内核 mixed 入站；默认开）
    #[serde(default = "default_true")]
    pub subscription_unified: bool,
    /// 系统代理托管（指向本地代理端口；关闭时还原快照；默认开——多数人即开即用，
    /// 仅监听端口的本地代理模式面向需要手动配置应用的用户）
    #[serde(default = "default_true")]
    pub system_proxy: bool,
}

fn default_true() -> bool {
    true
}

/// 内嵌节点的上游中继配置（token 为敏感凭据，settings 文件本身 0600 保护）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConnectorConfig {
    /// 上游地址（host:port）
    pub upstream_addr: String,
    /// Relay Token（psk_）
    pub token: String,
    /// TLS SNI 域名
    #[serde(default = "default_connector_sni")]
    pub sni_hostname: String,
    /// 跳过证书校验（仅开发）
    #[serde(default)]
    pub insecure: bool,
}

fn default_connector_sni() -> String {
    "cdn.cloudflare.com".into()
}

fn default_web_listen() -> String {
    DEFAULT_WEB_LISTEN.to_string()
}

impl Default for RoleSettings {
    fn default() -> Self {
        Self {
            client: true,
            server: false,
            web: false,
            web_listen: default_web_listen(),
            server_connector: None,
            subscription: false,
            subscription_feature: false,
            subscription_unified: true,
            system_proxy: true,
        }
    }
}

pub fn data_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".agile-net")
}

pub fn embedded_dir() -> PathBuf {
    data_dir().join("embedded-node")
}

pub fn embedded_db_path() -> PathBuf {
    embedded_dir().join("node.db")
}

fn settings_path() -> PathBuf {
    data_dir().join("gui-settings.json")
}

fn audit_path() -> PathBuf {
    data_dir().join("gui-audit.jsonl")
}

fn web_auth_path() -> PathBuf {
    data_dir().join("web-auth.json")
}

impl RoleSettings {
    pub fn load() -> Self {
        std::fs::read_to_string(settings_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let dir = data_dir();
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let data = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(settings_path(), data).map_err(|e| e.to_string())
    }
}

/// 本机用户名（审计归因用）
fn local_user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into())
}

/// GUI 侧审计：JSONL 追加（gui.role_toggle / web.exposure_change）。
/// 严禁记录密码/Token 明文。
pub fn audit(action: &str, detail: serde_json::Value) {
    let dir = data_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let line = serde_json::json!({
        "ts": ts,
        "action": action,
        "user": local_user(),
        "detail": detail,
    });
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path())
    {
        let _ = writeln!(f, "{line}");
    }
}

/// 构建内嵌节点配置（默认端口避让本地独立节点；可选接入上游做路由再发布）。
pub fn build_embedded_config(connector: Option<&ServerConnectorConfig>) -> NodeConfig {
    let dir = embedded_dir();
    let certs = dir.join("certs");
    NodeConfig {
        name: "AgileNet 内嵌节点".into(),
        db_path: embedded_db_path().to_string_lossy().to_string(),
        public_host: None,
        api: ApiConfig {
            addr: EMBEDDED_API_ADDR.to_string(),
            tls_cert_path: None,
            tls_key_path: None,
        },
        listener: Some(ListenerConfig {
            addr: EMBEDDED_RELAY_ADDR.to_string(),
            cert_path: certs.join("relay-cert.pem").to_string_lossy().to_string(),
            key_path: certs.join("relay-key.pem").to_string_lossy().to_string(),
            sni_hostname: "cdn.cloudflare.com".into(),
        }),
        connector: connector.map(|c| ConnectorConfig {
            upstream_addr: c.upstream_addr.clone(),
            token: c.token.clone(),
            sni_hostname: c.sni_hostname.clone(),
            advertise: Vec::new(), // 通告集 = 客户端隧道规则（动态再发布）
            ca_cert_path: None,
            pinned_cert_path: None,
            insecure: c.insecure,
        }),
        proxy: None,
        acme: None,
        log: None,
        limits: None,
    }
}

/// 打开内嵌节点数据库（运行中与未运行均可用；WAL 支持多句柄）。
pub fn open_embedded_db() -> Result<agile_net_node::db::Database, String> {
    let dir = embedded_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    agile_net_node::db::Database::open(embedded_db_path()).map_err(|e| e.to_string())
}

/// Web 远程面是否已设管理密码。
pub fn has_web_password() -> bool {
    web_auth_path().exists()
}

/// 设置 Web 远程面管理密码（argon2id 哈希落盘，0600）。
pub fn set_web_password(password: &str) -> Result<(), String> {
    if password.len() < 10 {
        return Err("管理密码至少 10 位".into());
    }
    let hash = agile_net_node::db::hash_password(password).map_err(|e| e.to_string())?;
    let dir = data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // 保留既有 JWT 密钥（改密不吊销既有会话）
    let secret = read_web_auth()["jwt_secret"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(generate_secret);
    write_web_auth(&hash, &secret)
}

fn read_web_auth() -> serde_json::Value {
    std::fs::read_to_string(web_auth_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

fn write_web_auth(password_hash: &str, jwt_secret: &str) -> Result<(), String> {
    let data = serde_json::json!({ "password_hash": password_hash, "jwt_secret": jwt_secret });
    let path = web_auth_path();
    std::fs::write(&path, serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn generate_secret() -> String {
    // 256 位随机密钥（两个 UUIDv4，源自操作系统 CSPRNG）
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// 校验 Web 远程面管理密码。
#[allow(dead_code)]
pub fn verify_web_password(password: &str) -> bool {
    let v = read_web_auth();
    let Some(hash) = v["password_hash"].as_str() else {
        return false;
    };
    agile_net_node::db::verify_password(password, hash).unwrap_or(false)
}

/// 桌面端 Web 鉴权实现（注入 agile-net-client 管理面 Web API）。
pub struct DesktopWebAuth;

impl agile_net_client::api::ClientWebAuth for DesktopWebAuth {
    fn has_password(&self) -> bool {
        has_web_password()
    }

    fn set_password(&self, password: &str) -> Result<(), String> {
        set_web_password(password)
    }

    fn verify_password(&self, password: &str) -> bool {
        verify_web_password(password)
    }

    fn jwt_secret(&self) -> String {
        let v = read_web_auth();
        if let Some(s) = v["jwt_secret"].as_str() {
            return s.to_string();
        }
        // 旧格式（仅密码哈希）懒升级：补写密钥
        let secret = generate_secret();
        if let Some(hash) = v["password_hash"].as_str() {
            let _ = write_web_auth(hash, &secret);
        }
        secret
    }

    fn audit(&self, action: &str, detail: serde_json::Value) {
        audit(action, detail);
    }
}
