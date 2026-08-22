//! Three-way role toggles (client / server / Web remote UI) and embedded node management.
//!
//! - Role state is persisted to `~/.anet/gui/gui-settings.json`
//! - Embedded node data (SQLite / certs) lives in `~/.anet/gui/embedded-node/`;
//!   default ports avoid the local standalone node (API 59290) and the Docker demo chain host mapping (59290) → API 59293 / Relay 54431
//! - Toggle changes and Web UI exposure changes are appended to `~/.anet/gui/gui-audit.jsonl` (audit)
//! - Web remote UI admin password is stored as an argon2id hash in `~/.anet/gui/web-auth.json`

use agile_net_core::config::node::{ApiConfig, ListenerConfig};
use agile_net_core::config::NodeConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Embedded node default listen addr (avoids standalone node 59090 / 54430 and Docker demo chain host mapping 59290)
pub const EMBEDDED_API_ADDR: &str = "127.0.0.1:59293";
pub const EMBEDDED_RELAY_ADDR: &str = "0.0.0.0:54431";
/// Web remote UI default listen addr (loopback only)
pub const DEFAULT_WEB_LISTEN: &str = "127.0.0.1:59291";

/// Subscription override script (runs in a QuickJS sandbox; Vec order is execution order, `order` stored redundantly in sync with the index)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubScript {
    pub id: String,
    pub name: String,
    pub code: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub order: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleSettings {
    /// Toggle A: client role (upstream connections, local proxy, route composition)
    pub client: bool,
    /// Toggle B: server role (embedded full node)
    pub server: bool,
    /// Toggle C: Web remote UI (admin UI exposed over HTTP)
    pub web: bool,
    /// Web UI listen address (127.0.0.1 / LAN, explicitly configurable)
    #[serde(default = "default_web_listen")]
    pub web_listen: String,
    /// Toggle D: subscription proxy role (mihomo sidecar, anet-gui-exclusive add-on service)
    #[serde(default)]
    pub subscription: bool,
    /// Subscription feature installed and activated (sidebar "Subscription/Proxy" entry visible; explicitly activated by the user after kernel install succeeds)
    #[serde(default)]
    pub subscription_feature: bool,
    /// System proxy management (points at the local proxy port; restores the snapshot when disabled; on by default — works out of the box for most users;
    /// the listen-only local proxy mode targets users who configure apps manually)
    #[serde(default = "default_true")]
    pub system_proxy: bool,
    /// Subscription outbound mode (rule|global|direct, written to mihomo mode)
    #[serde(default = "default_sub_mode")]
    pub sub_mode: String,
    /// Subscription override script chain (run in order on render_config output before handing to mihomo; Vec order = execution order)
    #[serde(default)]
    pub sub_scripts: Vec<SubScript>,
    /// TUN mode (docs/plan/tun.md P1: mihomo TUN takes over, anet in front, FlClash behind; requires admin)
    #[serde(default)]
    pub tun_mode: bool,
    /// TUN mode external upstream (fallback target for traffic matching no anet rule; defaults to FlClash mixed inbound)
    #[serde(default = "default_external_upstream")]
    pub external_upstream: String,
    /// System proxy lock (hardcore mode): treated as managed; auto-reclaimed when inspection finds it changed (no TUN needed)
    #[serde(default)]
    pub sysproxy_lock: bool,
    /// Floating ball window (desktop only; when on, a small ball stays at the bottom-right corner)
    #[serde(default)]
    pub float_ball: bool,
    /// Floating ball bubble notification toggle (when false, the float_ball_notify command and existing bridge points no longer emit)
    #[serde(default = "default_true")]
    pub notify_float_ball: bool,
    /// Performance mode (frontend disables blur/animations based on this; backend only persists it)
    #[serde(default)]
    pub reduce_effects: bool,
    /// Connection log (docs/todo/conn-log.md; default off — records are browsing history, opt-in)
    #[serde(default)]
    pub conn_log_enabled: bool,
    /// Miss policy for traffic matching no anet rule: true = DIRECT instead of the subscription /
    /// external-upstream fallback (the anet router's default outbound becomes Direct; under TUN the
    /// process-level rule keeps those raw dials loop-free)
    #[serde(default)]
    pub sub_miss_direct: bool,
    /// Close-button behavior: true (default) = minimize to tray, false = quit the app.
    /// Read by the main window's CloseRequested handler.
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
}

fn default_true() -> bool {
    true
}

fn default_web_listen() -> String {
    DEFAULT_WEB_LISTEN.to_string()
}

pub fn default_sub_mode() -> String {
    "rule".to_string()
}

/// Outbound mode validity check (rule|global|direct)
pub fn valid_sub_mode(mode: &str) -> bool {
    matches!(mode, "rule" | "global" | "direct")
}

/// TUN external upstream default (FlClash mixed inbound)
pub const DEFAULT_EXTERNAL_UPSTREAM: &str = "127.0.0.1:7890";

fn default_external_upstream() -> String {
    DEFAULT_EXTERNAL_UPSTREAM.to_string()
}

/// TUN fallback target validity check (tun.md §2.5 hard constraint):
/// - Must be loopback — a non-loopback target gets re-captured by mihomo TUN (MATCH→57890→fallback→captured again), forming a dead loop
/// - Must never point at local proxy 57890 / kernel mixed 57892 / control plane 59292 (port numbers stay in sync with subscription::MIHOMO_*)
pub fn validate_external_upstream(addr: &str) -> Result<std::net::SocketAddr, String> {
    let sa: std::net::SocketAddr = addr
        .trim()
        .parse()
        .map_err(|_| "外部上游地址格式应为 ip:port（如 127.0.0.1:7890）".to_string())?;
    if !sa.ip().is_loopback() {
        return Err("外部上游必须是本机回环地址（非回环目标会被 TUN 重捕获形成死环）".into());
    }
    if sa.port() == 0 {
        return Err("外部上游端口非法".into());
    }
    const FORBIDDEN: [u16; 4] = [57890, 57892, 57893, 59292];
    if FORBIDDEN.contains(&sa.port()) {
        return Err(format!("外部上游严禁指向本机端口 {}（防环硬约束）", sa.port()));
    }
    Ok(sa)
}

impl Default for RoleSettings {
    fn default() -> Self {
        Self {
            client: true,
            server: false,
            web: false,
            web_listen: default_web_listen(),
            subscription: false,
            subscription_feature: false,
            system_proxy: true,
            sub_mode: default_sub_mode(),
            sub_scripts: Vec::new(),
            tun_mode: false,
            external_upstream: default_external_upstream(),
            sysproxy_lock: false,
            float_ball: false,
            notify_float_ball: true,
            reduce_effects: false,
            conn_log_enabled: false,
            sub_miss_direct: false,
            close_to_tray: true,
        }
    }
}

pub fn data_dir() -> PathBuf {
    agile_net_core::util::gui_data_dir()
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
        let Some(raw) = std::fs::read_to_string(settings_path()).ok() else {
            return Self::default();
        };
        // Legacy server_connector(s) fields are dropped via serde's ignored keys (fan-out is now managed in the DB, no longer self-stored)
        serde_json::from_str(&raw).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let dir = data_dir();
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let data = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(settings_path(), data).map_err(|e| e.to_string())
    }
}

/// Local machine username (for audit attribution)
fn local_user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into())
}

/// GUI-side audit: JSONL append (gui.role_toggle / web.exposure_change).
/// Never record password/token plaintext.
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

// ==================== Event center (tail-read of gui-audit.jsonl) ====================

/// Single event-center event (return body of the recent_events command)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiEvent {
    /// Unix seconds
    pub ts: u64,
    /// Event kind (whitelist: role_toggle/kernel/sysproxy/custom_rule/sub_script/doctor/install/uninstall/connector/sync)
    pub kind: String,
    /// Human-readable description (assembled from whitelisted fields; never echoes the raw detail, so sensitive fields are filtered out by construction)
    pub detail: String,
}

/// Audit action → event kind whitelist mapping (actions not listed are skipped):
/// - role_toggle: user-visible toggles — three-way roles / subscription role / TUN / floating ball / global power switch
/// - kernel: subscription kernel lifecycle, kernel integrity, subscription add/remove/update/activate, outbound mode
/// - install: kernel / wintun download and manual install
fn event_kind(action: &str) -> Option<&'static str> {
    Some(match action {
        "gui.role_toggle"
        | "web.exposure_change"
        | "gui.tun_enable"
        | "gui.tun_disable"
        | "gui.tun_abandon"
        | "gui.tun_elevation"
        | "gui.float_ball"
        | "gui.proxy_power" => "role_toggle",
        "gui.kernel_start"
        | "gui.kernel_stop"
        | "gui.kernel_crash"
        | "gui.kernel_tamper"
        | "gui.wintun_download"
        | "gui.wintun_tamper"
        | "gui.subscription_add"
        | "gui.subscription_import"
        | "gui.subscription_update"
        | "gui.subscription_remove"
        | "gui.subscription_activate"
        | "gui.sub_mode" => "kernel",
        "gui.sysproxy_engage"
        | "gui.sysproxy_disengage"
        | "gui.sysproxy_reclaim"
        | "gui.sysproxy_conflict"
        | "gui.sysproxy_lock" => "sysproxy",
        "gui.custom_rule" | "gui.sub_rule_for_host" => "custom_rule",
        "gui.sub_script_add"
        | "gui.sub_script_update"
        | "gui.sub_script_remove"
        | "gui.sub_script_error" => "sub_script",
        "gui.doctor" => "doctor",
        "gui.dl_start" | "gui.dl_done" | "gui.dl_cancel" | "gui.dl_manual_install" => "install",
        "gui.uninstall" => "uninstall",
        "gui.fanout_change" => "connector",
        "gui.sync_config" | "gui.sync_upload" | "gui.sync_restore" => "sync",
        _ => return None,
    })
}

/// detail JSON → human-readable description. Only whitelisted fields (name/toggle/address etc.) are used;
/// the raw JSON is never echoed wholesale — although audit never stores password/token plaintext, structural filtering is still applied here.
fn human_detail(action: &str, d: &serde_json::Value) -> String {
    let s = |k: &str| d[k].as_str().unwrap_or_default();
    let b = |k: &str| d[k].as_bool().unwrap_or(false);
    let on_off = |on: bool| if on { "开启" } else { "关闭" };
    match action {
        "gui.role_toggle" => {
            let role = match s("role") {
                "client" => "客户端角色",
                "server" => "服务端角色",
                "web" => "Web 远程面",
                "subscription" => "订阅代理角色",
                other => other,
            };
            format!("{}{role}", on_off(b("on")))
        }
        "web.exposure_change" => {
            if s("change") == "password_set" {
                "设置 Web 远程面管理密码".into()
            } else {
                format!("Web 远程面监听改为 {}", s("listen"))
            }
        }
        "gui.tun_enable" => format!("开启 TUN 模式（上游 {}）", s("upstream")),
        "gui.tun_disable" => "关闭 TUN 模式".into(),
        "gui.tun_abandon" => format!("TUN 模式开启失败：{}", s("reason")),
        "gui.tun_elevation" => {
            if b("granted") { "TUN 提权已授权".into() } else { "TUN 提权被拒绝".into() }
        }
        "gui.float_ball" => format!("{}悬浮球", on_off(b("on"))),
        "gui.proxy_power" => {
            if b("on") { format!("全局代理已开启（{}）", s("detail")) } else { "全局代理已关闭".into() }
        }
        "gui.kernel_start" => "订阅内核已启动".into(),
        "gui.kernel_stop" => "订阅内核已停止".into(),
        "gui.kernel_crash" => {
            if b("give_up") {
                "订阅内核多次崩溃，已放弃自动重启".into()
            } else {
                format!("订阅内核崩溃，第 {} 次自动重启", d["restart"].as_u64().unwrap_or(0))
            }
        }
        "gui.kernel_tamper" => "内核校验失败，疑似镜像篡改（已拒绝落盘）".into(),
        "gui.wintun_download" => "wintun.dll 已就位".into(),
        "gui.wintun_tamper" => "wintun.dll 校验失败，疑似被篡改（已拒绝落盘）".into(),
        "gui.subscription_add" => format!("新增订阅「{}」（{} 个节点）", s("name"), d["nodes"].as_u64().unwrap_or(0)),
        "gui.subscription_import" => format!("导入本地订阅「{}」（{} 个节点）", s("name"), d["nodes"].as_u64().unwrap_or(0)),
        "gui.subscription_update" => format!("订阅「{}」已更新", s("name")),
        "gui.subscription_remove" => "移除订阅".into(),
        "gui.subscription_activate" => format!("激活订阅「{}」", s("name")),
        "gui.sub_mode" => format!("订阅出站模式切换为 {}", s("mode")),
        "gui.sysproxy_engage" => format!("系统代理已接管（{}）", s("server")),
        "gui.sysproxy_disengage" => "系统代理已还原".into(),
        "gui.sysproxy_reclaim" => format!("系统代理已自动收回（{}）", s("server")),
        "gui.sysproxy_conflict" => "系统代理被外部修改，已自动收回".into(),
        "gui.sysproxy_lock" => format!("{}系统代理锁定", on_off(b("on"))),
        "gui.custom_rule" => match s("action") {
            "add_bypass" => format!("新增放行规则 {}", s("pattern")),
            "remove" => "删除自定义规则".into(),
            other => format!("自定义规则变更（{other}）"),
        },
        "gui.sub_rule_for_host" => format!("为 {} 添加规则（{}）", s("host"), s("target")),
        "gui.sub_script_add" => format!("新增覆写脚本「{}」", s("name")),
        "gui.sub_script_update" => "更新覆写脚本".into(),
        "gui.sub_script_remove" => "删除覆写脚本".into(),
        "gui.sub_script_error" => format!("覆写脚本「{}」执行失败：{}", s("name"), s("error")),
        "gui.doctor" => "运行自我诊断".into(),
        "gui.dl_start" => format!("开始下载 {}", s("artifact")),
        "gui.dl_done" => format!("{} 下载完成", s("artifact")),
        "gui.dl_cancel" => "取消下载".into(),
        "gui.dl_manual_install" => format!("手动安装 {}", s("artifact")),
        "gui.uninstall" => "卸载应用并清理数据".into(),
        "gui.fanout_change" => {
            let verb = match s("action") {
                "add" => "新增",
                "update" => "更新",
                "remove" => "删除",
                _ => "变更",
            };
            format!("{verb}扇出「{}」", s("name"))
        }
        "gui.sync_config" => format!("同步通道设置为 {}", s("target")),
        "gui.sync_upload" => format!("配置存档已上传（版本 {}）", d["version"].as_u64().unwrap_or(0)),
        "gui.sync_restore" => format!(
            "已从版本 {} 恢复配置（来自 {}）",
            d["version"].as_u64().unwrap_or(0),
            s("device")
        ),
        _ => action.to_string(),
    }
}

/// Parse events from the tail of JSONL text (newest first, at most limit entries; skips non-whitelisted actions and bad lines).
fn parse_events(text: &str, limit: usize) -> Vec<GuiEvent> {
    let mut out = Vec::new();
    for line in text.lines().rev() {
        if out.len() >= limit {
            break;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(action) = v["action"].as_str() else { continue };
        let Some(kind) = event_kind(action) else { continue };
        out.push(GuiEvent {
            ts: v["ts"].as_u64().unwrap_or(0),
            kind: kind.to_string(),
            detail: human_detail(action, &v["detail"]),
        });
    }
    out
}

/// Event center data source: tail-reads gui-audit.jsonl (at most 256KB, dropping the partial line across the boundary),
/// returns the newest limit whitelisted events (newest first). Returns an empty Vec if the file does not exist.
pub fn recent_events(limit: usize) -> Vec<GuiEvent> {
    const TAIL_MAX: u64 = 256 * 1024;
    let Ok(mut f) = std::fs::File::open(audit_path()) else {
        return Vec::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(TAIL_MAX);
    use std::io::{Read as _, Seek as _, SeekFrom};
    if f.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf);
    // When not reading from the start, the first line is a partial line; drop it
    let text = match start {
        0 => text.into_owned(),
        _ => text.split_once('\n').map(|(_, rest)| rest.to_string()).unwrap_or_default(),
    };
    parse_events(&text, limit)
}

/// Build the embedded node config (default ports avoid the local standalone node and the Docker demo chain).
/// Fan-out connections are no longer generated from TOML: the SQLite connector table is the single source of truth (admin UI CRUD + hot operations).
pub fn build_embedded_config() -> NodeConfig {
    let dir = embedded_dir();
    let certs = dir.join("certs");
    NodeConfig {
        name: "AgileNet 内嵌端点".into(),
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
        connectors: Vec::new(),
        proxy: None,
        acme: None,
        log: None,
        limits: None,
    }
}

/// Open the embedded node database (usable whether the node is running or not; WAL supports multiple handles).
pub fn open_embedded_db() -> Result<agile_net_node::db::Database, String> {
    let dir = embedded_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    agile_net_node::db::Database::open(embedded_db_path()).map_err(|e| e.to_string())
}

/// Whether the Web remote UI admin password is set.
pub fn has_web_password() -> bool {
    web_auth_path().exists()
}

/// Set the Web remote UI admin password (argon2id hash on disk, mode 0600).
pub fn set_web_password(password: &str) -> Result<(), String> {
    // Same implementation as the server admin password policy (exported by the node side); error message localized to Chinese
    if agile_net_node::api::handlers::auth::validate_password_strength(password).is_err() {
        return Err("管理密码至少 10 位，且须同时包含大小写字母与数字".into());
    }
    let hash = agile_net_node::db::hash_password(password).map_err(|e| e.to_string())?;
    let dir = data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Keep the existing JWT secret (changing the password does not revoke existing sessions)
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
    // 256-bit random secret (two UUIDv4s, from the OS CSPRNG)
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Verify the Web remote UI admin password.
pub fn verify_web_password(password: &str) -> bool {
    let v = read_web_auth();
    let Some(hash) = v["password_hash"].as_str() else {
        return false;
    };
    agile_net_node::db::verify_password(password, hash).unwrap_or(false)
}

/// Desktop Web auth implementation (injected into the agile-net-client admin Web API).
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
        // Lazy upgrade of the old format (password hash only): backfill the secret
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_sub_mode_and_scripts() {
        // Legacy config without the new fields: serde defaults cover them
        let v: RoleSettings = serde_json::from_str(
            r#"{"client":true,"server":false,"web":false}"#,
        )
        .unwrap();
        assert_eq!(v.sub_mode, "rule");
        assert!(v.sub_scripts.is_empty());
    }

    #[test]
    fn settings_scripts_roundtrip_with_order_and_enabled() {
        let v = RoleSettings {
            sub_mode: "global".into(),
            sub_scripts: vec![
                SubScript { id: "a".into(), name: "甲".into(), code: "c1".into(), enabled: true, order: 0 },
                SubScript { id: "b".into(), name: "乙".into(), code: "c2".into(), enabled: false, order: 1 },
            ],
            ..Default::default()
        };
        let raw = serde_json::to_string(&v).unwrap();
        let back: RoleSettings = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.sub_mode, "global");
        assert_eq!(back.sub_scripts.len(), 2);
        assert_eq!(back.sub_scripts[0].id, "a");
        assert!(back.sub_scripts[0].enabled);
        assert!(!back.sub_scripts[1].enabled);
        assert_eq!(back.sub_scripts[1].order, 1);
        // Legacy script data missing enabled/order fields: enabled defaults to true, order to 0
        let legacy: SubScript =
            serde_json::from_str(r#"{"id":"x","name":"n","code":"c"}"#).unwrap();
        assert!(legacy.enabled);
        assert_eq!(legacy.order, 0);
    }

    #[test]
    fn settings_default_notify_and_reduce_effects() {
        // Legacy config without the new fields: serde defaults cover them (notify on, performance mode off)
        let v: RoleSettings = serde_json::from_str(
            r#"{"client":true,"server":false,"web":false}"#,
        )
        .unwrap();
        assert!(v.notify_float_ball);
        assert!(!v.reduce_effects);
        // Persistence roundtrip
        let v = RoleSettings {
            notify_float_ball: false,
            reduce_effects: true,
            ..Default::default()
        };
        let raw = serde_json::to_string(&v).unwrap();
        let back: RoleSettings = serde_json::from_str(&raw).unwrap();
        assert!(!back.notify_float_ball);
        assert!(back.reduce_effects);
    }

    #[test]
    fn parse_events_filters_and_orders() {
        let text = concat!(
            // Non-whitelisted action: skipped
            r#"{"ts":1,"action":"gui.dl_internal","user":"u","detail":{}}"#,
            "\n",
            // Bad line: skipped
            "{not-json}\n",
            // Whitelisted: role toggle
            r#"{"ts":2,"action":"gui.role_toggle","user":"u","detail":{"role":"client","on":false}}"#,
            "\n",
            // Whitelisted: kernel
            r#"{"ts":3,"action":"gui.kernel_start","user":"u","detail":{}}"#,
            "\n",
            // Contains sensitive-looking fields: detail is assembled from whitelisted fields, raw JSON not echoed
            r#"{"ts":4,"action":"gui.sysproxy_engage","user":"u","detail":{"server":"127.0.0.1:57890","token":"psk_secret"}}"#,
            "\n",
        );
        let ev = parse_events(text, 50);
        assert_eq!(ev.len(), 3);
        // Newest first
        assert_eq!(ev[0].ts, 4);
        assert_eq!(ev[0].kind, "sysproxy");
        assert_eq!(ev[0].detail, "系统代理已接管（127.0.0.1:57890）");
        assert!(!ev[0].detail.contains("psk_secret"));
        assert_eq!(ev[1].kind, "kernel");
        assert_eq!(ev[1].detail, "订阅内核已启动");
        assert_eq!(ev[2].kind, "role_toggle");
        assert_eq!(ev[2].detail, "关闭客户端角色");
    }

    #[test]
    fn parse_events_respects_limit() {
        let mut text = String::new();
        for i in 0..10 {
            text.push_str(&format!(
                "{{\"ts\":{i},\"action\":\"gui.kernel_stop\",\"user\":\"u\",\"detail\":{{}}}}\n"
            ));
        }
        let ev = parse_events(&text, 3);
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0].ts, 9);
        assert_eq!(ev[2].ts, 7);
    }

    #[test]
    fn event_kind_whitelist_covers_expected_categories() {
        for (action, kind) in [
            ("gui.role_toggle", "role_toggle"),
            ("gui.proxy_power", "role_toggle"),
            ("gui.kernel_crash", "kernel"),
            ("gui.subscription_add", "kernel"),
            ("gui.sysproxy_conflict", "sysproxy"),
            ("gui.custom_rule", "custom_rule"),
            ("gui.sub_script_error", "sub_script"),
            ("gui.doctor", "doctor"),
            ("gui.dl_done", "install"),
            ("gui.uninstall", "uninstall"),
            ("gui.fanout_change", "connector"),
        ] {
            assert_eq!(event_kind(action), Some(kind), "{action}");
        }
        // Non-whitelisted actions are all skipped
        for action in ["gui.fallback_change", "admin.console_access", "gui.dl_cancel_x", ""] {
            assert!(event_kind(action).is_none(), "{action}");
        }
    }

    #[test]
    fn sub_mode_validation() {
        assert!(valid_sub_mode("rule"));
        assert!(valid_sub_mode("global"));
        assert!(valid_sub_mode("direct"));
        assert!(!valid_sub_mode("RULE"));
        assert!(!valid_sub_mode(""));
    }

    #[test]
    fn settings_default_tun_fields() {
        // Legacy config without TUN fields: serde defaults cover them
        let v: RoleSettings = serde_json::from_str(
            r#"{"client":true,"server":false,"web":false}"#,
        )
        .unwrap();
        assert!(!v.tun_mode);
        assert_eq!(v.external_upstream, DEFAULT_EXTERNAL_UPSTREAM);
        // Persistence roundtrip
        let v = RoleSettings {
            tun_mode: true,
            external_upstream: "127.0.0.1:7897".into(),
            ..Default::default()
        };
        let raw = serde_json::to_string(&v).unwrap();
        let back: RoleSettings = serde_json::from_str(&raw).unwrap();
        assert!(back.tun_mode);
        assert_eq!(back.external_upstream, "127.0.0.1:7897");
    }

    #[test]
    fn external_upstream_validation() {
        // Valid: loopback + non-reserved port
        assert_eq!(
            validate_external_upstream("127.0.0.1:7890").unwrap().to_string(),
            "127.0.0.1:7890"
        );
        assert!(validate_external_upstream("[::1]:7890").unwrap().ip().is_loopback());
        // Must never point back at local ports (57890 local proxy / 57892 kernel mixed / 59292 control plane)
        for p in [57890, 57892, 59292] {
            let addr = format!("127.0.0.1:{p}");
            assert!(validate_external_upstream(&addr).is_err(), "{addr} 应被拒绝");
        }
        // Non-loopback targets (would be re-captured by TUN into a loop)
        assert!(validate_external_upstream("192.168.1.5:7890").is_err());
        assert!(validate_external_upstream("10.0.0.2:1080").is_err());
        // Invalid format / invalid port
        assert!(validate_external_upstream("not-an-addr").is_err());
        assert!(validate_external_upstream("127.0.0.1").is_err());
        assert!(validate_external_upstream("127.0.0.1:0").is_err());
        assert!(validate_external_upstream("example.com:7890").is_err());
    }
}
