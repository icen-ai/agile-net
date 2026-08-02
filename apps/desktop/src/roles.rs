//! 三路角色开关（客户端 / 服务端 / Web 远程面）与内嵌节点管理。
//!
//! - 角色状态持久化于 `~/.agile-net/gui-settings.json`
//! - 内嵌节点数据（SQLite / 证书）位于 `~/.agile-net/embedded-node/`，
//!   默认端口避让本地独立节点（API 59290）与 Docker 演示链宿主机映射（59290）→ API 59293 / Relay 54431
//! - 开关变更与 Web 面暴露变更写入 `~/.agile-net/gui-audit.jsonl`（审计）
//! - Web 远程面管理密码以 argon2id 哈希存于 `~/.agile-net/web-auth.json`

use agile_net_core::config::node::{ApiConfig, ListenerConfig};
use agile_net_core::config::NodeConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 内嵌节点默认监听（避让独立节点 59090 / 54430 与 Docker 演示链宿主机映射 59290）
pub const EMBEDDED_API_ADDR: &str = "127.0.0.1:59293";
pub const EMBEDDED_RELAY_ADDR: &str = "0.0.0.0:54431";
/// Web 远程面默认监听（仅 loopback）
pub const DEFAULT_WEB_LISTEN: &str = "127.0.0.1:59291";

/// 订阅覆写脚本（QuickJS 沙箱执行；Vec 顺序即执行顺序，order 与下标同步冗余存储）
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
    /// 开关A：客户端角色（连上游、本地代理、路由组合）
    pub client: bool,
    /// 开关B：服务端角色（内嵌完整节点）
    pub server: bool,
    /// 开关C：Web 远程面（管理 UI 经 HTTP 暴露）
    pub web: bool,
    /// Web 面监听地址（127.0.0.1 / LAN，显式可配）
    #[serde(default = "default_web_listen")]
    pub web_listen: String,
    /// 开关D：订阅代理角色（mihomo sidecar，anet-gui 独享附加服务）
    #[serde(default)]
    pub subscription: bool,
    /// 订阅功能已安装激活（侧栏「订阅/代理」入口可见；安装内核成功后由用户显式激活）
    #[serde(default)]
    pub subscription_feature: bool,
    /// 系统代理托管（指向本地代理端口；关闭时还原快照；默认开——多数人即开即用，
    /// 仅监听端口的本地代理模式面向需要手动配置应用的用户）
    #[serde(default = "default_true")]
    pub system_proxy: bool,
    /// 订阅出站模式（rule|global|direct，写入 mihomo mode）
    #[serde(default = "default_sub_mode")]
    pub sub_mode: String,
    /// 订阅覆写脚本链（render_config 产物交给 mihomo 前依序执行；Vec 顺序 = 执行顺序）
    #[serde(default)]
    pub sub_scripts: Vec<SubScript>,
    /// TUN 模式（docs/plan/tun.md P1：mihomo TUN 接管，anet 在前 FlClash 在后；需管理员）
    #[serde(default)]
    pub tun_mode: bool,
    /// TUN 模式外部上游（anet 未命中规则的流量回落目标，默认 FlClash mixed 入站）
    #[serde(default = "default_external_upstream")]
    pub external_upstream: String,
    /// 系统代理锁定（硬核模式）：视同托管，巡检发现被改即自动收回（无需 TUN）
    #[serde(default)]
    pub sysproxy_lock: bool,
    /// 悬浮球窗口（仅桌面；开启即常驻右下角小球）
    #[serde(default)]
    pub float_ball: bool,
    /// 悬浮球气泡通知开关（false 时 float_ball_notify 命令与既有桥接点均不再 emit）
    #[serde(default = "default_true")]
    pub notify_float_ball: bool,
    /// 性能模式（前端据此关模糊/动画；后端仅持久化存取）
    #[serde(default)]
    pub reduce_effects: bool,
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

/// 出站模式合法值校验（rule|global|direct）
pub fn valid_sub_mode(mode: &str) -> bool {
    matches!(mode, "rule" | "global" | "direct")
}

/// TUN 外部上游默认值（FlClash mixed 入站）
pub const DEFAULT_EXTERNAL_UPSTREAM: &str = "127.0.0.1:7890";

fn default_external_upstream() -> String {
    DEFAULT_EXTERNAL_UPSTREAM.to_string()
}

/// TUN 回落目标合法性校验（tun.md §2.5 硬约束）：
/// - 必须 loopback——非回环目标会被 mihomo TUN 重捕获（MATCH→57890→回落→再次被捕获）形成死环
/// - 严禁指向本地代理 57890 / 内核 mixed 57892 / 控制面 59292（端口号与 subscription::MIHOMO_* 保持一致）
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
        let Some(raw) = std::fs::read_to_string(settings_path()).ok() else {
            return Self::default();
        };
        // 旧版 server_connector(s) 字段随 serde 忽略键直接丢弃（扇出已入库管理，不再自存配置）
        serde_json::from_str(&raw).unwrap_or_default()
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

// ==================== 事件中心（gui-audit.jsonl 尾部倒读） ====================

/// 事件中心单条事件（recent_events 命令返回体）
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiEvent {
    /// Unix 秒
    pub ts: u64,
    /// 事件类别（白名单：role_toggle/kernel/sysproxy/custom_rule/sub_script/doctor/install/uninstall/connector/sync）
    pub kind: String,
    /// 人类可读描述（由白名单字段拼装，绝不回显原始 detail，天然过滤敏感字段）
    pub detail: String,
}

/// 审计 action → 事件类别白名单映射（未列入的 action 跳过）：
/// - role_toggle：三路角色 / 订阅角色 / TUN / 悬浮球 / 全局总开关等用户可感知开关
/// - kernel：订阅内核生命周期、内核完整性、订阅增删更/激活、出站模式
/// - install：内核 / wintun 下载与手动安装
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

/// detail JSON → 人类可读描述。只取用白名单字段（名称/开关/地址等），
/// 绝不整体回显原始 JSON——审计虽不落密码/Token 明文，此处仍做结构性过滤。
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

/// 解析 JSONL 文本尾部事件（新的在前，最多 limit 条；跳过未白名单 action 与坏行）。
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

/// 事件中心数据源：从 gui-audit.jsonl 尾部倒读（至多 256KB，丢弃跨边界残行），
/// 取最新 limit 条白名单事件（新的在前）。文件不存在返回空 Vec。
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
    // 非头部起读时首行是残行，丢弃
    let text = match start {
        0 => text.into_owned(),
        _ => text.split_once('\n').map(|(_, rest)| rest.to_string()).unwrap_or_default(),
    };
    parse_events(&text, limit)
}

/// 构建内嵌节点配置（默认端口避让本地独立节点与 Docker 演示链）。
/// 扇出连接不再自 TOML 生成：以 SQLite connector 表为唯一事实来源（管理面 CRUD + 热操作）。
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_sub_mode_and_scripts() {
        // 旧版配置无新字段：serde default 兜底
        let v: RoleSettings = serde_json::from_str(
            r#"{"client":true,"server":false,"web":false}"#,
        )
        .unwrap();
        assert_eq!(v.sub_mode, "rule");
        assert!(v.sub_scripts.is_empty());
    }

    #[test]
    fn settings_scripts_roundtrip_with_order_and_enabled() {
        let mut v = RoleSettings::default();
        v.sub_mode = "global".into();
        v.sub_scripts = vec![
            SubScript { id: "a".into(), name: "甲".into(), code: "c1".into(), enabled: true, order: 0 },
            SubScript { id: "b".into(), name: "乙".into(), code: "c2".into(), enabled: false, order: 1 },
        ];
        let raw = serde_json::to_string(&v).unwrap();
        let back: RoleSettings = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.sub_mode, "global");
        assert_eq!(back.sub_scripts.len(), 2);
        assert_eq!(back.sub_scripts[0].id, "a");
        assert!(back.sub_scripts[0].enabled);
        assert!(!back.sub_scripts[1].enabled);
        assert_eq!(back.sub_scripts[1].order, 1);
        // 缺省 enabled/order 字段的旧脚本数据：enabled 默认 true、order 默认 0
        let legacy: SubScript =
            serde_json::from_str(r#"{"id":"x","name":"n","code":"c"}"#).unwrap();
        assert!(legacy.enabled);
        assert_eq!(legacy.order, 0);
    }

    #[test]
    fn settings_default_notify_and_reduce_effects() {
        // 旧版配置无新字段：serde default 兜底（通知默认开、性能模式默认关）
        let v: RoleSettings = serde_json::from_str(
            r#"{"client":true,"server":false,"web":false}"#,
        )
        .unwrap();
        assert!(v.notify_float_ball);
        assert!(!v.reduce_effects);
        // 持久化往返
        let mut v = RoleSettings::default();
        v.notify_float_ball = false;
        v.reduce_effects = true;
        let raw = serde_json::to_string(&v).unwrap();
        let back: RoleSettings = serde_json::from_str(&raw).unwrap();
        assert!(!back.notify_float_ball);
        assert!(back.reduce_effects);
    }

    #[test]
    fn parse_events_filters_and_orders() {
        let text = concat!(
            // 非白名单 action：跳过
            r#"{"ts":1,"action":"gui.dl_internal","user":"u","detail":{}}"#,
            "\n",
            // 坏行：跳过
            "{not-json}\n",
            // 白名单：角色开关
            r#"{"ts":2,"action":"gui.role_toggle","user":"u","detail":{"role":"client","on":false}}"#,
            "\n",
            // 白名单：内核
            r#"{"ts":3,"action":"gui.kernel_start","user":"u","detail":{}}"#,
            "\n",
            // 含敏感样式字段：detail 由白名单字段拼装，不回显原始 JSON
            r#"{"ts":4,"action":"gui.sysproxy_engage","user":"u","detail":{"server":"127.0.0.1:57890","token":"psk_secret"}}"#,
            "\n",
        );
        let ev = parse_events(text, 50);
        assert_eq!(ev.len(), 3);
        // 新的在前
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
        // 未白名单的一律跳过
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
        // 旧版配置无 TUN 字段：serde default 兜底
        let v: RoleSettings = serde_json::from_str(
            r#"{"client":true,"server":false,"web":false}"#,
        )
        .unwrap();
        assert!(!v.tun_mode);
        assert_eq!(v.external_upstream, DEFAULT_EXTERNAL_UPSTREAM);
        // 持久化往返
        let mut v = RoleSettings::default();
        v.tun_mode = true;
        v.external_upstream = "127.0.0.1:7897".into();
        let raw = serde_json::to_string(&v).unwrap();
        let back: RoleSettings = serde_json::from_str(&raw).unwrap();
        assert!(back.tun_mode);
        assert_eq!(back.external_upstream, "127.0.0.1:7897");
    }

    #[test]
    fn external_upstream_validation() {
        // 合法：回环 + 非保留端口
        assert_eq!(
            validate_external_upstream("127.0.0.1:7890").unwrap().to_string(),
            "127.0.0.1:7890"
        );
        assert!(validate_external_upstream("[::1]:7890").unwrap().ip().is_loopback());
        // 严禁回指本机端口（57890 本地代理 / 57892 内核 mixed / 59292 控制面）
        for p in [57890, 57892, 59292] {
            let addr = format!("127.0.0.1:{p}");
            assert!(validate_external_upstream(&addr).is_err(), "{addr} 应被拒绝");
        }
        // 非回环目标（会被 TUN 重捕获成环）
        assert!(validate_external_upstream("192.168.1.5:7890").is_err());
        assert!(validate_external_upstream("10.0.0.2:1080").is_err());
        // 非法格式 / 非法端口
        assert!(validate_external_upstream("not-an-addr").is_err());
        assert!(validate_external_upstream("127.0.0.1").is_err());
        assert!(validate_external_upstream("127.0.0.1:0").is_err());
        assert!(validate_external_upstream("example.com:7890").is_err());
    }
}
