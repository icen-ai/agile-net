//! 自定义规则（放行 / hosts 映射 / 组合）：模型、持久化、系统 hosts 托管、生效并集。
//!
//! - 数据落 `~/.agile-net/gui-custom-rules.json`（serde JSON，临时文件 + rename 原子写）
//! - 放行：通配 pattern（语义见 `agile_net_client::wildcard_match`），命中默认直连
//!   （连订阅也不过，优先于订阅回落与端点规则）；可选「经过订阅」走 mihomo 回落
//! - hosts 映射：hostname→IP（SwitchHosts 语义）；系统 hosts 可写则落系统
//!   （`# AgileNet begin/end` 托管块幂等写入），失败回落进程内映射（引擎 hosts_map）
//! - 组合：命名集合（成员 = 规则 key：自定义=其 id，拉取规则=`type:value` 小写）；
//!   生效规则 = 单条启停 ∪ 启用组合的成员（组合中的拉取规则 key 由前端经既有
//!   暂停接口另行处理，引擎侧仅消费自定义规则 id）

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

// ==================== 模型 ====================

/// 放行规则（通配 IP/域名过滤）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassRule {
    pub id: String,
    pub pattern: String,
    #[serde(default)]
    pub via_subscription: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// hosts 映射（用户自建；系统既有非托管映射不入库，读取时合并展示 source=system）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRule {
    pub id: String,
    pub hostname: String,
    pub ip: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 用户意图：写入系统 hosts（实际成败看每次托管块写入结果，失败即进程内映射）
    #[serde(default)]
    pub to_system: bool,
}

/// 规则组合（命名集合；rule_keys 混合自定义规则 id 与拉取规则 key）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCombo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub rule_keys: Vec<String>,
    #[serde(default)]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// 持久化数据（GUI 数据目录 JSON）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoreData {
    #[serde(default)]
    pub bypass: Vec<BypassRule>,
    #[serde(default)]
    pub hosts: Vec<HostRule>,
    #[serde(default)]
    pub combos: Vec<RuleCombo>,
}

/// 生效规则并集：单条 enabled ∪ 启用组合的成员（交叉组网）。
/// 返回引擎可直接消费的快照（组合中未命中任何自定义规则的 key 忽略——
/// 那是拉取规则 key，前端经暂停接口另行处理）。
pub fn effective_rules(data: &StoreData) -> agile_net_client::CustomRules {
    let combo_keys: std::collections::HashSet<&str> = data
        .combos
        .iter()
        .filter(|c| c.enabled)
        .flat_map(|c| c.rule_keys.iter().map(|k| k.as_str()))
        .collect();
    let effective = |id: &str, enabled: bool| enabled || combo_keys.contains(id);
    agile_net_client::CustomRules {
        bypass: data
            .bypass
            .iter()
            .filter(|r| effective(&r.id, r.enabled))
            .map(|r| agile_net_client::CustomBypassRule {
                pattern: r.pattern.clone(),
                via_subscription: r.via_subscription,
            })
            .collect(),
        hosts: data
            .hosts
            .iter()
            .filter(|r| effective(&r.id, r.enabled))
            .map(|r| (r.hostname.clone(), r.ip.clone()))
            .collect(),
    }
}

// ==================== 存储（原子写） ====================

fn store_path() -> PathBuf {
    crate::roles::data_dir().join("gui-custom-rules.json")
}

/// 原子写：临时文件 + rename（避免半截 JSON 被下次启动读到）。
fn atomic_write(path: &Path, data: &str) -> Result<(), String> {
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "tmp".into())
    ));
    std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn load_from(path: &Path) -> StoreData {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_to(path: &Path, data: &StoreData) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let raw = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    atomic_write(path, &raw)
}

struct Store {
    path: PathBuf,
    data: StoreData,
}

static STORE: OnceLock<RwLock<Store>> = OnceLock::new();

fn global() -> &'static RwLock<Store> {
    STORE.get_or_init(|| {
        let path = store_path();
        let data = load_from(&path);
        RwLock::new(Store { path, data })
    })
}

fn read_store() -> RwLockReadGuard<'static, Store> {
    global().read().unwrap_or_else(|e| e.into_inner())
}

fn write_store() -> RwLockWriteGuard<'static, Store> {
    global().write().unwrap_or_else(|e| e.into_inner())
}

/// 当前数据快照（只读；命令层列表视图用）。
pub fn snapshot() -> StoreData {
    read_store().data.clone()
}

/// 变更落盘 + 引擎热更（全部写路径共用）。
fn commit(
    guard: &mut RwLockWriteGuard<'static, Store>,
    client: &agile_net_client::AgileNetClient,
) -> Result<(), String> {
    save_to(&guard.path.clone(), &guard.data)?;
    client.set_custom_rules(effective_rules(&guard.data));
    Ok(())
}

// ==================== 规则操作 ====================

fn new_id(prefix: &str) -> String {
    format!("{}-{}", prefix, &uuid::Uuid::new_v4().simple().to_string()[..8])
}

/// 规范化主机输入（一键加规则用）：去 scheme/路径/query/端口/末尾点，小写化，
/// 校验结果为域名或 IP 字面量；非法输入返回中文错误。
pub fn normalize_host(input: &str) -> Result<String, String> {
    let mut h = input.trim().to_lowercase();
    if let Some(i) = h.find("://") {
        h = h[i + 3..].to_string();
    }
    if let Some(i) = h.find(['/', '?', '#']) {
        h.truncate(i);
    }
    // 去端口（仅当冒号后全为数字且前面无冒号——排除 IPv6 字面量）
    if let Some(i) = h.rfind(':') {
        if !h[..i].contains(':') && !h[i + 1..].is_empty() && h[i + 1..].chars().all(|c| c.is_ascii_digit()) {
            h.truncate(i);
        }
    }
    while h.ends_with('.') {
        h.pop();
    }
    const BAD: &str = "主机名不合法（应为域名或 IP，如 example.com）";
    if h.is_empty() || h.chars().any(|c| c.is_whitespace()) {
        return Err(BAD.into());
    }
    // IPv6 字面量（去掉方括号后直收）
    let bare = h.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return Ok(bare.to_string());
    }
    // 域名校验：label 仅字母/数字/连字符，不为空、不超长、连字符不在首尾
    if !h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err(BAD.into());
    }
    if h.split('.')
        .any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-'))
    {
        return Err(BAD.into());
    }
    Ok(h)
}

/// 新增放行规则（同 pattern 去重；默认启用），返回 id。
pub fn add_bypass(
    client: &agile_net_client::AgileNetClient,
    pattern: &str,
    via_subscription: bool,
) -> Result<String, String> {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern.chars().any(|c| c.is_whitespace()) {
        return Err("匹配目标不能为空且不含空白字符".into());
    }
    let mut guard = write_store();
    if guard
        .data
        .bypass
        .iter()
        .any(|r| r.pattern.eq_ignore_ascii_case(pattern))
    {
        return Err("相同匹配目标的放行规则已存在".into());
    }
    let id = new_id("bypass");
    guard.data.bypass.push(BypassRule {
        id: id.clone(),
        pattern: pattern.to_string(),
        via_subscription,
        enabled: true,
    });
    commit(&mut guard, client)?;
    crate::roles::audit(
        "gui.custom_rule",
        serde_json::json!({"action": "add_bypass", "pattern": pattern}),
    );
    Ok(id)
}

/// 新增 hosts 映射（hostname 去重；默认启用）。
/// to_system=true 时尝试落系统 hosts 托管块，失败回落进程内（返回 persisted 标注）。
pub fn add_host(
    client: &agile_net_client::AgileNetClient,
    hostname: &str,
    ip: &str,
    to_system: bool,
) -> Result<(String, &'static str), String> {
    let hostname = hostname.trim().to_lowercase();
    if hostname.is_empty()
        || hostname
            .chars()
            .any(|c| c.is_whitespace() || c == '*' || c == '#')
    {
        return Err("主机名不合法".into());
    }
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        return Err("hosts 映射的主机名不能是 IP".into());
    }
    ip.trim()
        .parse::<std::net::IpAddr>()
        .map_err(|_| "IP 地址不合法".to_string())?;
    let mut guard = write_store();
    if guard.data.hosts.iter().any(|r| r.hostname == hostname) {
        return Err("该主机名的映射已存在".into());
    }
    let id = new_id("host");
    guard.data.hosts.push(HostRule {
        id: id.clone(),
        hostname: hostname.clone(),
        ip: ip.trim().to_string(),
        enabled: true,
        to_system,
    });
    let persisted = if to_system && rewrite_system_hosts(&mut guard) {
        "system"
    } else {
        "internal"
    };
    commit(&mut guard, client)?;
    crate::roles::audit(
        "gui.custom_rule",
        serde_json::json!({"action": "add_host", "hostname": hostname, "persisted": persisted}),
    );
    Ok((id, persisted))
}

/// 单条启停（bypass / hosts 通用 id 查找；系统既有映射只读）。
pub fn set_enabled(
    client: &agile_net_client::AgileNetClient,
    id: &str,
    enabled: bool,
) -> Result<(), String> {
    if id.starts_with("sys-") {
        return Err("系统 hosts 既有映射为只读（非本软件托管）".into());
    }
    let mut guard = write_store();
    let mut touched_system_host = false;
    if let Some(r) = guard.data.bypass.iter_mut().find(|r| r.id == id) {
        r.enabled = enabled;
    } else if let Some(r) = guard.data.hosts.iter_mut().find(|r| r.id == id) {
        r.enabled = enabled;
        touched_system_host = r.to_system;
    } else {
        return Err("规则不存在".into());
    }
    if touched_system_host {
        rewrite_system_hosts(&mut guard);
    }
    commit(&mut guard, client)?;
    Ok(())
}

/// 删除规则（bypass / hosts 通用；级联清理组合成员中的失效 key）。
pub fn remove(client: &agile_net_client::AgileNetClient, id: &str) -> Result<(), String> {
    if id.starts_with("sys-") {
        return Err("系统 hosts 既有映射为只读（非本软件托管）".into());
    }
    let mut guard = write_store();
    let before = guard.data.bypass.len();
    guard.data.bypass.retain(|r| r.id != id);
    let mut removed_host: Option<HostRule> = None;
    if guard.data.bypass.len() == before {
        if let Some(pos) = guard.data.hosts.iter().position(|r| r.id == id) {
            removed_host = Some(guard.data.hosts.remove(pos));
        } else {
            return Err("规则不存在".into());
        }
    }
    // 级联清理组合中的失效成员 key
    for c in &mut guard.data.combos {
        c.rule_keys.retain(|k| k != id);
    }
    if removed_host.as_ref().is_some_and(|r| r.to_system) {
        rewrite_system_hosts(&mut guard);
    }
    commit(&mut guard, client)?;
    crate::roles::audit("gui.custom_rule", serde_json::json!({"action": "remove", "id": id}));
    Ok(())
}

// ==================== 组合操作 ====================

pub fn add_combo(client: &agile_net_client::AgileNetClient, name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("组合名称不能为空".into());
    }
    let mut guard = write_store();
    if guard.data.combos.iter().any(|c| c.name == name) {
        return Err("同名组合已存在".into());
    }
    let id = new_id("combo");
    guard.data.combos.push(RuleCombo {
        id: id.clone(),
        name: name.to_string(),
        rule_keys: Vec::new(),
        enabled: false,
    });
    commit(&mut guard, client)?;
    Ok(id)
}

pub fn update_combo(
    client: &agile_net_client::AgileNetClient,
    id: &str,
    name: &str,
    rule_keys: Vec<String>,
) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("组合名称不能为空".into());
    }
    let mut guard = write_store();
    if guard
        .data
        .combos
        .iter()
        .any(|c| c.name == name && c.id != id)
    {
        return Err("同名组合已存在".into());
    }
    let Some(c) = guard.data.combos.iter_mut().find(|c| c.id == id) else {
        return Err("组合不存在".into());
    };
    c.name = name.to_string();
    c.rule_keys = rule_keys;
    commit(&mut guard, client)?;
    Ok(())
}

pub fn remove_combo(client: &agile_net_client::AgileNetClient, id: &str) -> Result<(), String> {
    let mut guard = write_store();
    let before = guard.data.combos.len();
    guard.data.combos.retain(|c| c.id != id);
    if guard.data.combos.len() == before {
        return Err("组合不存在".into());
    }
    commit(&mut guard, client)?;
    Ok(())
}

pub fn set_combo_enabled(
    client: &agile_net_client::AgileNetClient,
    id: &str,
    enabled: bool,
) -> Result<(), String> {
    let mut guard = write_store();
    let Some(c) = guard.data.combos.iter_mut().find(|c| c.id == id) else {
        return Err("组合不存在".into());
    };
    c.enabled = enabled;
    commit(&mut guard, client)?;
    Ok(())
}

/// 启动恢复：把已持久化的生效规则热更进引擎（GUI setup 调用一次）。
pub fn restore(client: &agile_net_client::AgileNetClient) {
    let data = snapshot();
    client.set_custom_rules(effective_rules(&data));
}

// ==================== 系统 hosts ====================

/// 本软件 GUI 托管块标记（与客户端引擎 resolve 规则的 `# BEGIN/END AGILE-NET` 块相互独立）。
pub const GUI_BLOCK_BEGIN: &str = "# AgileNet begin";
pub const GUI_BLOCK_END: &str = "# AgileNet end";
const ENGINE_BLOCK_BEGIN: &str = "# BEGIN AGILE-NET";
const ENGINE_BLOCK_END: &str = "# END AGILE-NET";

pub fn system_hosts_path() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        PathBuf::from(root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

pub struct SystemHosts {
    path: PathBuf,
}

impl SystemHosts {
    pub fn new() -> Self {
        Self {
            path: system_hosts_path(),
        }
    }

    /// 指定路径（仅测试注入用，随测试构建编译）。
    #[cfg(test)]
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// 读取非托管条目（跳过注释/空行/本软件两个托管块；hostname 小写去重，先现优先）。
    /// 返回 (hostname, ip 字面量)。
    pub fn read_entries(&self) -> Vec<(String, String)> {
        let Ok(content) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        parse_hosts_entries(&content)
    }

    /// 幂等写入托管块（entries 为空 = 移除块；内容无变化不写盘）。权限不足等失败返回 Err。
    pub fn write_managed(&self, entries: &[(String, String)]) -> Result<(), String> {
        let content = std::fs::read_to_string(&self.path).unwrap_or_default();
        let cleaned = strip_block(&content, GUI_BLOCK_BEGIN, GUI_BLOCK_END);
        let mut new_content = cleaned;
        if !entries.is_empty() {
            if !new_content.is_empty() && !new_content.ends_with('\n') {
                new_content.push('\n');
            }
            new_content.push_str(GUI_BLOCK_BEGIN);
            new_content.push('\n');
            for (hostname, ip) in entries {
                new_content.push_str(&format!("{ip} {hostname}\n"));
            }
            new_content.push_str(GUI_BLOCK_END);
            new_content.push('\n');
        }
        if new_content == content {
            return Ok(());
        }
        atomic_write(&self.path, &new_content)
    }
}

/// 解析 hosts 文本：非注释、非空、非托管块条目 → (hostname 小写, ip 字面量)；hostname 去重。
fn parse_hosts_entries(content: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut in_gui = false;
    let mut in_engine = false;
    for line in content.lines() {
        let trimmed = line.trim();
        match trimmed {
            GUI_BLOCK_BEGIN => in_gui = true,
            GUI_BLOCK_END => in_gui = false,
            ENGINE_BLOCK_BEGIN => in_engine = true,
            ENGINE_BLOCK_END => in_engine = false,
            _ => {}
        }
        if in_gui || in_engine || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut tokens = trimmed.split_whitespace().peekable();
        let Some(ip) = tokens.next() else { continue };
        // 非 IP 行（如缺省对齐的注释残留）跳过
        if ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        for host in tokens {
            if host.starts_with('#') {
                break; // 行内注释
            }
            let host = host.to_lowercase();
            if !out.iter().any(|(h, _)| *h == host) {
                out.push((host, ip.to_string()));
            }
        }
    }
    out
}

/// 剔除指定标记块（语义对齐客户端引擎 strip_managed_block）。
fn strip_block(content: &str, begin: &str, end: &str) -> String {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == begin {
            in_block = true;
            continue;
        }
        if trimmed == end {
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

/// 以当前库内容重写系统 hosts 托管块（启用且 to_system 的映射）；返回是否写入成功。
/// 失败（无权限等）不视为错误——对应规则回落进程内映射，引擎照常生效。
fn rewrite_system_hosts(guard: &mut RwLockWriteGuard<'static, Store>) -> bool {
    let entries: Vec<(String, String)> = guard
        .data
        .hosts
        .iter()
        .filter(|r| r.enabled && r.to_system)
        .map(|r| (r.hostname.clone(), r.ip.clone()))
        .collect();
    SystemHosts::new().write_managed(&entries).is_ok()
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anet-cr-test-{}-{}",
            tag,
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn br(id: &str, pattern: &str, via: bool, enabled: bool) -> BypassRule {
        BypassRule {
            id: id.into(),
            pattern: pattern.into(),
            via_subscription: via,
            enabled,
        }
    }

    fn hr(id: &str, host: &str, ip: &str, enabled: bool) -> HostRule {
        HostRule {
            id: id.into(),
            hostname: host.into(),
            ip: ip.into(),
            enabled,
            to_system: false,
        }
    }

    fn combo(id: &str, keys: &[&str], enabled: bool) -> RuleCombo {
        RuleCombo {
            id: id.into(),
            name: id.into(),
            rule_keys: keys.iter().map(|k| k.to_string()).collect(),
            enabled,
        }
    }

    // ---------- 主机输入规范化 ----------

    #[test]
    fn normalize_host_strips_noise_and_validates() {
        // 去 scheme / 端口 / 路径 / query / 末尾点，小写化
        assert_eq!(normalize_host("https://Example.COM:8443/a/b?x=1#f").unwrap(), "example.com");
        assert_eq!(normalize_host("api.example.com.").unwrap(), "api.example.com");
        assert_eq!(normalize_host("  baidu.com  ").unwrap(), "baidu.com");
        // IP 直收（IPv6 方括号去掉）
        assert_eq!(normalize_host("1.2.3.4").unwrap(), "1.2.3.4");
        assert_eq!(normalize_host("[::1]").unwrap(), "::1");
        // IPv6 字面量不被端口剥离误伤
        assert_eq!(normalize_host("2001:db8::1").unwrap(), "2001:db8::1");
        // 非法输入
        assert!(normalize_host("").is_err());
        assert!(normalize_host("exa mple.com").is_err());
        assert!(normalize_host("-bad.com").is_err());
        assert!(normalize_host("bad-.com").is_err());
        assert!(normalize_host("a..com").is_err());
        assert!(normalize_host("under_score.com").is_err());
        assert!(normalize_host("http://").is_err());
    }

    // ---------- 存储读写 ----------

    #[test]
    fn store_roundtrip_and_corrupt_fallback() {
        let dir = tmp_dir("store");
        let path = dir.join("rules.json");
        let data = StoreData {
            bypass: vec![br("bypass-1", "*.baidu.com", true, false)],
            hosts: vec![hr("host-1", "git.internal", "10.0.0.9", true)],
            combos: vec![combo("combo-1", &["bypass-1", "host:x.com"], true)],
        };
        save_to(&path, &data).unwrap();
        let loaded = load_from(&path);
        assert_eq!(loaded.bypass.len(), 1);
        assert_eq!(loaded.bypass[0].pattern, "*.baidu.com");
        assert!(loaded.bypass[0].via_subscription);
        assert!(!loaded.bypass[0].enabled); // enabled=false 须持久化
        assert_eq!(loaded.hosts[0].hostname, "git.internal");
        assert_eq!(loaded.combos[0].rule_keys.len(), 2);
        // 缺失字段向后兼容：最简 JSON 也能读
        std::fs::write(&path, r#"{"bypass":[{"id":"x","pattern":"a.com"}]}"#).unwrap();
        let loaded = load_from(&path);
        assert!(loaded.bypass[0].enabled); // 缺省 true
        assert!(!loaded.bypass[0].via_subscription);
        // 损坏文件 → 空库兜底
        std::fs::write(&path, "not json{{{").unwrap();
        let loaded = load_from(&path);
        assert!(loaded.bypass.is_empty() && loaded.hosts.is_empty() && loaded.combos.is_empty());
        // 不存在 → 空库
        let loaded = load_from(&dir.join("nope.json"));
        assert!(loaded.bypass.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_replaces_and_cleans_tmp() {
        let dir = tmp_dir("atomic");
        let path = dir.join("rules.json");
        atomic_write(&path, "first").unwrap();
        atomic_write(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        // 临时文件不残留
        assert!(!dir.join("rules.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- 生效并集 ----------

    #[test]
    fn effective_union_single_and_combo() {
        let data = StoreData {
            bypass: vec![
                br("b1", "a.com", false, true),   // 单条启用
                br("b2", "b.com", false, false),  // 停用，但在启用组合中
                br("b3", "c.com", false, false),  // 停用，组合未含
                br("b4", "d.com", false, false),  // 停用，组合含但组合停用
            ],
            hosts: vec![
                hr("h1", "x.internal", "10.0.0.1", false), // 停用，但在启用组合中
                hr("h2", "y.internal", "10.0.0.2", true),
            ],
            combos: vec![
                combo("c1", &["b2", "h1", "host:pull.com"], true), // 启用（含拉取规则 key）
                combo("c2", &["b4"], false),                       // 停用
            ],
        };
        let eff = effective_rules(&data);
        let pats: Vec<&str> = eff.bypass.iter().map(|b| b.pattern.as_str()).collect();
        assert_eq!(pats, vec!["a.com", "b.com"]); // b1 单条 ∪ b2 组合；b3/b4 不生效
        let hosts: Vec<&str> = eff.hosts.iter().map(|(h, _)| h.as_str()).collect();
        assert_eq!(hosts, vec!["x.internal", "y.internal"]);
    }

    #[test]
    fn effective_combo_toggle_cross_group() {
        // 交叉组网：同一条规则可被多个组合引用；任一启用组合含之即生效
        let mut data = StoreData {
            bypass: vec![br("b1", "a.com", true, false)],
            hosts: vec![],
            combos: vec![combo("c1", &["b1"], false), combo("c2", &["b1"], true)],
        };
        assert_eq!(effective_rules(&data).bypass.len(), 1);
        data.combos[1].enabled = false;
        assert_eq!(effective_rules(&data).bypass.len(), 0);
        data.combos[0].enabled = true;
        let eff = effective_rules(&data);
        assert_eq!(eff.bypass.len(), 1);
        assert!(eff.bypass[0].via_subscription);
    }

    // ---------- 系统 hosts 解析 ----------

    #[test]
    fn parse_hosts_skips_comments_and_managed_blocks() {
        let content = r#"# 注释行
127.0.0.1 localhost
::1 localhost ip6-localhost
10.0.0.1  git.internal  git2.internal   # 行内注释
# BEGIN AGILE-NET
127.0.0.1 engine.internal
# END AGILE-NET
# AgileNet begin
1.2.3.4 gui.internal
# AgileNet end
bad-line-here
192.168.1.1
8.8.8.8 DNS.EXAMPLE.com
10.0.0.1 git.internal
"#;
        let entries = parse_hosts_entries(content);
        // 托管块（两个标记体系）与注释/垃圾行被跳过；hostname 小写去重（先现优先）
        assert_eq!(
            entries,
            vec![
                ("localhost".to_string(), "127.0.0.1".to_string()),
                ("ip6-localhost".to_string(), "::1".to_string()),
                ("git.internal".to_string(), "10.0.0.1".to_string()),
                ("git2.internal".to_string(), "10.0.0.1".to_string()),
                ("dns.example.com".to_string(), "8.8.8.8".to_string()),
            ]
        );
    }

    #[test]
    fn read_entries_missing_file_is_empty() {
        let sh = SystemHosts::with_path(tmp_dir("missing").join("hosts"));
        assert!(sh.read_entries().is_empty());
    }

    // ---------- 系统 hosts 托管块幂等 ----------

    #[test]
    fn managed_block_write_idempotent_and_preserves_others() {
        let dir = tmp_dir("hosts");
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n10.1.1.1 keep.me\n").unwrap();
        let sh = SystemHosts::with_path(path.clone());

        let entries = vec![
            ("git.internal".to_string(), "10.0.0.9".to_string()),
            ("ops.internal".to_string(), "10.0.0.10".to_string()),
        ];
        sh.write_managed(&entries).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        assert!(first.contains("127.0.0.1 localhost"));
        assert!(first.contains("10.1.1.1 keep.me"));
        assert!(first.contains("# AgileNet begin\n10.0.0.9 git.internal\n10.0.0.10 ops.internal\n# AgileNet end\n"));
        // 二次写入内容不变（幂等）
        sh.write_managed(&entries).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        // 变更条目：旧块被整体替换而非叠加
        let entries2 = vec![("git.internal".to_string(), "10.0.0.11".to_string())];
        sh.write_managed(&entries2).unwrap();
        let third = std::fs::read_to_string(&path).unwrap();
        assert!(!third.contains("ops.internal"));
        assert!(third.contains("10.0.0.11 git.internal"));
        // 空条目 = 移除块，其余行原样
        sh.write_managed(&[]).unwrap();
        let cleared = std::fs::read_to_string(&path).unwrap();
        assert!(!cleared.contains("AgileNet"));
        assert_eq!(cleared, "127.0.0.1 localhost\n10.1.1.1 keep.me\n");
        // 非托管条目仍可被读取出（source=system 展示口径）
        assert_eq!(
            sh.read_entries(),
            vec![
                ("localhost".to_string(), "127.0.0.1".to_string()),
                ("keep.me".to_string(), "10.1.1.1".to_string()),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn managed_block_replaces_stale_block_without_trailing_newline() {
        let dir = tmp_dir("hosts2");
        let path = dir.join("hosts");
        // 无结尾换行的既有文件 + 旧托管块
        std::fs::write(
            &path,
            "127.0.0.1 localhost\n# AgileNet begin\n9.9.9.9 stale.internal\n# AgileNet end",
        )
        .unwrap();
        let sh = SystemHosts::with_path(path.clone());
        sh.write_managed(&[("a.internal".to_string(), "1.1.1.1".to_string())])
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("stale.internal"));
        assert!(content.contains("1.1.1.1 a.internal"));
        assert!(content.contains("127.0.0.1 localhost"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
