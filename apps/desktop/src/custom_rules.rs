//! Custom rules (bypass / hosts mapping / combos): model, persistence, system hosts management, effective union.
//!
//! - Persisted to `~/.agile-net/gui-custom-rules.json` (serde JSON, temp file + rename atomic write)
//! - Bypass: wildcard pattern (semantics see `agile_net_client::wildcard_match`); hits go direct by default
//!   (not even via the subscription, taking precedence over subscription fallback and endpoint rules); optional "via subscription" uses the mihomo fallback
//! - hosts mapping: hostname→IP (SwitchHosts semantics); written to the system hosts when writable
//!   (`# AgileNet begin/end` managed block written idempotently), falling back to in-process mapping (engine hosts_map) on failure
//! - Combos: named sets (members = rule keys: custom = its id, pulled rules = `type:value` lowercase);
//!   effective rules = individual toggles ∪ members of enabled combos (pulled-rule keys in combos are handled
//!   separately by the frontend via the existing pause API; the engine only consumes custom rule ids)

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

// ==================== Model ====================

/// Bypass rule (wildcard IP/domain filter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassRule {
    pub id: String,
    pub pattern: String,
    #[serde(default)]
    pub via_subscription: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// hosts mapping (user-created; pre-existing unmanaged system mappings are not stored, merged in at read time with source=system).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRule {
    pub id: String,
    pub hostname: String,
    pub ip: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// User intent: write to system hosts (actual success depends on each managed-block write; failure means in-process mapping)
    #[serde(default)]
    pub to_system: bool,
}

/// Rule combo (named set; rule_keys mixes custom rule ids and pulled-rule keys).
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

/// Persisted data (JSON in the GUI data directory).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoreData {
    #[serde(default)]
    pub bypass: Vec<BypassRule>,
    #[serde(default)]
    pub hosts: Vec<HostRule>,
    #[serde(default)]
    pub combos: Vec<RuleCombo>,
}

/// Effective rule union: individually enabled ∪ members of enabled combos (cross-grouping).
/// Returns a snapshot the engine can consume directly (combo keys matching no custom rule are ignored —
/// those are pulled-rule keys, handled separately by the frontend via the pause API).
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

// ==================== Storage (atomic write) ====================

fn store_path() -> PathBuf {
    crate::roles::data_dir().join("gui-custom-rules.json")
}

/// Atomic write: temp file + rename (avoids a half-written JSON being read on next startup).
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

/// Current data snapshot (read-only; for the command layer's list views).
pub fn snapshot() -> StoreData {
    read_store().data.clone()
}

/// Persist changes + hot-update the engine (shared by all write paths).
fn commit(
    guard: &mut RwLockWriteGuard<'static, Store>,
    client: &agile_net_client::AgileNetClient,
) -> Result<(), String> {
    save_to(&guard.path.clone(), &guard.data)?;
    client.set_custom_rules(effective_rules(&guard.data));
    Ok(())
}

// ==================== Rule operations ====================

fn new_id(prefix: &str) -> String {
    format!("{}-{}", prefix, &uuid::Uuid::new_v4().simple().to_string()[..8])
}

/// Normalize host input (for one-click rule creation): strip scheme/path/query/port/trailing dots, lowercase,
/// and validate the result as a domain or IP literal; invalid input returns a Chinese error message.
pub fn normalize_host(input: &str) -> Result<String, String> {
    let mut h = input.trim().to_lowercase();
    if let Some(i) = h.find("://") {
        h = h[i + 3..].to_string();
    }
    if let Some(i) = h.find(['/', '?', '#']) {
        h.truncate(i);
    }
    // Strip port (only when everything after the colon is digits and no earlier colon exists — excludes IPv6 literals)
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
    // IPv6 literal (accepted as-is after stripping brackets)
    let bare = h.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return Ok(bare.to_string());
    }
    // Domain validation: labels only letters/digits/hyphens, non-empty, within length limits, no leading/trailing hyphen
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

/// Add a bypass rule (dedup by pattern; enabled by default), returns id.
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

/// Add a hosts mapping (dedup by hostname; enabled by default).
/// With to_system=true, tries writing the system hosts managed block, falling back to in-process on failure (returns persisted marker).
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

/// Toggle a single rule (shared id lookup for bypass / hosts; pre-existing system mappings are read-only).
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

/// Delete a rule (shared for bypass / hosts; cascades removal of dead keys from combo members).
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
    // Cascade-remove dead member keys from combos
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

// ==================== Combo operations ====================

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

/// Startup restore: hot-update persisted effective rules into the engine (called once by GUI setup).
pub fn restore(client: &agile_net_client::AgileNetClient) {
    let data = snapshot();
    client.set_custom_rules(effective_rules(&data));
}

// ==================== System hosts ====================

/// GUI managed-block markers of this app (independent of the client engine resolve-rule `# BEGIN/END AGILE-NET` block).
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

    /// Custom path (for test injection only, compiled with test builds).
    #[cfg(test)]
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Read unmanaged entries (skipping comments/blank lines/this app's two managed blocks; hostname lowercased and deduped, first occurrence wins).
    /// Returns (hostname, ip literal).
    pub fn read_entries(&self) -> Vec<(String, String)> {
        let Ok(content) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        parse_hosts_entries(&content)
    }

    /// Idempotently write the managed block (empty entries = remove block; no write when content unchanged). Returns Err on failures such as insufficient permissions.
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

/// Parse hosts text: non-comment, non-blank, non-managed-block entries → (hostname lowercased, ip literal); hostname deduped.
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
        // Skip non-IP lines (e.g. leftover comment fragments from misaligned lines)
        if ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        for host in tokens {
            if host.starts_with('#') {
                break; // inline comment
            }
            let host = host.to_lowercase();
            if !out.iter().any(|(h, _)| *h == host) {
                out.push((host, ip.to_string()));
            }
        }
    }
    out
}

/// Strip the given marker block (semantics aligned with the client engine's strip_managed_block).
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

/// Rewrite the system hosts managed block from the current store (enabled mappings with to_system); returns whether the write succeeded.
/// Failure (e.g. no permission) is not an error — affected rules fall back to in-process mapping and still take effect in the engine.
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

// ==================== Unit tests ====================

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

    // ---------- Host input normalization ----------

    #[test]
    fn normalize_host_strips_noise_and_validates() {
        // Strip scheme / port / path / query / trailing dots, lowercase
        assert_eq!(normalize_host("https://Example.COM:8443/a/b?x=1#f").unwrap(), "example.com");
        assert_eq!(normalize_host("api.example.com.").unwrap(), "api.example.com");
        assert_eq!(normalize_host("  baidu.com  ").unwrap(), "baidu.com");
        // IPs accepted as-is (IPv6 brackets stripped)
        assert_eq!(normalize_host("1.2.3.4").unwrap(), "1.2.3.4");
        assert_eq!(normalize_host("[::1]").unwrap(), "::1");
        // IPv6 literals unaffected by port stripping
        assert_eq!(normalize_host("2001:db8::1").unwrap(), "2001:db8::1");
        // Invalid input
        assert!(normalize_host("").is_err());
        assert!(normalize_host("exa mple.com").is_err());
        assert!(normalize_host("-bad.com").is_err());
        assert!(normalize_host("bad-.com").is_err());
        assert!(normalize_host("a..com").is_err());
        assert!(normalize_host("under_score.com").is_err());
        assert!(normalize_host("http://").is_err());
    }

    // ---------- Storage read/write ----------

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
        assert!(!loaded.bypass[0].enabled); // enabled=false must persist
        assert_eq!(loaded.hosts[0].hostname, "git.internal");
        assert_eq!(loaded.combos[0].rule_keys.len(), 2);
        // Backward compatibility with missing fields: minimal JSON still loads
        std::fs::write(&path, r#"{"bypass":[{"id":"x","pattern":"a.com"}]}"#).unwrap();
        let loaded = load_from(&path);
        assert!(loaded.bypass[0].enabled); // defaults to true
        assert!(!loaded.bypass[0].via_subscription);
        // Corrupt file → fall back to empty store
        std::fs::write(&path, "not json{{{").unwrap();
        let loaded = load_from(&path);
        assert!(loaded.bypass.is_empty() && loaded.hosts.is_empty() && loaded.combos.is_empty());
        // Missing file → empty store
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
        // No temp file left behind
        assert!(!dir.join("rules.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- Effective union ----------

    #[test]
    fn effective_union_single_and_combo() {
        let data = StoreData {
            bypass: vec![
                br("b1", "a.com", false, true),   // individually enabled
                br("b2", "b.com", false, false),  // disabled, but in an enabled combo
                br("b3", "c.com", false, false),  // disabled, in no combo
                br("b4", "d.com", false, false),  // disabled, in a combo that is disabled
            ],
            hosts: vec![
                hr("h1", "x.internal", "10.0.0.1", false), // disabled, but in an enabled combo
                hr("h2", "y.internal", "10.0.0.2", true),
            ],
            combos: vec![
                combo("c1", &["b2", "h1", "host:pull.com"], true), // enabled (contains pulled-rule key)
                combo("c2", &["b4"], false),                       // disabled
            ],
        };
        let eff = effective_rules(&data);
        let pats: Vec<&str> = eff.bypass.iter().map(|b| b.pattern.as_str()).collect();
        assert_eq!(pats, vec!["a.com", "b.com"]); // b1 individual ∪ b2 combo; b3/b4 not effective
        let hosts: Vec<&str> = eff.hosts.iter().map(|(h, _)| h.as_str()).collect();
        assert_eq!(hosts, vec!["x.internal", "y.internal"]);
    }

    #[test]
    fn effective_combo_toggle_cross_group() {
        // Cross-grouping: one rule can be referenced by multiple combos; any enabled combo containing it makes it effective
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

    // ---------- System hosts parsing ----------

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
        // Managed blocks (both marker schemes) and comment/garbage lines are skipped; hostname lowercased and deduped (first occurrence wins)
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

    // ---------- System hosts managed block idempotency ----------

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
        // Second write leaves content unchanged (idempotent)
        sh.write_managed(&entries).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        // Changed entries: old block is replaced wholesale, not appended
        let entries2 = vec![("git.internal".to_string(), "10.0.0.11".to_string())];
        sh.write_managed(&entries2).unwrap();
        let third = std::fs::read_to_string(&path).unwrap();
        assert!(!third.contains("ops.internal"));
        assert!(third.contains("10.0.0.11 git.internal"));
        // Empty entries = remove block, other lines untouched
        sh.write_managed(&[]).unwrap();
        let cleared = std::fs::read_to_string(&path).unwrap();
        assert!(!cleared.contains("AgileNet"));
        assert_eq!(cleared, "127.0.0.1 localhost\n10.1.1.1 keep.me\n");
        // Unmanaged entries still readable (source=system display semantics)
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
        // Existing file without trailing newline + stale managed block
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
