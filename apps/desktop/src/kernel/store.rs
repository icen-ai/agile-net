//! Split from subscription.rs: subscription manifest persistence and CRUD (pure move, zero logic changes)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::roles;

use super::api::kernel_api;
use super::manager::kernel_asset;

// ==================== Subscription manifest (sensitive credentials, 0600) ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    /// Currently active subscription (global single choice; the kernel loads only the active one)
    #[serde(default)]
    pub active: bool,
    /// Last fetch/refresh time (seconds)
    #[serde(default)]
    pub updated_at: Option<u64>,
    /// Node count (counted at fetch time)
    #[serde(default)]
    pub node_count: usize,
    /// Traffic info (subscription-userinfo response header)
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
    #[serde(default)]
    pub total: u64,
    /// Expiry timestamp (seconds; 0/None = never expires)
    #[serde(default)]
    pub expire: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct SubStore {
    /// external-controller auth secret (randomly generated and persisted on first launch)
    #[serde(default)]
    pub(crate) secret: String,
    #[serde(default)]
    pub(crate) subscriptions: Vec<Subscription>,
}

pub(crate) fn store_path() -> PathBuf {
    roles::data_dir().join("subscriptions.json")
}

pub fn kernel_dir() -> PathBuf {
    roles::data_dir().join("mihomo")
}

pub(crate) fn kernel_bin_path() -> PathBuf {
    let name = if cfg!(windows) { "mihomo.exe" } else { "mihomo" };
    kernel_dir().join(name)
}

/// Whether the kernel binary is installed.
pub fn kernel_bin_exists() -> bool {
    kernel_bin_path().exists()
}

/// Whether the current platform supports the subscription kernel (has a pinned-version asset).
pub fn kernel_supported() -> bool {
    kernel_asset().is_some()
}

pub(crate) fn config_path() -> PathBuf {
    kernel_dir().join("config.yaml")
}

pub(crate) fn load_store() -> SubStore {
    std::fs::read_to_string(store_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub(crate) fn save_store(store: &SubStore) -> Result<(), String> {
    let dir = roles::data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = store_path();
    let data = serde_json::to_string_pretty(store).map_err(|e| e.to_string())?;
    std::fs::write(&path, data).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub(crate) fn ensure_secret(store: &mut SubStore) -> String {
    if store.secret.is_empty() {
        store.secret = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
    }
    store.secret.clone()
}

/// Redact a subscription URL (for audit/logs): scheme://host/…first 8 path chars
pub fn mask_url(url: &str) -> String {
    match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            match rest.find('/') {
                Some(j) => {
                    let path = &rest[j + 1..];
                    format!("{}://{}/…{}", &url[..i], &rest[..j], &path[..path.len().min(8)])
                }
                None => url.to_string(),
            }
        }
        None => "…".into(),
    }
}

// ==================== Subscription manifest operations ====================

/// Fetch a subscription and parse user/traffic info (subscription-userinfo header) plus node count.
/// Errors if the fetch fails or the body does not look like a Clash config — add/refresh require a successful fetch.
async fn fetch_subscription(url: &str) -> Result<(u64, u64, u64, Option<u64>, usize), String> {
    let client = reqwest::Client::builder()
        .user_agent("clash.meta/v1.19.29")
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("订阅拉取失败: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("订阅拉取失败 (HTTP {})", resp.status()));
    }
    // subscription-userinfo: upload=..; download=..; total=..; expire=..
    let mut upload = 0u64;
    let mut download = 0u64;
    let mut total = 0u64;
    let mut expire = None;
    let mut used_alt = 0u64;
    if let Some(v) = resp
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
    {
        for part in v.split(';') {
            let part = part.trim();
            if let Some((k, val)) = part.split_once('=') {
                let n: u64 = val.trim().parse().unwrap_or(0);
                match k.trim() {
                    "upload" => upload = n,
                    "download" => download = n,
                    "total" => total = n,
                    // Non-standard field: some panels only return used (may be fractional); fallback when u/d are 0
                    "used" => used_alt = val.trim().parse::<f64>().unwrap_or(0.0) as u64,
                    "expire" => {
                        if n > 0 {
                            expire = Some(n)
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if upload + download == 0 && used_alt > 0 {
        download = used_alt;
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let node_count = analyze_subscription(&body)?;
    Ok((upload, download, total, expire, node_count))
}

/// Sniff a subscription body and estimate node count (shared entry for URL fetch and local import):
/// Clash YAML ("name:" lines inside the proxies: section) or base64/plaintext share links (containing "://").
fn analyze_subscription(body: &str) -> Result<usize, String> {
    let node_count = if body.contains("proxies:") {
        let start = body.find("proxies:").unwrap_or(0);
        let end = body.find("proxy-groups:").unwrap_or(body.len());
        let section = &body[start..end.max(start)];
        section
            .lines()
            .filter(|l| l.trim_start().starts_with("name:"))
            .count()
    } else {
        let decoded = base64_decode_loose(body);
        let text = decoded.as_deref().unwrap_or(body);
        text.lines().filter(|l| l.contains("://")).count()
    };
    if node_count == 0 {
        return Err("订阅内容无法识别（不是 Clash 配置或分享链接）".into());
    }
    Ok(node_count)
}

/// Lenient base64 decoding (handles unpadded/wrapped subscription bodies)
fn base64_decode_loose(s: &str) -> Option<String> {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, &c) in TBL.iter().enumerate() {
        map[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        let v = map[b as usize];
        if v == 255 {
            continue;
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    String::from_utf8(out).ok().filter(|s| s.contains("://"))
}

pub fn list_subscriptions() -> Vec<Subscription> {
    load_store().subscriptions
}

/// Current subscription manifest (for the config generation pipeline)
pub(crate) fn current_store() -> SubStore {
    load_store()
}

/// Add a subscription: fetch-validates first (fails if unreachable/unrecognizable); the first subscription is auto-activated.
pub async fn add_subscription(name: &str, url: &str) -> Result<Subscription, String> {
    let url = url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("订阅地址须为 http(s) URL".into());
    }
    let (upload, download, total, expire, node_count) = fetch_subscription(url).await?;
    let mut store = load_store();
    ensure_secret(&mut store);
    let first = store.subscriptions.is_empty();
    let ts = now_ts();
    let sub = Subscription {
        id: uuid::Uuid::new_v4().simple().to_string(),
        name: if name.trim().is_empty() {
            format!("订阅 {}", store.subscriptions.len() + 1)
        } else {
            name.trim().to_string()
        },
        url: url.to_string(),
        active: first,
        updated_at: Some(ts),
        node_count,
        upload,
        download,
        total,
        expire,
    };
    store.subscriptions.push(sub.clone());
    save_store(&store)?;
    roles::audit(
        "gui.subscription_add",
        serde_json::json!({"name": sub.name, "url": mask_url(&sub.url), "nodes": node_count}),
    );
    Ok(sub)
}

pub fn remove_subscription(id: &str) -> Result<(), String> {
    let mut store = load_store();
    let before = store.subscriptions.len();
    let was_active = store.subscriptions.iter().any(|s| s.id == id && s.active);
    // Cascade-cleanup of on-disk YAML for locally imported subscriptions (only local-*.yaml under this app's kernel dir, to avoid deleting user files)
    let local_file = store
        .subscriptions
        .iter()
        .find(|s| s.id == id)
        .and_then(|s| s.url.strip_prefix("file://"))
        .map(std::path::PathBuf::from)
        .filter(|p| {
            p.parent() == Some(kernel_dir().as_path())
                && p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("local-"))
                    .unwrap_or(false)
        });
    store.subscriptions.retain(|s| s.id != id);
    if store.subscriptions.len() == before {
        return Err("订阅不存在".into());
    }
    // Active item deleted: activate the first one in order
    if was_active {
        if let Some(first) = store.subscriptions.first_mut() {
            first.active = true;
        }
    }
    save_store(&store)?;
    if let Some(p) = local_file {
        let _ = std::fs::remove_file(p);
    }
    roles::audit("gui.subscription_remove", serde_json::json!({"id": id}));
    Ok(())
}

/// Import a local YAML subscription: sniff content (same analyze entry as URL fetch) → write to
/// mihomo/local-<id>.yaml → store (url recorded with a file:// prefix, provider rendered as type: file).
/// Local subscriptions have no online traffic info; upload/download/total stay 0; online refresh unsupported.
pub fn add_local_subscription(name: &str, body: &str) -> Result<Subscription, String> {
    let node_count = analyze_subscription(body)?;
    let mut store = load_store();
    ensure_secret(&mut store);
    let first = store.subscriptions.is_empty();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let dir = kernel_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join(format!("local-{id}.yaml"));
    std::fs::write(&file, body).map_err(|e| format!("订阅文件落盘失败: {e}"))?;
    let sub = Subscription {
        id,
        name: if name.trim().is_empty() {
            format!("订阅 {}", store.subscriptions.len() + 1)
        } else {
            name.trim().to_string()
        },
        url: format!("file://{}", file.to_string_lossy()),
        active: first,
        updated_at: Some(now_ts()),
        node_count,
        upload: 0,
        download: 0,
        total: 0,
        expire: None,
    };
    store.subscriptions.push(sub.clone());
    save_store(&store)?;
    roles::audit(
        "gui.subscription_import",
        serde_json::json!({"name": sub.name, "nodes": node_count}),
    );
    Ok(sub)
}

/// Single-choice activation: only one active; returns the newly activated item.
pub fn set_active_subscription(id: &str) -> Result<Subscription, String> {
    let mut store = load_store();
    if !store.subscriptions.iter().any(|s| s.id == id) {
        return Err("订阅不存在".into());
    }
    for s in store.subscriptions.iter_mut() {
        s.active = s.id == id;
    }
    let sub = store
        .subscriptions
        .iter()
        .find(|s| s.id == id)
        .cloned()
        .unwrap();
    save_store(&store)?;
    roles::audit(
        "gui.subscription_activate",
        serde_json::json!({"name": sub.name}),
    );
    Ok(sub)
}

/// Refresh a subscription: re-fetch (updates traffic/expiry/node count/timestamp); if active, also notify the kernel to update the provider.
pub async fn update_subscription(id: &str) -> Result<Subscription, String> {
    let mut store = load_store();
    let idx = store
        .subscriptions
        .iter()
        .position(|s| s.id == id)
        .ok_or("订阅不存在")?;
    let url = store.subscriptions[idx].url.clone();
    if url.starts_with("file://") {
        return Err("本地导入的订阅不支持在线刷新（重新导入即可更新）".into());
    }
    let (upload, download, total, expire, node_count) = fetch_subscription(&url).await?;
    {
        let s = &mut store.subscriptions[idx];
        s.upload = upload;
        s.download = download;
        s.total = total;
        s.expire = expire;
        s.node_count = node_count;
        s.updated_at = Some(now_ts());
    }
    let sub = store.subscriptions[idx].clone();
    save_store(&store)?;
    if sub.active {
        if let Ok(api) = kernel_api().await {
            let _ = api.update_provider().await; // failure is non-blocking (next scheduled refresh self-heals)
        }
    }
    roles::audit(
        "gui.subscription_update",
        serde_json::json!({"name": sub.name, "url": mask_url(&sub.url)}),
    );
    Ok(sub)
}

pub(crate) fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ==================== Proxy list cache (read-only proxy page when the kernel is not running) ====================

fn proxy_cache_path() -> PathBuf {
    roles::data_dir().join("proxy-cache.json")
}

/// Merge provider node details (type/history) into the /proxies payload —
/// provider nodes are not in the global /proxies registry; the frontend shows the protocol via `PROXY_DATA[name].type`.
/// Existing entries (groups/built-ins) are not overwritten.
pub fn merge_provider_details(v: &mut serde_json::Value, pv: &serde_json::Value) {
    let (Some(map), Some(providers)) = (
        v["proxies"].as_object_mut(),
        pv["providers"].as_object(),
    ) else {
        return;
    };
    for p in providers.values() {
        let Some(list) = p["proxies"].as_array() else {
            continue;
        };
        for item in list {
            let Some(name) = item["name"].as_str() else {
                continue;
            };
            map.entry(name.to_string()).or_insert_with(|| {
                serde_json::json!({
                    "type": item["type"],
                    "history": item["history"],
                })
            });
        }
    }
}

/// Persist the most recent successful /proxies snapshot.
pub fn save_proxy_cache(v: &serde_json::Value) {
    if !v["proxies"].is_object() {
        return;
    }
    let data = serde_json::json!({"ts": now_ts(), "proxies": v["proxies"]});
    if let Ok(s) = serde_json::to_string(&data) {
        let _ = std::fs::write(proxy_cache_path(), s);
    }
}

/// Load the cached snapshot (tagged with `cached: true`; the frontend degrades to read-only display accordingly).
pub fn load_proxy_cache() -> Option<serde_json::Value> {
    let s = std::fs::read_to_string(proxy_cache_path()).ok()?;
    let mut v: serde_json::Value = serde_json::from_str(&s).ok()?;
    v["cached"] = serde_json::Value::Bool(true);
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_url_hides_token() {
        assert_eq!(
            mask_url("https://sub.example.com/api/v1/client/subscribe?token=deadbeef12345678"),
            "https://sub.example.com/…api/v1/c"
        );
        assert_eq!(mask_url("not-a-url"), "…");
    }
}
