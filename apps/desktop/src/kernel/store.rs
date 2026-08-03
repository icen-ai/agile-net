//! 从 subscription.rs 拆分：订阅清单持久化与 CRUD（纯搬运，零逻辑变更）

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::roles;

use super::api::kernel_api;
use super::manager::kernel_asset;

// ==================== 订阅清单（敏感凭据，0600） ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    /// 当前激活的订阅（全局单选；内核只加载激活项）
    #[serde(default)]
    pub active: bool,
    /// 最近一次拉取/刷新时间（秒）
    #[serde(default)]
    pub updated_at: Option<u64>,
    /// 节点数（拉取时统计）
    #[serde(default)]
    pub node_count: usize,
    /// 流量信息（subscription-userinfo 响应头）
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
    #[serde(default)]
    pub total: u64,
    /// 到期时间戳（秒；0/None = 长期有效）
    #[serde(default)]
    pub expire: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct SubStore {
    /// external-controller 鉴权密钥（首启随机生成持久化）
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

/// 内核二进制是否已安装。
pub fn kernel_bin_exists() -> bool {
    kernel_bin_path().exists()
}

/// 当前平台是否支持订阅内核（有钉版本资产）。
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

/// 订阅 URL 脱敏（审计/日志用）：scheme://host/…前 8 位路径
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

// ==================== 订阅清单操作 ====================

/// 拉取订阅并解析用户/流量信息（subscription-userinfo 头）与节点数。
/// 拉取失败或内容不像 Clash 配置即报错——添加/刷新都以拉通为准。
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
                    // 非标准字段：部分面板只回传 used（可带小数），u/d 为 0 时作兜底
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

/// 订阅体嗅探与节点数估算（URL 拉取与本地导入共用入口）：
/// Clash YAML（proxies: 段内 "name:" 行）或 base64/明文分享链接（含 "://"）。
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

/// 宽松 base64 解码（处理未填充/换行的订阅体）
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

/// 当前订阅清单（配置生成管线用）
pub(crate) fn current_store() -> SubStore {
    load_store()
}

/// 添加订阅：先拉取校验（拉不通/不可识别即失败），首个订阅自动激活。
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
    // 本地导入订阅级联清理落盘 YAML（仅本应用内核目录下的 local-*.yaml，防误删用户文件）
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
    // 激活项被删：顺位激活第一个
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

/// 本地 YAML 导入订阅：内容嗅探（与 URL 拉取同一 analyze 入口）→ 落盘
/// mihomo/local-<id>.yaml → 入库（url 记 file:// 前缀，provider 渲染为 type: file）。
/// 本地订阅无在线流量信息，upload/download/total 恒 0；不支持在线刷新。
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

/// 单选激活：仅一个 active；返回新的激活项。
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

/// 刷新订阅：重新拉取（更新流量/到期/节点数/时间戳）；激活项同时通知内核更新 provider。
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
            let _ = api.update_provider().await; // 失败不阻塞（下次定时刷新自愈）
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

// ==================== 代理列表缓存（内核未运行时代理页只读展示） ====================

fn proxy_cache_path() -> PathBuf {
    roles::data_dir().join("proxy-cache.json")
}

/// 把 provider 节点明细（type/history）并入 /proxies 载荷——
/// provider 节点不在全局 /proxies 注册表，前端据 `PROXY_DATA[name].type` 展示协议。
/// 已存在的条目（组/内置）不覆盖。
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

/// 持久化最近一次成功的 /proxies 快照。
pub fn save_proxy_cache(v: &serde_json::Value) {
    if !v["proxies"].is_object() {
        return;
    }
    let data = serde_json::json!({"ts": now_ts(), "proxies": v["proxies"]});
    if let Ok(s) = serde_json::to_string(&data) {
        let _ = std::fs::write(proxy_cache_path(), s);
    }
}

/// 读取缓存快照（附 `cached: true` 标记，前端据此降级为只读展示）。
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
