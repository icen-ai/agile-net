//! 订阅代理内核（mihomo sidecar）管理：钉版本下载校验 / 配置生成 / 生命周期 / REST 控制面。
//!
//! - 内核只从 mihomo 官方 GitHub Release 下载（镜像仅作 CDN 加速，
//!   完整性由内置 SHA-256 钉死保证，双镜像交叉验证得出）
//! - 数据布局（~/.agile-net/）：mihomo/ 内核与配置缓存；subscriptions.json 订阅清单（0600）
//! - 订阅解析完全交给内核 proxy-providers，本项目不解析订阅内容
//! - external-controller 仅 loopback + secret，严禁对外暴露

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::roles;

/// 钉死的内核版本与资产（升级内核 = 改这里 + 更新哈希）
pub const MIHOMO_VERSION: &str = "1.19.29";
/// mixed 入站（避让 Clash 7890 系、本地代理 57890 与常见占用 57891）
pub const MIHOMO_MIXED_PORT: u16 = 57892;
/// external-controller（避让 9090）
pub const MIHOMO_CTRL_PORT: u16 = 59292;

/// 当前平台的 (资产文件名, SHA-256, 包内二进制名)。
/// 哈希来源：官方 Release 文件经两个独立镜像交叉下载验证一致。
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn kernel_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some((
        "mihomo-windows-amd64-compatible-v1.19.29.zip",
        "322aaa5957ba9e72afdda9b71cc4329f691d2d45ec39e70bbca3f7bf5aa93d52",
        "mihomo-windows-amd64-compatible.exe",
    ))
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn kernel_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some((
        "mihomo-darwin-arm64-v1.19.29.gz",
        "4dc25df9e899f14161911302a8ee5fc9e202ed9c976fc405bf82c50ff27466ca",
        "mihomo-darwin-arm64",
    ))
}
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn kernel_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some((
        "mihomo-darwin-amd64-v1-v1.19.29.gz",
        "addf68bf604e05cce5334e949bb8915dd68b25744669b320f7d4c1e240ab92a0",
        "mihomo-darwin-amd64",
    ))
}
#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
)))]
fn kernel_asset() -> Option<(&'static str, &'static str, &'static str)> {
    None
}

/// 官方 Release URL + 镜像回退（镜像仅为 CDN，完整性由 SHA-256 钉死保证）
fn download_urls(asset: &str) -> Vec<String> {
    let path = format!(
        "MetaCubeX/mihomo/releases/download/v{MIHOMO_VERSION}/{asset}"
    );
    vec![
        format!("https://github.com/{path}"),
        format!("https://gh-proxy.com/https://github.com/{path}"),
        format!("https://ghfast.top/https://github.com/{path}"),
    ]
}

// ==================== 订阅清单（敏感凭据，0600） ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    /// 最近一次内核侧刷新时间（秒）
    #[serde(default)]
    pub updated_at: Option<u64>,
    /// 最近一次已知的节点数（状态展示用）
    #[serde(default)]
    pub node_count: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct SubStore {
    /// external-controller 鉴权密钥（首启随机生成持久化）
    #[serde(default)]
    secret: String,
    #[serde(default)]
    subscriptions: Vec<Subscription>,
}

fn store_path() -> PathBuf {
    roles::data_dir().join("subscriptions.json")
}

pub fn kernel_dir() -> PathBuf {
    roles::data_dir().join("mihomo")
}

fn kernel_bin_path() -> PathBuf {
    let name = if cfg!(windows) { "mihomo.exe" } else { "mihomo" };
    kernel_dir().join(name)
}

fn config_path() -> PathBuf {
    kernel_dir().join("config.yaml")
}

fn load_store() -> SubStore {
    std::fs::read_to_string(store_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_store(store: &SubStore) -> Result<(), String> {
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

fn ensure_secret(store: &mut SubStore) -> String {
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

// ==================== 配置生成（全量重写，严禁手改） ====================

fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 由订阅清单生成 mihomo config.yaml（无订阅时不应启动内核）。
pub fn render_config(store: &SubStore) -> String {
    let mut s = String::new();
    s.push_str("# 本文件由 AgileNet 自动生成，手动修改将在下次启动时被覆盖\n");
    s.push_str(&format!("mixed-port: {MIHOMO_MIXED_PORT}\n"));
    s.push_str("allow-lan: false\n");
    s.push_str(&format!(
        "external-controller: 127.0.0.1:{MIHOMO_CTRL_PORT}\n"
    ));
    s.push_str(&format!("secret: \"{}\"\n", yaml_escape(&store.secret)));
    s.push_str("log-level: warning\n");
    s.push_str("mode: rule\n");
    s.push_str("unified-delay: true\n");
    s.push_str("proxy-providers:\n");
    for (i, sub) in store.subscriptions.iter().enumerate() {
        s.push_str(&format!("  sub{i}:\n"));
        s.push_str("    type: http\n");
        s.push_str(&format!("    url: \"{}\"\n", yaml_escape(&sub.url)));
        s.push_str("    interval: 86400\n");
        s.push_str("    proxy: DIRECT\n");
        s.push_str("    health-check:\n");
        s.push_str("      enable: true\n");
        s.push_str("      url: http://www.gstatic.com/generate_204\n");
        s.push_str("      interval: 600\n");
    }
    s.push_str("proxy-groups:\n");
    s.push_str("  - name: AGILE-SUB\n");
    s.push_str("    type: select\n");
    s.push_str("    use:\n");
    for i in 0..store.subscriptions.len() {
        s.push_str(&format!("      - sub{i}\n"));
    }
    s.push_str("rules:\n");
    s.push_str("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n");
    s.push_str("  - MATCH,AGILE-SUB\n");
    s
}

/// 防环静态断言：生成配置不得把流量指回本地代理/控制面端口。
#[cfg(test)]
fn assert_no_loop(cfg: &str) {
    assert!(!cfg.contains("57890"), "配置不得引用本地代理端口");
    assert!(!cfg.contains("127.0.0.1:57892,DIRECT") || cfg.contains("IP-CIDR,127.0.0.0/8,DIRECT"));
}

// ==================== 内核下载（钉版本 + SHA-256 校验 + 原子落盘） ====================

/// 确保内核二进制存在（缺失则下载校验），返回二进制路径。
pub async fn ensure_kernel() -> Result<PathBuf, String> {
    let bin = kernel_bin_path();
    if bin.exists() {
        return Ok(bin);
    }
    let (asset, expect_sha, inner) =
        kernel_asset().ok_or("当前平台不支持订阅内核（仅 Windows x64 / macOS）")?;
    let dir = kernel_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let client = reqwest::Client::builder()
        .user_agent(format!("anet-gui/{MIHOMO_VERSION}"))
        .build()
        .map_err(|e| e.to_string())?;
    let mut last_err = String::new();
    let mut bytes = None;
    for url in download_urls(asset) {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.bytes().await {
                    Ok(b) => {
                        bytes = Some(b);
                        break;
                    }
                    Err(e) => last_err = format!("下载中断: {e}"),
                }
            }
            Ok(resp) => last_err = format!("HTTP {}", resp.status()),
            Err(e) => last_err = e.to_string(),
        }
    }
    let bytes = bytes.ok_or_else(|| format!("内核下载失败: {last_err}"))?;

    // SHA-256 校验（钉死值，镜像篡改可检出）
    use sha2::Digest;
    let actual = format!("{:x}", sha2::Sha256::digest(&bytes));
    if actual != expect_sha {
        roles::audit(
            "gui.kernel_tamper",
            serde_json::json!({"expect": expect_sha, "actual": actual}),
        );
        return Err("内核校验失败（SHA-256 不匹配，已拒绝落盘并记录审计）".into());
    }

    // 解包到临时文件后原子改名
    let tmp = dir.join("mihomo.download");
    let inner_bytes = if asset.ends_with(".zip") {
        let reader = std::io::Cursor::new(bytes.as_ref());
        let mut zip = zip::ZipArchive::new(reader).map_err(|e| e.to_string())?;
        let mut file = zip.by_name(inner).map_err(|e| e.to_string())?;
        let mut buf = Vec::with_capacity(file.size() as usize);
        std::io::Read::read_to_end(&mut file, &mut buf).map_err(|e| e.to_string())?;
        buf
    } else {
        let mut gz = flate2::read::GzDecoder::new(bytes.as_ref());
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut gz, &mut buf).map_err(|e| e.to_string())?;
        buf
    };
    std::fs::write(&tmp, inner_bytes).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, &bin).map_err(|e| e.to_string())?;
    roles::audit(
        "gui.kernel_download",
        serde_json::json!({"version": MIHOMO_VERSION}),
    );
    Ok(bin)
}

// ==================== 内核生命周期 ====================

#[derive(Debug, Clone, Serialize)]
pub struct KernelStatus {
    pub supported: bool,
    pub installed: bool,
    pub running: bool,
    pub version: String,
    pub restart_count: u32,
    pub last_error: String,
}

/// 内核进程托管：启动/停止/崩溃退避重启（上限 5 次后放弃并审计）。
/// 子进程由 supervisor 任务独占持有，停止经 mpsc 信号（杜绝跨 await 持锁死锁）。
pub struct KernelManager {
    stop_tx: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>>,
    restart_count: Arc<AtomicU32>,
    last_error: Arc<std::sync::Mutex<String>>,
}

impl Default for KernelManager {
    fn default() -> Self {
        Self {
            stop_tx: Arc::new(std::sync::Mutex::new(None)),
            restart_count: Arc::new(AtomicU32::new(0)),
            last_error: Arc::new(std::sync::Mutex::new(String::new())),
        }
    }
}

impl KernelManager {
    /// 启动内核（重写配置 → spawn → supervisor 监控）。
    pub async fn start(&self) -> Result<(), String> {
        if self.stop_tx.lock().unwrap().is_some() {
            return Ok(());
        }
        let mut store = load_store();
        if store.subscriptions.is_empty() {
            return Err("请先添加订阅".into());
        }
        ensure_secret(&mut store);
        save_store(&store)?;
        ensure_kernel().await?;
        std::fs::write(config_path(), render_config(&store)).map_err(|e| e.to_string())?;

        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
        *self.stop_tx.lock().unwrap() = Some(tx);
        self.restart_count.store(0, Ordering::SeqCst);
        self.supervise(rx);

        // 就绪检查：控制面 10s 内未起来（端口被占用等）即视为启动失败并回收
        let mut ready = false;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok(api) = kernel_api().await {
                if api.version().await.is_ok() {
                    ready = true;
                    break;
                }
            }
        }
        if !ready {
            self.stop().await;
            return Err("内核启动后控制面未就绪（57892/59292 端口被占用？）".into());
        }
        roles::audit("gui.kernel_start", serde_json::json!({}));
        Ok(())
    }

    fn spawn(bin: &PathBuf) -> Result<tokio::process::Child, String> {
        let dir = kernel_dir();
        let cfg = config_path();
        let mut cmd = tokio::process::Command::new(bin);
        cmd.arg("-d")
            .arg(&dir)
            .arg("-f")
            .arg(&cfg)
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            // CREATE_NO_WINDOW（tokio::process::Command 自带 creation_flags）
            cmd.creation_flags(0x08000000);
        }
        cmd.spawn().map_err(|e| format!("内核启动失败: {e}"))
    }

    /// supervisor：独占子进程；崩溃指数退避重启（1/2/4/8/16s，上限 5 次）；
    /// 收到停止信号即 kill 并退出，收尾清理句柄。
    fn supervise(&self, mut rx: tokio::sync::mpsc::Receiver<()>) {
        let stop_tx = self.stop_tx.clone();
        let restart_count = self.restart_count.clone();
        let last_error = self.last_error.clone();
        tokio::spawn(async move {
            let mut restarts = 0u32;
            loop {
                let mut child = match Self::spawn(&kernel_bin_path()) {
                    Ok(c) => c,
                    Err(e) => {
                        *last_error.lock().unwrap() = e;
                        break;
                    }
                };
                tokio::select! {
                    exit = child.wait() => {
                        restarts += 1;
                        restart_count.store(restarts, Ordering::SeqCst);
                        if let Ok(status) = &exit {
                            *last_error.lock().unwrap() = format!("内核退出: {status}");
                        }
                        if restarts > 5 {
                            roles::audit(
                                "gui.kernel_crash",
                                serde_json::json!({"give_up": true, "restarts": restarts - 1}),
                            );
                            break;
                        }
                        roles::audit("gui.kernel_crash", serde_json::json!({"restart": restarts}));
                        let backoff = 1u64 << (restarts - 1).min(4);
                        // 退避期间同样响应停止信号
                        if tokio::time::timeout(
                            std::time::Duration::from_secs(backoff),
                            rx.recv(),
                        )
                        .await
                        .is_ok()
                        {
                            break;
                        }
                    }
                    _ = rx.recv() => {
                        let _ = child.kill().await;
                        break;
                    }
                }
            }
            *stop_tx.lock().unwrap() = None;
        });
    }

    /// 停止内核（经 clone 的发送端发信号；槽位作存活标记由 supervisor 收尾清除，等待上限 5s）。
    pub async fn stop(&self) {
        let tx = self.stop_tx.lock().unwrap().clone();
        if let Some(tx) = tx {
            let _ = tx.send(()).await;
            for _ in 0..50 {
                if self.stop_tx.lock().unwrap().is_none() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        roles::audit("gui.kernel_stop", serde_json::json!({}));
    }

    pub async fn running(&self) -> bool {
        self.stop_tx.lock().unwrap().is_some()
    }

    pub async fn status(&self) -> KernelStatus {
        let running = self.running().await;
        let version = if running {
            match kernel_api().await {
                Ok(api) => api.version().await.unwrap_or_default(),
                Err(_) => String::new(),
            }
        } else {
            String::new()
        };
        KernelStatus {
            supported: kernel_asset().is_some(),
            installed: kernel_bin_path().exists(),
            running,
            version,
            restart_count: self.restart_count.load(Ordering::Relaxed),
            last_error: self.last_error.lock().unwrap().clone(),
        }
    }
}

// ==================== REST 控制面（loopback + secret） ====================

pub struct KernelApi {
    client: reqwest::Client,
    base: String,
    secret: String,
}

impl KernelApi {
    fn new(secret: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base: format!("http://127.0.0.1:{MIHOMO_CTRL_PORT}"),
            secret,
        }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{}", self.base, path))
            .header("Authorization", format!("Bearer {}", self.secret))
    }

    pub async fn version(&self) -> Result<String, String> {
        let v: serde_json::Value = self
            .req(reqwest::Method::GET, "/version")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        v["version"].as_str().map(|s| s.to_string()).ok_or_else(|| "版本解析失败".into())
    }

    /// 全量代理与组信息（原样透传 mihomo JSON）
    pub async fn proxies(&self) -> Result<serde_json::Value, String> {
        self.req(reqwest::Method::GET, "/proxies")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }

    /// 选择组内节点
    pub async fn select(&self, group: &str, name: &str) -> Result<(), String> {
        let resp = self
            .req(reqwest::Method::PUT, &format!("/proxies/{group}"))
            .json(&serde_json::json!({"name": name}))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("切换失败 (HTTP {})", resp.status()))
        }
    }

    /// 单节点延迟（ms）
    pub async fn delay(&self, name: &str) -> Result<u32, String> {
        let v: serde_json::Value = self
            .req(
                reqwest::Method::GET,
                &format!(
                    "/proxies/{}/delay?timeout=5000&url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204",
                    name
                ),
            )
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        v["delay"]
            .as_u64()
            .map(|d| d as u32)
            .ok_or_else(|| "测速失败".into())
    }

    /// 触发订阅（provider）手动刷新
    pub async fn update_provider(&self, index: usize) -> Result<(), String> {
        let resp = self
            .req(
                reqwest::Method::PUT,
                &format!("/providers/proxies/sub{index}"),
            )
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("刷新失败 (HTTP {})", resp.status()))
        }
    }
}

/// 以当前持久化 secret 构建控制面客户端。
pub async fn kernel_api() -> Result<KernelApi, String> {
    let store = load_store();
    if store.secret.is_empty() {
        return Err("内核尚未初始化".into());
    }
    Ok(KernelApi::new(store.secret))
}

// ==================== 订阅清单操作 ====================

pub fn list_subscriptions() -> Vec<Subscription> {
    load_store().subscriptions
}

pub fn add_subscription(name: &str, url: &str) -> Result<Subscription, String> {
    let url = url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("订阅地址须为 http(s) URL".into());
    }
    let mut store = load_store();
    ensure_secret(&mut store);
    let sub = Subscription {
        id: uuid::Uuid::new_v4().simple().to_string(),
        name: if name.trim().is_empty() {
            format!("订阅 {}", store.subscriptions.len() + 1)
        } else {
            name.trim().to_string()
        },
        url: url.to_string(),
        updated_at: None,
        node_count: 0,
    };
    store.subscriptions.push(sub.clone());
    save_store(&store)?;
    roles::audit(
        "gui.subscription_add",
        serde_json::json!({"name": sub.name, "url": mask_url(&sub.url)}),
    );
    Ok(sub)
}

pub fn remove_subscription(id: &str) -> Result<(), String> {
    let mut store = load_store();
    let before = store.subscriptions.len();
    store.subscriptions.retain(|s| s.id != id);
    if store.subscriptions.len() == before {
        return Err("订阅不存在".into());
    }
    save_store(&store)?;
    roles::audit("gui.subscription_remove", serde_json::json!({"id": id}));
    Ok(())
}

/// 手动刷新订阅（内核运行中走控制面，随后回写节点数/时间戳）。
pub async fn update_subscription(id: &str) -> Result<Subscription, String> {
    let mut store = load_store();
    let idx = store
        .subscriptions
        .iter()
        .position(|s| s.id == id)
        .ok_or("订阅不存在")?;
    let api = kernel_api().await?;
    api.update_provider(idx).await?;
    // 回写刷新时间；节点数由前端经 /proxies 聚合展示
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    store.subscriptions[idx].updated_at = Some(ts);
    let sub = store.subscriptions[idx].clone();
    save_store(&store)?;
    roles::audit(
        "gui.subscription_update",
        serde_json::json!({"name": sub.name, "url": mask_url(&sub.url)}),
    );
    Ok(sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_render_basic() {
        let mut store = SubStore::default();
        store.secret = "s3cret".into();
        store.subscriptions.push(Subscription {
            id: "a".into(),
            name: "机场A".into(),
            url: "https://example.com/sub?token=abc".into(),
            updated_at: None,
            node_count: 0,
        });
        store.subscriptions.push(Subscription {
            id: "b".into(),
            name: "机场B".into(),
            url: "https://b.example.com/link".into(),
            updated_at: None,
            node_count: 0,
        });
        let cfg = render_config(&store);
        assert!(cfg.contains("mixed-port: 57892"));
        assert!(cfg.contains("external-controller: 127.0.0.1:59292"));
        assert!(cfg.contains("secret: \"s3cret\""));
        assert!(cfg.contains("url: \"https://example.com/sub?token=abc\""));
        assert!(cfg.contains("      - sub0\n"));
        assert!(cfg.contains("      - sub1\n"));
        assert!(cfg.contains("  - MATCH,AGILE-SUB\n"));
        assert!(cfg.contains("IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"));
        assert_no_loop(&cfg);
    }

    #[test]
    fn config_escapes_quotes() {
        let mut store = SubStore::default();
        store.secret = "s".into();
        store.subscriptions.push(Subscription {
            id: "a".into(),
            name: "x".into(),
            url: "https://evil.com/\"injected".into(),
            updated_at: None,
            node_count: 0,
        });
        let cfg = render_config(&store);
        assert!(cfg.contains("\\\"injected"));
    }

    #[test]
    fn mask_url_hides_token() {
        assert_eq!(
            mask_url("https://sub.example.com/api/v1/client/subscribe?token=deadbeef12345678"),
            "https://sub.example.com/…api/v1/c"
        );
        assert_eq!(mask_url("not-a-url"), "…");
    }

    /// E2E（真实下载内核 + 启动 + REST 握手 + 停止），手动运行：
    /// cargo test --manifest-path apps/desktop/Cargo.toml kernel_e2e -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "联网下载内核，显式 --ignored 运行"]
    async fn kernel_e2e() {
        // 备份并隔离真实订阅清单（测试结束还原，不污染用户数据）
        let path = store_path();
        let backup = std::fs::read_to_string(&path).ok();
        let restore = |b: Option<String>| {
            match b {
                Some(s) => std::fs::write(&path, s).unwrap(),
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        };

        let mut store = SubStore::default();
        ensure_secret(&mut store);
        // 不可达 provider：拉取失败不阻塞内核启动与控制面
        store.subscriptions.push(Subscription {
            id: "e2e".into(),
            name: "e2e-dummy".into(),
            url: "http://127.0.0.1:9/sub".into(),
            updated_at: None,
            node_count: 0,
        });
        save_store(&store).unwrap();

        let km = KernelManager::default();
        let result = async {
            km.start().await.map_err(|e| format!("start: {e}"))?;
            // 控制面最多等 15s（含解压后冷启动）
            let mut version = String::new();
            for _ in 0..30 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if let Ok(api) = kernel_api().await {
                    if let Ok(v) = api.version().await {
                        version = v;
                        break;
                    }
                }
            }
            if version.is_empty() {
                return Err("external-controller 15s 内未就绪".to_string());
            }
            eprintln!("kernel version: {version}");
            // proxies 端点可用（即使 provider 失败也有内置 DIRECT/REJECT）
            let api = kernel_api().await.unwrap();
            let px = api.proxies().await.unwrap();
            assert!(px["proxies"].is_object());
            let st = km.status().await;
            assert!(st.running);
            Ok::<(), String>(())
        }
        .await;
        km.stop().await;
        restore(backup);
        result.unwrap();
    }
}
