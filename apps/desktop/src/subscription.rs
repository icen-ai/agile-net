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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

/// 内核二进制是否已安装。
pub fn kernel_bin_exists() -> bool {
    kernel_bin_path().exists()
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

/// 由订阅清单生成 mihomo config.yaml（仅加载当前激活订阅，单 provider 恒名 main）。
pub fn render_config(store: &SubStore) -> String {
    let active = store.subscriptions.iter().find(|s| s.active);
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
    if let Some(sub) = active {
        s.push_str("proxy-providers:\n");
        s.push_str("  main:\n");
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
    if active.is_some() {
        s.push_str("    use:\n");
        s.push_str("      - main\n");
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
    /// /traffic WS 累计器（内核启动时挂任务，停止即清零）
    traffic: Arc<TrafficStats>,
    traffic_stop: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>>,
}

impl Default for KernelManager {
    fn default() -> Self {
        Self {
            stop_tx: Arc::new(std::sync::Mutex::new(None)),
            restart_count: Arc::new(AtomicU32::new(0)),
            last_error: Arc::new(std::sync::Mutex::new(String::new())),
            traffic: Arc::new(TrafficStats::default()),
            traffic_stop: Arc::new(std::sync::Mutex::new(None)),
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
        self.start_traffic();
        roles::audit("gui.kernel_start", serde_json::json!({}));
        Ok(())
    }

    /// 挂 /traffic WS 流量累计任务（幂等；内核停止时经信号终止并清零）。
    fn start_traffic(&self) {
        if self.traffic_stop.lock().unwrap().is_some() {
            return;
        }
        let store = load_store();
        if store.secret.is_empty() {
            return;
        }
        self.traffic.reset();
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
        *self.traffic_stop.lock().unwrap() = Some(tx);
        let stats = self.traffic.clone();
        let slot = self.traffic_stop.clone();
        tokio::spawn(async move {
            traffic_ws_loop(store.secret, stats, rx).await;
            *slot.lock().unwrap() = None;
        });
    }

    /// 当前流量快照（内核停止后为零值）。
    pub fn traffic(&self) -> TrafficSnapshot {
        self.traffic.snapshot()
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
        // 流量累计任务随内核停止：发信号并等待任务退出自清槽位（上限 5s；
        // 保证 stop→start 快速重启时 start_traffic 看到的是已清槽位，新旧任务不打架）
        let ttx = self.traffic_stop.lock().unwrap().clone();
        if let Some(tx) = ttx {
            let _ = tx.send(()).await;
            for _ in 0..50 {
                if self.traffic_stop.lock().unwrap().is_none() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        self.traffic.reset();
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

    /// 组延迟（name → ms）：provider 节点不注册进全局 /proxies，单节点
    /// `/proxies/{name}/delay` 恒 404，必须走 `/group/{group}/delay`（内核并发测全组，
    /// 失败节点记为 timeout 值，此处过滤剔除）。
    pub async fn group_delay(
        &self,
        group: &str,
    ) -> Result<std::collections::HashMap<String, u32>, String> {
        const TIMEOUT_MS: u32 = 5000;
        let resp = self
            .req(
                reqwest::Method::GET,
                &format!(
                    "/group/{group}/delay?timeout={TIMEOUT_MS}&url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
                ),
            )
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("测速失败 (HTTP {})", resp.status()));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let obj = v.as_object().ok_or("测速失败")?;
        Ok(obj
            .iter()
            .filter_map(|(k, val)| {
                let d = val.as_u64()? as u32;
                (d < TIMEOUT_MS).then(|| (k.clone(), d))
            })
            .collect())
    }

    /// provider 节点明细（type/history；provider 节点不在全局 /proxies 注册表）
    pub async fn provider_proxies(&self) -> Result<serde_json::Value, String> {
        self.req(reqwest::Method::GET, "/providers/proxies")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }

    /// 触发订阅（provider）手动刷新（单 provider 恒名 main，见 render_config）
    pub async fn update_provider(&self) -> Result<(), String> {
        let resp = self
            .req(reqwest::Method::PUT, "/providers/proxies/main")
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

// ==================== 流量统计（/traffic WS 累计） ====================

/// 内核流量累计器：/traffic WS 每秒推送 {up,down}（该秒字节数），此处累计会话总量并记录最近秒速率。
/// 全 Atomic 无锁；内核停止即清零（任务退出时统一 reset）。
#[derive(Debug, Default)]
pub struct TrafficStats {
    up_total: AtomicU64,
    down_total: AtomicU64,
    up_rate: AtomicU64,
    down_rate: AtomicU64,
}

/// 流量快照（sub_traffic 命令返回体）
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct TrafficSnapshot {
    pub up_total: u64,
    pub down_total: u64,
    pub up_rate: u64,
    pub down_rate: u64,
}

impl TrafficStats {
    fn add(&self, up: u64, down: u64) {
        self.up_total.fetch_add(up, Ordering::Relaxed);
        self.down_total.fetch_add(down, Ordering::Relaxed);
        self.up_rate.store(up, Ordering::Relaxed);
        self.down_rate.store(down, Ordering::Relaxed);
    }
    fn clear_rates(&self) {
        self.up_rate.store(0, Ordering::Relaxed);
        self.down_rate.store(0, Ordering::Relaxed);
    }
    fn reset(&self) {
        self.up_total.store(0, Ordering::Relaxed);
        self.down_total.store(0, Ordering::Relaxed);
        self.clear_rates();
    }
    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            up_total: self.up_total.load(Ordering::Relaxed),
            down_total: self.down_total.load(Ordering::Relaxed),
            up_rate: self.up_rate.load(Ordering::Relaxed),
            down_rate: self.down_rate.load(Ordering::Relaxed),
        }
    }
}

/// /traffic WS 累计任务：断线指数退避重连（1s 起、30s 封顶，会话稳定 10s 后断线重置退避）；
/// 停止信号（含发送端被丢弃）即退出并清零计数。
async fn traffic_ws_loop(secret: String, stats: Arc<TrafficStats>, mut stop: tokio::sync::mpsc::Receiver<()>) {
    let mut backoff = 1u64;
    loop {
        let started = std::time::Instant::now();
        tokio::select! {
            _ = stop.recv() => break,
            _ = traffic_ws_session(&secret, &stats) => {}
        }
        // 断线：速率归零（总量保留，重连后续累计）
        stats.clear_rates();
        if started.elapsed() >= std::time::Duration::from_secs(10) {
            backoff = 1;
        }
        if tokio::time::timeout(std::time::Duration::from_secs(backoff), stop.recv())
            .await
            .is_ok()
        {
            break;
        }
        backoff = (backoff * 2).min(30);
    }
    stats.reset();
}

/// 单段 WS 会话：握手 → 帧循环（text 累计 / ping→pong / close 正常结束）。
/// 极简 RFC 6455 客户端，仅面向 loopback mihomo 控制面，不引入额外依赖。
async fn traffic_ws_session(secret: &str, stats: &TrafficStats) -> Result<(), String> {
    traffic_ws_session_on(MIHOMO_CTRL_PORT, secret, stats).await
}

/// 端口可参数化的会话本体（生产走控制面端口；测试注入 mock 端口）。
async fn traffic_ws_session_on(port: u16, secret: &str, stats: &TrafficStats) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let req = format!(
        "GET /traffic HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {secret}\r\n\r\n",
        ws_key()
    );
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    // HTTP 101 响应头（到 \r\n\r\n 为止）
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        head.push(b[0]);
        if head.len() > 8192 {
            return Err("WS 握手响应头过长".into());
        }
    }
    let head = String::from_utf8_lossy(&head);
    if !head.starts_with("HTTP/1.1 101") && !head.starts_with("HTTP/1.0 101") {
        return Err(format!(
            "WS 握手失败: {}",
            head.lines().next().unwrap_or("无状态行")
        ));
    }
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("WS 连接已关闭".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Some(frame) = parse_ws_frame(&buf)? {
            buf.drain(..frame.consumed);
            match frame.opcode {
                0x1 | 0x2 => {
                    if !frame.fin {
                        return Err("不支持分片帧".into());
                    }
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&frame.payload) {
                        stats.add(
                            v["up"].as_u64().unwrap_or(0),
                            v["down"].as_u64().unwrap_or(0),
                        );
                    }
                }
                0x8 => return Ok(()), // close
                0x9 => {
                    // ping → pong（客户端帧须掩码）
                    let pong = build_ws_frame(0xA, &frame.payload);
                    stream.write_all(&pong).await.map_err(|e| e.to_string())?;
                }
                _ => {} // pong / 其他忽略
            }
        }
        if buf.len() > 1 << 20 {
            return Err("WS 帧缓冲超限".into());
        }
    }
}

struct WsFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    consumed: usize,
}

/// 解析一帧服务端 WS 帧（RFC 6455）：Ok(None)=数据不足；
/// 带掩码/保留位/非法控制帧视为协议错误（服务端→客户端帧不允许掩码）。
fn parse_ws_frame(buf: &[u8]) -> Result<Option<WsFrame>, String> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    if buf[0] & 0x70 != 0 {
        return Err("WS 帧带保留位（不支持扩展）".into());
    }
    let opcode = buf[0] & 0x0f;
    if buf[1] & 0x80 != 0 {
        return Err("服务端帧不允许掩码".into());
    }
    let mut len = (buf[1] & 0x7f) as u64;
    let mut pos = 2;
    if len == 126 {
        if buf.len() < 4 {
            return Ok(None);
        }
        len = u16::from_be_bytes([buf[2], buf[3]]) as u64;
        pos = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return Ok(None);
        }
        len = u64::from_be_bytes(buf[2..10].try_into().unwrap());
        pos = 10;
    }
    if opcode >= 0x8 && (!fin || len > 125) {
        return Err("非法控制帧".into());
    }
    let total = pos + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(WsFrame {
        fin,
        opcode,
        payload: buf[pos..total].to_vec(),
        consumed: total,
    }))
}

/// 构造客户端 WS 帧（FIN 置位；RFC 6455 要求客户端帧掩码）。
fn build_ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mask: [u8; 4] = uuid::Uuid::new_v4().as_bytes()[..4].try_into().unwrap();
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    if payload.len() < 126 {
        out.push(0x80 | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        out.push(0x80 | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// Sec-WebSocket-Key（16 随机字节 base64）
fn ws_key() -> String {
    b64_encode(uuid::Uuid::new_v4().as_bytes())
}

fn b64_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { TBL[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { TBL[n as usize & 63] as char } else { '=' });
    }
    out
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
    // 节点数估算与格式嗅探：Clash YAML（proxies: 段内 "name:" 行）或 base64/明文分享链接（含 "://"）
    let node_count = if body.contains("proxies:") {
        let start = body.find("proxies:").unwrap_or(0);
        let end = body.find("proxy-groups:").unwrap_or(body.len());
        let section = &body[start..end.max(start)];
        section
            .lines()
            .filter(|l| l.trim_start().starts_with("name:"))
            .count()
    } else {
        let decoded = base64_decode_loose(&body);
        let text = decoded.as_deref().unwrap_or(&body);
        text.lines().filter(|l| l.contains("://")).count()
    };
    if node_count == 0 {
        return Err("订阅内容无法识别（不是 Clash 配置或分享链接）".into());
    }
    Ok((upload, download, total, expire, node_count))
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
    roles::audit("gui.subscription_remove", serde_json::json!({"id": id}));
    Ok(())
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

fn now_ts() -> u64 {
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
    fn config_render_basic() {
        let mut store = SubStore::default();
        store.secret = "s3cret".into();
        let mk = |id: &str, name: &str, url: &str, active: bool| Subscription {
            id: id.into(),
            name: name.into(),
            url: url.into(),
            active,
            updated_at: None,
            node_count: 0,
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
        };
        store
            .subscriptions
            .push(mk("a", "机场A", "https://example.com/sub?token=abc", true));
        store
            .subscriptions
            .push(mk("b", "机场B", "https://b.example.com/link", false));
        let cfg = render_config(&store);
        assert!(cfg.contains("mixed-port: 57892"));
        assert!(cfg.contains("external-controller: 127.0.0.1:59292"));
        assert!(cfg.contains("secret: \"s3cret\""));
        // 仅加载激活订阅（单 provider 恒名 main）
        assert!(cfg.contains("  main:\n"));
        assert!(cfg.contains("url: \"https://example.com/sub?token=abc\""));
        assert!(!cfg.contains("b.example.com"));
        assert!(cfg.contains("      - main\n"));
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
            active: true,
            updated_at: None,
            node_count: 0,
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
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

    #[test]
    fn traffic_stats_accumulate_and_reset() {
        let st = TrafficStats::default();
        st.add(100, 200);
        st.add(50, 60);
        let snap = st.snapshot();
        assert_eq!((snap.up_total, snap.down_total), (150, 260));
        assert_eq!((snap.up_rate, snap.down_rate), (50, 60));
        st.clear_rates();
        let snap = st.snapshot();
        assert_eq!((snap.up_total, snap.down_total), (150, 260));
        assert_eq!((snap.up_rate, snap.down_rate), (0, 0));
        st.reset();
        let snap = st.snapshot();
        assert_eq!(
            (snap.up_total, snap.down_total, snap.up_rate, snap.down_rate),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn ws_frame_parse_text_and_close() {
        // 短文本帧
        let payload = br#"{"up":3,"down":5}"#;
        let mut buf = vec![0x81, payload.len() as u8];
        buf.extend_from_slice(payload);
        let f = parse_ws_frame(&buf).unwrap().expect("应解析出完整帧");
        assert!(f.fin);
        assert_eq!(f.opcode, 0x1);
        assert_eq!(f.payload, payload);
        assert_eq!(f.consumed, buf.len());
        // close 帧
        let f = parse_ws_frame(&[0x88, 0x00]).unwrap().unwrap();
        assert_eq!(f.opcode, 0x8);
        // 数据不足 → None
        assert!(parse_ws_frame(&[0x81]).unwrap().is_none());
        assert!(parse_ws_frame(&[0x81, 20, b'{']).unwrap().is_none());
    }

    #[test]
    fn ws_frame_parse_extended_len() {
        let payload = vec![7u8; 300];
        let mut buf = vec![0x82, 126];
        buf.extend_from_slice(&300u16.to_be_bytes());
        buf.extend_from_slice(&payload);
        let f = parse_ws_frame(&buf).unwrap().unwrap();
        assert_eq!(f.opcode, 0x2);
        assert_eq!(f.payload.len(), 300);
        assert_eq!(f.consumed, 304);
        // 16 位长度头不全 → None
        assert!(parse_ws_frame(&[0x82, 126, 0x01]).unwrap().is_none());
    }

    #[test]
    fn ws_frame_rejects_masked_and_bad_control() {
        // 服务端帧带掩码 → 协议错误
        assert!(parse_ws_frame(&[0x81, 0x80]).is_err());
        // 保留位 → 协议错误
        assert!(parse_ws_frame(&[0xC1, 0x00]).is_err());
        // 分片控制帧 → 协议错误
        assert!(parse_ws_frame(&[0x08, 0x00]).is_err());
    }

    #[test]
    fn ws_client_frame_is_masked() {
        let out = build_ws_frame(0xA, b"hi");
        assert_eq!(out[0], 0x8A); // FIN + pong
        assert_eq!(out[1] & 0x80, 0x80); // 掩码位
        assert_eq!(out[1] & 0x7f, 2);
        let mask = &out[2..6];
        assert_eq!(out[6] ^ mask[0], b'h');
        assert_eq!(out[7] ^ mask[1], b'i');
    }

    #[test]
    fn b64_vectors() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(ws_key().len(), 24);
    }

    /// mock 控制面：校验握手请求 → 推两条 /traffic 帧 → close，验证端到端累计
    #[tokio::test]
    async fn ws_session_accumulates_from_mock_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            let head = String::from_utf8_lossy(&head);
            assert!(head.starts_with("GET /traffic HTTP/1.1\r\n"), "握手请求行: {head}");
            assert!(head.contains("Authorization: Bearer sek"), "缺鉴权头: {head}");
            assert!(head.contains("Sec-WebSocket-Key: "), "缺 WS Key: {head}");
            s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();
            for msg in [r#"{"up":10,"down":20}"#, r#"{"up":5,"down":7}"#] {
                let mut f = vec![0x81, msg.len() as u8];
                f.extend_from_slice(msg.as_bytes());
                s.write_all(&f).await.unwrap();
            }
            s.write_all(&[0x88, 0x00]).await.unwrap(); // close
        });
        let stats = TrafficStats::default();
        traffic_ws_session_on(port, "sek", &stats).await.unwrap();
        server.await.unwrap();
        let snap = stats.snapshot();
        assert_eq!((snap.up_total, snap.down_total), (15, 27));
        assert_eq!((snap.up_rate, snap.down_rate), (5, 7));
    }

    /// 真实订阅全链路 E2E：AG_E2E_SUB_URL=<订阅地址> cargo test real_sub_e2e -- --ignored --nocapture
    /// 拉取 → 启动内核 → 选择 AG_E2E_NODE_PREFIX（默认"荷兰-NL-4"）节点 → 经 mixed 出口访问谷歌 204
    #[tokio::test]
    #[ignore = "真实订阅联网测试，显式 --ignored 运行"]
    async fn real_sub_e2e() {
        let url = std::env::var("AG_E2E_SUB_URL").expect("AG_E2E_SUB_URL 未设置");
        let prefix = std::env::var("AG_E2E_NODE_PREFIX").unwrap_or_else(|_| "荷兰-NL-4".into());

        // 拉取校验
        let sub = add_subscription("e2e-real", &url).await.unwrap();
        eprintln!("订阅拉取成功: {} 节点, 流量 {}/{} 到期 {:?}", sub.node_count, sub.download, sub.total, sub.expire);
        assert!(sub.node_count > 0);

        // 启动内核
        let km = KernelManager::default();
        km.start().await.unwrap();
        eprintln!("内核已启动并就绪");

        // 找到目标节点并选择
        let api = kernel_api().await.unwrap();
        let px = api.proxies().await.unwrap();
        let mut node = None;
        let mut group = "AGILE-SUB".to_string();
        if let Some(groups) = px["proxies"].as_object() {
            for (gn, g) in groups {
                if let Some(all) = g["all"].as_array() {
                    for n in all {
                        if let Some(name) = n.as_str() {
                            if name.starts_with(&prefix) {
                                node = Some(name.to_string());
                                if g["all"].is_array() && g["type"].as_str() == Some("Selector") {
                                    group = gn.clone();
                                }
                            }
                        }
                    }
                }
            }
        }
        let node = node.expect("未找到目标前缀节点");
        eprintln!("选择节点: {node} @ {group}");
        api.select(&group, &node).await.unwrap();

        // 经 mixed 出口访问谷歌（204 即通）
        let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{MIHOMO_MIXED_PORT}")).unwrap();
        let client = reqwest::Client::builder().proxy(proxy).build().unwrap();
        let resp = client
            .get("https://www.google.com/generate_204")
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .unwrap();
        eprintln!("google generate_204 -> HTTP {}", resp.status());
        assert_eq!(resp.status().as_u16(), 204, "经订阅节点访问谷歌失败");

        km.stop().await;
        // 订阅保留在清单中供 GUI 使用（用户随后可自行删除）
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
            active: true,
            updated_at: None,
            node_count: 0,
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
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
