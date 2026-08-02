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
/// 制品缺失时的错误前缀：前端据此转下载流程（展示下载进度卡，不当作失败 toast）
pub const NEED_DOWNLOAD_PREFIX: &str = "NEED_DOWNLOAD:";
/// mixed 入站（避让 Clash 7890 系、本地代理 57890 与常见占用 57891）
pub const MIHOMO_MIXED_PORT: u16 = 57892;
/// TUN 模式：mihomo socks 入站（anet 未命中流量的回落点，经 IN-TYPE 规则直达订阅出口）
pub const MIHOMO_SOCKS_PORT: u16 = 57893;
/// external-controller（避让 9090）
pub const MIHOMO_CTRL_PORT: u16 = 59292;

/// 当前平台的 (资产文件名, SHA-256, 包内二进制名)。
/// 哈希来源：官方 Release 文件经两个独立镜像交叉下载验证一致。
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) fn kernel_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some((
        "mihomo-windows-amd64-compatible-v1.19.29.zip",
        "322aaa5957ba9e72afdda9b71cc4329f691d2d45ec39e70bbca3f7bf5aa93d52",
        "mihomo-windows-amd64-compatible.exe",
    ))
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn kernel_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some((
        "mihomo-darwin-arm64-v1.19.29.gz",
        "4dc25df9e899f14161911302a8ee5fc9e202ed9c976fc405bf82c50ff27466ca",
        "mihomo-darwin-arm64",
    ))
}
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub(crate) fn kernel_asset() -> Option<(&'static str, &'static str, &'static str)> {
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
pub(crate) fn kernel_asset() -> Option<(&'static str, &'static str, &'static str)> {
    None
}

/// 官方 Release URL + 镜像回退（镜像仅为 CDN，完整性由 SHA-256 钉死保证）
pub(crate) fn download_urls(asset: &str) -> Vec<String> {
    let path = format!("MetaCubeX/mihomo/releases/download/v{MIHOMO_VERSION}/{asset}");
    vec![
        format!("https://github.com/{path}"),
        format!("https://gh-proxy.com/https://github.com/{path}"),
        format!("https://ghfast.top/https://github.com/{path}"),
    ]
}

/// wintun zip 下载源（官方源直连 + 本地代理兜底；gh-proxy/ghfast 仅镜像 github.com，
/// 不能代理任意域名，已从候移除——受限网络主路径是本地候选复用 reuse_local_wintun）
pub(crate) fn wintun_urls() -> Vec<String> {
    vec![format!("https://{WINTUN_ZIP_PATH}")]
}

// ==================== wintun.dll 钉版本下发（TUN 模式，Windows x64） ====================

/// 钉死的 wintun 版本（升级 = 改这里 + 更新哈希）
pub const WINTUN_VERSION: &str = "0.14.1";
/// wintun-0.14.1.zip 的 SHA-256（与内核同策略钉死；哈希与 wintun.net 官网、
/// wireguard-windows 构建脚本等多源交叉验证一致）
pub(crate) const WINTUN_ZIP_SHA256: &str =
    "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
/// 官方源路径（完整性由 SHA-256 钉死保证；下载镜像见 wintun_urls）
const WINTUN_ZIP_PATH: &str = "download.wireguard.com/wintun/wintun-0.14.1.zip";
/// wintun.dll 0.14.1 (amd64, 427,552 B) 本体的 SHA-256——本地候选复用时的校验钉
/// （取自 FlClash 分发的同版本官方 dll；zip 内层 dll 与整包哈希不同，勿混用）
pub(crate) const WINTUN_DLL_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

/// wintun.dll 落盘位置（与 mihomo.exe 同目录，wintun 按 exe 相邻加载）。
pub fn wintun_dll_path() -> PathBuf {
    kernel_dir().join("wintun.dll")
}

/// 本地候选复用：Clash 系客户端普遍自带同版本官方 wintun.dll（受限网络下
/// wireguard.com 不可达时免下载）；仅在 SHA-256 匹配钉值时复用，否则忽略。
fn wintun_local_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_default();
    if !home.as_os_str().is_empty() {
        v.push(home.join(".config/clash/wintun.dll")); // FlClash 数据目录
    }
    if let Ok(x) = std::env::var("APPDATA") {
        v.push(PathBuf::from(x).join("FlClash/wintun.dll"));
    }
    if let Ok(x) = std::env::var("LOCALAPPDATA") {
        v.push(PathBuf::from(x).join("Programs/FlClash/wintun.dll"));
    }
    v
}

/// 复用本地已存在的官方 wintun.dll（SHA-256 钉值校验），命中返回 true。
fn reuse_local_wintun(dll: &PathBuf) -> Result<bool, String> {
    use sha2::Digest;
    for cand in wintun_local_candidates() {
        let Ok(bytes) = std::fs::read(&cand) else { continue };
        if format!("{:x}", sha2::Sha256::digest(&bytes)) == WINTUN_DLL_SHA256 {
            std::fs::copy(&cand, dll).map_err(|e| format!("wintun 本地复用落盘失败: {e}"))?;
            tracing::info!(from = %cand.display(), "wintun.dll 本地复用（免下载）");
            roles::audit(
                "gui.wintun_download",
                serde_json::json!({"source": format!("local:{}", cand.display())}),
            );
            return Ok(true);
        }
    }
    Ok(false)
}

/// 确保 wintun.dll 存在（已存在 / 本地候选复用即返回），仅 Windows x64 需要。
/// 缺失时**不再当场下载**——返回 NEED_DOWNLOAD 错误，由下载管理器（download.rs）
/// 后台流式下载 + 进度展示，完成后前端重试原动作（见 set_tun_mode）。
pub async fn ensure_wintun() -> Result<PathBuf, String> {
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        Err("TUN 模式当前仅支持 Windows x64".into())
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        let dll = wintun_dll_path();
        if dll.exists() {
            return Ok(dll);
        }
        let dir = kernel_dir();
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        // 优先本地候选复用（受限网络下 wireguard.com 不可达时的主路径，免下载）
        if reuse_local_wintun(&dll)? {
            return Ok(dll);
        }
        Err(format!("{NEED_DOWNLOAD_PREFIX}wintun 组件未安装"))
    }
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
/// mode 为出站模式（rule|global|direct，非法值回落 rule）；tun=true 走 TUN 骨架（§2.3）。
pub fn render_config(store: &SubStore, mode: &str, tun: bool) -> String {
    if tun {
        return render_config_tun(store);
    }
    let mode = if roles::valid_sub_mode(mode) {
        mode
    } else {
        "rule"
    };
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
    s.push_str(&format!("mode: {mode}\n"));
    s.push_str("unified-delay: true\n");
    push_provider_section(&mut s, active);
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

/// proxy-providers 段（两种模式共用；保留：代理页测速/切换仍走控制面，与数据面解耦）。
/// 本地导入订阅（url 为 file:// 前缀）走 type: file 引用落盘 YAML，不经 URL 拉取。
fn push_provider_section(s: &mut String, active: Option<&Subscription>) {
    if let Some(sub) = active {
        s.push_str("proxy-providers:\n");
        s.push_str("  main:\n");
        if let Some(path) = sub.url.strip_prefix("file://") {
            s.push_str("    type: file\n");
            s.push_str(&format!("    path: \"{}\"\n", yaml_escape(path)));
        } else {
            s.push_str("    type: http\n");
            s.push_str(&format!("    url: \"{}\"\n", yaml_escape(&sub.url)));
            s.push_str("    interval: 86400\n");
            s.push_str("    proxy: DIRECT\n");
        }
        s.push_str("    health-check:\n");
        s.push_str("      enable: true\n");
        s.push_str("      url: http://www.gstatic.com/generate_204\n");
        s.push_str("      interval: 600\n");
    }
}

/// TUN 模式配置骨架（tun.md §2.3，全量重写原则不变）：
/// 无 mixed-port（关闭 57892，防环关键）；TUN 捕获全部流量，fake-ip 保域名，
/// 全部 TCP 经 ANET-IN（socks5 127.0.0.1:57890）转交 anet 路由器分流。
/// 既定决策：TUN 配置不经过覆写脚本链——脚本作用于订阅代理配置语义，
/// 本骨架的防环约束（无 mixed-port / ANET-IN 出站 / MATCH 指向）必须完整保留。
fn render_config_tun(store: &SubStore) -> String {
    let active = store.subscriptions.iter().find(|s| s.active);
    let mut s = String::new();
    s.push_str("# 本文件由 AgileNet 自动生成，手动修改将在下次启动时被覆盖（TUN 模式）\n");
    // 防环关键：严禁 mixed-port（57892 关闭），否则 57890→57892→MATCH→57890 死环（§2.5）
    s.push_str(&format!(
        "external-controller: 127.0.0.1:{MIHOMO_CTRL_PORT}\n"
    ));
    s.push_str(&format!("secret: \"{}\"\n", yaml_escape(&store.secret)));
    s.push_str("log-level: warning\n");
    // 订阅出口（P1.5）：socks 入站给 anet 回落用，经下方 IN-TYPE 规则直达 AGILE-SUB；
    // 无 FlClash 时 TUN 下未命中流量也能经订阅节点出网（mihomo 自身出站不被 TUN 捕获）
    s.push_str(&format!("socks-port: {MIHOMO_SOCKS_PORT}\n"));
    s.push_str("tun:\n");
    s.push_str("  enable: true\n");
    s.push_str("  stack: mixed              # TCP 系统栈 / UDP gVisor；异常时降级 gvisor\n");
    s.push_str("  auto-route: true\n");
    s.push_str("  auto-detect-interface: true\n");
    s.push_str("  dns-hijack:\n");
    s.push_str("    - any:53\n");
    s.push_str("dns:\n");
    // fake-ip 保域名：SOCKS5 CONNECT 以域名形式到达 57890，AgileNet 域名规则方可匹配
    s.push_str("  enable: true\n");
    s.push_str("  enhanced-mode: fake-ip\n");
    s.push_str("  fake-ip-range: 198.18.0.1/16\n");
    s.push_str("  nameserver:\n");
    s.push_str("    - 223.5.5.5\n");
    s.push_str("    - 119.29.29.29\n");
    s.push_str("proxies:\n");
    s.push_str("  - name: ANET-IN\n");
    s.push_str("    type: socks5\n");
    s.push_str("    server: 127.0.0.1\n");
    s.push_str("    port: 57890             # 唯一允许出现 57890 的位置（出站形式）\n");
    push_provider_section(&mut s, active);
    s.push_str("proxy-groups:\n");
    s.push_str("  - name: AGILE-SUB\n");
    s.push_str("    type: select\n");
    if active.is_some() {
        s.push_str("    use:\n");
        s.push_str("      - main\n");
    }
    s.push_str("rules:\n");
    s.push_str("  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT   # 压制 QUIC：anet 入站不支持 UDP，强制回退 TCP\n");
    s.push_str("  - NETWORK,UDP,DIRECT                          # 其余 UDP（STUN 等）直连，P1 不接管\n");
    s.push_str("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n");
    s.push_str("  - IN-TYPE,socks,AGILE-SUB                   # anet 回落（socks 入站）直达订阅出口\n");
    s.push_str("  - MATCH,ANET-IN                               # 全部 TCP 转交 anet 路由器\n");
    s
}

/// 防环静态检查（§2.5 硬约束）：配置生成后、落盘前执行，违规即拒绝启动内核。
/// TUN 配置：不得含 mixed-port；57892 严禁出现；57890 仅以 proxies 出站形式出现一次；
/// rules 必须 MATCH→ANET-IN（严禁回指 57892）。
/// 非 TUN 配置：维持原断言（严禁引用本地代理 57890；mixed-port 57892 是内核自身入站，合法）。
/// secret 行为随机十六进制，可能巧合命中端口数字串，不参与检查。
pub(crate) fn check_no_loop(cfg: &str, tun: bool) -> Result<(), String> {
    let body: Vec<&str> = cfg
        .lines()
        .filter(|l| !l.starts_with("secret:"))
        .collect();
    let hit = |needle: &str| body.iter().filter(|l| l.contains(needle)).count();
    if tun {
        if hit("mixed-port") > 0 {
            return Err("TUN 配置严禁含 mixed-port（57892 与 57890 互指会成死环）".into());
        }
        if hit("57892") > 0 {
            return Err("TUN 配置严禁引用 57892（防环）".into());
        }
        let n = hit("57890");
        if n != 1 || !body.iter().any(|l| l.trim().starts_with("port: 57890")) {
            return Err("TUN 配置中 57890 须且仅须出现在 ANET-IN proxies 出站".into());
        }
        if hit("  - MATCH,ANET-IN") != 1 {
            return Err("TUN 配置 rules 必须以 MATCH,ANET-IN 收尾".into());
        }
        // P1.5 订阅出口：socks 入站与 IN-TYPE 规则必须各出现且仅出现一次
        if hit("57893") != 1 || !body.iter().any(|l| l.starts_with("socks-port: 57893")) {
            return Err("TUN 配置须含且仅含 socks-port: 57893（订阅出口入站）".into());
        }
        if hit("  - IN-TYPE,socks,AGILE-SUB") != 1 {
            return Err("TUN 配置 rules 须含 IN-TYPE,socks,AGILE-SUB（订阅出口规则）".into());
        }
    } else if hit("57890") > 0 {
        return Err("配置不得引用本地代理端口 57890（防环）".into());
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod job_tests {
    #[test]
    fn job_set_kill_on_close() {
        use windows_sys::Win32::System::JobObjects::*;
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            assert!(!job.is_null());
            let mut info: super::JobObjectExtendedLimitInformation = std::mem::zeroed();
            info.basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<super::JobObjectExtendedLimitInformation>() as u32,
            );
            let err = std::io::Error::last_os_error();
            windows_sys::Win32::Foundation::CloseHandle(job);
            assert!(ok != 0, "SetInformationJobObject failed: {err}");
        }
    }
}

// ==================== 内核下载（钉版本 + SHA-256 校验 + 原子落盘） ====================

/// JOBOBJECT_EXTENDED_LIMIT_INFORMATION（windows-sys 0.59 未收录，按 SDK 布局自绘；
/// KILL_ON_JOB_CLOSE 实测必须用 Extended 类，Basic 类报 ERROR_INVALID_PARAMETER）
#[repr(C)]
#[derive(Clone, Copy)]
struct IoCounters {
    read_ops: u64,
    write_ops: u64,
    other_ops: u64,
    read_bytes: u64,
    write_bytes: u64,
    other_bytes: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct JobObjectExtendedLimitInformation {
    basic: windows_sys::Win32::System::JobObjects::JOBOBJECT_BASIC_LIMIT_INFORMATION,
    io: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

/// Windows：把内核子进程挂进带 KILL_ON_JOB_CLOSE 的 Job——GUI 以任何方式退出
/// （崩溃、强杀、提权重启 app.exit）系统都会连带终止内核，杜绝孤儿 mihomo。
/// Job 句柄有意保持打开直至本进程退出（句柄泄漏即生命周期锚点）。
#[cfg(windows)]
fn bind_kill_on_close(child: &tokio::process::Child) {
    use windows_sys::Win32::System::JobObjects::*;
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            tracing::warn!("CreateJobObjectW failed; kernel not bound to GUI lifetime");
            return;
        }
        let mut info: JobObjectExtendedLimitInformation = std::mem::zeroed();
        info.basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JobObjectExtendedLimitInformation>() as u32,
        );
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            windows_sys::Win32::Foundation::CloseHandle(job);
            tracing::warn!(error = %err, "SetInformationJobObject failed; kernel not bound");
            return;
        }
        if let Some(h) = child.raw_handle() {
            if AssignProcessToJobObject(job, h) == 0 {
                tracing::warn!("AssignProcessToJobObject failed (kernel may already be in a job)");
            }
        }
    }
}

/// 启动前清扫遗留内核进程（只杀 exe 路径=本应用内核目录者，用户自建的 mihomo/Clash 不动；
/// 提权实例遗留的无权限进程跳过——Job 绑定普及后此类遗留只会越来越少）。
#[cfg(windows)]
pub fn sweep_orphan_kernels() {
    let exe = kernel_bin_path();
    let script = format!(
        "Get-CimInstance Win32_Process -Filter \"Name='mihomo.exe'\" \
         | Where-Object {{ $_.ExecutablePath -eq '{}' }} \
         | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}",
        exe.to_string_lossy()
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output();
}

// ==================== 内核下载（钉版本 + SHA-256 校验 + 原子落盘） ====================

/// 确保内核二进制存在；缺失时**不再当场下载**——返回 NEED_DOWNLOAD 错误，
/// 由下载管理器（download.rs）后台流式下载 + 进度展示，完成后前端重试原动作。
pub async fn ensure_kernel() -> Result<PathBuf, String> {
    let bin = kernel_bin_path();
    if bin.exists() {
        return Ok(bin);
    }
    if kernel_asset().is_none() {
        return Err("当前平台不支持订阅内核（仅 Windows x64 / macOS）".into());
    }
    Err(format!("{NEED_DOWNLOAD_PREFIX}订阅内核未安装"))
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
    /// 最近一次生成配置时被跳过的覆写脚本（脚本名, 错误摘要；空 = 全部成功）
    pub script_errors: Vec<(String, String)>,
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
    /// /connections 连接跟踪（活跃 map + 已关闭环 + 命中聚合）
    tracker: Arc<ConnTracker>,
    conns_stop: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>>,
    logs_stop: Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>>,
    /// 最近一次启动时覆写脚本失败摘要（供前端灵动岛告警展示）
    script_errors: Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

impl Default for KernelManager {
    fn default() -> Self {
        Self {
            stop_tx: Arc::new(std::sync::Mutex::new(None)),
            restart_count: Arc::new(AtomicU32::new(0)),
            last_error: Arc::new(std::sync::Mutex::new(String::new())),
            traffic: Arc::new(TrafficStats::default()),
            traffic_stop: Arc::new(std::sync::Mutex::new(None)),
            tracker: Arc::new(ConnTracker::default()),
            conns_stop: Arc::new(std::sync::Mutex::new(None)),
            logs_stop: Arc::new(std::sync::Mutex::new(None)),
            script_errors: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

impl KernelManager {
    /// 启动内核（重写配置 → spawn → supervisor 监控）。
    pub async fn start(&self) -> Result<(), String> {
        if self.stop_tx.lock().unwrap().is_some() {
            return Ok(());
        }
        #[cfg(windows)]
        sweep_orphan_kernels();
        let mut store = load_store();
        if store.subscriptions.is_empty() {
            return Err("请先添加订阅".into());
        }
        ensure_secret(&mut store);
        save_store(&store)?;
        ensure_kernel().await?;
        // 配置生成管线：基础 render（含出站模式与 TUN 分模式）→ 覆写脚本链（失败脚本跳过并审计）→
        // 防环静态检查（§2.5 硬约束，违规拒绝启动）→ 落盘。
        // TUN 模式既定决策：TUN 骨架不经过脚本链——脚本作用于订阅代理配置语义，
        // TUN 骨架防环约束（无 mixed-port / ANET-IN 出站 / MATCH 指向）必须完整保留。
        let settings = roles::RoleSettings::load();
        let effective = if settings.tun_mode {
            *self.script_errors.lock().unwrap() = Vec::new();
            render_config(&store, &settings.sub_mode, true)
        } else {
            let base = render_config(&store, &settings.sub_mode, false);
            let (effective, script_fails) =
                crate::sub_script::apply_scripts(&base, &settings.sub_scripts);
            *self.script_errors.lock().unwrap() = script_fails;
            effective
        };
        check_no_loop(&effective, settings.tun_mode)?;
        std::fs::write(config_path(), effective).map_err(|e| e.to_string())?;

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
            return Err("内核启动后控制面未就绪（端口被占用或权限不足？）".into());
        }
        self.start_traffic();
        self.start_collectors();
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

    /// 挂 /connections 与 /logs WS 采集任务（幂等；内核停止时经信号终止并清零，
    /// 与 start_traffic 同一生命周期模式——仅在内核就绪后挂载，未运行不空转）。
    fn start_collectors(&self) {
        let store = load_store();
        if store.secret.is_empty() {
            return;
        }
        self.tracker.reset();
        // /connections：全量快照 → 活跃 map + 已关闭环 + 命中聚合
        if self.conns_stop.lock().unwrap().is_none() {
            let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
            *self.conns_stop.lock().unwrap() = Some(tx);
            let tracker = self.tracker.clone();
            let slot = self.conns_stop.clone();
            let secret = store.secret.clone();
            tokio::spawn(async move {
                collect_ws_loop(secret, "/connections", rx, move |payload| {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
                        tracker.apply_snapshot(&v);
                    }
                })
                .await;
                *slot.lock().unwrap() = None;
            });
        }
        // /logs?level=info：内核日志 ring buffer
        if self.logs_stop.lock().unwrap().is_none() {
            let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
            *self.logs_stop.lock().unwrap() = Some(tx);
            let tracker = self.tracker.clone();
            let slot = self.logs_stop.clone();
            let secret = store.secret.clone();
            tokio::spawn(async move {
                collect_ws_loop(secret, "/logs?level=info", rx, move |payload| {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
                        tracker.push_log(&v);
                    }
                })
                .await;
                *slot.lock().unwrap() = None;
            });
        }
    }

    /// 当前流量快照（内核停止后为零值）。
    pub fn traffic(&self) -> TrafficSnapshot {
        self.traffic.snapshot()
    }

    /// 连接快照（活跃, 已关闭）；内核停止后为空。
    pub fn connections(&self) -> (Vec<ConnectionInfo>, Vec<ConnectionInfo>) {
        self.tracker.connections()
    }

    /// 内核日志（旧→新）；内核停止后为空。
    pub fn logs(&self) -> Vec<LogEntry> {
        self.tracker.logs()
    }

    /// 规则命中聚合（count 降序，top 100）；内核停止后为空。
    pub fn rule_hits(&self) -> Vec<RuleHit> {
        self.tracker.rule_hits()
    }

    /// 清空日志与命中缓冲（连接态不动）。
    pub fn clear_logs(&self) {
        self.tracker.clear_logs();
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
        let child = cmd.spawn().map_err(|e| format!("内核启动失败: {e}"))?;
        #[cfg(windows)]
        bind_kill_on_close(&child);
        Ok(child)
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
        Self::drain_stop(&self.stop_tx).await;
        // 流量/连接/日志采集任务随内核停止：发信号并等待任务退出自清槽位（上限 5s；
        // 保证 stop→start 快速重启时挂载函数看到的是已清槽位，新旧任务不打架）
        Self::drain_stop(&self.traffic_stop).await;
        Self::drain_stop(&self.conns_stop).await;
        Self::drain_stop(&self.logs_stop).await;
        self.traffic.reset();
        self.tracker.reset();
        roles::audit("gui.kernel_stop", serde_json::json!({}));
    }

    /// 经槽位发停止信号并等待任务自清槽位（上限 5s）。
    async fn drain_stop(slot: &Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>>) {
        let tx = slot.lock().unwrap().clone();
        if let Some(tx) = tx {
            let _ = tx.send(()).await;
            for _ in 0..50 {
                if slot.lock().unwrap().is_none() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
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
            script_errors: self.script_errors.lock().unwrap().clone(),
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

    /// 出站模式热切（PATCH /configs，mihomo 支持 mode 热更新，无需重启内核）
    pub async fn set_mode(&self, mode: &str) -> Result<(), String> {
        let resp = self
            .req(reqwest::Method::PATCH, "/configs")
            .json(&serde_json::json!({"mode": mode}))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("模式切换失败 (HTTP {})", resp.status()))
        }
    }

    /// 关闭单条连接（DELETE /connections/{id}；mihomo 204 无体）
    pub async fn close_connection(&self, id: &str) -> Result<(), String> {
        let resp = self
            .req(reqwest::Method::DELETE, &format!("/connections/{id}"))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("关闭连接失败 (HTTP {})", resp.status()))
        }
    }

    /// 当前生效配置（GET /configs；E2E 断言 TUN 骨架已加载用）
    #[cfg(test)]
    pub async fn configs(&self) -> Result<serde_json::Value, String> {
        self.req(reqwest::Method::GET, "/configs")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
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

/// 单段 /traffic WS 会话（语义保持：text 帧 {up,down} 累计）。
async fn traffic_ws_session(secret: &str, stats: &TrafficStats) -> Result<(), String> {
    traffic_ws_session_on(MIHOMO_CTRL_PORT, secret, stats).await
}

/// 端口可参数化的 /traffic 会话（生产走控制面端口；测试注入 mock 端口）。
async fn traffic_ws_session_on(port: u16, secret: &str, stats: &TrafficStats) -> Result<(), String> {
    ws_session_on(port, secret, "/traffic", &mut |payload| {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
            stats.add(
                v["up"].as_u64().unwrap_or(0),
                v["down"].as_u64().unwrap_or(0),
            );
        }
    })
    .await
}

/// 采集通用重连循环（/connections、/logs 共用）：断线指数退避重连
/// （1s 起、30s 封顶，会话稳定 10s 后断线重置退避）；停止信号（含发送端被丢弃）即退出。
async fn collect_ws_loop<F>(
    secret: String,
    path: &str,
    mut stop: tokio::sync::mpsc::Receiver<()>,
    mut handler: F,
) where
    F: FnMut(&[u8]) + Send,
{
    let mut backoff = 1u64;
    loop {
        let started = std::time::Instant::now();
        tokio::select! {
            _ = stop.recv() => break,
            _ = ws_session_on(MIHOMO_CTRL_PORT, &secret, path, &mut handler) => {}
        }
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
}

/// 通用单段 WS 会话（握手路径参数化）：握手 → 帧循环（text/binary 帧交 handler /
/// ping→pong / close 正常结束）。极简 RFC 6455 客户端，仅面向 loopback mihomo 控制面，
/// 不引入额外依赖。
async fn ws_session_on<F: FnMut(&[u8])>(
    port: u16,
    secret: &str,
    path: &str,
    handler: &mut F,
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {secret}\r\n\r\n",
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
                    handler(&frame.payload);
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

/// 速率格式化（B/KB/MB 自适应，1024 进制；托盘 tooltip 与前端展示共用）
pub fn format_rate(bytes: u64) -> String {
    if bytes >= 1 << 20 {
        format!("{:.1} MB", bytes as f64 / 1048576.0)
    } else if bytes >= 1 << 10 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// ==================== 连接/日志采集（/connections、/logs WS） ====================

/// 连接记录（活跃与已关闭共用结构；速率由相邻快照差分得出）
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    /// 目标主机（metadata.host 优先，缺省 destinationIP）
    pub host: String,
    /// 发起进程（metadata.process；未知为空串）
    pub process: String,
    /// 出站链（末段即节点名）
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub upload: u64,
    pub download: u64,
    /// 快照差分速率（字节/秒；已关闭连接恒 0）
    pub up_rate: u64,
    pub down_rate: u64,
    /// 建立时间（秒级时间戳）
    pub start: u64,
    /// 存活时长（秒；活跃=至今，关闭=总存活）
    pub elapsed: u64,
}

/// 内核日志条目（/logs WS 推送）
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// 收到时间（秒级时间戳）
    pub time: u64,
    pub level: String,
    pub payload: String,
}

/// 规则命中聚合（按 rule+rule_payload）
#[derive(Debug, Clone, Serialize)]
pub struct RuleHit {
    pub rule: String,
    pub payload: String,
    pub count: u64,
    pub last_host: String,
    pub last_seen: u64,
}

/// 活跃连接内部态（ConnectionInfo + 差分基准）
#[derive(Debug)]
struct ConnState {
    info: ConnectionInfo,
    last_up: u64,
    last_down: u64,
    last_tick: std::time::Instant,
}

/// 连接/日志/命中缓冲（Mutex 短临界区，与 TrafficStats 全 Atomic 风格并列的既定简单方案；
/// 随内核 stop 清零——内核停止后命令层返回空集）
#[derive(Debug, Default)]
pub struct ConnTracker {
    active: std::sync::Mutex<std::collections::HashMap<String, ConnState>>,
    /// 最近已关闭（新的在前，上限 300）
    closed: std::sync::Mutex<std::collections::VecDeque<ConnectionInfo>>,
    /// 命中聚合 key=(rule, rule_payload)，保留 top 100
    hits: std::sync::Mutex<std::collections::HashMap<(String, String), RuleHit>>,
    /// 日志 ring buffer（上限 500，旧→新排列）
    logs: std::sync::Mutex<std::collections::VecDeque<LogEntry>>,
}

impl ConnTracker {
    /// /connections 全量快照：更新活跃表（差分速率）、迁移消失项到已关闭环、登记新连接命中。
    fn apply_snapshot(&self, v: &serde_json::Value) {
        let now = now_ts();
        let Some(list) = v["connections"].as_array() else {
            return;
        };
        let mut active = self.active.lock().unwrap();
        let mut seen = std::collections::HashSet::new();
        for c in list {
            let Some(id) = c["id"].as_str() else { continue };
            seen.insert(id.to_string());
            let up = c["upload"].as_u64().unwrap_or(0);
            let down = c["download"].as_u64().unwrap_or(0);
            if let Some(st) = active.get_mut(id) {
                let dt = st.last_tick.elapsed().as_secs().max(1);
                st.info.up_rate = up.saturating_sub(st.last_up) / dt;
                st.info.down_rate = down.saturating_sub(st.last_down) / dt;
                st.info.upload = up;
                st.info.download = down;
                st.info.elapsed = now.saturating_sub(st.info.start);
                st.last_up = up;
                st.last_down = down;
                st.last_tick = std::time::Instant::now();
            } else {
                let md = &c["metadata"];
                let host = md["host"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .or_else(|| md["destinationIP"].as_str())
                    .unwrap_or_default()
                    .to_string();
                let info = ConnectionInfo {
                    id: id.to_string(),
                    host,
                    process: md["process"].as_str().unwrap_or_default().to_string(),
                    chains: c["chains"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    rule: c["rule"].as_str().unwrap_or_default().to_string(),
                    rule_payload: c["rulePayload"].as_str().unwrap_or_default().to_string(),
                    upload: up,
                    download: down,
                    up_rate: 0,
                    down_rate: 0,
                    start: c["start"].as_str().and_then(parse_rfc3339_ts).unwrap_or(now),
                    elapsed: 0,
                };
                self.record_hit(&info);
                active.insert(
                    id.to_string(),
                    ConnState {
                        info,
                        last_up: up,
                        last_down: down,
                        last_tick: std::time::Instant::now(),
                    },
                );
            }
        }
        // 快照中消失 = 已关闭：迁移到环首（固定速率清零，elapsed 定格）
        let gone: Vec<String> = active.keys().filter(|k| !seen.contains(*k)).cloned().collect();
        if !gone.is_empty() {
            let mut closed = self.closed.lock().unwrap();
            for id in gone {
                if let Some(mut st) = active.remove(&id) {
                    st.info.up_rate = 0;
                    st.info.down_rate = 0;
                    closed.push_front(st.info);
                }
            }
            while closed.len() > 300 {
                closed.pop_back();
            }
        }
    }

    /// 新连接命中登记（count 递增；超过 128 键时修剪保留 top 100）
    fn record_hit(&self, info: &ConnectionInfo) {
        if info.rule.is_empty() {
            return;
        }
        let mut hits = self.hits.lock().unwrap();
        let key = (info.rule.clone(), info.rule_payload.clone());
        let h = hits.entry(key).or_insert_with(|| RuleHit {
            rule: info.rule.clone(),
            payload: info.rule_payload.clone(),
            count: 0,
            last_host: String::new(),
            last_seen: 0,
        });
        h.count += 1;
        h.last_host = info.host.clone();
        h.last_seen = now_ts();
        if hits.len() > 128 {
            let mut all: Vec<(String, String)> = hits
                .values()
                .map(|x| (x.rule.clone(), x.payload.clone()))
                .collect();
            all.sort_by_key(|k| std::cmp::Reverse(hits[k].count));
            all.truncate(100);
            let keep: std::collections::HashSet<_> = all.into_iter().collect();
            hits.retain(|k, _| keep.contains(k));
        }
    }

    fn push_log(&self, v: &serde_json::Value) {
        let Some(payload) = v["payload"].as_str() else {
            return;
        };
        let mut logs = self.logs.lock().unwrap();
        logs.push_back(LogEntry {
            time: now_ts(),
            level: v["type"].as_str().unwrap_or("info").to_string(),
            payload: payload.to_string(),
        });
        while logs.len() > 500 {
            logs.pop_front();
        }
    }

    fn connections(&self) -> (Vec<ConnectionInfo>, Vec<ConnectionInfo>) {
        let active = self
            .active
            .lock()
            .unwrap()
            .values()
            .map(|st| st.info.clone())
            .collect();
        let closed = self.closed.lock().unwrap().iter().cloned().collect();
        (active, closed)
    }

    fn rule_hits(&self) -> Vec<RuleHit> {
        let mut v: Vec<RuleHit> = self.hits.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then(b.last_seen.cmp(&a.last_seen)));
        v
    }

    fn logs(&self) -> Vec<LogEntry> {
        self.logs.lock().unwrap().iter().cloned().collect()
    }

    /// 清空日志与命中缓冲（sub_clear_logs 命令；连接态不动）
    fn clear_logs(&self) {
        self.logs.lock().unwrap().clear();
        self.hits.lock().unwrap().clear();
    }

    /// 采集任务退出即清零（对齐 traffic 停止清零语义）
    fn reset(&self) {
        self.active.lock().unwrap().clear();
        self.closed.lock().unwrap().clear();
        self.hits.lock().unwrap().clear();
        self.logs.lock().unwrap().clear();
    }
}

/// 极简 RFC3339 时间戳解析（mihomo start 字段；容忍小数秒与 Z/±HH:MM 偏移，仅取秒）。
/// 不引入 chrono——控制面数据，解析失败由调用方回落当前时间。
fn parse_rfc3339_ts(s: &str) -> Option<u64> {
    let (date, rest) = s.split_once('T')?;
    let mut it = date.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let mo: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    // 时区标记只可能出现在 "HH:MM:SS" 第 8 字节之后
    let tz_at = rest
        .char_indices()
        .skip_while(|(i, _)| *i < 8)
        .find(|(_, c)| matches!(c, 'Z' | '+' | '-'))
        .map(|(i, _)| i);
    let (time_s, tz_s) = match tz_at {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "Z"),
    };
    let time_s = time_s.split('.').next()?;
    let mut it = time_s.split(':');
    let hh: i64 = it.next()?.parse().ok()?;
    let mm: i64 = it.next().unwrap_or("0").parse().ok()?;
    let ss: i64 = it.next().unwrap_or("0").parse().ok()?;
    let off: i64 = match tz_s {
        "" | "Z" => 0,
        t => {
            let sign = if t.starts_with('-') { -1 } else { 1 };
            let mut it = t[1..].split(':');
            let h: i64 = it.next()?.parse().ok()?;
            let m: i64 = it.next().unwrap_or("0").parse().ok()?;
            sign * (h * 3600 + m * 60)
        }
    };
    // days-from-civil（Howard Hinnant 算法）
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let ts = days * 86400 + hh * 3600 + mm * 60 + ss - off;
    u64::try_from(ts).ok()
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
        let cfg = render_config(&store, "rule", false);
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
        assert!(check_no_loop(&cfg, false).is_ok());
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
        let cfg = render_config(&store, "rule", false);
        assert!(cfg.contains("\\\"injected"));
    }

    #[test]
    fn config_render_local_file_provider() {
        // 本地导入订阅（file:// 前缀）渲染为 type: file + path，不经 URL 拉取
        let mut store = SubStore::default();
        store.secret = "s".into();
        store.subscriptions.push(Subscription {
            id: "a".into(),
            name: "本地".into(),
            url: "file://C:/Users/x/local-a.yaml".into(),
            active: true,
            updated_at: None,
            node_count: 0,
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
        });
        let cfg = render_config(&store, "rule", false);
        assert!(cfg.contains("    type: file\n"));
        assert!(cfg.contains("    path: \"C:/Users/x/local-a.yaml\"\n"));
        assert!(!cfg.contains("type: http"));
        assert!(!cfg.contains("interval: 86400"));
        assert!(check_no_loop(&cfg, false).is_ok());
        // TUN 骨架同样支持
        let cfg = render_config(&store, "rule", true);
        assert!(cfg.contains("    type: file\n"));
        assert!(check_no_loop(&cfg, true).is_ok());
    }

    #[test]
    fn config_render_mode_three_states() {
        let store = SubStore::default();
        for (mode, expect) in [
            ("rule", "mode: rule\n"),
            ("global", "mode: global\n"),
            ("direct", "mode: direct\n"),
        ] {
            assert!(render_config(&store, mode, false).contains(expect), "mode={mode}");
        }
        // 非法值回落 rule
        assert!(render_config(&store, "bogus", false).contains("mode: rule\n"));
    }

    /// TUN 模式配置快照（tun.md §2.3 骨架逐字段）+ 防环检查通过
    #[test]
    fn config_render_tun_snapshot() {
        let mut store = SubStore::default();
        store.secret = "s3cret".into();
        store.subscriptions.push(Subscription {
            id: "a".into(),
            name: "机场A".into(),
            url: "https://example.com/sub?token=abc".into(),
            active: true,
            updated_at: None,
            node_count: 0,
            upload: 0,
            download: 0,
            total: 0,
            expire: None,
        });
        let cfg = render_config(&store, "rule", true);
        // 骨架头部：无 mixed-port（防环关键），控制面保留
        assert!(!cfg.contains("mixed-port"));
        assert!(cfg.contains("external-controller: 127.0.0.1:59292"));
        assert!(cfg.contains("secret: \"s3cret\""));
        // tun 段：enable / stack mixed / auto-route / auto-detect-interface / dns-hijack
        assert!(cfg.contains("tun:\n  enable: true\n"));
        assert!(cfg.contains("  stack: mixed"));
        assert!(cfg.contains("  auto-route: true\n"));
        assert!(cfg.contains("  auto-detect-interface: true\n"));
        assert!(cfg.contains("    - any:53\n"));
        // dns 段：fake-ip 保域名
        assert!(cfg.contains("  enhanced-mode: fake-ip\n"));
        assert!(cfg.contains("  fake-ip-range: 198.18.0.1/16\n"));
        assert!(cfg.contains("    - 223.5.5.5\n"));
        // ANET-IN socks5 → 57890（全量 TCP 转交 anet 路由器）
        assert!(cfg.contains("  - name: ANET-IN\n    type: socks5\n    server: 127.0.0.1\n"));
        assert!(cfg.contains("    port: 57890"));
        // P1.5 订阅出口：socks 入站 57893 + IN-TYPE 规则直达 AGILE-SUB
        assert!(cfg.contains("socks-port: 57893\n"));
        assert!(cfg.contains("  - IN-TYPE,socks,AGILE-SUB"));
        // proxy-providers 保留（代理页测速/切换仍走控制面）
        assert!(cfg.contains("proxy-providers:\n  main:\n"));
        assert!(cfg.contains("url: \"https://example.com/sub?token=abc\""));
        assert!(cfg.contains("  - name: AGILE-SUB\n    type: select\n    use:\n      - main\n"));
        // rules：QUIC 压制 + UDP DIRECT + 回环直连 + MATCH→ANET-IN
        assert!(cfg.contains("  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
        assert!(cfg.contains("  - NETWORK,UDP,DIRECT"));
        assert!(cfg.contains("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve\n"));
        assert!(cfg.contains("  - MATCH,ANET-IN"));
        assert!(check_no_loop(&cfg, true).is_ok(), "TUN 骨架须过防环检查");
    }

    /// 防环静态检查全覆盖（tun.md §2.5 各条）
    #[test]
    fn check_no_loop_covers_all_clauses() {
        let mut store = SubStore::default();
        store.secret = "s".into();
        let tun_cfg = render_config(&store, "rule", true);
        let base_cfg = render_config(&store, "rule", false);
        assert!(check_no_loop(&tun_cfg, true).is_ok());
        assert!(check_no_loop(&base_cfg, false).is_ok());

        // TUN：含 mixed-port → 拒绝
        let bad = tun_cfg.replace("tun:\n", "mixed-port: 57892\ntun:\n");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN：57892 出现（rules 回指）→ 拒绝
        let bad = tun_cfg.replace("  - MATCH,ANET-IN", "  - MATCH,ANET-IN\n  - DST-PORT,57892,DIRECT");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN：57890 重复出现（rules 回指本地代理）→ 拒绝
        let bad = tun_cfg.replace(
            "  - MATCH,ANET-IN",
            "  - IP-CIDR,127.0.0.1/32,DIRECT # 57890\n  - MATCH,ANET-IN",
        );
        assert!(check_no_loop(&bad, true).is_err());
        // TUN：57890 不在 proxies 出站行（被挪到注释里）→ 拒绝
        let bad = tun_cfg.replace("    port: 57890", "    port: 15789 # 57890");
        assert!(check_no_loop(&bad, true).is_err());
        // TUN：缺 MATCH,ANET-IN → 拒绝
        let bad = tun_cfg.replace("  - MATCH,ANET-IN", "  - MATCH,AGILE-SUB");
        assert!(check_no_loop(&bad, true).is_err());
        // 非 TUN：引用 57890 → 拒绝；mixed-port 57892 是内核自身入站（合法，维持原断言）
        let bad = base_cfg.replace("  - MATCH,AGILE-SUB", "  - MATCH,AGILE-SUB # 57890");
        assert!(check_no_loop(&bad, false).is_err());
        assert!(base_cfg.contains("mixed-port: 57892"));
        assert!(check_no_loop(&base_cfg, false).is_ok());
        // secret 行随机十六进制巧合命中端口串不误伤
        let mut store = SubStore::default();
        store.secret = "57890abcdef".into();
        let cfg = render_config(&store, "rule", false);
        assert!(check_no_loop(&cfg, false).is_ok(), "secret 行不参与检查");
        let cfg = render_config(&store, "rule", true);
        assert!(check_no_loop(&cfg, true).is_ok(), "secret 行不参与检查");
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

    #[test]
    fn format_rate_scales() {
        assert_eq!(format_rate(0), "0 B");
        assert_eq!(format_rate(512), "512 B");
        assert_eq!(format_rate(1024), "1.0 KB");
        assert_eq!(format_rate(1536), "1.5 KB");
        assert_eq!(format_rate(1048576), "1.0 MB");
        assert_eq!(format_rate(12 * 1048576 + 524288), "12.5 MB");
    }

    #[test]
    fn rfc3339_parse_variants() {
        assert_eq!(parse_rfc3339_ts("1970-01-01T00:00:00Z"), Some(0));
        // +08:00 的 08:00 = UTC 00:00
        assert_eq!(parse_rfc3339_ts("1970-01-01T08:00:00+08:00"), Some(0));
        assert_eq!(parse_rfc3339_ts("2024-01-01T00:00:00Z"), Some(1704067200));
        // 小数秒容忍（mihomo 实际格式）
        assert_eq!(parse_rfc3339_ts("2024-01-01T00:00:00.123456Z"), Some(1704067200));
        // 负偏移
        assert_eq!(parse_rfc3339_ts("2023-12-31T19:00:00-05:00"), Some(1704067200));
        // 非法输入
        assert!(parse_rfc3339_ts("not-a-time").is_none());
        assert!(parse_rfc3339_ts("").is_none());
    }

    #[test]
    fn conn_tracker_snapshot_lifecycle() {
        let t = ConnTracker::default();
        let snap = |conns: serde_json::Value| serde_json::json!({"connections": conns});
        let conn = |id: &str, up: u64, down: u64| {
            serde_json::json!({
                "id": id,
                "metadata": {"host": "example.com", "process": "chrome.exe", "destinationIP": "93.184.216.34"},
                "upload": up, "download": down,
                "start": "1970-01-01T00:00:00Z",
                "chains": ["AGILE-SUB", "节点A"],
                "rule": "DomainSuffix", "rulePayload": "example.com"
            })
        };
        // 首个快照：两条活跃
        t.apply_snapshot(&snap(serde_json::json!([conn("c1", 100, 200), conn("c2", 0, 0)])));
        let (active, closed) = t.connections();
        assert_eq!(active.len(), 2);
        assert!(closed.is_empty());
        let c1 = active.iter().find(|c| c.id == "c1").unwrap();
        assert_eq!(c1.host, "example.com");
        assert_eq!(c1.process, "chrome.exe");
        assert_eq!(c1.chains, vec!["AGILE-SUB", "节点A"]);
        assert_eq!(c1.rule, "DomainSuffix");
        assert_eq!(c1.rule_payload, "example.com");
        assert_eq!((c1.upload, c1.download), (100, 200));
        // 命中聚合
        let hits = t.rule_hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].count, 2);
        assert_eq!(hits[0].last_host, "example.com");
        // 第二个快照：c1 仍在（累计增长）, c2 消失 → 已关闭环
        std::thread::sleep(std::time::Duration::from_millis(1100));
        t.apply_snapshot(&snap(serde_json::json!([conn("c1", 300, 500)])));
        let (active, closed) = t.connections();
        assert_eq!(active.len(), 1);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id, "c2");
        assert_eq!((closed[0].up_rate, closed[0].down_rate), (0, 0));
        let c1 = &active[0];
        assert_eq!((c1.upload, c1.download), (300, 500));
        assert!(c1.up_rate > 0 && c1.down_rate > 0, "差分速率应 > 0");
        assert!(c1.elapsed >= 1, "start=epoch，elapsed 须为大值");
        // host 缺省回落 destinationIP；rule 空不记命中
        let bare = serde_json::json!({
            "id": "c3", "metadata": {"destinationIP": "1.1.1.1"},
            "upload": 1, "download": 1, "start": "bad-start", "chains": []
        });
        t.apply_snapshot(&snap(serde_json::json!([conn("c1", 300, 500), bare])));
        let (active, _) = t.connections();
        let c3 = active.iter().find(|c| c.id == "c3").unwrap();
        assert_eq!(c3.host, "1.1.1.1");
        assert_eq!(t.rule_hits().len(), 1, "rule 缺失不记命中");
        // 清空后全空
        t.reset();
        let (active, closed) = t.connections();
        assert!(active.is_empty() && closed.is_empty());
        assert!(t.rule_hits().is_empty());
    }

    #[test]
    fn log_buffer_ring_and_clear() {
        let t = ConnTracker::default();
        for i in 0..505 {
            t.push_log(&serde_json::json!({"type": "info", "payload": format!("log-{i}")}));
        }
        let logs = t.logs();
        assert_eq!(logs.len(), 500, "ring 上限 500");
        assert_eq!(logs[0].payload, "log-5", "最旧的被挤出（旧→新排列）");
        assert_eq!(logs[499].payload, "log-504");
        // 非日志载荷忽略
        t.push_log(&serde_json::json!({"type": "info"}));
        assert_eq!(t.logs().len(), 500);
        t.clear_logs();
        assert!(t.logs().is_empty());
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

        // 内核缺失时先经下载管理器落盘（ensure_kernel 不再当场下载）
        if !kernel_bin_exists() {
            let st = std::sync::Arc::new(std::sync::Mutex::new(crate::download::DlState::default()));
            crate::download::run_download(crate::download::Artifact::Kernel, st)
                .await
                .unwrap();
        }
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

    /// TUN 接管全链路 E2E（docs/plan/tun.md §2.8；需管理员本机手动，显式 --ignored 运行）：
    /// cargo test --manifest-path apps/desktop/Cargo.toml tun_e2e -- --ignored --nocapture
    ///
    /// 自动断言：wintun 下载校验落盘 → TUN 配置启动内核 → 控制面 /configs 确认 tun.enable=true
    /// 且无 mixed-port。以下步骤按 §2.8 手动验证（需 FlClash 监听 7890 与 AgileNet 端点在线）：
    ///   1. curl http://ip.sb（不带 -x，模拟不读系统代理应用）→ 出口 IP = FlClash 节点
    ///   2. AgileNet 内网域名走隧道通
    ///   3. 浏览器系统代理 = 57890 访问谷歌经 anet→FlClash 通
    ///   4. 关 FlClash → 未命中失败 + 灵动岛上报告警
    ///   5. 退出 GUI → 系统代理与路由表还原
    #[tokio::test]
    #[ignore = "需管理员本机 + 联网下载 wintun/内核，显式 --ignored 运行"]
    async fn tun_e2e() {
        use crate::tun::Elevation;
        if !crate::tun::SystemElevation.is_admin() {
            eprintln!("跳过：需以管理员身份运行本测试（TUN 需管理员权限）");
            return;
        }
        // 备份并隔离真实配置（测试结束还原，不污染用户数据）
        let settings_file = roles::data_dir().join("gui-settings.json");
        let settings_backup = std::fs::read_to_string(&settings_file).ok();
        let sub_file = store_path();
        let sub_backup = std::fs::read_to_string(&sub_file).ok();
        let restore = || {
            match &settings_backup {
                Some(s) => std::fs::write(&settings_file, s).unwrap(),
                None => {
                    let _ = std::fs::remove_file(&settings_file);
                }
            }
            match &sub_backup {
                Some(s) => std::fs::write(&sub_file, s).unwrap(),
                None => {
                    let _ = std::fs::remove_file(&sub_file);
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
        let settings = roles::RoleSettings {
            tun_mode: true,
            subscription: true,
            ..Default::default()
        };
        settings.save().unwrap();

        let km = KernelManager::default();
        let result = async {
            // 内核/wintun 缺失时先经下载管理器落盘（ensure_* 不再当场下载）
            if !kernel_bin_exists() {
                let st = std::sync::Arc::new(std::sync::Mutex::new(
                    crate::download::DlState::default(),
                ));
                crate::download::run_download(crate::download::Artifact::Kernel, st)
                    .await
                    .map_err(|e| format!("内核下载: {e}"))?;
            }
            if let Err(e) = ensure_wintun().await {
                if e.starts_with(NEED_DOWNLOAD_PREFIX) {
                    let st = std::sync::Arc::new(std::sync::Mutex::new(
                        crate::download::DlState::default(),
                    ));
                    crate::download::run_download(crate::download::Artifact::Wintun, st)
                        .await
                        .map_err(|e2| format!("wintun 下载: {e2}"))?;
                } else {
                    return Err(format!("wintun: {e}"));
                }
            }
            assert!(wintun_dll_path().exists(), "wintun.dll 未落盘");
            km.start().await.map_err(|e| format!("start: {e}"))?;
            let api = kernel_api().await?;
            let cfg = api.configs().await?;
            assert_eq!(cfg["tun"]["enable"].as_bool(), Some(true), "控制面未见 TUN 生效");
            assert!(cfg.get("mixed-port").is_none(), "TUN 配置严禁 mixed-port");
            eprintln!("TUN 已接管；请按 docs/plan/tun.md §2.8 手动执行 curl/浏览器验证步骤");
            Ok::<(), String>(())
        }
        .await;
        km.stop().await;
        restore();
        result.unwrap();
    }
}
