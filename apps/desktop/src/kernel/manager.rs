//! 从 subscription.rs 拆分：内核进程生命周期（纯搬运，零逻辑变更）

use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::roles;

use super::api::kernel_api;
use super::config::{check_no_loop, render_config};
use super::store::{config_path, ensure_secret, kernel_bin_path, kernel_dir, load_store, save_store};
use super::ws::{
    ConnTracker, ConnectionInfo, LogEntry, RuleHit, TrafficSnapshot, TrafficStats,
    collect_ws_loop, traffic_ws_loop,
};

/// 钉死的内核版本与资产（升级内核 = 改这里 + 更新哈希）
pub const MIHOMO_VERSION: &str = "1.19.29";
/// 制品缺失时的错误前缀：前端据此转下载流程（展示下载进度卡，不当作失败 toast）
pub const NEED_DOWNLOAD_PREFIX: &str = "NEED_DOWNLOAD:";

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::config::MIHOMO_MIXED_PORT;
    use crate::kernel::store::{
        SubStore, Subscription, add_subscription, kernel_bin_exists, store_path,
    };
    use crate::kernel::wintun::{ensure_wintun, wintun_dll_path};

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
