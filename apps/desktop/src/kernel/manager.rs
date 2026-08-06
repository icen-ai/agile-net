//! Split out of subscription.rs: kernel process lifecycle (pure move, zero logic changes)

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

/// Pinned kernel version and asset (kernel upgrade = change here + update the hash)
pub const MIHOMO_VERSION: &str = "1.19.29";
/// Error prefix when the artifact is missing: the frontend switches to the download flow (shows a download progress card, not a failure toast)
pub const NEED_DOWNLOAD_PREFIX: &str = "NEED_DOWNLOAD:";

/// (asset filename, SHA-256, in-archive binary name) for the current platform.
/// Hash provenance: the official Release file was cross-downloaded via two independent mirrors and verified identical.
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

/// Official Release URL + mirror fallback (mirrors are CDN only; integrity is guaranteed by the pinned SHA-256)
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

// ==================== Kernel download (pinned version + SHA-256 check + atomic write) ====================

/// JOBOBJECT_EXTENDED_LIMIT_INFORMATION (not covered by windows-sys 0.59; hand-rolled per SDK layout;
/// KILL_ON_JOB_CLOSE empirically requires the Extended class — Basic fails with ERROR_INVALID_PARAMETER)
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

/// Windows: bind the kernel child process to a Job with KILL_ON_JOB_CLOSE — however the GUI exits
/// (crash, force-kill, elevated restart via app.exit), the OS kills the kernel too; no orphan mihomo.
/// The Job handle is intentionally kept open until this process exits (the handle leak is the lifetime anchor).
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

/// Sweep leftover kernel processes before start (kills only those whose exe path is this app's kernel dir;
/// user-installed mihomo/Clash untouched; unkillable elevated leftovers are skipped — Job binding makes these rarer).
#[cfg(windows)]
pub fn sweep_orphan_kernels() {
    let exe = kernel_bin_path();
    let script = format!(
        "Get-CimInstance Win32_Process -Filter \"Name='mihomo.exe'\" \
         | Where-Object {{ $_.ExecutablePath -eq '{}' }} \
         | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}",
        exe.to_string_lossy()
    );
    let _ = agile_net_core::util::silent_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output();
}

// ==================== Kernel download (pinned version + SHA-256 check + atomic write) ====================

/// Ensure the kernel binary exists; if missing, **no longer downloads in place** — returns a NEED_DOWNLOAD error;
/// the download manager (download.rs) streams it in the background with progress, then the frontend retries the original action.
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

// ==================== Kernel lifecycle ====================

#[derive(Debug, Clone, Serialize)]
pub struct KernelStatus {
    pub supported: bool,
    pub installed: bool,
    pub running: bool,
    pub version: String,
    pub restart_count: u32,
    pub last_error: String,
    /// Override scripts skipped during the last config render (script name, error summary; empty = all succeeded)
    pub script_errors: Vec<(String, String)>,
}

/// Mutable kernel-manager state (single-lock aggregate, no per-slot boilerplate; locks are statement-scoped, never held across await).
#[derive(Default)]
struct KernelState {
    /// supervisor stop signal (the slot doubles as a liveness marker, cleared by the supervisor on exit)
    stop_tx: Option<tokio::sync::mpsc::Sender<()>>,
    last_error: String,
    /// /traffic WS collector stop signal
    traffic_stop: Option<tokio::sync::mpsc::Sender<()>>,
    /// /connections collector stop signal
    conns_stop: Option<tokio::sync::mpsc::Sender<()>>,
    /// /logs collector stop signal
    logs_stop: Option<tokio::sync::mpsc::Sender<()>>,
    /// Override-script failure summary from the last start (for the frontend dynamic-island alert)
    script_errors: Vec<(String, String)>,
}

/// Kernel process management: start/stop/crash-backoff restart (gives up and audits after 5 restarts).
/// The child process is owned exclusively by the supervisor task; stop goes through an mpsc signal (no lock held across await).
pub struct KernelManager {
    state: Arc<std::sync::Mutex<KernelState>>,
    restart_count: Arc<AtomicU32>,
    /// /traffic WS accumulator (task attached on kernel start, reset on stop)
    traffic: Arc<TrafficStats>,
    /// /connections tracking (active map + closed ring + hit aggregation)
    tracker: Arc<ConnTracker>,
}

impl Default for KernelManager {
    fn default() -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(KernelState::default())),
            restart_count: Arc::new(AtomicU32::new(0)),
            traffic: Arc::new(TrafficStats::default()),
            tracker: Arc::new(ConnTracker::default()),
        }
    }
}

impl KernelManager {
    /// Start the kernel (rewrite config → spawn → supervisor watch).
    pub async fn start(&self) -> Result<(), String> {
        if self.state.lock().unwrap().stop_tx.is_some() {
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
        // Config pipeline: base render (with outbound mode and TUN sub-mode) → override script chain (failing scripts
        // skipped and audited) → no-loop static check (§2.5 hard constraint; violations refuse to start) → write to disk.
        // Settled TUN-mode decision: the TUN skeleton bypasses the script chain — scripts operate on subscription
        // proxy config semantics; the TUN skeleton's no-loop constraints (no mixed-port / ANET-IN outbound / MATCH target) must stay intact.
        let settings = roles::RoleSettings::load();
        let effective = if settings.tun_mode {
            self.state.lock().unwrap().script_errors = Vec::new();
            render_config(&store, &settings.sub_mode, true)
        } else {
            let base = render_config(&store, &settings.sub_mode, false);
            let (effective, script_fails) =
                crate::sub_script::apply_scripts(&base, &settings.sub_scripts);
            self.state.lock().unwrap().script_errors = script_fails;
            effective
        };
        check_no_loop(&effective, settings.tun_mode)?;
        std::fs::write(config_path(), effective).map_err(|e| e.to_string())?;

        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
        self.state.lock().unwrap().stop_tx = Some(tx);
        self.restart_count.store(0, Ordering::SeqCst);
        self.supervise(rx);

        // Readiness check: if the control plane is not up within 10s (e.g. port taken), treat as start failure and roll back
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

    /// Attach the /traffic WS accumulation task (idempotent; terminated via signal and reset when the kernel stops).
    fn start_traffic(&self) {
        if self.state.lock().unwrap().traffic_stop.is_some() {
            return;
        }
        let store = load_store();
        if store.secret.is_empty() {
            return;
        }
        self.traffic.reset();
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
        self.state.lock().unwrap().traffic_stop = Some(tx);
        let stats = self.traffic.clone();
        let state = self.state.clone();
        tokio::spawn(async move {
            traffic_ws_loop(store.secret, stats, rx).await;
            state.lock().unwrap().traffic_stop = None;
        });
    }

    /// Attach the /connections and /logs WS collectors (idempotent; terminated via signal and reset on kernel stop;
    /// same lifecycle pattern as start_traffic — attached only after the kernel is ready, no idle spinning when not running).
    fn start_collectors(&self) {
        let store = load_store();
        if store.secret.is_empty() {
            return;
        }
        self.tracker.reset();
        // /connections: full snapshot → active map + closed ring + hit aggregation
        if self.state.lock().unwrap().conns_stop.is_none() {
            let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
            self.state.lock().unwrap().conns_stop = Some(tx);
            let tracker = self.tracker.clone();
            let state = self.state.clone();
            let secret = store.secret.clone();
            tokio::spawn(async move {
                collect_ws_loop(secret, "/connections", rx, move |payload| {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
                        tracker.apply_snapshot(&v);
                    }
                })
                .await;
                state.lock().unwrap().conns_stop = None;
            });
        }
        // /logs?level=info: kernel log ring buffer
        if self.state.lock().unwrap().logs_stop.is_none() {
            let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
            self.state.lock().unwrap().logs_stop = Some(tx);
            let tracker = self.tracker.clone();
            let state = self.state.clone();
            let secret = store.secret.clone();
            tokio::spawn(async move {
                collect_ws_loop(secret, "/logs?level=info", rx, move |payload| {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) {
                        tracker.push_log(&v);
                    }
                })
                .await;
                state.lock().unwrap().logs_stop = None;
            });
        }
    }

    /// Current traffic snapshot (zero after the kernel stops).
    pub fn traffic(&self) -> TrafficSnapshot {
        self.traffic.snapshot()
    }

    /// Connection snapshot (active, closed); empty after the kernel stops.
    pub fn connections(&self) -> (Vec<ConnectionInfo>, Vec<ConnectionInfo>) {
        self.tracker.connections()
    }

    /// Kernel logs (old → new); empty after the kernel stops.
    pub fn logs(&self) -> Vec<LogEntry> {
        self.tracker.logs()
    }

    /// Rule hit aggregation (count descending, top 100); empty after the kernel stops.
    pub fn rule_hits(&self) -> Vec<RuleHit> {
        self.tracker.rule_hits()
    }

    /// Clear log and hit buffers (connection state untouched).
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
            // CREATE_NO_WINDOW (tokio::process::Command has built-in creation_flags)
            cmd.creation_flags(0x08000000);
        }
        let child = cmd.spawn().map_err(|e| format!("内核启动失败: {e}"))?;
        #[cfg(windows)]
        bind_kill_on_close(&child);
        Ok(child)
    }

    /// supervisor: owns the child process; exponential-backoff restart on crash (1/2/4/8/16s, max 5 times);
    /// kills and exits on stop signal, then cleans up the handle.
    fn supervise(&self, mut rx: tokio::sync::mpsc::Receiver<()>) {
        let state = self.state.clone();
        let restart_count = self.restart_count.clone();
        tokio::spawn(async move {
            let mut restarts = 0u32;
            loop {
                let mut child = match Self::spawn(&kernel_bin_path()) {
                    Ok(c) => c,
                    Err(e) => {
                        state.lock().unwrap().last_error = e;
                        break;
                    }
                };
                tokio::select! {
                    exit = child.wait() => {
                        restarts += 1;
                        restart_count.store(restarts, Ordering::SeqCst);
                        if let Ok(status) = &exit {
                            state.lock().unwrap().last_error = format!("内核退出: {status}");
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
                        // Respond to the stop signal during backoff as well
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
            state.lock().unwrap().stop_tx = None;
        });
    }

    /// Stop the kernel (signal via the cloned sender; the liveness slot is cleared by the supervisor on exit, wait up to 5s).
    pub async fn stop(&self) {
        self.drain_stop(|s| &mut s.stop_tx).await;
        // Traffic/connection/log collectors stop with the kernel: signal and wait for task exit to self-clear the slot (up to 5s;
        // ensures a fast stop→start restart sees cleared slots, so old and new tasks never clash)
        self.drain_stop(|s| &mut s.traffic_stop).await;
        self.drain_stop(|s| &mut s.conns_stop).await;
        self.drain_stop(|s| &mut s.logs_stop).await;
        self.traffic.reset();
        self.tracker.reset();
        roles::audit("gui.kernel_stop", serde_json::json!({}));
    }

    /// Signal stop via the slot and wait for the task to self-clear it (up to 5s; pick selects the target slot from the aggregate state, no lock across await).
    async fn drain_stop(
        &self,
        pick: impl Fn(&mut KernelState) -> &mut Option<tokio::sync::mpsc::Sender<()>>,
    ) {
        let tx = pick(&mut self.state.lock().unwrap()).clone();
        if let Some(tx) = tx {
            let _ = tx.send(()).await;
            for _ in 0..50 {
                if pick(&mut self.state.lock().unwrap()).is_none() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }

    pub async fn running(&self) -> bool {
        self.state.lock().unwrap().stop_tx.is_some()
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
        let state = self.state.lock().unwrap();
        KernelStatus {
            supported: kernel_asset().is_some(),
            installed: kernel_bin_path().exists(),
            running,
            version,
            restart_count: self.restart_count.load(Ordering::Relaxed),
            last_error: state.last_error.clone(),
            script_errors: state.script_errors.clone(),
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

    /// Real-subscription full-chain E2E: AG_E2E_SUB_URL=<subscription URL> cargo test real_sub_e2e -- --ignored --nocapture
    /// Fetch → start kernel → select the AG_E2E_NODE_PREFIX node (default: the Netherlands NL node) → reach google 204 via the mixed outbound
    #[tokio::test]
    #[ignore = "真实订阅联网测试，显式 --ignored 运行"]
    async fn real_sub_e2e() {
        let url = std::env::var("AG_E2E_SUB_URL").expect("AG_E2E_SUB_URL 未设置");
        let prefix = std::env::var("AG_E2E_NODE_PREFIX").unwrap_or_else(|_| "荷兰-NL-4".into());

        // Fetch and verify
        let sub = add_subscription("e2e-real", &url).await.unwrap();
        eprintln!("订阅拉取成功: {} 节点, 流量 {}/{} 到期 {:?}", sub.node_count, sub.download, sub.total, sub.expire);
        assert!(sub.node_count > 0);

        // Start the kernel
        let km = KernelManager::default();
        km.start().await.unwrap();
        eprintln!("内核已启动并就绪");

        // Find and select the target node
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

        // Reach google via the mixed outbound (204 = reachable)
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
        // Keep the subscription in the manifest for GUI use (the user can delete it later)
    }
    /// E2E (real kernel download + start + REST handshake + stop), run manually:
    /// cargo test --manifest-path apps/desktop/Cargo.toml kernel_e2e -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "联网下载内核，显式 --ignored 运行"]
    async fn kernel_e2e() {
        // Back up and isolate the real subscription manifest (restored after the test; user data untouched)
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
        // Unreachable provider: fetch failure does not block kernel start or the control plane
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

        // If the kernel is missing, land it via the download manager first (ensure_kernel no longer downloads in place)
        if !kernel_bin_exists() {
            let st = std::sync::Arc::new(std::sync::Mutex::new(crate::download::DlState::default()));
            crate::download::run_download(crate::download::Artifact::Kernel, st)
                .await
                .unwrap();
        }
        let km = KernelManager::default();
        let result = async {
            km.start().await.map_err(|e| format!("start: {e}"))?;
            // Wait up to 15s for the control plane (including cold start after extraction)
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
            // The proxies endpoint is usable (built-in DIRECT/REJECT exist even if the provider failed)
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

    /// TUN takeover full-chain E2E (docs/plan/tun.md §2.8; admin machine, manual, run with --ignored):
    /// cargo test --manifest-path apps/desktop/Cargo.toml tun_e2e -- --ignored --nocapture
    ///
    /// Auto-asserts: wintun download verified and landed → kernel started with TUN config → control plane /configs
    /// confirms tun.enable=true and no mixed-port. Verify these steps manually per §2.8 (needs FlClash listening on 7890 and the AgileNet endpoint online):
    ///   1. curl http://ip.sb (without -x, simulating an app that ignores the system proxy) → egress IP = FlClash node
    ///   2. AgileNet internal domains reachable through the tunnel
    ///   3. Browser with system proxy = 57890 reaches google via anet→FlClash
    ///   4. Kill FlClash → miss/failure + dynamic-island alert
    ///   5. Exit GUI → system proxy and route table restored
    #[tokio::test]
    #[ignore = "需管理员本机 + 联网下载 wintun/内核，显式 --ignored 运行"]
    async fn tun_e2e() {
        use crate::tun::Elevation;
        if !crate::tun::SystemElevation.is_admin() {
            eprintln!("跳过：需以管理员身份运行本测试（TUN 需管理员权限）");
            return;
        }
        // Back up and isolate the real config (restored after the test; user data untouched)
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
        // Unreachable provider: fetch failure does not block kernel start or the control plane
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
            // If kernel/wintun is missing, land it via the download manager first (ensure_* no longer downloads in place)
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
