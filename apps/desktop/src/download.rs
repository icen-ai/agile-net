//! Artifact download manager (mihomo kernel / wintun.dll): unified download UX.
//!
//! - State machine idle / downloading{artifact,mirror,downloaded,total?} / done / failed{artifact,reason},
//!   held by AppState; frontend polls `dl_state` to render the progress card (no Tauri events)
//! - Enable flow no longer downloads inline: on missing artifact the caller `start()`s a background
//!   streaming download and hints the frontend with NEED_DOWNLOAD, which auto-retries the enable action
//! - Integrity pinned by SHA-256 in subscription.rs; failed packages are refused (tamper audit
//!   gui.kernel_tamper / gui.wintun_tamper, same as the old ensure_* policy)
//! - Manual install: local file routed by artifact (package pinned / bare binary unpinnable / wintun.dll
//!   dll-pinned); mismatch needs explicit confirmation (allow_mismatch=true); audited gui.dl_manual_install
//! - Audit: gui.dl_start / gui.dl_done (with mirror) / gui.dl_failed (with reason) / gui.dl_manual_install;
//!   never log file contents

use agile_net_node::db::sha256_hex;
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::roles;
use crate::subscription as sub;

/// Artifact kind (dl_start / dl_install_manual command arg, lowercase string)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Artifact {
    /// Subscription kernel (mihomo)
    Kernel,
    /// Virtual NIC driver for TUN mode
    Wintun,
}

impl Artifact {
    pub fn name(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Wintun => "wintun",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "kernel" => Ok(Self::Kernel),
            "wintun" => Ok(Self::Wintun),
            _ => Err("非法制品类型（kernel|wintun）".into()),
        }
    }
}

/// Download state machine (dl_state command return body; serde tag=phase)
#[derive(Debug, Clone, Default, Serialize)]
#[serde(tag = "phase", rename_all = "lowercase")]
pub enum DlState {
    #[default]
    Idle,
    Downloading {
        artifact: String,
        /// Mirror hit (e.g. direct github.com / local proxy ghfast.top)
        mirror: String,
        downloaded: u64,
        /// None when content-length is missing (frontend shows only downloaded bytes)
        total: Option<u64>,
    },
    Done {
        artifact: String,
    },
    Failed {
        artifact: String,
        reason: String,
    },
}

/// Manual install result (dl_install_manual command return body; serde tag=result)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ManualInstallResult {
    Installed { artifact: String },
    /// Hash differs from the pin (or bare binary cannot be pinned): frontend confirms, then recalls with allow_mismatch
    HashMismatch {
        artifact: String,
        actual_hash: String,
        expect_version: String,
    },
}

/// Internal manual-install outcome (with audit fields; mismatch=true on installed means user-confirmed force install)
#[derive(Debug)]
pub(crate) struct ManualOutcome {
    pub result: ManualInstallResult,
    pub actual_hash: String,
    /// File shape: package / binary / dll (for audit)
    pub kind: &'static str,
    pub mismatch: bool,
}

/// Download manager: single task slot (only one artifact downloads at a time; start is idempotent per artifact).
#[derive(Default)]
pub struct DownloadManager {
    state: Arc<Mutex<DlState>>,
    task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl DownloadManager {
    pub fn state(&self) -> DlState {
        self.state.lock().unwrap().clone()
    }

    /// Start background download (idempotent Ok if same artifact is downloading; error if another is; may restart after done/failed).
    pub fn start(&self, artifact: Artifact) -> Result<(), String> {
        if let DlState::Downloading { artifact: a, .. } = &*self.state.lock().unwrap() {
            if a == artifact.name() {
                return Ok(());
            }
            return Err(format!("{a} 下载进行中，请先完成或取消"));
        }
        roles::audit("gui.dl_start", serde_json::json!({"artifact": artifact.name()}));
        self.spawn_task(artifact, run_download(artifact, self.state.clone()))
    }

    /// Task assembly (the single state-machine transition path shared by prod/tests): terminal transition + done/failed audit + slot self-clear.
    fn spawn_task(
        &self,
        artifact: Artifact,
        fut: impl std::future::Future<Output = Result<String, String>> + Send + 'static,
    ) -> Result<(), String> {
        let mut slot = self.task.lock().unwrap();
        if slot.is_some() {
            return Err("已有下载任务进行中".into());
        }
        *self.state.lock().unwrap() = DlState::Downloading {
            artifact: artifact.name().into(),
            mirror: String::new(),
            downloaded: 0,
            total: None,
        };
        let st = self.state.clone();
        let slot2 = self.task.clone();
        let handle = tokio::spawn(async move {
            match fut.await {
                Ok(mirror) => {
                    roles::audit(
                        "gui.dl_done",
                        serde_json::json!({"artifact": artifact.name(), "mirror": mirror}),
                    );
                    *st.lock().unwrap() = DlState::Done {
                        artifact: artifact.name().into(),
                    };
                }
                Err(reason) => {
                    roles::audit(
                        "gui.dl_failed",
                        serde_json::json!({"artifact": artifact.name(), "reason": reason}),
                    );
                    *st.lock().unwrap() = DlState::Failed {
                        artifact: artifact.name().into(),
                        reason,
                    };
                }
            }
            *slot2.lock().unwrap() = None;
        });
        *slot = Some(handle);
        Ok(())
    }

    /// Cancel download: abort the task back to idle (partial bytes are dropped with the task, never persisted).
    pub fn cancel(&self) {
        if let Some(h) = self.task.lock().unwrap().take() {
            h.abort();
        }
        *self.state.lock().unwrap() = DlState::Idle;
        roles::audit("gui.dl_cancel", serde_json::json!({}));
    }
}

/// Manually install a local artifact file (pin-verified; on mismatch the frontend confirms and recalls with allow_mismatch).
/// Free function (no manager instance); the command layer may run it inside spawn_blocking.
pub(crate) fn install_manual(
    artifact: Artifact,
    path: &Path,
    allow_mismatch: bool,
) -> Result<ManualInstallResult, String> {
    let pins = ManualPins::production()?;
    let out = install_manual_at(
        artifact,
        path,
        allow_mismatch,
        &pins,
        &sub::kernel_bin_path(),
        &sub::wintun_dll_path(),
    )?;
    roles::audit(
        "gui.dl_manual_install",
        serde_json::json!({
            "artifact": artifact.name(),
            "path": path.to_string_lossy(),
            "hash": out.actual_hash,
            "kind": out.kind,
            "mismatch_override": out.mismatch,
            "installed": matches!(out.result, ManualInstallResult::Installed { .. }),
        }),
    );
    Ok(out.result)
}

// ==================== Download execution (streaming + pin verify + atomic persist) ====================

/// Full background download flow: streaming download (progress written to shared state) -> pin SHA-256 verify -> extract and persist.
/// Returns the mirror hit (for gui.dl_done audit); tamper-check failures are audited here (gui.kernel_tamper / gui.wintun_tamper).
pub(crate) async fn run_download(
    artifact: Artifact,
    state: Arc<Mutex<DlState>>,
) -> Result<String, String> {
    let name = artifact.name();
    let report = |mirror: &str, downloaded: u64, total: Option<u64>| {
        *state.lock().unwrap() = DlState::Downloading {
            artifact: name.into(),
            mirror: mirror.into(),
            downloaded,
            total,
        };
    };
    match artifact {
        Artifact::Kernel => {
            let (asset, expect_sha, inner) = sub::kernel_asset()
                .ok_or("当前平台不支持订阅内核（仅 Windows x64 / macOS）")?;
            let (bytes, mirror) = download_stream(&sub::download_urls(asset), &report)
                .await
                .map_err(|e| format!("内核下载失败: {e}"))?;
            if let Err(actual) = verify_pin(&bytes, expect_sha) {
                roles::audit(
                    "gui.kernel_tamper",
                    serde_json::json!({"expect": expect_sha, "actual": actual}),
                );
                return Err("内核校验失败（SHA-256 不匹配，疑似镜像篡改，已拒绝落盘并记录审计）".into());
            }
            let inner_bytes = extract_pkg(&bytes, inner)?;
            atomic_write(&sub::kernel_bin_path(), &inner_bytes, true)?;
            Ok(mirror)
        }
        Artifact::Wintun => {
            let (bytes, mirror) = download_stream(&sub::wintun_urls(), &report)
                .await
                .map_err(|e| format!("wintun 下载失败: {e}"))?;
            if let Err(actual) = verify_pin(&bytes, sub::WINTUN_ZIP_SHA256) {
                roles::audit(
                    "gui.wintun_tamper",
                    serde_json::json!({"expect": sub::WINTUN_ZIP_SHA256, "actual": actual}),
                );
                return Err("wintun 校验失败（SHA-256 不匹配，疑似被篡改，已拒绝落盘并记录审计）".into());
            }
            let dll = extract_wintun_dll(&bytes)?;
            atomic_write(&sub::wintun_dll_path(), &dll, false)?;
            Ok(mirror)
        }
    }
}

/// Streaming download: keeps the original download_bytes candidate order (per URL: direct first, then local proxy 57890),
/// reports (mirror, downloaded, total) every ~64KB; total=None when content-length is missing.
/// Returns (full bytes, mirror description hit).
async fn download_stream(
    urls: &[String],
    report: &impl Fn(&str, u64, Option<u64>),
) -> Result<(Vec<u8>, String), String> {
    let ua = format!("anet-gui/{}", sub::MIHOMO_VERSION);
    let mk = |proxy: bool| {
        let mut b = reqwest::Client::builder()
            .user_agent(&ua)
            .timeout(std::time::Duration::from_secs(60));
        if proxy {
            b = b.proxy(reqwest::Proxy::all("http://127.0.0.1:57890").expect("valid proxy url"));
        } else {
            // the direct arm must be truly direct: reqwest picks up HTTP(S)_PROXY env vars by default,
            // which would silently re-route the "direct" candidate (and make tests machine-dependent)
            b = b.no_proxy();
        }
        b.build().map_err(|e| e.to_string())
    };
    let (direct, via_proxy) = (mk(false)?, mk(true)?);
    let mut last_err = String::new();
    for url in urls {
        for (label, c) in [("直连", &direct), ("本地代理", &via_proxy)] {
            let mirror = format!("{label} {}", url_host(url));
            match c.get(url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let total = resp.content_length();
                    let mut resp = resp;
                    let mut buf: Vec<u8> = Vec::with_capacity(total.unwrap_or(0) as usize);
                    let mut reported = 0u64;
                    report(&mirror, 0, total);
                    let mut broken = false;
                    loop {
                        match resp.chunk().await {
                            Ok(Some(chunk)) => {
                                buf.extend_from_slice(&chunk);
                                if buf.len() as u64 - reported >= 65536 {
                                    reported = buf.len() as u64;
                                    report(&mirror, reported, total);
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                last_err = format!("{label}下载中断: {e}");
                                broken = true;
                                break;
                            }
                        }
                    }
                    if broken {
                        continue; // same URL, try next channel (direct -> local proxy)
                    }
                    report(&mirror, buf.len() as u64, total);
                    return Ok((buf, mirror));
                }
                Ok(resp) => last_err = format!("{label} HTTP {}", resp.status()),
                Err(e) => last_err = format!("{label}: {e}"),
            }
        }
    }
    Err(last_err)
}

/// URL host part (for mirror display; returned as-is when parsing fails)
fn url_host(url: &str) -> &str {
    match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            match rest.find('/') {
                Some(j) => &rest[..j],
                None => rest,
            }
        }
        None => url,
    }
}

/// Pin check: Ok on match; Err(actual hash) on mismatch (caller decides tamper-audit / manual-confirm branch)
fn verify_pin(bytes: &[u8], expect: &str) -> Result<(), String> {
    let actual = sha256_hex(bytes);
    if actual != expect {
        return Err(actual);
    }
    Ok(())
}

/// Extract kernel package (zip/gz routed by magic bytes), returns the inner entry content.
fn extract_pkg(bytes: &[u8], inner: &str) -> Result<Vec<u8>, String> {
    if bytes.starts_with(b"PK\x03\x04") {
        let reader = std::io::Cursor::new(bytes);
        let mut zip = zip::ZipArchive::new(reader).map_err(|e| e.to_string())?;
        let mut file = zip
            .by_name(inner)
            .map_err(|_| format!("包内未找到 {inner}"))?;
        let mut buf = Vec::with_capacity(file.size() as usize);
        std::io::Read::read_to_end(&mut file, &mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut gz = flate2::read::GzDecoder::new(bytes);
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut gz, &mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    } else {
        Err("无法识别的内核包格式（须为官方 zip/gz 包）".into())
    }
}

/// Extract amd64/wintun.dll from the wintun zip.
fn extract_wintun_dll(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let reader = std::io::Cursor::new(bytes);
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| e.to_string())?;
    let mut inner = None;
    for i in 0..zip.len() {
        let name = zip.by_index(i).map_err(|e| e.to_string())?.name().to_string();
        if name.replace('\\', "/").ends_with("bin/amd64/wintun.dll") {
            inner = Some(name);
            break;
        }
    }
    let inner = inner.ok_or("wintun 包内未找到 amd64/wintun.dll")?;
    let mut file = zip.by_name(&inner).map_err(|e| e.to_string())?;
    let mut buf = Vec::with_capacity(file.size() as usize);
    std::io::Read::read_to_end(&mut file, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Atomic persist: temp file + rename (keeps the *.download temp-name convention); chmod 0755 on unix when executable.
fn atomic_write(dest: &Path, bytes: &[u8], executable: bool) -> Result<(), String> {
    let dir = dest.parent().ok_or("目标路径无父目录")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!(
        "{}.download",
        dest.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    std::fs::rename(&tmp, dest).map_err(|e| format!("落盘失败: {e}"))?;
    Ok(())
}

// ==================== Manual install (local file -> pin verify -> persist) ====================

/// Pin set for manual install (production reads pinned constants from subscription.rs; tests inject their own pins).
pub(crate) struct ManualPins {
    pub kernel_sha: String,
    pub kernel_inner: String,
    pub kernel_version: String,
    pub wintun_zip_sha: String,
    pub wintun_dll_sha: String,
    pub wintun_version: String,
}

impl ManualPins {
    fn production() -> Result<Self, String> {
        let (_, ksha, kinner) =
            sub::kernel_asset().ok_or("当前平台不支持订阅内核（仅 Windows x64 / macOS）")?;
        Ok(Self {
            kernel_sha: ksha.into(),
            kernel_inner: kinner.into(),
            kernel_version: sub::MIHOMO_VERSION.into(),
            wintun_zip_sha: sub::WINTUN_ZIP_SHA256.into(),
            wintun_dll_sha: sub::WINTUN_DLL_SHA256.into(),
            wintun_version: sub::WINTUN_VERSION.into(),
        })
    }
}

/// Read local file (256MB cap, guards against huge files passed by mistake)
fn read_file_capped(path: &Path) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("无法读取文件: {e}"))?;
    if meta.len() > 256 * 1024 * 1024 {
        return Err("文件过大（超过 256MB，不像官方制品）".into());
    }
    std::fs::read(path).map_err(|e| format!("无法读取文件: {e}"))
}

/// Hash-mismatch outcome (actual hash goes into both result and audit fields, avoiding recompute at call sites)
fn mismatch_outcome(
    artifact: Artifact,
    actual_hash: &str,
    expect_version: &str,
    kind: &'static str,
) -> ManualOutcome {
    ManualOutcome {
        result: ManualInstallResult::HashMismatch {
            artifact: artifact.name().into(),
            actual_hash: actual_hash.into(),
            expect_version: expect_version.into(),
        },
        actual_hash: actual_hash.into(),
        kind,
        mismatch: true,
    }
}

/// Install-success outcome (mismatch=true means user-confirmed force install)
fn installed_outcome(artifact: Artifact, actual_hash: String, kind: &'static str, mismatch: bool) -> ManualOutcome {
    ManualOutcome {
        result: ManualInstallResult::Installed {
            artifact: artifact.name().into(),
        },
        actual_hash,
        kind,
        mismatch,
    }
}

/// Manual-install routing (pure function: no audit, no global state; target paths injected by caller for test isolation).
pub(crate) fn install_manual_at(
    artifact: Artifact,
    path: &Path,
    allow_mismatch: bool,
    pins: &ManualPins,
    kernel_bin: &Path,
    wintun_dll: &Path,
) -> Result<ManualOutcome, String> {
    if !path.is_file() {
        return Err("文件不存在或不是普通文件".into());
    }
    let bytes = read_file_capped(path)?;
    let actual_hash = sha256_hex(&bytes);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    let is_zip = bytes.starts_with(b"PK\x03\x04");
    let is_gz = bytes.starts_with(&[0x1f, 0x8b]);
    match artifact {
        Artifact::Kernel => {
            // Package (by magic bytes or extension) -> check against package pin; anything else is a bare binary -> cannot be pinned
            if is_zip || is_gz || ext == "zip" || ext == "gz" {
                let mismatch = verify_pin(&bytes, &pins.kernel_sha).is_err();
                if mismatch && !allow_mismatch {
                    return Ok(mismatch_outcome(artifact, &actual_hash, &pins.kernel_version, "包"));
                }
                // Pin match installs directly; mismatch only reaches here after explicit user confirmation (allow_mismatch)
                let inner = extract_pkg(&bytes, &pins.kernel_inner)?;
                atomic_write(kernel_bin, &inner, true)?;
                Ok(installed_outcome(artifact, actual_hash, "包", mismatch))
            } else {
                // Bare binary: the pin covers the package hash and cannot be checked -- requires explicit user confirmation
                if !allow_mismatch {
                    return Ok(mismatch_outcome(artifact, &actual_hash, &pins.kernel_version, "二进制"));
                }
                atomic_write(kernel_bin, &bytes, true)?;
                Ok(installed_outcome(artifact, actual_hash, "二进制", true))
            }
        }
        Artifact::Wintun => {
            if is_zip || ext == "zip" {
                // zip package -> verify whole-package pin, then extract amd64/wintun.dll
                let mismatch = verify_pin(&bytes, &pins.wintun_zip_sha).is_err();
                if mismatch && !allow_mismatch {
                    return Ok(mismatch_outcome(artifact, &actual_hash, &pins.wintun_version, "包"));
                }
                let dll = extract_wintun_dll(&bytes)?;
                atomic_write(wintun_dll, &dll, false)?;
                Ok(installed_outcome(artifact, actual_hash, "包", mismatch))
            } else {
                // bare wintun.dll -> pin the dll itself (shares the same pin as local candidates)
                let mismatch = verify_pin(&bytes, &pins.wintun_dll_sha).is_err();
                if mismatch && !allow_mismatch {
                    return Ok(mismatch_outcome(artifact, &actual_hash, &pins.wintun_version, "dll"));
                }
                atomic_write(wintun_dll, &bytes, false)?;
                Ok(installed_outcome(artifact, actual_hash, "dll", mismatch))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Progress report sink (sequence of (downloaded, total?))
    type Reports = Arc<Mutex<Vec<(u64, Option<u64>)>>>;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anet-dl-test-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_pins() -> ManualPins {
        ManualPins {
            kernel_sha: String::new(),
            kernel_inner: "mihomo-windows-amd64-compatible.exe".into(),
            kernel_version: "1.19.29".into(),
            wintun_zip_sha: String::new(),
            wintun_dll_sha: String::new(),
            wintun_version: "0.14.1".into(),
        }
    }

    /// Build a zip package (single Stored entry)
    fn make_zip(entry: &str, content: &[u8]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opt = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        w.start_file(entry, opt).unwrap();
        std::io::Write::write_all(&mut w, content).unwrap();
        w.finish().unwrap().into_inner()
    }

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    // ---------- Streaming download progress ----------

    /// Mock HTTP server: feeds the body in chunks (30ms apart to force multiple chunks); asserts cumulative monotone progress and byte equality
    #[tokio::test]
    async fn stream_download_reports_cumulative_progress() {
        let chunks: Vec<Vec<u8>> = vec![vec![1u8; 100_000], vec![2u8; 100_000], vec![3u8; 50_000]];
        let total: usize = chunks.iter().map(Vec::len).sum();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = chunks.concat();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            s.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
            for c in &chunks {
                s.write_all(c).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            }
        });
        let reports: Reports = Arc::new(Mutex::new(Vec::new()));
        let reports2 = reports.clone();
        let url = format!("http://127.0.0.1:{port}/pkg.zip");
        let (bytes, mirror) = download_stream(&[url], &move |_m, d, t| {
            reports2.lock().unwrap().push((d, t));
        })
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(bytes, body, "下载字节须与源一致");
        assert!(mirror.starts_with("直连 127.0.0.1"), "mirror={mirror}");
        let reps = reports.lock().unwrap().clone();
        assert!(reps.len() >= 2, "至少有起始与结束进度: {reps:?}");
        assert_eq!(reps[0], (0, Some(total as u64)));
        // Monotone non-decreasing, ending at total (content-length known -> total always Some)
        for w in reps.windows(2) {
            assert!(w[1].0 >= w[0].0, "进度单调不减: {reps:?}");
            assert_eq!(w[1].1, Some(total as u64));
        }
        assert_eq!(reps.last().unwrap().0, total as u64);
    }

    /// content-length missing (chunked encoding) -> total=None, only downloaded bytes accumulate
    #[tokio::test]
    async fn stream_download_without_content_length() {
        let payload = b"hello-chunked-world".to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let n = payload.len();
        let served = payload.clone();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            s.write_all(format!("{n:x}\r\n").as_bytes()).await.unwrap();
            s.write_all(&served).await.unwrap();
            s.write_all(b"\r\n0\r\n\r\n").await.unwrap();
        });
        let reports: Reports = Arc::new(Mutex::new(Vec::new()));
        let reports2 = reports.clone();
        let url = format!("http://127.0.0.1:{port}/pkg.bin");
        let (bytes, _) = download_stream(&[url], &move |_m, d, t| {
            reports2.lock().unwrap().push((d, t));
        })
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(bytes, payload);
        let reps = reports.lock().unwrap().clone();
        assert!(!reps.is_empty());
        assert!(reps.iter().all(|(_, t)| t.is_none()), "total 应恒为 None: {reps:?}");
        assert_eq!(reps.last().unwrap().0, n as u64);
    }

    /// All URLs fail -> Err (contains the last error)
    #[tokio::test]
    async fn stream_download_all_mirrors_fail() {
        let err = download_stream(
            &["http://127.0.0.1:1/none.zip".to_string()],
            &move |_m, _d, _t| {},
        )
        .await
        .unwrap_err();
        assert!(!err.is_empty());
    }

    // ---------- State machine transitions ----------

    /// idle -> downloading -> done; task slot self-clears, start works again
    #[tokio::test]
    async fn state_machine_done_transition() {
        let dm = DownloadManager::default();
        assert!(matches!(dm.state(), DlState::Idle));
        dm.spawn_task(Artifact::Kernel, async { Ok("直连 example.com".into()) })
            .unwrap();
        assert!(matches!(dm.state(), DlState::Downloading { .. }));
        // wait for the task to finish
        for _ in 0..50 {
            if matches!(dm.state(), DlState::Done { .. }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        match dm.state() {
            DlState::Done { artifact } => assert_eq!(artifact, "kernel"),
            other => panic!("应为 done: {other:?}"),
        }
        assert!(dm.task.lock().unwrap().is_none(), "任务槽须自清");
        // can start again after done
        dm.spawn_task(Artifact::Wintun, async { Err("网络不可达".into()) })
            .unwrap();
        for _ in 0..50 {
            if matches!(dm.state(), DlState::Failed { .. }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        match dm.state() {
            DlState::Failed { artifact, reason } => {
                assert_eq!(artifact, "wintun");
                assert_eq!(reason, "网络不可达");
            }
            other => panic!("应为 failed: {other:?}"),
        }
    }

    /// Cancel mid-download -> idle; pending task is aborted
    #[tokio::test]
    async fn state_machine_cancel_returns_idle() {
        let dm = DownloadManager::default();
        dm.spawn_task(Artifact::Kernel, async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok("m".into())
        })
        .unwrap();
        assert!(matches!(dm.state(), DlState::Downloading { .. }));
        dm.cancel();
        assert!(matches!(dm.state(), DlState::Idle));
        assert!(dm.task.lock().unwrap().is_none());
    }

    // ---------- Manual install: kernel three branches ----------

    /// kernel zip pin match -> installed; persisted content is the in-package binary
    #[test]
    fn manual_kernel_zip_pin_match_installs() {
        let dir = tempdir("kzip-ok");
        let zip_bytes = make_zip("mihomo-windows-amd64-compatible.exe", b"fake-kernel-bin");
        let src = write_file(&dir, "mihomo.zip", &zip_bytes);
        let bin = dir.join("mihomo.exe");
        let mut pins = test_pins();
        pins.kernel_sha = sha256_hex(&zip_bytes);
        let out = install_manual_at(Artifact::Kernel, &src, false, &pins, &bin, &dir.join("wintun.dll"))
            .unwrap();
        assert!(matches!(out.result, ManualInstallResult::Installed { .. }));
        assert!(!out.mismatch);
        assert_eq!(std::fs::read(&bin).unwrap(), b"fake-kernel-bin");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// kernel zip pin mismatch: returns hash_mismatch by default; allow_mismatch force-installs and persists
    #[test]
    fn manual_kernel_zip_mismatch_then_override() {
        let dir = tempdir("kzip-mm");
        let zip_bytes = make_zip("mihomo-windows-amd64-compatible.exe", b"fake-kernel-bin");
        let src = write_file(&dir, "mihomo.zip", &zip_bytes);
        let bin = dir.join("mihomo.exe");
        let mut pins = test_pins();
        pins.kernel_sha = "0".repeat(64);
        let out = install_manual_at(Artifact::Kernel, &src, false, &pins, &bin, &dir.join("wintun.dll"))
            .unwrap();
        match &out.result {
            ManualInstallResult::HashMismatch {
                actual_hash,
                expect_version,
                ..
            } => {
                assert_eq!(*actual_hash, sha256_hex(&zip_bytes));
                assert_eq!(expect_version, "1.19.29");
            }
            other => panic!("应为 hash_mismatch: {other:?}"),
        }
        assert!(!bin.exists(), "未确认前不得落盘");
        // user confirms force install
        let out = install_manual_at(Artifact::Kernel, &src, true, &pins, &bin, &dir.join("wintun.dll"))
            .unwrap();
        assert!(matches!(out.result, ManualInstallResult::Installed { .. }));
        assert!(out.mismatch, "强装须标记 mismatch_override");
        assert_eq!(std::fs::read(&bin).unwrap(), b"fake-kernel-bin");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// kernel bare binary: cannot be pinned -> hash_mismatch; persisted as-is after confirmation
    #[test]
    fn manual_kernel_bare_exe_requires_confirmation() {
        let dir = tempdir("kexe");
        let src = write_file(&dir, "mihomo.exe", b"bare-kernel");
        let bin = dir.join("installed").join("mihomo.exe");
        let pins = test_pins();
        let out = install_manual_at(Artifact::Kernel, &src, false, &pins, &bin, &dir.join("wintun.dll"))
            .unwrap();
        assert!(matches!(out.result, ManualInstallResult::HashMismatch { .. }));
        assert!(!bin.exists());
        let out = install_manual_at(Artifact::Kernel, &src, true, &pins, &bin, &dir.join("wintun.dll"))
            .unwrap();
        assert!(matches!(out.result, ManualInstallResult::Installed { .. }));
        assert_eq!(std::fs::read(&bin).unwrap(), b"bare-kernel");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- Manual install: wintun ----------

    /// wintun bare dll pin match / mismatch returns mismatch
    #[test]
    fn manual_wintun_dll_pin_match_and_mismatch() {
        let dir = tempdir("wdll");
        let dll_bytes = b"fake-wintun-dll".to_vec();
        let src = write_file(&dir, "wintun.dll", &dll_bytes);
        let dest = dir.join("out").join("wintun.dll");
        let mut pins = test_pins();
        pins.wintun_dll_sha = sha256_hex(&dll_bytes);
        let out = install_manual_at(Artifact::Wintun, &src, false, &pins, &dir.join("mihomo.exe"), &dest)
            .unwrap();
        assert!(matches!(out.result, ManualInstallResult::Installed { .. }));
        assert!(!out.mismatch);
        assert_eq!(std::fs::read(&dest).unwrap(), dll_bytes);
        // pin mismatch -> mismatch (nothing persisted before confirmation)
        pins.wintun_dll_sha = "0".repeat(64);
        let dest2 = dir.join("out2").join("wintun.dll");
        let out = install_manual_at(Artifact::Wintun, &src, false, &pins, &dir.join("mihomo.exe"), &dest2)
            .unwrap();
        assert!(matches!(out.result, ManualInstallResult::HashMismatch { .. }));
        assert!(!dest2.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// wintun zip pin match -> extracts amd64/wintun.dll and persists it
    #[test]
    fn manual_wintun_zip_pin_match_extracts() {
        let dir = tempdir("wzip");
        let zip_bytes = make_zip("wintun/bin/amd64/wintun.dll", b"dll-in-zip");
        let src = write_file(&dir, "wintun-0.14.1.zip", &zip_bytes);
        let dest = dir.join("out").join("wintun.dll");
        let mut pins = test_pins();
        pins.wintun_zip_sha = sha256_hex(&zip_bytes);
        let out = install_manual_at(Artifact::Wintun, &src, false, &pins, &dir.join("mihomo.exe"), &dest)
            .unwrap();
        assert!(matches!(out.result, ManualInstallResult::Installed { .. }));
        assert_eq!(std::fs::read(&dest).unwrap(), b"dll-in-zip");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Missing path -> Err
    #[test]
    fn manual_install_missing_file_errors() {
        let dir = tempdir("missing");
        let pins = test_pins();
        let err = install_manual_at(
            Artifact::Kernel,
            &dir.join("nope.zip"),
            false,
            &pins,
            &dir.join("mihomo.exe"),
            &dir.join("wintun.dll"),
        )
        .unwrap_err();
        assert!(err.contains("不存在"), "err={err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- Extraction / helpers ----------

    #[test]
    fn extract_pkg_zip_and_gz() {
        let zip_bytes = make_zip("inner.exe", b"zip-content");
        assert_eq!(extract_pkg(&zip_bytes, "inner.exe").unwrap(), b"zip-content");
        // gz magic-bytes branch
        let mut enc =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, b"gz-content").unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(extract_pkg(&gz, "ignored").unwrap(), b"gz-content");
        // non-package format
        assert!(extract_pkg(b"plain-bytes", "x").is_err());
    }

    #[test]
    fn url_host_extracts_host() {
        assert_eq!(url_host("https://github.com/a/b"), "github.com");
        assert_eq!(url_host("https://ghfast.top/https://github.com/x"), "ghfast.top");
        assert_eq!(url_host("no-scheme"), "no-scheme");
    }

    #[test]
    fn atomic_write_lands_bytes() {
        let dir = tempdir("atomic");
        let dest = dir.join("sub").join("f.bin");
        atomic_write(&dest, b"abc", false).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
        // no temp file left behind
        assert!(!dir.join("sub").join("f.bin.download").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
