//! Split from subscription.rs: pinned wintun.dll provisioning (pure move, zero logic change)

use std::path::PathBuf;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use crate::roles;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use super::manager::NEED_DOWNLOAD_PREFIX;
use super::store::kernel_dir;

/// wintun zip download sources (direct official source + local proxy fallback; gh-proxy/ghfast only
/// mirror github.com and cannot proxy arbitrary domains, so they were dropped from candidates — on
/// restricted networks the main path is local candidate reuse via reuse_local_wintun)
pub(crate) fn wintun_urls() -> Vec<String> {
    vec![format!("https://{WINTUN_ZIP_PATH}")]
}

// ==================== Pinned wintun.dll provisioning (TUN mode, Windows x64) ====================

/// Pinned wintun version (upgrade = change here + update hashes)
pub const WINTUN_VERSION: &str = "0.14.1";
/// SHA-256 of wintun-0.14.1.zip (pinned with the same policy as the kernel; hash cross-verified
/// against multiple sources including the wintun.net site and the wireguard-windows build script)
pub(crate) const WINTUN_ZIP_SHA256: &str =
    "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
/// Official source path (integrity enforced by the SHA-256 pin; download mirrors see wintun_urls)
const WINTUN_ZIP_PATH: &str = "download.wireguard.com/wintun/wintun-0.14.1.zip";
/// SHA-256 of the wintun.dll 0.14.1 (amd64, 427,552 B) binary itself — verification pin for local
/// candidate reuse and embedded provisioning (the inner dll hashes differently from the whole zip;
/// do not mix with WINTUN_ZIP_SHA256). Pin single source is node-side (crates/node/src/tool/doctor/tun.rs,
/// shared with doctor checks); re-export only, keeping the sub::WINTUN_DLL_SHA256 path unchanged.
pub use agile_net_node::tool::doctor::WINTUN_DLL_SHA256;

/// Where wintun.dll is provisioned (same dir as mihomo.exe; wintun loads adjacent to the exe).
pub fn wintun_dll_path() -> PathBuf {
    kernel_dir().join("wintun.dll")
}

/// Local candidate reuse: Clash-family clients commonly bundle the same official wintun.dll version
/// (download-free when wireguard.com is unreachable on restricted networks); reuse only on SHA-256 pin match, else ignore.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn wintun_local_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_default();
    if !home.as_os_str().is_empty() {
        v.push(home.join(".config/clash/wintun.dll")); // FlClash data dir
    }
    if let Ok(x) = std::env::var("APPDATA") {
        v.push(PathBuf::from(x).join("FlClash/wintun.dll"));
    }
    if let Ok(x) = std::env::var("LOCALAPPDATA") {
        v.push(PathBuf::from(x).join("Programs/FlClash/wintun.dll"));
    }
    v
}

/// Reuse an existing local official wintun.dll (SHA-256 pin verified); returns true on hit.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
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

/// Ensure wintun.dll exists (returns immediately if present or reused from local candidates); Windows x64 only.
/// When missing, **no inline download anymore** — returns a NEED_DOWNLOAD error and the download manager
/// (download.rs) streams it in the background with progress; the frontend retries the original action
/// afterwards (see set_tun_mode). wintun.dll 0.14.1 (amd64) official binary is embedded — wireguard.com
/// is unreachable on restricted networks and gh mirrors cannot proxy non-github domains, so the download
/// path inevitably fails for CN users (root cause of the popup storm); hence the pinned version ships
/// with the binary (wintun is MIT-licensed, redistribution allowed; source https://www.wintun.net/).
/// Upgrade = replace apps/desktop/wintun/wintun.dll + bump WINTUN_VERSION
/// + update the node-side pin (crates/node/src/tool/doctor/tun.rs WINTUN_DLL_SHA256, single source repo-wide).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
static WINTUN_DLL_EMBEDDED: &[u8] = include_bytes!("../../wintun/wintun.dll");

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
        // Main path: write the embedded official dll to disk (pin-verified, defeats build-time tampering); no network, no download
        {
            use sha2::Digest;
            if format!("{:x}", sha2::Sha256::digest(WINTUN_DLL_EMBEDDED)) == WINTUN_DLL_SHA256 {
                std::fs::write(&dll, WINTUN_DLL_EMBEDDED)
                    .map_err(|e| format!("wintun 内嵌落盘失败: {e}"))?;
                return Ok(dll);
            }
        }
        // Fallback: reuse local candidates (Clash-family clients bundle the same dll version)
        if reuse_local_wintun(&dll)? {
            return Ok(dll);
        }
        Err(format!("{NEED_DOWNLOAD_PREFIX}wintun 组件未安装"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Embedded wintun.dll must match the pin (guards against wrong-version swaps / build-time pollution;
    /// after pin single-sourcing, "sync three places" shrinks to two: this embedded file + node-side constant)
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn wintun_embedded_matches_pin() {
        use sha2::Digest;
        assert_eq!(WINTUN_VERSION, "0.14.1");
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(WINTUN_DLL_EMBEDDED)),
            WINTUN_DLL_SHA256
        );
        assert_eq!(WINTUN_DLL_EMBEDDED.len(), 427_552);
    }
}
