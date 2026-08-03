//! 从 subscription.rs 拆分：wintun.dll 钉版本下发（纯搬运，零逻辑变更）

use std::path::PathBuf;

use crate::roles;

use super::manager::NEED_DOWNLOAD_PREFIX;
use super::store::kernel_dir;

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
/// wintun.dll 0.14.1 (amd64, 427,552 B) 本体的 SHA-256——本地候选复用与内嵌落盘的校验钉
/// （zip 内层 dll 与整包哈希不同，勿与 WINTUN_ZIP_SHA256 混用）。
/// 钉值唯一来源在 node 侧（crates/node/src/tool/doctor/tun.rs，doctor 校验共用），
/// 此处仅 re-export 保持 sub::WINTUN_DLL_SHA256 引用路径不变。
pub use agile_net_node::tool::doctor::WINTUN_DLL_SHA256;

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
/// wintun.dll 0.14.1 (amd64) 官方原版内嵌——wireguard.com 在受限网络不可达、
/// gh 镜像又不能代理非 github 域名，下载路径对国内用户必然失败（弹窗风暴根源），
/// 故钉版本直接随二进制分发（wintun 为 MIT 许可，允许再分发；来源 https://www.wintun.net/）。
/// 升级 = 替换 apps/desktop/wintun/wintun.dll + 更新 WINTUN_VERSION
/// + 更新 node 侧钉值（crates/node/src/tool/doctor/tun.rs WINTUN_DLL_SHA256，全仓唯一来源）。
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
        // 主路径：内嵌官方 dll 落盘（钉值校验，杜绝编译期篡改）；免网络、免下载
        {
            use sha2::Digest;
            if format!("{:x}", sha2::Sha256::digest(WINTUN_DLL_EMBEDDED)) == WINTUN_DLL_SHA256 {
                std::fs::write(&dll, WINTUN_DLL_EMBEDDED)
                    .map_err(|e| format!("wintun 内嵌落盘失败: {e}"))?;
                return Ok(dll);
            }
        }
        // 兜底：本地候选复用（Clash 系客户端自带同版本 dll）
        if reuse_local_wintun(&dll)? {
            return Ok(dll);
        }
        Err(format!("{NEED_DOWNLOAD_PREFIX}wintun 组件未安装"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内嵌 wintun.dll 必须与钉值一致（防替换错版本/构建期污染；
    /// 钉值单源化后「同步三处」收敛为两处：本内嵌文件 + node 侧常量）
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
