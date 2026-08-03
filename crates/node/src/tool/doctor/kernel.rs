//! Section 4: subscription kernel (mihomo binary pinned-version check + control-plane /version reachability).

use super::util::{kernel_bin_name, listeners_on};
use super::{DoctorContext, DoctorSection, DoctorStatus, item, section};
use crate::tool::netstat::SocketInfo;
use std::path::Path;
use std::time::Duration;

/// Pinned mihomo version (kept in sync with MIHOMO_VERSION in apps/desktop/src/subscription.rs).
/// Note: upstream only publishes hashes for the archives (bare binaries cannot be pinned, see the
/// download.rs design), so "runnable + self-reported version = pinned version" serves as the
/// integrity proxy check here.
const MIHOMO_VERSION: &str = "1.19.29";

fn kernel_platform_supported() -> bool {
    cfg!(all(target_os = "windows", target_arch = "x86_64"))
        || cfg!(all(target_os = "macos", target_arch = "aarch64"))
        || cfg!(all(target_os = "macos", target_arch = "x86_64"))
}

/// Read the control-plane secret from subscriptions.json (no file/no secret → None).
fn read_ctrl_secret(ctx: &DoctorContext) -> Option<String> {
    std::fs::read_to_string(ctx.data_dir.join("subscriptions.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| {
            v["secret"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
}

pub(super) async fn section_kernel(ctx: &DoctorContext, socks: &[SocketInfo]) -> DoctorSection {
    let mut items = Vec::new();
    if !kernel_platform_supported() {
        items.push(item(
            "kernel",
            "订阅内核（mihomo）",
            DoctorStatus::Info,
            "当前平台不支持订阅内核（仅 Windows x64 / macOS）",
            None,
        ));
        return section("kernel", "订阅内核", items);
    }

    let bin = ctx.data_dir.join("mihomo").join(kernel_bin_name());
    if !bin.exists() {
        items.push(item(
            "kernel-bin",
            "内核二进制",
            DoctorStatus::Info,
            "未安装（启用订阅功能时经下载管理器安装）",
            None,
        ));
    } else {
        match probe_kernel_version(&bin).await {
            Ok(line) if line.contains(MIHOMO_VERSION) => items.push(item(
                "kernel-bin",
                "内核二进制",
                DoctorStatus::Ok,
                format!("v{MIHOMO_VERSION} 可运行（自报版本与钉版一致）"),
                None,
            )),
            Ok(line) => {
                let fixed = ctx.fix && std::fs::remove_file(&bin).is_ok();
                let detail = format!(
                    "自报版本与钉版 v{MIHOMO_VERSION} 不符（{}，疑似被替换）",
                    line.chars().take(80).collect::<String>()
                );
                if fixed {
                    items.push(item(
                        "kernel-bin",
                        "内核二进制",
                        DoctorStatus::Fixed,
                        format!("{detail}，已删除"),
                        Some("下次启用订阅时将自动重新下载钉版内核".into()),
                    ));
                } else {
                    items.push(item(
                        "kernel-bin",
                        "内核二进制",
                        DoctorStatus::Err,
                        detail,
                        Some("删除该文件后重新启用订阅（自动重下钉版内核）".into()),
                    ));
                }
            }
            Err(e) => {
                let fixed = ctx.fix && std::fs::remove_file(&bin).is_ok();
                let detail = format!("内核无法运行（{e}，文件损坏或不兼容）");
                if fixed {
                    items.push(item(
                        "kernel-bin",
                        "内核二进制",
                        DoctorStatus::Fixed,
                        format!("{detail}，已删除"),
                        Some("下次启用订阅时将自动重新下载钉版内核".into()),
                    ));
                } else {
                    items.push(item(
                        "kernel-bin",
                        "内核二进制",
                        DoctorStatus::Err,
                        detail,
                        Some("删除该文件后重新启用订阅（自动重下钉版内核）".into()),
                    ));
                }
            }
        }
    }

    // Control-plane /version reachability (skipped without a secret)
    let ctrl_listening = !listeners_on(socks, 59292).is_empty();
    if !ctrl_listening {
        items.push(item(
            "kernel-ctrl",
            "控制面 :59292",
            DoctorStatus::Info,
            "未监听（内核未运行）",
            None,
        ));
    } else {
        match read_ctrl_secret(ctx) {
            None => items.push(item(
                "kernel-ctrl",
                "控制面 :59292",
                DoctorStatus::Info,
                "监听中，但无 secret（subscriptions.json 缺失），跳过 /version 探测",
                None,
            )),
            Some(secret) => match probe_ctrl_version(&secret).await {
                Ok(body) => items.push(item(
                    "kernel-ctrl",
                    "控制面 :59292",
                    DoctorStatus::Ok,
                    format!("/version 可达：{body}"),
                    None,
                )),
                Err(e) => items.push(item(
                    "kernel-ctrl",
                    "控制面 :59292",
                    DoctorStatus::Warn,
                    format!("监听中但 /version 不可达：{e}"),
                    Some("内核可能处于启动早期或 secret 已轮换；持续不可达请重启订阅角色".into()),
                )),
            },
        }
    }
    section("kernel", "订阅内核", items)
}

/// Run `mihomo -v` and take the version line (3s timeout; no console window in GUI context).
async fn probe_kernel_version(bin: &Path) -> Result<String, String> {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.arg("-v");
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = match tokio::time::timeout(Duration::from_secs(3), cmd.output()).await {
        Ok(r) => r.map_err(|e| e.to_string())?,
        Err(_) => return Err("执行超时（3s）".into()),
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    text.lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .ok_or_else(|| "无版本输出".to_string())
}

/// GET http://127.0.0.1:59292/version（Bearer secret，2s）。
async fn probe_ctrl_version(secret: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get("http://127.0.0.1:59292/version")
        .bearer_auth(secret)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    Ok(body.chars().take(80).collect())
}
