//! 第 3 节：TUN 支持（wintun.dll SHA-256 钉值校验 / 管理员权限判定）。

use super::{DoctorContext, DoctorSection, DoctorStatus, item, section};

/// wintun.dll 0.14.1 (amd64) 本体 SHA-256 钉值（全仓唯一来源；
/// 桌面端经 agile_net_node::tool::doctor::WINTUN_DLL_SHA256 引用，
/// 升级 = 改这里 + 替换 apps/desktop/wintun/wintun.dll 内嵌文件 + 更新 desktop 侧 WINTUN_VERSION）。
pub const WINTUN_DLL_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

/// Windows 管理员权限：whoami /groups 含高完整性级 SID（免新依赖，语义对齐提权判定）。
#[cfg(windows)]
fn is_elevated() -> Option<bool> {
    let out = super::util::silent_command("whoami")
        .args(["/groups"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    Some(stdout.contains("S-1-16-12288"))
}

pub(super) fn section_tun(ctx: &DoctorContext) -> DoctorSection {
    let mut items = Vec::new();
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        let dll = ctx.data_dir.join("mihomo").join("wintun.dll");
        if !dll.exists() {
            items.push(item(
                "wintun",
                "wintun.dll",
                DoctorStatus::Info,
                "未安装（开启 TUN 模式时自动下载）",
                None,
            ));
        } else {
            match std::fs::read(&dll) {
                Ok(bytes) if crate::db::sha256_hex(&bytes) == WINTUN_DLL_SHA256 => {
                    items.push(item(
                        "wintun",
                        "wintun.dll",
                        DoctorStatus::Ok,
                        "0.14.1 完整性校验通过（SHA-256 钉值匹配）",
                        None,
                    ))
                }
                Ok(_) => {
                    // 损坏/篡改：删除让下次开启 TUN 自动重下
                    let fixed = ctx.fix && std::fs::remove_file(&dll).is_ok();
                    if fixed {
                        items.push(item(
                            "wintun",
                            "wintun.dll",
                            DoctorStatus::Fixed,
                            "SHA-256 与钉值不符（疑似损坏/篡改），已删除",
                            Some("下次开启 TUN 模式时将自动重新下载官方版本".into()),
                        ));
                    } else {
                        items.push(item(
                            "wintun",
                            "wintun.dll",
                            DoctorStatus::Err,
                            "SHA-256 与钉值不符（疑似损坏/篡改）",
                            Some(format!("删除 {} 后重新开启 TUN 模式", dll.display())),
                        ));
                    }
                }
                Err(e) => items.push(item(
                    "wintun",
                    "wintun.dll",
                    DoctorStatus::Warn,
                    format!("存在但读取失败：{e}"),
                    None,
                )),
            }
        }
        match is_elevated() {
            Some(true) => items.push(item(
                "admin",
                "管理员权限",
                DoctorStatus::Ok,
                "当前进程已提权（TUN 可直接开启）",
                None,
            )),
            Some(false) => items.push(item(
                "admin",
                "管理员权限",
                DoctorStatus::Info,
                "非管理员进程（开启 TUN 时会请求 UAC 提权）",
                None,
            )),
            None => items.push(item(
                "admin",
                "管理员权限",
                DoctorStatus::Info,
                "无法判定管理员权限（whoami 不可用）",
                None,
            )),
        }
    }
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = ctx;
        items.push(item(
            "tun",
            "TUN 支持",
            DoctorStatus::Info,
            "当前平台 TUN 由系统 tun/utun 设备提供（GUI TUN 模式限 Windows x64，无需 wintun）",
            None,
        ));
    }
    section("tun", "TUN 支持", items)
}
