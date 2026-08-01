//! 系统代理托管：把系统代理指向本地代理端口，关闭时还原快照；
//! 冲突巡检——系统代理被第三方改动时可检出并一键收回（诊断核心）。
//!
//! - Windows：HKCU Internet Settings（ProxyEnable/ProxyServer）+ InternetSetOption 即时生效
//! - macOS：networksetup 逐网络服务设置 web/secure/socks 代理，快照逐服务还原

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::roles;

/// 托管状态（前端轮询展示）。
#[derive(Debug, Clone, Serialize)]
pub struct SysProxyStatus {
    /// 托管开关是否开启
    pub managed: bool,
    /// 冲突：系统当前值 ≠ 我们设置的期望值（被第三方修改或代理端口已变）
    pub conflict: bool,
    /// 期望值（127.0.0.1:端口；未托管为空）
    pub expected: String,
    /// 系统当前值（原始字串；未启用系统代理为空）
    pub current: String,
}

fn snapshot_path() -> PathBuf {
    roles::data_dir().join("sysproxy-snapshot.json")
}

/// 开启托管前的系统代理快照（关闭时还原）。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    /// Windows：先前的 ProxyServer（未启用为 None）
    previous: Option<String>,
    /// macOS：逐服务快照（service, kind, enabled, server, port）
    #[serde(default)]
    services: Vec<ServiceSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceSnapshot {
    service: String,
    kind: String,
    enabled: bool,
    server: String,
    port: u16,
}

// ==================== 平台实现 ====================

#[cfg(windows)]
mod imp {
    use super::*;

    const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn key() -> Result<winreg::RegKey, String> {
        winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey_with_flags(SUBKEY, winreg::enums::KEY_READ | winreg::enums::KEY_WRITE)
            .map_err(|e| e.to_string())
    }

    /// 当前系统代理（启用则 Some(server)）。
    pub fn get() -> Result<Option<String>, String> {
        let k = key()?;
        let enabled: u32 = k.get_value("ProxyEnable").unwrap_or(0);
        if enabled == 0 {
            return Ok(None);
        }
        let server: String = k.get_value("ProxyServer").unwrap_or_default();
        Ok(Some(server))
    }

    /// 通知系统设置变更（不通知则运行中的应用不感知）。
    fn notify() {
        use windows_sys::Win32::Networking::WinInet::{
            INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
        };
        unsafe {
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null(),
                0,
            );
            InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
        }
    }

    pub fn set(server: &str) -> Result<(), String> {
        let k = key()?;
        k.set_value("ProxyServer", &server).map_err(|e| e.to_string())?;
        k.set_value("ProxyEnable", &1u32).map_err(|e| e.to_string())?;
        notify();
        Ok(())
    }

    pub fn take_snapshot() -> Result<(), String> {
        let snap = Snapshot {
            previous: get()?,
            services: Vec::new(),
        };
        let data = serde_json::to_string_pretty(&snap).map_err(|e| e.to_string())?;
        std::fs::write(snapshot_path(), data).map_err(|e| e.to_string())
    }

    pub fn restore() -> Result<(), String> {
        let data = std::fs::read_to_string(snapshot_path()).map_err(|e| e.to_string())?;
        let snap: Snapshot = serde_json::from_str(&data).map_err(|e| e.to_string())?;
        match snap.previous {
            Some(server) => set(&server)?,
            None => disable()?,
        }
        let _ = std::fs::remove_file(snapshot_path());
        Ok(())
    }

    pub fn disable() -> Result<(), String> {
        let k = key()?;
        k.set_value("ProxyEnable", &0u32).map_err(|e| e.to_string())?;
        notify();
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    const KINDS: [(&str, &str, &str); 3] = [
        ("web", "-getwebproxy", "-setwebproxy"),
        ("secure", "-getsecurewebproxy", "-setsecurewebproxy"),
        ("socks", "-getsocksfirewallproxy", "-setsocksfirewallproxy"),
    ];

    fn run(args: &[&str]) -> Result<String, String> {
        let out = std::process::Command::new("networksetup")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    fn services() -> Result<Vec<String>, String> {
        let out = run(&["-listallnetworkservices"])?;
        Ok(out
            .lines()
            .skip(1)
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('*'))
            .collect())
    }

    /// 解析 get*proxy 输出：(enabled, server, port)
    fn parse_get(out: &str) -> (bool, String, u16) {
        let mut enabled = false;
        let mut server = String::new();
        let mut port = 0u16;
        for line in out.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("Enabled:") {
                enabled = v.trim().eq_ignore_ascii_case("yes");
            } else if let Some(v) = line.strip_prefix("Server:") {
                server = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Port:") {
                port = v.trim().parse().unwrap_or(0);
            }
        }
        (enabled, server, port)
    }

    /// 当前系统代理（任一服务启用 web/secure/socks 代理则返回首个命中 server:port）。
    pub fn get() -> Result<Option<String>, String> {
        for svc in services()? {
            for (_, get_arg, _) in KINDS {
                let (enabled, server, port) = parse_get(&run(&[get_arg, &svc])?);
                if enabled && !server.is_empty() {
                    return Ok(Some(format!("{server}:{port}")));
                }
            }
        }
        Ok(None)
    }

    pub fn set(server: &str) -> Result<(), String> {
        let (host, port) = server
            .rsplit_once(':')
            .ok_or_else(|| format!("代理地址格式错误: {server}"))?;
        for svc in services()? {
            for (_, _, set_arg) in KINDS {
                run(&[set_arg, &svc, host, port])?;
            }
        }
        Ok(())
    }

    fn clear_all() -> Result<(), String> {
        for svc in services()? {
            for (_, _, set_arg) in KINDS {
                run(&[set_arg, &svc, "", "0"])?;
                run(&[&format!("{set_arg}state"), &svc, "off"])?;
            }
        }
        Ok(())
    }

    pub fn take_snapshot() -> Result<(), String> {
        let mut snaps = Vec::new();
        for svc in services()? {
            for (kind, get_arg, _) in KINDS {
                let (enabled, server, port) = parse_get(&run(&[get_arg, &svc])?);
                snaps.push(ServiceSnapshot {
                    service: svc.clone(),
                    kind: kind.to_string(),
                    enabled,
                    server,
                    port,
                });
            }
        }
        let snap = Snapshot {
            previous: None,
            services: snaps,
        };
        let data = serde_json::to_string_pretty(&snap).map_err(|e| e.to_string())?;
        std::fs::write(snapshot_path(), data).map_err(|e| e.to_string())
    }

    pub fn restore() -> Result<(), String> {
        let data = std::fs::read_to_string(snapshot_path()).map_err(|e| e.to_string())?;
        let snap: Snapshot = serde_json::from_str(&data).map_err(|e| e.to_string())?;
        for s in &snap.services {
            let Some((_, _, set_arg)) = KINDS.iter().find(|(k, _, _)| *k == s.kind) else {
                continue;
            };
            if s.enabled && !s.server.is_empty() {
                run(&[set_arg, &s.service, &s.server, &s.port.to_string()])?;
            } else {
                run(&[&format!("{set_arg}state"), &s.service, "off"])?;
            }
        }
        let _ = std::fs::remove_file(snapshot_path());
        Ok(())
    }

    pub fn disable() -> Result<(), String> {
        clear_all()
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    pub fn get() -> Result<Option<String>, String> {
        Ok(None)
    }
    pub fn set(_server: &str) -> Result<(), String> {
        Err("当前平台不支持系统代理托管".into())
    }
    pub fn take_snapshot() -> Result<(), String> {
        Ok(())
    }
    pub fn restore() -> Result<(), String> {
        Ok(())
    }
    pub fn disable() -> Result<(), String> {
        Ok(())
    }
}

// ==================== 对外语义 ====================

/// 开启托管：快照（仅首次，重复调用不覆盖原快照）→ 指向本地代理端口。
/// 幂等：代理重启/端口变化时重复 engage 安全，还原始终回到首次开启前的状态。
pub fn engage(server: &str) -> Result<(), String> {
    if !snapshot_path().exists() {
        imp::take_snapshot()?;
    }
    imp::set(server)?;
    roles::audit("gui.sysproxy_engage", serde_json::json!({"server": server}));
    Ok(())
}

/// 启动清理：存在未还原快照说明上次异常退出（进程被杀/崩溃）可能遗留
/// 系统代理指向已死端口，按快照还原；无快照则未曾托管，不碰系统设置。
pub fn cleanup_if_pending() -> Result<(), String> {
    if snapshot_path().exists() {
        disengage()?;
    }
    Ok(())
}

/// 关闭托管：还原快照（无快照则直接关闭系统代理）。
pub fn disengage() -> Result<(), String> {
    if snapshot_path().exists() {
        imp::restore()?;
    } else {
        imp::disable()?;
    }
    roles::audit("gui.sysproxy_disengage", serde_json::json!({}));
    Ok(())
}

/// 巡检：返回托管状态与冲突判定。
pub fn inspect(managed: bool, expected: &str) -> Result<SysProxyStatus, String> {
    let current = imp::get()?.unwrap_or_default();
    let conflict = managed && current != expected;
    Ok(SysProxyStatus {
        managed,
        conflict,
        expected: if managed { expected.to_string() } else { String::new() },
        current,
    })
}

/// 收回：把系统代理重写为期望值。
pub fn reclaim(server: &str) -> Result<(), String> {
    imp::set(server)?;
    roles::audit("gui.sysproxy_reclaim", serde_json::json!({"server": server}));
    Ok(())
}
