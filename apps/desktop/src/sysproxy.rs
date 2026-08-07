//! System proxy management: point the system proxy at the local proxy port and restore the snapshot on disable;
//! conflict inspection — detect third-party changes to the system proxy and reclaim it with one click (doctor core).
//!
//! - Windows: HKCU Internet Settings (ProxyEnable/ProxyServer) + InternetSetOption for immediate effect
//! - macOS: networksetup sets web/secure/socks proxies per network service, snapshot restores per service

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::roles;

/// Managed state (polled by the frontend for display).
#[derive(Debug, Clone, Serialize)]
pub struct SysProxyStatus {
    /// Whether management is enabled
    pub managed: bool,
    /// Conflict: current system value != our expected value (modified by a third party, or proxy port changed)
    pub conflict: bool,
    /// Expected value (127.0.0.1:port; empty when unmanaged)
    pub expected: String,
    /// Current system value (raw string; empty when system proxy is disabled)
    pub current: String,
}

fn snapshot_path() -> PathBuf {
    roles::data_dir().join("sysproxy-snapshot.json")
}

/// Snapshot of the system proxy taken before enabling management (restored on disable).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    /// Windows: previous ProxyServer (None when it was disabled)
    previous: Option<String>,
    /// macOS: per-service snapshot (service, kind, enabled, server, port)
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

// ==================== Platform implementations ====================

#[cfg(windows)]
mod imp {
    use super::*;

    const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn key() -> Result<winreg::RegKey, String> {
        winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
            .open_subkey_with_flags(SUBKEY, winreg::enums::KEY_READ | winreg::enums::KEY_WRITE)
            .map_err(|e| e.to_string())
    }

    /// Current system proxy (Some(server) when enabled).
    pub fn get() -> Result<Option<String>, String> {
        let k = key()?;
        let enabled: u32 = k.get_value("ProxyEnable").unwrap_or(0);
        if enabled == 0 {
            return Ok(None);
        }
        let server: String = k.get_value("ProxyServer").unwrap_or_default();
        Ok(Some(server))
    }

    /// Notify the system of settings changes (running apps won't notice otherwise).
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

    /// Parse get*proxy output: (enabled, server, port)
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

    /// Current system proxy (returns the first hit server:port if any service has web/secure/socks proxy enabled).
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

// ==================== Public semantics ====================

/// Enable management: snapshot (first call only; repeat calls never overwrite the original snapshot) -> point to the local proxy port.
/// Idempotent: safe to re-engage after proxy restart/port change; restore always returns to the pre-first-engage state.
pub fn engage(server: &str) -> Result<(), String> {
    if !snapshot_path().exists() {
        imp::take_snapshot()?;
    }
    imp::set(server)?;
    roles::audit("gui.sysproxy_engage", serde_json::json!({"server": server}));
    ensure_watchdog();
    Ok(())
}

/// Startup cleanup: an unrestored snapshot means the last run exited abnormally (process killed/crashed)
/// and may have left the system proxy pointing at a dead port — restore from the snapshot; no snapshot means never managed, leave system settings untouched.
pub fn cleanup_if_pending() -> Result<(), String> {
    if snapshot_path().exists() {
        disengage()?;
    }
    Ok(())
}

/// Disable management: restore the snapshot (or just disable the system proxy if none exists).
pub fn disengage() -> Result<(), String> {
    if snapshot_path().exists() {
        imp::restore()?;
    } else {
        imp::disable()?;
    }
    roles::audit("gui.sysproxy_disengage", serde_json::json!({}));
    Ok(())
}

/// Inspect: return managed state and conflict determination.
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

/// Reclaim: rewrite the system proxy to the expected value.
/// Snapshot first when none exists (lock/TUN patrols can reclaim without a prior engage — the
/// pre-management system state must still be restorable on a later disengage instead of being lost).
pub fn reclaim(server: &str) -> Result<(), String> {
    if !snapshot_path().exists() {
        imp::take_snapshot()?;
    }
    imp::set(server)?;
    roles::audit("gui.sysproxy_reclaim", serde_json::json!({"server": server}));
    ensure_watchdog();
    Ok(())
}

// ==================== Exit-path recovery ====================

/// Whether the system proxy is (or should be) under our management: the explicit system-proxy
/// preference, locked mode (patrol auto-reclaims), or TUN mode (side effects engage it).
/// Every exit/uninstall path must disengage when this holds — otherwise the system is left
/// pointing at a dead port and the machine goes offline.
pub(crate) fn managed(r: &roles::RoleSettings) -> bool {
    r.system_proxy || r.sysproxy_lock || r.tun_mode
}

/// Spawn the detached restore watchdog once per process (`--sysproxy-watchdog <pid>` headless mode):
/// it waits for THIS process to die, then restores the system proxy if a management snapshot is
/// still on disk — i.e. only when we were killed / crashed / force-terminated without disengaging
/// (incl. Windows shutdown/logoff terminating the process). A clean exit deletes the snapshot
/// first, so the watchdog then does nothing and exits.
#[cfg(windows)]
pub(crate) fn ensure_watchdog() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--sysproxy-watchdog")
        .arg(std::process::id().to_string());
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW: debug builds are console-subsystem
    if let Err(e) = cmd.spawn() {
        tracing::warn!(error = %e, "failed to spawn sysproxy restore watchdog");
    }
}

#[cfg(not(windows))]
pub(crate) fn ensure_watchdog() {}

#[cfg(test)]
mod tests {
    /// The managed predicate gates every exit/uninstall disengage path: it must cover the explicit
    /// system-proxy preference, locked mode, and TUN mode — a mode escaping it strands the machine
    /// on a dead proxy port (offline) after quit.
    #[test]
    fn managed_covers_all_takeover_modes() {
        let base = crate::roles::RoleSettings {
            system_proxy: false,
            sysproxy_lock: false,
            tun_mode: false,
            ..Default::default()
        };
        assert!(!super::managed(&base));
        for (sp, lock, tun) in [(true, false, false), (false, true, false), (false, false, true)] {
            let r = crate::roles::RoleSettings {
                system_proxy: sp,
                sysproxy_lock: lock,
                tun_mode: tun,
                ..base.clone()
            };
            assert!(super::managed(&r), "managed must hold for sp={sp} lock={lock} tun={tun}");
        }
    }
}
