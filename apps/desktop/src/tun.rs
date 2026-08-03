//! TUN mode support (docs/plan/tun.md P1, Windows x64 desktop GUI only):
//! - Admin privilege detection (CheckTokenMembership; abstraction allows injecting mocks, see tests)
//! - "Restart as administrator" (ShellExecuteW runas relaunches own exe; tun_mode is persisted and auto-restored after restart)
//! - External upstream TCP probe (once when enabling TUN; failure only raises a dynamic-island warning, non-blocking)

/// Elevation check abstraction (production = system API; tests inject mocks).
pub trait Elevation: Send + Sync {
    /// Whether the current process already has admin privileges.
    fn is_admin(&self) -> bool;
    /// Relaunch own exe as administrator (caller then exits the current instance).
    fn relaunch_elevated(&self) -> Result<(), String>;
}

/// Production implementation: Windows system API; always unsupported on other platforms.
pub struct SystemElevation;

#[cfg(windows)]
impl Elevation for SystemElevation {
    fn is_admin(&self) -> bool {
        is_admin()
    }

    fn relaunch_elevated(&self) -> Result<(), String> {
        relaunch_elevated()
    }
}

#[cfg(not(windows))]
impl Elevation for SystemElevation {
    fn is_admin(&self) -> bool {
        false
    }

    fn relaunch_elevated(&self) -> Result<(), String> {
        Err("TUN 模式当前仅支持 Windows x64".into())
    }
}

/// Whether the current process runs as administrator (CheckTokenMembership against the Administrators group).
#[cfg(windows)]
pub fn is_admin() -> bool {
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, SECURITY_NT_AUTHORITY,
    };
    use windows_sys::Win32::System::SystemServices::{
        DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID,
    };
    unsafe {
        let mut sid = std::ptr::null_mut();
        if AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut sid,
        ) == 0
        {
            return false;
        }
        let mut member = 0;
        // TokenHandle = NULL: use the current thread's token (process token when not impersonating)
        let ok = CheckTokenMembership(std::ptr::null_mut(), sid, &mut member) != 0 && member != 0;
        FreeSid(sid);
        ok
    }
}

/// Relaunch own exe as administrator (the runas verb triggers UAC; Ok only means the request was issued).
/// SW_HIDE: console-subsystem debug builds launched via ShellExecute get a newly allocated visible console
/// window — hide it (logs are viewable in the GUI console window); release is a windows-subsystem build with no console anyway.
#[cfg(windows)]
fn relaunch_elevated() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let verb: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    let file: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let ret = unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE,
        )
    };
    // Return value > 32 means success, otherwise an error code
    if ret as usize > 32 {
        Ok(())
    } else {
        Err(format!("以管理员身份重启失败 (code {})", ret as usize))
    }
}

/// Pre-check before enabling TUN: pass if already admin; otherwise NEED_ELEVATION (frontend shows an elevation dialog).
pub fn precheck(elev: &dyn Elevation) -> Result<(), String> {
    if elev.is_admin() {
        Ok(())
    } else {
        Err(format!("{NEED_ELEVATION_PREFIX}TUN 模式需要管理员权限（创建虚拟网卡）"))
    }
}

/// Error prefix: lets the frontend distinguish "needs elevation" from ordinary errors (dialog instead of toast).
pub const NEED_ELEVATION_PREFIX: &str = "NEED_ELEVATION:";

/// External upstream TCP probe (1.5s default timeout; unreachable only warns, non-blocking).
pub async fn tcp_reachable(addr: std::net::SocketAddr) -> bool {
    tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockElevation {
        admin: bool,
    }

    impl Elevation for MockElevation {
        fn is_admin(&self) -> bool {
            self.admin
        }

        fn relaunch_elevated(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn precheck_admin_passes() {
        let elev = MockElevation { admin: true };
        assert!(precheck(&elev).is_ok());
    }

    #[test]
    fn precheck_non_admin_requires_elevation() {
        let elev = MockElevation { admin: false };
        let err = precheck(&elev).unwrap_err();
        assert!(err.starts_with(NEED_ELEVATION_PREFIX), "err={err}");
    }

    #[tokio::test]
    async fn tcp_reachable_probe() {
        // Listening port → reachable
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(tcp_reachable(addr).await);
        drop(listener);
        // Released port → unreachable (connection refused)
        assert!(!tcp_reachable(addr).await);
    }
}
