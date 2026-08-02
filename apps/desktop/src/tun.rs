//! TUN 模式支撑（docs/plan/tun.md P1，仅 Windows x64 桌面 GUI）：
//! - 管理员权限检测（CheckTokenMembership；抽象层可注入 mock，见 tests）
//! - 「以管理员身份重启」（ShellExecuteW runas 拉起自身 exe；tun_mode 已持久化，重启后自动恢复开启）
//! - 外部上游 TCP 拨测（开启 TUN 时一次；不通仅灵动岛告警，不阻断）

/// 权限检测抽象（生产 = 系统 API；测试注入 mock）。
pub trait Elevation: Send + Sync {
    /// 当前进程是否已具有管理员权限。
    fn is_admin(&self) -> bool;
    /// 以管理员身份拉起自身 exe（调用方随后退出当前实例）。
    fn relaunch_elevated(&self) -> Result<(), String>;
}

/// 生产实现：Windows 系统 API；其他平台恒为不支持。
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

/// 当前进程是否以管理员身份运行（CheckTokenMembership 查 Administrators 组成员）。
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
        // TokenHandle = NULL：使用当前线程（未模拟则为进程）令牌
        let ok = CheckTokenMembership(std::ptr::null_mut(), sid, &mut member) != 0 && member != 0;
        FreeSid(sid);
        ok
    }
}

/// 以管理员身份拉起自身 exe（runas 动词触发 UAC；返回 Ok 仅表示请求已发出）。
/// 用 SW_HIDE：控制台子系统的 debug 构建经 ShellExecute 拉起会新分配可见命令行窗口，
/// 隐藏之（日志可在 GUI 控制台窗口查看）；release 为 windows 子系统本无控制台。
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
    // 返回值 > 32 表示成功，否则为错误码
    if ret as usize > 32 {
        Ok(())
    } else {
        Err(format!("以管理员身份重启失败 (code {})", ret as usize))
    }
}

/// 开启 TUN 前置判定：已是管理员直接放行；否则报 NEED_ELEVATION（前端弹提权对话框）。
pub fn precheck(elev: &dyn Elevation) -> Result<(), String> {
    if elev.is_admin() {
        Ok(())
    } else {
        Err(format!("{NEED_ELEVATION_PREFIX}TUN 模式需要管理员权限（创建虚拟网卡）"))
    }
}

/// 错误前缀：前端据此区分「需提权」与普通错误（弹对话框而非 toast）。
pub const NEED_ELEVATION_PREFIX: &str = "NEED_ELEVATION:";

/// 外部上游 TCP 拨测（默认 1.5s 超时；不通仅告警不阻断）。
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
        // 监听端口 → 可达
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(tcp_reachable(addr).await);
        drop(listener);
        // 已释放端口 → 不可达（连接拒绝）
        assert!(!tcp_reachable(addr).await);
    }
}
