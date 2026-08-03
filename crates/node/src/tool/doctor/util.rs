//! 跨节共享小工具：socket 匹配、内核文件名、静默子进程。

use crate::tool::netstat::SocketInfo;

/// 从 "addr:port"（含 "[v6]:port"）提取端口。
fn socket_port(s: &SocketInfo) -> Option<u16> {
    s.local.rsplit_once(':')?.1.parse().ok()
}

/// 指定端口的 LISTEN 监听者（ports/sysproxy/kernel 三节共享）。
pub(super) fn listeners_on(socks: &[SocketInfo], port: u16) -> Vec<&SocketInfo> {
    socks
        .iter()
        .filter(|s| s.state.as_deref() == Some("LISTEN") && socket_port(s) == Some(port))
        .collect()
}

/// 内核二进制文件名（ports/kernel 两节共用）。
pub(super) fn kernel_bin_name() -> &'static str {
    if cfg!(windows) { "mihomo.exe" } else { "mihomo" }
}

/// 拉起子进程不弹控制台窗口（GUI 上下文调 reg/networksetup 等控制台程序）。
pub(super) fn silent_command(prog: &str) -> std::process::Command {
    #[allow(unused_mut)]
    let mut c = std::process::Command::new(prog);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}
