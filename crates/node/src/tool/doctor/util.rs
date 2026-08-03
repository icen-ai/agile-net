//! Cross-section shared helpers: socket matching, kernel file name, silent child processes.

use crate::tool::netstat::SocketInfo;

/// Extract the port from "addr:port" (including "[v6]:port").
fn socket_port(s: &SocketInfo) -> Option<u16> {
    s.local.rsplit_once(':')?.1.parse().ok()
}

/// LISTEN listeners on the given port (shared by the ports/sysproxy/kernel sections).
pub(super) fn listeners_on(socks: &[SocketInfo], port: u16) -> Vec<&SocketInfo> {
    socks
        .iter()
        .filter(|s| s.state.as_deref() == Some("LISTEN") && socket_port(s) == Some(port))
        .collect()
}

/// Kernel binary file name (shared by the ports/kernel sections).
pub(super) fn kernel_bin_name() -> &'static str {
    if cfg!(windows) { "mihomo.exe" } else { "mihomo" }
}

/// Spawn a child process without a console window (GUI context calling console programs like reg/networksetup).
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
