//! 第 2 节：系统代理（残留检测与自动还原；Windows 注册表 / macOS networksetup）。

use super::util::listeners_on;
use super::{DoctorContext, DoctorSection, DoctorStatus, item, section};
use crate::tool::netstat::SocketInfo;

/// 系统代理读取结果。
enum SysProxy {
    Off,
    On(String),
    /// 仅非 Windows/macOS 构造（read_sysproxy 的平台 cfg 分支）
    #[allow(dead_code)]
    Unsupported,
    Unknown(String),
}

/// Windows：reg query 读 HKCU Internet Settings（零新依赖；值不存在/查询失败 → None）。
#[cfg(windows)]
fn reg_query(value: &str) -> Option<String> {
    let out = super::util::silent_command("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            value,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let l = line.trim();
        if l.starts_with(value) {
            // 形如 "ProxyEnable    REG_DWORD    0x1"
            return l.split_whitespace().last().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(windows)]
fn read_sysproxy() -> SysProxy {
    let enabled = reg_query("ProxyEnable")
        .map(|v| v == "0x1" || v == "1")
        .unwrap_or(false);
    if !enabled {
        return SysProxy::Off;
    }
    match reg_query("ProxyServer") {
        Some(server) if !server.is_empty() => SysProxy::On(server),
        _ => SysProxy::Unknown("ProxyEnable=1 但 ProxyServer 为空".into()),
    }
}

#[cfg(windows)]
fn disable_sysproxy() -> Result<(), String> {
    let out = super::util::silent_command("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(target_os = "macos")]
mod macos_proxy {
    use super::SysProxy;

    /// (种类, 查询参数, 关态参数)
    const KINDS: &[(&str, &str, &str)] = &[
        ("web", "-getwebproxy", "-setwebproxystate"),
        ("secure", "-getsecurewebproxy", "-setsecurewebproxystate"),
        ("socks", "-getsocksfirewallproxy", "-setsocksfirewallproxystate"),
    ];

    fn run(args: &[&str]) -> Result<String, String> {
        let out = super::super::util::silent_command("networksetup")
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

    fn parse_get(out: &str) -> (bool, String, u16) {
        let (mut enabled, mut server, mut port) = (false, String::new(), 0u16);
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

    /// 任一服务启用 web/secure/socks 代理则返回首个命中 server:port。
    pub fn get() -> SysProxy {
        match services() {
            Ok(svcs) => {
                for svc in &svcs {
                    for (_, get_arg, _) in KINDS {
                        match run(&[get_arg, svc]) {
                            Ok(out) => {
                                let (enabled, server, port) = parse_get(&out);
                                if enabled && !server.is_empty() {
                                    return SysProxy::On(format!("{server}:{port}"));
                                }
                            }
                            Err(e) => return SysProxy::Unknown(e),
                        }
                    }
                }
                SysProxy::Off
            }
            Err(e) => SysProxy::Unknown(e),
        }
    }

    /// 关闭所有指向本地代理端口（127.0.0.1:57890）的服务代理状态。
    pub fn disable_local() -> Result<(), String> {
        for svc in services()? {
            for (_, get_arg, off_arg) in KINDS {
                let out = run(&[get_arg, &svc])?;
                let (enabled, server, port) = parse_get(&out);
                if enabled && server == "127.0.0.1" && port == 57890 {
                    run(&[off_arg, &svc, "off"])?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn read_sysproxy() -> SysProxy {
    macos_proxy::get()
}

#[cfg(not(any(windows, target_os = "macos")))]
fn read_sysproxy() -> SysProxy {
    SysProxy::Unsupported
}

/// 代理地址是否指向本机客户端代理端口（兼容 "127.0.0.1:57890" 与按协议分段形式）。
fn targets_local_proxy(server: &str) -> bool {
    (server.contains("127.0.0.1") || server.contains("localhost")) && server.contains("57890")
}

pub(super) fn section_sysproxy(ctx: &DoctorContext, socks: &[SocketInfo]) -> DoctorSection {
    let mut items = Vec::new();
    match read_sysproxy() {
        SysProxy::Unsupported => items.push(item(
            "sysproxy",
            "系统代理",
            DoctorStatus::Info,
            "当前平台跳过系统代理检测（仅 Windows/macOS）",
            None,
        )),
        SysProxy::Unknown(e) => items.push(item(
            "sysproxy",
            "系统代理",
            DoctorStatus::Info,
            format!("无法读取系统代理配置：{e}"),
            None,
        )),
        SysProxy::Off => items.push(item(
            "sysproxy",
            "系统代理",
            DoctorStatus::Ok,
            "系统代理未启用",
            None,
        )),
        SysProxy::On(server) if targets_local_proxy(&server) => {
            let proxy_alive = !listeners_on(socks, 57890).is_empty();
            if proxy_alive {
                items.push(item(
                    "sysproxy",
                    "系统代理",
                    DoctorStatus::Ok,
                    format!("指向本地代理（{server}），代理运行中"),
                    None,
                ));
            } else if ctx.fix {
                // 残留：代理已不在运行，系统代理仍指向 57890 → 还原关闭
                #[cfg(windows)]
                let res = disable_sysproxy();
                #[cfg(target_os = "macos")]
                let res = macos_proxy::disable_local();
                #[cfg(not(any(windows, target_os = "macos")))]
                let res: Result<(), String> = Ok(());
                match res {
                    Ok(()) => items.push(item(
                        "sysproxy",
                        "系统代理",
                        DoctorStatus::Fixed,
                        format!("已关闭残留系统代理（原指向 {server}，代理未运行）"),
                        Some("Windows 上运行中的浏览器可能需重启才感知变更".into()),
                    )),
                    Err(e) => items.push(item(
                        "sysproxy",
                        "系统代理",
                        DoctorStatus::Err,
                        format!("系统代理残留指向 {server}（代理未运行），自动关闭失败：{e}"),
                        Some("手动关闭：系统设置 → 网络 → 代理".into()),
                    )),
                }
            } else {
                items.push(item(
                    "sysproxy",
                    "系统代理",
                    DoctorStatus::Err,
                    format!("系统代理残留指向 {server}，但代理未运行（全网流量将失败）"),
                    Some("关闭系统代理，或启动 AgileNet 客户端角色".into()),
                ));
            }
        }
        SysProxy::On(server) => items.push(item(
            "sysproxy",
            "系统代理",
            DoctorStatus::Info,
            format!("系统代理指向 {server}（其他代理软件）"),
            Some("与 AgileNet 系统代理托管共存时注意相互覆盖；必要时启用「系统代理锁定」".into()),
        )),
    }
    section("sysproxy", "系统代理", items)
}
