//! Section 1: ports and occupancy (own-process recognition + orphaned mihomo sweep).

use super::util::{kernel_bin_name, listeners_on};
use super::{DoctorContext, DoctorItem, DoctorSection, DoctorStatus, item, section};
use crate::tool::netstat::SocketInfo;

/// Ports under check (port, description): default port conventions in AGENTS.md §4 (50k range avoids the Clash family).
const PORT_CHECKS: &[(u16, &str)] = &[
    (59090, "API 管理面（anet-svc）"),
    (54430, "Relay 扇入监听（anet-svc）"),
    (59293, "内嵌节点 API（anet-gui 服务端角色）"),
    (54431, "内嵌节点 Relay（anet-gui 服务端角色）"),
    (57890, "客户端本地代理（anet-gui）"),
    (57892, "订阅内核 mixed 入站（mihomo）"),
    (57893, "订阅内核 socks 入站（mihomo）"),
    (59292, "订阅内核控制面（mihomo）"),
];

/// Own-process name keywords (occupancy by these is not a conflict).
const OUR_PROCESS_KEYWORDS: &[&str] = &["anet", "agile", "mihomo"];

fn is_our_process(name: &str) -> bool {
    let n = name.to_lowercase();
    OUR_PROCESS_KEYWORDS.iter().any(|k| n.contains(k))
}

/// Single-port evaluation (pure function; tests inject listeners directly).
/// `expected`: the port "should be listening" under the current roles; `idle_reason` explains
/// the not-listening state when it should not listen.
pub(super) fn eval_port(
    port: u16,
    label: &str,
    listeners: &[&SocketInfo],
    expected: bool,
    idle_reason: &str,
) -> DoctorItem {
    let id = format!("port-{port}");
    let label = format!("{label} :{port}");
    if let Some(s) = listeners.first() {
        let name = s.process.as_deref().unwrap_or("-");
        return match (s.pid, is_our_process(name)) {
            (Some(pid), _) if pid == std::process::id() => item(
                id,
                label,
                DoctorStatus::Ok,
                format!("本进程（{name}）监听中"),
                None,
            ),
            (_, true) => item(
                id,
                label,
                DoctorStatus::Ok,
                format!(
                    "{} 监听中",
                    match s.pid {
                        Some(pid) => format!("{name} (PID {pid})"),
                        None => name.to_string(),
                    }
                ),
                None,
            ),
            (None, false) => item(
                id,
                label,
                DoctorStatus::Warn,
                "端口被占用，但无权限确认归属进程".to_string(),
                Some(format!(
                    "以管理员/root 身份运行可查看归属；确认占用者可 `anet tool killport {port}` 处理"
                )),
            ),
            (Some(pid), false) => item(
                id,
                label,
                DoctorStatus::Err,
                format!("端口被外部进程 {name} (PID {pid}) 占用"),
                Some(format!(
                    "结束占用进程（`anet tool killport {port} -y`）或在配置中更换该端口后重启服务"
                )),
            ),
        };
    }
    if expected {
        item(
            id,
            label,
            DoctorStatus::Warn,
            format!("{idle_reason}，但端口未监听"),
            Some("确认对应角色/服务已启动；端口被占用改配后需重启生效".into()),
        )
    } else {
        item(id, label, DoctorStatus::Info, format!("未监听（{idle_reason}）"), None)
    }
}

/// Read gui-settings.json (when present and parseable; only the role booleans are used for port expectations).
fn read_gui_settings(ctx: &DoctorContext) -> Option<serde_json::Value> {
    std::fs::read_to_string(ctx.data_dir.join("gui-settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

pub(super) fn section_ports(
    ctx: &DoctorContext,
    socks: &[SocketInfo],
    enum_failed: bool,
) -> DoctorSection {
    let mut items = Vec::new();
    if enum_failed {
        items.push(item(
            "socket-enum",
            "socket 枚举",
            DoctorStatus::Err,
            "无法枚举本机 socket（netstat2 失败或完全无权限）",
            Some("以管理员/root 身份重试；或用 `anet tool listen` 单独确认".into()),
        ));
        return section("ports", "端口与占用", items);
    }

    let svc_running = crate::svc::running_record().is_some();
    let settings = read_gui_settings(ctx);
    let client_role = settings
        .as_ref()
        .and_then(|v| v["client"].as_bool())
        .unwrap_or(false);
    let sub_role = settings
        .as_ref()
        .and_then(|v| v["subscription"].as_bool())
        .unwrap_or(false);
    let server_role = settings
        .as_ref()
        .and_then(|v| v["server"].as_bool())
        .unwrap_or(false);
    let kernel_installed = ctx.data_dir.join("mihomo").join(kernel_bin_name()).exists();

    for &(port, label) in PORT_CHECKS {
        let listeners = listeners_on(socks, port);
        let (expected, reason) = match port {
            59090 => (svc_running, "anet-svc 服务运行中".to_string()),
            59293 | 54431 => (
                ctx.gui && server_role,
                if ctx.gui && server_role {
                    "服务端角色（内嵌节点）已开启".to_string()
                } else if settings.is_none() {
                    "GUI 未运行过（无 gui-settings.json）".to_string()
                } else {
                    "服务端角色（内嵌节点）未开启".to_string()
                },
            ),
            54430 => (
                false,
                if svc_running {
                    "relay listener 可能未在配置启用".to_string()
                } else {
                    "anet-svc 未运行".to_string()
                },
            ),
            57890 => (
                ctx.gui && client_role,
                if ctx.gui && client_role {
                    "客户端角色已开启".to_string()
                } else if settings.is_none() {
                    "GUI 未运行过（无 gui-settings.json）".to_string()
                } else {
                    "客户端角色未开启".to_string()
                },
            ),
            _ => (
                ctx.gui && sub_role,
                if !kernel_installed {
                    "订阅内核未安装".to_string()
                } else if ctx.gui && sub_role {
                    "订阅角色已开启".to_string()
                } else {
                    "订阅角色未开启".to_string()
                },
            ),
        };
        // For 54430 the not-expected reason is already given; this is the 59090 reason when the service is down
        let reason = if port == 59090 && !svc_running {
            "anet-svc 未运行".to_string()
        } else {
            reason
        };
        items.push(eval_port(port, label, &listeners, expected, &reason));
    }

    if let Some(it) = sweep_orphan_kernels(ctx, socks) {
        items.push(it);
    }
    section("ports", "端口与占用", items)
}

/// Sweep leftover orphaned mihomo processes (only kills those whose exe path is inside this app's
/// kernel directory; user-installed mihomo/Clash is untouched; processes whose exe path is unreadable
/// are skipped — same criteria as GUI sweep_orphan_kernels, cross-platform via sysinfo).
fn sweep_orphan_kernels(ctx: &DoctorContext, socks: &[SocketInfo]) -> Option<DoctorItem> {
    use sysinfo::{ProcessesToUpdate, System};
    let kernel_dir = ctx.data_dir.join("mihomo");
    if !kernel_dir.exists() {
        return None;
    }
    // Managed whitelist: listeners of control-plane 59292 (bound as soon as the kernel starts,
    // covers GUI-managed instances) + explicitly passed-in PIDs
    let mut managed: Vec<u32> = ctx.managed_pids.clone();
    managed.extend(listeners_on(socks, 59292).iter().filter_map(|s| s.pid));

    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut orphans: Vec<(u32, sysinfo::Pid)> = Vec::new();
    for (pid, proc_) in sys.processes() {
        let name = proc_.name().to_string_lossy().to_lowercase();
        if name != "mihomo" && name != "mihomo.exe" {
            continue;
        }
        let Some(exe) = proc_.exe() else { continue }; // exe path unreadable (e.g. elevated instance): skip
        if !exe.starts_with(&kernel_dir) {
            continue;
        }
        if managed.contains(&pid.as_u32()) {
            continue;
        }
        orphans.push((pid.as_u32(), *pid));
    }
    if orphans.is_empty() {
        return None;
    }
    if !ctx.fix {
        return Some(item(
            "orphan-kernel",
            "遗留内核进程",
            DoctorStatus::Warn,
            format!(
                "发现 {} 个遗留 mihomo 进程（{}）",
                orphans.len(),
                orphans
                    .iter()
                    .map(|(p, _)| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Some("重启 anet-gui 可自动清扫；或手动结束上述进程".into()),
        ));
    }
    let mut killed = Vec::new();
    let mut failed = Vec::new();
    for (pid_u, pid) in &orphans {
        match sys.process(*pid) {
            Some(p) if p.kill() => killed.push(pid_u.to_string()),
            _ => failed.push(pid_u.to_string()),
        }
    }
    if failed.is_empty() {
        Some(item(
            "orphan-kernel",
            "遗留内核进程",
            DoctorStatus::Fixed,
            format!("已清理 {} 个遗留 mihomo 进程（PID {}）", killed.len(), killed.join(", ")),
            None,
        ))
    } else {
        Some(item(
            "orphan-kernel",
            "遗留内核进程",
            DoctorStatus::Warn,
            format!(
                "已清理 {} 个，{} 个终止失败（PID {}）",
                killed.len(),
                failed.len(),
                failed.join(", ")
            ),
            Some("终止失败的进程可能为提权实例，请以管理员身份手动结束".into()),
        ))
    }
}
