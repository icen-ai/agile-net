//! doctor — 自我诊断引擎（`anet doctor` 与 anet-gui「自我诊断」按钮共用）。
//!
//! 契约要点：
//! - [`run`] 返回结构化 [`DoctorReport`]（serde Serialize 即 GUI 契约，字段名不得改动），
//!   [`render`] 负责人类可读渲染（分节 + 状态标记 + 建议 + 汇总行）；
//! - 能安全自动修复的问题直接修并标 `fixed`：孤儿 mihomo、残留系统代理、损坏的 GUI
//!   配置文件（备份后重置）、非法自定义规则、系统 hosts 托管块漂移、损坏的 wintun/内核文件；
//! - 退出码语义由调用方决定：[`exit_code`] —— 有 `err` 项 → 1，否则 0（warn/info 不影响）；
//! - 本机操作：不走会话校验、不写审计日志；节点数据库仅以只读方式打开（CIDR 冲突检查）。

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::netstat::{self, SocketInfo};

// ==================== 报告模型（GUI 契约，字段名一字不得改） ====================

/// 单项检查结论：`ok` 通过 / `info` 提示 / `warn` 警告 / `err` 错误 / `fixed` 已自动修复。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Ok,
    Info,
    Warn,
    Err,
    Fixed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorItem {
    pub id: String,
    pub label: String,
    pub status: DoctorStatus,
    pub detail: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorSection {
    pub id: String,
    pub title: String,
    pub items: Vec<DoctorItem>,
}

/// 汇总计数（info 项不计入；fixed 不抵消 err——修复前的 err 已转为 fixed）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctorSummary {
    pub ok: usize,
    pub warn: usize,
    pub err: usize,
    pub fixed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub sections: Vec<DoctorSection>,
    pub summary: DoctorSummary,
    pub duration_ms: u64,
}

/// 诊断上下文：控制 GUI 特有路径（GUI 数据文件 / 内核与 wintun 钉值 / 孤儿 sweep / 系统代理）。
#[derive(Debug, Clone)]
pub struct DoctorContext {
    /// GUI 上下文：检查 GUI 数据文件、订阅内核与 wintun、系统代理残留、hosts 托管块漂移
    pub gui: bool,
    /// 允许自动修复（false = 只诊断不动手；测试与只读场景用）
    pub fix: bool,
    /// AgileNet 数据目录（默认 ~/.agile-net；测试注入临时目录）
    pub data_dir: PathBuf,
    /// 节点 SQLite 路径（只读查 CIDR 冲突；None 或不存在 = 跳过）
    pub db_path: Option<PathBuf>,
    /// 已知受管的 mihomo PID（孤儿判定白名单，叠加控制面监听者自动豁免）
    pub managed_pids: Vec<u32>,
}

impl DoctorContext {
    /// anet-gui 自我诊断：检查 GUI 数据文件 + 内嵌节点库（存在时）。
    pub fn gui() -> Self {
        let data_dir = default_data_dir();
        let embedded_db = data_dir.join("embedded-node").join("node.db");
        Self {
            gui: true,
            fix: true,
            db_path: embedded_db.exists().then_some(embedded_db),
            data_dir,
            managed_pids: Vec::new(),
        }
    }

    /// `anet doctor`：本机体检；节点库取 DATABASE_PATH 或 ./agile-net.db（存在时）。
    pub fn cli() -> Self {
        let db_path = std::env::var("DATABASE_PATH")
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .or_else(|| {
                let p = PathBuf::from("agile-net.db");
                p.exists().then_some(p)
            });
        Self {
            gui: false,
            fix: true,
            data_dir: default_data_dir(),
            db_path,
            managed_pids: Vec::new(),
        }
    }
}

/// 数据目录（与 apps/desktop roles::data_dir 同规则）。
fn default_data_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".agile-net")
}

// ==================== 入口 ====================

/// 检查节计划（id, 标题），顺序即执行顺序；GUI 据此在诊断开始时预渲染骨架占位。
pub const SECTION_PLAN: [(&str, &str); 7] = [
    ("ports", "端口与占用"),
    ("sysproxy", "系统代理"),
    ("tun", "TUN 支持"),
    ("kernel", "订阅内核"),
    ("network", "网络连通"),
    ("config", "配置与数据"),
    ("rules", "规则冲突"),
];

/// 执行全部检查并生成报告（检查项失败只落到对应 item，绝不 panic/中断整体）。
pub async fn run(ctx: DoctorContext) -> DoctorReport {
    run_streaming(ctx, |_| {}).await
}

/// 同 [`run`]，但每完成一节即回调（GUI 流式渲染：逐节到达逐节上屏）。
pub async fn run_streaming(
    ctx: DoctorContext,
    on_section: impl Fn(&DoctorSection),
) -> DoctorReport {
    let start = Instant::now();
    // socket 枚举一次，ports/sysproxy/kernel 三节共享（失败时 ports 节报 err，其余按无监听处理）
    let socks_result = netstat::sockets();
    let enum_failed = socks_result.is_err();
    let socks = socks_result.unwrap_or_default();

    let mut sections = Vec::with_capacity(SECTION_PLAN.len());
    let mut push = |sec: DoctorSection| {
        on_section(&sec);
        sections.push(sec);
    };
    push(section_ports(&ctx, &socks, enum_failed));
    push(section_sysproxy(&ctx, &socks));
    push(section_tun(&ctx));
    push(section_kernel(&ctx, &socks).await);
    push(section_network().await);
    push(section_config(&ctx));
    push(section_rules(&ctx));
    let summary = summarize(&sections);
    DoctorReport {
        sections,
        summary,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// 退出码：有 err → 1，否则 0（warn/info 不影响）。
pub fn exit_code(report: &DoctorReport) -> i32 {
    if report.summary.err > 0 { 1 } else { 0 }
}

fn summarize(sections: &[DoctorSection]) -> DoctorSummary {
    let mut s = DoctorSummary::default();
    for sec in sections {
        for it in &sec.items {
            match it.status {
                DoctorStatus::Ok => s.ok += 1,
                DoctorStatus::Warn => s.warn += 1,
                DoctorStatus::Err => s.err += 1,
                DoctorStatus::Fixed => s.fixed += 1,
                DoctorStatus::Info => {}
            }
        }
    }
    s
}

fn item(
    id: impl Into<String>,
    label: impl Into<String>,
    status: DoctorStatus,
    detail: impl Into<String>,
    suggestion: Option<String>,
) -> DoctorItem {
    DoctorItem {
        id: id.into(),
        label: label.into(),
        status,
        detail: detail.into(),
        suggestion,
    }
}

fn section(id: &str, title: &str, items: Vec<DoctorItem>) -> DoctorSection {
    DoctorSection {
        id: id.into(),
        title: title.into(),
        items,
    }
}

/// 人类可读渲染（cli 无着色体系，沿用 [标记] 文本风格）。
pub fn render(report: &DoctorReport) -> String {
    let mut out = String::from("AgileNet 自我诊断报告");
    for sec in &report.sections {
        out.push_str(&format!("\n\n■ {}", sec.title));
        for it in &sec.items {
            out.push_str(&format!(
                "\n  {} {}：{}",
                tag(it.status),
                it.label,
                it.detail
            ));
            if let Some(s) = &it.suggestion {
                out.push_str(&format!("\n      建议：{s}"));
            }
        }
    }
    let s = &report.summary;
    out.push_str(&format!(
        "\n\n汇总：通过 {} · 警告 {} · 错误 {} · 已修复 {}（耗时 {}ms）",
        s.ok, s.warn, s.err, s.fixed, report.duration_ms
    ));
    out
}

fn tag(status: DoctorStatus) -> &'static str {
    match status {
        DoctorStatus::Ok => "[通过]",
        DoctorStatus::Info => "[提示]",
        DoctorStatus::Warn => "[警告]",
        DoctorStatus::Err => "[错误]",
        DoctorStatus::Fixed => "[修复]",
    }
}

// ==================== 1. 端口与占用 ====================

/// 受检端口（端口, 说明）：默认端口规范见 AGENTS.md §4（5 万段避让 Clash 系）。
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

/// 本家进程名关键字（占用这些端口时不视为冲突）。
const OUR_PROCESS_KEYWORDS: &[&str] = &["anet", "agile", "mihomo"];

fn is_our_process(name: &str) -> bool {
    let n = name.to_lowercase();
    OUR_PROCESS_KEYWORDS.iter().any(|k| n.contains(k))
}

/// 从 "addr:port"（含 "[v6]:port"）提取端口。
fn socket_port(s: &SocketInfo) -> Option<u16> {
    s.local.rsplit_once(':')?.1.parse().ok()
}

fn listeners_on<'a>(socks: &'a [SocketInfo], port: u16) -> Vec<&'a SocketInfo> {
    socks
        .iter()
        .filter(|s| s.state.as_deref() == Some("LISTEN") && socket_port(s) == Some(port))
        .collect()
}

/// 单端口评估（纯函数，测试直接注入监听者）。
/// `expected`：该端口按当前角色「应监听」；`idle_reason` 为未监听且不应监听时的说明。
fn eval_port(
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

/// 读取 gui-settings.json（存在且可解析时；仅取角色布尔字段做端口期望判定）。
fn read_gui_settings(ctx: &DoctorContext) -> Option<serde_json::Value> {
    std::fs::read_to_string(ctx.data_dir.join("gui-settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

fn kernel_bin_name() -> &'static str {
    if cfg!(windows) { "mihomo.exe" } else { "mihomo" }
}

fn section_ports(ctx: &DoctorContext, socks: &[SocketInfo], enum_failed: bool) -> DoctorSection {
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
        // 54430 不应监听时 reason 已给出；59090 服务未运行时的 reason
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

/// 清扫遗留 mihomo 孤儿进程（只杀 exe 路径=本应用内核目录者，用户自建的 mihomo/Clash 不动；
/// 无权限读 exe 路径的进程跳过——与 GUI sweep_orphan_kernels 同口径，跨平台 sysinfo 实现）。
fn sweep_orphan_kernels(ctx: &DoctorContext, socks: &[SocketInfo]) -> Option<DoctorItem> {
    use sysinfo::{ProcessesToUpdate, System};
    let kernel_dir = ctx.data_dir.join("mihomo");
    if !kernel_dir.exists() {
        return None;
    }
    // 受管白名单：控制面 59292 的监听者（内核启动即绑定，覆盖 GUI 托管实例）+ 显式传入
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
        let Some(exe) = proc_.exe() else { continue }; // 无权限读路径（如提权实例）：跳过
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

// ==================== 2. 系统代理 ====================

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
    let out = silent_command("reg")
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
    let out = silent_command("reg")
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
        let out = super::silent_command("networksetup")
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

/// 拉起子进程不弹控制台窗口（GUI 上下文调 reg/networksetup 等控制台程序）。
fn silent_command(prog: &str) -> std::process::Command {
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

fn section_sysproxy(ctx: &DoctorContext, socks: &[SocketInfo]) -> DoctorSection {
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

// ==================== 3. TUN 支持 ====================

/// wintun.dll 0.14.1 (amd64) 本体 SHA-256（与 apps/desktop/src/subscription.rs WINTUN_DLL_SHA256 同步）。
const WINTUN_DLL_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// Windows 管理员权限：whoami /groups 含高完整性级 SID（免新依赖，语义对齐提权判定）。
#[cfg(windows)]
fn is_elevated() -> Option<bool> {
    let out = silent_command("whoami").args(["/groups"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    Some(stdout.contains("S-1-16-12288"))
}

fn section_tun(ctx: &DoctorContext) -> DoctorSection {
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
                Ok(bytes) if sha256_hex(&bytes) == WINTUN_DLL_SHA256 => items.push(item(
                    "wintun",
                    "wintun.dll",
                    DoctorStatus::Ok,
                    "0.14.1 完整性校验通过（SHA-256 钉值匹配）",
                    None,
                )),
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

// ==================== 4. 订阅内核 ====================

/// 钉死的 mihomo 版本（与 apps/desktop/src/subscription.rs MIHOMO_VERSION 同步）。
/// 注：官方只对压缩包给哈希钉（裸二进制不可对钉，见 download.rs 设计），
/// 故这里以「可运行 + 自报版本 = 钉版」做完整性代理校验。
const MIHOMO_VERSION: &str = "1.19.29";

fn kernel_platform_supported() -> bool {
    cfg!(all(target_os = "windows", target_arch = "x86_64"))
        || cfg!(all(target_os = "macos", target_arch = "aarch64"))
        || cfg!(all(target_os = "macos", target_arch = "x86_64"))
}

/// 读取 subscriptions.json 中的控制面 secret（无文件/无 secret → None）。
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

async fn section_kernel(ctx: &DoctorContext, socks: &[SocketInfo]) -> DoctorSection {
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

    // 控制面 /version 可达性（无 secret 跳过）
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

/// 运行 `mihomo -v` 取版本行（3s 超时；GUI 上下文不弹黑窗）。
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

// ==================== 5. 网络连通 ====================

async fn section_network() -> DoctorSection {
    let mut items = Vec::new();

    // DNS 解析
    match tokio::net::lookup_host(("www.cloudflare.com", 443)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            match addrs.first() {
                Some(first) => items.push(item(
                    "dns",
                    "DNS 解析",
                    DoctorStatus::Ok,
                    format!(
                        "www.cloudflare.com → {}（共 {} 个地址）",
                        first.ip(),
                        addrs.len()
                    ),
                    None,
                )),
                None => items.push(item(
                    "dns",
                    "DNS 解析",
                    DoctorStatus::Err,
                    "www.cloudflare.com 解析结果为空",
                    Some("检查系统 DNS 配置（`anet tool dnsconf`）".into()),
                )),
            }
        }
        Err(e) => items.push(item(
            "dns",
            "DNS 解析",
            DoctorStatus::Err,
            format!("www.cloudflare.com 解析失败：{e}"),
            Some("检查系统 DNS 配置（`anet tool dnsconf` / `anet tool dns www.cloudflare.com`）".into()),
        )),
    }

    // HTTPS 出站
    let https_start = Instant::now();
    let https = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string());
    match https {
        Err(e) => items.push(item(
            "https",
            "HTTPS 出站",
            DoctorStatus::Err,
            format!("HTTP 客户端构建失败：{e}"),
            None,
        )),
        Ok(client) => match client.get("https://ipwho.is/").send().await {
            Ok(resp) if resp.status().is_success() => items.push(item(
                "https",
                "HTTPS 出站",
                DoctorStatus::Ok,
                format!(
                    "ipwho.is 可达（HTTP {}，{}ms）",
                    resp.status(),
                    https_start.elapsed().as_millis()
                ),
                None,
            )),
            Ok(resp) => items.push(item(
                "https",
                "HTTPS 出站",
                DoctorStatus::Err,
                format!("ipwho.is 返回 HTTP {}", resp.status()),
                Some("出站 HTTPS 异常：检查网关/防火墙（`anet tool diag ipwho.is 443`）".into()),
            )),
            Err(e) => items.push(item(
                "https",
                "HTTPS 出站",
                DoctorStatus::Err,
                format!("ipwho.is 不可达：{e}"),
                Some("出站 HTTPS 不通：检查网关/防火墙（`anet tool diag ipwho.is 443`）".into()),
            )),
        },
    }

    // 默认网关 ping（失败仅提示——很多网关禁 ICMP）
    match default_net::get_default_gateway() {
        Ok(gw) => match ping_once(gw.ip_addr, Duration::from_secs(1)).await {
            Ok(ms) => items.push(item(
                "gateway",
                "默认网关",
                DoctorStatus::Ok,
                format!("{} 可达（{ms:.1}ms）", gw.ip_addr),
                None,
            )),
            Err(e) => items.push(item(
                "gateway",
                "默认网关",
                DoctorStatus::Info,
                format!("{} ping 不通（{e}；网关常禁 ICMP，仅提示）", gw.ip_addr),
                None,
            )),
        },
        Err(_) => items.push(item(
            "gateway",
            "默认网关",
            DoctorStatus::Info,
            "未找到默认网关（可能仅本地网络）",
            None,
        )),
    }
    section("network", "网络连通", items)
}

/// 单发 ICMP ping（surge-ping；无权限/超时均为 Err 由调用方降级为提示）。
async fn ping_once(addr: IpAddr, timeout: Duration) -> Result<f64, String> {
    use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};
    let config = match addr {
        IpAddr::V4(_) => Config::default(),
        IpAddr::V6(_) => Config::builder().kind(ICMP::V6).build(),
    };
    let client = Client::new(&config).map_err(|e| format!("ICMP socket 创建失败：{e}"))?;
    let mut pinger = client.pinger(addr, PingIdentifier(rand::random())).await;
    pinger.timeout(timeout);
    pinger
        .ping(PingSequence(0), b"anet-doctor")
        .await
        .map(|(_, rtt)| rtt.as_secs_f64() * 1000.0)
        .map_err(|e| e.to_string())
}

// ==================== 6. 配置与数据 ====================

/// GUI 数据文件（文件名, 损坏重置时的默认内容；内容须能被桌面端反序列化为默认值）。
const GUI_DATA_FILES: &[(&str, &str)] = &[
    // RoleSettings 必填三字段写全，其余字段 serde default 兜底
    ("gui-settings.json", r#"{"client":true,"server":false,"web":false}"#),
    ("subscriptions.json", "{}"),
    ("gui-custom-rules.json", "{}"),
];

fn section_config(ctx: &DoctorContext) -> DoctorSection {
    let mut items = Vec::new();
    let dir = &ctx.data_dir;
    if !dir.exists() {
        items.push(item(
            "data-dir",
            "数据目录",
            DoctorStatus::Info,
            format!("{} 不存在（将在首次使用时创建）", dir.display()),
            None,
        ));
    } else {
        // 目录可写
        let probe = dir.join(".doctor-write-test");
        match std::fs::write(&probe, b"t").and_then(|_| std::fs::remove_file(&probe)) {
            Ok(()) => items.push(item(
                "writable",
                "数据目录可写",
                DoctorStatus::Ok,
                dir.display().to_string(),
                None,
            )),
            Err(e) => items.push(item(
                "writable",
                "数据目录可写",
                DoctorStatus::Err,
                format!("{} 写入失败：{e}", dir.display()),
                Some("检查目录权限与占用（杀毒软件实时防护可能拦截）".into()),
            )),
        }
        // GUI 数据文件可解析（CLI 上下文只检已存在的文件；GUI 上下文缺失也报告）
        for &(name, default_content) in GUI_DATA_FILES {
            let path = dir.join(name);
            if !path.exists() {
                if ctx.gui {
                    items.push(item(
                        format!("file-{name}"),
                        name,
                        DoctorStatus::Info,
                        "不存在（按需创建）",
                        None,
                    ));
                }
                continue;
            }
            let parsed = std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
            if parsed.is_some() {
                items.push(item(
                    format!("file-{name}"),
                    name,
                    DoctorStatus::Ok,
                    "可解析",
                    None,
                ));
                continue;
            }
            // 损坏：备份为 .bak-时间戳 并重置默认
            if ctx.fix {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let bak = dir.join(format!("{name}.bak-{ts}"));
                let res = std::fs::rename(&path, &bak)
                    .and_then(|_| std::fs::write(&path, default_content));
                match res {
                    Ok(()) => items.push(item(
                        format!("file-{name}"),
                        name,
                        DoctorStatus::Fixed,
                        format!("文件损坏，已备份为 {} 并重置默认", bak.display()),
                        None,
                    )),
                    Err(e) => items.push(item(
                        format!("file-{name}"),
                        name,
                        DoctorStatus::Err,
                        format!("文件损坏且重置失败：{e}"),
                        Some(format!("手动备份并删除 {} 后重启应用", path.display())),
                    )),
                }
            } else {
                items.push(item(
                    format!("file-{name}"),
                    name,
                    DoctorStatus::Err,
                    "文件损坏（JSON 不可解析）",
                    Some("备份后删除该文件，应用将以默认值重建".into()),
                ));
            }
        }
    }

    // 磁盘剩余空间（<1GiB err / <5GiB warn）
    items.push(check_disk_space(dir));
    section("config", "配置与数据", items)
}

/// 数据目录所在卷的剩余空间检查（sysinfo Disks，最长挂载点前缀匹配）。
fn check_disk_space(dir: &Path) -> DoctorItem {
    const GIB: u64 = 1024 * 1024 * 1024;
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disk = disks
        .iter()
        .filter(|d| dir.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len());
    match disk {
        None => item(
            "disk",
            "磁盘剩余空间",
            DoctorStatus::Info,
            "未找到数据目录所在卷",
            None,
        ),
        Some(d) => {
            let avail = d.available_space();
            let detail = format!(
                "剩余 {:.1} GiB（卷 {}）",
                avail as f64 / GIB as f64,
                d.mount_point().display()
            );
            if avail < GIB {
                item(
                    "disk",
                    "磁盘剩余空间",
                    DoctorStatus::Err,
                    detail,
                    Some("剩余空间不足 1 GiB：清理磁盘，数据库/日志写入即将失败".into()),
                )
            } else if avail < 5 * GIB {
                item(
                    "disk",
                    "磁盘剩余空间",
                    DoctorStatus::Warn,
                    detail,
                    Some("剩余空间不足 5 GiB：建议清理（下载制品与日志将持续占用）".into()),
                )
            } else {
                item("disk", "磁盘剩余空间", DoctorStatus::Ok, detail, None)
            }
        }
    }
}

// ==================== 7. 规则冲突 ====================

/// GUI 托管块标记（与 apps/desktop/src/custom_rules.rs 一致）。
const GUI_BLOCK_BEGIN: &str = "# AgileNet begin";
const GUI_BLOCK_END: &str = "# AgileNet end";

fn system_hosts_path() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        PathBuf::from(root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

/// 放行 pattern 合法性（对齐 desktop add_bypass：非空且无空白字符）。
fn valid_bypass_pattern(p: &str) -> bool {
    !p.is_empty() && !p.chars().any(|c| c.is_whitespace())
}

/// hosts 映射合法性（对齐 desktop add_host：主机名非 IP、无空白/*/#；IP 可解析）。
fn valid_host_entry(host: &str, ip: &str) -> bool {
    !host.is_empty()
        && !host.chars().any(|c| c.is_whitespace() || c == '*' || c == '#')
        && host.parse::<IpAddr>().is_err()
        && ip.parse::<IpAddr>().is_ok()
}

/// 从 gui-custom-rules.json 提取生效的 hosts 映射（enabled 且 to_system）。
fn expected_hosts_entries(v: &serde_json::Value) -> Vec<(String, String)> {
    v["hosts"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|r| r["enabled"].as_bool().unwrap_or(true) && r["to_system"].as_bool().unwrap_or(false))
                .filter_map(|r| {
                    Some((
                        r["hostname"].as_str()?.to_lowercase(),
                        r["ip"].as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 解析系统 hosts 中的 GUI 托管块条目。
fn read_managed_block(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let t = line.trim();
        match t {
            GUI_BLOCK_BEGIN => in_block = true,
            GUI_BLOCK_END => in_block = false,
            _ if in_block && !t.is_empty() && !t.starts_with('#') => {
                let mut tokens = t.split_whitespace();
                if let (Some(ip), Some(host)) = (tokens.next(), tokens.next()) {
                    out.push((host.to_lowercase(), ip.to_string()));
                }
            }
            _ => {}
        }
    }
    out
}

/// 剔除托管块（语义对齐 desktop strip_block）。
fn strip_managed_block(content: &str) -> String {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let t = line.trim();
        if t == GUI_BLOCK_BEGIN {
            in_block = true;
            continue;
        }
        if t == GUI_BLOCK_END {
            in_block = false;
            continue;
        }
        if !in_block {
            out.push(line);
        }
    }
    let mut s = out.join("\n");
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// 幂等重写系统 hosts 托管块（temp + rename；权限不足返回 Err）。
fn rewrite_managed_block(path: &Path, entries: &[(String, String)]) -> Result<(), String> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut new_content = strip_managed_block(&content);
    if !entries.is_empty() {
        new_content.push_str(GUI_BLOCK_BEGIN);
        new_content.push('\n');
        for (host, ip) in entries {
            new_content.push_str(&format!("{ip} {host}\n"));
        }
        new_content.push_str(GUI_BLOCK_END);
        new_content.push('\n');
    }
    if new_content == content {
        return Ok(());
    }
    let tmp = path.with_extension("anet-doctor-tmp");
    std::fs::write(&tmp, &new_content).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// 清理规则文件中的非法项（Value 层面操作以保留未知字段）；返回移除项描述。
fn sanitize_rules_file(v: &mut serde_json::Value) -> Vec<String> {
    let mut removed = Vec::new();
    let mut removed_ids: Vec<String> = Vec::new();
    if let Some(arr) = v["bypass"].as_array_mut() {
        arr.retain(|r| {
            let pattern = r["pattern"].as_str().unwrap_or("");
            let ok = valid_bypass_pattern(pattern);
            if !ok {
                removed.push(format!("bypass:{pattern}"));
                if let Some(id) = r["id"].as_str() {
                    removed_ids.push(id.to_string());
                }
            }
            ok
        });
    }
    if let Some(arr) = v["hosts"].as_array_mut() {
        arr.retain(|r| {
            let host = r["hostname"].as_str().unwrap_or("");
            let ip = r["ip"].as_str().unwrap_or("");
            let ok = valid_host_entry(host, ip);
            if !ok {
                removed.push(format!("host:{host}"));
                if let Some(id) = r["id"].as_str() {
                    removed_ids.push(id.to_string());
                }
            }
            ok
        });
    }
    // 级联清理组合中的失效成员 key（对齐 desktop remove 语义）
    if !removed_ids.is_empty()
        && let Some(combos) = v["combos"].as_array_mut()
    {
        for c in combos {
            if let Some(keys) = c["rule_keys"].as_array_mut() {
                keys.retain(|k| {
                    k.as_str()
                        .map(|s| !removed_ids.iter().any(|id| id == s))
                        .unwrap_or(true)
                });
            }
        }
    }
    removed
}

/// 放行 pattern 重复检测（大小写不敏感）；返回重复的 pattern 列表。
fn duplicate_patterns(v: &serde_json::Value) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut dups: Vec<String> = Vec::new();
    if let Some(arr) = v["bypass"].as_array() {
        for r in arr {
            let Some(p) = r["pattern"].as_str() else { continue };
            let key = p.to_lowercase();
            if seen.contains(&key) {
                if !dups.contains(&key) {
                    dups.push(key);
                }
            } else {
                seen.push(key);
            }
        }
    }
    dups
}

fn section_rules(ctx: &DoctorContext) -> DoctorSection {
    let mut items = Vec::new();
    let rules_path = ctx.data_dir.join("gui-custom-rules.json");
    let rules_val: Option<serde_json::Value> = std::fs::read_to_string(&rules_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    if let Some(mut v) = rules_val {
        // 非法项（err + fix 移除）
        let invalid = sanitize_rules_file(&mut v);
        if !invalid.is_empty() {
            let fixed = ctx.fix
                && std::fs::write(&rules_path, serde_json::to_string_pretty(&v).unwrap_or_default())
                    .is_ok();
            if fixed {
                items.push(item(
                    "custom-invalid",
                    "非法自定义规则",
                    DoctorStatus::Fixed,
                    format!("已移除 {} 条非法规则（{}）", invalid.len(), invalid.join(", ")),
                    None,
                ));
            } else {
                items.push(item(
                    "custom-invalid",
                    "非法自定义规则",
                    DoctorStatus::Err,
                    format!("存在 {} 条非法规则（{}）", invalid.len(), invalid.join(", ")),
                    Some("删除 gui-custom-rules.json 中对应条目或重置该文件".into()),
                ));
            }
        }
        // pattern 重复（warn）
        let dups = duplicate_patterns(&v);
        if !dups.is_empty() {
            items.push(item(
                "custom-dup",
                "放行规则重复",
                DoctorStatus::Warn,
                format!("重复 pattern：{}", dups.join(", ")),
                Some("在 GUI「自定义规则」中删除重复项".into()),
            ));
        }
        if invalid.is_empty() && dups.is_empty() {
            items.push(item(
                "custom",
                "自定义规则",
                DoctorStatus::Ok,
                "无重复/非法项",
                None,
            ));
        }
        // hosts 托管块漂移（fix 重写）
        let expected = expected_hosts_entries(&v);
        let hosts_path = system_hosts_path();
        let content = std::fs::read_to_string(&hosts_path).unwrap_or_default();
        let current = read_managed_block(&content);
        let mut exp = expected.clone();
        let mut cur = current.clone();
        exp.sort();
        cur.sort();
        if exp != cur {
            if ctx.fix {
                match rewrite_managed_block(&hosts_path, &expected) {
                    Ok(()) => items.push(item(
                        "hosts-drift",
                        "系统 hosts 托管块",
                        DoctorStatus::Fixed,
                        format!(
                            "托管块与规则库不一致（期望 {} 条/实际 {} 条），已重写",
                            expected.len(),
                            current.len()
                        ),
                        None,
                    )),
                    Err(e) => items.push(item(
                        "hosts-drift",
                        "系统 hosts 托管块",
                        DoctorStatus::Warn,
                        format!("托管块漂移，重写失败：{e}"),
                        Some("以管理员/root 身份运行 doctor 或在 GUI 中重新保存 hosts 映射".into()),
                    )),
                }
            } else {
                items.push(item(
                    "hosts-drift",
                    "系统 hosts 托管块",
                    DoctorStatus::Warn,
                    format!(
                        "托管块与规则库不一致（期望 {} 条/实际 {} 条）",
                        expected.len(),
                        current.len()
                    ),
                    Some("在 GUI「自定义规则」重新保存 hosts 映射以重写托管块".into()),
                ));
            }
        }
    } else if rules_path.exists() {
        // 损坏文件由「配置与数据」节负责修复（本节在其后执行，届时已重置为 {}）
        items.push(item(
            "custom",
            "自定义规则",
            DoctorStatus::Info,
            "规则文件不可解析（见「配置与数据」节处理）",
            None,
        ));
    }

    // 节点库 CIDR 包含关系冲突（只读；无库跳过）
    match &ctx.db_path {
        Some(db) if db.exists() => match read_db_cidrs(db) {
            Ok(values) => {
                let conflicts = cidr_conflicts(&values);
                if conflicts.is_empty() {
                    items.push(item(
                        "cidr",
                        "节点 CIDR 规则",
                        DoctorStatus::Ok,
                        format!("{} 条 ip-cidr 规则无包含冲突", values.len()),
                        None,
                    ));
                } else {
                    for (i, (big, small)) in conflicts.iter().take(10).enumerate() {
                        items.push(item(
                            format!("cidr-{i}"),
                            "CIDR 包含冲突",
                            DoctorStatus::Warn,
                            format!("{big} 完全包含 {small}（后者永不命中）"),
                            Some("确认包含关系是否有意；无意则删除被包含规则".into()),
                        ));
                    }
                    if conflicts.len() > 10 {
                        items.push(item(
                            "cidr-more",
                            "CIDR 包含冲突",
                            DoctorStatus::Warn,
                            format!("另有 {} 对包含冲突未列出", conflicts.len() - 10),
                            None,
                        ));
                    }
                }
            }
            Err(e) => items.push(item(
                "cidr",
                "节点 CIDR 规则",
                DoctorStatus::Info,
                format!("数据库只读打开失败，跳过 CIDR 冲突检查：{e}"),
                None,
            )),
        },
        _ => items.push(item(
            "cidr",
            "节点 CIDR 规则",
            DoctorStatus::Info,
            "未发现节点数据库，跳过 CIDR 冲突检查",
            None,
        )),
    }
    section("rules", "规则冲突", items)
}

/// 只读打开节点库读取 ip-cidr 规则值（不走 db 模块——避免触发迁移写）。
fn read_db_cidrs(path: &Path) -> Result<Vec<String>, String> {
    let conn = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare("SELECT value FROM rule WHERE type = 'ip-cidr'")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// CIDR 包含关系对（大网, 被包含网）；同值重复也报告。纯函数便于测试。
fn cidr_conflicts(values: &[String]) -> Vec<(String, String)> {
    let nets: Vec<Option<ip_network::IpNetwork>> =
        values.iter().map(|v| v.parse().ok()).collect();
    let contains = |a: &ip_network::IpNetwork, b: &ip_network::IpNetwork| {
        a.is_ipv4() == b.is_ipv4()
            && a.netmask() <= b.netmask()
            && a.contains(b.network_address())
    };
    let mut out = Vec::new();
    for i in 0..nets.len() {
        for j in (i + 1)..nets.len() {
            let (Some(a), Some(b)) = (&nets[i], &nets[j]) else {
                continue;
            };
            if contains(a, b) {
                out.push((values[i].clone(), values[j].clone()));
            } else if contains(b, a) {
                out.push((values[j].clone(), values[i].clone()));
            }
        }
    }
    out
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anet-doctor-test-{}-{}",
            tag,
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_ctx(dir: &Path, fix: bool) -> DoctorContext {
        DoctorContext {
            gui: true,
            fix,
            data_dir: dir.to_path_buf(),
            db_path: None,
            managed_pids: Vec::new(),
        }
    }

    fn listen_socket(port: u16, pid: Option<u32>, process: Option<&str>) -> SocketInfo {
        SocketInfo {
            proto: "tcp".into(),
            local: format!("127.0.0.1:{port}"),
            remote: None,
            state: Some("LISTEN".into()),
            pid,
            process: process.map(|s| s.into()),
        }
    }

    // ---------- 契约与汇总 ----------

    #[test]
    fn status_serializes_lowercase_contract() {
        assert_eq!(serde_json::to_value(DoctorStatus::Ok).unwrap(), "ok");
        assert_eq!(serde_json::to_value(DoctorStatus::Info).unwrap(), "info");
        assert_eq!(serde_json::to_value(DoctorStatus::Warn).unwrap(), "warn");
        assert_eq!(serde_json::to_value(DoctorStatus::Err).unwrap(), "err");
        assert_eq!(serde_json::to_value(DoctorStatus::Fixed).unwrap(), "fixed");
    }

    #[test]
    fn report_json_shape_matches_contract() {
        let report = DoctorReport {
            sections: vec![section(
                "s",
                "节",
                vec![item("i", "l", DoctorStatus::Ok, "d", Some("sug".into()))],
            )],
            summary: DoctorSummary { ok: 1, warn: 0, err: 0, fixed: 0 },
            duration_ms: 5,
        };
        let v = serde_json::to_value(&report).unwrap();
        assert!(v["duration_ms"].is_u64());
        assert_eq!(v["summary"]["ok"], 1);
        let it = &v["sections"][0]["items"][0];
        assert_eq!(it["id"], "i");
        assert_eq!(it["label"], "l");
        assert_eq!(it["status"], "ok");
        assert_eq!(it["detail"], "d");
        assert_eq!(it["suggestion"], "sug");
        // suggestion 缺省序列化为 null（GUI 契约字段必须存在）
        let it2 = serde_json::to_value(item("a", "b", DoctorStatus::Info, "c", None)).unwrap();
        assert!(it2.get("suggestion").is_some());
        assert!(it2["suggestion"].is_null());
    }

    #[test]
    fn summary_counts_and_exit_code() {
        let report = DoctorReport {
            sections: vec![section(
                "s",
                "节",
                vec![
                    item("a", "x", DoctorStatus::Ok, "", None),
                    item("b", "x", DoctorStatus::Info, "", None),
                    item("c", "x", DoctorStatus::Warn, "", None),
                    item("d", "x", DoctorStatus::Err, "", None),
                    item("e", "x", DoctorStatus::Fixed, "", None),
                ],
            )],
            summary: DoctorSummary::default(),
            duration_ms: 0,
        };
        let s = summarize(&report.sections);
        assert_eq!((s.ok, s.warn, s.err, s.fixed), (1, 1, 1, 1));
        let mut r = report;
        r.summary = summarize(&r.sections);
        assert_eq!(exit_code(&r), 1);
        r.sections[0].items.retain(|i| i.status != DoctorStatus::Err);
        r.summary = summarize(&r.sections);
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn render_contains_sections_tags_and_suggestion() {
        let report = DoctorReport {
            sections: vec![section(
                "ports",
                "端口与占用",
                vec![
                    item("p1", "API :59090", DoctorStatus::Ok, "未监听（anet-svc 未运行）", None),
                    item(
                        "p2",
                        "Relay :54430",
                        DoctorStatus::Err,
                        "被 evil.exe (PID 9) 占用",
                        Some("结束占用进程".into()),
                    ),
                ],
            )],
            summary: DoctorSummary { ok: 1, warn: 0, err: 1, fixed: 0 },
            duration_ms: 7,
        };
        let text = render(&report);
        assert!(text.contains("■ 端口与占用"));
        assert!(text.contains("[通过] API :59090"));
        assert!(text.contains("[错误] Relay :54430"));
        assert!(text.contains("建议：结束占用进程"));
        assert!(text.contains("错误 1"));
        assert!(text.contains("耗时 7ms"));
    }

    // ---------- 端口评估 ----------

    #[test]
    fn eval_port_foreign_occupation_is_err() {
        let socks = [listen_socket(59090, Some(4242), Some("nginx.exe"))];
        let refs: Vec<&SocketInfo> = socks.iter().collect();
        let it = eval_port(59090, "API 管理面", &refs, false, "x");
        assert_eq!(it.status, DoctorStatus::Err);
        assert!(it.detail.contains("nginx.exe"));
        assert!(it.detail.contains("4242"));
        assert!(it.suggestion.as_deref().unwrap_or("").contains("killport"));
    }

    #[test]
    fn eval_port_our_process_is_ok() {
        for name in ["anet-svc.exe", "mihomo", "anet-gui.exe"] {
            let socks = [listen_socket(59292, Some(1), Some(name))];
            let refs: Vec<&SocketInfo> = socks.iter().collect();
            let it = eval_port(59292, "控制面", &refs, false, "x");
            assert_eq!(it.status, DoctorStatus::Ok, "{name} 应视为本家");
        }
    }

    #[test]
    fn eval_port_expected_missing_is_warn_otherwise_info() {
        let it = eval_port(57890, "本地代理", &[], true, "客户端角色已开启");
        assert_eq!(it.status, DoctorStatus::Warn);
        let it = eval_port(57890, "本地代理", &[], false, "客户端角色未开启");
        assert_eq!(it.status, DoctorStatus::Info);
        assert!(it.detail.contains("未监听"));
    }

    #[test]
    fn eval_port_hidden_pid_is_warn() {
        let socks = [listen_socket(59090, None, None)];
        let refs: Vec<&SocketInfo> = socks.iter().collect();
        let it = eval_port(59090, "API", &refs, false, "x");
        assert_eq!(it.status, DoctorStatus::Warn);
        assert!(it.detail.contains("无权限"));
    }

    // ---------- 规则检查 ----------

    #[test]
    fn duplicate_patterns_case_insensitive() {
        let v = json!({"bypass":[
            {"id":"a","pattern":"*.Baidu.com"},
            {"id":"b","pattern":"*.baidu.com"},
            {"id":"c","pattern":"foo.com"}
        ]});
        assert_eq!(duplicate_patterns(&v), vec!["*.baidu.com".to_string()]);
    }

    #[test]
    fn sanitize_removes_invalid_and_cascades_combo_keys() {
        let mut v = json!({
            "bypass":[
                {"id":"b1","pattern":"ok.com"},
                {"id":"b2","pattern":"bad pattern"},
                {"id":"b3","pattern":""}
            ],
            "hosts":[
                {"id":"h1","hostname":"git.internal","ip":"10.0.0.9"},
                {"id":"h2","hostname":"1.2.3.4","ip":"10.0.0.9"},
                {"id":"h3","hostname":"x.com","ip":"not-an-ip"}
            ],
            "combos":[{"id":"c1","name":"n","rule_keys":["b1","b2","h2"]}]
        });
        let removed = sanitize_rules_file(&mut v);
        assert_eq!(removed.len(), 4); // b2 空白 / b3 空串 / h2 主机名为 IP / h3 IP 不可解析
        let bypass = v["bypass"].as_array().unwrap();
        assert_eq!(bypass.len(), 1);
        assert_eq!(bypass[0]["pattern"], "ok.com");
        let hosts = v["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        // 组合中失效 id 被级联清理
        let keys = v["combos"][0]["rule_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "b1");
    }

    #[test]
    fn rules_section_fixes_invalid_entries_on_disk() {
        let dir = tmp_dir("rules");
        std::fs::write(
            dir.join("gui-custom-rules.json"),
            r#"{"bypass":[{"id":"b1","pattern":"ok.com"},{"id":"b2","pattern":"bad pattern"}],"hosts":[],"combos":[]}"#,
        )
        .unwrap();
        let sec = section_rules(&test_ctx(&dir, true));
        let fixed = sec.items.iter().find(|i| i.id == "custom-invalid").unwrap();
        assert_eq!(fixed.status, DoctorStatus::Fixed);
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("gui-custom-rules.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["bypass"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- hosts 托管块 ----------

    #[test]
    fn managed_block_roundtrip_and_strip() {
        let content = "127.0.0.1 localhost\n# AgileNet begin\n10.0.0.9 git.internal\n# AgileNet end\n";
        let entries = read_managed_block(content);
        assert_eq!(entries, vec![("git.internal".to_string(), "10.0.0.9".to_string())]);
        let stripped = strip_managed_block(content);
        assert_eq!(stripped, "127.0.0.1 localhost\n");
    }

    #[test]
    fn rewrite_managed_block_updates_file() {
        let dir = tmp_dir("hosts");
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n# AgileNet begin\n9.9.9.9 stale\n# AgileNet end\n").unwrap();
        rewrite_managed_block(&path, &[("a.internal".into(), "1.1.1.1".into())]).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("1.1.1.1 a.internal"));
        assert!(!content.contains("stale"));
        assert!(content.contains("127.0.0.1 localhost"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- 配置文件修复 ----------

    #[test]
    fn config_section_backs_up_and_resets_corrupt_file() {
        let dir = tmp_dir("config");
        std::fs::write(dir.join("gui-settings.json"), "not json{{{").unwrap();
        let sec = section_config(&test_ctx(&dir, true));
        let it = sec
            .items
            .iter()
            .find(|i| i.id == "file-gui-settings.json")
            .unwrap();
        assert_eq!(it.status, DoctorStatus::Fixed);
        // 新文件可解析且为默认三字段
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("gui-settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["client"], true);
        // 备份存在
        let bak = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with("gui-settings.json.bak-"));
        assert!(bak, "应生成 .bak-时间戳 备份");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_section_reports_corrupt_without_fix() {
        let dir = tmp_dir("config-nofix");
        std::fs::write(dir.join("subscriptions.json"), "{{bad").unwrap();
        let sec = section_config(&test_ctx(&dir, false));
        let it = sec
            .items
            .iter()
            .find(|i| i.id == "file-subscriptions.json")
            .unwrap();
        assert_eq!(it.status, DoctorStatus::Err);
        assert!(it.suggestion.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- CIDR 冲突 ----------

    #[test]
    fn cidr_conflicts_detects_containment_and_duplicates() {
        let values = vec![
            "10.0.0.0/8".to_string(),
            "10.12.0.0/16".to_string(),
            "192.168.0.0/24".to_string(),
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
            "2001:db8:1::/48".to_string(),
        ];
        let conflicts = cidr_conflicts(&values);
        assert!(conflicts.contains(&("10.0.0.0/8".into(), "10.12.0.0/16".into())));
        assert!(conflicts.contains(&("10.0.0.0/8".into(), "10.0.0.0/8".into())));
        assert!(conflicts.contains(&("2001:db8::/32".into(), "2001:db8:1::/48".into())));
        assert!(!conflicts.iter().any(|(a, b)| a == "192.168.0.0/24" || b == "192.168.0.0/24"));
    }

    #[test]
    fn cidr_conflicts_skips_unparseable() {
        let values = vec!["not-a-cidr".to_string(), "10.0.0.0/8".to_string()];
        assert!(cidr_conflicts(&values).is_empty());
    }

    // ---------- 端到端冒烟 ----------

    #[tokio::test]
    async fn run_produces_all_sections_and_consistent_summary() {
        let dir = tmp_dir("run");
        let report = run(test_ctx(&dir, false)).await;
        let ids: Vec<&str> = report.sections.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["ports", "sysproxy", "tun", "kernel", "network", "config", "rules"]
        );
        let s = summarize(&report.sections);
        assert_eq!(s.ok, report.summary.ok);
        assert_eq!(s.err, report.summary.err);
        assert_eq!(exit_code(&report), if s.err > 0 { 1 } else { 0 });
        // 渲染不 panic 且含汇总行
        assert!(render(&report).contains("汇总："));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
