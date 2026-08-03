//! fwstatus / fwcheck — firewall probe hints (P3, shell-out probing; no rule-parsing reimplementation).
//!
//! Probes firewall-cmd / iptables / nft / Windows netsh advfirewall in order, using the first one found;
//! when none exist it honestly reports "no supported firewall tool detected" and suggests manual checks.
//! The iptables/nftables/firewalld rule systems differ too much (marginal-cost principle), so this module
//! only probes and hints, and never parses firewall rules (see docs/todo/cli-tool.md §2 P3).

use super::ToolOutcome;
use serde_json::json;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Tool probe priority: probe in order; the first one found is the primary tool.
const PROBE_ORDER: &[&str] = &["firewall-cmd", "iptables", "nft", "netsh"];

/// A detected firewall tool.
#[derive(Debug, Clone)]
struct FwTool {
    /// Tool name (firewall-cmd / iptables / nft / netsh)
    name: &'static str,
    /// Full path resolved from PATH (executed by full path later, no further PATH lookups)
    path: PathBuf,
}

/// Read-only status probe result for a single tool.
#[derive(Debug, Clone)]
struct ToolStatus {
    /// The status command actually executed (for display)
    command: String,
    /// Whether the status command ran successfully (false on insufficient permission / service not running)
    accessible: bool,
    /// Status summary (firewalld run state, rule-output line count, or a localized excerpt)
    detail: String,
    /// Extra hint (permission restricted, service not running, etc.)
    hint: Option<String>,
}

/// `anet tool fwstatus`: firewall status overview.
pub fn fwstatus() -> ToolOutcome {
    fwstatus_inner(None)
}

/// fwstatus implementation (path_env lets tests inject PATH).
fn fwstatus_inner(path_env: Option<&OsStr>) -> ToolOutcome {
    let tools = detect_tools(path_env);
    let Some(primary) = tools.first() else {
        let human = format!(
            "防火墙状态探测（shell out 探测，不解析规则）\n{}\n{}",
            no_tool_line(),
            manual_advice()
        );
        return ToolOutcome::fail(
            human,
            json!({
                "detected": false,
                "tools": [],
                "message": no_tool_line(),
                "hints": manual_hints(),
            }),
        );
    };
    let status = probe_status(primary);

    let mut human = String::from("防火墙状态探测（shell out 探测，不解析规则）\n");
    human.push_str(&format!(
        "主用工具: {} ({})\n",
        primary.name,
        primary.path.display()
    ));
    human.push_str(&format!("  $ {}\n", status.command));
    if !status.accessible {
        human.push_str("  结果: 不可访问（权限受限或服务未运行）\n");
    }
    human.push_str(&indent(&status.detail));
    if let Some(hint) = &status.hint {
        human.push_str(&format!("  提示: {hint}\n"));
    }
    if tools.len() > 1 {
        let others: Vec<&str> = tools[1..].iter().map(|t| t.name).collect();
        human.push_str(&format!("同时检测到: {}\n", others.join(" / ")));
    }

    ToolOutcome::ok(
        human.trim_end(),
        json!({
            "detected": true,
            "tools": tools
                .iter()
                .map(|t| json!({ "name": t.name, "path": t.path.display().to_string() }))
                .collect::<Vec<_>>(),
            "primary": {
                "name": primary.name,
                "path": primary.path.display().to_string(),
                "command": status.command,
                "accessible": status.accessible,
                "detail": status.detail,
                "hint": status.hint,
            },
        }),
    )
}

/// `anet tool fwcheck <port>`: probe the allow status of a port (probe-hint level).
pub fn fwcheck(port: u16) -> ToolOutcome {
    fwcheck_inner(port, None)
}

/// fwcheck implementation (path_env lets tests inject PATH).
fn fwcheck_inner(port: u16, path_env: Option<&OsStr>) -> ToolOutcome {
    let tools = detect_tools(path_env);
    let Some(primary) = tools.first() else {
        let human = format!(
            "端口防火墙探测: {port}/tcp（探测提示级别，不解析规则）\n{}\n{}",
            no_tool_line(),
            manual_advice()
        );
        return ToolOutcome::fail(
            human,
            json!({
                "port": port,
                "verdict": "unknown",
                "tool": null,
                "detail": no_tool_line(),
                "hints": manual_hints(),
            }),
        );
    };

    let (verdict, detail, mut hints) = check_port(primary, port);
    hints.push(format!(
        "本结果仅覆盖本机 {}；云安全组/上游网关防火墙需另行确认",
        primary.name
    ));
    hints.push(format!(
        "实测建议: 外部机器执行 anet tool tcping <本机IP> {port}；本机执行 anet tool portof {port} 确认监听"
    ));

    let mut human = format!("端口防火墙探测: {port}/tcp（探测提示级别，不解析规则）\n");
    human.push_str(&format!(
        "工具: {} ({})\n",
        primary.name,
        primary.path.display()
    ));
    human.push_str(&format!("结论: {detail}\n"));
    for h in &hints {
        human.push_str(&format!("  - {h}\n"));
    }

    let json = json!({
        "port": port,
        "verdict": verdict,
        "tool": { "name": primary.name, "path": primary.path.display().to_string() },
        "detail": detail,
        "hints": hints,
    });
    // Only "open" confirms reachability (exit 0); closed/unknown both exit 1, distinguished by verdict
    if verdict == "open" {
        ToolOutcome::ok(human.trim_end(), json)
    } else {
        ToolOutcome::fail(human.trim_end(), json)
    }
}

// ==================== Tool detection (shell out) ====================

/// Probe PATH for firewall tools in priority order (returns all hits; the first is primary).
fn detect_tools(path_env: Option<&OsStr>) -> Vec<FwTool> {
    PROBE_ORDER
        .iter()
        .filter_map(|name| find_on_path(name, path_env).map(|path| FwTool { name, path }))
        .collect()
}

/// Find an executable in PATH (injectable), returning its full path.
fn find_on_path(prog: &str, path_env: Option<&OsStr>) -> Option<PathBuf> {
    let path_var = match path_env {
        Some(p) => p.to_os_string(),
        None => std::env::var_os("PATH")?,
    };
    for dir in std::env::split_paths(&path_var) {
        // Windows executables carry extensions (a common PATHEXT subset suffices)
        #[cfg(windows)]
        let candidates = [
            format!("{prog}.exe"),
            format!("{prog}.cmd"),
            format!("{prog}.bat"),
            prog.to_string(),
        ];
        #[cfg(not(windows))]
        let candidates = [prog.to_string()];
        for name in &candidates {
            let full = dir.join(name);
            if is_executable(&full) {
                return Some(full);
            }
        }
    }
    None
}

/// Whether the path is an executable file (unix checks the exec bit).
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Whether the path is an executable file (Windows has no exec bit; existence suffices).
#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Run a command and capture output (spawn failure returns an Err description; never panics).
fn run_capture(prog: &Path, args: &[&str]) -> Result<Output, String> {
    let mut cmd = Command::new(prog);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: avoid popping up a console window in GUI scenarios
        cmd.creation_flags(0x08000000);
    }
    cmd.output()
        .map_err(|e| format!("执行 {} 失败: {e}", prog.display()))
}

// ==================== Status/port probing ====================

/// Run one read-only status command per tool (no rule parsing).
fn probe_status(tool: &FwTool) -> ToolStatus {
    match tool.name {
        "firewall-cmd" => {
            let command = "firewall-cmd --state".to_string();
            match run_capture(&tool.path, &["--state"]) {
                Ok(o) => {
                    // --state prints running / not running (exit code is also non-zero when not running; judge by text)
                    let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if text == "running" || text == "not running" {
                        ToolStatus {
                            command,
                            accessible: true,
                            detail: format!("firewalld 状态: {text}"),
                            hint: (text == "not running").then(|| {
                                "firewalld 已安装但未运行，其规则当前不生效".to_string()
                            }),
                        }
                    } else {
                        ToolStatus {
                            command,
                            accessible: false,
                            detail: summarize_output(&o),
                            hint: Some("查询 firewalld 状态失败，可能需要 root 权限".into()),
                        }
                    }
                }
                Err(e) => ToolStatus {
                    command,
                    accessible: false,
                    detail: e,
                    hint: None,
                },
            }
        }
        "iptables" => rule_table_status(tool, &["-L", "-n"], "iptables -L -n", "规则表"),
        "nft" => rule_table_status(tool, &["list", "ruleset"], "nft list ruleset", "规则集"),
        "netsh" => {
            let command = "netsh advfirewall show allprofiles state".to_string();
            match run_capture(&tool.path, &["advfirewall", "show", "allprofiles", "state"]) {
                Ok(o) if o.status.success() => ToolStatus {
                    command,
                    accessible: true,
                    // Output is localized per system language; do not parse ON/OFF, excerpt verbatim
                    detail: excerpt(&String::from_utf8_lossy(&o.stdout), 8),
                    hint: None,
                },
                Ok(o) => ToolStatus {
                    command,
                    accessible: false,
                    detail: summarize_output(&o),
                    hint: Some("netsh 查询失败，请人工检查 Windows 防火墙状态".into()),
                },
                Err(e) => ToolStatus {
                    command,
                    accessible: false,
                    detail: e,
                    hint: None,
                },
            }
        }
        _ => unreachable!("detect_tools 仅产出 PROBE_ORDER 内工具"),
    }
}

/// Shared by iptables / nft: list rules read-only; on success report only the line count (content not parsed).
fn rule_table_status(tool: &FwTool, args: &[&str], command: &str, noun: &str) -> ToolStatus {
    match run_capture(&tool.path, args) {
        Ok(o) if o.status.success() => {
            let lines = String::from_utf8_lossy(&o.stdout).lines().count();
            ToolStatus {
                command: command.into(),
                accessible: true,
                detail: format!("{noun}可读取（共 {lines} 行，未解析内容）"),
                hint: None,
            }
        }
        Ok(o) => ToolStatus {
            command: command.into(),
            accessible: false,
            detail: summarize_output(&o),
            hint: Some(format!("读取{noun}需 root / CAP_NET_ADMIN（可 sudo 重试）")),
        },
        Err(e) => ToolStatus {
            command: command.into(),
            accessible: false,
            detail: e,
            hint: None,
        },
    }
}

/// Port-allowance probe: firewalld can be queried directly; other tools get manual-check commands instead of rule parsing.
/// Returns (verdict: open/closed/unknown, conclusion, hint list).
fn check_port(tool: &FwTool, port: u16) -> (&'static str, String, Vec<String>) {
    match tool.name {
        "firewall-cmd" => check_port_firewalld(tool, port),
        "iptables" => (
            "unknown",
            format!("检测到 iptables，但按设计不重实现规则解析，无法自动判定 {port}/tcp"),
            vec![
                format!("人工排查: iptables -L -n | grep {port}（或 iptables -S | grep {port}）"),
                "读取规则表需 root / CAP_NET_ADMIN".into(),
            ],
        ),
        "nft" => (
            "unknown",
            format!("检测到 nftables，但按设计不重实现规则解析，无法自动判定 {port}/tcp"),
            vec![
                format!("人工排查: nft list ruleset | grep {port}"),
                "读取规则集需 root / CAP_NET_ADMIN".into(),
            ],
        ),
        "netsh" => (
            "unknown",
            format!("检测到 Windows 防火墙（netsh advfirewall），不重实现规则解析，无法自动判定 {port}/tcp"),
            vec![
                format!("人工排查: netsh advfirewall firewall show rule name=all | findstr \"{port}\""),
                "或检查「Windows Defender 防火墙 → 高级设置 → 入站规则」".into(),
            ],
        ),
        _ => unreachable!("detect_tools 仅产出 PROBE_ORDER 内工具"),
    }
}

/// firewalld port probe: --query-port is a direct query interface (not rule parsing), TCP only.
fn check_port_firewalld(tool: &FwTool, port: u16) -> (&'static str, String, Vec<String>) {
    let running = run_capture(&tool.path, &["--state"])
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "running")
        .unwrap_or(false);
    if !running {
        return (
            "unknown",
            format!("firewalld 未运行或状态不可查，无法判定 {port}/tcp 放行状态"),
            vec!["firewalld 未运行时其放行规则不生效；仍需确认无其它防火墙（iptables/nft/云安全组）".into()],
        );
    }
    let arg = format!("--query-port={port}/tcp");
    match run_capture(&tool.path, &[&arg]) {
        Ok(o) if o.status.success() => (
            "open",
            format!("firewalld 已放行 {port}/tcp"),
            vec![format!("$ firewall-cmd --query-port={port}/tcp → 放行")],
        ),
        Ok(o) => (
            "closed",
            format!("firewalld 未放行 {port}/tcp"),
            vec![
                format!(
                    "$ firewall-cmd --query-port={port}/tcp → 未放行（exit {}）",
                    o.status.code().unwrap_or(-1)
                ),
                format!("如需放行: firewall-cmd --add-port={port}/tcp（加 --permanent 持久化）"),
            ],
        ),
        Err(e) => (
            "unknown",
            format!("firewall-cmd 查询失败: {e}"),
            vec!["查询端口放行状态可能需要 root 权限".into()],
        ),
    }
}

// ==================== Output helpers ====================

/// Unified "not detected" wording.
fn no_tool_line() -> String {
    format!(
        "未检测到支持的防火墙工具（已依次探测: {}）",
        PROBE_ORDER.join(" / ")
    )
}

/// Manual-check advice when no firewall tool exists (shared by human/json).
fn manual_hints() -> Vec<String> {
    vec![
        "Linux: 确认 firewalld / iptables / nftables 是否安装（国产化裁剪系统可能均未预装）".into(),
        "Windows: 检查「设置 → Windows 安全中心 → 防火墙和网络保护」".into(),
        "云主机: 检查云平台安全组 / 上游网关防火墙（本命令无法覆盖）".into(),
    ]
}

/// Human rendering of the manual-check advice.
fn manual_advice() -> String {
    let mut out = String::from("建议人工排查:\n");
    for h in manual_hints() {
        out.push_str(&format!("  - {h}\n"));
    }
    out.trim_end().to_string()
}

/// Indent a multi-line excerpt by two spaces (for human output).
fn indent(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Excerpt the first N non-empty lines (localized output kept verbatim, not parsed).
fn excerpt(text: &str, max_lines: usize) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(max_lines)
        .collect::<Vec<_>>()
        .join("\n")
}

/// One-line summary of failed output (stderr preferred, truncated to 160 chars).
fn summarize_output(out: &Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = if !stderr.trim().is_empty() {
        &stderr
    } else {
        &stdout
    };
    let mut summary = excerpt(text, 2).replace('\n', "; ");
    if summary.is_empty() {
        summary = format!("命令退出码 {}", out.status.code().unwrap_or(-1));
    }
    if summary.chars().count() > 160 {
        summary = summary.chars().take(160).collect::<String>() + "…";
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique temp directory (best-effort cleanup at test end).
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("anet-fw-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Fake firewall-cmd: --state prints running; --query-port=8080/tcp allowed, all other ports denied.
    #[cfg(unix)]
    fn write_fake_firewall_cmd(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let script = "#!/bin/sh\nif [ \"$1\" = \"--state\" ]; then\n  echo running\n  exit 0\nfi\nif [ \"$1\" = \"--query-port=8080/tcp\" ]; then\n  exit 0\nfi\nexit 1\n";
        let path = dir.join("firewall-cmd");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Fake firewall-cmd (Windows .bat, executed by std via cmd.exe).
    /// Note: std always quotes arguments when invoking batch files; use %~1 to strip quotes before comparing.
    #[cfg(windows)]
    fn write_fake_firewall_cmd(dir: &Path) {
        let bat = "@echo off\r\nif \"%~1\"==\"--state\" (\r\n  echo running\r\n  exit /b 0\r\n)\r\nif \"%~1\"==\"--query-port=8080/tcp\" exit /b 0\r\nexit /b 1\r\n";
        std::fs::write(dir.join("firewall-cmd.bat"), bat).unwrap();
    }

    /// Generic fake executable (arbitrary content, never executed).
    #[cfg(unix)]
    fn write_fake_exe(dir: &Path, name: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Generic fake executable (Windows .bat).
    #[cfg(windows)]
    fn write_fake_exe(dir: &Path, name: &str) {
        std::fs::write(dir.join(format!("{name}.bat")), "@echo off\r\nexit /b 0\r\n").unwrap();
    }

    /// Environment with no firewall tool: honestly report "not detected" + manual-check advice (doc §7 batch-3 acceptance).
    #[test]
    fn no_tool_reported_honestly() {
        let dir = temp_dir("empty");
        let path = Some(dir.as_os_str());

        let st = fwstatus_inner(path);
        assert!(!st.success);
        assert_eq!(st.exit_code, 1);
        assert!(
            st.human.contains("未检测到支持的防火墙工具"),
            "{}",
            st.human
        );
        assert!(st.human.contains("建议人工排查"), "{}", st.human);
        assert_eq!(st.json["detected"], json!(false));

        let chk = fwcheck_inner(8080, path);
        assert!(!chk.success);
        assert_eq!(chk.exit_code, 1);
        assert_eq!(chk.json["verdict"], json!("unknown"));
        assert!(chk.json["tool"].is_null());
        assert!(
            chk.human.contains("未检测到支持的防火墙工具"),
            "{}",
            chk.human
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Fake firewalld: state running, 8080/tcp allowed and 9090/tcp denied (both paths).
    #[test]
    fn fake_firewalld_status_and_port_query() {
        let dir = temp_dir("firewalld");
        write_fake_firewall_cmd(&dir);
        let path = Some(dir.as_os_str());

        let st = fwstatus_inner(path);
        assert!(st.success, "{}", st.human);
        assert_eq!(st.exit_code, 0);
        assert!(st.human.contains("firewall-cmd"), "{}", st.human);
        assert!(st.human.contains("running"), "{}", st.human);
        assert_eq!(st.json["detected"], json!(true));
        assert_eq!(st.json["primary"]["name"], json!("firewall-cmd"));
        assert_eq!(st.json["primary"]["accessible"], json!(true));

        let open = fwcheck_inner(8080, path);
        assert!(open.success, "{}", open.human);
        assert_eq!(open.exit_code, 0);
        assert_eq!(open.json["verdict"], json!("open"));

        let closed = fwcheck_inner(9090, path);
        assert!(!closed.success);
        assert_eq!(closed.exit_code, 1);
        assert_eq!(closed.json["verdict"], json!("closed"));
        assert!(closed.human.contains("未放行"), "{}", closed.human);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Probe priority: with firewall-cmd and nft both present, firewall-cmd is primary and nft is listed as "also detected".
    #[test]
    fn priority_order_prefers_firewall_cmd() {
        let dir = temp_dir("prio");
        write_fake_firewall_cmd(&dir);
        write_fake_exe(&dir, "nft");
        let tools = detect_tools(Some(dir.as_os_str()));
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "firewall-cmd");
        assert_eq!(tools[1].name, "nft");

        let st = fwstatus_inner(Some(dir.as_os_str()));
        assert!(st.human.contains("主用工具: firewall-cmd"), "{}", st.human);
        assert!(st.human.contains("同时检测到: nft"), "{}", st.human);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// find_on_path: finds executables via injected PATH, returns None when missing.
    #[test]
    fn find_on_path_with_injected_path() {
        let dir = temp_dir("find");
        write_fake_exe(&dir, "nft");
        assert!(find_on_path("nft", Some(dir.as_os_str())).is_some());
        assert!(find_on_path("definitely-not-exist-tool", Some(dir.as_os_str())).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
