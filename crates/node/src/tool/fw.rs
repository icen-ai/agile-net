//! fwstatus / fwcheck — 防火墙探测提示（P3，shell out 探测，不重实现规则解析）。
//!
//! 依次探测 firewall-cmd / iptables / nft / Windows netsh advfirewall，
//! 哪个存在用哪个；全部不存在时如实输出「未检测到支持的防火墙工具」并建议人工排查。
//! iptables/nftables/firewalld 三套体系规则差异过大，超出边际成本原则，
//! 本模块只做探测提示，绝不解析防火墙规则（见 docs/todo/cli-tool.md §2 P3）。

use super::ToolOutcome;
use serde_json::json;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// 工具探测优先级：依次探测，首个存在者为主用工具。
const PROBE_ORDER: &[&str] = &["firewall-cmd", "iptables", "nft", "netsh"];

/// 检测到的防火墙工具。
#[derive(Debug, Clone)]
struct FwTool {
    /// 工具名（firewall-cmd / iptables / nft / netsh）
    name: &'static str,
    /// 在 PATH 中解析到的完整路径（后续按完整路径执行，不再依赖 PATH 查找）
    path: PathBuf,
}

/// 单工具的只读状态探测结果。
#[derive(Debug, Clone)]
struct ToolStatus {
    /// 实际执行的状态命令（展示用）
    command: String,
    /// 状态命令是否成功执行（权限不足/服务未运行时为 false）
    accessible: bool,
    /// 状态摘要（firewalld 运行态、规则输出行数或本地化摘录）
    detail: String,
    /// 附加提示（权限受限、服务未运行等）
    hint: Option<String>,
}

/// `anet tool fwstatus`：防火墙状态概览。
pub fn fwstatus() -> ToolOutcome {
    fwstatus_inner(None)
}

/// fwstatus 实现（path_env 供测试注入 PATH）。
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

/// `anet tool fwcheck <port>`：探测指定端口的放行状态（探测提示级别）。
pub fn fwcheck(port: u16) -> ToolOutcome {
    fwcheck_inner(port, None)
}

/// fwcheck 实现（path_env 供测试注入 PATH）。
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
    // open 才可确认可达（exit 0）；closed/unknown 均 exit 1，由 verdict 区分
    if verdict == "open" {
        ToolOutcome::ok(human.trim_end(), json)
    } else {
        ToolOutcome::fail(human.trim_end(), json)
    }
}

// ==================== 工具探测（shell out） ====================

/// 按优先级探测 PATH 中的防火墙工具（返回全部命中，首个为主用）。
fn detect_tools(path_env: Option<&OsStr>) -> Vec<FwTool> {
    PROBE_ORDER
        .iter()
        .filter_map(|name| find_on_path(name, path_env).map(|path| FwTool { name, path }))
        .collect()
}

/// 在 PATH（可注入）中查找可执行文件，返回完整路径。
fn find_on_path(prog: &str, path_env: Option<&OsStr>) -> Option<PathBuf> {
    let path_var = match path_env {
        Some(p) => p.to_os_string(),
        None => std::env::var_os("PATH")?,
    };
    for dir in std::env::split_paths(&path_var) {
        // Windows 可执行文件带扩展名（PATHEXT 常见子集即可）
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

/// 是否可执行文件（unix 校验执行位）。
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// 是否可执行文件（Windows 无执行位，存在即可）。
#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// 执行命令并捕获输出（spawn 失败返回 Err 描述，绝不 panic）。
fn run_capture(prog: &Path, args: &[&str]) -> Result<Output, String> {
    let mut cmd = Command::new(prog);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW：避免 GUI 场景弹出控制台黑窗
        cmd.creation_flags(0x08000000);
    }
    cmd.output()
        .map_err(|e| format!("执行 {} 失败: {e}", prog.display()))
}

// ==================== 状态/端口探测 ====================

/// 对主用工具执行只读状态命令（各工具一句，不解析规则）。
fn probe_status(tool: &FwTool) -> ToolStatus {
    match tool.name {
        "firewall-cmd" => {
            let command = "firewall-cmd --state".to_string();
            match run_capture(&tool.path, &["--state"]) {
                Ok(o) => {
                    // --state 输出 running / not running（未运行时退出码也非 0，按文本判）
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
                    // 输出随系统语言本地化，不解析 ON/OFF，原样摘录
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

/// iptables / nft 共用：只读列出规则，成功仅报行数（不解析内容）。
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

/// 端口放行探测：firewalld 可直接查询；其余工具不解析规则，只给人工排查命令。
/// 返回 (verdict: open/closed/unknown, 结论, 提示清单)。
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

/// firewalld 端口探测：--query-port 是直接查询接口（非规则解析），仅查 TCP。
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

// ==================== 输出辅助 ====================

/// 「未检测到」统一文案。
fn no_tool_line() -> String {
    format!(
        "未检测到支持的防火墙工具（已依次探测: {}）",
        PROBE_ORDER.join(" / ")
    )
}

/// 无防火墙工具时的人工排查建议（human/json 共用）。
fn manual_hints() -> Vec<String> {
    vec![
        "Linux: 确认 firewalld / iptables / nftables 是否安装（国产化裁剪系统可能均未预装）".into(),
        "Windows: 检查「设置 → Windows 安全中心 → 防火墙和网络保护」".into(),
        "云主机: 检查云平台安全组 / 上游网关防火墙（本命令无法覆盖）".into(),
    ]
}

/// 人工排查建议的 human 渲染。
fn manual_advice() -> String {
    let mut out = String::from("建议人工排查:\n");
    for h in manual_hints() {
        out.push_str(&format!("  - {h}\n"));
    }
    out.trim_end().to_string()
}

/// 多行摘录统一缩进两个空格（human 输出用）。
fn indent(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// 摘录前 N 个非空行（本地化输出原样保留，不解析）。
fn excerpt(text: &str, max_lines: usize) -> String {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(max_lines)
        .collect::<Vec<_>>()
        .join("\n")
}

/// 失败输出的单行摘要（优先 stderr，截断 160 字符）。
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

    /// 唯一临时目录（测试结束 best-effort 清理）。
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("anet-fw-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 假 firewall-cmd：--state 输出 running；--query-port=8080/tcp 放行，其余端口未放行。
    #[cfg(unix)]
    fn write_fake_firewall_cmd(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let script = "#!/bin/sh\nif [ \"$1\" = \"--state\" ]; then\n  echo running\n  exit 0\nfi\nif [ \"$1\" = \"--query-port=8080/tcp\" ]; then\n  exit 0\nfi\nexit 1\n";
        let path = dir.join("firewall-cmd");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// 假 firewall-cmd（Windows .bat，由 std 经 cmd.exe 执行）。
    /// 注意：std 调用批处理时参数一律加引号，用 %~1 去引号后再比较。
    #[cfg(windows)]
    fn write_fake_firewall_cmd(dir: &Path) {
        let bat = "@echo off\r\nif \"%~1\"==\"--state\" (\r\n  echo running\r\n  exit /b 0\r\n)\r\nif \"%~1\"==\"--query-port=8080/tcp\" exit /b 0\r\nexit /b 1\r\n";
        std::fs::write(dir.join("firewall-cmd.bat"), bat).unwrap();
    }

    /// 通用假可执行文件（内容随意，不会被执行）。
    #[cfg(unix)]
    fn write_fake_exe(dir: &Path, name: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// 通用假可执行文件（Windows .bat）。
    #[cfg(windows)]
    fn write_fake_exe(dir: &Path, name: &str) {
        std::fs::write(dir.join(format!("{name}.bat")), "@echo off\r\nexit /b 0\r\n").unwrap();
    }

    /// 无防火墙工具环境：如实输出「未检测到」+ 人工排查建议（文档 §7 批次三验收）。
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

    /// 假 firewalld：状态 running，8080/tcp 放行、9090/tcp 未放行（通/断两路）。
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

    /// 探测优先级：firewall-cmd 与 nft 同时存在时主用 firewall-cmd，nft 列为「同时检测到」。
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

    /// find_on_path：注入 PATH 可找到可执行文件，缺失时返回 None。
    #[test]
    fn find_on_path_with_injected_path() {
        let dir = temp_dir("find");
        write_fake_exe(&dir, "nft");
        assert!(find_on_path("nft", Some(dir.as_os_str())).is_some());
        assert!(find_on_path("definitely-not-exist-tool", Some(dir.as_os_str())).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
