//! psinfo / killport — process info and kill-by-port (P0, thin wrapper over sysinfo).
//!
//! killport kill-safety: SIGTERM by default, SIGKILL only with `--force`; before acting it prints
//! the processes to be terminated and requires `-y` (non-interactive terminals must confirm explicitly, otherwise it refuses).

use super::netstat::{SocketInfo, sockets};
use super::ToolOutcome;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, Signal, System};

/// `anet tool psinfo <pid>`: command line, user, exe path, CPU/memory.
pub fn psinfo(pid: u32) -> ToolOutcome {
    let spid = Pid::from_u32(pid);
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[spid]), true);
    if sys.process(spid).is_none() {
        return ToolOutcome::fail(
            format!("进程 {pid} 不存在或已退出"),
            json!({ "pid": pid, "error": "not_found" }),
        );
    }
    // CPU usage needs two refreshes for a delta (sysinfo requires a minimum interval)
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_processes(ProcessesToUpdate::Some(&[spid]), true);
    let Some(p) = sys.process(spid) else {
        return ToolOutcome::fail(
            format!("进程 {pid} 已退出"),
            json!({ "pid": pid, "error": "not_found" }),
        );
    };

    let name = p.name().to_string_lossy().into_owned();
    let cmd: Vec<String> = p.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
    let exe = p.exe().map(|e| e.to_string_lossy().into_owned());
    let user = p.user_id().and_then(|uid| {
        let users = sysinfo::Users::new_with_refreshed_list();
        users.get_user_by_id(uid).map(|u| u.name().to_string())
    });
    let cpu = p.cpu_usage();
    let memory = p.memory();
    let virtual_memory = p.virtual_memory();
    let status = format!("{:?}", p.status());
    let parent = p.parent().map(|p| p.as_u32());
    let start_time = p.start_time();
    let run_time = p.run_time();
    // start_time of 0 means the platform cannot provide it (e.g. Windows system processes); display "-"
    let started_at = (start_time > 0)
        .then(|| {
            chrono::DateTime::from_timestamp(start_time as i64, 0)
                .map(|utc| utc.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
        })
        .flatten();

    let cmdline = if cmd.is_empty() { name.clone() } else { cmd.join(" ") };
    let human = format!(
        "进程 {pid}：{name}\n\
         \x20 命令行:  {cmdline}\n\
         \x20 exe:     {}\n\
         \x20 用户:    {}\n\
         \x20 状态:    {status}\n\
         \x20 CPU:     {cpu:.1}%\n\
         \x20 内存:    {} (RSS)，虚拟 {}\n\
         \x20 父进程:  {}\n\
         \x20 启动:    {}（运行 {}）",
        exe.as_deref().unwrap_or("-"),
        user.as_deref().unwrap_or("-"),
        fmt_bytes(memory),
        fmt_bytes(virtual_memory),
        parent.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        started_at.as_deref().unwrap_or("-"),
        fmt_duration_secs(run_time),
    );
    ToolOutcome::ok(
        human,
        json!({
            "pid": pid,
            "name": name,
            "cmd": cmd,
            "exe": exe,
            "user": user,
            "status": status,
            "cpu_percent": cpu,
            "memory_bytes": memory,
            "virtual_memory_bytes": virtual_memory,
            "parent": parent,
            "start_time": start_time,
            "run_time_seconds": run_time,
        }),
    )
}

/// `anet tool killport <port>`: find the owning process via [`sockets`], then terminate it.
pub fn killport(port: u16, force: bool, yes: bool) -> ToolOutcome {
    killport_impl(port, force, yes, std::io::stdin().is_terminal(), owners_of)
}

/// Port-owner lookup (killport data source; tests inject a stub to stay independent of the netstat implementation).
fn owners_of(port: u16) -> Result<Vec<SocketInfo>, String> {
    let all = sockets()?;
    Ok(all
        .into_iter()
        .filter(|s| local_port(&s.local) == Some(port))
        .collect())
}

/// Extract the local port from "addr:port" (including "[v6]:port").
fn local_port(local: &str) -> Option<u16> {
    local.rsplit_once(':')?.1.parse().ok()
}

/// killport implementation (interactive/owners injectable, so tests can cover kill-safety and the kill path).
fn killport_impl(
    port: u16,
    force: bool,
    yes: bool,
    interactive: bool,
    owners: impl Fn(u16) -> Result<Vec<SocketInfo>, String>,
) -> ToolOutcome {
    let signal = if force { "KILL" } else { "TERM" };
    let targets = match owners(port) {
        Ok(t) => t,
        Err(e) => {
            return ToolOutcome::usage_error(format!("枚举 socket 失败：{e}"));
        }
    };
    if targets.is_empty() {
        return ToolOutcome::fail(
            format!("端口 {port} 未被占用"),
            json!({ "port": port, "signal": signal, "targets": [], "killed": 0 }),
        );
    }
    // Group and dedup by PID (one process may hold multiple sockets on the same port)
    let mut by_pid: BTreeMap<u32, Vec<&SocketInfo>> = BTreeMap::new();
    for s in &targets {
        if let Some(pid) = s.pid {
            by_pid.entry(pid).or_default().push(s);
        }
    }
    if by_pid.is_empty() {
        return ToolOutcome::fail(
            format!("端口 {port} 被占用，但无权限获取所属进程 PID（需 root 或 CAP_NET_ADMIN）"),
            json!({ "port": port, "signal": signal, "error": "pid_hidden", "killed": 0 }),
        );
    }

    // Termination plan: enrich process name/exe (sysinfo is authoritative, the socket-enriched name is the fallback)
    let mut sys = System::new();
    let mut plan_lines = Vec::new();
    let mut target_json = Vec::new();
    for (&pid, socks) in &by_pid {
        sys.refresh_processes(ProcessesToUpdate::Some(&[Pid::from_u32(pid)]), true);
        let (name, exe) = match sys.process(Pid::from_u32(pid)) {
            Some(p) => (
                Some(p.name().to_string_lossy().into_owned()),
                p.exe().map(|e| e.to_string_lossy().into_owned()),
            ),
            None => (socks.iter().find_map(|s| s.process.clone()), None),
        };
        let socks_desc: Vec<String> = socks
            .iter()
            .map(|s| match &s.state {
                Some(st) => format!("{} {} {st}", s.proto, s.local),
                None => format!("{} {}", s.proto, s.local),
            })
            .collect();
        plan_lines.push(format!(
            "  PID {pid}  {}  [{}]",
            name.as_deref().unwrap_or("?"),
            socks_desc.join(", ")
        ));
        target_json.push(json!({
            "pid": pid,
            "process": name,
            "exe": exe,
            "sockets": socks,
        }));
    }
    let plan = format!(
        "端口 {port} 的 {} 个占用进程（signal={signal}）：\n{}",
        by_pid.len(),
        plan_lines.join("\n")
    );

    // Kill-safety: -y passes directly; interactive terminals get a second confirmation; non-interactive without -y is refused
    if !yes {
        if !interactive {
            return ToolOutcome::usage_error(format!(
                "{plan}\n拒绝执行：非交互终端必须显式加 -y 确认（防误杀）"
            ));
        }
        eprintln!("{plan}");
        eprint!("确认终止以上进程？输入 y 继续: ");
        use std::io::Write;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        let ans = line.trim().to_ascii_lowercase();
        if ans != "y" && ans != "yes" {
            return ToolOutcome::fail(
                "已取消，未终止任何进程",
                json!({ "port": port, "signal": signal, "confirmed": false, "killed": 0 }),
            );
        }
    }

    let results: Vec<KillResult> = by_pid.keys().map(|&pid| terminate(pid, force)).collect();
    let killed = results.iter().filter(|r| r.exited).count();
    let total = results.len();
    let all_ok = killed == total;

    let mut human = format!("{plan}\n处理结果：");
    for r in &results {
        human.push_str(&format!(
            "\n  PID {}  {}{}",
            r.pid,
            if r.exited { "已终止" } else { "终止失败" },
            r.note.as_deref().map(|n| format!("（{n}）")).unwrap_or_default()
        ));
    }
    if !all_ok && !force {
        human.push_str("\n提示：对未退出进程可加 --force（SIGKILL）强制终止");
    }
    let results_json: Vec<_> = results
        .iter()
        .map(|r| {
            json!({
                "pid": r.pid,
                "signal_sent": r.signal_sent,
                "exited": r.exited,
                "note": r.note,
            })
        })
        .collect();
    let body = json!({
        "port": port,
        "signal": signal,
        "confirmed": true,
        "targets": target_json,
        "results": results_json,
        "killed": killed,
        "total": total,
    });
    if all_ok {
        ToolOutcome::ok(human, body)
    } else {
        ToolOutcome::fail(human, body)
    }
}

/// Termination result for a single process.
struct KillResult {
    pid: u32,
    signal_sent: bool,
    exited: bool,
    note: Option<String>,
}

/// Terminate the given process: SIGTERM by default, SIGKILL with `--force`; wait up to 3s to confirm exit.
fn terminate(pid: u32, force: bool) -> KillResult {
    let spid = Pid::from_u32(pid);
    let mut sys = System::new();
    // Liveness check: zombie/dead states count as exited (a child stays in /proc until reaped by wait)
    let alive = |sys: &mut System| {
        sys.refresh_processes(ProcessesToUpdate::Some(&[spid]), true);
        match sys.process(spid) {
            None => false,
            Some(p) => !matches!(
                p.status(),
                sysinfo::ProcessStatus::Zombie | sysinfo::ProcessStatus::Dead
            ),
        }
    };
    if !alive(&mut sys) {
        return KillResult {
            pid,
            signal_sent: false,
            exited: true,
            note: Some("进程已退出".into()),
        };
    }
    let (sent, note) = if force {
        let ok = sys.process(spid).map(|p| p.kill()).unwrap_or(false);
        (ok, None)
    } else {
        match sys.process(spid).and_then(|p| p.kill_with(Signal::Term)) {
            Some(ok) => (ok, None),
            // Platforms like Windows have no SIGTERM semantics; degrade to a direct kill (equivalent to SIGKILL)
            None => {
                let ok = sys.process(spid).map(|p| p.kill()).unwrap_or(false);
                (ok, Some("平台不支持 SIGTERM，已直接终止".into()))
            }
        }
    };
    if !sent {
        return KillResult {
            pid,
            signal_sent: false,
            exited: false,
            note: Some("信号发送失败（可能权限不足）".into()),
        };
    }
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if !alive(&mut sys) {
            return KillResult {
                pid,
                signal_sent: true,
                exited: true,
                note,
            };
        }
    }
    KillResult {
        pid,
        signal_sent: true,
        exited: false,
        note,
    }
}

/// Human-readable byte count (KiB/MiB/GiB, one decimal).
fn fmt_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if n >= GIB {
        format!("{:.1} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

/// Human-readable duration in seconds (e.g. 1d2h3m).
fn fmt_duration_secs(secs: u64) -> String {
    let (d, rem) = (secs / 86400, secs % 86400);
    let (h, rem) = (rem / 3600, rem % 3600);
    let (m, s) = (rem / 60, rem % 60);
    if d > 0 {
        format!("{d}d{h}h{m}m")
    } else if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};

    /// Child-process entry (ignored; spawned explicitly by the killport tests via env var):
    /// binds a random loopback port, reports it on stdout, then accepts connections until killed.
    #[test]
    #[ignore = "子进程入口，由 killport 测试拉起"]
    fn killport_child_listener() {
        if std::env::var("ANET_TOOL_KILLPORT_CHILD").is_err() {
            return;
        }
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("子进程绑定回环端口失败");
        println!("ANET_PORT={}", listener.local_addr().unwrap().port());
        loop {
            match listener.accept() {
                Ok((s, _)) => drop(s),
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// Spawn the listener child process; returns the handle and its loopback listen port.
    fn spawn_listener_child() -> (Child, u16) {
        let exe = std::env::current_exe().expect("获取测试二进制路径失败");
        let mut child = Command::new(exe)
            .args([
                "tool::sysinfo::tests::killport_child_listener",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("ANET_TOOL_KILLPORT_CHILD", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("拉起子进程失败");
        let stdout = child.stdout.take().expect("子进程 stdout 缺失");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if let Some(p) = line.trim().strip_prefix("ANET_PORT=") {
                            let _ = tx.send(p.to_string());
                            break;
                        }
                    }
                }
            }
        });
        let port: u16 = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("子进程未在 30s 内报告端口")
            .parse()
            .expect("子进程端口号解析失败");
        (child, port)
    }

    /// Build an owner-lookup stub: claims `port` is held by `pid` in TCP LISTEN state.
    fn fake_owner(pid: u32, port: u16) -> impl Fn(u16) -> Result<Vec<SocketInfo>, String> {
        move |p| {
            assert_eq!(p, port);
            Ok(vec![SocketInfo {
                proto: "tcp".into(),
                local: format!("127.0.0.1:{port}"),
                remote: None,
                state: Some("LISTEN".into()),
                pid: Some(pid),
                process: Some("test-child".into()),
            }])
        }
    }

    #[test]
    fn local_port_extracts_port() {
        assert_eq!(local_port("0.0.0.0:8080"), Some(8080));
        assert_eq!(local_port("127.0.0.1:1"), Some(1));
        assert_eq!(local_port("[::]:9090"), Some(9090));
        assert_eq!(local_port("127.0.0.1:abc"), None);
        assert_eq!(local_port("noport"), None);
    }

    #[test]
    fn fmt_helpers_render() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(12 * 1024 * 1024 + 400_000), "12.4 MiB");
        assert_eq!(fmt_duration_secs(30), "30s");
        assert_eq!(fmt_duration_secs(90), "1m30s");
        assert_eq!(fmt_duration_secs(90000), "1d1h0m");
    }

    #[test]
    fn psinfo_reports_current_process() {
        let pid = std::process::id();
        let outcome = psinfo(pid);
        assert!(outcome.success, "human: {}", outcome.human);
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.json["pid"], pid);
        assert!(outcome.json["memory_bytes"].as_u64().unwrap() > 0);
        assert!(outcome.human.contains(&format!("进程 {pid}")));
    }

    #[test]
    fn psinfo_missing_process_fails() {
        // u32::MAX is outside every platform's valid PID range, so it reliably does not exist
        let outcome = psinfo(u32::MAX);
        assert!(!outcome.success);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.human.contains("不存在"));
    }

    #[test]
    fn killport_free_port_fails() {
        let outcome = killport_impl(1, false, true, false, |_| Ok(vec![]));
        assert!(!outcome.success);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.human.contains("未被占用"));
    }

    #[test]
    fn killport_finder_error_is_usage_error() {
        let outcome = killport_impl(1, false, true, false, |_| Err("boom".into()));
        assert_eq!(outcome.exit_code, 2);
        assert!(outcome.human.contains("boom"));
    }

    #[test]
    fn killport_hides_pid_without_permission() {
        // Socket visible but PID hidden (permission-limited): report honestly instead of staying silent
        let finder = |_| {
            Ok(vec![SocketInfo {
                proto: "tcp".into(),
                local: "0.0.0.0:80".into(),
                remote: None,
                state: Some("LISTEN".into()),
                pid: None,
                process: None,
            }])
        };
        let outcome = killport_impl(80, false, true, false, finder);
        assert!(!outcome.success);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.human.contains("无权限获取所属进程 PID"));
    }

    /// Kill-safety: non-interactive without -y must refuse, and the target process must stay alive.
    #[test]
    fn killport_refuses_without_yes_non_interactive() {
        let (mut child, port) = spawn_listener_child();
        let outcome = killport_impl(port, false, false, false, fake_owner(child.id(), port));
        assert_eq!(outcome.exit_code, 2, "human: {}", outcome.human);
        assert!(outcome.human.contains("-y"));
        assert!(outcome.human.contains(&child.id().to_string()));
        // Refused to execute; the child must still be alive
        assert!(child.try_wait().expect("探测子进程失败").is_none());
        child.kill().expect("清理子进程失败");
        let _ = child.wait();
    }

    /// Both SIGTERM and SIGKILL paths: killport -y terminates the listener child and frees the port.
    #[test]
    fn killport_terminates_child_and_frees_port() {
        for force in [false, true] {
            let (mut child, port) = spawn_listener_child();
            let pid = child.id();
            let outcome = killport_impl(port, force, true, false, fake_owner(pid, port));
            assert!(
                outcome.success,
                "force={force} human: {}",
                outcome.human
            );
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(outcome.json["killed"], 1);
            assert_eq!(outcome.json["signal"], if force { "KILL" } else { "TERM" });
            // Process has exited (reaped by wait)
            let _ = child.wait().expect("等待子进程退出失败");
            // Port is free: can bind again
            let relisten = std::net::TcpListener::bind(("127.0.0.1", port));
            assert!(relisten.is_ok(), "force={force} 端口 {port} 未释放");
        }
    }
}
